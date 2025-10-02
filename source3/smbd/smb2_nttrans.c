/*
   Unix SMB/CIFS implementation.
   SMB NT transaction handling
   Copyright (C) Jeremy Allison			1994-2007
   Copyright (C) Stefan (metze) Metzmacher	2003

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "fake_file.h"
#include "../libcli/security/security.h"
#include "../librpc/gen_ndr/ndr_security.h"
#include "passdb/lookup_sid.h"
#include "auth.h"
#include "smbprofile.h"
#include "source3/libsmb/proto.h"
#include "lib/util_ea.h"
#include "librpc/gen_ndr/ndr_quota.h"
#include "librpc/gen_ndr/ndr_security.h"

extern const struct generic_mapping file_generic_mapping;

/*********************************************************************
 Windows seems to do canonicalization of inheritance bits. Do the
 same.
*********************************************************************/

static void canonicalize_inheritance_bits(struct files_struct *fsp,
					  struct security_descriptor *psd)
{
	bool set_auto_inherited = false;

	/*
	 * We need to filter out the
	 * SEC_DESC_DACL_AUTO_INHERITED|SEC_DESC_DACL_AUTO_INHERIT_REQ
	 * bits. If both are set we store SEC_DESC_DACL_AUTO_INHERITED
	 * as this alters whether SEC_ACE_FLAG_INHERITED_ACE is set
	 * when an ACE is inherited. Otherwise we zero these bits out.
	 * See:
	 *
	 * http://social.msdn.microsoft.com/Forums/eu/os_fileservices/thread/11f77b68-731e-407d-b1b3-064750716531
	 *
	 * for details.
	 */

	if (!lp_acl_flag_inherited_canonicalization(SNUM(fsp->conn))) {
		psd->type &= ~SEC_DESC_DACL_AUTO_INHERIT_REQ;
		return;
	}

	if ((psd->type & (SEC_DESC_DACL_AUTO_INHERITED|SEC_DESC_DACL_AUTO_INHERIT_REQ))
			== (SEC_DESC_DACL_AUTO_INHERITED|SEC_DESC_DACL_AUTO_INHERIT_REQ)) {
		set_auto_inherited = true;
	}

	psd->type &= ~(SEC_DESC_DACL_AUTO_INHERITED|SEC_DESC_DACL_AUTO_INHERIT_REQ);
	if (set_auto_inherited) {
		psd->type |= SEC_DESC_DACL_AUTO_INHERITED;
	}
}

/****************************************************************************
 Internal fn to set security descriptors.
****************************************************************************/

NTSTATUS set_sd(files_struct *fsp, struct security_descriptor *psd,
		       uint32_t security_info_sent)
{
	files_struct *sd_fsp = NULL;
	NTSTATUS status;
	bool refuse;

	if (!CAN_WRITE(fsp->conn)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!lp_nt_acl_support(SNUM(fsp->conn))) {
		return NT_STATUS_OK;
	}

	refuse = refuse_symlink_fsp(fsp);
	if (refuse) {
		DBG_DEBUG("ACL set on symlink %s denied.\n",
			fsp_str_dbg(fsp));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (psd->owner_sid == NULL) {
		security_info_sent &= ~SECINFO_OWNER;
	}
	if (psd->group_sid == NULL) {
		security_info_sent &= ~SECINFO_GROUP;
	}

	/* Ensure we have at least one thing set. */
	if ((security_info_sent & (SECINFO_OWNER|SECINFO_GROUP|SECINFO_DACL|SECINFO_SACL)) == 0) {
		/* Just like W2K3 */
		return NT_STATUS_OK;
	}

	/* Ensure we have the rights to do this. */
	if (security_info_sent & SECINFO_OWNER) {
		status = check_any_access_fsp(fsp, SEC_STD_WRITE_OWNER);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	if (security_info_sent & SECINFO_GROUP) {
		status = check_any_access_fsp(fsp, SEC_STD_WRITE_OWNER);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	if (security_info_sent & SECINFO_DACL) {
		status = check_any_access_fsp(fsp, SEC_STD_WRITE_DAC);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		/* Convert all the generic bits. */
		if (psd->dacl) {
			security_acl_map_generic(psd->dacl, &file_generic_mapping);
		}
	}

	if (security_info_sent & SECINFO_SACL) {
		status = check_any_access_fsp(fsp, SEC_FLAG_SYSTEM_SECURITY);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		/*
		 * Setting a SACL also requires WRITE_DAC.
		 * See the smbtorture3 SMB2-SACL test.
		 */
		status = check_any_access_fsp(fsp, SEC_STD_WRITE_DAC);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		/* Convert all the generic bits. */
		if (psd->sacl) {
			security_acl_map_generic(psd->sacl, &file_generic_mapping);
		}
	}

	canonicalize_inheritance_bits(fsp, psd);

	if (DEBUGLEVEL >= 10) {
		DEBUG(10,("set_sd for file %s\n", fsp_str_dbg(fsp)));
		NDR_PRINT_DEBUG(security_descriptor, psd);
	}

	sd_fsp = metadata_fsp(fsp);
	status = SMB_VFS_FSET_NT_ACL(sd_fsp, security_info_sent, psd);
	TALLOC_FREE(psd);

	if (NT_STATUS_IS_OK(status)) {
		notify_fname(fsp->conn,
			     NOTIFY_ACTION_MODIFIED,
			     FILE_NOTIFY_CHANGE_SECURITY,
			     fsp->fsp_name,
			     NULL);
	}

	return status;
}

static bool check_smb2_posix_chmod_ace(const struct files_struct *fsp,
					uint32_t security_info_sent,
					struct security_descriptor *psd,
					mode_t *pmode)
{
	struct security_ace *ace = NULL;
	int cmp;

	/*
	 * This must be an ACL with one ACE containing an
	 * MS NFS style mode entry coming in on a POSIX
	 * handle over SMB2+.
	 */
	if (!conn_using_smb2(fsp->conn->sconn)) {
		return false;
	}

	if (!fsp->fsp_flags.posix_open) {
		return false;
	}

	if (!(security_info_sent & SECINFO_DACL)) {
		return false;
	}

	if (psd->dacl == NULL) {
		return false;
	}

	if (psd->dacl->num_aces != 1) {
		return false;
	}
	ace = &psd->dacl->aces[0];

	if (ace->trustee.num_auths != 3) {
		return false;
	}

	cmp = dom_sid_compare_domain(&global_sid_Unix_NFS_Mode, &ace->trustee);
	if (cmp != 0) {
		return false;
	}

	*pmode = (mode_t)ace->trustee.sub_auths[2];
	*pmode &= (S_IRWXU | S_IRWXG | S_IRWXO);

	return true;
}

/****************************************************************************
 Internal fn to set security descriptors from a data blob.
****************************************************************************/

NTSTATUS set_sd_blob(files_struct *fsp, uint8_t *data, uint32_t sd_len,
		       uint32_t security_info_sent)
{
	struct security_descriptor *psd = NULL;
	NTSTATUS status;
	bool do_chmod = false;
	mode_t smb2_posix_mode = 0;
	int ret;

	if (sd_len == 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = unmarshall_sec_desc(talloc_tos(), data, sd_len, &psd);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	do_chmod = check_smb2_posix_chmod_ace(fsp,
				security_info_sent,
				psd,
				&smb2_posix_mode);
	if (!do_chmod) {
		return set_sd(fsp, psd, security_info_sent);
	}

	TALLOC_FREE(psd);

	ret = SMB_VFS_FCHMOD(fsp, smb2_posix_mode);
	if (ret != 0) {
		status = map_nt_error_from_unix(errno);
		DBG_ERR("smb2_posix_chmod [%s] [%04o] failed: %s\n",
			fsp_str_dbg(fsp),
			(unsigned)smb2_posix_mode,
			nt_errstr(status));
		return status;
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Copy a file.
****************************************************************************/

NTSTATUS copy_internals(TALLOC_CTX *ctx,
			connection_struct *conn,
			struct smb_request *req,
			struct files_struct *src_dirfsp,
			struct smb_filename *smb_fname_src,
			struct files_struct *dst_dirfsp,
			struct smb_filename *smb_fname_dst,
			uint32_t attrs)
{
	files_struct *fsp1,*fsp2;
	uint32_t fattr;
	int info;
	off_t ret=-1;
	NTSTATUS status = NT_STATUS_OK;

	if (!CAN_WRITE(conn)) {
		status = NT_STATUS_MEDIA_WRITE_PROTECTED;
		goto out;
	}

        /* Source must already exist. */
	if (!VALID_STAT(smb_fname_src->st)) {
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto out;
	}

	/* Ensure attributes match. */
	fattr = fdos_mode(smb_fname_src->fsp);
	if ((fattr & ~attrs) & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) {
		status = NT_STATUS_NO_SUCH_FILE;
		goto out;
	}

	/* Disallow if dst file already exists. */
	if (VALID_STAT(smb_fname_dst->st)) {
		status = NT_STATUS_OBJECT_NAME_COLLISION;
		goto out;
	}

	/* No copy from a directory. */
	if (S_ISDIR(smb_fname_src->st.st_ex_mode)) {
		status = NT_STATUS_FILE_IS_A_DIRECTORY;
		goto out;
	}

	DBG_DEBUG("doing file copy %s to %s\n",
		  smb_fname_str_dbg(smb_fname_src),
		  smb_fname_str_dbg(smb_fname_dst));

        status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		req,					/* req */
		src_dirfsp,				/* dirfsp */
		smb_fname_src,				/* fname */
		FILE_READ_DATA|FILE_READ_ATTRIBUTES|
			FILE_READ_EA,			/* access_mask */
		(FILE_SHARE_READ | FILE_SHARE_WRITE |	/* share_access */
		    FILE_SHARE_DELETE),
		FILE_OPEN,				/* create_disposition*/
		0,					/* create_options */
		FILE_ATTRIBUTE_NORMAL,			/* file_attributes */
		NO_OPLOCK,				/* oplock_request */
		NULL,					/* lease */
		0,					/* allocation_size */
		0,					/* private_flags */
		NULL,					/* sd */
		NULL,					/* ea_list */
		&fsp1,					/* result */
		&info,					/* pinfo */
		NULL, NULL);				/* create context */

	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

        status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		req,					/* req */
		dst_dirfsp,				/* dirfsp */
		smb_fname_dst,				/* fname */
		FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES|
			FILE_WRITE_EA,			/* access_mask */
		(FILE_SHARE_READ | FILE_SHARE_WRITE |	/* share_access */
		    FILE_SHARE_DELETE),
		FILE_CREATE,				/* create_disposition*/
		0,					/* create_options */
		fattr,					/* file_attributes */
		NO_OPLOCK,				/* oplock_request */
		NULL,					/* lease */
		0,					/* allocation_size */
		0,					/* private_flags */
		NULL,					/* sd */
		NULL,					/* ea_list */
		&fsp2,					/* result */
		&info,					/* pinfo */
		NULL, NULL);				/* create context */

	if (!NT_STATUS_IS_OK(status)) {
		close_file_free(NULL, &fsp1, ERROR_CLOSE);
		goto out;
	}

	if (smb_fname_src->st.st_ex_size) {
		ret = vfs_transfer_file(fsp1, fsp2, smb_fname_src->st.st_ex_size);
	}

	/*
	 * As we are opening fsp1 read-only we only expect
	 * an error on close on fsp2 if we are out of space.
	 * Thus we don't look at the error return from the
	 * close of fsp1.
	 */
	close_file_free(NULL, &fsp1, NORMAL_CLOSE);

	/* Ensure the modtime is set correctly on the destination file. */
	set_close_write_time(fsp2, smb_fname_src->st.st_ex_mtime);

	status = close_file_free(NULL, &fsp2, NORMAL_CLOSE);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("close_file_free() failed: %s\n",
			    nt_errstr(status));
		/*
		 * We can't do much but leak the fsp
		 */
		goto out;
	}

	/* Grrr. We have to do this as open_file_ntcreate adds FILE_ATTRIBUTE_ARCHIVE when it
	   creates the file. This isn't the correct thing to do in the copy
	   case. JRA */

	if (smb_fname_dst->fsp == NULL) {
		struct smb_filename *pathref = NULL;

		status = synthetic_pathref(ctx,
					conn->cwd_fsp,
					smb_fname_dst->base_name,
					smb_fname_dst->stream_name,
					NULL,
					smb_fname_dst->twrp,
					smb_fname_dst->flags,
					&pathref);

		/* should we handle NT_STATUS_OBJECT_NAME_NOT_FOUND specially here ???? */
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
		file_set_dosmode(conn, pathref, fattr, dst_dirfsp, false);
		smb_fname_dst->st.st_ex_mode = pathref->st.st_ex_mode;
		TALLOC_FREE(pathref);
	} else {
		file_set_dosmode(
			conn, smb_fname_dst, fattr, dst_dirfsp, false);
	}

	if (ret < (off_t)smb_fname_src->st.st_ex_size) {
		status = NT_STATUS_DISK_FULL;
		goto out;
	}
 out:
	if (!NT_STATUS_IS_OK(status)) {
		DBG_NOTICE("Error %s copy file %s to %s\n",
			   nt_errstr(status),
			   smb_fname_str_dbg(smb_fname_src),
			   smb_fname_str_dbg(smb_fname_dst));
	}

	return status;
}

/******************************************************************************
 Fake up a completely empty SD.
*******************************************************************************/

static NTSTATUS get_null_nt_acl(TALLOC_CTX *mem_ctx, struct security_descriptor **ppsd)
{
	size_t sd_size;

	*ppsd = make_standard_sec_desc( mem_ctx, &global_sid_World, &global_sid_World, NULL, &sd_size);
	if(!*ppsd) {
		DBG_ERR("Unable to malloc space for security descriptor.\n");
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Get a security descriptor from the file system, normalize for components
 requested.
****************************************************************************/

static NTSTATUS smbd_fetch_security_desc(connection_struct *conn,
				TALLOC_CTX *mem_ctx,
				files_struct *fsp,
				uint32_t security_info_wanted,
				struct security_descriptor **ppsd)
{
	NTSTATUS status;
	struct security_descriptor *psd = NULL;
	bool need_to_read_sd = false;
	bool refuse;

	/*
	 * Get the permissions to return.
	 */

	if (security_info_wanted & SECINFO_SACL) {
		status = check_any_access_fsp(fsp, SEC_FLAG_SYSTEM_SECURITY);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("Access to SACL denied.\n");
			return status;
		}
	}

	if (security_info_wanted & (SECINFO_DACL|SECINFO_OWNER|SECINFO_GROUP)) {
		status = check_any_access_fsp(fsp, SEC_STD_READ_CONTROL);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("Access to DACL, OWNER, or GROUP denied.\n");
			return status;
		}
	}

	refuse = refuse_symlink_fsp(fsp);
	if (refuse) {
		DBG_DEBUG("ACL get on symlink %s denied.\n",
			fsp_str_dbg(fsp));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (security_info_wanted & (SECINFO_DACL|SECINFO_OWNER|
			SECINFO_GROUP|SECINFO_SACL)) {
		/* Don't return SECINFO_LABEL if anything else was
		   requested. See bug #8458. */
		security_info_wanted &= ~SECINFO_LABEL;

		/*
		 * Only query the file system SD if the caller asks
		 * for any bits. This allows a caller to open without
		 * READ_CONTROL but still issue a query sd. See
		 * smb2.sdread test.
		 */
		need_to_read_sd = true;
	}

	if (lp_nt_acl_support(SNUM(conn)) &&
	    ((security_info_wanted & SECINFO_LABEL) == 0) &&
	    need_to_read_sd)
	{
		files_struct *sd_fsp = metadata_fsp(fsp);
		status = SMB_VFS_FGET_NT_ACL(
			sd_fsp, security_info_wanted, mem_ctx, &psd);
	} else {
		status = get_null_nt_acl(mem_ctx, &psd);
	}

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!(security_info_wanted & SECINFO_OWNER)) {
		psd->owner_sid = NULL;
	}
	if (!(security_info_wanted & SECINFO_GROUP)) {
		psd->group_sid = NULL;
	}
	if (!(security_info_wanted & SECINFO_DACL)) {
		psd->type &= ~SEC_DESC_DACL_PRESENT;
		psd->dacl = NULL;
	}
	if (!(security_info_wanted & SECINFO_SACL)) {
		psd->type &= ~SEC_DESC_SACL_PRESENT;
		psd->sacl = NULL;
	}

	/* If the SACL/DACL is NULL, but was requested, we mark that it is
	 * present in the reply to match Windows behavior */
	if (psd->sacl == NULL &&
	    security_info_wanted & SECINFO_SACL)
		psd->type |= SEC_DESC_SACL_PRESENT;
	if (psd->dacl == NULL &&
	    security_info_wanted & SECINFO_DACL)
		psd->type |= SEC_DESC_DACL_PRESENT;

	if (security_info_wanted & SECINFO_LABEL) {
		/* Like W2K3 return a null object. */
		psd->owner_sid = NULL;
		psd->group_sid = NULL;
		psd->dacl = NULL;
		psd->sacl = NULL;
		psd->type &= ~(SEC_DESC_DACL_PRESENT|SEC_DESC_SACL_PRESENT);
	}

	*ppsd = psd;
	return NT_STATUS_OK;
}

/****************************************************************************
 Write a security descriptor into marshalled format.
****************************************************************************/

static NTSTATUS smbd_marshall_security_desc(TALLOC_CTX *mem_ctx,
					files_struct *fsp,
					struct security_descriptor *psd,
					uint32_t max_data_count,
					uint8_t **ppmarshalled_sd,
					size_t *psd_size)
{
	*psd_size = ndr_size_security_descriptor(psd, 0);

	DBG_NOTICE("sd_size = %zu.\n", *psd_size);

	if (DEBUGLEVEL >= 10) {
		DBG_DEBUG("security desc for file %s\n",
			fsp_str_dbg(fsp));
		NDR_PRINT_DEBUG(security_descriptor, psd);
	}

	if (max_data_count < *psd_size) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	return marshall_sec_desc(mem_ctx,
				 psd,
				 ppmarshalled_sd,
				 psd_size);
}

/****************************************************************************
 Reply to query a security descriptor.
 Callable from SMB1 and SMB2.
 If it returns NT_STATUS_BUFFER_TOO_SMALL, psd_size is initialized with
 the required size.
****************************************************************************/

NTSTATUS smbd_do_query_security_desc(connection_struct *conn,
					TALLOC_CTX *mem_ctx,
					files_struct *fsp,
					uint32_t security_info_wanted,
					uint32_t max_data_count,
					uint8_t **ppmarshalled_sd,
					size_t *psd_size)
{
	NTSTATUS status;
	struct security_descriptor *psd = NULL;

	/*
	 * Get the permissions to return.
	 */

	status = smbd_fetch_security_desc(conn,
					mem_ctx,
					fsp,
					security_info_wanted,
					&psd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = smbd_marshall_security_desc(mem_ctx,
					fsp,
					psd,
					max_data_count,
					ppmarshalled_sd,
					psd_size);
	TALLOC_FREE(psd);
	return status;
}

#ifdef HAVE_SYS_QUOTAS
static enum ndr_err_code fill_qtlist_from_sids(TALLOC_CTX *mem_ctx,
					       struct files_struct *fsp,
					       SMB_NTQUOTA_HANDLE *qt_handle,
					       struct dom_sid *sids,
					       uint32_t elems)
{
	uint32_t i;
	TALLOC_CTX *list_ctx = NULL;

	list_ctx = talloc_init("quota_sid_list");

	if (list_ctx == NULL) {
		DBG_ERR("failed to allocate\n");
		return NDR_ERR_ALLOC;
	}

	if (qt_handle->quota_list!=NULL) {
		free_ntquota_list(&(qt_handle->quota_list));
	}
	for (i = 0; i < elems; i++) {
		SMB_NTQUOTA_STRUCT qt;
		SMB_NTQUOTA_LIST *list_item;
		bool ok;

		if (!NT_STATUS_IS_OK(vfs_get_ntquota(fsp,
						     SMB_USER_QUOTA_TYPE,
						     &sids[i], &qt))) {
			/* non fatal error, return empty item in result */
			ZERO_STRUCT(qt);
			continue;
		}


		list_item = talloc_zero(list_ctx, SMB_NTQUOTA_LIST);
		if (list_item == NULL) {
			DBG_ERR("failed to allocate\n");
			return NDR_ERR_ALLOC;
		}

		ok = sid_to_uid(&sids[i], &list_item->uid);
		if (!ok) {
			struct dom_sid_buf buf;
			DBG_WARNING("Could not convert SID %s to uid\n",
				    dom_sid_str_buf(&sids[i], &buf));
			/* No idea what to return here... */
			return NDR_ERR_INVALID_POINTER;
		}

		list_item->quotas = talloc_zero(list_item, SMB_NTQUOTA_STRUCT);
		if (list_item->quotas == NULL) {
			DBG_ERR("failed to allocate\n");
			return NDR_ERR_ALLOC;
		}

		*list_item->quotas = qt;
		list_item->mem_ctx = list_ctx;
		DLIST_ADD(qt_handle->quota_list, list_item);
	}
	qt_handle->tmp_list = qt_handle->quota_list;
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code extract_sids_from_buf(TALLOC_CTX *mem_ctx,
				  uint32_t sidlistlength,
				  DATA_BLOB *sid_buf,
				  struct dom_sid **sids,
				  uint32_t *num)
{
	DATA_BLOB blob;
	uint32_t i = 0;
	enum ndr_err_code err;

	struct sid_list_elem {
		struct sid_list_elem *prev, *next;
		struct dom_sid sid;
	};

	struct sid_list_elem *sid_list = NULL;
	struct sid_list_elem *iter = NULL;
	TALLOC_CTX *list_ctx = talloc_init("sid_list");
	if (!list_ctx) {
		DBG_ERR("OOM\n");
		err = NDR_ERR_ALLOC;
		goto done;
	}

	*num = 0;
	*sids = NULL;

	if (sidlistlength) {
		uint32_t offset = 0;
		struct ndr_pull *ndr_pull = NULL;

		if (sidlistlength > sid_buf->length) {
			DBG_ERR("sid_list_length 0x%x exceeds "
				"available bytes %zx\n",
				sidlistlength,
				sid_buf->length);
			err = NDR_ERR_OFFSET;
			goto done;
		}
		while (true) {
			struct file_get_quota_info info;
			struct sid_list_elem *item = NULL;
			uint32_t new_offset = 0;
			blob.data = sid_buf->data + offset;
			blob.length = sidlistlength - offset;
			ndr_pull = ndr_pull_init_blob(&blob, list_ctx);
			if (!ndr_pull) {
				DBG_ERR("OOM\n");
				err = NDR_ERR_ALLOC;
				goto done;
			}
			err = ndr_pull_file_get_quota_info(ndr_pull,
					   NDR_SCALARS | NDR_BUFFERS, &info);
			if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
				DBG_ERR("Failed to pull file_get_quota_info "
					"from sidlist buffer\n");
				goto done;
			}
			item = talloc_zero(list_ctx, struct sid_list_elem);
			if (!item) {
				DBG_ERR("OOM\n");
				err = NDR_ERR_ALLOC;
				goto done;
			}
			item->sid = info.sid;
			DLIST_ADD(sid_list, item);
			i++;
			if (i == UINT32_MAX) {
				DBG_ERR("Integer overflow\n");
				err = NDR_ERR_ARRAY_SIZE;
				goto done;
			}
			new_offset = info.next_entry_offset;

			/* if new_offset == 0 no more sid(s) to read. */
			if (new_offset == 0) {
				break;
			}

			/* Integer wrap? */
			if ((offset + new_offset) < offset) {
				DBG_ERR("Integer wrap while adding "
					"new_offset 0x%x to current "
					"buffer offset 0x%x\n",
					new_offset, offset);
				err = NDR_ERR_OFFSET;
				goto done;
			}

			offset += new_offset;

			/* check if new offset is outside buffer boundary. */
			if (offset >= sidlistlength) {
				DBG_ERR("bufsize 0x%x exceeded by "
                                        "new offset 0x%x)\n",
					sidlistlength,
					offset);
				err = NDR_ERR_OFFSET;
				goto done;
			}
		}
		*sids = talloc_zero_array(mem_ctx, struct dom_sid, i);
		if (*sids == NULL) {
			DBG_ERR("OOM\n");
			err = NDR_ERR_ALLOC;
			goto done;
		}

		*num = i;

		for (iter = sid_list, i = 0; iter; iter = iter->next, i++) {
			struct dom_sid_buf buf;
			(*sids)[i] = iter->sid;
			DBG_DEBUG("quota SID[%u] %s\n",
				(unsigned int)i,
				dom_sid_str_buf(&iter->sid, &buf));
		}
	}
	err = NDR_ERR_SUCCESS;
done:
	TALLOC_FREE(list_ctx);
	return err;
}

NTSTATUS smbd_do_query_getinfo_quota(TALLOC_CTX *mem_ctx,
				     files_struct *fsp,
				     bool restart_scan,
				     bool return_single,
				     uint32_t sid_list_length,
				     DATA_BLOB *sid_buf,
				     uint32_t max_data_count,
				     uint8_t **p_data,
				     uint32_t *p_data_size)
{
	NTSTATUS status;
	SMB_NTQUOTA_HANDLE *qt_handle = NULL;
	SMB_NTQUOTA_LIST *qt_list = NULL;
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	qt_handle =
		(SMB_NTQUOTA_HANDLE *)fsp->fake_file_handle->private_data;

	if (sid_list_length ) {
		struct dom_sid *sids;
		uint32_t elems = 0;
		/*
		 * error check pulled offsets and lengths for wrap and
		 * exceeding available bytes.
		 */
		if (sid_list_length > sid_buf->length) {
			DBG_ERR("sid_list_length 0x%x exceeds "
				"available bytes %zx\n",
				sid_list_length,
				sid_buf->length);
			return NT_STATUS_INVALID_PARAMETER;
		}

		err = extract_sids_from_buf(mem_ctx, sid_list_length,
					    sid_buf, &sids, &elems);
		if (!NDR_ERR_CODE_IS_SUCCESS(err) || elems == 0) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		err = fill_qtlist_from_sids(mem_ctx,
					    fsp,
					    qt_handle,
					    sids,
					    elems);
		if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
			return NT_STATUS_INVALID_PARAMETER;
		}
	} else if (restart_scan) {
		if (vfs_get_user_ntquota_list(fsp,
					      &(qt_handle->quota_list))!=0) {
			return NT_STATUS_INTERNAL_ERROR;
		}
	} else {
		if (qt_handle->quota_list!=NULL &&
			qt_handle->tmp_list==NULL) {
			free_ntquota_list(&(qt_handle->quota_list));
		}
	}

	if (restart_scan !=0 ) {
		qt_list = qt_handle->quota_list;
	} else {
		qt_list = qt_handle->tmp_list;
	}
	status = fill_quota_buffer(mem_ctx, qt_list,
				   return_single != 0,
				   max_data_count,
				   &blob,
				   &qt_handle->tmp_list);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (blob.length > max_data_count) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	*p_data = blob.data;
	*p_data_size = blob.length;
	return NT_STATUS_OK;
}
#endif /* HAVE_SYS_QUOTAS */
