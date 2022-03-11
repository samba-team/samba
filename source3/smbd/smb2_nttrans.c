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
#include "libsmb/libsmb.h"
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

	if (!CAN_WRITE(fsp->conn)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!lp_nt_acl_support(SNUM(fsp->conn))) {
		return NT_STATUS_OK;
	}

	status = refuse_symlink_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("ACL set on symlink %s denied.\n",
			fsp_str_dbg(fsp));
		return status;
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
		if (!(fsp->access_mask & SEC_STD_WRITE_OWNER)) {
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	if (security_info_sent & SECINFO_GROUP) {
		if (!(fsp->access_mask & SEC_STD_WRITE_OWNER)) {
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	if (security_info_sent & SECINFO_DACL) {
		if (!(fsp->access_mask & SEC_STD_WRITE_DAC)) {
			return NT_STATUS_ACCESS_DENIED;
		}
		/* Convert all the generic bits. */
		if (psd->dacl) {
			security_acl_map_generic(psd->dacl, &file_generic_mapping);
		}
	}

	if (security_info_sent & SECINFO_SACL) {
		if (!(fsp->access_mask & SEC_FLAG_SYSTEM_SECURITY)) {
			return NT_STATUS_ACCESS_DENIED;
		}
		/*
		 * Setting a SACL also requires WRITE_DAC.
		 * See the smbtorture3 SMB2-SACL test.
		 */
		if (!(fsp->access_mask & SEC_STD_WRITE_DAC)) {
			return NT_STATUS_ACCESS_DENIED;
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

	return status;
}

/****************************************************************************
 Internal fn to set security descriptors from a data blob.
****************************************************************************/

NTSTATUS set_sd_blob(files_struct *fsp, uint8_t *data, uint32_t sd_len,
		       uint32_t security_info_sent)
{
	struct security_descriptor *psd = NULL;
	NTSTATUS status;

	if (sd_len == 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = unmarshall_sec_desc(talloc_tos(), data, sd_len, &psd);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return set_sd(fsp, psd, security_info_sent);
}

/****************************************************************************
 Copy a file.
****************************************************************************/

NTSTATUS copy_internals(TALLOC_CTX *ctx,
			connection_struct *conn,
			struct smb_request *req,
			struct smb_filename *smb_fname_src,
			struct smb_filename *smb_fname_dst,
			uint32_t attrs)
{
	files_struct *fsp1,*fsp2;
	uint32_t fattr;
	int info;
	off_t ret=-1;
	NTSTATUS status = NT_STATUS_OK;
	struct smb_filename *parent = NULL;
	struct smb_filename *pathref = NULL;

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

	/* No links from a directory. */
	if (S_ISDIR(smb_fname_src->st.st_ex_mode)) {
		status = NT_STATUS_FILE_IS_A_DIRECTORY;
		goto out;
	}

	DEBUG(10,("copy_internals: doing file copy %s to %s\n",
		  smb_fname_str_dbg(smb_fname_src),
		  smb_fname_str_dbg(smb_fname_dst)));

        status = SMB_VFS_CREATE_FILE(
		conn,					/* conn */
		req,					/* req */
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

	status = SMB_VFS_PARENT_PATHNAME(conn,
					 talloc_tos(),
					 smb_fname_dst,
					 &parent,
					 NULL);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}
	if (smb_fname_dst->fsp == NULL) {
		status = synthetic_pathref(parent,
					conn->cwd_fsp,
					smb_fname_dst->base_name,
					smb_fname_dst->stream_name,
					NULL,
					smb_fname_dst->twrp,
					smb_fname_dst->flags,
					&pathref);

		/* should we handle NT_STATUS_OBJECT_NAME_NOT_FOUND specially here ???? */
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(parent);
			goto out;
		}
		file_set_dosmode(conn, pathref, fattr, parent, false);
		smb_fname_dst->st.st_ex_mode = pathref->st.st_ex_mode;
	} else {
		file_set_dosmode(conn, smb_fname_dst, fattr, parent, false);
	}
	TALLOC_FREE(parent);

	if (ret < (off_t)smb_fname_src->st.st_ex_size) {
		status = NT_STATUS_DISK_FULL;
		goto out;
	}
 out:
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3,("copy_internals: Error %s copy file %s to %s\n",
			nt_errstr(status), smb_fname_str_dbg(smb_fname_src),
			smb_fname_str_dbg(smb_fname_dst)));
	}

	return status;
}
