/*
 * Convert ZFS/NFSv4 acls to NT acls and vice versa.
 *
 * Copyright (C) Jiri Sasek, 2007
 * based on the foobar.c module which is copyrighted by Volker Lendecke
 *
 * Many thanks to Axel Apitz for help to fix the special ace's handling
 * issues.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "nfs4_acls.h"

#ifdef HAVE_FREEBSD_SUNACL_H
#include "sunacl.h"
#endif

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#define ZFSACL_MODULE_NAME "zfsacl"

struct zfsacl_config_data {
	struct smbacl4_vfs_params nfs4_params;
	bool zfsacl_map_dacl_protected;
	bool zfsacl_denymissingspecial;
	bool zfsacl_block_special;
};

/* zfs_get_nt_acl()
 * read the local file's acls and return it in NT form
 * using the NFSv4 format conversion
 */
static NTSTATUS zfs_get_nt_acl_common(struct connection_struct *conn,
				      TALLOC_CTX *mem_ctx,
				      const struct smb_filename *smb_fname,
				      const ace_t *acebuf,
				      int naces,
				      struct SMB4ACL_T **ppacl,
				      struct zfsacl_config_data *config)
{
	int i;
	struct SMB4ACL_T *pacl;
	SMB_STRUCT_STAT sbuf;
	SMB_ACE4PROP_T blocking_ace;
	const SMB_STRUCT_STAT *psbuf = NULL;
	int ret;
	bool inherited_is_present = false;
	bool is_dir;

	if (VALID_STAT(smb_fname->st)) {
		psbuf = &smb_fname->st;
	}

	if (psbuf == NULL) {
		ret = vfs_stat_smb_basename(conn, smb_fname, &sbuf);
		if (ret != 0) {
			DBG_INFO("stat [%s]failed: %s\n",
				 smb_fname_str_dbg(smb_fname), strerror(errno));
			return map_nt_error_from_unix(errno);
		}
		psbuf = &sbuf;
	}
	is_dir = S_ISDIR(psbuf->st_ex_mode);

	mem_ctx = talloc_tos();

	/* create SMB4ACL data */
	if((pacl = smb_create_smb4acl(mem_ctx)) == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	for(i=0; i<naces; i++) {
		SMB_ACE4PROP_T aceprop;
		uint16_t special = 0;

		aceprop.aceType  = (uint32_t) acebuf[i].a_type;
		aceprop.aceFlags = (uint32_t) acebuf[i].a_flags;
		aceprop.aceMask  = (uint32_t) acebuf[i].a_access_mask;
		aceprop.who.id   = (uint32_t) acebuf[i].a_who;

		if (config->zfsacl_block_special &&
		    (aceprop.aceMask == 0) &&
		    (aceprop.aceFlags & ACE_EVERYONE) &&
		    (aceprop.aceFlags & ACE_INHERITED_ACE))
		{
			continue;
		}
		/*
		 * Windows clients expect SYNC on acls to correctly allow
		 * rename, cf bug #7909. But not on DENY ace entries, cf bug
		 * #8442.
		 */
		if (aceprop.aceType == SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE) {
			aceprop.aceMask |= SMB_ACE4_SYNCHRONIZE;
		}

		special = acebuf[i].a_flags & (ACE_OWNER|ACE_GROUP|ACE_EVERYONE);

		if (is_dir &&
		    (aceprop.aceMask & SMB_ACE4_ADD_FILE) &&
		    (special != 0))
		{
			aceprop.aceMask |= SMB_ACE4_DELETE_CHILD;
		}

#ifdef ACE_INHERITED_ACE
		if (aceprop.aceFlags & ACE_INHERITED_ACE) {
			inherited_is_present = true;
		}
#endif
		switch(special) {
		case(ACE_OWNER):
			aceprop.flags = SMB_ACE4_ID_SPECIAL;
			aceprop.who.special_id = SMB_ACE4_WHO_OWNER;
			break;
		case(ACE_GROUP):
			aceprop.flags = SMB_ACE4_ID_SPECIAL;
			aceprop.who.special_id = SMB_ACE4_WHO_GROUP;
			break;
		case(ACE_EVERYONE):
			aceprop.flags = SMB_ACE4_ID_SPECIAL;
			aceprop.who.special_id = SMB_ACE4_WHO_EVERYONE;
			break;
		default:
			aceprop.flags	= 0;
		}
		if (smb_add_ace4(pacl, &aceprop) == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

#ifdef ACE_INHERITED_ACE
	if (!inherited_is_present && config->zfsacl_map_dacl_protected) {
		DBG_DEBUG("Setting SEC_DESC_DACL_PROTECTED on [%s]\n",
			  smb_fname_str_dbg(smb_fname));
		smbacl4_set_controlflags(pacl,
					 SEC_DESC_DACL_PROTECTED |
					 SEC_DESC_SELF_RELATIVE);
	}
#endif
	*ppacl = pacl;
	return NT_STATUS_OK;
}

/* call-back function processing the NT acl -> ZFS acl using NFSv4 conv. */
static bool zfs_process_smbacl(vfs_handle_struct *handle, files_struct *fsp,
			       struct SMB4ACL_T *smbacl)
{
	int naces = smb_get_naces(smbacl), i, rv;
	ace_t *acebuf;
	struct SMB4ACE_T *smbace;
	TALLOC_CTX	*mem_ctx;
	bool have_special_id = false;
	bool must_add_empty_ace = false;
	struct zfsacl_config_data *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct zfsacl_config_data,
				return False);

	if (config->zfsacl_block_special && S_ISDIR(fsp->fsp_name->st.st_ex_mode)) {
		naces++;
		must_add_empty_ace = true;
	}
	/* allocate the field of ZFS aces */
	mem_ctx = talloc_tos();
	acebuf = (ace_t *) talloc_size(mem_ctx, sizeof(ace_t)*naces);
	if(acebuf == NULL) {
		errno = ENOMEM;
		return False;
	}
	/* handle all aces */
	for(smbace = smb_first_ace4(smbacl), i = 0;
			smbace!=NULL;
			smbace = smb_next_ace4(smbace), i++) {
		SMB_ACE4PROP_T *aceprop = smb_get_ace4(smbace);

		acebuf[i].a_type        = aceprop->aceType;
		acebuf[i].a_flags       = aceprop->aceFlags;
		acebuf[i].a_access_mask = aceprop->aceMask;
		/* SYNC on acls is a no-op on ZFS.
		   See bug #7909. */
		acebuf[i].a_access_mask &= ~SMB_ACE4_SYNCHRONIZE;
		acebuf[i].a_who         = aceprop->who.id;
		if(aceprop->flags & SMB_ACE4_ID_SPECIAL) {
			switch(aceprop->who.special_id) {
			case SMB_ACE4_WHO_EVERYONE:
				acebuf[i].a_flags |= ACE_EVERYONE;
				break;
			case SMB_ACE4_WHO_OWNER:
				acebuf[i].a_flags |= ACE_OWNER;
				break;
			case SMB_ACE4_WHO_GROUP:
				acebuf[i].a_flags |= ACE_GROUP|ACE_IDENTIFIER_GROUP;
				break;
			default:
				DEBUG(8, ("unsupported special_id %d\n", \
					aceprop->who.special_id));
				continue; /* don't add it !!! */
			}
			have_special_id = true;
		}
	}
	if (must_add_empty_ace) {
		acebuf[i].a_type = SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE;
		acebuf[i].a_flags = SMB_ACE4_DIRECTORY_INHERIT_ACE |
			SMB_ACE4_FILE_INHERIT_ACE |
			ACE_EVERYONE |
			ACE_INHERITED_ACE;
		acebuf[i].a_access_mask = 0;
		i++;
	}

	if (!have_special_id && config->zfsacl_denymissingspecial) {
		errno = EACCES;
		return false;
	}

	SMB_ASSERT(i == naces);

	/* store acl */
	if (fsp->fh->fd != -1) {
		rv = facl(fsp->fh->fd, ACE_SETACL, naces, acebuf);
	}
	else {
		rv = acl(fsp->fsp_name->base_name, ACE_SETACL, naces, acebuf);
	}
	if (rv != 0) {
		if(errno == ENOSYS) {
			DEBUG(9, ("acl(ACE_SETACL, %s): Operation is not "
				  "supported on the filesystem where the file "
				  "reside", fsp_str_dbg(fsp)));
		} else {
			DEBUG(9, ("acl(ACE_SETACL, %s): %s ", fsp_str_dbg(fsp),
				  strerror(errno)));
		}
		return false;
	}

	return True;
}

/* zfs_set_nt_acl()
 * set the local file's acls obtaining it in NT form
 * using the NFSv4 format conversion
 */
static NTSTATUS zfs_set_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
			   uint32_t security_info_sent,
			   const struct security_descriptor *psd)
{
	struct zfsacl_config_data *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct zfsacl_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	return smb_set_nt_acl_nfs4(handle,
				fsp,
				&config->nfs4_params,
				security_info_sent,
				psd,
				zfs_process_smbacl);
}

static int get_zfsacl(TALLOC_CTX *mem_ctx,
		      const struct smb_filename *smb_fname,
		      ace_t **outbuf)
{
	int naces, rv;
	ace_t *acebuf = NULL;

	naces = acl(smb_fname->base_name, ACE_GETACLCNT, 0, NULL);
	if (naces == -1) {
		int dbg_level = 10;

		if (errno == ENOSYS) {
			dbg_level = 1;
		}
		DEBUG(dbg_level, ("acl(ACE_GETACLCNT, %s): %s ",
				  smb_fname->base_name, strerror(errno)));
		return naces;
	}
	acebuf = talloc_size(mem_ctx, sizeof(ace_t)*naces);
	if (acebuf == NULL) {
		errno = ENOMEM;
		return -1;
	}

	rv = acl(smb_fname->base_name, ACE_GETACL, naces, acebuf);
	if (rv == -1) {
		DBG_DEBUG("acl(ACE_GETACL, %s) failed: %s ",
			  smb_fname->base_name, strerror(errno));
		return -1;
	}

	*outbuf = acebuf;
	return naces;
}

static int fget_zfsacl(TALLOC_CTX *mem_ctx,
		       struct files_struct *fsp,
		       ace_t **outbuf)
{
	int naces, rv;
	ace_t *acebuf = NULL;

	if (fsp->fh->fd == -1) {
		return get_zfsacl(mem_ctx, fsp->fsp_name, outbuf);
	}

	naces = facl(fsp->fh->fd, ACE_GETACLCNT, 0, NULL);
	if (naces == -1) {
		int dbg_level = 10;

		if (errno == ENOSYS) {
			dbg_level = 1;
		}
		DEBUG(dbg_level, ("facl(ACE_GETACLCNT, %s): %s ",
				  fsp_str_dbg(fsp), strerror(errno)));
		return naces;
	}

	acebuf = talloc_size(mem_ctx, sizeof(ace_t)*naces);
	if (acebuf == NULL) {
		errno = ENOMEM;
		return -1;
	}

	rv = facl(fsp->fh->fd, ACE_GETACL, naces, acebuf);
	if (rv == -1) {
		DBG_DEBUG("acl(ACE_GETACL, %s): %s ",
			  fsp_str_dbg(fsp), strerror(errno));
		return -1;
	}

	*outbuf = acebuf;
	return naces;
}

static NTSTATUS zfsacl_fget_nt_acl(struct vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   uint32_t security_info,
				   TALLOC_CTX *mem_ctx,
				   struct security_descriptor **ppdesc)
{
	struct SMB4ACL_T *pacl;
	NTSTATUS status;
	struct zfsacl_config_data *config = NULL;
	ace_t *acebuf = NULL;
	int naces;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct zfsacl_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	TALLOC_CTX *frame = talloc_stackframe();

	naces = fget_zfsacl(talloc_tos(), fsp, &acebuf);
	if (naces == -1) {
		status = map_nt_error_from_unix(errno);
		TALLOC_FREE(frame);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
			return status;
		}

		status = make_default_filesystem_acl(mem_ctx,
						     DEFAULT_ACL_POSIX,
						     fsp->fsp_name->base_name,
						     &fsp->fsp_name->st,
						     ppdesc);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		(*ppdesc)->type |= SEC_DESC_DACL_PROTECTED;
		return NT_STATUS_OK;
	}

	status = zfs_get_nt_acl_common(handle->conn,
				       frame,
				       fsp->fsp_name,
				       acebuf,
				       naces,
				       &pacl,
				       config);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = smb_fget_nt_acl_nfs4(fsp, NULL, security_info, mem_ctx,
				      ppdesc, pacl);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS zfsacl_get_nt_acl_at(struct vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				uint32_t security_info,
				TALLOC_CTX *mem_ctx,
				struct security_descriptor **ppdesc)
{
	struct SMB4ACL_T *pacl = NULL;
	NTSTATUS status;
	struct zfsacl_config_data *config = NULL;
	TALLOC_CTX *frame = NULL;
	int naces;
	ace_t *acebuf = NULL;

	SMB_ASSERT(dirfsp == handle->conn->cwd_fsp);

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct zfsacl_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	frame = talloc_stackframe();

	naces = get_zfsacl(frame, smb_fname, &acebuf);
	if (naces == -1) {
		status = map_nt_error_from_unix(errno);
		TALLOC_FREE(frame);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
			return status;
		}

		if (!VALID_STAT(smb_fname->st)) {
			DBG_ERR("No stat info for [%s]\n",
				smb_fname_str_dbg(smb_fname));
			return NT_STATUS_INTERNAL_ERROR;
		}

		status = make_default_filesystem_acl(mem_ctx,
						     DEFAULT_ACL_POSIX,
						     smb_fname->base_name,
						     &smb_fname->st,
						     ppdesc);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		(*ppdesc)->type |= SEC_DESC_DACL_PROTECTED;
		return NT_STATUS_OK;
	}

	status = zfs_get_nt_acl_common(handle->conn,
				       frame,
				       smb_fname,
				       acebuf,
				       naces,
				       &pacl,
				       config);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = smb_get_nt_acl_nfs4(handle->conn,
					smb_fname,
					NULL,
					security_info,
					mem_ctx,
					ppdesc,
					pacl);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS zfsacl_fset_nt_acl(vfs_handle_struct *handle,
			 files_struct *fsp,
			 uint32_t security_info_sent,
			 const struct security_descriptor *psd)
{
	return zfs_set_nt_acl(handle, fsp, security_info_sent, psd);
}

/* nils.goroll@hamburg.de 2008-06-16 :

   See also
   - https://bugzilla.samba.org/show_bug.cgi?id=5446
   - http://bugs.opensolaris.org/view_bug.do?bug_id=6688240

   Solaris supports NFSv4 and ZFS ACLs through a common system call, acl(2)
   with ACE_SETACL / ACE_GETACL / ACE_GETACLCNT, which is being wrapped for
   use by samba in this module.

   As the acl(2) interface is identical for ZFS and for NFS, this module,
   vfs_zfsacl, can not only be used for ZFS, but also for sharing NFSv4
   mounts on Solaris.

   But while "traditional" POSIX DRAFT ACLs (using acl(2) with SETACL
   / GETACL / GETACLCNT) fail for ZFS, the Solaris NFS client
   implements a compatibility wrapper, which will make calls to
   traditional ACL calls though vfs_solarisacl succeed. As the
   compatibility wrapper's implementation is (by design) incomplete,
   we want to make sure that it is never being called.

   As long as Samba does not support an explicit method for a module
   to define conflicting vfs methods, we should override all conflicting
   methods here.

   For this to work, we need to make sure that this module is initialised
   *after* vfs_solarisacl

   Function declarations taken from vfs_solarisacl
*/

static SMB_ACL_T zfsacl_fail__sys_acl_get_file(vfs_handle_struct *handle,
					const struct smb_filename *smb_fname,
					SMB_ACL_TYPE_T type,
					TALLOC_CTX *mem_ctx)
{
	return (SMB_ACL_T)NULL;
}

static SMB_ACL_T zfsacl_fail__sys_acl_get_fd(vfs_handle_struct *handle,
					     files_struct *fsp,
					     TALLOC_CTX *mem_ctx)
{
	return (SMB_ACL_T)NULL;
}

static int zfsacl_fail__sys_acl_set_file(vfs_handle_struct *handle,
					 const struct smb_filename *smb_fname,
					 SMB_ACL_TYPE_T type,
					 SMB_ACL_T theacl)
{
	return -1;
}

static int zfsacl_fail__sys_acl_set_fd(vfs_handle_struct *handle,
				       files_struct *fsp,
				       SMB_ACL_T theacl)
{
	return -1;
}

static int zfsacl_fail__sys_acl_delete_def_file(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	return -1;
}

static int zfsacl_fail__sys_acl_blob_get_file(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			TALLOC_CTX *mem_ctx,
			char **blob_description,
			DATA_BLOB *blob)
{
	return -1;
}

static int zfsacl_fail__sys_acl_blob_get_fd(vfs_handle_struct *handle, files_struct *fsp, TALLOC_CTX *mem_ctx, char **blob_description, DATA_BLOB *blob)
{
	return -1;
}

static int zfsacl_connect(struct vfs_handle_struct *handle,
			    const char *service, const char *user)
{
	struct zfsacl_config_data *config = NULL;
	int ret;

	ret = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (ret < 0) {
		return ret;
	}

	config = talloc_zero(handle->conn, struct zfsacl_config_data);
	if (!config) {
		DBG_ERR("talloc_zero() failed\n");
		errno = ENOMEM;
		return -1;
	}

	config->zfsacl_map_dacl_protected = lp_parm_bool(SNUM(handle->conn),
				"zfsacl", "map_dacl_protected", false);

	config->zfsacl_denymissingspecial = lp_parm_bool(SNUM(handle->conn),
				"zfsacl", "denymissingspecial", false);

	config->zfsacl_block_special = lp_parm_bool(SNUM(handle->conn),
				"zfsacl", "block_special", true);

	ret = smbacl4_get_vfs_params(handle->conn, &config->nfs4_params);
	if (ret < 0) {
		TALLOC_FREE(config);
		return ret;
	}

	SMB_VFS_HANDLE_SET_DATA(handle, config,
				NULL, struct zfsacl_config_data,
				return -1);

	return 0;
}

/* VFS operations structure */

static struct vfs_fn_pointers zfsacl_fns = {
	.connect_fn = zfsacl_connect,
	.sys_acl_get_file_fn = zfsacl_fail__sys_acl_get_file,
	.sys_acl_get_fd_fn = zfsacl_fail__sys_acl_get_fd,
	.sys_acl_blob_get_file_fn = zfsacl_fail__sys_acl_blob_get_file,
	.sys_acl_blob_get_fd_fn = zfsacl_fail__sys_acl_blob_get_fd,
	.sys_acl_set_file_fn = zfsacl_fail__sys_acl_set_file,
	.sys_acl_set_fd_fn = zfsacl_fail__sys_acl_set_fd,
	.sys_acl_delete_def_file_fn = zfsacl_fail__sys_acl_delete_def_file,
	.fget_nt_acl_fn = zfsacl_fget_nt_acl,
	.get_nt_acl_at_fn = zfsacl_get_nt_acl_at,
	.fset_nt_acl_fn = zfsacl_fset_nt_acl,
};

static_decl_vfs;
NTSTATUS vfs_zfsacl_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "zfsacl",
				&zfsacl_fns);
}
