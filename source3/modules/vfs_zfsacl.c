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

#if HAVE_FREEBSD_SUNACL_H
#include "sunacl.h"
#endif

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#define ZFSACL_MODULE_NAME "zfsacl"

/* zfs_get_nt_acl()
 * read the local file's acls and return it in NT form
 * using the NFSv4 format conversion
 */
static NTSTATUS zfs_get_nt_acl_common(struct connection_struct *conn,
				      TALLOC_CTX *mem_ctx,
				      const struct smb_filename *smb_fname,
				      struct SMB4ACL_T **ppacl)
{
	int naces, i;
	ace_t *acebuf;
	struct SMB4ACL_T *pacl;
	SMB_STRUCT_STAT sbuf;
	const SMB_STRUCT_STAT *psbuf = NULL;
	int ret;

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

	if (S_ISDIR(psbuf->st_ex_mode) && (ace->aceMask & SMB_ACE4_ADD_FILE)) {
		ace->aceMask |= SMB_ACE4_DELETE_CHILD;
	}

	/* read the number of file aces */
	if((naces = acl(smb_fname->base_name, ACE_GETACLCNT, 0, NULL)) == -1) {
		if(errno == ENOSYS) {
			DEBUG(9, ("acl(ACE_GETACLCNT, %s): Operation is not "
				  "supported on the filesystem where the file "
				  "reside\n", smb_fname->base_name));
		} else {
			DEBUG(9, ("acl(ACE_GETACLCNT, %s): %s ", smb_fname->base_name,
					strerror(errno)));
		}
		return map_nt_error_from_unix(errno);
	}
	/* allocate the field of ZFS aces */
	mem_ctx = talloc_tos();
	acebuf = (ace_t *) talloc_size(mem_ctx, sizeof(ace_t)*naces);
	if(acebuf == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	/* read the aces into the field */
	if(acl(smb_fname->base_name, ACE_GETACL, naces, acebuf) < 0) {
		DEBUG(9, ("acl(ACE_GETACL, %s): %s ", smb_fname->base_name,
				strerror(errno)));
		return map_nt_error_from_unix(errno);
	}
	/* create SMB4ACL data */
	if((pacl = smb_create_smb4acl(mem_ctx)) == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	for(i=0; i<naces; i++) {
		SMB_ACE4PROP_T aceprop;

		aceprop.aceType  = (uint32_t) acebuf[i].a_type;
		aceprop.aceFlags = (uint32_t) acebuf[i].a_flags;
		aceprop.aceMask  = (uint32_t) acebuf[i].a_access_mask;
		aceprop.who.id   = (uint32_t) acebuf[i].a_who;

		/*
		 * Windows clients expect SYNC on acls to correctly allow
		 * rename, cf bug #7909. But not on DENY ace entries, cf bug
		 * #8442.
		 */
		if (aceprop.aceType == SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE) {
			aceprop.aceMask |= SMB_ACE4_SYNCHRONIZE;
		}

		if(aceprop.aceFlags & ACE_OWNER) {
			aceprop.flags = SMB_ACE4_ID_SPECIAL;
			aceprop.who.special_id = SMB_ACE4_WHO_OWNER;
		} else if(aceprop.aceFlags & ACE_GROUP) {
			aceprop.flags = SMB_ACE4_ID_SPECIAL;
			aceprop.who.special_id = SMB_ACE4_WHO_GROUP;
		} else if(aceprop.aceFlags & ACE_EVERYONE) {
			aceprop.flags = SMB_ACE4_ID_SPECIAL;
			aceprop.who.special_id = SMB_ACE4_WHO_EVERYONE;
		} else {
			aceprop.flags	= 0;
		}
		if(smb_add_ace4(pacl, &aceprop) == NULL)
			return NT_STATUS_NO_MEMORY;
	}

	*ppacl = pacl;
	return NT_STATUS_OK;
}

/* call-back function processing the NT acl -> ZFS acl using NFSv4 conv. */
static bool zfs_process_smbacl(vfs_handle_struct *handle, files_struct *fsp,
			       struct SMB4ACL_T *smbacl)
{
	int naces = smb_get_naces(smbacl), i;
	ace_t *acebuf;
	struct SMB4ACE_T *smbace;
	TALLOC_CTX	*mem_ctx;
	bool have_special_id = false;

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

	if (!have_special_id
	    && lp_parm_bool(fsp->conn->params->service, "zfsacl",
			    "denymissingspecial", false)) {
		errno = EACCES;
		return false;
	}

	SMB_ASSERT(i == naces);

	/* store acl */
	if(acl(fsp->fsp_name->base_name, ACE_SETACL, naces, acebuf)) {
		if(errno == ENOSYS) {
			DEBUG(9, ("acl(ACE_SETACL, %s): Operation is not "
				  "supported on the filesystem where the file "
				  "reside", fsp_str_dbg(fsp)));
		} else {
			DEBUG(9, ("acl(ACE_SETACL, %s): %s ", fsp_str_dbg(fsp),
				  strerror(errno)));
		}
		return 0;
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
        return smb_set_nt_acl_nfs4(handle, fsp, NULL, security_info_sent, psd,
				   zfs_process_smbacl);
}

static NTSTATUS zfsacl_fget_nt_acl(struct vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   uint32_t security_info,
				   TALLOC_CTX *mem_ctx,
				   struct security_descriptor **ppdesc)
{
	struct SMB4ACL_T *pacl;
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();

	status = zfs_get_nt_acl_common(handle->conn, frame,
				       fsp->fsp_name, &pacl);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = smb_fget_nt_acl_nfs4(fsp, NULL, security_info, mem_ctx,
				      ppdesc, pacl);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS zfsacl_get_nt_acl(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint32_t security_info,
				TALLOC_CTX *mem_ctx,
				struct security_descriptor **ppdesc)
{
	struct SMB4ACL_T *pacl;
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();

	status = zfs_get_nt_acl_common(handle->conn, frame, smb_fname, &pacl);
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
   implemets a compatibility wrapper, which will make calls to
   traditional ACL calls though vfs_solarisacl succeed. As the
   compatibility wrapper's implementation is (by design) incomplete,
   we want to make sure that it is never being called.

   As long as Samba does not support an exiplicit method for a module
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

/* VFS operations structure */

static struct vfs_fn_pointers zfsacl_fns = {
	.sys_acl_get_file_fn = zfsacl_fail__sys_acl_get_file,
	.sys_acl_get_fd_fn = zfsacl_fail__sys_acl_get_fd,
	.sys_acl_blob_get_file_fn = zfsacl_fail__sys_acl_blob_get_file,
	.sys_acl_blob_get_fd_fn = zfsacl_fail__sys_acl_blob_get_fd,
	.sys_acl_set_file_fn = zfsacl_fail__sys_acl_set_file,
	.sys_acl_set_fd_fn = zfsacl_fail__sys_acl_set_fd,
	.sys_acl_delete_def_file_fn = zfsacl_fail__sys_acl_delete_def_file,
	.fget_nt_acl_fn = zfsacl_fget_nt_acl,
	.get_nt_acl_fn = zfsacl_get_nt_acl,
	.fset_nt_acl_fn = zfsacl_fset_nt_acl,
};

NTSTATUS vfs_zfsacl_init(TALLOC_CTX *);
NTSTATUS vfs_zfsacl_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "zfsacl",
				&zfsacl_fns);
}
