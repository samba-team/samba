/*
 * Convert NFSv4 acls stored per http://www.suse.de/~agruen/nfs4acl/ to NT acls and vice versa.
 *
 * Copyright (C) Jiri Sasek, 2007
 * based on the foobar.c module which is copyrighted by Volker Lendecke
 * based on pvfs_acl_nfs4.c  Copyright (C) Andrew Tridgell 2006
 *
 * based on vfs_fake_acls:
 * Copyright (C) Tim Potter, 1999-2000
 * Copyright (C) Alexander Bokovoy, 2002
 * Copyright (C) Andrew Bartlett, 2002,2012
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
#include "librpc/gen_ndr/ndr_nfs4acl.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

static struct nfs4acl *nfs4acl_blob2acl(DATA_BLOB *blob, TALLOC_CTX *mem_ctx)
{
	enum ndr_err_code ndr_err;
	struct nfs4acl *acl = talloc(mem_ctx, struct nfs4acl);
	if (!acl) {
		errno = ENOMEM;
		return NULL;
	}

	ndr_err = ndr_pull_struct_blob(blob, acl, acl,
		(ndr_pull_flags_fn_t)ndr_pull_nfs4acl);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0, ("ndr_pull_acl_t failed: %s\n",
			  ndr_errstr(ndr_err)));
		TALLOC_FREE(acl);
		return NULL;
	}
	return acl;
}

static DATA_BLOB nfs4acl_acl2blob(TALLOC_CTX *mem_ctx, struct nfs4acl *acl)
{
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;
	ndr_err = ndr_push_struct_blob(&blob, mem_ctx, acl,
		(ndr_push_flags_fn_t)ndr_push_nfs4acl);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0, ("ndr_push_acl_t failed: %s\n",
			  ndr_errstr(ndr_err)));
		return data_blob_null;
	}
	return blob;
}

static NTSTATUS nfs4_get_nfs4_acl_common(TALLOC_CTX *mem_ctx,
					 DATA_BLOB *blob,
					 SMB4ACL_T **ppacl)
{
	int i;
	struct nfs4acl *nfs4acl = NULL;
	SMB4ACL_T *pacl = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	nfs4acl = nfs4acl_blob2acl(blob, frame);

	/* create SMB4ACL data */
	if((pacl = smb_create_smb4acl(mem_ctx)) == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	for(i=0; i<nfs4acl->a_count; i++) {
		SMB_ACE4PROP_T aceprop;

		aceprop.aceType  = (uint32) nfs4acl->ace[i].e_type;
		aceprop.aceFlags = (uint32) nfs4acl->ace[i].e_flags;
		aceprop.aceMask  = (uint32) nfs4acl->ace[i].e_mask;
		aceprop.who.id   = (uint32) nfs4acl->ace[i].e_id;
		if (!strcmp(nfs4acl->ace[i].e_who,
			    NFS4ACL_XATTR_OWNER_WHO)) {
			aceprop.flags = SMB_ACE4_ID_SPECIAL;
			aceprop.who.special_id = SMB_ACE4_WHO_OWNER;
		} else if (!strcmp(nfs4acl->ace[i].e_who,
				   NFS4ACL_XATTR_GROUP_WHO)) {
			aceprop.flags = SMB_ACE4_ID_SPECIAL;
			aceprop.who.special_id = SMB_ACE4_WHO_GROUP;
		} else if (!strcmp(nfs4acl->ace[i].e_who,
				   NFS4ACL_XATTR_EVERYONE_WHO)) {
			aceprop.flags = SMB_ACE4_ID_SPECIAL;
			aceprop.who.special_id = SMB_ACE4_WHO_EVERYONE;
		} else {
			aceprop.flags = 0;
		}
		if(smb_add_ace4(pacl, &aceprop) == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	}

	*ppacl = pacl;
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

/* Fetch the NFSv4 ACL from the xattr, and convert into Samba's internal NFSv4 format */
static NTSTATUS nfs4_fget_nfs4_acl(vfs_handle_struct *handle, TALLOC_CTX *mem_ctx,
				   files_struct *fsp, SMB4ACL_T **ppacl)
{
	NTSTATUS status;
	DATA_BLOB blob = data_blob_null;
	ssize_t length;
	TALLOC_CTX *frame = talloc_stackframe();

	do {
		blob.length += 1000;
		blob.data = talloc_realloc(frame, blob.data, uint8_t, blob.length);
		if (!blob.data) {
			TALLOC_FREE(frame);
			errno = ENOMEM;
			return NT_STATUS_NO_MEMORY;
		}
		length = SMB_VFS_NEXT_FGETXATTR(handle, fsp, NFS4ACL_XATTR_NAME, blob.data, blob.length);
		blob.length = length;
	} while (length == -1 && errno == ERANGE);
	if (length == -1) {
		TALLOC_FREE(frame);
		return map_nt_error_from_unix(errno);
	}
	status = nfs4_get_nfs4_acl_common(mem_ctx, &blob, ppacl);
	TALLOC_FREE(frame);
	return status;
}

/* Fetch the NFSv4 ACL from the xattr, and convert into Samba's internal NFSv4 format */
static NTSTATUS nfs4_get_nfs4_acl(vfs_handle_struct *handle, TALLOC_CTX *mem_ctx,
				  const char *path, SMB4ACL_T **ppacl)
{
	NTSTATUS status;
	DATA_BLOB blob = data_blob_null;
	ssize_t length;
	TALLOC_CTX *frame = talloc_stackframe();

	do {
		blob.length += 1000;
		blob.data = talloc_realloc(frame, blob.data, uint8_t, blob.length);
		if (!blob.data) {
			TALLOC_FREE(frame);
			errno = ENOMEM;
			return NT_STATUS_NO_MEMORY;
		}
		length = SMB_VFS_NEXT_GETXATTR(handle, path, NFS4ACL_XATTR_NAME, blob.data, blob.length);
		blob.length = length;
	} while (length == -1 && errno == ERANGE);
	if (length == -1) {
		TALLOC_FREE(frame);
		return map_nt_error_from_unix(errno);
	}
	status = nfs4_get_nfs4_acl_common(mem_ctx, &blob, ppacl);
	TALLOC_FREE(frame);
	return status;
}

static bool nfs4acl_smb4acl2nfs4acl(TALLOC_CTX *mem_ctx,
				    SMB4ACL_T *smbacl,
				    struct nfs4acl **pnfs4acl,
				    bool denymissingspecial)
{
	struct nfs4acl *nfs4acl;
	SMB4ACE_T *smbace;
	bool have_special_id = false;
	int i;

	/* allocate the field of NFS4 aces */
	nfs4acl = talloc_zero(mem_ctx, struct nfs4acl);
	if(nfs4acl == NULL) {
		errno = ENOMEM;
		return false;
	}

	nfs4acl->a_count = smb_get_naces(smbacl);

	nfs4acl->ace = talloc_zero_array(nfs4acl, struct nfs4ace,
					 nfs4acl->a_count);
	if(nfs4acl->ace == NULL) {
		TALLOC_FREE(nfs4acl);
		errno = ENOMEM;
		return false;
	}

	/* handle all aces */
	for(smbace = smb_first_ace4(smbacl), i = 0;
			smbace!=NULL;
			smbace = smb_next_ace4(smbace), i++) {
		SMB_ACE4PROP_T *aceprop = smb_get_ace4(smbace);

		nfs4acl->ace[i].e_type        = aceprop->aceType;
		nfs4acl->ace[i].e_flags       = aceprop->aceFlags;
		nfs4acl->ace[i].e_mask        = aceprop->aceMask;
		nfs4acl->ace[i].e_id          = aceprop->who.id;
		if(aceprop->flags & SMB_ACE4_ID_SPECIAL) {
			switch(aceprop->who.special_id) {
			case SMB_ACE4_WHO_EVERYONE:
				nfs4acl->ace[i].e_who =
					NFS4ACL_XATTR_EVERYONE_WHO;
				break;
			case SMB_ACE4_WHO_OWNER:
				nfs4acl->ace[i].e_who =
					NFS4ACL_XATTR_OWNER_WHO;
				break;
			case SMB_ACE4_WHO_GROUP:
				nfs4acl->ace[i].e_who =
					NFS4ACL_XATTR_GROUP_WHO;
				break;
			default:
				DEBUG(8, ("unsupported special_id %d\n", \
					aceprop->who.special_id));
				continue; /* don't add it !!! */
			}
			have_special_id = true;
		} else {
			nfs4acl->ace[i].e_who = "";
		}
	}

	if (!have_special_id && denymissingspecial) {
		TALLOC_FREE(nfs4acl);
		errno = EACCES;
		return false;
	}

	SMB_ASSERT(i == nfs4acl->a_count);

	*pnfs4acl = nfs4acl;
	return true;
}

static bool nfs4acl_xattr_set_smb4acl(vfs_handle_struct *handle,
				      const char *path,
				      SMB4ACL_T *smbacl)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct nfs4acl *nfs4acl;
	int ret;
	bool denymissingspecial;
	DATA_BLOB blob;

	denymissingspecial = lp_parm_bool(handle->conn->params->service,
					  "nfs4acl_xattr",
					  "denymissingspecial", false);

	if (!nfs4acl_smb4acl2nfs4acl(frame, smbacl, &nfs4acl,
				     denymissingspecial)) {
		DEBUG(0, ("Failed to convert smb ACL to nfs4 ACL.\n"));
		TALLOC_FREE(frame);
		return false;
	}

	blob = nfs4acl_acl2blob(frame, nfs4acl);
	if (!blob.data) {
		DEBUG(0, ("Failed to convert ACL to linear blob for xattr\n"));
		TALLOC_FREE(frame);
		errno = EINVAL;
		return false;
	}
	ret = SMB_VFS_NEXT_SETXATTR(handle, path, NFS4ACL_XATTR_NAME,
				    blob.data, blob.length, 0);
	if (ret != 0) {
		DEBUG(0, ("can't store acl in xattr: %s\n", strerror(errno)));
	}
	TALLOC_FREE(frame);
	return ret == 0;
}

/* call-back function processing the NT acl -> NFS4 acl using NFSv4 conv. */
static bool nfs4acl_xattr_fset_smb4acl(vfs_handle_struct *handle,
				       files_struct *fsp,
				       SMB4ACL_T *smbacl)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct nfs4acl *nfs4acl;
	int ret;
	bool denymissingspecial;
	DATA_BLOB blob;

	denymissingspecial = lp_parm_bool(fsp->conn->params->service,
					  "nfs4acl_xattr",
					  "denymissingspecial", false);

	if (!nfs4acl_smb4acl2nfs4acl(frame, smbacl, &nfs4acl,
				     denymissingspecial)) {
		DEBUG(0, ("Failed to convert smb ACL to nfs4 ACL.\n"));
		TALLOC_FREE(frame);
		return false;
	}

	blob = nfs4acl_acl2blob(frame, nfs4acl);
	if (!blob.data) {
		DEBUG(0, ("Failed to convert ACL to linear blob for xattr\n"));
		TALLOC_FREE(frame);
		errno = EINVAL;
		return false;
	}
	if (fsp->fh->fd == -1) {
		DEBUG(0, ("Error: fsp->fh->fd == -1\n"));
	}
	ret = SMB_VFS_NEXT_FSETXATTR(handle, fsp, NFS4ACL_XATTR_NAME,
				     blob.data, blob.length, 0);
	if (ret != 0) {
		DEBUG(0, ("can't store acl in xattr: %s\n", strerror(errno)));
	}
	TALLOC_FREE(frame);
	return ret == 0;
}

/* nfs4_set_nt_acl()
 * set the local file's acls obtaining it in NT form
 * using the NFSv4 format conversion
 */
static NTSTATUS nfs4_set_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
			   uint32 security_info_sent,
			   const struct security_descriptor *psd)
{
	return smb_set_nt_acl_nfs4(handle, fsp, security_info_sent, psd,
			nfs4acl_xattr_fset_smb4acl);
}

static SMB4ACL_T *nfs4acls_defaultacl(TALLOC_CTX *mem_ctx)
{
	SMB4ACL_T *pacl = NULL;
	SMB4ACE_T *pace;
	SMB_ACE4PROP_T ace = { SMB_ACE4_ID_SPECIAL,
		SMB_ACE4_WHO_EVERYONE,
		SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE,
		0,
		SMB_ACE4_ALL_MASKS };

	DEBUG(10, ("Building default full access acl\n"));

	pacl = smb_create_smb4acl(mem_ctx);
	if (pacl == NULL) {
		DEBUG(0, ("talloc failed\n"));
		errno = ENOMEM;
		return NULL;
	}

	pace = smb_add_ace4(pacl, &ace);
	if (pace == NULL) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(pacl);
		errno = ENOMEM;
		return NULL;
	}

	return pacl;
}

/*
 * Because there is no good way to guarantee that a new xattr will be
 * created on file creation there might be no acl xattr on a file when
 * trying to read the acl. In this case the acl xattr will get
 * constructed at that time from the parent acl.
 * If the parent ACL doesn't have an xattr either the call will
 * recurse to the next parent directory until the share root is
 * reached. If the share root doesn't contain an ACL xattr either a
 * default ACL will be used.
 * Also a default ACL will be set if a non inheriting ACL is encountered.
 *
 * Basic algorithm:
 *   read acl xattr blob
 *   if acl xattr blob doesn't exist
 *     stat current directory to know if it's a file or directory
 *     read acl xattr blob from parent dir
 *     acl xattr blob to smb nfs4 acl
 *     calculate inherited smb nfs4 acl
 *     without inheritance use default smb nfs4 acl
 *     smb nfs4 acl to acl xattr blob
 *     set acl xattr blob
 *     return smb nfs4 acl
 *   else
 *     acl xattr blob to smb nfs4 acl
 *
 * Todo: Really use mem_ctx after fixing interface of nfs4_acls
 */
static SMB4ACL_T *nfs4acls_inheritacl(vfs_handle_struct *handle,
	const char *path,
	TALLOC_CTX *mem_ctx)
{
	char *parent_dir = NULL;
	SMB4ACL_T *pparentacl = NULL;
	SMB4ACL_T *pchildacl = NULL;
	SMB4ACE_T *pace;
	SMB_ACE4PROP_T ace;
	bool isdir;
	struct smb_filename *smb_fname = NULL;
	NTSTATUS status;
	int ret;
	TALLOC_CTX *frame = talloc_stackframe();

	DEBUG(10, ("nfs4acls_inheritacl invoked for %s\n", path));
	smb_fname = synthetic_smb_fname(frame, path, NULL, NULL);
	if (smb_fname == NULL) {
		TALLOC_FREE(frame);
		errno = ENOMEM;
		return NULL;
	}

	ret = SMB_VFS_STAT(handle->conn, smb_fname);
	if (ret == -1) {
		DEBUG(0,("nfs4acls_inheritacl: failed to stat "
			 "directory %s. Error was %s\n",
			 smb_fname_str_dbg(smb_fname),
			 strerror(errno)));
		TALLOC_FREE(frame);
		return NULL;
	}
	isdir = S_ISDIR(smb_fname->st.st_ex_mode);

	if (!parent_dirname(talloc_tos(),
			    path,
			    &parent_dir,
			    NULL)) {
		TALLOC_FREE(frame);
		errno = ENOMEM;
		return NULL;
	}

	status = nfs4_get_nfs4_acl(handle, frame, parent_dir, &pparentacl);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)
	    && strncmp(parent_dir, ".", 2) != 0) {
		pparentacl = nfs4acls_inheritacl(handle, parent_dir,
						 frame);
	}
	else if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		pparentacl = nfs4acls_defaultacl(frame);

	}
	else if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	pchildacl = smb_create_smb4acl(mem_ctx);
	if (pchildacl == NULL) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(frame);
		errno = ENOMEM;
		return NULL;
	}

	for (pace = smb_first_ace4(pparentacl); pace != NULL;
	     pace = smb_next_ace4(pace)) {
		SMB4ACE_T *pchildace;
		ace = *smb_get_ace4(pace);
		if (isdir && !(ace.aceFlags & SMB_ACE4_DIRECTORY_INHERIT_ACE)
		    || !isdir && !(ace.aceFlags & SMB_ACE4_FILE_INHERIT_ACE)) {
			DEBUG(10, ("non inheriting ace type: %d, iflags: %x, "
				   "flags: %x, mask: %x, who: %d\n",
				   ace.aceType, ace.flags, ace.aceFlags,
				   ace.aceMask, ace.who.id));
			continue;
		}
		DEBUG(10, ("inheriting ace type: %d, iflags: %x, "
			   "flags: %x, mask: %x, who: %d\n",
			   ace.aceType, ace.flags, ace.aceFlags,
			   ace.aceMask, ace.who.id));
		ace.aceFlags |= SMB_ACE4_INHERITED_ACE;
		if ((isdir && (ace.aceFlags & SMB_ACE4_DIRECTORY_INHERIT_ACE)
		     || !isdir && (ace.aceFlags & SMB_ACE4_FILE_INHERIT_ACE))
		    && ace.aceFlags & SMB_ACE4_INHERIT_ONLY_ACE) {
			ace.aceFlags &= ~SMB_ACE4_INHERIT_ONLY_ACE;
		}
		if (ace.aceFlags & SMB_ACE4_NO_PROPAGATE_INHERIT_ACE) {
			ace.aceFlags &= ~SMB_ACE4_FILE_INHERIT_ACE;
			ace.aceFlags &= ~SMB_ACE4_DIRECTORY_INHERIT_ACE;
			ace.aceFlags &= ~SMB_ACE4_NO_PROPAGATE_INHERIT_ACE;
		}
		pchildace = smb_add_ace4(pchildacl, &ace);
		if (pchildace == NULL) {
			DEBUG(0, ("talloc failed\n"));
			TALLOC_FREE(frame);
			errno = ENOMEM;
			return NULL;
		}
	}

	/* Set a default ACL if we didn't inherit anything. */
	if (smb_first_ace4(pchildacl) == NULL) {
		TALLOC_FREE(pchildacl);
		pchildacl = nfs4acls_defaultacl(mem_ctx);
	}

	/* store the returned ACL to get it directly in the
	   future and avoid dynamic inheritance behavior. */
	nfs4acl_xattr_set_smb4acl(handle, path, pchildacl);

	TALLOC_FREE(frame);
	return pchildacl;
}

static NTSTATUS nfs4acl_xattr_fget_nt_acl(struct vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   uint32 security_info,
				   TALLOC_CTX *mem_ctx,
				   struct security_descriptor **ppdesc)
{
	SMB4ACL_T *pacl;
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();

	status = nfs4_fget_nfs4_acl(handle, frame, fsp, &pacl);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		pacl = nfs4acls_inheritacl(handle, fsp->fsp_name->base_name,
					   frame);
	}
	else if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = smb_fget_nt_acl_nfs4(fsp, security_info, mem_ctx, ppdesc, pacl);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS nfs4acl_xattr_get_nt_acl(struct vfs_handle_struct *handle,
				  const char *name, uint32 security_info,
				  TALLOC_CTX *mem_ctx,
				  struct security_descriptor **ppdesc)
{
	SMB4ACL_T *pacl;
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();

	status = nfs4_get_nfs4_acl(handle, frame, name, &pacl);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		pacl = nfs4acls_inheritacl(handle, name, frame);
	}
	else if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = smb_get_nt_acl_nfs4(handle->conn, name, security_info,
				     mem_ctx, ppdesc,
				     pacl);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS nfs4acl_xattr_fset_nt_acl(vfs_handle_struct *handle,
			 files_struct *fsp,
			 uint32 security_info_sent,
			 const struct security_descriptor *psd)
{
	return nfs4_set_nt_acl(handle, fsp, security_info_sent, psd);
}

/*
   As long as Samba does not support an exiplicit method for a module
   to define conflicting vfs methods, we should override all conflicting
   methods here.  That way, we know we are using the NFSv4 storage

   Function declarations taken from vfs_solarisacl
*/

static SMB_ACL_T nfs4acl_xattr_fail__sys_acl_get_file(vfs_handle_struct *handle,
						      const char *path_p,
						      SMB_ACL_TYPE_T type,
						      TALLOC_CTX *mem_ctx)
{
	return (SMB_ACL_T)NULL;
}

static SMB_ACL_T nfs4acl_xattr_fail__sys_acl_get_fd(vfs_handle_struct *handle,
						    files_struct *fsp,
						    TALLOC_CTX *mem_ctx)
{
	return (SMB_ACL_T)NULL;
}

static int nfs4acl_xattr_fail__sys_acl_set_file(vfs_handle_struct *handle,
					 const char *name,
					 SMB_ACL_TYPE_T type,
					 SMB_ACL_T theacl)
{
	return -1;
}

static int nfs4acl_xattr_fail__sys_acl_set_fd(vfs_handle_struct *handle,
				       files_struct *fsp,
				       SMB_ACL_T theacl)
{
	return -1;
}

static int nfs4acl_xattr_fail__sys_acl_delete_def_file(vfs_handle_struct *handle,
						const char *path)
{
	return -1;
}

static int nfs4acl_xattr_fail__sys_acl_blob_get_file(vfs_handle_struct *handle, const char *path_p, TALLOC_CTX *mem_ctx, char **blob_description, DATA_BLOB *blob)
{
	return -1;
}

static int nfs4acl_xattr_fail__sys_acl_blob_get_fd(vfs_handle_struct *handle, files_struct *fsp, TALLOC_CTX *mem_ctx, char **blob_description, DATA_BLOB *blob)
{
	return -1;
}

/* VFS operations structure */

static struct vfs_fn_pointers nfs4acl_xattr_fns = {
	.sys_acl_get_file_fn = nfs4acl_xattr_fail__sys_acl_get_file,
	.sys_acl_get_fd_fn = nfs4acl_xattr_fail__sys_acl_get_fd,
	.sys_acl_blob_get_file_fn = nfs4acl_xattr_fail__sys_acl_blob_get_file,
	.sys_acl_blob_get_fd_fn = nfs4acl_xattr_fail__sys_acl_blob_get_fd,
	.sys_acl_set_file_fn = nfs4acl_xattr_fail__sys_acl_set_file,
	.sys_acl_set_fd_fn = nfs4acl_xattr_fail__sys_acl_set_fd,
	.sys_acl_delete_def_file_fn = nfs4acl_xattr_fail__sys_acl_delete_def_file,
	.fget_nt_acl_fn = nfs4acl_xattr_fget_nt_acl,
	.get_nt_acl_fn = nfs4acl_xattr_get_nt_acl,
	.fset_nt_acl_fn = nfs4acl_xattr_fset_nt_acl,
};

NTSTATUS vfs_nfs4acl_xattr_init(void);
NTSTATUS vfs_nfs4acl_xattr_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "nfs4acl_xattr",
				&nfs4acl_xattr_fns);
}
