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
 * Copyright (C) Ralph Boehme 2017
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
#include "nfs4acl_xattr.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

static const struct enum_list nfs4acl_encoding[] = {
	{NFS4ACL_ENCODING_NDR, "ndr"},
	{NFS4ACL_ENCODING_XDR, "xdr"},
};

static struct nfs4acl *nfs4acl_blob2acl(DATA_BLOB *blob, TALLOC_CTX *mem_ctx)
{
	enum ndr_err_code ndr_err;
	struct nfs4acl *acl = talloc_zero(mem_ctx, struct nfs4acl);

	if (acl == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	ndr_err = ndr_pull_struct_blob(blob, acl, acl,
		(ndr_pull_flags_fn_t)ndr_pull_nfs4acl);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_ERR("ndr_pull_acl_t failed: %s\n", ndr_errstr(ndr_err));
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
		DBG_ERR("ndr_push_acl_t failed: %s\n", ndr_errstr(ndr_err));
		return data_blob_null;
	}
	return blob;
}

static NTSTATUS nfs4_get_nfs4_acl_common(TALLOC_CTX *mem_ctx,
					 DATA_BLOB *blob,
					 struct SMB4ACL_T **_smb4acl)
{
	struct nfs4acl *nfs4acl = NULL;
	struct SMB4ACL_T *smb4acl = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	int i;

	nfs4acl = nfs4acl_blob2acl(blob, frame);
	if (nfs4acl == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_ERROR;
	}

	smb4acl = smb_create_smb4acl(mem_ctx);
	if (smb4acl == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < nfs4acl->a_count; i++) {
		SMB_ACE4PROP_T aceprop;

		aceprop.aceType  = (uint32_t) nfs4acl->ace[i].e_type;
		aceprop.aceFlags = (uint32_t) nfs4acl->ace[i].e_flags;
		aceprop.aceMask  = (uint32_t) nfs4acl->ace[i].e_mask;
		aceprop.who.id   = (uint32_t) nfs4acl->ace[i].e_id;

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
		if (smb_add_ace4(smb4acl, &aceprop) == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	}

	*_smb4acl = smb4acl;
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

/* Fetch the NFSv4 ACL from the xattr, and convert into Samba's internal NFSv4 format */
static NTSTATUS nfs4_fget_nfs4_acl(vfs_handle_struct *handle, TALLOC_CTX *mem_ctx,
				   files_struct *fsp, struct SMB4ACL_T **ppacl)
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
		length = SMB_VFS_NEXT_FGETXATTR(handle, fsp, NFS4ACL_NDR_XATTR_NAME, blob.data, blob.length);
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
static NTSTATUS nfs4_get_nfs4_acl(vfs_handle_struct *handle,
				TALLOC_CTX *mem_ctx,
				const struct smb_filename *smb_fname,
				struct SMB4ACL_T **ppacl)
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
		length = SMB_VFS_NEXT_GETXATTR(handle, smb_fname,
				NFS4ACL_NDR_XATTR_NAME, blob.data, blob.length);
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
				    struct SMB4ACL_T *smbacl,
				    struct nfs4acl **_nfs4acl,
				    bool denymissingspecial)
{
	struct nfs4acl *nfs4acl = NULL;
	struct SMB4ACE_T *smbace = NULL;
	bool have_special_id = false;
	int i;

	nfs4acl = talloc_zero(mem_ctx, struct nfs4acl);
	if (nfs4acl == NULL) {
		errno = ENOMEM;
		return false;
	}

	nfs4acl->a_count = smb_get_naces(smbacl);

	nfs4acl->ace = talloc_zero_array(nfs4acl, struct nfs4ace,
					 nfs4acl->a_count);
	if (nfs4acl->ace == NULL) {
		TALLOC_FREE(nfs4acl);
		errno = ENOMEM;
		return false;
	}

	for (smbace = smb_first_ace4(smbacl), i = 0;
	     smbace != NULL;
	     smbace = smb_next_ace4(smbace), i++)
	{
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
				DBG_DEBUG("unsupported special_id %d\n",
					  aceprop->who.special_id);
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

	*_nfs4acl = nfs4acl;
	return true;
}

/* call-back function processing the NT acl -> NFS4 acl using NFSv4 conv. */
static bool nfs4acl_xattr_fset_smb4acl(vfs_handle_struct *handle,
				       files_struct *fsp,
				       struct SMB4ACL_T *smbacl)
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
		DBG_ERR("Failed to convert ACL to linear blob for xattr\n");
		TALLOC_FREE(frame);
		errno = EINVAL;
		return false;
	}
	if (fsp->fh->fd == -1) {
		DEBUG(0, ("Error: fsp->fh->fd == -1\n"));
	}
	ret = SMB_VFS_NEXT_FSETXATTR(handle, fsp, NFS4ACL_NDR_XATTR_NAME,
				     blob.data, blob.length, 0);
	if (ret != 0) {
		DBG_ERR("can't store acl in xattr: %s\n", strerror(errno));
	}
	TALLOC_FREE(frame);
	return ret == 0;
}

static NTSTATUS nfs4acl_xattr_default_sd(
	struct vfs_handle_struct *handle,
	const struct smb_filename *smb_fname,
	TALLOC_CTX *mem_ctx,
	struct security_descriptor **sd)
{
	struct nfs4acl_config *config = NULL;
	enum default_acl_style default_acl_style;
	mode_t required_mode;
	SMB_STRUCT_STAT sbuf = smb_fname->st;
	int ret;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return NT_STATUS_INTERNAL_ERROR);

	default_acl_style = config->default_acl_style;

	if (!VALID_STAT(sbuf)) {
		ret = vfs_stat_smb_basename(handle->conn,
					    smb_fname,
					    &sbuf);
		if (ret != 0) {
			return map_nt_error_from_unix(errno);
		}
	}

	if (S_ISDIR(sbuf.st_ex_mode)) {
		required_mode = 0777;
	} else {
		required_mode = 0666;
	}
	if ((sbuf.st_ex_mode & required_mode) != required_mode) {
		default_acl_style = DEFAULT_ACL_POSIX;
	}

	return make_default_filesystem_acl(mem_ctx,
					   default_acl_style,
					   smb_fname->base_name,
					   &sbuf,
					   sd);
}

static NTSTATUS nfs4acl_xattr_fget_nt_acl(struct vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   uint32_t security_info,
				   TALLOC_CTX *mem_ctx,
				   struct security_descriptor **sd)
{
	struct SMB4ACL_T *smb4acl = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;

	status = nfs4_fget_nfs4_acl(handle, frame, fsp, &smb4acl);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		TALLOC_FREE(frame);
		return nfs4acl_xattr_default_sd(
			handle, fsp->fsp_name, mem_ctx, sd);
	}
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = smb_fget_nt_acl_nfs4(fsp, NULL, security_info, mem_ctx,
				      sd, smb4acl);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS nfs4acl_xattr_get_nt_acl(struct vfs_handle_struct *handle,
				  const struct smb_filename *smb_fname,
				  uint32_t security_info,
				  TALLOC_CTX *mem_ctx,
				  struct security_descriptor **sd)
{
	struct SMB4ACL_T *smb4acl = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;

	status = nfs4_get_nfs4_acl(handle, frame, smb_fname, &smb4acl);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		TALLOC_FREE(frame);
		return nfs4acl_xattr_default_sd(
			handle,	smb_fname, mem_ctx, sd);
	}
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = smb_get_nt_acl_nfs4(handle->conn, smb_fname, NULL,
				     security_info, mem_ctx, sd,
				     smb4acl);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS nfs4acl_xattr_fset_nt_acl(vfs_handle_struct *handle,
			 files_struct *fsp,
			 uint32_t security_info_sent,
			 const struct security_descriptor *psd)
{
	return smb_set_nt_acl_nfs4(handle, fsp, NULL, security_info_sent,
				   psd,	nfs4acl_xattr_fset_smb4acl);
}

static int nfs4acl_connect(struct vfs_handle_struct *handle,
			   const char *service,
			   const char *user)
{
	struct nfs4acl_config *config = NULL;
	const struct enum_list *default_acl_style_list = NULL;
	const char *default_xattr_name = NULL;
	int enumval;
	unsigned nfs_version;
	int ret;

	default_acl_style_list = get_default_acl_style_list();

	config = talloc_zero(handle->conn, struct nfs4acl_config);
	if (config == NULL) {
		DBG_ERR("talloc_zero() failed\n");
		return -1;
	}

	ret = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (ret < 0) {
		TALLOC_FREE(config);
		return ret;
	}

	ret = smbacl4_get_vfs_params(handle->conn, &config->nfs4_params);
	if (ret < 0) {
		TALLOC_FREE(config);
		return ret;
	}

	enumval = lp_parm_enum(SNUM(handle->conn),
			       "nfs4acl_xattr",
			       "encoding",
			       nfs4acl_encoding,
			       NFS4ACL_ENCODING_NDR);
	if (enumval == -1) {
		DBG_ERR("Invalid \"nfs4acl_xattr:encoding\" parameter\n");
		return -1;
	}
	config->encoding = (enum nfs4acl_encoding)enumval;

	switch (config->encoding) {
	case NFS4ACL_ENCODING_NDR:
	default:
		default_xattr_name = NFS4ACL_NDR_XATTR_NAME;
		break;
	}

	nfs_version = (unsigned)lp_parm_int(SNUM(handle->conn),
					    "nfs4acl_xattr",
					    "version",
					    40);
	switch (nfs_version) {
	case 40:
		config->nfs_version = ACL4_XATTR_VERSION_40;
		break;
	default:
		config->nfs_version = ACL4_XATTR_VERSION_DEFAULT;
		break;
	}

	config->default_acl_style = lp_parm_enum(SNUM(handle->conn),
						 "nfs4acl_xattr",
						 "default acl style",
						 default_acl_style_list,
						 DEFAULT_ACL_EVERYONE);

	config->xattr_name = lp_parm_talloc_string(config,
						   SNUM(handle->conn),
						   "nfs4acl_xattr",
						   "xattr_name",
						   default_xattr_name);

	SMB_VFS_HANDLE_SET_DATA(handle, config, NULL, struct nfs4acl_config,
				return -1);

	/*
	 * Ensure we have the parameters correct if we're using this module.
	 */
	DBG_NOTICE("Setting 'inherit acls = true', "
		   "'dos filemode = true', "
		   "'force unknown acl user = true', "
		   "'create mask = 0666', "
		   "'directory mask = 0777' and "
		   "'store dos attributes = yes' "
		   "for service [%s]\n", service);

	lp_do_parameter(SNUM(handle->conn), "inherit acls", "true");
	lp_do_parameter(SNUM(handle->conn), "dos filemode", "true");
	lp_do_parameter(SNUM(handle->conn), "force unknown acl user", "true");
	lp_do_parameter(SNUM(handle->conn), "create mask", "0666");
	lp_do_parameter(SNUM(handle->conn), "directory mask", "0777");
	lp_do_parameter(SNUM(handle->conn), "store dos attributes", "yes");

	return 0;
}

/*
   As long as Samba does not support an exiplicit method for a module
   to define conflicting vfs methods, we should override all conflicting
   methods here.  That way, we know we are using the NFSv4 storage

   Function declarations taken from vfs_solarisacl
*/

static SMB_ACL_T nfs4acl_xattr_fail__sys_acl_get_file(vfs_handle_struct *handle,
					const struct smb_filename *smb_fname,
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
					 const struct smb_filename *smb_fname,
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
			const struct smb_filename *smb_fname)
{
	return -1;
}

static int nfs4acl_xattr_fail__sys_acl_blob_get_file(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			TALLOC_CTX *mem_ctx,
			char **blob_description,
			DATA_BLOB *blob)
{
	return -1;
}

static int nfs4acl_xattr_fail__sys_acl_blob_get_fd(vfs_handle_struct *handle, files_struct *fsp, TALLOC_CTX *mem_ctx, char **blob_description, DATA_BLOB *blob)
{
	return -1;
}

/* VFS operations structure */

static struct vfs_fn_pointers nfs4acl_xattr_fns = {
	.connect_fn = nfs4acl_connect,
	.fget_nt_acl_fn = nfs4acl_xattr_fget_nt_acl,
	.get_nt_acl_fn = nfs4acl_xattr_get_nt_acl,
	.fset_nt_acl_fn = nfs4acl_xattr_fset_nt_acl,

	.sys_acl_get_file_fn = nfs4acl_xattr_fail__sys_acl_get_file,
	.sys_acl_get_fd_fn = nfs4acl_xattr_fail__sys_acl_get_fd,
	.sys_acl_blob_get_file_fn = nfs4acl_xattr_fail__sys_acl_blob_get_file,
	.sys_acl_blob_get_fd_fn = nfs4acl_xattr_fail__sys_acl_blob_get_fd,
	.sys_acl_set_file_fn = nfs4acl_xattr_fail__sys_acl_set_file,
	.sys_acl_set_fd_fn = nfs4acl_xattr_fail__sys_acl_set_fd,
	.sys_acl_delete_def_file_fn = nfs4acl_xattr_fail__sys_acl_delete_def_file,
};

NTSTATUS vfs_nfs4acl_xattr_init(TALLOC_CTX *);
NTSTATUS vfs_nfs4acl_xattr_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "nfs4acl_xattr",
				&nfs4acl_xattr_fns);
}
