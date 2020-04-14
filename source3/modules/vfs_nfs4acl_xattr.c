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
#include "libcli/security/security_token.h"
#include "libcli/security/dom_sid.h"
#include "nfs4_acls.h"
#include "librpc/gen_ndr/ndr_nfs4acl.h"
#include "nfs4acl_xattr.h"
#include "nfs4acl_xattr_ndr.h"
#include "nfs4acl_xattr_xdr.h"
#include "nfs4acl_xattr_nfs.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

static const struct enum_list nfs4acl_encoding[] = {
	{NFS4ACL_ENCODING_NDR, "ndr"},
	{NFS4ACL_ENCODING_XDR, "xdr"},
	{NFS4ACL_ENCODING_NFS, "nfs"},
};

/*
 * Check if someone changed the POSIX mode, for files we expect 0666, for
 * directories 0777. Discard the ACL blob if the mode is different.
 */
static bool nfs4acl_validate_blob(vfs_handle_struct *handle,
				  const struct smb_filename *smb_fname)
{
	struct nfs4acl_config *config = NULL;
	mode_t expected_mode;
	int ret;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return false);

	if (!config->validate_mode) {
		return true;
	}

	if (!VALID_STAT(smb_fname->st)) {
		/* might be a create */
		return true;
	}

	if (S_ISDIR(smb_fname->st.st_ex_mode)) {
		expected_mode = 0777;
	} else {
		expected_mode = 0666;
	}
	if ((smb_fname->st.st_ex_mode & expected_mode) == expected_mode) {
		return true;
	}

	ret = SMB_VFS_NEXT_REMOVEXATTR(handle,
				       smb_fname,
				       config->xattr_name);
	if (ret != 0 && errno != ENOATTR) {
		DBG_ERR("Removing NFS4 xattr failed: %s\n", strerror(errno));
		return false;
	}

	return true;
}

static NTSTATUS nfs4acl_get_blob(struct vfs_handle_struct *handle,
				 files_struct *fsp,
				 const struct smb_filename *smb_fname_in,
				 TALLOC_CTX *mem_ctx,
				 DATA_BLOB *blob)
{
	struct nfs4acl_config *config = NULL;
	const struct smb_filename *smb_fname = NULL;
	size_t allocsize = 256;
	ssize_t length;
	bool ok;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return NT_STATUS_INTERNAL_ERROR);

	*blob = data_blob_null;

	if (fsp == NULL && smb_fname_in == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}
	smb_fname = smb_fname_in;
	if (smb_fname == NULL) {
		smb_fname = fsp->fsp_name;
	}
	if (smb_fname == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	ok = nfs4acl_validate_blob(handle, smb_fname);
	if (!ok) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	do {

		allocsize *= 4;
		ok = data_blob_realloc(mem_ctx, blob, allocsize);
		if (!ok) {
			return NT_STATUS_NO_MEMORY;
		}

		if (fsp != NULL && fsp->fh->fd != -1) {
			length = SMB_VFS_NEXT_FGETXATTR(handle,
							fsp,
							config->xattr_name,
							blob->data,
							blob->length);
		} else {
			length = SMB_VFS_NEXT_GETXATTR(handle,
						       smb_fname,
						       config->xattr_name,
						       blob->data,
						       blob->length);
		}
	} while (length == -1 && errno == ERANGE && allocsize <= 65536);

	if (length == -1) {
		return map_nt_error_from_unix(errno);
	}

	return NT_STATUS_OK;
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

static NTSTATUS nfs4acl_blob_to_smb4(struct vfs_handle_struct *handle,
				     DATA_BLOB *blob,
				     TALLOC_CTX *mem_ctx,
				     struct SMB4ACL_T **smb4acl)
{
	struct nfs4acl_config *config = NULL;
	NTSTATUS status;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return NT_STATUS_INTERNAL_ERROR);

	switch (config->encoding) {
	case NFS4ACL_ENCODING_NDR:
		status = nfs4acl_ndr_blob_to_smb4(handle, mem_ctx, blob, smb4acl);
		break;
	case NFS4ACL_ENCODING_XDR:
		status = nfs4acl_xdr_blob_to_smb4(handle, mem_ctx, blob, smb4acl);
		break;
	case NFS4ACL_ENCODING_NFS:
		status = nfs4acl_nfs_blob_to_smb4(handle, mem_ctx, blob, smb4acl);
		break;
	default:
		status = NT_STATUS_INTERNAL_ERROR;
		break;
	}

	return status;
}

static NTSTATUS nfs4acl_xattr_fget_nt_acl(struct vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   uint32_t security_info,
				   TALLOC_CTX *mem_ctx,
				   struct security_descriptor **sd)
{
	struct SMB4ACL_T *smb4acl = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	DATA_BLOB blob;
	NTSTATUS status;

	status = nfs4acl_get_blob(handle, fsp, NULL, frame, &blob);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		TALLOC_FREE(frame);
		return nfs4acl_xattr_default_sd(
			handle, fsp->fsp_name, mem_ctx, sd);
	}
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = nfs4acl_blob_to_smb4(handle, &blob, frame, &smb4acl);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = smb_fget_nt_acl_nfs4(fsp, NULL, security_info, mem_ctx,
				      sd, smb4acl);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS nfs4acl_xattr_get_nt_acl_at(struct vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				uint32_t security_info,
				TALLOC_CTX *mem_ctx,
				struct security_descriptor **sd)
{
	struct SMB4ACL_T *smb4acl = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	DATA_BLOB blob;
	NTSTATUS status;

	SMB_ASSERT(dirfsp == handle->conn->cwd_fsp);

	status = nfs4acl_get_blob(handle, NULL, smb_fname, frame, &blob);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		TALLOC_FREE(frame);
		return nfs4acl_xattr_default_sd(
			handle,	smb_fname, mem_ctx, sd);
	}
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = nfs4acl_blob_to_smb4(handle, &blob, frame, &smb4acl);
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

static bool nfs4acl_smb4acl_set_fn(vfs_handle_struct *handle,
				   files_struct *fsp,
				   struct SMB4ACL_T *smb4acl)
{
	struct nfs4acl_config *config = NULL;
	DATA_BLOB blob;
	NTSTATUS status;
	int saved_errno = 0;
	int ret;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return false);

	switch (config->encoding) {
	case NFS4ACL_ENCODING_NDR:
		status = nfs4acl_smb4acl_to_ndr_blob(handle, talloc_tos(),
						     smb4acl, &blob);
		break;
	case NFS4ACL_ENCODING_XDR:
		status = nfs4acl_smb4acl_to_xdr_blob(handle, talloc_tos(),
						     smb4acl, &blob);
		break;
	case NFS4ACL_ENCODING_NFS:
		status = nfs4acl_smb4acl_to_nfs_blob(handle, talloc_tos(),
						     smb4acl, &blob);
		break;
	default:
		status = NT_STATUS_INTERNAL_ERROR;
		break;
	}
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (fsp->fh->fd != -1) {
		ret = SMB_VFS_NEXT_FSETXATTR(handle, fsp, config->xattr_name,
					     blob.data, blob.length, 0);
	} else {
		ret = SMB_VFS_NEXT_SETXATTR(handle, fsp->fsp_name,
					    config->xattr_name,
					    blob.data, blob.length, 0);
	}
	if (ret != 0) {
		saved_errno = errno;
	}
	data_blob_free(&blob);
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	if (ret != 0) {
		DBG_ERR("can't store acl in xattr: %s\n", strerror(errno));
		return false;
	}

	return true;
}

static NTSTATUS nfs4acl_xattr_fset_nt_acl(vfs_handle_struct *handle,
			 files_struct *fsp,
			 uint32_t security_info_sent,
			 const struct security_descriptor *psd)
{
	struct nfs4acl_config *config = NULL;
	const struct security_token *token = NULL;
	mode_t existing_mode;
	mode_t expected_mode;
	mode_t restored_mode;
	bool chown_needed = false;
	struct dom_sid_buf buf;
	NTSTATUS status;
	int ret;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return NT_STATUS_INTERNAL_ERROR);

	if (!VALID_STAT(fsp->fsp_name->st)) {
		DBG_ERR("Invalid stat info on [%s]\n", fsp_str_dbg(fsp));
		return NT_STATUS_INTERNAL_ERROR;
	}

	existing_mode = fsp->fsp_name->st.st_ex_mode;
	if (S_ISDIR(existing_mode)) {
		expected_mode = 0777;
	} else {
		expected_mode = 0666;
	}
	if (!config->validate_mode) {
		existing_mode = 0;
		expected_mode = 0;
	}
	if ((existing_mode & expected_mode) != expected_mode) {

		restored_mode = existing_mode | expected_mode;

		if (fsp->fh->fd != -1) {
			ret = SMB_VFS_NEXT_FCHMOD(handle,
						  fsp,
						  restored_mode);
		} else {
			ret = SMB_VFS_NEXT_CHMOD(handle,
						 fsp->fsp_name,
						 restored_mode);
		}
		if (ret != 0) {
			DBG_ERR("Resetting POSIX mode on [%s] from [0%o]: %s\n",
				fsp_str_dbg(fsp), existing_mode,
				strerror(errno));
			return map_nt_error_from_unix(errno);
		}
	}

	status = smb_set_nt_acl_nfs4(handle,
				     fsp,
				     &config->nfs4_params,
				     security_info_sent,
				     psd,
				     nfs4acl_smb4acl_set_fn);
	if (NT_STATUS_IS_OK(status)) {
		return NT_STATUS_OK;
	}
	if (!NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		return status;
	}

	/*
	 * We got access denied. If we're already root, or we didn't
	 * need to do a chown, or the fsp isn't open with WRITE_OWNER
	 * access, just return.
	 */

	if ((security_info_sent & SECINFO_OWNER) &&
	    (psd->owner_sid != NULL))
	{
		chown_needed = true;
	}
	if ((security_info_sent & SECINFO_GROUP) &&
	    (psd->group_sid != NULL))
	{
		chown_needed = true;
	}

	if (get_current_uid(handle->conn) == 0 ||
	    chown_needed == false ||
	    !(fsp->access_mask & SEC_STD_WRITE_OWNER))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	/*
	 * Only allow take-ownership, not give-ownership. That's the way Windows
	 * implements SEC_STD_WRITE_OWNER. MS-FSA 2.1.5.16 just states: If
	 * InputBuffer.OwnerSid is not a valid owner SID for a file in the
	 * objectstore, as determined in an implementation specific manner, the
	 * object store MUST return STATUS_INVALID_OWNER.
	 */
	token = get_current_nttok(fsp->conn);
	if (!security_token_is_sid(token, psd->owner_sid)) {
		return NT_STATUS_INVALID_OWNER;
	}

	DBG_DEBUG("overriding chown on file %s for sid %s\n",
		  fsp_str_dbg(fsp),
		  dom_sid_str_buf(psd->owner_sid, &buf));

	status = smb_set_nt_acl_nfs4(handle,
				     fsp,
				     &config->nfs4_params,
				     security_info_sent,
				     psd,
				     nfs4acl_smb4acl_set_fn);
	return status;
}

static int nfs4acl_connect(struct vfs_handle_struct *handle,
			   const char *service,
			   const char *user)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct nfs4acl_config *config = NULL;
	const struct enum_list *default_acl_style_list = NULL;
	const char *default_xattr_name = NULL;
	bool default_validate_mode = true;
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
	case NFS4ACL_ENCODING_XDR:
		default_xattr_name = NFS4ACL_XDR_XATTR_NAME;
		break;
	case NFS4ACL_ENCODING_NFS:
		default_xattr_name = NFS4ACL_NFS_XATTR_NAME;
		default_validate_mode = false;
		break;
	case NFS4ACL_ENCODING_NDR:
	default:
		default_xattr_name = NFS4ACL_NDR_XATTR_NAME;
		break;
	}

	nfs_version = (unsigned)lp_parm_int(SNUM(handle->conn),
					    "nfs4acl_xattr",
					    "version",
					    41);
	switch (nfs_version) {
	case 40:
		config->nfs_version = ACL4_XATTR_VERSION_40;
		break;
	case 41:
		config->nfs_version = ACL4_XATTR_VERSION_41;
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

	config->xattr_name = lp_parm_substituted_string(config, lp_sub,
						   SNUM(handle->conn),
						   "nfs4acl_xattr",
						   "xattr_name",
						   default_xattr_name);

	config->nfs4_id_numeric = lp_parm_bool(SNUM(handle->conn),
					       "nfs4acl_xattr",
					       "nfs4_id_numeric",
					       false);


	config->validate_mode = lp_parm_bool(SNUM(handle->conn),
					     "nfs4acl_xattr",
					     "validate_mode",
					     default_validate_mode);

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
	.get_nt_acl_at_fn = nfs4acl_xattr_get_nt_acl_at,
	.fset_nt_acl_fn = nfs4acl_xattr_fset_nt_acl,

	.sys_acl_get_file_fn = nfs4acl_xattr_fail__sys_acl_get_file,
	.sys_acl_get_fd_fn = nfs4acl_xattr_fail__sys_acl_get_fd,
	.sys_acl_blob_get_file_fn = nfs4acl_xattr_fail__sys_acl_blob_get_file,
	.sys_acl_blob_get_fd_fn = nfs4acl_xattr_fail__sys_acl_blob_get_fd,
	.sys_acl_set_file_fn = nfs4acl_xattr_fail__sys_acl_set_file,
	.sys_acl_set_fd_fn = nfs4acl_xattr_fail__sys_acl_set_fd,
	.sys_acl_delete_def_file_fn = nfs4acl_xattr_fail__sys_acl_delete_def_file,
};

static_decl_vfs;
NTSTATUS vfs_nfs4acl_xattr_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "nfs4acl_xattr",
				&nfs4acl_xattr_fns);
}
