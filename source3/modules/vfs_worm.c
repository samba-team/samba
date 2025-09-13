/*
 * VFS module to disallow writes for older files
 *
 * Copyright (C) 2013, Volker Lendecke
 * Copyright (C) 2023-2024, Björn Jacke
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
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "system/filesys.h"
#include "libcli/security/security.h"

struct worm_config_data {
	double grace_period;
};
static const uint32_t write_access_flags = FILE_WRITE_DATA | FILE_APPEND_DATA |
					   FILE_WRITE_ATTRIBUTES |
					   DELETE_ACCESS | WRITE_DAC_ACCESS |
					   WRITE_OWNER_ACCESS | FILE_WRITE_EA;

static int vfs_worm_connect(struct vfs_handle_struct *handle,
			    const char *service, const char *user)
{
	struct worm_config_data *config = NULL;
	int ret;

	ret = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (ret < 0) {
		return ret;
	}

	if (IS_IPC(handle->conn) || IS_PRINT(handle->conn)) {
		return 0;
	}

	config = talloc_zero(handle->conn, struct worm_config_data);
	if (config == NULL) {
		DBG_ERR("talloc_zero() failed\n");
		errno = ENOMEM;
		return -1;
	}
	config->grace_period = lp_parm_int(SNUM(handle->conn), "worm",
						"grace_period", 3600);

	SMB_VFS_HANDLE_SET_DATA(handle, config,
				NULL, struct worm_config_data,
				return -1);
	return 0;

}

static bool is_readonly(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	double age;
	struct worm_config_data *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct worm_config_data,
				return true);

	if (!VALID_STAT(smb_fname->st)) {
		goto out;
	}

	age = timespec_elapsed(&smb_fname->st.st_ex_ctime);

	if (age > config->grace_period) {
		return true;
	}

out:
	return false;
}
static bool fsp_is_readonly(vfs_handle_struct *handle, files_struct *fsp)
{
	double age;
	struct worm_config_data *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct worm_config_data,
				return true);

	if (!VALID_STAT(fsp->fsp_name->st)) {
		goto out;
	}

	age = timespec_elapsed(&fsp->fsp_name->st.st_ex_ctime);

	if (age > config->grace_period) {
		return true;
	}

out:
	return false;
}

static NTSTATUS vfs_worm_create_file(vfs_handle_struct *handle,
				     struct smb_request *req,
				     struct files_struct *dirfsp,
				     struct smb_filename *smb_fname,
				     uint32_t access_mask,
				     uint32_t share_access,
				     uint32_t create_disposition,
				     uint32_t create_options,
				     uint32_t file_attributes,
				     uint32_t oplock_request,
				     const struct smb2_lease *lease,
				     uint64_t allocation_size,
				     uint32_t private_flags,
				     struct security_descriptor *sd,
				     struct ea_list *ea_list,
				     files_struct **result,
				     int *pinfo,
				     const struct smb2_create_blobs *in_context_blobs,
				     struct smb2_create_blobs *out_context_blobs)
{
	NTSTATUS status;
	bool readonly;

	readonly = is_readonly(handle, smb_fname);

	if (readonly && (access_mask & write_access_flags)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	status = SMB_VFS_NEXT_CREATE_FILE(
		handle, req, dirfsp, smb_fname, access_mask,
		share_access, create_disposition, create_options,
		file_attributes, oplock_request, lease, allocation_size,
		private_flags, sd, ea_list, result, pinfo,
		in_context_blobs, out_context_blobs);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	 * Access via MAXIMUM_ALLOWED_ACCESS?
	 */
	if (readonly && ((*result)->access_mask & write_access_flags)) {
		close_file_free(req, result, NORMAL_CLOSE);
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_OK;
}

static int vfs_worm_openat(vfs_handle_struct *handle,
			   const struct files_struct *dirfsp,
			   const struct smb_filename *smb_fname,
			   files_struct *fsp,
			   const struct vfs_open_how *how)
{
	if (is_readonly(handle, smb_fname) &&
	    (fsp->access_mask & write_access_flags)) {
		errno = EACCES;
		return -1;
	}

	return SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
}

static int vfs_worm_fntimes(vfs_handle_struct *handle,
			    files_struct *fsp,
			    struct smb_file_time *ft)
{
	if (fsp_is_readonly(handle, fsp)) {
		errno = EACCES;
		return -1;
	}

	return SMB_VFS_NEXT_FNTIMES(handle, fsp, ft);
}

static int vfs_worm_fchmod(vfs_handle_struct *handle,
			   files_struct *fsp,
			   mode_t mode)
{
	if (fsp_is_readonly(handle, fsp)) {
		errno = EACCES;
		return -1;
	}

	return SMB_VFS_NEXT_FCHMOD(handle, fsp, mode);
}

static int vfs_worm_fchown(vfs_handle_struct *handle,
			   files_struct *fsp,
			   uid_t uid,
			   gid_t gid)
{
	if (fsp_is_readonly(handle, fsp)) {
		errno = EACCES;
		return -1;
	}

	return SMB_VFS_NEXT_FCHOWN(handle, fsp, uid, gid);
}

static int vfs_worm_renameat(vfs_handle_struct *handle,
			     files_struct *src_dirfsp,
			     const struct smb_filename *smb_fname_src,
			     files_struct *dst_dirfsp,
			     const struct smb_filename *smb_fname_dst,
			     const struct vfs_rename_how *how)
{
	if (is_readonly(handle, smb_fname_src)) {
		errno = EACCES;
		return -1;
	}

	return SMB_VFS_NEXT_RENAMEAT(handle,
				     src_dirfsp,
				     smb_fname_src,
				     dst_dirfsp,
				     smb_fname_dst,
				     how);
}

static int vfs_worm_fsetxattr(struct vfs_handle_struct *handle,
			      struct files_struct *fsp,
			      const char *name,
			      const void *value,
			      size_t size,
			      int flags)
{
	if (fsp_is_readonly(handle, fsp)) {
		errno = EACCES;
		return -1;
	}

	return SMB_VFS_NEXT_FSETXATTR(handle, fsp, name, value, size, flags);
}

static int vfs_worm_fremotexattr(struct vfs_handle_struct *handle,
				 struct files_struct *fsp,
				 const char *name)
{
	if (fsp_is_readonly(handle, fsp)) {
		errno = EACCES;
		return -1;
	}

	return SMB_VFS_NEXT_FREMOVEXATTR(handle, fsp, name);
}

static int vfs_worm_unlinkat(vfs_handle_struct *handle,
			     struct files_struct *dirfsp,
			     const struct smb_filename *smb_fname,
			     int flags)
{
	struct smb_filename *full_fname = NULL;
	bool readonly;

	full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						  dirfsp,
						  smb_fname);
	if (full_fname == NULL) {
		return -1;
	}

	readonly = is_readonly(handle, full_fname);

	TALLOC_FREE(full_fname);

	if (readonly) {
		errno = EACCES;
		return -1;
	}

	return SMB_VFS_NEXT_UNLINKAT(handle, dirfsp, smb_fname, flags);
}

static NTSTATUS vfs_worm_fset_dos_attributes(struct vfs_handle_struct *handle,
					     struct files_struct *fsp,
					     uint32_t dosmode)
{
	if (fsp_is_readonly(handle, fsp)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	return SMB_VFS_NEXT_FSET_DOS_ATTRIBUTES(handle, fsp, dosmode);
}

static NTSTATUS vfs_worm_fset_nt_acl(vfs_handle_struct *handle,
				     files_struct *fsp,
				     uint32_t security_info_sent,
				     const struct security_descriptor *psd)
{
	if (fsp_is_readonly(handle, fsp)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	return SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, security_info_sent, psd);
}

static int vfs_worm_sys_acl_set_fd(vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   SMB_ACL_TYPE_T type,
				   SMB_ACL_T theacl)
{
	if (fsp_is_readonly(handle, fsp)) {
		errno = EACCES;
		return -1;
	}

	return SMB_VFS_NEXT_SYS_ACL_SET_FD(handle, fsp, type, theacl);
}

static int vfs_worm_sys_acl_delete_def_fd(vfs_handle_struct *handle,
					  struct files_struct *fsp)
{
	if (fsp_is_readonly(handle, fsp)) {
		errno = EACCES;
		return -1;
	}

	return SMB_VFS_NEXT_SYS_ACL_DELETE_DEF_FD(handle, fsp);
}

static struct vfs_fn_pointers vfs_worm_fns = {
	.connect_fn = vfs_worm_connect,
	.create_file_fn = vfs_worm_create_file,
	.openat_fn = vfs_worm_openat,
	.fntimes_fn = vfs_worm_fntimes,
	.fchmod_fn = vfs_worm_fchmod,
	.fchown_fn = vfs_worm_fchown,
	.renameat_fn = vfs_worm_renameat,
	.fsetxattr_fn = vfs_worm_fsetxattr,
	.fremovexattr_fn = vfs_worm_fremotexattr,
	.unlinkat_fn = vfs_worm_unlinkat,
	.fset_dos_attributes_fn = vfs_worm_fset_dos_attributes,
	.fset_nt_acl_fn = vfs_worm_fset_nt_acl,
	.sys_acl_set_fd_fn = vfs_worm_sys_acl_set_fd,
	.sys_acl_delete_def_fd_fn = vfs_worm_sys_acl_delete_def_fd,
};

static_decl_vfs;
NTSTATUS vfs_worm_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret;

	ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "worm",
			       &vfs_worm_fns);
	if (!NT_STATUS_IS_OK(ret)) {
		return ret;
	}

	return ret;
}
