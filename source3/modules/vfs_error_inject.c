/*
 *  Unix SMB/CIFS implementation.
 *  Samba VFS module for error injection in VFS calls
 *  Copyright (C) Christof Schmitt 2017
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "librpc/gen_ndr/ndr_open_files.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

struct unix_error_map {
	const char *err_str;
	int error;
} unix_error_map_array[] = {
	{	"ESTALE",	ESTALE	},
	{	"EBADF",	EBADF	},
	{	"EINTR",	EINTR	},
	{	"EACCES",	EACCES	},
	{	"EROFS",	EROFS	},
};

static int find_unix_error_from_string(const char *err_str)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(unix_error_map_array); i++) {
		struct unix_error_map *m = &unix_error_map_array[i];

		if (strequal(err_str, m->err_str)) {
			return m->error;
		}
	}

	return 0;
}

static int inject_unix_error(const char *vfs_func, vfs_handle_struct *handle)
{
	const char *err_str;
	int error;

	err_str = lp_parm_const_string(SNUM(handle->conn),
				       "error_inject", vfs_func, NULL);
	if (err_str == NULL) {
		return 0;
	}

	error = find_unix_error_from_string(err_str);
	if (error != 0) {
		DBG_WARNING("Returning error %s for VFS function %s\n",
			    err_str, vfs_func);
		return error;
	}

	if (strequal(err_str, "panic")) {
		DBG_ERR("Panic in VFS function %s\n", vfs_func);
		smb_panic("error_inject");
	}

	DBG_ERR("Unknown error inject %s requested "
		"for vfs function %s\n", err_str, vfs_func);

	return 0;
}

static int vfs_error_inject_chdir(vfs_handle_struct *handle,
				  const struct smb_filename *smb_fname)
{
	int error;

	error = inject_unix_error("chdir", handle);
	if (error != 0) {
		errno = error;
		return -1;
	}

	return SMB_VFS_NEXT_CHDIR(handle, smb_fname);
}

static ssize_t vfs_error_inject_pwrite(vfs_handle_struct *handle,
				       files_struct *fsp,
				       const void *data,
				       size_t n,
				       off_t offset)
{
	int error;

	error = inject_unix_error("pwrite", handle);
	if (error != 0) {
		errno = error;
		return -1;
	}

	return SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);
}

static int vfs_error_inject_openat(struct vfs_handle_struct *handle,
				   const struct files_struct *dirfsp,
				   const struct smb_filename *smb_fname,
				   files_struct *fsp,
				   const struct vfs_open_how *how)
{
	int error = inject_unix_error("openat", handle);
	int create_error = inject_unix_error("openat_create", handle);
	int dirfsp_flags = (O_NOFOLLOW|O_DIRECTORY);
	bool return_error;

#ifdef O_PATH
	dirfsp_flags |= O_PATH;
#else
#ifdef O_SEARCH
	dirfsp_flags |= O_SEARCH;
#endif
#endif

	if ((create_error != 0) && (how->flags & O_CREAT)) {
		struct stat_ex st = {
			.st_ex_nlink = 0,
		};
		int ret;

		ret = SMB_VFS_FSTATAT(handle->conn,
				      dirfsp,
				      smb_fname,
				      &st,
				      AT_SYMLINK_NOFOLLOW);

		if ((ret == -1) && (errno == ENOENT)) {
			errno = create_error;
			return -1;
		}
	}

	return_error = (error != 0);
	return_error &= !fsp->fsp_flags.is_pathref;
	return_error &= ((how->flags & dirfsp_flags) != dirfsp_flags);

	if (return_error) {
		errno = error;
		return -1;
	}
	return SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
}

static int vfs_error_inject_unlinkat(struct vfs_handle_struct *handle,
				     struct files_struct *dirfsp,
				     const struct smb_filename *smb_fname,
				     int flags)
{
	struct smb_filename *full_fname = NULL;
	struct smb_filename *parent_fname = NULL;
	int error = inject_unix_error("unlinkat", handle);
	int ret;
	NTSTATUS status;

	if (error == 0) {
		return SMB_VFS_NEXT_UNLINKAT(handle, dirfsp, smb_fname, flags);
	}

	full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						  dirfsp,
						  smb_fname);
	if (full_fname == NULL) {
		return -1;
	}

	status = SMB_VFS_PARENT_PATHNAME(handle->conn,
					 full_fname, /* TALLOC_CTX. */
					 full_fname,
					 &parent_fname,
					 NULL);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(full_fname);
		errno = map_errno_from_nt_status(status);
		return -1;
	}

	ret = SMB_VFS_STAT(handle->conn, parent_fname);
	if (ret != 0) {
		TALLOC_FREE(full_fname);
		return -1;
	}

	if (parent_fname->st.st_ex_uid == get_current_uid(dirfsp->conn)) {
		return SMB_VFS_NEXT_UNLINKAT(handle, dirfsp, smb_fname, flags);
	}

	errno = error;
	return -1;
}

static NTSTATUS vfs_error_inject_durable_reconnect(struct vfs_handle_struct *handle,
						   struct smb_request *smb1req,
						   struct smbXsrv_open *op,
						   const DATA_BLOB old_cookie,
						   TALLOC_CTX *mem_ctx,
						   struct files_struct **fsp,
						   DATA_BLOB *new_cookie)
{
	const char *vfs_func = "durable_reconnect";
	const char *err_str = NULL;
	NTSTATUS status;
	enum ndr_err_code ndr_err;
	struct vfs_default_durable_cookie cookie;
	DATA_BLOB modified_cookie = data_blob_null;

	err_str = lp_parm_const_string(SNUM(handle->conn),
				       "error_inject",
				       vfs_func,
				       NULL);
	if (err_str == NULL) {
		return SMB_VFS_NEXT_DURABLE_RECONNECT(handle,
						      smb1req,
						      op,
						      old_cookie,
						      mem_ctx,
						      fsp,
						      new_cookie);
	}

	ndr_err = ndr_pull_struct_blob(&old_cookie, talloc_tos(), &cookie,
			(ndr_pull_flags_fn_t)ndr_pull_vfs_default_durable_cookie);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		return status;
	}

	if (strcmp(cookie.magic, VFS_DEFAULT_DURABLE_COOKIE_MAGIC) != 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (cookie.version != VFS_DEFAULT_DURABLE_COOKIE_VERSION) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (strequal(err_str, "st_ex_nlink")) {
		cookie.stat_info.st_ex_nlink += 1;
	} else {
		DBG_ERR("Unknown error inject %s requested "
			"for vfs function %s\n", err_str, vfs_func);
		return SMB_VFS_NEXT_DURABLE_RECONNECT(handle,
						      smb1req,
						      op,
						      old_cookie,
						      mem_ctx,
						      fsp,
						      new_cookie);
	}

	ndr_err = ndr_push_struct_blob(&modified_cookie, talloc_tos(), &cookie,
			(ndr_push_flags_fn_t)ndr_push_vfs_default_durable_cookie);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		return status;
	}

	return SMB_VFS_NEXT_DURABLE_RECONNECT(handle,
					      smb1req,
					      op,
					      modified_cookie,
					      mem_ctx,
					      fsp,
					      new_cookie);
}

static struct vfs_fn_pointers vfs_error_inject_fns = {
	.chdir_fn = vfs_error_inject_chdir,
	.pwrite_fn = vfs_error_inject_pwrite,
	.openat_fn = vfs_error_inject_openat,
	.unlinkat_fn = vfs_error_inject_unlinkat,
	.durable_reconnect_fn = vfs_error_inject_durable_reconnect,
};

static_decl_vfs;
NTSTATUS vfs_error_inject_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "error_inject",
				&vfs_error_inject_fns);
}
