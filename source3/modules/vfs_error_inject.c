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
};

static int find_unix_error_from_string(const char *err_str)
{
	int i;

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

	err_str = lp_parm_const_string(SNUM(handle->conn),
				       "error_inject", vfs_func, NULL);

	if (err_str != NULL) {
		int error;

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
	}

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
				   int flags,
				   mode_t mode)
{
	int error = inject_unix_error("openat", handle);
	if (error != 0) {
		errno = error;
		return -1;
	}
	return SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, flags, mode);
}

static int vfs_error_inject_unlinkat(struct vfs_handle_struct *handle,
				     struct files_struct *dirfsp,
				     const struct smb_filename *smb_fname,
				     int flags)
{
	struct smb_filename *parent_fname = NULL;
	int error = inject_unix_error("unlinkat", handle);
	int ret;
	bool ok;

	if (error == 0) {
		return SMB_VFS_NEXT_UNLINKAT(handle, dirfsp, smb_fname, flags);
	}

	ok = parent_smb_fname(talloc_tos(), smb_fname, &parent_fname, NULL);
	if (!ok) {
		return -1;
	}

	ret = SMB_VFS_STAT(handle->conn, parent_fname);
	if (ret != 0) {
		TALLOC_FREE(parent_fname);
		return -1;
	}

	if (parent_fname->st.st_ex_uid == get_current_uid(dirfsp->conn)) {
		TALLOC_FREE(parent_fname);
		return SMB_VFS_NEXT_UNLINKAT(handle, dirfsp, smb_fname, flags);
	}

	TALLOC_FREE(parent_fname);
	errno = error;
	return -1;
}

static struct vfs_fn_pointers vfs_error_inject_fns = {
	.chdir_fn = vfs_error_inject_chdir,
	.pwrite_fn = vfs_error_inject_pwrite,
	.openat_fn = vfs_error_inject_openat,
	.unlinkat_fn = vfs_error_inject_unlinkat,
};

static_decl_vfs;
NTSTATUS vfs_error_inject_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "error_inject",
				&vfs_error_inject_fns);
}
