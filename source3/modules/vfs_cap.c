/*
 * CAP VFS module for Samba 3.x Version 0.3
 *
 * Copyright (C) Tim Potter, 1999-2000
 * Copyright (C) Alexander Bokovoy, 2002-2003
 * Copyright (C) Stefan (metze) Metzmacher, 2003
 * Copyright (C) TAKAHASHI Motonobu (monyo), 2003
 * Copyright (C) Jeremy Allison, 2007
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

/* cap functions */
static char *capencode(TALLOC_CTX *ctx, const char *from);
static char *capdecode(TALLOC_CTX *ctx, const char *from);

static uint64_t cap_disk_free(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uint64_t *bsize,
			uint64_t *dfree,
			uint64_t *dsize)
{
	char *capname = capencode(talloc_tos(), smb_fname->base_name);
	struct smb_filename *cap_smb_fname = NULL;

	if (!capname) {
		errno = ENOMEM;
		return (uint64_t)-1;
	}
	cap_smb_fname = synthetic_smb_fname(talloc_tos(),
					capname,
					NULL,
					NULL,
					smb_fname->twrp,
					smb_fname->flags);
	if (cap_smb_fname == NULL) {
		TALLOC_FREE(capname);
		errno = ENOMEM;
		return (uint64_t)-1;
	}
	return SMB_VFS_NEXT_DISK_FREE(handle, cap_smb_fname,
			bsize, dfree, dsize);
}

static int cap_get_quota(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			enum SMB_QUOTA_TYPE qtype,
			unid_t id,
			SMB_DISK_QUOTA *dq)
{
	char *cappath = capencode(talloc_tos(), smb_fname->base_name);
	struct smb_filename *cap_smb_fname = NULL;

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	cap_smb_fname = synthetic_smb_fname(talloc_tos(),
					cappath,
					NULL,
					NULL,
					smb_fname->twrp,
					smb_fname->flags);
	if (cap_smb_fname == NULL) {
		TALLOC_FREE(cappath);
		errno = ENOMEM;
		return -1;
	}
	return SMB_VFS_NEXT_GET_QUOTA(handle, cap_smb_fname, qtype, id, dq);
}

static struct dirent *
cap_readdir(vfs_handle_struct *handle, struct files_struct *dirfsp, DIR *dirp)
{
	struct dirent *result;
	struct dirent *newdirent;
	char *newname;
	size_t newnamelen;
	DEBUG(3,("cap: cap_readdir\n"));

	result = SMB_VFS_NEXT_READDIR(handle, dirfsp, dirp);
	if (!result) {
		return NULL;
	}

	newname = capdecode(talloc_tos(), result->d_name);
	if (!newname) {
		return NULL;
	}
	DEBUG(3,("cap: cap_readdir: %s\n", newname));
	newnamelen = strlen(newname)+1;
	newdirent = talloc_size(
		talloc_tos(), sizeof(struct dirent) + newnamelen);
	if (!newdirent) {
		return NULL;
	}
	talloc_set_name_const(newdirent, "struct dirent");
	memcpy(newdirent, result, sizeof(struct dirent));
	memcpy(&newdirent->d_name, newname, newnamelen);
	return newdirent;
}

static int cap_mkdirat(vfs_handle_struct *handle,
		struct files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		mode_t mode)
{
	char *cappath = capencode(talloc_tos(), smb_fname->base_name);
	struct smb_filename *cap_smb_fname = NULL;

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}

	cap_smb_fname = synthetic_smb_fname(talloc_tos(),
					cappath,
					NULL,
					NULL,
					smb_fname->twrp,
					smb_fname->flags);
	if (cap_smb_fname == NULL) {
		TALLOC_FREE(cappath);
		errno = ENOMEM;
		return -1;
	}

	return SMB_VFS_NEXT_MKDIRAT(handle,
			dirfsp,
			cap_smb_fname,
			mode);
}

static int cap_openat(vfs_handle_struct *handle,
		      const struct files_struct *dirfsp,
		      const struct smb_filename *smb_fname_in,
		      files_struct *fsp,
		      const struct vfs_open_how *how)
{
	char *cappath = NULL;
	struct smb_filename *smb_fname = NULL;
	int ret;
	int saved_errno = 0;

	cappath = capencode(talloc_tos(), smb_fname_in->base_name);
	if (cappath == NULL) {
		errno = ENOMEM;
		return -1;
	}

	smb_fname = cp_smb_filename(talloc_tos(), smb_fname_in);
	if (smb_fname == NULL) {
		TALLOC_FREE(cappath);
		errno = ENOMEM;
		return -1;
	}
	smb_fname->base_name = cappath;

	DBG_DEBUG("cap_open for %s\n", smb_fname_str_dbg(smb_fname));
	ret = SMB_VFS_NEXT_OPENAT(handle,
				  dirfsp,
				  smb_fname,
				  fsp,
				  how);
	if (ret == -1) {
		saved_errno = errno;
	}
	TALLOC_FREE(cappath);
	TALLOC_FREE(smb_fname);
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return ret;
}

static int cap_renameat(vfs_handle_struct *handle,
			files_struct *src_dirfsp,
			const struct smb_filename *smb_fname_src,
			files_struct *dst_dirfsp,
			const struct smb_filename *smb_fname_dst,
			const struct vfs_rename_how *how)
{
	char *capold = NULL;
	char *capnew = NULL;
	struct smb_filename *smb_fname_src_tmp = NULL;
	struct smb_filename *smb_fname_dst_tmp = NULL;
	struct smb_filename *full_fname_src = NULL;
	struct smb_filename *full_fname_dst = NULL;
	int ret = -1;
	int saved_errno = 0;

	full_fname_src = full_path_from_dirfsp_atname(talloc_tos(),
						      src_dirfsp,
						      smb_fname_src);
	if (full_fname_src == NULL) {
		errno = ENOMEM;
		goto out;
	}

	full_fname_dst = full_path_from_dirfsp_atname(talloc_tos(),
						      dst_dirfsp,
						      smb_fname_dst);
	if (full_fname_dst == NULL) {
		errno = ENOMEM;
		goto out;
	}

	capold = capencode(talloc_tos(), full_fname_src->base_name);
	capnew = capencode(talloc_tos(), full_fname_dst->base_name);
	if (!capold || !capnew) {
		errno = ENOMEM;
		goto out;
	}

	/* Setup temporary smb_filename structs. */
	smb_fname_src_tmp = cp_smb_filename(talloc_tos(), full_fname_src);
	if (smb_fname_src_tmp == NULL) {
		errno = ENOMEM;
		goto out;
	}
	smb_fname_dst_tmp = cp_smb_filename(talloc_tos(), full_fname_dst);
	if (smb_fname_dst_tmp == NULL) {
		errno = ENOMEM;
		goto out;
	}

	smb_fname_src_tmp->base_name = capold;
	smb_fname_dst_tmp->base_name = capnew;

	ret = SMB_VFS_NEXT_RENAMEAT(handle,
				    src_dirfsp->conn->cwd_fsp,
				    smb_fname_src_tmp,
				    dst_dirfsp->conn->cwd_fsp,
				    smb_fname_dst_tmp,
				    how);

 out:

	if (ret != 0) {
		saved_errno = errno;
	}

	TALLOC_FREE(full_fname_src);
	TALLOC_FREE(full_fname_dst);
	TALLOC_FREE(capold);
	TALLOC_FREE(capnew);
	TALLOC_FREE(smb_fname_src_tmp);
	TALLOC_FREE(smb_fname_dst_tmp);

	if (ret != 0) {
		errno = saved_errno;
	}

	return ret;
}

static int cap_fstatat(struct vfs_handle_struct *handle,
		       const struct files_struct *dirfsp,
		       const struct smb_filename *smb_fname,
		       SMB_STRUCT_STAT *sbuf,
		       int flags)
{
	struct smb_filename *tmp = NULL;
	int ret;

	tmp = cp_smb_filename(talloc_tos(), smb_fname);
	if (tmp == NULL) {
		errno = ENOMEM;
		return -1;
	}

	tmp->base_name = capencode(talloc_tos(), smb_fname->base_name);
	if (tmp->base_name == NULL) {
		TALLOC_FREE(tmp);
		errno = ENOMEM;
		return -1;
	}

	ret = SMB_VFS_NEXT_FSTATAT(handle, dirfsp, tmp, sbuf, flags);

	{
		int err = errno;
		TALLOC_FREE(tmp);
		errno = err;
	}

	return ret;
}

static int cap_stat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
	char *cappath;
	char *tmp_base_name = NULL;
	int ret;

	cappath = capencode(talloc_tos(), smb_fname->base_name);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}

	tmp_base_name = smb_fname->base_name;
	smb_fname->base_name = cappath;

	ret = SMB_VFS_NEXT_STAT(handle, smb_fname);

	smb_fname->base_name = tmp_base_name;
	TALLOC_FREE(cappath);

	return ret;
}

static int cap_lstat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
	char *cappath;
	char *tmp_base_name = NULL;
	int ret;

	cappath = capencode(talloc_tos(), smb_fname->base_name);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}

	tmp_base_name = smb_fname->base_name;
	smb_fname->base_name = cappath;

	ret = SMB_VFS_NEXT_LSTAT(handle, smb_fname);

	smb_fname->base_name = tmp_base_name;
	TALLOC_FREE(cappath);

	return ret;
}

static int cap_unlinkat(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			int flags)
{
	struct smb_filename *full_fname = NULL;
	struct smb_filename *smb_fname_tmp = NULL;
	char *cappath = NULL;
	int ret;

	full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						  dirfsp,
						  smb_fname);
	if (full_fname == NULL) {
		return -1;
	}

	cappath = capencode(talloc_tos(), full_fname->base_name);
	if (!cappath) {
		TALLOC_FREE(full_fname);
		errno = ENOMEM;
		return -1;
	}

	/* Setup temporary smb_filename structs. */
	smb_fname_tmp = cp_smb_filename(talloc_tos(), full_fname);
	TALLOC_FREE(full_fname);
	if (smb_fname_tmp == NULL) {
		errno = ENOMEM;
		return -1;
	}

	smb_fname_tmp->base_name = cappath;

	ret = SMB_VFS_NEXT_UNLINKAT(handle,
			dirfsp->conn->cwd_fsp,
			smb_fname_tmp,
			flags);

	TALLOC_FREE(smb_fname_tmp);
	return ret;
}

static int cap_lchown(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
	struct smb_filename *cap_smb_fname = NULL;
	char *cappath = capencode(talloc_tos(), smb_fname->base_name);
	int ret;
	int saved_errno;

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}

	cap_smb_fname = synthetic_smb_fname(talloc_tos(),
					cappath,
					NULL,
					NULL,
					smb_fname->twrp,
					smb_fname->flags);
	if (cap_smb_fname == NULL) {
		TALLOC_FREE(cappath);
		errno = ENOMEM;
		return -1;
	}

	ret = SMB_VFS_NEXT_LCHOWN(handle, cap_smb_fname, uid, gid);
	saved_errno = errno;
	TALLOC_FREE(cappath);
	TALLOC_FREE(cap_smb_fname);
	errno = saved_errno;
	return ret;
}

static int cap_chdir(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	struct smb_filename *cap_smb_fname = NULL;
	char *cappath = capencode(talloc_tos(), smb_fname->base_name);
	int ret;
	int saved_errno = 0;

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
	DEBUG(3,("cap: cap_chdir for %s\n", smb_fname->base_name));

	cap_smb_fname = synthetic_smb_fname(talloc_tos(),
					cappath,
					NULL,
					NULL,
					smb_fname->twrp,
					smb_fname->flags);
	if (cap_smb_fname == NULL) {
		TALLOC_FREE(cappath);
		errno = ENOMEM;
		return -1;
	}
	ret = SMB_VFS_NEXT_CHDIR(handle, cap_smb_fname);
	if (ret == -1) {
		saved_errno = errno;
	}
	TALLOC_FREE(cappath);
	TALLOC_FREE(cap_smb_fname);
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return ret;
}

static int cap_symlinkat(vfs_handle_struct *handle,
			const struct smb_filename *link_contents,
			struct files_struct *dirfsp,
			const struct smb_filename *new_smb_fname)
{
	struct smb_filename *full_fname = NULL;
	char *capold = capencode(talloc_tos(), link_contents->base_name);
	char *capnew = NULL;
	struct smb_filename *new_link_target = NULL;
	struct smb_filename *new_cap_smb_fname = NULL;
	int saved_errno = 0;
	int ret;

	if (capold == NULL) {
		errno = ENOMEM;
		return -1;
	}

	full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						dirfsp,
						new_smb_fname);
	if (full_fname == NULL) {
		return -1;
	}

	capnew = capencode(talloc_tos(), full_fname->base_name);
	if (!capnew) {
		TALLOC_FREE(full_fname);
		errno = ENOMEM;
		return -1;
	}

	new_link_target = synthetic_smb_fname(talloc_tos(),
					      capold,
					      NULL,
					      NULL,
					      new_smb_fname->twrp,
					      new_smb_fname->flags);
	if (new_link_target == NULL) {
		TALLOC_FREE(full_fname);
		TALLOC_FREE(capold);
		TALLOC_FREE(capnew);
		errno = ENOMEM;
		return -1;
	}

	new_cap_smb_fname = synthetic_smb_fname(talloc_tos(),
					capnew,
					NULL,
					NULL,
					new_smb_fname->twrp,
					new_smb_fname->flags);
	if (new_cap_smb_fname == NULL) {
		TALLOC_FREE(full_fname);
		TALLOC_FREE(capold);
		TALLOC_FREE(capnew);
		TALLOC_FREE(new_link_target);
		errno = ENOMEM;
		return -1;
	}
	ret = SMB_VFS_NEXT_SYMLINKAT(handle,
			new_link_target,
			handle->conn->cwd_fsp,
			new_cap_smb_fname);
	if (ret == -1) {
		saved_errno = errno;
	}
	TALLOC_FREE(full_fname);
	TALLOC_FREE(capold);
	TALLOC_FREE(capnew);
	TALLOC_FREE(new_link_target);
	TALLOC_FREE(new_cap_smb_fname);
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return ret;
}

static int cap_readlinkat(vfs_handle_struct *handle,
			const struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			char *buf,
			size_t bufsiz)
{
	struct smb_filename *full_fname = NULL;
	struct smb_filename *cap_smb_fname = NULL;
	char *cappath = NULL;
	int saved_errno = 0;
	int ret;

	full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						dirfsp,
						smb_fname);
	if (full_fname == NULL) {
		return -1;
	}

	cappath = capencode(talloc_tos(), full_fname->base_name);
	if (cappath == NULL) {
		TALLOC_FREE(full_fname);
		errno = ENOMEM;
		return -1;
	}
	cap_smb_fname = synthetic_smb_fname(talloc_tos(),
					cappath,
					NULL,
					NULL,
					smb_fname->twrp,
					smb_fname->flags);
	if (cap_smb_fname == NULL) {
		TALLOC_FREE(full_fname);
		TALLOC_FREE(cappath);
		errno = ENOMEM;
		return -1;
	}
	ret = SMB_VFS_NEXT_READLINKAT(handle,
			handle->conn->cwd_fsp,
			cap_smb_fname,
			buf,
			bufsiz);
	if (ret == -1) {
		saved_errno = errno;
	}
	TALLOC_FREE(full_fname);
	TALLOC_FREE(cappath);
	TALLOC_FREE(cap_smb_fname);
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return ret;
}

static int cap_linkat(vfs_handle_struct *handle,
		      files_struct *src_dirfsp,
		      const struct smb_filename *old_smb_fname,
		      files_struct *dst_dirfsp,
		      const struct smb_filename *new_smb_fname,
		      int flags)
{
	struct smb_filename *old_full_fname = NULL;
	struct smb_filename *new_full_fname = NULL;
	char *capold = NULL;
	char *capnew = NULL;
	struct smb_filename *old_cap_smb_fname = NULL;
	struct smb_filename *new_cap_smb_fname = NULL;
	int saved_errno = 0;
	int ret;

	/* Process 'old' name. */
	old_full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						      src_dirfsp,
						      old_smb_fname);
	if (old_full_fname == NULL) {
		goto nomem_out;
        }
	capold = capencode(talloc_tos(), old_full_fname->base_name);
	if (capold == NULL) {
		goto nomem_out;
	}
	TALLOC_FREE(old_full_fname);
	old_cap_smb_fname = synthetic_smb_fname(talloc_tos(),
					capold,
					NULL,
					NULL,
					old_smb_fname->twrp,
					old_smb_fname->flags);
	if (old_cap_smb_fname == NULL) {
		goto nomem_out;
	}

	/* Process 'new' name. */
	new_full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						      dst_dirfsp,
						      new_smb_fname);
	if (new_full_fname == NULL) {
		goto nomem_out;
        }
	capnew = capencode(talloc_tos(), new_full_fname->base_name);
	if (capnew == NULL) {
		goto nomem_out;
	}
	TALLOC_FREE(new_full_fname);
	new_cap_smb_fname = synthetic_smb_fname(talloc_tos(),
					capnew,
					NULL,
					NULL,
					new_smb_fname->twrp,
					new_smb_fname->flags);
	if (new_cap_smb_fname == NULL) {
		goto nomem_out;
	}

	ret = SMB_VFS_NEXT_LINKAT(handle,
			handle->conn->cwd_fsp,
			old_cap_smb_fname,
			handle->conn->cwd_fsp,
			new_cap_smb_fname,
			flags);
	if (ret == -1) {
		saved_errno = errno;
	}
	TALLOC_FREE(old_full_fname);
	TALLOC_FREE(old_full_fname);
	TALLOC_FREE(capold);
	TALLOC_FREE(capnew);
	TALLOC_FREE(old_cap_smb_fname);
	TALLOC_FREE(new_cap_smb_fname);
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return ret;

  nomem_out:

	TALLOC_FREE(old_full_fname);
	TALLOC_FREE(old_full_fname);
	TALLOC_FREE(capold);
	TALLOC_FREE(capnew);
	TALLOC_FREE(old_cap_smb_fname);
	TALLOC_FREE(new_cap_smb_fname);
	errno = ENOMEM;
	return -1;
}

static int cap_mknodat(vfs_handle_struct *handle,
		files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		mode_t mode,
		SMB_DEV_T dev)
{
	struct smb_filename *full_fname = NULL;
	struct smb_filename *cap_smb_fname = NULL;
	char *cappath = NULL;
	int ret;
	int saved_errno = 0;

	full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						dirfsp,
						smb_fname);
        if (full_fname == NULL) {
                return -1;
        }

	cappath = capencode(talloc_tos(), full_fname->base_name);
	if (!cappath) {
		TALLOC_FREE(full_fname);
		errno = ENOMEM;
		return -1;
	}
	cap_smb_fname = synthetic_smb_fname(talloc_tos(),
					cappath,
					NULL,
					NULL,
					smb_fname->twrp,
					smb_fname->flags);
	if (cap_smb_fname == NULL) {
		TALLOC_FREE(full_fname);
		TALLOC_FREE(cappath);
		errno = ENOMEM;
		return -1;
	}
	ret = SMB_VFS_NEXT_MKNODAT(handle,
			handle->conn->cwd_fsp,
			cap_smb_fname,
			mode,
			dev);
	if (ret == -1) {
		saved_errno = errno;
	}
	TALLOC_FREE(full_fname);
	TALLOC_FREE(cappath);
	TALLOC_FREE(cap_smb_fname);
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return ret;
}

static struct smb_filename *cap_realpath(vfs_handle_struct *handle,
			TALLOC_CTX *ctx,
			const struct smb_filename *smb_fname)
{
        /* monyo need capencode'ed and capdecode'ed? */
	struct smb_filename *cap_smb_fname = NULL;
	struct smb_filename *return_fname = NULL;
	char *cappath = capencode(talloc_tos(), smb_fname->base_name);
	int saved_errno = 0;

	if (!cappath) {
		errno = ENOMEM;
		return NULL;
	}
	cap_smb_fname = synthetic_smb_fname(ctx,
					cappath,
					NULL,
					NULL,
					smb_fname->twrp,
					smb_fname->flags);
	if (cap_smb_fname == NULL) {
		TALLOC_FREE(cappath);
		errno = ENOMEM;
		return NULL;
	}
	return_fname = SMB_VFS_NEXT_REALPATH(handle, ctx, cap_smb_fname);
	if (return_fname == NULL) {
		saved_errno = errno;
	}
	TALLOC_FREE(cappath);
	TALLOC_FREE(cap_smb_fname);
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return return_fname;
}

static ssize_t cap_fgetxattr(vfs_handle_struct *handle, struct files_struct *fsp, const char *path, void *value, size_t size)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_FGETXATTR(handle, fsp, cappath, value, size);
}

static int cap_fremovexattr(vfs_handle_struct *handle, struct files_struct *fsp, const char *path)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_FREMOVEXATTR(handle, fsp, cappath);
}

static int cap_fsetxattr(vfs_handle_struct *handle, struct files_struct *fsp, const char *path, const void *value, size_t size, int flags)
{
	char *cappath = capencode(talloc_tos(), path);

	if (!cappath) {
		errno = ENOMEM;
		return -1;
	}
        return SMB_VFS_NEXT_FSETXATTR(handle, fsp, cappath, value, size, flags);
}

static NTSTATUS cap_create_dfs_pathat(vfs_handle_struct *handle,
			files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			const struct referral *reflist,
			size_t referral_count)
{
	char *cappath = capencode(talloc_tos(), smb_fname->base_name);
	struct smb_filename *cap_smb_fname = NULL;
	NTSTATUS status;

	if (cappath == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	cap_smb_fname = synthetic_smb_fname(talloc_tos(),
					cappath,
					NULL,
					NULL,
					smb_fname->twrp,
					smb_fname->flags);
	if (cap_smb_fname == NULL) {
		TALLOC_FREE(cappath);
		return NT_STATUS_NO_MEMORY;
	}
	status = SMB_VFS_NEXT_CREATE_DFS_PATHAT(handle,
			dirfsp,
			cap_smb_fname,
			reflist,
			referral_count);
	TALLOC_FREE(cappath);
	TALLOC_FREE(cap_smb_fname);
	return status;
}

static NTSTATUS cap_read_dfs_pathat(struct vfs_handle_struct *handle,
			TALLOC_CTX *mem_ctx,
			struct files_struct *dirfsp,
			struct smb_filename *smb_fname,
			struct referral **ppreflist,
			size_t *preferral_count)
{
	struct smb_filename *full_fname = NULL;
	struct smb_filename *cap_smb_fname = NULL;
	char *cappath = NULL;
	NTSTATUS status;

	full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						dirfsp,
						smb_fname);
	if (full_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	cappath = capencode(talloc_tos(), full_fname->base_name);
	if (cappath == NULL) {
		TALLOC_FREE(full_fname);
		return NT_STATUS_NO_MEMORY;
	}
	cap_smb_fname = synthetic_smb_fname(talloc_tos(),
				cappath,
				NULL,
				NULL,
				smb_fname->twrp,
				smb_fname->flags);
	if (cap_smb_fname == NULL) {
		TALLOC_FREE(full_fname);
		TALLOC_FREE(cappath);
		return NT_STATUS_NO_MEMORY;
	}

	status = SMB_VFS_NEXT_READ_DFS_PATHAT(handle,
			mem_ctx,
			handle->conn->cwd_fsp,
			cap_smb_fname,
			ppreflist,
			preferral_count);

	if (NT_STATUS_IS_OK(status)) {
		/* Return any stat(2) info. */
		smb_fname->st = cap_smb_fname->st;
	}

	TALLOC_FREE(full_fname);
	TALLOC_FREE(cappath);
	TALLOC_FREE(cap_smb_fname);
	return status;
}

static struct vfs_fn_pointers vfs_cap_fns = {
	.disk_free_fn = cap_disk_free,
	.get_quota_fn = cap_get_quota,
	.readdir_fn = cap_readdir,
	.mkdirat_fn = cap_mkdirat,
	.openat_fn = cap_openat,
	.renameat_fn = cap_renameat,
	.fstatat_fn = cap_fstatat,
	.stat_fn = cap_stat,
	.lstat_fn = cap_lstat,
	.unlinkat_fn = cap_unlinkat,
	.lchown_fn = cap_lchown,
	.chdir_fn = cap_chdir,
	.symlinkat_fn = cap_symlinkat,
	.readlinkat_fn = cap_readlinkat,
	.linkat_fn = cap_linkat,
	.mknodat_fn = cap_mknodat,
	.realpath_fn = cap_realpath,
	.getxattrat_send_fn = vfs_not_implemented_getxattrat_send,
	.getxattrat_recv_fn = vfs_not_implemented_getxattrat_recv,
	.fgetxattr_fn = cap_fgetxattr,
	.fremovexattr_fn = cap_fremovexattr,
	.fsetxattr_fn = cap_fsetxattr,
	.create_dfs_pathat_fn = cap_create_dfs_pathat,
	.read_dfs_pathat_fn = cap_read_dfs_pathat
};

static_decl_vfs;
NTSTATUS vfs_cap_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "cap",
				&vfs_cap_fns);
}

/* For CAP functions */
#define hex_tag ':'
#define is_hex(s)		((s)[0] == hex_tag)

/*******************************************************************
  original code -> ":xx"  - CAP format
********************************************************************/

static char *capencode(TALLOC_CTX *ctx, const char *from)
{
	char *out = NULL;
	const char *p1;
	char *to = NULL;
	size_t len = 0;

	for (p1 = from; *p1; p1++) {
		if ((unsigned char)*p1 >= 0x80) {
			len += 3;
		} else {
			len++;
		}
	}
	len++;

	to = talloc_array(ctx, char, len);
	if (!to) {
		return NULL;
	}

	for (out = to; *from;) {
		/* buffer husoku error */
		if ((unsigned char)*from >= 0x80) {
			*out++ = hex_tag;
			*out++ = nybble_to_hex_lower(((*from) >> 4));
			*out++ = nybble_to_hex_lower(*from);
			from++;
		} else {
			*out++ = *from++;
		}
  	}
	*out = '\0';
	return to;
}

/*******************************************************************
  CAP -> original code
********************************************************************/
/* ":xx" -> a byte */

static char *capdecode(TALLOC_CTX *ctx, const char *from)
{
	const char *p1;
	char *out = NULL;
	char *to = NULL;
	size_t len = 0;

	for (p1 = from; *p1; len++) {
		if (is_hex(p1)) {
			p1 += 3;
		} else {
			p1++;
		}
	}
	len++;

	to = talloc_array(ctx, char, len);
	if (!to) {
		return NULL;
	}

	for (out = to; *from;) {
		if (is_hex(from)) {
			(void)hex_byte(&from[1], (uint8_t *)(out++));
			from += 3;
		} else {
			*out++ = *from++;
		}
	}
	*out = '\0';
	return to;
}
