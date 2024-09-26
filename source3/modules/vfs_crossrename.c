/*
 * Copyright (c) Björn Jacke 2010
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
#include "transfer_file.h"
#include "smbprofile.h"

#define MODULE "crossrename"
static off_t module_sizelimit;

static int crossrename_connect(
                struct vfs_handle_struct *  handle,
                const char *                service,
                const char *                user)
{
	int ret = SMB_VFS_NEXT_CONNECT(handle, service, user);

	if (ret < 0) {
		return ret;
	}

	module_sizelimit = (off_t) lp_parm_int(SNUM(handle->conn),
					MODULE, "sizelimit", 20);
	/* convert from MiB to byte: */
	module_sizelimit *= 1048576;

	return 0;
}

/*********************************************************
 For rename across filesystems initial Patch from Warren Birnbaum
 <warrenb@hpcvscdp.cv.hp.com>
**********************************************************/

static NTSTATUS copy_reg(vfs_handle_struct *handle,
			 struct files_struct *srcfsp,
			 const struct smb_filename *source,
			 struct files_struct *dstfsp,
			 const struct smb_filename *dest)
{
	NTSTATUS status = NT_STATUS_OK;
	int ret;
	off_t off;
	int ifd = -1;
	int ofd = -1;
	struct timespec ts[2];

	if (!VALID_STAT(source->st)) {
		status = NT_STATUS_OBJECT_PATH_NOT_FOUND;
		goto out;
	}
	if (!S_ISREG(source->st.st_ex_mode)) {
		status = NT_STATUS_OBJECT_PATH_NOT_FOUND;
		goto out;
	}

	if (source->st.st_ex_size > module_sizelimit) {
		DBG_INFO("%s: size of %s larger than sizelimit (%lld > %lld), "
			 "rename prohibited\n",
			MODULE,
			source->base_name,
			(long long)source->st.st_ex_size,
			(long long)module_sizelimit);
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	ret = SMB_VFS_NEXT_UNLINKAT(handle,
				    dstfsp,
				    dest,
				    0);
	if (ret == -1 && errno != ENOENT) {
		status = map_nt_error_from_unix(errno);
		goto out;
	}

	ifd = openat(fsp_get_pathref_fd(srcfsp),
		     source->base_name,
		     O_RDONLY,
		     0);
	if (ifd < 0) {
		status = map_nt_error_from_unix(errno);
		goto out;
	}

	ofd = openat(fsp_get_pathref_fd(dstfsp),
		     dest->base_name,
		     O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW,
		     0600);
	if (ofd < 0) {
		status = map_nt_error_from_unix(errno);
		goto out;
	}

	off = transfer_file(ifd, ofd, source->st.st_ex_size);
	if (off == -1) {
		status = map_nt_error_from_unix(errno);
		goto out;
	}

	ret = fchown(ofd, source->st.st_ex_uid, source->st.st_ex_gid);
	if (ret == -1 && errno != EPERM) {
		status = map_nt_error_from_unix(errno);
		goto out;
	}

	/*
	 * fchown turns off set[ug]id bits for non-root,
	 * so do the chmod last.
	 */
	ret = fchmod(ofd, source->st.st_ex_mode & 07777);
	if (ret == -1 && errno != EPERM) {
		status = map_nt_error_from_unix(errno);
		goto out;
	}

	/* Try to copy the old file's modtime and access time.  */
	ts[0] = source->st.st_ex_atime;
	ts[1] = source->st.st_ex_mtime;
	ret = futimens(ofd, ts);
	if (ret == -1) {
		DBG_DEBUG("Updating the time stamp on destinaton '%s' failed "
			  "with '%s'. Rename operation can continue.\n",
			  dest->base_name,
			  strerror(errno));
	}

	ret = close(ifd);
	if (ret == -1) {
		status = map_nt_error_from_unix(errno);
		goto out;
	}
	ifd = -1;

	ret = close(ofd);
	if (ret == -1) {
		status = map_nt_error_from_unix(errno);
		goto out;
	}
	ofd = -1;

	ret = SMB_VFS_NEXT_UNLINKAT(handle, srcfsp, source, 0);
	if (ret == -1) {
		status = map_nt_error_from_unix(errno);
	}

out:
	if (ifd != -1) {
		ret = close(ifd);
		if (ret == -1) {
			DBG_DEBUG("Failed to close %s (%d): %s.\n",
				  source->base_name,
				  ifd,
				  strerror(errno));
		}
	}
	if (ofd != -1) {
		ret = close(ofd);
		if (ret == -1) {
			DBG_DEBUG("Failed to close %s (%d): %s.\n",
				  dest->base_name,
				  ofd,
				  strerror(errno));
		}
	}

	return status;
}

static int crossrename_renameat(vfs_handle_struct *handle,
			files_struct *srcfsp,
			const struct smb_filename *smb_fname_src,
			files_struct *dstfsp,
			const struct smb_filename *smb_fname_dst,
			const struct vfs_rename_how *how)
{
	int result = -1;

	START_PROFILE(syscall_renameat);

	if (smb_fname_src->stream_name || smb_fname_dst->stream_name) {
		errno = ENOENT;
		goto out;
	}

	result = SMB_VFS_NEXT_RENAMEAT(handle,
				       srcfsp,
				       smb_fname_src,
				       dstfsp,
				       smb_fname_dst,
				       how);

	if ((result == -1) && (errno == EXDEV)) {
		/* Rename across filesystems needed. */
		NTSTATUS status = copy_reg(handle,
					   srcfsp,
					   smb_fname_src,
					   dstfsp,
					   smb_fname_dst);
		result = 0;
		if (!NT_STATUS_IS_OK(status)) {
			errno = map_errno_from_nt_status(status);
			result = -1;
		}
	}

 out:
	END_PROFILE(syscall_renameat);
	return result;
}


static struct vfs_fn_pointers vfs_crossrename_fns = {
	.connect_fn = crossrename_connect,
	.renameat_fn = crossrename_renameat
};

static_decl_vfs;
NTSTATUS vfs_crossrename_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, MODULE,
				&vfs_crossrename_fns);
}

