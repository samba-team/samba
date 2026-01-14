/*
 * Module to make use of awesome Btrfs features
 *
 * Copyright (C) David Disseldorp 2011-2013
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
#include "system/filesys.h"
#include <linux/ioctl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <libgen.h>
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "librpc/gen_ndr/smbXsrv.h"
#include "librpc/gen_ndr/ioctl.h"
#include "lib/util/tevent_ntstatus.h"
#include "offload_token.h"

static uint32_t btrfs_fs_capabilities(struct vfs_handle_struct *handle,
				      enum timestamp_set_resolution *_ts_res)
{
	uint32_t fs_capabilities;
	enum timestamp_set_resolution ts_res;

	/* inherit default capabilities, expose compression support */
	fs_capabilities = SMB_VFS_NEXT_FS_CAPABILITIES(handle, &ts_res);
	fs_capabilities |= (FILE_FILE_COMPRESSION
			    | FILE_SUPPORTS_BLOCK_REFCOUNTING);
	*_ts_res = ts_res;

	return fs_capabilities;
}

#define SHADOW_COPY_PREFIX "@GMT-"	/* vfs_shadow_copy format */
#define SHADOW_COPY_PATH_FORMAT "@GMT-%Y.%m.%d-%H.%M.%S"

#define BTRFS_SUBVOL_RDONLY		(1ULL << 1)
#define BTRFS_SUBVOL_NAME_MAX		4039
#define BTRFS_PATH_NAME_MAX		4087
struct btrfs_ioctl_vol_args_v2 {
	int64_t fd;
	uint64_t transid;
	uint64_t flags;
	uint64_t unused[4];
	char name[BTRFS_SUBVOL_NAME_MAX + 1];
};
struct btrfs_ioctl_vol_args {
	int64_t fd;
	char name[BTRFS_PATH_NAME_MAX + 1];
};

#define BTRFS_IOCTL_MAGIC 0x94
#define BTRFS_IOC_SNAP_DESTROY _IOW(BTRFS_IOCTL_MAGIC, 15, \
				    struct btrfs_ioctl_vol_args)
#define BTRFS_IOC_SNAP_CREATE_V2 _IOW(BTRFS_IOCTL_MAGIC, 23, \
				      struct btrfs_ioctl_vol_args_v2)

static NTSTATUS btrfs_fget_compression(struct vfs_handle_struct *handle,
				       TALLOC_CTX *mem_ctx,
				       struct files_struct *fsp,
				       uint16_t *_compression_fmt)
{
	struct sys_proc_fd_path_buf buf;
	int ret;
	long flags = 0;
	int fsp_fd = fsp_get_pathref_fd(fsp);
	int fd = -1;
	NTSTATUS status;

	if (!fsp->fsp_flags.is_pathref) {
		ret = ioctl(fsp_fd, FS_IOC_GETFLAGS, &flags);
		if (ret < 0) {
			DBG_WARNING("FS_IOC_GETFLAGS failed: %s, fd %lld\n",
				    strerror(errno), (long long)fsp_fd);
			return map_nt_error_from_unix(errno);
		}
		if (flags & FS_COMPR_FL) {
			*_compression_fmt = COMPRESSION_FORMAT_LZNT1;
		} else {
			*_compression_fmt = COMPRESSION_FORMAT_NONE;
		}
		return NT_STATUS_OK;
	}

	if (!fsp->fsp_flags.have_proc_fds) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	fd = open(sys_proc_fd_path(fsp_fd, &buf), O_RDONLY);
	if (fd == -1) {
		DBG_DEBUG("/proc open of %s failed: %s\n",
			  buf.buf,
			  strerror(errno));
		return map_nt_error_from_unix(errno);
	}

	ret = ioctl(fd, FS_IOC_GETFLAGS, &flags);
	if (ret < 0) {
		DEBUG(1, ("FS_IOC_GETFLAGS failed: %s, fd %lld\n",
			  strerror(errno), (long long)fd));
		status = map_nt_error_from_unix(errno);
		goto err_close;
	}
	if (flags & FS_COMPR_FL) {
		*_compression_fmt = COMPRESSION_FORMAT_LZNT1;
	} else {
		*_compression_fmt = COMPRESSION_FORMAT_NONE;
	}
	status = NT_STATUS_OK;

err_close:
	if (fd != -1) {
		close(fd);
	}

	return status;
}

static NTSTATUS btrfs_set_compression(struct vfs_handle_struct *handle,
				      TALLOC_CTX *mem_ctx,
				      struct files_struct *fsp,
				      uint16_t compression_fmt)
{
	int ret;
	long flags = 0;
	int fd;
	NTSTATUS status;

	if ((fsp == NULL) || (fsp_get_io_fd(fsp) == -1)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto err_out;
	}
	fd = fsp_get_io_fd(fsp);

	ret = ioctl(fd, FS_IOC_GETFLAGS, &flags);
	if (ret < 0) {
		DEBUG(1, ("FS_IOC_GETFLAGS failed: %s, fd %d\n",
			  strerror(errno), fd));
		status = map_nt_error_from_unix(errno);
		goto err_out;
	}

	if (compression_fmt == COMPRESSION_FORMAT_NONE) {
		DEBUG(5, ("setting compression\n"));
		flags &= (~FS_COMPR_FL);
	} else if ((compression_fmt == COMPRESSION_FORMAT_DEFAULT)
		|| (compression_fmt == COMPRESSION_FORMAT_LZNT1)) {
		DEBUG(5, ("clearing compression\n"));
		flags |= FS_COMPR_FL;
	} else {
		DEBUG(1, ("invalid compression format 0x%x\n",
			  (int)compression_fmt));
		status = NT_STATUS_INVALID_PARAMETER;
		goto err_out;
	}

	ret = ioctl(fd, FS_IOC_SETFLAGS, &flags);
	if (ret < 0) {
		DEBUG(1, ("FS_IOC_SETFLAGS failed: %s, fd %d\n",
			  strerror(errno), fd));
		status = map_nt_error_from_unix(errno);
		goto err_out;
	}
	status = NT_STATUS_OK;
err_out:
	return status;
}

/*
 * Check whether a path can be shadow copied. Return the base volume, allowing
 * the caller to determine if multiple paths lie on the same base volume.
 */
#define BTRFS_INODE_SUBVOL 256
static NTSTATUS btrfs_snap_check_path(struct vfs_handle_struct *handle,
				      TALLOC_CTX *mem_ctx,
				      const char *service_path,
				      char **base_volume)
{
	struct stat st;
	char *base;

	if (!lp_parm_bool(SNUM(handle->conn),
			 "btrfs", "manipulate snapshots", false)) {
		DEBUG(2, ("Btrfs snapshot manipulation disabled, passing\n"));
		return SMB_VFS_NEXT_SNAP_CHECK_PATH(handle, mem_ctx,
						    service_path, base_volume);
	}

	/* btrfs userspace uses this logic to confirm subvolume */
	if (stat(service_path, &st) < 0) {
		return NT_STATUS_NOT_SUPPORTED;
	}
	if ((st.st_ino != BTRFS_INODE_SUBVOL) || !S_ISDIR(st.st_mode)) {
		DEBUG(0, ("%s not a btrfs subvolume, snapshots not available\n",
			  service_path));
		return NT_STATUS_NOT_SUPPORTED;
	}

	/* we "snapshot" the service path itself */
	base = talloc_strdup(mem_ctx, service_path);
	if (base == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	*base_volume = base;

	return NT_STATUS_OK;
}

static NTSTATUS btrfs_gen_snap_dest_path(TALLOC_CTX *mem_ctx,
					 const char *src_path,
					 time_t *tstamp,
					 char **dest_path, char **subvolume)
{
	struct tm t_gmt;
	char time_str[50];
	size_t tlen;

	gmtime_r(tstamp, &t_gmt);

	tlen = strftime(time_str, ARRAY_SIZE(time_str),
			SHADOW_COPY_PATH_FORMAT, &t_gmt);
	if (tlen <= 0) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	*dest_path = talloc_strdup(mem_ctx, src_path);
	*subvolume = talloc_strdup(mem_ctx, time_str);
	if ((*dest_path == NULL) || (*subvolume == NULL)) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

static NTSTATUS btrfs_snap_create(struct vfs_handle_struct *handle,
				  TALLOC_CTX *mem_ctx,
				  const char *base_volume,
				  time_t *tstamp,
				  bool rw,
				  char **_base_path,
				  char **_snap_path)
{
	struct btrfs_ioctl_vol_args_v2 ioctl_arg;
	DIR *src_dir;
	DIR *dest_dir;
	int src_fd;
	int dest_fd;
	char *dest_path = NULL;
	char *dest_subvolume = NULL;
	int ret;
	NTSTATUS status;
	char *base_path;
	char *snap_path;
	TALLOC_CTX *tmp_ctx;
	int saved_errno;
	size_t len;

	if (!lp_parm_bool(SNUM(handle->conn),
			  "btrfs", "manipulate snapshots", false)) {
		DEBUG(2, ("Btrfs snapshot manipulation disabled, passing\n"));
		return SMB_VFS_NEXT_SNAP_CREATE(handle, mem_ctx, base_volume,
						tstamp, rw, _base_path,
						_snap_path);
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	base_path = talloc_strdup(tmp_ctx, base_volume);
	if (base_path == NULL) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	status = btrfs_gen_snap_dest_path(tmp_ctx, base_volume, tstamp,
					  &dest_path, &dest_subvolume);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return status;
	}

	snap_path = talloc_asprintf(tmp_ctx, "%s/%s", dest_path,
				    dest_subvolume);
	if (snap_path == NULL) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	src_dir = opendir(base_volume);
	if (src_dir == NULL) {
		DEBUG(0, ("snap src %s open failed: %s\n",
			  base_volume, strerror(errno)));
		status = map_nt_error_from_unix(errno);
		talloc_free(tmp_ctx);
		return status;
	}
	src_fd = dirfd(src_dir);
	if (src_fd < 0) {
		status = map_nt_error_from_unix(errno);
		closedir(src_dir);
		talloc_free(tmp_ctx);
		return status;
	}

	dest_dir = opendir(dest_path);
	if (dest_dir == NULL) {
		DEBUG(0, ("snap dest %s open failed: %s\n",
			  dest_path, strerror(errno)));
		status = map_nt_error_from_unix(errno);
		closedir(src_dir);
		talloc_free(tmp_ctx);
		return status;
	}
	dest_fd = dirfd(dest_dir);
	if (dest_fd < 0) {
		status = map_nt_error_from_unix(errno);
		closedir(src_dir);
		closedir(dest_dir);
		talloc_free(tmp_ctx);
		return status;
	}

	/* avoid zeroing the entire struct here, name is 4k */
	ioctl_arg.fd = src_fd;
	ioctl_arg.transid = 0;
	ioctl_arg.flags = (rw == false) ? BTRFS_SUBVOL_RDONLY : 0;
	memset(ioctl_arg.unused, 0, sizeof(ioctl_arg.unused));
	len = strlcpy(ioctl_arg.name, dest_subvolume,
		      ARRAY_SIZE(ioctl_arg.name));
	if (len >= ARRAY_SIZE(ioctl_arg.name)) {
		DEBUG(1, ("subvolume name too long for SNAP_CREATE ioctl\n"));
		closedir(src_dir);
		closedir(dest_dir);
		talloc_free(tmp_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	become_root();
	ret = ioctl(dest_fd, BTRFS_IOC_SNAP_CREATE_V2, &ioctl_arg);
	saved_errno = errno;
	unbecome_root();
	if (ret < 0) {
		DEBUG(0, ("%s -> %s(%s) BTRFS_IOC_SNAP_CREATE_V2 failed: %s\n",
			  base_volume, dest_path, dest_subvolume,
			  strerror(saved_errno)));
		status = map_nt_error_from_unix(saved_errno);
		closedir(src_dir);
		closedir(dest_dir);
		talloc_free(tmp_ctx);
		return status;
	}
	DEBUG(5, ("%s -> %s(%s) BTRFS_IOC_SNAP_CREATE_V2 done\n",
		  base_volume, dest_path, dest_subvolume));

	*_base_path = talloc_steal(mem_ctx, base_path);
	*_snap_path = talloc_steal(mem_ctx, snap_path);
	closedir(src_dir);
	closedir(dest_dir);
	talloc_free(tmp_ctx);

	return NT_STATUS_OK;
}

static NTSTATUS btrfs_snap_delete(struct vfs_handle_struct *handle,
				  TALLOC_CTX *mem_ctx,
				  char *base_path,
				  char *snap_path)
{
	char *tstr;
	struct tm t_gmt = {};
	DIR *dest_dir;
	int dest_fd;
	struct btrfs_ioctl_vol_args ioctl_arg;
	int ret;
	NTSTATUS status;
	char *dest_path;
	char *subvolume;
	TALLOC_CTX *tmp_ctx;
	int saved_errno;
	size_t len;

	if (!lp_parm_bool(SNUM(handle->conn),
			  "btrfs", "manipulate snapshots", false)) {
		DEBUG(2, ("Btrfs snapshot manipulation disabled, passing\n"));
		return SMB_VFS_NEXT_SNAP_DELETE(handle, mem_ctx,
						base_path, snap_path);
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	dest_path = talloc_strdup(tmp_ctx, snap_path);
	if (dest_path == NULL) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	subvolume = talloc_strdup(tmp_ctx, snap_path);
	if (subvolume == NULL) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	dest_path = dirname(dest_path);
	subvolume = basename(subvolume);

	/* confirm snap_path matches creation format */
	tstr = strptime(subvolume, SHADOW_COPY_PATH_FORMAT, &t_gmt);
	if ((tstr == NULL) || (*tstr != '\0')) {
		DEBUG(0, ("snapshot path %s does not match creation format\n",
			  snap_path));
		talloc_free(tmp_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	dest_dir = opendir(dest_path);
	if (dest_dir == NULL) {
		DEBUG(0, ("snap destroy dest %s open failed: %s\n",
			  dest_path, strerror(errno)));
		status = map_nt_error_from_unix(errno);
		talloc_free(tmp_ctx);
		return status;
	}
	dest_fd = dirfd(dest_dir);
	if (dest_fd < 0) {
		status = map_nt_error_from_unix(errno);
		closedir(dest_dir);
		talloc_free(tmp_ctx);
		return status;
	}

	ioctl_arg.fd = -1;	/* not needed */
	len = strlcpy(ioctl_arg.name, subvolume, ARRAY_SIZE(ioctl_arg.name));
	if (len >= ARRAY_SIZE(ioctl_arg.name)) {
		DEBUG(1, ("subvolume name too long for SNAP_DESTROY ioctl\n"));
		closedir(dest_dir);
		talloc_free(tmp_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	become_root();
	ret = ioctl(dest_fd, BTRFS_IOC_SNAP_DESTROY, &ioctl_arg);
	saved_errno = errno;
	unbecome_root();
	if (ret < 0) {
		DEBUG(0, ("%s(%s) BTRFS_IOC_SNAP_DESTROY failed: %s\n",
			  dest_path, subvolume, strerror(saved_errno)));
		status = map_nt_error_from_unix(saved_errno);
		closedir(dest_dir);
		talloc_free(tmp_ctx);
		return status;
	}
	DEBUG(5, ("%s(%s) BTRFS_IOC_SNAP_DESTROY done\n",
		  dest_path, subvolume));

	closedir(dest_dir);
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

static struct vfs_fn_pointers btrfs_fns = {
	.fs_capabilities_fn = btrfs_fs_capabilities,
	.fget_compression_fn = btrfs_fget_compression,
	.set_compression_fn = btrfs_set_compression,
	.snap_check_path_fn = btrfs_snap_check_path,
	.snap_create_fn = btrfs_snap_create,
	.snap_delete_fn = btrfs_snap_delete,
};

static_decl_vfs;
NTSTATUS vfs_btrfs_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"btrfs", &btrfs_fns);
}
