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

#include <linux/ioctl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <libgen.h>
#include "system/filesys.h"
#include "includes.h"
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

struct btrfs_ioctl_clone_range_args {
	int64_t src_fd;
	uint64_t src_offset;
	uint64_t src_length;
	uint64_t dest_offset;
};

#define BTRFS_IOCTL_MAGIC 0x94
#define BTRFS_IOC_CLONE_RANGE _IOW(BTRFS_IOCTL_MAGIC, 13, \
				   struct btrfs_ioctl_clone_range_args)
#define BTRFS_IOC_SNAP_DESTROY _IOW(BTRFS_IOCTL_MAGIC, 15, \
				    struct btrfs_ioctl_vol_args)
#define BTRFS_IOC_SNAP_CREATE_V2 _IOW(BTRFS_IOCTL_MAGIC, 23, \
				      struct btrfs_ioctl_vol_args_v2)

static struct vfs_offload_ctx *btrfs_offload_ctx;

struct btrfs_offload_read_state {
	struct vfs_handle_struct *handle;
	files_struct *fsp;
	DATA_BLOB token;
};

static void btrfs_offload_read_done(struct tevent_req *subreq);

static struct tevent_req *btrfs_offload_read_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct vfs_handle_struct *handle,
	files_struct *fsp,
	uint32_t fsctl,
	uint32_t ttl,
	off_t offset,
	size_t to_copy)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct btrfs_offload_read_state *state = NULL;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct btrfs_offload_read_state);
	if (req == NULL) {
		return NULL;
	}
	*state = (struct btrfs_offload_read_state) {
		.handle = handle,
		.fsp = fsp,
	};

	status = vfs_offload_token_ctx_init(fsp->conn->sconn->client,
					    &btrfs_offload_ctx);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	if (fsctl == FSCTL_DUP_EXTENTS_TO_FILE) {
		status = vfs_offload_token_create_blob(state, fsp, fsctl,
						       &state->token);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}

		status = vfs_offload_token_db_store_fsp(btrfs_offload_ctx, fsp,
							&state->token);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	subreq = SMB_VFS_NEXT_OFFLOAD_READ_SEND(mem_ctx, ev, handle, fsp,
						fsctl, ttl, offset, to_copy);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, btrfs_offload_read_done, req);
	return req;
}

static void btrfs_offload_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct btrfs_offload_read_state *state = tevent_req_data(
		req, struct btrfs_offload_read_state);
	NTSTATUS status;

	status = SMB_VFS_NEXT_OFFLOAD_READ_RECV(subreq,
						state->handle,
						state,
						&state->token);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	status = vfs_offload_token_db_store_fsp(btrfs_offload_ctx,
						state->fsp,
						&state->token);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
	return;
}

static NTSTATUS btrfs_offload_read_recv(struct tevent_req *req,
					struct vfs_handle_struct *handle,
					TALLOC_CTX *mem_ctx,
					DATA_BLOB *token)
{
	struct btrfs_offload_read_state *state = tevent_req_data(
		req, struct btrfs_offload_read_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	token->length = state->token.length;
	token->data = talloc_move(mem_ctx, &state->token.data);

	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct btrfs_offload_write_state {
	struct vfs_handle_struct *handle;
	off_t copied;
	bool need_unbecome_user;
};

static void btrfs_offload_write_cleanup(struct tevent_req *req,
					enum tevent_req_state req_state)
{
	struct btrfs_offload_write_state *state =
		tevent_req_data(req,
		struct btrfs_offload_write_state);
	bool ok;

	if (!state->need_unbecome_user) {
		return;
	}

	ok = unbecome_user_without_service();
	SMB_ASSERT(ok);
	state->need_unbecome_user = false;
}

static void btrfs_offload_write_done(struct tevent_req *subreq);

static struct tevent_req *btrfs_offload_write_send(struct vfs_handle_struct *handle,
						TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						uint32_t fsctl,
						DATA_BLOB *token,
						off_t transfer_offset,
						struct files_struct *dest_fsp,
						off_t dest_off,
						off_t num)
{
	struct tevent_req *req = NULL;
	struct btrfs_offload_write_state *state = NULL;
	struct tevent_req *subreq = NULL;
	struct btrfs_ioctl_clone_range_args cr_args;
	struct lock_struct src_lck;
	struct lock_struct dest_lck;
	off_t src_off = transfer_offset;
	files_struct *src_fsp = NULL;
	int ret;
	bool handle_offload_write = true;
	bool do_locking = false;
	NTSTATUS status;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct btrfs_offload_write_state);
	if (req == NULL) {
		return NULL;
	}

	state->handle = handle;

	tevent_req_set_cleanup_fn(req, btrfs_offload_write_cleanup);

	status = vfs_offload_token_db_fetch_fsp(btrfs_offload_ctx,
						token, &src_fsp);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	switch (fsctl) {
	case FSCTL_SRV_COPYCHUNK:
	case FSCTL_SRV_COPYCHUNK_WRITE:
		do_locking = true;
		break;

	case FSCTL_DUP_EXTENTS_TO_FILE:
		/* dup extents does not use locking */
		break;

	default:
		handle_offload_write = false;
		break;
	}

	if (num == 0) {
		/*
		 * With a @src_length of zero, BTRFS_IOC_CLONE_RANGE clones
		 * all data from @src_offset->EOF! This is certainly not what
		 * the caller expects, and not what vfs_default does.
		 */
		handle_offload_write = false;
	}

	if (!handle_offload_write) {
		subreq = SMB_VFS_NEXT_OFFLOAD_WRITE_SEND(handle,
							 state,
							 ev,
							 fsctl,
							 token,
							 transfer_offset,
							 dest_fsp,
							 dest_off,
							 num);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq,
					btrfs_offload_write_done,
					req);
		return req;
	}

	status = vfs_offload_token_check_handles(
		fsctl, src_fsp, dest_fsp);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}

	ok = become_user_without_service_by_fsp(src_fsp);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
		return tevent_req_post(req, ev);
	}
	state->need_unbecome_user = true;

	status = vfs_stat_fsp(src_fsp);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	if (src_fsp->fsp_name->st.st_ex_size < src_off + num) {
		/* [MS-SMB2] Handling a Server-Side Data Copy Request */
		tevent_req_nterror(req, NT_STATUS_INVALID_VIEW_SIZE);
		return tevent_req_post(req, ev);
	}

	if (do_locking) {
		init_strict_lock_struct(src_fsp,
					src_fsp->op->global->open_persistent_id,
					src_off,
					num,
					READ_LOCK,
					&src_lck);
		if (!SMB_VFS_STRICT_LOCK_CHECK(src_fsp->conn, src_fsp, &src_lck)) {
			tevent_req_nterror(req, NT_STATUS_FILE_LOCK_CONFLICT);
			return tevent_req_post(req, ev);
		}
	}

	ok = unbecome_user_without_service();
	SMB_ASSERT(ok);
	state->need_unbecome_user = false;

	if (do_locking) {
		init_strict_lock_struct(dest_fsp,
					dest_fsp->op->global->open_persistent_id,
					dest_off,
					num,
					WRITE_LOCK,
					&dest_lck);

		if (!SMB_VFS_STRICT_LOCK_CHECK(dest_fsp->conn, dest_fsp, &dest_lck)) {
			tevent_req_nterror(req, NT_STATUS_FILE_LOCK_CONFLICT);
			return tevent_req_post(req, ev);
		}
	}

	ZERO_STRUCT(cr_args);
	cr_args.src_fd = src_fsp->fh->fd;
	cr_args.src_offset = (uint64_t)src_off;
	cr_args.dest_offset = (uint64_t)dest_off;
	cr_args.src_length = (uint64_t)num;

	ret = ioctl(dest_fsp->fh->fd, BTRFS_IOC_CLONE_RANGE, &cr_args);
	if (ret < 0) {
		/*
		 * BTRFS_IOC_CLONE_RANGE only supports 'sectorsize' aligned
		 * cloning. Which is 4096 by default, therefore fall back to
		 * manual read/write on failure.
		 */
		DEBUG(5, ("BTRFS_IOC_CLONE_RANGE failed: %s, length %llu, "
			  "src fd: %lld off: %llu, dest fd: %d off: %llu\n",
			  strerror(errno),
			  (unsigned long long)cr_args.src_length,
			  (long long)cr_args.src_fd,
			  (unsigned long long)cr_args.src_offset,
			  dest_fsp->fh->fd,
			  (unsigned long long)cr_args.dest_offset));
		subreq = SMB_VFS_NEXT_OFFLOAD_WRITE_SEND(handle,
							 state,
							 ev,
							 fsctl,
							 token,
							 transfer_offset,
							 dest_fsp,
							 dest_off,
							 num);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		/* wait for subreq completion */
		tevent_req_set_callback(subreq,
					btrfs_offload_write_done,
					req);
		return req;
	}

	DEBUG(5, ("BTRFS_IOC_CLONE_RANGE returned %d\n", ret));
	/* BTRFS_IOC_CLONE_RANGE is all or nothing */
	state->copied = num;
	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

/* only used if the request is passed through to next VFS module */
static void btrfs_offload_write_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct btrfs_offload_write_state *state =
		tevent_req_data(req,
		struct btrfs_offload_write_state);
	NTSTATUS status;

	status = SMB_VFS_NEXT_OFFLOAD_WRITE_RECV(state->handle,
						 subreq,
						 &state->copied);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS btrfs_offload_write_recv(struct vfs_handle_struct *handle,
					 struct tevent_req *req,
					 off_t *copied)
{
	struct btrfs_offload_write_state *state =
		tevent_req_data(req,
		struct btrfs_offload_write_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		DEBUG(4, ("server side copy chunk failed: %s\n",
			  nt_errstr(status)));
		tevent_req_received(req);
		return status;
	}

	DEBUG(10, ("server side copy chunk copied %llu\n",
		   (unsigned long long)state->copied));
	*copied = state->copied;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

/*
 * caller must pass a non-null fsp or smb_fname. If fsp is null, then
 * fall back to opening the corresponding file to issue the ioctl.
 */
static NTSTATUS btrfs_get_compression(struct vfs_handle_struct *handle,
				      TALLOC_CTX *mem_ctx,
				      struct files_struct *fsp,
				      struct smb_filename *smb_fname,
				      uint16_t *_compression_fmt)
{
	int ret;
	long flags = 0;
	int fd;
	bool opened = false;
	NTSTATUS status;
	DIR *dir = NULL;

	if ((fsp != NULL) && (fsp->fh->fd != -1)) {
		fd = fsp->fh->fd;
	} else if (smb_fname != NULL) {
		if (S_ISDIR(smb_fname->st.st_ex_mode)) {
			dir = opendir(smb_fname->base_name);
			if (dir == NULL) {
				return NT_STATUS_UNSUCCESSFUL;
			}
			opened = true;
			fd = dirfd(dir);
			if (fd < 0) {
				status = NT_STATUS_UNSUCCESSFUL;
				goto err_close;
			}
		} else {
			fd = open(smb_fname->base_name, O_RDONLY);
			if (fd < 0) {
				return NT_STATUS_UNSUCCESSFUL;
			}
			opened = true;
		}
	} else {
		return NT_STATUS_INVALID_PARAMETER;
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
	if (opened) {
		if (dir != NULL) {
			closedir(dir);
		} else {
			close(fd);
		}
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

	if ((fsp == NULL) || (fsp->fh->fd == -1)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto err_out;
	}
	fd = fsp->fh->fd;

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
	struct tm t_gmt;
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
	.offload_read_send_fn = btrfs_offload_read_send,
	.offload_read_recv_fn = btrfs_offload_read_recv,
	.offload_write_send_fn = btrfs_offload_write_send,
	.offload_write_recv_fn = btrfs_offload_write_recv,
	.get_compression_fn = btrfs_get_compression,
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
