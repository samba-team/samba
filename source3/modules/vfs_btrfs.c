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
#include "system/filesys.h"
#include "includes.h"
#include "smbd/smbd.h"
#include "librpc/gen_ndr/smbXsrv.h"
#include "librpc/gen_ndr/ioctl.h"
#include "lib/util/tevent_ntstatus.h"

static uint32_t btrfs_fs_capabilities(struct vfs_handle_struct *handle,
				      enum timestamp_set_resolution *_ts_res)
{
	uint32_t fs_capabilities;
	enum timestamp_set_resolution ts_res;

	/* inherit default capabilities, expose compression support */
	fs_capabilities = SMB_VFS_NEXT_FS_CAPABILITIES(handle, &ts_res);
	fs_capabilities |= FILE_FILE_COMPRESSION;
	*_ts_res = ts_res;

	return fs_capabilities;
}

struct btrfs_ioctl_clone_range_args {
	int64_t src_fd;
	uint64_t src_offset;
	uint64_t src_length;
	uint64_t dest_offset;
};

#define BTRFS_IOCTL_MAGIC 0x94
#define BTRFS_IOC_CLONE_RANGE _IOW(BTRFS_IOCTL_MAGIC, 13, \
				   struct btrfs_ioctl_clone_range_args)

struct btrfs_cc_state {
	struct vfs_handle_struct *handle;
	off_t copied;
	struct tevent_req *subreq;	/* non-null if passed to next VFS fn */
};
static void btrfs_copy_chunk_done(struct tevent_req *subreq);

static struct tevent_req *btrfs_copy_chunk_send(struct vfs_handle_struct *handle,
						TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct files_struct *src_fsp,
						off_t src_off,
						struct files_struct *dest_fsp,
						off_t dest_off,
						off_t num)
{
	struct tevent_req *req;
	struct btrfs_cc_state *cc_state;
	struct btrfs_ioctl_clone_range_args cr_args;
	struct lock_struct src_lck;
	struct lock_struct dest_lck;
	int ret;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &cc_state, struct btrfs_cc_state);
	if (req == NULL) {
		return NULL;
	}
	cc_state->handle = handle;

	if (num == 0) {
		/*
		 * With a @src_length of zero, BTRFS_IOC_CLONE_RANGE clones
		 * all data from @src_offset->EOF! This is certainly not what
		 * the caller expects, and not what vfs_default does.
		 */
		cc_state->subreq = SMB_VFS_NEXT_COPY_CHUNK_SEND(handle,
								cc_state, ev,
								src_fsp,
								src_off,
								dest_fsp,
								dest_off, num);
		if (tevent_req_nomem(cc_state->subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(cc_state->subreq,
					btrfs_copy_chunk_done,
					req);
		return req;
	}

	status = vfs_stat_fsp(src_fsp);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	if (src_fsp->fsp_name->st.st_ex_size < src_off + num) {
		/* [MS-SMB2] Handling a Server-Side Data Copy Request */
		tevent_req_nterror(req, NT_STATUS_INVALID_VIEW_SIZE);
		return tevent_req_post(req, ev);
	}

	if (src_fsp->op == NULL || dest_fsp->op == NULL) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return tevent_req_post(req, ev);
	}

	init_strict_lock_struct(src_fsp,
				src_fsp->op->global->open_persistent_id,
				src_off,
				num,
				READ_LOCK,
				&src_lck);
	init_strict_lock_struct(dest_fsp,
				dest_fsp->op->global->open_persistent_id,
				dest_off,
				num,
				WRITE_LOCK,
				&dest_lck);

	if (!SMB_VFS_STRICT_LOCK(src_fsp->conn, src_fsp, &src_lck)) {
		tevent_req_nterror(req, NT_STATUS_FILE_LOCK_CONFLICT);
		return tevent_req_post(req, ev);
	}
	if (!SMB_VFS_STRICT_LOCK(dest_fsp->conn, dest_fsp, &dest_lck)) {
		SMB_VFS_STRICT_UNLOCK(src_fsp->conn, src_fsp, &src_lck);
		tevent_req_nterror(req, NT_STATUS_FILE_LOCK_CONFLICT);
		return tevent_req_post(req, ev);
	}

	ZERO_STRUCT(cr_args);
	cr_args.src_fd = src_fsp->fh->fd;
	cr_args.src_offset = (uint64_t)src_off;
	cr_args.dest_offset = (uint64_t)dest_off;
	cr_args.src_length = (uint64_t)num;

	ret = ioctl(dest_fsp->fh->fd, BTRFS_IOC_CLONE_RANGE, &cr_args);
	SMB_VFS_STRICT_UNLOCK(dest_fsp->conn, dest_fsp, &dest_lck);
	SMB_VFS_STRICT_UNLOCK(src_fsp->conn, src_fsp, &src_lck);
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
		cc_state->subreq = SMB_VFS_NEXT_COPY_CHUNK_SEND(handle,
								cc_state, ev,
								src_fsp,
								src_off,
								dest_fsp,
								dest_off, num);
		if (tevent_req_nomem(cc_state->subreq, req)) {
			return tevent_req_post(req, ev);
		}
		/* wait for subreq completion */
		tevent_req_set_callback(cc_state->subreq,
					btrfs_copy_chunk_done,
					req);
		return req;
	}

	DEBUG(5, ("BTRFS_IOC_CLONE_RANGE returned %d\n", ret));
	/* BTRFS_IOC_CLONE_RANGE is all or nothing */
	cc_state->copied = num;
	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

/* only used if the request is passed through to next VFS module */
static void btrfs_copy_chunk_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct btrfs_cc_state *cc_state = tevent_req_data(req,
							struct btrfs_cc_state);
	NTSTATUS status;

	status = SMB_VFS_NEXT_COPY_CHUNK_RECV(cc_state->handle,
					      cc_state->subreq,
					      &cc_state->copied);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS btrfs_copy_chunk_recv(struct vfs_handle_struct *handle,
				      struct tevent_req *req,
				      off_t *copied)
{
	NTSTATUS status;
	struct btrfs_cc_state *cc_state = tevent_req_data(req,
							struct btrfs_cc_state);

	if (tevent_req_is_nterror(req, &status)) {
		DEBUG(4, ("server side copy chunk failed: %s\n",
			  nt_errstr(status)));
		tevent_req_received(req);
		return status;
	}

	DEBUG(10, ("server side copy chunk copied %llu\n",
		   (unsigned long long)cc_state->copied));
	*copied = cc_state->copied;
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


static struct vfs_fn_pointers btrfs_fns = {
	.fs_capabilities_fn = btrfs_fs_capabilities,
	.copy_chunk_send_fn = btrfs_copy_chunk_send,
	.copy_chunk_recv_fn = btrfs_copy_chunk_recv,
	.get_compression_fn = btrfs_get_compression,
	.set_compression_fn = btrfs_set_compression,
};

NTSTATUS vfs_btrfs_init(void);
NTSTATUS vfs_btrfs_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"btrfs", &btrfs_fns);
}
