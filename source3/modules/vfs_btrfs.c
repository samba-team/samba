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
#include <sys/ioctl.h>
#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "../librpc/gen_ndr/smbXsrv.h"
#include "lib/util/tevent_ntstatus.h"

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

	status = vfs_stat_fsp(src_fsp);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	if (src_fsp->fsp_name->st.st_ex_size < src_off + num) {
		/* [MS-SMB2] Handling a Server-Side Data Copy Request */
		tevent_req_nterror(req, NT_STATUS_INVALID_VIEW_SIZE);
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
	SMB_VFS_STRICT_UNLOCK(src_fsp->conn, src_fsp, &dest_lck);
	SMB_VFS_STRICT_UNLOCK(src_fsp->conn, src_fsp, &src_lck);
	if (ret < 0) {
		/*
		 * BTRFS_IOC_CLONE_RANGE only supports 'sectorsize' aligned
		 * cloning. Which is 4096 by default, therefore fall back to
		 * manual read/write on failure.
		 */
		DEBUG(5, ("BTRFS_IOC_CLONE_RANGE failed: %s, length %lu, "
			  "src fd: %ld off: %lu, dest fd: %d off: %lu\n",
			  strerror(errno), cr_args.src_length,
			  cr_args.src_fd, cr_args.src_offset,
			  dest_fsp->fh->fd, cr_args.dest_offset));
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

	DEBUG(10, ("server side copy chunk copied %lu\n", cc_state->copied));
	*copied = cc_state->copied;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

static struct vfs_fn_pointers btrfs_fns = {
	.copy_chunk_send_fn = btrfs_copy_chunk_send,
	.copy_chunk_recv_fn = btrfs_copy_chunk_recv,
};

NTSTATUS vfs_btrfs_init(void);
NTSTATUS vfs_btrfs_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"btrfs", &btrfs_fns);
}
