/*
 *  Unix SMB/CIFS implementation.
 *  Samba VFS module for delay injection in VFS calls
 *  Copyright (C) Ralph Boehme 2018
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
#include "lib/util/tevent_unix.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

static void inject_delay(const char *vfs_func, vfs_handle_struct *handle)
{
	int delay;

	delay = lp_parm_int(SNUM(handle->conn), "delay_inject", vfs_func, 0);
	if (delay == 0) {
		return;
	}

	DBG_DEBUG("Injected delay for [%s] of [%d] ms\n", vfs_func, delay);

	smb_msleep(delay);
}

static int vfs_delay_inject_ntimes(vfs_handle_struct *handle,
				   const struct smb_filename *smb_fname,
				   struct smb_file_time *ft)
{
	inject_delay("ntimes", handle);

	return SMB_VFS_NEXT_NTIMES(handle, smb_fname, ft);
}

struct vfs_delay_inject_pread_state {
	struct tevent_context *ev;
	struct vfs_handle_struct *handle;
	struct files_struct *fsp;
	void *data;
	size_t n;
	off_t offset;
	ssize_t ret;
	struct vfs_aio_state vfs_aio_state;
};

static void vfs_delay_inject_pread_wait_done(struct tevent_req *subreq);
static void vfs_delay_inject_pread_done(struct tevent_req *subreq);

static struct tevent_req *vfs_delay_inject_pread_send(
				struct vfs_handle_struct *handle,
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct files_struct *fsp,
				void *data,
				size_t n,
				off_t offset)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct vfs_delay_inject_pread_state *state = NULL;
	int delay;
	struct timeval delay_tv;

	delay = lp_parm_int(
		SNUM(handle->conn), "delay_inject", "pread_send", 0);
	delay_tv = tevent_timeval_current_ofs(delay / 1000,
					      (delay * 1000) % 1000000);

	req = tevent_req_create(mem_ctx, &state,
				struct vfs_delay_inject_pread_state);
	if (req == NULL) {
		return NULL;
	}
	*state = (struct vfs_delay_inject_pread_state) {
		.ev = ev,
		.handle = handle,
		.fsp = fsp,
		.data = data,
		.n = n,
		.offset = offset,
	};

	if (delay == 0) {
		subreq = SMB_VFS_NEXT_PREAD_SEND(state,
						 state->ev,
						 state->handle,
						 state->fsp,
						 state->data,
						 state->n,
						 state->offset);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq,
					vfs_delay_inject_pread_done,
					req);
		return req;
	}

	subreq = tevent_wakeup_send(state, ev, delay_tv);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, vfs_delay_inject_pread_wait_done, req);
	return req;
}


static void vfs_delay_inject_pread_wait_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct vfs_delay_inject_pread_state *state = tevent_req_data(
		req, struct vfs_delay_inject_pread_state);
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_error(req, EIO);
		return;
	}

	subreq = SMB_VFS_NEXT_PREAD_SEND(state,
					 state->ev,
					 state->handle,
					 state->fsp,
					 state->data,
					 state->n,
					 state->offset);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, vfs_delay_inject_pread_done, req);
}

static void vfs_delay_inject_pread_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct vfs_delay_inject_pread_state *state = tevent_req_data(
		req, struct vfs_delay_inject_pread_state);

	state->ret = SMB_VFS_PREAD_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);

	tevent_req_done(req);
}

static ssize_t vfs_delay_inject_pread_recv(struct tevent_req *req,
				struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_delay_inject_pread_state *state = tevent_req_data(
		req, struct vfs_delay_inject_pread_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

struct vfs_delay_inject_pwrite_state {
	struct tevent_context *ev;
	struct vfs_handle_struct *handle;
	struct files_struct *fsp;
	const void *data;
	size_t n;
	off_t offset;
	ssize_t ret;
	struct vfs_aio_state vfs_aio_state;
};

static void vfs_delay_inject_pwrite_wait_done(struct tevent_req *subreq);
static void vfs_delay_inject_pwrite_done(struct tevent_req *subreq);

static struct tevent_req *vfs_delay_inject_pwrite_send(
				struct vfs_handle_struct *handle,
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct files_struct *fsp,
				const void *data,
				size_t n,
				off_t offset)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct vfs_delay_inject_pwrite_state *state = NULL;
	int delay;
	struct timeval delay_tv;

	delay = lp_parm_int(
		SNUM(handle->conn), "delay_inject", "pwrite_send", 0);
	delay_tv = tevent_timeval_current_ofs(delay / 1000,
					      (delay * 1000) % 1000000);

	req = tevent_req_create(mem_ctx, &state,
				struct vfs_delay_inject_pwrite_state);
	if (req == NULL) {
		return NULL;
	}
	*state = (struct vfs_delay_inject_pwrite_state) {
		.ev = ev,
		.handle = handle,
		.fsp = fsp,
		.data = data,
		.n = n,
		.offset = offset,
	};

	if (delay == 0) {
		subreq = SMB_VFS_NEXT_PWRITE_SEND(state,
						 state->ev,
						 state->handle,
						 state->fsp,
						 state->data,
						 state->n,
						 state->offset);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq,
					vfs_delay_inject_pwrite_done,
					req);
		return req;
	}

	subreq = tevent_wakeup_send(state, ev, delay_tv);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(
		subreq, vfs_delay_inject_pwrite_wait_done, req);
	return req;
}


static void vfs_delay_inject_pwrite_wait_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct vfs_delay_inject_pwrite_state *state = tevent_req_data(
		req, struct vfs_delay_inject_pwrite_state);
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_error(req, EIO);
		return;
	}

	subreq = SMB_VFS_NEXT_PWRITE_SEND(state,
					 state->ev,
					 state->handle,
					 state->fsp,
					 state->data,
					 state->n,
					 state->offset);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, vfs_delay_inject_pwrite_done, req);
}

static void vfs_delay_inject_pwrite_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct vfs_delay_inject_pwrite_state *state = tevent_req_data(
		req, struct vfs_delay_inject_pwrite_state);

	state->ret = SMB_VFS_PWRITE_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);

	tevent_req_done(req);
}

static ssize_t vfs_delay_inject_pwrite_recv(struct tevent_req *req,
				struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_delay_inject_pwrite_state *state = tevent_req_data(
		req, struct vfs_delay_inject_pwrite_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static struct vfs_fn_pointers vfs_delay_inject_fns = {
	.ntimes_fn = vfs_delay_inject_ntimes,
	.pread_send_fn = vfs_delay_inject_pread_send,
	.pread_recv_fn = vfs_delay_inject_pread_recv,
	.pwrite_send_fn = vfs_delay_inject_pwrite_send,
	.pwrite_recv_fn = vfs_delay_inject_pwrite_recv,
};

static_decl_vfs;
NTSTATUS vfs_delay_inject_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "delay_inject",
				&vfs_delay_inject_fns);
}
