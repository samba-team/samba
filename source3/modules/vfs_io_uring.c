/*
 * Use the io_uring of Linux (>= 5.1)
 *
 * Copyright (C) Volker Lendecke 2008
 * Copyright (C) Jeremy Allison 2010
 * Copyright (C) Stefan Metzmacher 2019
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "lib/util/tevent_unix.h"
#include "smbprofile.h"
#include <liburing.h>

struct vfs_io_uring_request;

struct vfs_io_uring_config {
	struct io_uring uring;
	struct tevent_fd *fde;
	struct vfs_io_uring_request *queue;
	struct vfs_io_uring_request *pending;
};

struct vfs_io_uring_request {
	struct vfs_io_uring_request *prev, *next;
	struct vfs_io_uring_request **list_head;
	struct vfs_io_uring_config *config;
	struct tevent_req *req;
	void *state;
	struct io_uring_sqe sqe;
	struct io_uring_cqe cqe;
	struct timespec start_time;
	struct timespec end_time;
	SMBPROFILE_BYTES_ASYNC_STATE(profile_bytes);
};

static void vfs_io_uring_finish_req(struct vfs_io_uring_request *cur,
				    const struct io_uring_cqe *cqe,
				    struct timespec end_time,
				    const char *location)
{
	struct tevent_req *req =
		talloc_get_type_abort(cur->req,
		struct tevent_req);

	talloc_set_destructor(cur->state, NULL);
	if (cur->list_head != NULL) {
		DLIST_REMOVE((*cur->list_head), cur);
		cur->list_head = NULL;
	}
	cur->cqe = *cqe;

	SMBPROFILE_BYTES_ASYNC_SET_IDLE(cur->profile_bytes);
	cur->end_time = end_time;

	/*
	 * We rely on being inside the _send() function
	 * or tevent_req_defer_callback() being called
	 * already.
	 */
	_tevent_req_done(req, location);
}

static void vfs_io_uring_config_destroy(struct vfs_io_uring_config *config,
				        int ret,
				        const char *location)
{
	struct vfs_io_uring_request *cur = NULL, *next = NULL;
	struct timespec start_time;
	struct timespec end_time;
	struct io_uring_cqe err_cqe = {
		.res = ret,
	};

	PROFILE_TIMESTAMP(&start_time);

	if (config->uring.ring_fd != -1) {
		/* TODO: cancel queued and pending requests */
		TALLOC_FREE(config->fde);
		io_uring_queue_exit(&config->uring);
		config->uring.ring_fd = -1;
	}

	PROFILE_TIMESTAMP(&end_time);

	for (cur = config->pending; cur != NULL; cur = next) {
		next = cur->next;
		err_cqe.user_data = (uintptr_t)(void *)cur;
		vfs_io_uring_finish_req(cur, &err_cqe, end_time, location);
	}

	for (cur = config->queue; cur != NULL; cur = next) {
		next = cur->next;
		err_cqe.user_data = (uintptr_t)(void *)cur;
		cur->start_time = start_time;
		vfs_io_uring_finish_req(cur, &err_cqe, end_time, location);
	}
}

static int vfs_io_uring_config_destructor(struct vfs_io_uring_config *config)
{
	vfs_io_uring_config_destroy(config, -EUCLEAN, __location__);
	return 0;
}

static int vfs_io_uring_request_state_deny_destructor(void *_state)
{
	struct __vfs_io_uring_generic_state {
		struct vfs_io_uring_request ur;
	} *state = (struct __vfs_io_uring_generic_state *)_state;
	struct vfs_io_uring_request *cur = &state->ur;

	/* our parent is gone */
	cur->req = NULL;

	/* remove ourself from any list */
	DLIST_REMOVE((*cur->list_head), cur);
	cur->list_head = NULL;

	/*
	 * Our state is about to go away,
	 * all we can do is shutting down the whole uring.
	 * But that's ok as we're most likely called from exit_server()
	 */
	vfs_io_uring_config_destroy(cur->config, -ESHUTDOWN, __location__);
	return 0;
}

static void vfs_io_uring_fd_handler(struct tevent_context *ev,
				    struct tevent_fd *fde,
				    uint16_t flags,
				    void *private_data);

static int vfs_io_uring_connect(vfs_handle_struct *handle, const char *service,
			    const char *user)
{
	int ret;
	struct vfs_io_uring_config *config;
	unsigned num_entries;
	bool sqpoll;
	unsigned flags = 0;

	config = talloc_zero(handle->conn, struct vfs_io_uring_config);
	if (config == NULL) {
		DEBUG(0, ("talloc_zero() failed\n"));
		return -1;
	}

	SMB_VFS_HANDLE_SET_DATA(handle, config,
				NULL, struct vfs_io_uring_config,
				return -1);

	ret = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (ret < 0) {
		return ret;
	}

	num_entries = lp_parm_ulong(SNUM(handle->conn),
				    "vfs_io_uring",
				    "num_entries",
				    128);
	num_entries = MAX(num_entries, 1);

	sqpoll = lp_parm_bool(SNUM(handle->conn),
			     "vfs_io_uring",
			     "sqpoll",
			     false);
	if (sqpoll) {
		flags |= IORING_SETUP_SQPOLL;
	}

	ret = io_uring_queue_init(num_entries, &config->uring, flags);
	if (ret < 0) {
		SMB_VFS_NEXT_DISCONNECT(handle);
		errno = -ret;
		return -1;
	}

	talloc_set_destructor(config, vfs_io_uring_config_destructor);

#ifdef HAVE_IO_URING_RING_DONTFORK
	ret = io_uring_ring_dontfork(&config->uring);
	if (ret < 0) {
		SMB_VFS_NEXT_DISCONNECT(handle);
		errno = -ret;
		return -1;
	}
#endif /* HAVE_IO_URING_RING_DONTFORK */

	config->fde = tevent_add_fd(handle->conn->sconn->ev_ctx,
				    config,
				    config->uring.ring_fd,
				    TEVENT_FD_READ,
				    vfs_io_uring_fd_handler,
				    handle);
	if (config->fde == NULL) {
		ret = errno;
		SMB_VFS_NEXT_DISCONNECT(handle);
		errno = ret;
		return -1;
	}

	return 0;
}

static void vfs_io_uring_queue_run(struct vfs_io_uring_config *config)
{
	struct vfs_io_uring_request *cur = NULL, *next = NULL;
	struct io_uring_cqe *cqe = NULL;
	unsigned cqhead;
	unsigned nr = 0;
	struct timespec start_time;
	struct timespec end_time;
	int ret;

	PROFILE_TIMESTAMP(&start_time);

	if (config->uring.ring_fd == -1) {
		vfs_io_uring_config_destroy(config, -ESTALE, __location__);
		return;
	}

	for (cur = config->queue; cur != NULL; cur = next) {
		struct io_uring_sqe *sqe = NULL;

		next = cur->next;

		sqe = io_uring_get_sqe(&config->uring);
		if (sqe == NULL) {
			break;
		}

		talloc_set_destructor(cur->state,
			vfs_io_uring_request_state_deny_destructor);
		DLIST_REMOVE(config->queue, cur);
		*sqe = cur->sqe;
		DLIST_ADD_END(config->pending, cur);
		cur->list_head = &config->pending;
		SMBPROFILE_BYTES_ASYNC_SET_BUSY(cur->profile_bytes);

		cur->start_time = start_time;
	}

	ret = io_uring_submit(&config->uring);
	if (ret == -EAGAIN || ret == -EBUSY) {
		/* We just retry later */
	} else if (ret < 0) {
		vfs_io_uring_config_destroy(config, ret, __location__);
		return;
	}

	PROFILE_TIMESTAMP(&end_time);

	io_uring_for_each_cqe(&config->uring, cqhead, cqe) {
		cur = (struct vfs_io_uring_request *)io_uring_cqe_get_data(cqe);
		vfs_io_uring_finish_req(cur, cqe, end_time, __location__);
		nr++;
	}

	io_uring_cq_advance(&config->uring, nr);
}

static void vfs_io_uring_fd_handler(struct tevent_context *ev,
				    struct tevent_fd *fde,
				    uint16_t flags,
				    void *private_data)
{
	vfs_handle_struct *handle = (vfs_handle_struct *)private_data;
	struct vfs_io_uring_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct vfs_io_uring_config,
				smb_panic(__location__));

	vfs_io_uring_queue_run(config);
}

struct vfs_io_uring_pread_state {
	struct vfs_io_uring_request ur;
	struct iovec iov;
};

static struct tevent_req *vfs_io_uring_pread_send(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct files_struct *fsp,
					     void *data,
					     size_t n, off_t offset)
{
	struct tevent_req *req = NULL;
	struct vfs_io_uring_pread_state *state = NULL;
	struct vfs_io_uring_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct vfs_io_uring_config,
				smb_panic(__location__));

	req = tevent_req_create(mem_ctx, &state,
				struct vfs_io_uring_pread_state);
	if (req == NULL) {
		return NULL;
	}
	state->ur.config = config;
	state->ur.req = req;
	state->ur.state = state;

	SMBPROFILE_BYTES_ASYNC_START(syscall_asys_pread, profile_p,
				     state->ur.profile_bytes, n);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->ur.profile_bytes);

	state->iov.iov_base = (void *)data;
	state->iov.iov_len = n;
	io_uring_prep_readv(&state->ur.sqe,
			    fsp->fh->fd,
			    &state->iov, 1,
			    offset);
	io_uring_sqe_set_data(&state->ur.sqe, &state->ur);
	DLIST_ADD_END(config->queue, &state->ur);
	state->ur.list_head = &config->queue;

	vfs_io_uring_queue_run(config);

	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_defer_callback(req, ev);
	return req;
}

static ssize_t vfs_io_uring_pread_recv(struct tevent_req *req,
				  struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_io_uring_pread_state *state = tevent_req_data(
		req, struct vfs_io_uring_pread_state);
	int ret;

	SMBPROFILE_BYTES_ASYNC_END(state->ur.profile_bytes);
	vfs_aio_state->duration = nsec_time_diff(&state->ur.end_time,
						 &state->ur.start_time);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	if (state->ur.cqe.res < 0) {
		vfs_aio_state->error = -state->ur.cqe.res;
		ret = -1;
	} else {
		vfs_aio_state->error = 0;
		ret = state->ur.cqe.res;
	}

	tevent_req_received(req);
	return ret;
}

struct vfs_io_uring_pwrite_state {
	struct vfs_io_uring_request ur;
	struct iovec iov;
};

static struct tevent_req *vfs_io_uring_pwrite_send(struct vfs_handle_struct *handle,
					      TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct files_struct *fsp,
					      const void *data,
					      size_t n, off_t offset)
{
	struct tevent_req *req = NULL;
	struct vfs_io_uring_pwrite_state *state = NULL;
	struct vfs_io_uring_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct vfs_io_uring_config,
				smb_panic(__location__));

	req = tevent_req_create(mem_ctx, &state,
				struct vfs_io_uring_pwrite_state);
	if (req == NULL) {
		return NULL;
	}
	state->ur.config = config;
	state->ur.req = req;
	state->ur.state = state;

	SMBPROFILE_BYTES_ASYNC_START(syscall_asys_pwrite, profile_p,
				     state->ur.profile_bytes, n);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->ur.profile_bytes);

	state->iov.iov_base = discard_const(data);
	state->iov.iov_len = n;
	io_uring_prep_writev(&state->ur.sqe,
			     fsp->fh->fd,
			     &state->iov, 1,
			     offset);
	io_uring_sqe_set_data(&state->ur.sqe, &state->ur);
	DLIST_ADD_END(config->queue, &state->ur);
	state->ur.list_head = &config->queue;

	vfs_io_uring_queue_run(config);

	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_defer_callback(req, ev);
	return req;
}

static ssize_t vfs_io_uring_pwrite_recv(struct tevent_req *req,
				   struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_io_uring_pwrite_state *state = tevent_req_data(
		req, struct vfs_io_uring_pwrite_state);
	int ret;

	SMBPROFILE_BYTES_ASYNC_END(state->ur.profile_bytes);
	vfs_aio_state->duration = nsec_time_diff(&state->ur.end_time,
						 &state->ur.start_time);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	if (state->ur.cqe.res < 0) {
		vfs_aio_state->error = -state->ur.cqe.res;
		ret = -1;
	} else {
		vfs_aio_state->error = 0;
		ret = state->ur.cqe.res;
	}

	tevent_req_received(req);
	return ret;
}

struct vfs_io_uring_fsync_state {
	struct vfs_io_uring_request ur;
};

static struct tevent_req *vfs_io_uring_fsync_send(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct files_struct *fsp)
{
	struct tevent_req *req = NULL;
	struct vfs_io_uring_fsync_state *state = NULL;
	struct vfs_io_uring_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct vfs_io_uring_config,
				smb_panic(__location__));

	req = tevent_req_create(mem_ctx, &state,
				struct vfs_io_uring_fsync_state);
	if (req == NULL) {
		return NULL;
	}
	state->ur.config = config;
	state->ur.req = req;
	state->ur.state = state;

	SMBPROFILE_BYTES_ASYNC_START(syscall_asys_fsync, profile_p,
				     state->ur.profile_bytes, 0);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->ur.profile_bytes);

	io_uring_prep_fsync(&state->ur.sqe,
			    fsp->fh->fd,
			    0); /* fsync_flags */
	io_uring_sqe_set_data(&state->ur.sqe, &state->ur);
	DLIST_ADD_END(config->queue, &state->ur);
	state->ur.list_head = &config->queue;

	vfs_io_uring_queue_run(config);

	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_defer_callback(req, ev);
	return req;
}

static int vfs_io_uring_fsync_recv(struct tevent_req *req,
			      struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_io_uring_fsync_state *state = tevent_req_data(
		req, struct vfs_io_uring_fsync_state);
	int ret;

	SMBPROFILE_BYTES_ASYNC_END(state->ur.profile_bytes);
	vfs_aio_state->duration = nsec_time_diff(&state->ur.end_time,
						 &state->ur.start_time);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	if (state->ur.cqe.res < 0) {
		vfs_aio_state->error = -state->ur.cqe.res;
		ret = -1;
	} else {
		vfs_aio_state->error = 0;
		ret = state->ur.cqe.res;
	}

	tevent_req_received(req);
	return ret;
}

static struct vfs_fn_pointers vfs_io_uring_fns = {
	.connect_fn = vfs_io_uring_connect,
	.pread_send_fn = vfs_io_uring_pread_send,
	.pread_recv_fn = vfs_io_uring_pread_recv,
	.pwrite_send_fn = vfs_io_uring_pwrite_send,
	.pwrite_recv_fn = vfs_io_uring_pwrite_recv,
	.fsync_send_fn = vfs_io_uring_fsync_send,
	.fsync_recv_fn = vfs_io_uring_fsync_recv,
};

static_decl_vfs;
NTSTATUS vfs_io_uring_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"io_uring", &vfs_io_uring_fns);
}
