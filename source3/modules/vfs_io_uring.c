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
#include "lib/util/sys_rw.h"
#include "lib/util/iov_buf.h"
#include "smbprofile.h"
#include <liburing.h>

struct vfs_io_uring_request;

struct vfs_io_uring_config {
	struct io_uring uring;
	struct tevent_fd *fde;
	/* recursion guard. See comment above vfs_io_uring_queue_run() */
	bool busy;
	/* recursion guard. See comment above vfs_io_uring_queue_run() */
	bool need_retry;
	struct vfs_io_uring_request *queue;
	struct vfs_io_uring_request *pending;
};

struct vfs_io_uring_request {
	struct vfs_io_uring_request *prev, *next;
	struct vfs_io_uring_request **list_head;
	struct vfs_io_uring_config *config;
	struct tevent_req *req;
	struct io_uring_sqe sqe;
	struct io_uring_cqe cqe;
	void (*completion_fn)(struct vfs_io_uring_request *cur,
			      const char *location);
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
	void *state = _tevent_req_data(req);

	talloc_set_destructor(state, NULL);
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
	cur->completion_fn(cur, location);
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
				    "io_uring",
				    "num_entries",
				    128);
	num_entries = MAX(num_entries, 1);

	sqpoll = lp_parm_bool(SNUM(handle->conn),
			     "io_uring",
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

static void _vfs_io_uring_queue_run(struct vfs_io_uring_config *config)
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
		void *state = _tevent_req_data(cur->req);

		next = cur->next;

		sqe = io_uring_get_sqe(&config->uring);
		if (sqe == NULL) {
			break;
		}

		talloc_set_destructor(state,
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

/*
 * Wrapper function to prevent recursion which could happen
 * if we called _vfs_io_uring_queue_run() directly without
 * recursion checks.
 *
 * Looking at the pread call, we can have:
 *
 * vfs_io_uring_pread_send()
 *        ->vfs_io_uring_pread_submit()  <-----------------------------------
 *                ->vfs_io_uring_request_submit()                           |
 *                        ->vfs_io_uring_queue_run()                        |
 *                                ->_vfs_io_uring_queue_run()               |
 *                                                                          |
 * But inside _vfs_io_uring_queue_run() looks like:                         |
 *                                                                          |
 * _vfs_io_uring_queue_run() {                                              |
 *      if (THIS_IO_COMPLETED) {                                            |
 *              ->vfs_io_uring_finish_req()                                 |
 *                      ->cur->completion_fn()                              |
 *      }                                                                   |
 * }                                                                        |
 *                                                                          |
 * cur->completion_fn() for pread is set to vfs_io_uring_pread_completion() |
 *                                                                          |
 * vfs_io_uring_pread_completion() {                                        |
 *      if (READ_TERMINATED) {                                              |
 *              -> tevent_req_done() - We're done, go back up the stack.    |
 *              return;                                                     |
 *      }                                                                   |
 *                                                                          |
 *      We have a short read - adjust the io vectors                        |
 *                                                                          |
 *      ->vfs_io_uring_pread_submit() ---------------------------------------
 * }
 *
 * So before calling _vfs_io_uring_queue_run() we backet it with setting
 * a flag config->busy, and unset it once _vfs_io_uring_queue_run() finally
 * exits the retry loop.
 *
 * If we end up back into vfs_io_uring_queue_run() we notice we've done so
 * as config->busy is set and don't recurse into _vfs_io_uring_queue_run().
 *
 * We set the second flag config->need_retry that tells us to loop in the
 * vfs_io_uring_queue_run() call above us in the stack and return.
 *
 * When the outer call to _vfs_io_uring_queue_run() returns we are in
 * a loop checking if config->need_retry was set. That happens if
 * the short read case occurs and _vfs_io_uring_queue_run() ended up
 * recursing into vfs_io_uring_queue_run().
 *
 * Once vfs_io_uring_pread_completion() finishes without a short
 * read (the READ_TERMINATED case, tevent_req_done() is called)
 * then config->need_retry is left as false, we exit the loop,
 * set config->busy to false so the next top level call into
 * vfs_io_uring_queue_run() won't think it's a recursed call
 * and return.
 *
 */

static void vfs_io_uring_queue_run(struct vfs_io_uring_config *config)
{
	if (config->busy) {
		/*
		 * We've recursed due to short read/write.
		 * Set need_retry to ensure we retry the
		 * io_uring_submit().
		 */
		config->need_retry = true;
		return;
	}

	/*
	 * Bracket the loop calling _vfs_io_uring_queue_run()
	 * with busy = true / busy = false.
	 * so we can detect recursion above.
	 */

	config->busy = true;

	do {
		config->need_retry = false;
		_vfs_io_uring_queue_run(config);
	} while (config->need_retry);

	config->busy = false;
}

static void vfs_io_uring_request_submit(struct vfs_io_uring_request *cur)
{
	struct vfs_io_uring_config *config = cur->config;

	io_uring_sqe_set_data(&cur->sqe, cur);
	DLIST_ADD_END(config->queue, cur);
	cur->list_head = &config->queue;

	vfs_io_uring_queue_run(config);
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
	struct files_struct *fsp;
	off_t offset;
	struct iovec iov;
	size_t nread;
};

static void vfs_io_uring_pread_submit(struct vfs_io_uring_pread_state *state);
static void vfs_io_uring_pread_completion(struct vfs_io_uring_request *cur,
					  const char *location);

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
	bool ok;

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
	state->ur.completion_fn = vfs_io_uring_pread_completion;

	SMBPROFILE_BYTES_ASYNC_START(syscall_asys_pread, profile_p,
				     state->ur.profile_bytes, n);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->ur.profile_bytes);

	ok = sys_valid_io_range(offset, n);
	if (!ok) {
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}

	state->fsp = fsp;
	state->offset = offset;
	state->iov.iov_base = (void *)data;
	state->iov.iov_len = n;
	vfs_io_uring_pread_submit(state);

	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_defer_callback(req, ev);
	return req;
}

static void vfs_io_uring_pread_submit(struct vfs_io_uring_pread_state *state)
{
	io_uring_prep_readv(&state->ur.sqe,
			    state->fsp->fh->fd,
			    &state->iov, 1,
			    state->offset);
	vfs_io_uring_request_submit(&state->ur);
}

static void vfs_io_uring_pread_completion(struct vfs_io_uring_request *cur,
					  const char *location)
{
	struct vfs_io_uring_pread_state *state = tevent_req_data(
		cur->req, struct vfs_io_uring_pread_state);
	struct iovec *iov = &state->iov;
	int num_iov = 1;
	bool ok;

	/*
	 * We rely on being inside the _send() function
	 * or tevent_req_defer_callback() being called
	 * already.
	 */

	if (cur->cqe.res < 0) {
		int err = -cur->cqe.res;
		_tevent_req_error(cur->req, err, location);
		return;
	}

	if (cur->cqe.res == 0) {
		/*
		 * We reached EOF, we're done
		 */
		tevent_req_done(cur->req);
		return;
	}

	ok = iov_advance(&iov, &num_iov, cur->cqe.res);
	if (!ok) {
		/* This is not expected! */
		DBG_ERR("iov_advance() failed cur->cqe.res=%d > iov_len=%d\n",
			(int)cur->cqe.res,
			(int)state->iov.iov_len);
		tevent_req_error(cur->req, EIO);
		return;
	}

	/* sys_valid_io_range() already checked the boundaries */
	state->nread += state->ur.cqe.res;
	if (num_iov == 0) {
		/* We're done */
		tevent_req_done(cur->req);
		return;
	}

	/*
	 * sys_valid_io_range() already checked the boundaries
	 * now try to get the rest.
	 */
	state->offset += state->ur.cqe.res;
	vfs_io_uring_pread_submit(state);
}

static ssize_t vfs_io_uring_pread_recv(struct tevent_req *req,
				  struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_io_uring_pread_state *state = tevent_req_data(
		req, struct vfs_io_uring_pread_state);
	ssize_t ret;

	SMBPROFILE_BYTES_ASYNC_END(state->ur.profile_bytes);
	vfs_aio_state->duration = nsec_time_diff(&state->ur.end_time,
						 &state->ur.start_time);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		tevent_req_received(req);
		return -1;
	}

	vfs_aio_state->error = 0;
	ret = state->nread;

	tevent_req_received(req);
	return ret;
}

struct vfs_io_uring_pwrite_state {
	struct vfs_io_uring_request ur;
	struct files_struct *fsp;
	off_t offset;
	struct iovec iov;
	size_t nwritten;
};

static void vfs_io_uring_pwrite_submit(struct vfs_io_uring_pwrite_state *state);
static void vfs_io_uring_pwrite_completion(struct vfs_io_uring_request *cur,
					   const char *location);

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
	bool ok;

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
	state->ur.completion_fn = vfs_io_uring_pwrite_completion;

	SMBPROFILE_BYTES_ASYNC_START(syscall_asys_pwrite, profile_p,
				     state->ur.profile_bytes, n);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->ur.profile_bytes);

	ok = sys_valid_io_range(offset, n);
	if (!ok) {
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}

	state->fsp = fsp;
	state->offset = offset;
	state->iov.iov_base = discard_const(data);
	state->iov.iov_len = n;
	vfs_io_uring_pwrite_submit(state);

	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_defer_callback(req, ev);
	return req;
}

static void vfs_io_uring_pwrite_submit(struct vfs_io_uring_pwrite_state *state)
{
	io_uring_prep_writev(&state->ur.sqe,
			     state->fsp->fh->fd,
			     &state->iov, 1,
			     state->offset);
	vfs_io_uring_request_submit(&state->ur);
}

static void vfs_io_uring_pwrite_completion(struct vfs_io_uring_request *cur,
					   const char *location)
{
	struct vfs_io_uring_pwrite_state *state = tevent_req_data(
		cur->req, struct vfs_io_uring_pwrite_state);
	struct iovec *iov = &state->iov;
	int num_iov = 1;
	bool ok;

	/*
	 * We rely on being inside the _send() function
	 * or tevent_req_defer_callback() being called
	 * already.
	 */

	if (cur->cqe.res < 0) {
		int err = -cur->cqe.res;
		_tevent_req_error(cur->req, err, location);
		return;
	}

	if (cur->cqe.res == 0) {
		/*
		 * Ensure we can never spin.
		 */
		tevent_req_error(cur->req, ENOSPC);
		return;
	}

	ok = iov_advance(&iov, &num_iov, cur->cqe.res);
	if (!ok) {
		/* This is not expected! */
		DBG_ERR("iov_advance() failed cur->cqe.res=%d > iov_len=%d\n",
			(int)cur->cqe.res,
			(int)state->iov.iov_len);
		tevent_req_error(cur->req, EIO);
		return;
	}

	/* sys_valid_io_range() already checked the boundaries */
	state->nwritten += state->ur.cqe.res;
	if (num_iov == 0) {
		/* We're done */
		tevent_req_done(cur->req);
		return;
	}

	/*
	 * sys_valid_io_range() already checked the boundaries
	 * now try to write the rest.
	 */
	state->offset += state->ur.cqe.res;
	vfs_io_uring_pwrite_submit(state);
}

static ssize_t vfs_io_uring_pwrite_recv(struct tevent_req *req,
				   struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_io_uring_pwrite_state *state = tevent_req_data(
		req, struct vfs_io_uring_pwrite_state);
	ssize_t ret;

	SMBPROFILE_BYTES_ASYNC_END(state->ur.profile_bytes);
	vfs_aio_state->duration = nsec_time_diff(&state->ur.end_time,
						 &state->ur.start_time);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		tevent_req_received(req);
		return -1;
	}

	vfs_aio_state->error = 0;
	ret = state->nwritten;

	tevent_req_received(req);
	return ret;
}

struct vfs_io_uring_fsync_state {
	struct vfs_io_uring_request ur;
};

static void vfs_io_uring_fsync_completion(struct vfs_io_uring_request *cur,
					  const char *location);

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
	state->ur.completion_fn = vfs_io_uring_fsync_completion;

	SMBPROFILE_BYTES_ASYNC_START(syscall_asys_fsync, profile_p,
				     state->ur.profile_bytes, 0);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->ur.profile_bytes);

	io_uring_prep_fsync(&state->ur.sqe,
			    fsp->fh->fd,
			    0); /* fsync_flags */
	vfs_io_uring_request_submit(&state->ur);

	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_defer_callback(req, ev);
	return req;
}

static void vfs_io_uring_fsync_completion(struct vfs_io_uring_request *cur,
					  const char *location)
{
	/*
	 * We rely on being inside the _send() function
	 * or tevent_req_defer_callback() being called
	 * already.
	 */

	if (cur->cqe.res < 0) {
		int err = -cur->cqe.res;
		_tevent_req_error(cur->req, err, location);
		return;
	}

	if (cur->cqe.res > 0) {
		/* This is not expected! */
		DBG_ERR("got cur->cqe.res=%d\n", (int)cur->cqe.res);
		tevent_req_error(cur->req, EIO);
		return;
	}

	tevent_req_done(cur->req);
}

static int vfs_io_uring_fsync_recv(struct tevent_req *req,
			      struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_io_uring_fsync_state *state = tevent_req_data(
		req, struct vfs_io_uring_fsync_state);

	SMBPROFILE_BYTES_ASYNC_END(state->ur.profile_bytes);
	vfs_aio_state->duration = nsec_time_diff(&state->ur.end_time,
						 &state->ur.start_time);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		tevent_req_received(req);
		return -1;
	}

	vfs_aio_state->error = 0;

	tevent_req_received(req);
	return 0;
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
