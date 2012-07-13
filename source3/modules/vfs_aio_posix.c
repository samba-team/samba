/*
 * Simulate pread_send/recv and pwrite_send/recv using posix aio
 *
 * Copyright (C) Volker Lendecke 2012
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"
#include "system/filesys.h"
#include "system/shmem.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "lib/util/tevent_unix.h"
#include <aio.h>

/* The signal we'll use to signify aio done. */
#ifndef RT_SIGNAL_AIO
#define RT_SIGNAL_AIO	(SIGRTMIN+3)
#endif

#ifndef HAVE_STRUCT_SIGEVENT_SIGEV_VALUE_SIVAL_PTR
#ifdef HAVE_STRUCT_SIGEVENT_SIGEV_VALUE_SIGVAL_PTR
#define sival_int	sigval_int
#define sival_ptr	sigval_ptr
#endif
#endif

static struct tevent_signal *aio_signal_event = NULL;

struct aio_posix_state {
	struct aiocb acb;
	ssize_t ret;
	int err;
};

static int aio_posix_state_destructor(struct aio_posix_state *s)
{
	int ret;

	/*
	 * We could do better here. This destructor is run when a
	 * request is prematurely cancelled. We wait for the aio to
	 * complete, so that we do not have to maintain aiocb structs
	 * beyond the life of an aio_posix_state. Possible, but not
	 * sure the effort is worth it right now.
	 */

	do {
		const struct aiocb *a = &s->acb;
		ret = aio_suspend(&a, 1, NULL);
	} while ((ret == -1) && (errno == EINTR));

	return 0;
}

static struct tevent_req *aio_posix_pread_send(
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct files_struct *fsp, void *data, size_t n, off_t offset)
{
	struct tevent_req *req;
	struct aio_posix_state *state;
	struct aiocb *a;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct aio_posix_state);
	if (req == NULL) {
		return NULL;
	}

	a = &state->acb;

	a->aio_fildes = fsp->fh->fd;
	a->aio_buf = data;
	a->aio_nbytes = n;
	a->aio_offset = offset;
	a->aio_sigevent.sigev_notify = SIGEV_SIGNAL;
	a->aio_sigevent.sigev_signo  = RT_SIGNAL_AIO;
	a->aio_sigevent.sigev_value.sival_ptr = req;

	ret = aio_read(a);
	if (ret == 0) {
		talloc_set_destructor(state, aio_posix_state_destructor);
		return req;
	}

	if (errno == EAGAIN) {
		/*
		 * aio overloaded, do the sync fallback
		 */
		state->ret = sys_pread(fsp->fh->fd, data, n, offset);
		if (state->ret == -1) {
			state->err = errno;
		}
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	tevent_req_error(req, errno);
	return tevent_req_post(req, ev);
}

static struct tevent_req *aio_posix_pwrite_send(
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct files_struct *fsp, const void *data, size_t n, off_t offset)
{
	struct tevent_req *req;
	struct aio_posix_state *state;
	struct aiocb *a;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct aio_posix_state);
	if (req == NULL) {
		return NULL;
	}

	a = &state->acb;

	a->aio_fildes = fsp->fh->fd;
	a->aio_buf = discard_const(data);
	a->aio_nbytes = n;
	a->aio_offset = offset;
	a->aio_sigevent.sigev_notify = SIGEV_SIGNAL;
	a->aio_sigevent.sigev_signo  = RT_SIGNAL_AIO;
	a->aio_sigevent.sigev_value.sival_ptr = req;

	ret = aio_write(a);
	if (ret == 0) {
		talloc_set_destructor(state, aio_posix_state_destructor);
		return req;
	}

	if (errno == EAGAIN) {
		/*
		 * aio overloaded, do the sync fallback
		 */
		state->ret = sys_pwrite(fsp->fh->fd, data, n, offset);
		if (state->ret == -1) {
			state->err = errno;
		}
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	tevent_req_error(req, errno);
	return tevent_req_post(req, ev);
}

static void aio_posix_signal_handler(struct tevent_context *ev,
				     struct tevent_signal *se,
				     int signum, int count,
				     void *_info, void *private_data)
{
	siginfo_t *info;
	struct tevent_req *req;
	struct aio_posix_state *state;
	int err;

	info = (siginfo_t *)_info;
	req = talloc_get_type_abort(info->si_value.sival_ptr,
				    struct tevent_req);
	state = tevent_req_data(req, struct aio_posix_state);

	err = aio_error(&state->acb);
	if (err == EINPROGRESS) {
		DEBUG(10, ("aio_posix_signal_handler: operation req %p "
			   "still in progress\n", req));
		return;
	}
	if (err == ECANCELED) {
		DEBUG(10, ("aio_posix_signal_handler: operation req %p "
			   "canceled\n", req));
		return;
	}

	/*
	 * No need to suspend for this in the destructor anymore
	 */
	talloc_set_destructor(state, NULL);

	state->ret = aio_return(&state->acb);
	state->err = err;
	tevent_req_done(req);
}

static ssize_t aio_posix_recv(struct tevent_req *req, int *err)
{
	struct aio_posix_state *state = tevent_req_data(
		req, struct aio_posix_state);

	if (tevent_req_is_unix_error(req, err)) {
		return -1;
	}
	*err = state->err;
	return state->ret;
}

static struct tevent_req *aio_posix_fsync_send(
	struct vfs_handle_struct *handle, TALLOC_CTX *mem_ctx,
	struct tevent_context *ev, struct files_struct *fsp)
{
	struct tevent_req *req;
	struct aio_posix_state *state;
	struct aiocb *a;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct aio_posix_state);
	if (req == NULL) {
		return NULL;
	}

	a = &state->acb;

	a->aio_fildes = fsp->fh->fd;
	a->aio_sigevent.sigev_notify = SIGEV_SIGNAL;
	a->aio_sigevent.sigev_signo  = RT_SIGNAL_AIO;
	a->aio_sigevent.sigev_value.sival_ptr = req;

	ret = aio_fsync(O_SYNC, a);
	if (ret == 0) {
		talloc_set_destructor(state, aio_posix_state_destructor);
		return req;
	}

	if (errno == EAGAIN) {
		/*
		 * aio overloaded, do the sync fallback
		 */
		state->ret = fsync(fsp->fh->fd);
		if (state->ret == -1) {
			state->err = errno;
		}
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	tevent_req_error(req, errno);
	return tevent_req_post(req, ev);
}

static int aio_posix_int_recv(struct tevent_req *req, int *err)
{
	struct aio_posix_state *state = tevent_req_data(
		req, struct aio_posix_state);

	if (tevent_req_is_unix_error(req, err)) {
		return -1;
	}
	*err = state->err;
	return state->ret;
}

static int aio_posix_connect(vfs_handle_struct *handle, const char *service,
			     const char *user)
{
	if (aio_signal_event == NULL) {
		struct tevent_context *ev = handle->conn->sconn->ev_ctx;

		aio_signal_event = tevent_add_signal(
			ev, ev, RT_SIGNAL_AIO, SA_SIGINFO,
			aio_posix_signal_handler, NULL);

		if (aio_signal_event == NULL) {
			DEBUG(1, ("tevent_add_signal failed\n"));
			return -1;
		}
	}
	return SMB_VFS_NEXT_CONNECT(handle, service, user);
}

static struct vfs_fn_pointers vfs_aio_posix_fns = {
	.connect_fn = aio_posix_connect,
	.pread_send_fn = aio_posix_pread_send,
	.pread_recv_fn = aio_posix_recv,
	.pwrite_send_fn = aio_posix_pwrite_send,
	.pwrite_recv_fn = aio_posix_recv,
	.fsync_send_fn = aio_posix_fsync_send,
	.fsync_recv_fn = aio_posix_int_recv,
};

NTSTATUS vfs_aio_posix_init(void);
NTSTATUS vfs_aio_posix_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"aio_posix", &vfs_aio_posix_fns);
}
