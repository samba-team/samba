/*
 * Simulate Posix AIO using Linux kernel AIO.
 *
 * Copyright (C) Jeremy Allison 2012
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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include <sys/eventfd.h>
#include <libaio.h>

struct aio_extra;
static int event_fd = -1;
static io_context_t io_ctx;
static int aio_linux_requestid;
static struct io_event *io_recv_events;
static struct fd_event *aio_read_event;

struct aio_private_data {
	struct aio_private_data *prev, *next;
	int requestid;
	SMB_STRUCT_AIOCB *aiocb;
	struct iocb *event_iocb;
	ssize_t ret_size;
	int ret_errno;
	bool cancelled;
};

/* List of outstanding requests we have. */
static struct aio_private_data *pd_list;

static void aio_linux_handle_completion(struct event_context *event_ctx,
			struct fd_event *event,
			uint16 flags,
			void *p);

/************************************************************************
 Housekeeping. Cleanup if no activity for 30 seconds.
***********************************************************************/

static void aio_linux_housekeeping(struct tevent_context *event_ctx,
                                        struct tevent_timer *te,
                                        struct timeval now,
                                        void *private_data)
{
	/* Remove this timed event handler. */
	TALLOC_FREE(te);

	if (pd_list != NULL) {
		/* Still busy. Look again in 30 seconds. */
		(void)tevent_add_timer(event_ctx,
					NULL,
					timeval_current_ofs(30, 0),
					aio_linux_housekeeping,
					NULL);
		return;
	}

	/* No activity for 30 seconds. Close out kernel resources. */
	io_queue_release(io_ctx);
	memset(&io_ctx, '\0', sizeof(io_ctx));

	if (event_fd != -1) {
		close(event_fd);
		event_fd = -1;
	}

	TALLOC_FREE(aio_read_event);
	TALLOC_FREE(io_recv_events);
}

/************************************************************************
 Ensure event fd and aio context are initialized.
***********************************************************************/

static bool init_aio_linux(struct vfs_handle_struct *handle)
{
	struct tevent_timer *te = NULL;

	if (event_fd != -1) {
		/* Already initialized. */
		return true;
	}

	/* Schedule a shutdown event for 30 seconds from now. */
	te = tevent_add_timer(server_event_context(),
				NULL,
				timeval_current_ofs(30, 0),
				aio_linux_housekeeping,
				NULL);

	if (te == NULL) {
		goto fail;
	}

	/* Ensure we have enough space for aio_pending_size events. */
	io_recv_events = talloc_zero_array(NULL,
				struct io_event,
				aio_pending_size);
	if (io_recv_events == NULL) {
		goto fail;
	}

	event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (event_fd == -1) {
		goto fail;
	}

	aio_read_event = tevent_add_fd(server_event_context(),
				NULL,
				event_fd,
				TEVENT_FD_READ,
				aio_linux_handle_completion,
				NULL);
	if (aio_read_event == NULL) {
		goto fail;
	}

	if (io_queue_init(aio_pending_size, &io_ctx)) {
		goto fail;
	}

	DEBUG(10,("init_aio_linux: initialized with up to %d events\n",
		  aio_pending_size));

	return true;

  fail:

	DEBUG(10,("init_aio_linux: initialization failed\n"));

	TALLOC_FREE(te);
	TALLOC_FREE(io_recv_events);
	TALLOC_FREE(aio_read_event);
	if (event_fd != -1) {
		close(event_fd);
		event_fd = -1;
	}
	memset(&io_ctx, '\0', sizeof(io_ctx));
	return false;
}

/************************************************************************
 Private data destructor.
***********************************************************************/

static int pd_destructor(struct aio_private_data *pd)
{
	DLIST_REMOVE(pd_list, pd);
	return 0;
}

/************************************************************************
 Create and initialize a private data struct.
***********************************************************************/

static struct aio_private_data *create_private_data(TALLOC_CTX *ctx,
					SMB_STRUCT_AIOCB *aiocb)
{
	struct aio_private_data *pd = talloc_zero(ctx, struct aio_private_data);
	if (!pd) {
		return NULL;
	}
	pd->event_iocb = talloc_zero(pd, struct iocb);
	pd->requestid = aio_linux_requestid++;
	pd->aiocb = aiocb;
	pd->ret_size = -1;
	pd->ret_errno = EINPROGRESS;
	talloc_set_destructor(pd, pd_destructor);
	DLIST_ADD_END(pd_list, pd, struct aio_private_data *);
	return pd;
}

/************************************************************************
 Initiate an asynchronous pread call.
***********************************************************************/

static int aio_linux_read(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				SMB_STRUCT_AIOCB *aiocb)
{
	struct aio_extra *aio_ex = (struct aio_extra *)aiocb->aio_sigevent.sigev_value.sival_ptr;
	struct aio_private_data *pd = NULL;
	int ret;

	if (!init_aio_linux(handle)) {
		return -1;
	}

	pd = create_private_data(aio_ex, aiocb);
	if (pd == NULL) {
		DEBUG(10, ("aio_linux_read: Could not create private data.\n"));
		return -1;
	}

	io_prep_pread(pd->event_iocb,
			pd->aiocb->aio_fildes,
			discard_const(pd->aiocb->aio_buf),
			pd->aiocb->aio_nbytes,
			pd->aiocb->aio_offset);
	io_set_eventfd(pd->event_iocb, event_fd);
	/* Use the callback pointer as a private data ptr. */
	io_set_callback(pd->event_iocb, (io_callback_t)pd);

	ret = io_submit(io_ctx, 1, &pd->event_iocb);
	if (ret < 0) {
		errno = ret;
		return -1;
	}

	DEBUG(10, ("aio_linux_read: requestid=%d read requested "
		"of %llu bytes at offset %llu\n",
		pd->requestid,
		(unsigned long long)pd->aiocb->aio_nbytes,
		(unsigned long long)pd->aiocb->aio_offset));

	return 0;
}

/************************************************************************
 Initiate an asynchronous pwrite call.
***********************************************************************/

static int aio_linux_write(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				SMB_STRUCT_AIOCB *aiocb)
{
	struct aio_extra *aio_ex = (struct aio_extra *)aiocb->aio_sigevent.sigev_value.sival_ptr;
	struct aio_private_data *pd = NULL;
	int ret;

	if (!init_aio_linux(handle)) {
		return -1;
	}

	pd = create_private_data(aio_ex, aiocb);
	if (pd == NULL) {
		DEBUG(10, ("aio_linux_write: Could not create private data.\n"));
		return -1;
	}

	io_prep_pwrite(pd->event_iocb,
			pd->aiocb->aio_fildes,
			discard_const(pd->aiocb->aio_buf),
			pd->aiocb->aio_nbytes,
			pd->aiocb->aio_offset);
	io_set_eventfd(pd->event_iocb, event_fd);
	/* Use the callback pointer as a private data ptr. */
	io_set_callback(pd->event_iocb, (io_callback_t)pd);

	ret = io_submit(io_ctx, 1, &pd->event_iocb);
	if (ret < 0) {
		errno = ret;
		return -1;
	}

	DEBUG(10, ("aio_linux_write: requestid=%d pwrite requested "
		"of %llu bytes at offset %llu\n",
		pd->requestid,
		(unsigned long long)pd->aiocb->aio_nbytes,
		(unsigned long long)pd->aiocb->aio_offset));

	return 0;
}

/************************************************************************
 Save off the error / success conditions from the io_event.
 Is idempotent (can be called multiple times given the same ioev).
***********************************************************************/

static void aio_linux_setup_returns(struct io_event *ioev)
{
	struct aio_private_data *pd = (struct aio_private_data *)ioev->data;

	/* ioev->res2 contains the -errno if error. */
	/* ioev->res contains the number of bytes sent/received. */
	if (ioev->res2) {
		pd->ret_size = -1;
		pd->ret_errno = -ioev->res2;
	} else {
		pd->ret_size = ioev->res;
		pd->ret_errno = 0;
	}
}

/************************************************************************
 Handle a single finished io.
***********************************************************************/

static void aio_linux_handle_io_finished(struct io_event *ioev)
{
	struct aio_extra *aio_ex = NULL;
	struct aio_private_data *pd = (struct aio_private_data *)ioev->data;

	aio_linux_setup_returns(ioev);

	aio_ex = (struct aio_extra *)pd->aiocb->aio_sigevent.sigev_value.sival_ptr;
	smbd_aio_complete_aio_ex(aio_ex);

	DEBUG(10,("aio_linux_handle_io_finished: requestid %d completed\n",
		pd->requestid ));
	TALLOC_FREE(aio_ex);
}

/************************************************************************
 Callback when multiple IOs complete.
***********************************************************************/

static void aio_linux_handle_completion(struct event_context *event_ctx,
				struct fd_event *event,
				uint16 flags,
				void *p)
{
	uint64_t num_events = 0;

	DEBUG(10, ("aio_linux_handle_completion called with flags=%d\n",
			(int)flags));

	if ((flags & EVENT_FD_READ) == 0) {
		return;
	}

	/* Read the number of events available. */
	if (sys_read(event_fd, &num_events, sizeof(num_events)) !=
			sizeof(num_events)) {
		smb_panic("aio_linux_handle_completion: invalid read");
	}

	while (num_events > 0) {
		uint64_t events_to_read = MIN(num_events, aio_pending_size);
		struct timespec ts;
		int i;
		int ret;

		ts.tv_sec = 0;
		ts.tv_nsec = 0;

		ret = io_getevents(io_ctx,
			1,
			(long)events_to_read,
			io_recv_events,
			&ts);

		if (ret < 0) {
			errno = -ret;
			DEBUG(1, ("aio_linux_handle_completion: "
				"io_getevents error %s\n",
				strerror(errno) ));
			return;
		}

		if (ret == 0) {
			DEBUG(10, ("aio_linux_handle_completion: "
				"io_getevents returned 0\n"));
			continue;
		}

		/* ret is positive. */
		for (i = 0; i < ret; i++) {
			aio_linux_handle_io_finished(&io_recv_events[i]);
		}

		num_events -= ret;
	}
}

/************************************************************************
 Find the private data by aiocb.
***********************************************************************/

static struct aio_private_data *find_private_data_by_aiocb(SMB_STRUCT_AIOCB *aiocb)
{
	struct aio_private_data *pd;

	for (pd = pd_list; pd != NULL; pd = pd->next) {
		if (pd->aiocb == aiocb) {
			return pd;
		}
	}

	return NULL;
}

/************************************************************************
 Called to return the result of a completed AIO.
 Should only be called if aio_error returns something other than EINPROGRESS.
 Returns:
	Any other value - return from IO operation.
***********************************************************************/

static ssize_t aio_linux_return_fn(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				SMB_STRUCT_AIOCB *aiocb)
{
	struct aio_private_data *pd = find_private_data_by_aiocb(aiocb);

	if (pd == NULL) {
		errno = EINVAL;
		DEBUG(0, ("aio_linux_return_fn: returning EINVAL\n"));
		return -1;
	}

	pd->aiocb = NULL;

	if (pd->ret_size == -1) {
		errno = pd->ret_errno;
	}

	return pd->ret_size;
}

/************************************************************************
 Called to check the result of an AIO.
 Returns:
	EINPROGRESS - still in progress.
	EINVAL - invalid aiocb.
	ECANCELED - request was cancelled.
	0 - request completed successfully.
	Any other value - errno from IO operation.
***********************************************************************/

static int aio_linux_error_fn(struct vfs_handle_struct *handle,
			     struct files_struct *fsp,
			     SMB_STRUCT_AIOCB *aiocb)
{
	struct aio_private_data *pd = find_private_data_by_aiocb(aiocb);

	if (pd == NULL) {
		return EINVAL;
	}
	if (pd->cancelled) {
		return ECANCELED;
	}
	return pd->ret_errno;
}

/************************************************************************
 Called to request the cancel of an AIO, or all of them on a specific
 fsp if aiocb == NULL.
***********************************************************************/

static int aio_linux_cancel(struct vfs_handle_struct *handle,
			struct files_struct *fsp,
			SMB_STRUCT_AIOCB *aiocb)
{
	struct aio_private_data *pd = NULL;

	for (pd = pd_list; pd != NULL; pd = pd->next) {
		if (pd->aiocb == NULL) {
			continue;
		}
		if (pd->aiocb->aio_fildes != fsp->fh->fd) {
			continue;
		}
		if ((aiocb != NULL) && (pd->aiocb != aiocb)) {
			continue;
		}

		/*
		 * We let the kernel do its job, but we discard the result when
		 * it's finished. NB. Should I call io_cancel here ?
		 */

		pd->cancelled = true;
	}

	return AIO_CANCELED;
}

/************************************************************************
 Callback for a previously detected job completion deferred to the main
 loop.
***********************************************************************/

static void aio_linux_handle_immediate(struct tevent_context *ctx,
				struct tevent_immediate *im,
				void *private_data)
{
	struct io_event *ioev = (struct io_event *)private_data;

	aio_linux_handle_io_finished(ioev);
	TALLOC_FREE(ioev);
}

/************************************************************************
 Private data struct used in suspend completion code.
***********************************************************************/

struct suspend_private {
	int num_entries;
	int num_finished;
	const SMB_STRUCT_AIOCB * const *aiocb_array;
};

/************************************************************************
 Handle a single finished io from suspend.
***********************************************************************/

static void aio_linux_handle_suspend_io_finished(struct suspend_private *sp,
						struct io_event *ioev)
{
	struct aio_private_data *pd = (struct aio_private_data *)ioev->data;
	struct io_event *new_ioev = NULL;
	struct tevent_immediate *im = NULL;
	int i;

	/* Is this a requestid with an aiocb we're interested in ? */
	for (i = 0; i < sp->num_entries; i++) {
		if (sp->aiocb_array[i] == pd->aiocb) {
			sp->num_finished++;
			/*
			 * We don't call aio_linux_handle_io_finished()
			 * here, but only the function that sets up the
			 * return values. This allows
			 * aio_linux_handle_io_finished() to be successfully
			 * called from smbd/aio.c:wait_for_aio_completion()
			 * once we return from here with all io's done.
			 */
			aio_linux_setup_returns(ioev);
			return;
		}
	}

	/* Jobid completed we weren't waiting for.
	   We must reshedule this as an immediate event
	   on the main event context. */
	im = tevent_create_immediate(NULL);
	if (!im) {
		exit_server_cleanly("aio_linux_handle_suspend_completion: no memory");
	}

	new_ioev = (struct io_event *)talloc_memdup(NULL,
						ioev,
						sizeof(struct io_event));
	if (!new_ioev) {
		exit_server_cleanly("aio_linux_handle_suspend_completion: no memory");
	}

	DEBUG(10,("aio_linux_handle_suspend_completion: "
			"re-scheduling requestid %d\n",
			pd->requestid));

	tevent_schedule_immediate(im,
			server_event_context(),
			aio_linux_handle_immediate,
			(void *)new_ioev);
}

/************************************************************************
 Callback when an IO completes from a suspend call.
***********************************************************************/

static void aio_linux_handle_suspend_completion(struct event_context *event_ctx,
				struct fd_event *event,
				uint16 flags,
				void *p)
{
	struct suspend_private *sp = (struct suspend_private *)p;
	uint64_t remaining_events = sp->num_entries - sp->num_finished;
	uint64_t num_events = 0;

	DEBUG(10, ("aio_linux_handle_suspend_completion called with flags=%d\n",
			(int)flags));

	if ((flags & EVENT_FD_READ) == 0) {
		return;
	}

	/* Read the number of events available. */
	if (sys_read(event_fd, &num_events, sizeof(num_events)) !=
			sizeof(num_events)) {
		smb_panic("aio_linux_handle_completion: invalid read");
	}

	while (num_events > 0) {
		uint64_t events_to_read = MIN(num_events, remaining_events);
		struct timespec ts;
		int i;
		int ret;

		ts.tv_sec = 0;
		ts.tv_nsec = 0;

		ret = io_getevents(io_ctx,
			1,
			(long)events_to_read,
			io_recv_events,
			&ts);

		if (ret < 0) {
			errno = -ret;
			DEBUG(1, ("aio_linux_handle_suspend_completion: "
				"io_getevents error %s\n",
				strerror(errno) ));
			return;
		}

		if (ret == 0) {
			DEBUG(10, ("aio_linux_handle_suspend_completion: "
				"io_getevents returned 0\n"));
			continue;
		}

		/* ret is positive. */
		for (i = 0; i < ret; i++) {
			aio_linux_handle_suspend_io_finished(sp,
					&io_recv_events[i]);
		}

		num_events -= ret;
	}
}

static void aio_linux_suspend_timed_out(struct tevent_context *event_ctx,
					struct tevent_timer *te,
					struct timeval now,
					void *private_data)
{
	bool *timed_out = (bool *)private_data;
	/* Remove this timed event handler. */
	TALLOC_FREE(te);
	*timed_out = true;
}

/************************************************************************
 Called to request everything to stop until all IO is completed.
***********************************************************************/

static int aio_linux_suspend(struct vfs_handle_struct *handle,
			struct files_struct *fsp,
			const SMB_STRUCT_AIOCB * const aiocb_array[],
			int n,
			const struct timespec *timeout)
{
	struct event_context *ev = NULL;
	struct fd_event *sock_event = NULL;
	int ret = -1;
	struct suspend_private sp;
	bool timed_out = false;
	TALLOC_CTX *frame = talloc_stackframe();

	/* This is a blocking call, and has to use a sub-event loop. */
	ev = event_context_init(frame);
	if (ev == NULL) {
		errno = ENOMEM;
		goto out;
	}

	if (timeout) {
		struct timeval tv = convert_timespec_to_timeval(*timeout);
		struct tevent_timer *te = tevent_add_timer(ev,
						frame,
						timeval_current_ofs(tv.tv_sec,
								    tv.tv_usec),
						aio_linux_suspend_timed_out,
						&timed_out);
		if (!te) {
			errno = ENOMEM;
			goto out;
		}
	}

	ZERO_STRUCT(sp);
	sp.num_entries = n;
	sp.aiocb_array = aiocb_array;
	sp.num_finished = 0;

	sock_event = tevent_add_fd(ev,
				frame,
				event_fd,
				TEVENT_FD_READ,
				aio_linux_handle_suspend_completion,
				(void *)&sp);
	if (sock_event == NULL) {
		goto out;
	}
	/*
	 * We're going to cheat here. We know that smbd/aio.c
	 * only calls this when it's waiting for every single
	 * outstanding call to finish on a close, so just wait
	 * individually for each IO to complete. We don't care
	 * what order they finish - only that they all do. JRA.
	 */
	while (sp.num_entries != sp.num_finished) {
		if (tevent_loop_once(ev) == -1) {
			goto out;
		}

		if (timed_out) {
			errno = EAGAIN;
			goto out;
		}
	}

	ret = 0;

  out:

	TALLOC_FREE(frame);
	return ret;
}

static int aio_linux_connect(vfs_handle_struct *handle, const char *service,
			       const char *user)
{
	/*********************************************************************
	 * How many io_events to initialize ?
	 * 128 per process seems insane as a default until you realize that
	 * (a) Throttling is done in SMB2 via the crediting algorithm.
	 * (b) SMB1 clients are limited to max_mux (50) outstanding
	 *     requests and Windows clients don't use this anyway.
	 * Essentially we want this to be unlimited unless smb.conf
	 * says different.
	 *********************************************************************/
	aio_pending_size = lp_parm_int(
		SNUM(handle->conn), "aio_linux", "aio num events", 128);
	return SMB_VFS_NEXT_CONNECT(handle, service, user);
}

static struct vfs_fn_pointers vfs_aio_linux_fns = {
	.connect_fn = aio_linux_connect,
	.aio_read_fn = aio_linux_read,
	.aio_write_fn = aio_linux_write,
	.aio_return_fn = aio_linux_return_fn,
	.aio_cancel_fn = aio_linux_cancel,
	.aio_error_fn = aio_linux_error_fn,
	.aio_suspend_fn = aio_linux_suspend,
};

NTSTATUS vfs_aio_linux_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"aio_linux", &vfs_aio_linux_fns);
}
