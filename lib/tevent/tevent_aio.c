/* 
   Unix SMB/CIFS implementation.

   main select loop and event handling - aio/epoll hybrid implementation

   Copyright (C) Andrew Tridgell	2006

   based on events_standard.c
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
/*
  this is a very strange beast. The Linux AIO implementation doesn't
  yet integrate properly with epoll, but there is a kernel patch that
  allows the aio wait primitives to be used to wait for epoll events,
  and this can be used to give us a unified event system incorporating
  both aio events and epoll events

  this is _very_ experimental code
*/

#include "system/filesys.h"
#include "replace.h"
#include "tevent.h"
#include "tevent_internal.h"
#include "tevent_util.h"
#include <sys/epoll.h>
#include <libaio.h>

#define MAX_AIO_QUEUE_DEPTH	100
#ifndef IOCB_CMD_EPOLL_WAIT
#define IOCB_CMD_EPOLL_WAIT	9
#endif

struct aio_event_context {
	/* a pointer back to the generic event_context */
	struct tevent_context *ev;

	/* list of filedescriptor events */
	struct tevent_fd *fd_events;

	/* number of registered fd event handlers */
	int num_fd_events;

	uint32_t destruction_count;

	io_context_t ioctx;

	struct epoll_event epevent[MAX_AIO_QUEUE_DEPTH];

	struct iocb *epoll_iocb;

	int epoll_fd;
	int is_epoll_set;
	pid_t pid;
};

struct aio_event {
	struct tevent_context *event_ctx;
	struct iocb iocb;
	void *private_data;
	event_aio_handler_t handler;
};

/*
  map from EVENT_FD_* to EPOLLIN/EPOLLOUT
*/
static uint32_t epoll_map_flags(uint16_t flags)
{
	uint32_t ret = 0;
	if (flags & EVENT_FD_READ) ret |= (EPOLLIN | EPOLLERR | EPOLLHUP);
	if (flags & EVENT_FD_WRITE) ret |= (EPOLLOUT | EPOLLERR | EPOLLHUP);
	return ret;
}

/*
 free the epoll fd
*/
static int aio_ctx_destructor(struct aio_event_context *aio_ev)
{
	io_queue_release(aio_ev->ioctx);
	close(aio_ev->epoll_fd);
	aio_ev->epoll_fd = -1;
	return 0;
}

static void epoll_add_event(struct aio_event_context *aio_ev, struct tevent_fd *fde);

/*
  reopen the epoll handle when our pid changes
  see http://junkcode.samba.org/ftp/unpacked/junkcode/epoll_fork.c for an 
  demonstration of why this is needed
 */
static void epoll_check_reopen(struct aio_event_context *aio_ev)
{
	struct tevent_fd *fde;

	if (aio_ev->pid == getpid()) {
		return;
	}

	close(aio_ev->epoll_fd);
	aio_ev->epoll_fd = epoll_create(MAX_AIO_QUEUE_DEPTH);
	if (aio_ev->epoll_fd == -1) {
		ev_debug(aio_ev->ev, EV_DEBUG_FATAL, "Failed to recreate epoll handle after fork\n");
		return;
	}
	aio_ev->pid = getpid();
	for (fde=aio_ev->fd_events;fde;fde=fde->next) {
		epoll_add_event(aio_ev, fde);
	}
}

#define EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT	(1<<0)
#define EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR	(1<<1)
#define EPOLL_ADDITIONAL_FD_FLAG_GOT_ERROR	(1<<2)

/*
 add the epoll event to the given fd_event
*/
static void epoll_add_event(struct aio_event_context *aio_ev, struct tevent_fd *fde)
{
	struct epoll_event event;
	if (aio_ev->epoll_fd == -1) return;

	fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR;

	/* if we don't want events yet, don't add an aio_event */
	if (fde->flags == 0) return;

	memset(&event, 0, sizeof(event));
	event.events = epoll_map_flags(fde->flags);
	event.data.ptr = fde;
	epoll_ctl(aio_ev->epoll_fd, EPOLL_CTL_ADD, fde->fd, &event);
	fde->additional_flags |= EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;

	/* only if we want to read we want to tell the event handler about errors */
	if (fde->flags & EVENT_FD_READ) {
		fde->additional_flags |= EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR;
	}
}

/*
 delete the epoll event for given fd_event
*/
static void epoll_del_event(struct aio_event_context *aio_ev, struct tevent_fd *fde)
{
	struct epoll_event event;

	DLIST_REMOVE(aio_ev->fd_events, fde);

	if (aio_ev->epoll_fd == -1) return;

	fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR;

	/* if there's no aio_event, we don't need to delete it */
	if (!(fde->additional_flags & EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT)) return;

	ZERO_STRUCT(event);
	event.events = epoll_map_flags(fde->flags);
	event.data.ptr = fde;
	epoll_ctl(aio_ev->epoll_fd, EPOLL_CTL_DEL, fde->fd, &event);

	fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;
}

/*
 change the epoll event to the given fd_event
*/
static void epoll_mod_event(struct aio_event_context *aio_ev, struct tevent_fd *fde)
{
	struct epoll_event event;
	if (aio_ev->epoll_fd == -1) return;

	fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR;

	ZERO_STRUCT(event);
	event.events = epoll_map_flags(fde->flags);
	event.data.ptr = fde;
	epoll_ctl(aio_ev->epoll_fd, EPOLL_CTL_MOD, fde->fd, &event);

	/* only if we want to read we want to tell the event handler about errors */
	if (fde->flags & EVENT_FD_READ) {
		fde->additional_flags |= EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR;
	}
}

static void epoll_change_event(struct aio_event_context *aio_ev, struct tevent_fd *fde)
{
	bool got_error = (fde->additional_flags & EPOLL_ADDITIONAL_FD_FLAG_GOT_ERROR);
	bool want_read = (fde->flags & EVENT_FD_READ);
	bool want_write= (fde->flags & EVENT_FD_WRITE);

	if (aio_ev->epoll_fd == -1) return;

	fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR;

	/* there's already an event */
	if (fde->additional_flags & EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT) {
		if (want_read || (want_write && !got_error)) {
			epoll_mod_event(aio_ev, fde);
			return;
		}
		epoll_del_event(aio_ev, fde);
		return;
	}

	/* there's no aio_event attached to the fde */
	if (want_read || (want_write && !got_error)) {
		DLIST_ADD(aio_ev->fd_events, fde);
		epoll_add_event(aio_ev, fde);
		return;
	}
}

static int setup_epoll_wait(struct aio_event_context *aio_ev)
{
	if (aio_ev->is_epoll_set) {
		return 0;
	}
	memset(aio_ev->epoll_iocb, 0, sizeof(*aio_ev->epoll_iocb));
	aio_ev->epoll_iocb->aio_fildes = aio_ev->epoll_fd;
	aio_ev->epoll_iocb->aio_lio_opcode = IOCB_CMD_EPOLL_WAIT;
	aio_ev->epoll_iocb->aio_reqprio = 0;

	aio_ev->epoll_iocb->u.c.nbytes = MAX_AIO_QUEUE_DEPTH;
	aio_ev->epoll_iocb->u.c.offset = -1;
	aio_ev->epoll_iocb->u.c.buf = aio_ev->epevent;

	if (io_submit(aio_ev->ioctx, 1, &aio_ev->epoll_iocb) != 1) {
		return -1;
	}
	aio_ev->is_epoll_set = 1;

	return 0;
}


/*
  event loop handling using aio/epoll hybrid
*/
static int aio_event_loop(struct aio_event_context *aio_ev, struct timeval *tvalp)
{
	int ret, i;
	uint32_t destruction_count = ++aio_ev->destruction_count;
	struct timespec timeout;
	struct io_event events[8];

	if (aio_ev->epoll_fd == -1) return -1;

	if (aio_ev->ev->num_signal_handlers && 
	    common_event_check_signal(aio_ev->ev)) {
		return 0;
	}

	if (tvalp) {
		timeout.tv_sec = tvalp->tv_sec;
		timeout.tv_nsec = tvalp->tv_usec;
		timeout.tv_nsec *= 1000;
	}

	if (setup_epoll_wait(aio_ev) < 0) 
		return -1;

	ret = io_getevents(aio_ev->ioctx, 1, 8,
			   events, tvalp?&timeout:NULL);

	if (ret == -EINTR) {
		if (aio_ev->ev->num_signal_handlers) {
			common_event_check_signal(aio_ev->ev);
		}
		return 0;
	}

	if (ret == 0 && tvalp) {
		/* we don't care about a possible delay here */
		common_event_loop_timer_delay(aio_ev->ev);
		return 0;
	}

	for (i=0;i<ret;i++) {
		struct io_event *event = &events[i];
		struct iocb *finished = event->obj;

		switch (finished->aio_lio_opcode) {
		case IO_CMD_PWRITE:
		case IO_CMD_PREAD: {
			struct aio_event *ae = talloc_get_type(finished->data, 
							       struct aio_event);
			if (ae) {
				talloc_set_destructor(ae, NULL);
				ae->handler(ae->event_ctx, ae, 
					    event->res, ae->private_data);
				talloc_free(ae);
			}
			break;
		}
		case IOCB_CMD_EPOLL_WAIT: {
			struct epoll_event *ep = (struct epoll_event *)finished->u.c.buf;
			struct tevent_fd *fde;
			uint16_t flags = 0;
			int j;

			aio_ev->is_epoll_set = 0;

			for (j=0; j<event->res; j++, ep++) {
				fde = talloc_get_type(ep->data.ptr, 
						      struct tevent_fd);
				if (fde == NULL) {
					return -1;
				}
				if (ep->events & (EPOLLHUP|EPOLLERR)) {
					fde->additional_flags |= EPOLL_ADDITIONAL_FD_FLAG_GOT_ERROR;
					if (!(fde->additional_flags & EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR)) {
						epoll_del_event(aio_ev, fde);
						continue;
					}
					flags |= EVENT_FD_READ;
				}
				if (ep->events & EPOLLIN) flags |= EVENT_FD_READ;
				if (ep->events & EPOLLOUT) flags |= EVENT_FD_WRITE;
				if (flags) {
					fde->handler(aio_ev->ev, fde, flags, fde->private_data);
				}
			}
			break;
		}
		}
		if (destruction_count != aio_ev->destruction_count) {
			return 0;
		}
	}

	return 0;
}

/*
  create a aio_event_context structure.
*/
static int aio_event_context_init(struct tevent_context *ev)
{
	struct aio_event_context *aio_ev;
	
	aio_ev = talloc_zero(ev, struct aio_event_context);
	if (!aio_ev) return -1;

	aio_ev->ev = ev;
	aio_ev->epoll_iocb = talloc(aio_ev, struct iocb);

	if (io_queue_init(MAX_AIO_QUEUE_DEPTH, &aio_ev->ioctx) != 0) {
		talloc_free(aio_ev);
		return -1;
	}

	aio_ev->epoll_fd = epoll_create(MAX_AIO_QUEUE_DEPTH);
	if (aio_ev->epoll_fd == -1) {
		talloc_free(aio_ev);
		return -1;
	}
	aio_ev->pid = getpid();

	talloc_set_destructor(aio_ev, aio_ctx_destructor);

	ev->additional_data = aio_ev;

	if (setup_epoll_wait(aio_ev) < 0) {
		talloc_free(aio_ev);
		return -1;
	}

	return 0;
}

/*
  destroy an fd_event
*/
static int aio_event_fd_destructor(struct tevent_fd *fde)
{
	struct tevent_context *ev = fde->event_ctx;
	struct aio_event_context *aio_ev = talloc_get_type(ev->additional_data,
							   struct aio_event_context);

	epoll_check_reopen(aio_ev);

	aio_ev->num_fd_events--;
	aio_ev->destruction_count++;

	epoll_del_event(aio_ev, fde);

	if (fde->flags & EVENT_FD_AUTOCLOSE) {
		close(fde->fd);
		fde->fd = -1;
	}

	return 0;
}

/*
  add a fd based event
  return NULL on failure (memory allocation error)
*/
static struct tevent_fd *aio_event_add_fd(struct tevent_context *ev, TALLOC_CTX *mem_ctx,
					 int fd, uint16_t flags,
					 event_fd_handler_t handler,
					 void *private_data)
{
	struct aio_event_context *aio_ev = talloc_get_type(ev->additional_data,
							   struct aio_event_context);
	struct tevent_fd *fde;

	epoll_check_reopen(aio_ev);

	fde = talloc(mem_ctx?mem_ctx:ev, struct tevent_fd);
	if (!fde) return NULL;

	fde->event_ctx		= ev;
	fde->fd			= fd;
	fde->flags		= flags;
	fde->handler		= handler;
	fde->private_data	= private_data;
	fde->additional_flags	= 0;
	fde->additional_data	= NULL;

	aio_ev->num_fd_events++;
	talloc_set_destructor(fde, aio_event_fd_destructor);

	DLIST_ADD(aio_ev->fd_events, fde);
	epoll_add_event(aio_ev, fde);

	return fde;
}


/*
  return the fd event flags
*/
static uint16_t aio_event_get_fd_flags(struct tevent_fd *fde)
{
	return fde->flags;
}

/*
  set the fd event flags
*/
static void aio_event_set_fd_flags(struct tevent_fd *fde, uint16_t flags)
{
	struct tevent_context *ev;
	struct aio_event_context *aio_ev;

	if (fde->flags == flags) return;

	ev = fde->event_ctx;
	aio_ev = talloc_get_type(ev->additional_data, struct aio_event_context);

	fde->flags = flags;

	epoll_check_reopen(aio_ev);

	epoll_change_event(aio_ev, fde);
}

/*
  do a single event loop using the events defined in ev 
*/
static int aio_event_loop_once(struct tevent_context *ev)
{
	struct aio_event_context *aio_ev = talloc_get_type(ev->additional_data,
		 					   struct aio_event_context);
	struct timeval tval;

	tval = common_event_loop_timer_delay(ev);
	if (ev_timeval_is_zero(&tval)) {
		return 0;
	}

	epoll_check_reopen(aio_ev);

	return aio_event_loop(aio_ev, &tval);
}

/*
  return on failure or (with 0) if all fd events are removed
*/
static int aio_event_loop_wait(struct tevent_context *ev)
{
	struct aio_event_context *aio_ev = talloc_get_type(ev->additional_data,
							   struct aio_event_context);
	while (aio_ev->num_fd_events) {
		if (aio_event_loop_once(ev) != 0) {
			break;
		}
	}

	return 0;
}

/*
  called when a disk IO event needs to be cancelled
*/
static int aio_destructor(struct aio_event *ae)
{
	struct tevent_context *ev = ae->event_ctx;
	struct aio_event_context *aio_ev = talloc_get_type(ev->additional_data,
							   struct aio_event_context);
	struct io_event result;
	io_cancel(aio_ev->ioctx, &ae->iocb, &result);
	/* TODO: handle errors from io_cancel()! */
	return 0;
}

/* submit an aio disk IO event */
static struct aio_event *aio_event_add_aio(struct tevent_context *ev, 
					   TALLOC_CTX *mem_ctx,
					   struct iocb *iocb,
					   event_aio_handler_t handler,
					   void *private_data)
{
	struct aio_event_context *aio_ev = talloc_get_type(ev->additional_data,
							   struct aio_event_context);
	struct iocb *iocbp;
	struct aio_event *ae = talloc(mem_ctx?mem_ctx:ev, struct aio_event);
	if (ae == NULL) return NULL;

	ae->event_ctx    = ev;
	ae->iocb         = *iocb;
	ae->handler      = handler;
	ae->private_data = private_data;
	iocbp = &ae->iocb;

	if (io_submit(aio_ev->ioctx, 1, &iocbp) != 1) {
		talloc_free(ae);
		return NULL;
	}
	ae->iocb.data = ae;
	talloc_set_destructor(ae, aio_destructor);

	return ae;
}

static const struct event_ops aio_event_ops = {
	.context_init	= aio_event_context_init,
	.add_fd		= aio_event_add_fd,
	.add_aio        = aio_event_add_aio,
	.get_fd_flags	= aio_event_get_fd_flags,
	.set_fd_flags	= aio_event_set_fd_flags,
	.add_timer	= common_event_add_timed,
	.add_signal	= common_event_add_signal,
	.loop_once	= aio_event_loop_once,
	.loop_wait	= aio_event_loop_wait,
};

bool events_aio_init(void)
{
	return event_register_backend("aio", &aio_event_ops);
}

