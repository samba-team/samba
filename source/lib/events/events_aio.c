/* 
   Unix SMB/CIFS implementation.

   main select loop and event handling - aio/epoll hybrid implementation

   Copyright (C) Andrew Tridgell	2006

   based on events_standard.c
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/
/*
  this is a very strange beast. The Linux AIO implementation doesn't
  yet integrate properly with epoll, but there is a kernel patch that
  allows the aio wait primitives to be used to wait for epoll events,
  and this can be used to give us a unified event system incorporating
  both aio events and epoll events

  this is _very_ experimental code
*/

#include "includes.h"
#include "system/filesys.h"
#include "system/select.h" /* needed for WITH_EPOLL */
#include "lib/util/dlinklist.h"
#include "lib/events/events.h"
#include "lib/events/events_internal.h"
#include <libaio.h>

#define MAX_AIO_QUEUE_DEPTH	10
#define IOCB_CMD_EPOLL_WAIT	9

struct aio_event_context {
	/* a pointer back to the generic event_context */
	struct event_context *ev;

	/* number of registered fd event handlers */
	int num_fd_events;

	/* list of timed events */
	struct timed_event *timed_events;

	uint32_t destruction_count;

	io_context_t ioctx;

	struct io_event events[MAX_AIO_QUEUE_DEPTH];
	struct epoll_event epevent;

	struct iocb *epoll_iocb;

	int epoll_fd;
};

static void aio_event_loop_timer(struct aio_event_context *aio_ev);

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
	close(aio_ev->epoll_fd);
	aio_ev->epoll_fd = -1;
	return 0;
}

#define EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT	(1<<0)
#define EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR	(1<<1)
#define EPOLL_ADDITIONAL_FD_FLAG_GOT_ERROR	(1<<2)

/*
 add the epoll event to the given fd_event
*/
static void epoll_add_event(struct aio_event_context *aio_ev, struct fd_event *fde)
{
	struct epoll_event event;
	if (aio_ev->epoll_fd == -1) return;

	fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR;

	/* if we don't want events yet, don't add an aio_event */
	if (fde->flags == 0) return;

	ZERO_STRUCT(event);
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
static void epoll_del_event(struct aio_event_context *aio_ev, struct fd_event *fde)
{
	struct epoll_event event;
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
static void epoll_mod_event(struct aio_event_context *aio_ev, struct fd_event *fde)
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

static void epoll_change_event(struct aio_event_context *aio_ev, struct fd_event *fde)
{
	BOOL got_error = (fde->additional_flags & EPOLL_ADDITIONAL_FD_FLAG_GOT_ERROR);
	BOOL want_read = (fde->flags & EVENT_FD_READ);
	BOOL want_write= (fde->flags & EVENT_FD_WRITE);

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
		epoll_add_event(aio_ev, fde);
		return;
	}
}

static int setup_epoll_wait(struct aio_event_context *aio_ev)
{
	struct io_event r;
	
	memset(aio_ev->epoll_iocb, 0, sizeof(*aio_ev->epoll_iocb));
	aio_ev->epoll_iocb->aio_fildes = aio_ev->epoll_fd;
	aio_ev->epoll_iocb->aio_lio_opcode = IOCB_CMD_EPOLL_WAIT;
	aio_ev->epoll_iocb->aio_reqprio = 0;

	aio_ev->epoll_iocb->u.c.nbytes = 1;
	aio_ev->epoll_iocb->u.c.offset = -1;
	aio_ev->epoll_iocb->u.c.buf = &aio_ev->epevent;

	if (io_submit(aio_ev->ioctx, 1, &aio_ev->epoll_iocb) != 1) {
		return -1;
	}
}


/*
  event loop handling using aio/epoll hybrid
*/
static int aio_event_loop(struct aio_event_context *aio_ev, struct timeval *tvalp)
{
	int ret, i;
	uint32_t destruction_count = aio_ev->destruction_count;
	struct timespec timeout;

	if (aio_ev->epoll_fd == -1) return -1;

	if (tvalp) {
		timeout.tv_sec = tvalp->tv_sec;
		timeout.tv_nsec = tvalp->tv_usec;
		timeout.tv_nsec *= 1000;
	}

	setup_epoll_wait(aio_ev);

	ret = io_getevents(aio_ev->ioctx, 1, MAX_AIO_QUEUE_DEPTH,
			   aio_ev->events, tvalp?&timeout:NULL);
	if (ret == -EINTR) {
		return 0;
	}

	if (ret == 0 && tvalp) {
		aio_event_loop_timer(aio_ev);
		return 0;
	}

	for (i=0;i<ret;i++) {
		struct iocb *finished = aio_ev->events[i].obj;
		switch (finished->aio_lio_opcode) {
		case IOCB_CMD_EPOLL_WAIT: {
			struct epoll_event *ep = (struct epoll_event *)finished->u.c.buf;
			struct fd_event *fde = talloc_get_type(ep->data.ptr, 
							       struct fd_event);
			uint16_t flags = 0;

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
				if (destruction_count != aio_ev->destruction_count) {
					return 0;
				}
			}
			break;
		}
		}
	}

	return 0;
}

/*
  create a aio_event_context structure.
*/
static int aio_event_context_init(struct event_context *ev, void *private_data)
{
	struct aio_event_context *aio_ev;
	
	aio_ev = talloc_zero(ev, struct aio_event_context);
	if (!aio_ev) return -1;

	aio_ev->ev = ev;
	aio_ev->epoll_iocb = talloc(aio_ev, struct iocb);

	if (io_queue_init(MAX_AIO_QUEUE_DEPTH, &aio_ev->ioctx) != 0) {
		return -1;
	}

	aio_ev->epoll_fd = epoll_create(MAX_AIO_QUEUE_DEPTH);
	if (aio_ev->epoll_fd == -1) return -1;

	talloc_set_destructor(aio_ev, aio_ctx_destructor);

	ev->additional_data = aio_ev;
	return 0;
}

/*
  destroy an fd_event
*/
static int aio_event_fd_destructor(struct fd_event *fde)
{
	struct event_context *ev = fde->event_ctx;
	struct aio_event_context *aio_ev = talloc_get_type(ev->additional_data,
							   struct aio_event_context);

	aio_ev->num_fd_events--;
	aio_ev->destruction_count++;

	epoll_del_event(aio_ev, fde);

	return 0;
}

/*
  add a fd based event
  return NULL on failure (memory allocation error)
*/
static struct fd_event *aio_event_add_fd(struct event_context *ev, TALLOC_CTX *mem_ctx,
					 int fd, uint16_t flags,
					 event_fd_handler_t handler,
					 void *private_data)
{
	struct aio_event_context *aio_ev = talloc_get_type(ev->additional_data,
							   struct aio_event_context);
	struct fd_event *fde;

	fde = talloc(mem_ctx?mem_ctx:ev, struct fd_event);
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

	epoll_add_event(aio_ev, fde);

	return fde;
}


/*
  return the fd event flags
*/
static uint16_t aio_event_get_fd_flags(struct fd_event *fde)
{
	return fde->flags;
}

/*
  set the fd event flags
*/
static void aio_event_set_fd_flags(struct fd_event *fde, uint16_t flags)
{
	struct event_context *ev;
	struct aio_event_context *aio_ev;

	if (fde->flags == flags) return;

	ev = fde->event_ctx;
	aio_ev = talloc_get_type(ev->additional_data, struct aio_event_context);

	fde->flags = flags;

	epoll_change_event(aio_ev, fde);
}

/*
  destroy a timed event
*/
static int aio_event_timed_destructor(struct timed_event *te)
{
	struct aio_event_context *aio_ev = talloc_get_type(te->event_ctx->additional_data,
							   struct aio_event_context);
	DLIST_REMOVE(aio_ev->timed_events, te);
	return 0;
}

static int aio_event_timed_deny_destructor(struct timed_event *te)
{
	return -1;
}

/*
  add a timed event
  return NULL on failure (memory allocation error)
*/
static struct timed_event *aio_event_add_timed(struct event_context *ev, TALLOC_CTX *mem_ctx,
					       struct timeval next_event, 
					       event_timed_handler_t handler, 
					       void *private_data) 
{
	struct aio_event_context *aio_ev = talloc_get_type(ev->additional_data,
							   struct aio_event_context);
	struct timed_event *te, *last_te, *cur_te;

	te = talloc(mem_ctx?mem_ctx:ev, struct timed_event);
	if (te == NULL) return NULL;

	te->event_ctx		= ev;
	te->next_event		= next_event;
	te->handler		= handler;
	te->private_data	= private_data;
	te->additional_data	= NULL;

	/* keep the list ordered */
	last_te = NULL;
	for (cur_te = aio_ev->timed_events; cur_te; cur_te = cur_te->next) {
		/* if the new event comes before the current one break */
		if (!timeval_is_zero(&cur_te->next_event) &&
		    timeval_compare(&te->next_event,
				    &cur_te->next_event) < 0) {
			break;
		}

		last_te = cur_te;
	}

	DLIST_ADD_AFTER(aio_ev->timed_events, te, last_te);

	talloc_set_destructor(te, aio_event_timed_destructor);

	return te;
}

/*
  a timer has gone off - call it
*/
static void aio_event_loop_timer(struct aio_event_context *aio_ev)
{
	struct timeval t = timeval_current();
	struct timed_event *te = aio_ev->timed_events;

	if (te == NULL) {
		return;
	}

	/* deny the handler to free the event */
	talloc_set_destructor(te, aio_event_timed_deny_destructor);

	/* We need to remove the timer from the list before calling the
	 * handler because in a semi-async inner event loop called from the
	 * handler we don't want to come across this event again -- vl */
	DLIST_REMOVE(aio_ev->timed_events, te);

	te->handler(aio_ev->ev, te, t, te->private_data);

	/* The destructor isn't necessary anymore, we've already removed the
	 * event from the list. */
	talloc_set_destructor(te, NULL);

	talloc_free(te);
}

/*
  do a single event loop using the events defined in ev 
*/
static int aio_event_loop_once(struct event_context *ev)
{
	struct aio_event_context *aio_ev = talloc_get_type(ev->additional_data,
		 					   struct aio_event_context);
	struct timeval tval;

	/* work out the right timeout for all timed events */
	if (aio_ev->timed_events) {
		struct timeval t = timeval_current();
		tval = timeval_until(&t, &aio_ev->timed_events->next_event);
		if (timeval_is_zero(&tval)) {
			aio_event_loop_timer(aio_ev);
			return 0;
		}
	} else {
		/* have a default tick time of 30 seconds. This guarantees
		   that code that uses its own timeout checking will be
		   able to proceeed eventually */
		tval = timeval_set(30, 0);
	}

	return aio_event_loop(aio_ev, &tval);
}

/*
  return on failure or (with 0) if all fd events are removed
*/
static int aio_event_loop_wait(struct event_context *ev)
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

static const struct event_ops aio_event_ops = {
	.context_init	= aio_event_context_init,
	.add_fd		= aio_event_add_fd,
	.get_fd_flags	= aio_event_get_fd_flags,
	.set_fd_flags	= aio_event_set_fd_flags,
	.add_timed	= aio_event_add_timed,
	.loop_once	= aio_event_loop_once,
	.loop_wait	= aio_event_loop_wait,
};

const struct event_ops *event_aio_get_ops(void)
{
	return &aio_event_ops;
}
