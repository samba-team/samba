/* 
   Unix SMB/CIFS implementation.
   main select loop and event handling
   Copyright (C) Andrew Tridgell 2003
   
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
  PLEASE READ THIS BEFORE MODIFYING!

  This module is a general abstraction for the main select loop and
  event handling. Do not ever put any localised hacks in here, instead
  register one of the possible event types and implement that event
  somewhere else.

  There are 2 types of event handling that are handled in this module:

  1) a file descriptor becoming readable or writeable. This is mostly
     used for network sockets, but can be used for any type of file
     descriptor. You may only register one handler for each file
     descriptor/io combination or you will get unpredictable results
     (this means that you can have a handler for read events, and a
     separate handler for write events, but not two handlers that are
     both handling read events)

  2) a timed event. You can register an event that happens at a
     specific time.  You can register as many of these as you
     like. They are single shot - add a new timed event in the event
     handler to get another event.

  To setup a set of events you first need to create a event_context
  structure using the function event_context_init(); This returns a
  'struct event_context' that you use in all subsequent calls.

  After that you can add/remove events that you are interested in
  using event_add_*() and talloc_free()

  Finally, you call event_loop_wait() to block waiting for one of the
  events to occor. In normal operation event_loop_wait() will loop
  forever.

*/

#include "includes.h"
#include "system/time.h"
#include "system/select.h"
#include "system/filesys.h"
#include "dlinklist.h"
#include "lib/events/events.h"

/* use epoll if it is available */
#if defined(HAVE_EPOLL_CREATE) && defined(HAVE_SYS_EPOLL_H)
#define WITH_EPOLL 1
#endif

#if WITH_EPOLL
#include <sys/epoll.h>
#endif

struct event_context {	
	/* list of filedescriptor events */
	struct fd_event {
		struct event_context *event_ctx;
		struct fd_event *next, *prev;
		int fd;
		uint16_t flags; /* see EVENT_FD_* flags */
		event_fd_handler_t handler;
		void *private;
	} *fd_events;

	/* list of timed events */
	struct timed_event {
		struct event_context *event_ctx;
		struct timed_event *next, *prev;
		struct timeval next_event;
		event_timed_handler_t handler;
		void *private;
	} *timed_events;

	/* the maximum file descriptor number in fd_events */
	int maxfd;

	/* information for exiting from the event loop */
	int exit_code;

	/* this is changed by the destructors for the fd event
	   type. It is used to detect event destruction by event
	   handlers, which means the code that is calling the event
	   handler needs to assume that the linked list is no longer
	   valid
	*/
	uint32_t destruction_count;

#if WITH_EPOLL
	/* when using epoll this is the handle from epoll_create */
	int epoll_fd;
#endif
};


/*
  destroy an event context
*/
static int event_context_destructor(void *ptr)
{
#if WITH_EPOLL
	struct event_context *ev = talloc_get_type(ptr, struct event_context);
	if (ev->epoll_fd != -1) {
		close(ev->epoll_fd);
		ev->epoll_fd = -1;
	}
#endif
	return 0;
}

/*
  create a event_context structure. This must be the first events
  call, and all subsequent calls pass this event_context as the first
  element. Event handlers also receive this as their first argument.
*/
struct event_context *event_context_init(TALLOC_CTX *mem_ctx)
{
	struct event_context *ev;

	ev = talloc_zero(mem_ctx, struct event_context);
	if (!ev) return NULL;

#if WITH_EPOLL
	ev->epoll_fd = epoll_create(64);
#endif

	talloc_set_destructor(ev, event_context_destructor);

	return ev;
}


/*
  recalculate the maxfd
*/
static void calc_maxfd(struct event_context *ev)
{
	struct fd_event *e;
	ev->maxfd = 0;
	for (e=ev->fd_events; e; e=e->next) {
		if (e->fd > ev->maxfd) {
			ev->maxfd = e->fd;
		}
	}
}


/* to mark the ev->maxfd invalid
 * this means we need to recalculate it
 */
#define EVENT_INVALID_MAXFD (-1)


#if WITH_EPOLL
/*
  called when a epoll call fails, and we should fallback
  to using select
*/
static void epoll_fallback_to_select(struct event_context *ev, const char *reason)
{
	DEBUG(0,("%s (%s) - falling back to select()\n", reason, strerror(errno)));
	close(ev->epoll_fd);
	ev->epoll_fd = -1;
}
#endif


#if WITH_EPOLL
/*
  map from EVENT_FD_* to EPOLLIN/EPOLLOUT
*/
static uint32_t epoll_map_flags(uint16_t flags)
{
	uint32_t ret = 0;
	if (flags & EVENT_FD_READ) ret |= EPOLLIN;
	if (flags & EVENT_FD_WRITE) ret |= EPOLLOUT;
	return ret;
}
#endif

/*
  destroy an fd_event
*/
static int event_fd_destructor(void *ptr)
{
	struct fd_event *fde = talloc_get_type(ptr, struct fd_event);
	struct event_context *ev = fde->event_ctx;

	if (ev->maxfd == fde->fd) {
		ev->maxfd = EVENT_INVALID_MAXFD;
	}
	DLIST_REMOVE(ev->fd_events, fde);
	ev->destruction_count++;
#if WITH_EPOLL
	if (ev->epoll_fd != -1) {
		struct epoll_event event;
		ZERO_STRUCT(event);
		event.events = epoll_map_flags(fde->flags);
		event.data.ptr = fde;
		epoll_ctl(ev->epoll_fd, EPOLL_CTL_DEL, fde->fd, &event);
	}
#endif
	return 0;
}

/*
  add a fd based event
  return NULL on failure (memory allocation error)
*/
struct fd_event *event_add_fd(struct event_context *ev, TALLOC_CTX *mem_ctx,
			      int fd, uint16_t flags, event_fd_handler_t handler,
			      void *private)
{
	struct fd_event *e = talloc(ev, struct fd_event);
	if (!e) return NULL;

	e->event_ctx = ev;
	e->fd        = fd;
	e->flags     = flags;
	e->handler   = handler;
	e->private   = private;

	DLIST_ADD(ev->fd_events, e);

	if (e->fd > ev->maxfd) {
		ev->maxfd = e->fd;
	}

	talloc_set_destructor(e, event_fd_destructor);
	if (mem_ctx) {
		talloc_steal(mem_ctx, e);
	}

#if WITH_EPOLL
	if (ev->epoll_fd != -1) {
		struct epoll_event event;
		ZERO_STRUCT(event);
		event.events = epoll_map_flags(flags);
		event.data.ptr = e;
		if (epoll_ctl(ev->epoll_fd, EPOLL_CTL_ADD, e->fd, &event) != 0) {
			epoll_fallback_to_select(ev, "EPOLL_CTL_ADD failed");
		}
	}
#endif

	return e;
}


/*
  return the fd event flags
*/
uint16_t event_fd_flags(struct fd_event *fde)
{
	return fde?fde->flags:0;
}

/*
  set the fd event flags
*/
void event_fd_setflags(struct fd_event *fde, uint16_t flags)
{
#if WITH_EPOLL
	struct event_context *ev;
	if (fde == NULL || 
	    fde->flags == flags) {
		return;
	}
	ev = fde->event_ctx;
	if (ev->epoll_fd != -1) {
		struct epoll_event event;
		ZERO_STRUCT(event);
		event.events = epoll_map_flags(flags);
		event.data.ptr = fde;
		if (epoll_ctl(ev->epoll_fd, EPOLL_CTL_MOD, fde->fd, &event) != 0) {
			epoll_fallback_to_select(ev, "EPOLL_CTL_MOD failed");
		}
	}
#endif
	if (fde) {
		fde->flags = flags;
	}
}

/*
  destroy a timed event
*/
static int event_timed_destructor(void *ptr)
{
	struct timed_event *te = talloc_get_type(ptr, struct timed_event);
	DLIST_REMOVE(te->event_ctx->timed_events, te);
	return 0;
}

/*
  add a timed event
  return NULL on failure (memory allocation error)
*/
struct timed_event *event_add_timed(struct event_context *ev, TALLOC_CTX *mem_ctx,
				    struct timeval next_event, 
				    event_timed_handler_t handler, 
				    void *private) 
{
	struct timed_event *te, *e;

	e = talloc(mem_ctx?mem_ctx:ev, struct timed_event);
	if (e == NULL) return NULL;

	e->event_ctx  = ev;
	e->next_event = next_event;
	e->handler    = handler;
	e->private    = private;

	/* keep the list ordered */
	if (ev->timed_events == NULL || 
	    timeval_compare(&e->next_event, &ev->timed_events->next_event) > 0) {
		DLIST_ADD(ev->timed_events, e);
	} else {
		for (te=ev->timed_events;te && te->next;te=te->next) {
			if (!timeval_is_zero(&te->next->next_event) &&
			    timeval_compare(&te->next->next_event, &e->next_event) < 0) {
				break;
			}
		}
		DLIST_ADD_AFTER(ev->timed_events, e, te);
	}

	talloc_set_destructor(e, event_timed_destructor);

	return e;
}

/*
  a timer has gone off - call it
*/
static void event_loop_timer(struct event_context *ev)
{
	struct timeval t = timeval_current();
	struct timed_event *te = ev->timed_events;

	te->next_event = timeval_zero();

	te->handler(ev, te, t, te->private);

	/* note the care taken to prevent referencing a event
	   that could have been freed by the handler */
	if (ev->timed_events && timeval_is_zero(&ev->timed_events->next_event)) {
		talloc_free(ev->timed_events);
	}
}

#if WITH_EPOLL
/*
  event loop handling using epoll
*/
static int event_loop_epoll(struct event_context *ev, struct timeval *tvalp)
{
	int ret, i;
	const int maxevents = 8;
	struct epoll_event events[maxevents];
	uint32_t destruction_count = ev->destruction_count;
	int timeout = -1;

	if (tvalp) {
		timeout = (tvalp->tv_usec / 1000) + (tvalp->tv_sec*1000);
	}

	ret = epoll_wait(ev->epoll_fd, events, maxevents, timeout);

	if (ret == -1 && errno != EINTR) {
		epoll_fallback_to_select(ev, "epoll_wait() failed");
		return -1;
	}

	if (ret == 0 && tvalp) {
		event_loop_timer(ev);
		return 0;
	}

	for (i=0;i<ret;i++) {
		struct fd_event *fde = talloc_get_type(events[i].data.ptr, 
						       struct fd_event);
		uint16_t flags = 0;

		if (fde == NULL) {
			epoll_fallback_to_select(ev, "epoll_wait() gave bad data");
			return -1;
		}
		if (events[i].events & EPOLLIN) flags |= EVENT_FD_READ;
		if (events[i].events & EPOLLOUT) flags |= EVENT_FD_WRITE;
		if (flags) {
			fde->handler(ev, fde, flags, fde->private);
			if (destruction_count != ev->destruction_count) {
				break;
			}
		}
	}

	return 0;
}		
#endif

/*
  event loop handling using select()
*/
static int event_loop_select(struct event_context *ev, struct timeval *tvalp)
{
	fd_set r_fds, w_fds;
	int selrtn;
	uint32_t destruction_count = ev->destruction_count;
	struct fd_event *fe;

	/* we maybe need to recalculate the maxfd */
	if (ev->maxfd == EVENT_INVALID_MAXFD) {
		calc_maxfd(ev);
	}
		
	FD_ZERO(&r_fds);
	FD_ZERO(&w_fds);

	/* setup any fd events */
	for (fe=ev->fd_events; fe; ) {
		struct fd_event *next = fe->next;
		if (fe->flags & EVENT_FD_READ) {
			FD_SET(fe->fd, &r_fds);
		}
		if (fe->flags & EVENT_FD_WRITE) {
			FD_SET(fe->fd, &w_fds);
		}
		fe = next;
	}

	selrtn = select(ev->maxfd+1, &r_fds, &w_fds, NULL, tvalp);
		
	if (selrtn == -1 && errno == EBADF) {
		/* the socket is dead! this should never
		   happen as the socket should have first been
		   made readable and that should have removed
		   the event, so this must be a bug. This is a
		   fatal error. */
		DEBUG(0,("ERROR: EBADF on event_loop_once\n"));
		ev->exit_code = EBADF;
		return -1;
	}

	if (selrtn == 0 && tvalp) {
		event_loop_timer(ev);
		return 0;
	}

	if (selrtn > 0) {
		/* at least one file descriptor is ready - check
		   which ones and call the handler, being careful to allow
		   the handler to remove itself when called */
		for (fe=ev->fd_events; fe; fe=fe->next) {
			uint16_t flags = 0;
			if (FD_ISSET(fe->fd, &r_fds)) flags |= EVENT_FD_READ;
			if (FD_ISSET(fe->fd, &w_fds)) flags |= EVENT_FD_WRITE;
			if (flags) {
				fe->handler(ev, fe, flags, fe->private);
				if (destruction_count != ev->destruction_count) {
					break;
				}
			}
		}
	}

	return 0;
}		

/*
  do a single event loop using the events defined in ev 
*/
int event_loop_once(struct event_context *ev)
{
	struct timeval tval, *tvalp;

	tvalp = NULL;
		
	/* work out the right timeout for all timed events */
	if (ev->timed_events) {
		struct timeval t = timeval_current();
		tval = timeval_diff(&ev->timed_events->next_event, &t);
		tvalp = &tval;
		if (timeval_is_zero(tvalp)) {
			event_loop_timer(ev);
			return 0;
		}
	}

#if WITH_EPOLL
	if (ev->epoll_fd != -1) {
		if (event_loop_epoll(ev, tvalp) == 0) {
			return 0;
		}
	}
#endif

	return event_loop_select(ev, tvalp);
}

/*
  go into an event loop using the events defined in ev this function
  will return with the specified code if one of the handlers calls
  event_loop_exit()

  also return (with code 0) if all fd events are removed
*/
int event_loop_wait(struct event_context *ev)
{
	ev->exit_code = 0;
	ev->maxfd = EVENT_INVALID_MAXFD;

	while (ev->fd_events && ev->exit_code == 0) {
		if (event_loop_once(ev) != 0) {
			break;
		}
	}

	return ev->exit_code;
}
