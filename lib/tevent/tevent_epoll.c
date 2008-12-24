/* 
   Unix SMB/CIFS implementation.

   main select loop and event handling - epoll implementation

   Copyright (C) Andrew Tridgell	2003-2005
   Copyright (C) Stefan Metzmacher	2005
   
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

#include "replace.h"
#include "system/filesys.h"
#include "system/network.h"
#include "tevent.h"
#include "tevent_internal.h"
#include "tevent_util.h"
#include <sys/epoll.h>

struct epoll_event_context {
	/* a pointer back to the generic event_context */
	struct event_context *ev;

	/* list of filedescriptor events */
	struct fd_event *fd_events;

	/* number of registered fd event handlers */
	int num_fd_events;

	/* this is changed by the destructors for the fd event
	   type. It is used to detect event destruction by event
	   handlers, which means the code that is calling the event
	   handler needs to assume that the linked list is no longer
	   valid
	*/
	uint32_t destruction_count;

	/* when using epoll this is the handle from epoll_create */
	int epoll_fd;

	pid_t pid;
};

/*
  called when a epoll call fails, and we should fallback
  to using select
*/
static void epoll_panic(struct epoll_event_context *epoll_ev, const char *reason)
{
	ev_debug(epoll_ev->ev, EV_DEBUG_FATAL,
		 "%s (%s) - calling abort()\n", reason, strerror(errno));
	abort();
}

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
static int epoll_ctx_destructor(struct epoll_event_context *epoll_ev)
{
	close(epoll_ev->epoll_fd);
	epoll_ev->epoll_fd = -1;
	return 0;
}

/*
 init the epoll fd
*/
static int epoll_init_ctx(struct epoll_event_context *epoll_ev)
{
	epoll_ev->epoll_fd = epoll_create(64);
	epoll_ev->pid = getpid();
	talloc_set_destructor(epoll_ev, epoll_ctx_destructor);
	if (epoll_ev->epoll_fd == -1) {
		return -1;
	}
	return 0;
}

static void epoll_add_event(struct epoll_event_context *epoll_ev, struct fd_event *fde);

/*
  reopen the epoll handle when our pid changes
  see http://junkcode.samba.org/ftp/unpacked/junkcode/epoll_fork.c for an 
  demonstration of why this is needed
 */
static void epoll_check_reopen(struct epoll_event_context *epoll_ev)
{
	struct fd_event *fde;

	if (epoll_ev->pid == getpid()) {
		return;
	}

	close(epoll_ev->epoll_fd);
	epoll_ev->epoll_fd = epoll_create(64);
	if (epoll_ev->epoll_fd == -1) {
		ev_debug(epoll_ev->ev, EV_DEBUG_FATAL,
			 "Failed to recreate epoll handle after fork\n");
		return;
	}
	epoll_ev->pid = getpid();
	for (fde=epoll_ev->fd_events;fde;fde=fde->next) {
		epoll_add_event(epoll_ev, fde);
	}
}

#define EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT	(1<<0)
#define EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR	(1<<1)
#define EPOLL_ADDITIONAL_FD_FLAG_GOT_ERROR	(1<<2)

/*
 add the epoll event to the given fd_event
*/
static void epoll_add_event(struct epoll_event_context *epoll_ev, struct fd_event *fde)
{
	struct epoll_event event;

	if (epoll_ev->epoll_fd == -1) return;

	fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR;

	/* if we don't want events yet, don't add an epoll_event */
	if (fde->flags == 0) return;

	ZERO_STRUCT(event);
	event.events = epoll_map_flags(fde->flags);
	event.data.ptr = fde;
	if (epoll_ctl(epoll_ev->epoll_fd, EPOLL_CTL_ADD, fde->fd, &event) != 0) {
		epoll_panic(epoll_ev, "EPOLL_CTL_ADD failed");
	}
	fde->additional_flags |= EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;

	/* only if we want to read we want to tell the event handler about errors */
	if (fde->flags & EVENT_FD_READ) {
		fde->additional_flags |= EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR;
	}
}

/*
 delete the epoll event for given fd_event
*/
static void epoll_del_event(struct epoll_event_context *epoll_ev, struct fd_event *fde)
{
	struct epoll_event event;

	if (epoll_ev->epoll_fd == -1) return;

	fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR;

	/* if there's no epoll_event, we don't need to delete it */
	if (!(fde->additional_flags & EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT)) return;

	ZERO_STRUCT(event);
	event.events = epoll_map_flags(fde->flags);
	event.data.ptr = fde;
	if (epoll_ctl(epoll_ev->epoll_fd, EPOLL_CTL_DEL, fde->fd, &event) != 0) {
		ev_debug(epoll_ev->ev, EV_DEBUG_FATAL,
			 "epoll_del_event failed! probable early close bug (%s)\n",
			 strerror(errno));
	}
	fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;
}

/*
 change the epoll event to the given fd_event
*/
static void epoll_mod_event(struct epoll_event_context *epoll_ev, struct fd_event *fde)
{
	struct epoll_event event;
	if (epoll_ev->epoll_fd == -1) return;

	fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR;

	ZERO_STRUCT(event);
	event.events = epoll_map_flags(fde->flags);
	event.data.ptr = fde;
	if (epoll_ctl(epoll_ev->epoll_fd, EPOLL_CTL_MOD, fde->fd, &event) != 0) {
		epoll_panic(epoll_ev, "EPOLL_CTL_MOD failed");
	}

	/* only if we want to read we want to tell the event handler about errors */
	if (fde->flags & EVENT_FD_READ) {
		fde->additional_flags |= EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR;
	}
}

static void epoll_change_event(struct epoll_event_context *epoll_ev, struct fd_event *fde)
{
	bool got_error = (fde->additional_flags & EPOLL_ADDITIONAL_FD_FLAG_GOT_ERROR);
	bool want_read = (fde->flags & EVENT_FD_READ);
	bool want_write= (fde->flags & EVENT_FD_WRITE);

	if (epoll_ev->epoll_fd == -1) return;

	fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR;

	/* there's already an event */
	if (fde->additional_flags & EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT) {
		if (want_read || (want_write && !got_error)) {
			epoll_mod_event(epoll_ev, fde);
			return;
		}
		/* 
		 * if we want to match the select behavior, we need to remove the epoll_event
		 * when the caller isn't interested in events.
		 *
		 * this is because epoll reports EPOLLERR and EPOLLHUP, even without asking for them
		 */
		epoll_del_event(epoll_ev, fde);
		return;
	}

	/* there's no epoll_event attached to the fde */
	if (want_read || (want_write && !got_error)) {
		epoll_add_event(epoll_ev, fde);
		return;
	}
}

/*
  event loop handling using epoll
*/
static int epoll_event_loop(struct epoll_event_context *epoll_ev, struct timeval *tvalp)
{
	int ret, i;
#define MAXEVENTS 32
	struct epoll_event events[MAXEVENTS];
	uint32_t destruction_count = ++epoll_ev->destruction_count;
	int timeout = -1;

	if (epoll_ev->epoll_fd == -1) return -1;

	if (tvalp) {
		/* it's better to trigger timed events a bit later than to early */
		timeout = ((tvalp->tv_usec+999) / 1000) + (tvalp->tv_sec*1000);
	}

	if (epoll_ev->ev->num_signal_handlers && 
	    common_event_check_signal(epoll_ev->ev)) {
		return 0;
	}

	ret = epoll_wait(epoll_ev->epoll_fd, events, MAXEVENTS, timeout);

	if (ret == -1 && errno == EINTR && epoll_ev->ev->num_signal_handlers) {
		if (common_event_check_signal(epoll_ev->ev)) {
			return 0;
		}
	}

	if (ret == -1 && errno != EINTR) {
		epoll_panic(epoll_ev, "epoll_wait() failed");
		return -1;
	}

	if (ret == 0 && tvalp) {
		/* we don't care about a possible delay here */
		common_event_loop_timer_delay(epoll_ev->ev);
		return 0;
	}

	for (i=0;i<ret;i++) {
		struct fd_event *fde = talloc_get_type(events[i].data.ptr, 
						       struct fd_event);
		uint16_t flags = 0;

		if (fde == NULL) {
			epoll_panic(epoll_ev, "epoll_wait() gave bad data");
			return -1;
		}
		if (events[i].events & (EPOLLHUP|EPOLLERR)) {
			fde->additional_flags |= EPOLL_ADDITIONAL_FD_FLAG_GOT_ERROR;
			/*
			 * if we only wait for EVENT_FD_WRITE, we should not tell the
			 * event handler about it, and remove the epoll_event,
			 * as we only report errors when waiting for read events,
			 * to match the select() behavior
			 */
			if (!(fde->additional_flags & EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR)) {
				epoll_del_event(epoll_ev, fde);
				continue;
			}
			flags |= EVENT_FD_READ;
		}
		if (events[i].events & EPOLLIN) flags |= EVENT_FD_READ;
		if (events[i].events & EPOLLOUT) flags |= EVENT_FD_WRITE;
		if (flags) {
			fde->handler(epoll_ev->ev, fde, flags, fde->private_data);
			if (destruction_count != epoll_ev->destruction_count) {
				break;
			}
		}
	}

	return 0;
}

/*
  create a epoll_event_context structure.
*/
static int epoll_event_context_init(struct event_context *ev)
{
	int ret;
	struct epoll_event_context *epoll_ev;

	epoll_ev = talloc_zero(ev, struct epoll_event_context);
	if (!epoll_ev) return -1;
	epoll_ev->ev = ev;
	epoll_ev->epoll_fd = -1;

	ret = epoll_init_ctx(epoll_ev);
	if (ret != 0) {
		talloc_free(epoll_ev);
		return ret;
	}

	ev->additional_data = epoll_ev;
	return 0;
}

/*
  destroy an fd_event
*/
static int epoll_event_fd_destructor(struct fd_event *fde)
{
	struct event_context *ev = fde->event_ctx;
	struct epoll_event_context *epoll_ev = talloc_get_type(ev->additional_data,
							   struct epoll_event_context);

	epoll_check_reopen(epoll_ev);

	epoll_ev->num_fd_events--;
	epoll_ev->destruction_count++;

	DLIST_REMOVE(epoll_ev->fd_events, fde);
		
	epoll_del_event(epoll_ev, fde);

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
static struct fd_event *epoll_event_add_fd(struct event_context *ev, TALLOC_CTX *mem_ctx,
					 int fd, uint16_t flags,
					 event_fd_handler_t handler,
					 void *private_data)
{
	struct epoll_event_context *epoll_ev = talloc_get_type(ev->additional_data,
							   struct epoll_event_context);
	struct fd_event *fde;

	epoll_check_reopen(epoll_ev);

	fde = talloc(mem_ctx?mem_ctx:ev, struct fd_event);
	if (!fde) return NULL;

	fde->event_ctx		= ev;
	fde->fd			= fd;
	fde->flags		= flags;
	fde->handler		= handler;
	fde->private_data	= private_data;
	fde->additional_flags	= 0;
	fde->additional_data	= NULL;

	epoll_ev->num_fd_events++;
	talloc_set_destructor(fde, epoll_event_fd_destructor);

	DLIST_ADD(epoll_ev->fd_events, fde);
	epoll_add_event(epoll_ev, fde);

	return fde;
}


/*
  return the fd event flags
*/
static uint16_t epoll_event_get_fd_flags(struct fd_event *fde)
{
	return fde->flags;
}

/*
  set the fd event flags
*/
static void epoll_event_set_fd_flags(struct fd_event *fde, uint16_t flags)
{
	struct event_context *ev;
	struct epoll_event_context *epoll_ev;

	if (fde->flags == flags) return;

	ev = fde->event_ctx;
	epoll_ev = talloc_get_type(ev->additional_data, struct epoll_event_context);

	fde->flags = flags;

	epoll_check_reopen(epoll_ev);

	epoll_change_event(epoll_ev, fde);
}

/*
  do a single event loop using the events defined in ev 
*/
static int epoll_event_loop_once(struct event_context *ev)
{
	struct epoll_event_context *epoll_ev = talloc_get_type(ev->additional_data,
		 					   struct epoll_event_context);
	struct timeval tval;

	tval = common_event_loop_timer_delay(ev);
	if (ev_timeval_is_zero(&tval)) {
		return 0;
	}

	epoll_check_reopen(epoll_ev);

	return epoll_event_loop(epoll_ev, &tval);
}

/*
  return on failure or (with 0) if all fd events are removed
*/
static int epoll_event_loop_wait(struct event_context *ev)
{
	struct epoll_event_context *epoll_ev = talloc_get_type(ev->additional_data,
							   struct epoll_event_context);
	while (epoll_ev->num_fd_events) {
		if (epoll_event_loop_once(ev) != 0) {
			break;
		}
	}

	return 0;
}

static const struct event_ops epoll_event_ops = {
	.context_init	= epoll_event_context_init,
	.add_fd		= epoll_event_add_fd,
	.get_fd_flags	= epoll_event_get_fd_flags,
	.set_fd_flags	= epoll_event_set_fd_flags,
	.add_timer	= common_event_add_timed,
	.add_signal	= common_event_add_signal,
	.loop_once	= epoll_event_loop_once,
	.loop_wait	= epoll_event_loop_wait,
};

bool events_epoll_init(void)
{
	return event_register_backend("epoll", &epoll_event_ops);
}
