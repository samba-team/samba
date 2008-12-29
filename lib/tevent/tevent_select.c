/* 
   Unix SMB/CIFS implementation.
   main select loop and event handling
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

/*
  This is SAMBA's default event loop code

*/

#include "replace.h"
#include "system/filesys.h"
#include "system/select.h"
#include "tevent.h"
#include "tevent_util.h"
#include "tevent_internal.h"

struct select_event_context {
	/* a pointer back to the generic event_context */
	struct tevent_context *ev;

	/* list of filedescriptor events */
	struct tevent_fd *fd_events;

	/* list of timed events */
	struct tevent_timer *timed_events;

	/* the maximum file descriptor number in fd_events */
	int maxfd;

	/* information for exiting from the event loop */
	int exit_code;

	/* this is incremented when the loop over events causes something which
	   could change the events yet to be processed */
	uint32_t destruction_count;
};

/*
  create a select_event_context structure.
*/
static int select_event_context_init(struct tevent_context *ev)
{
	struct select_event_context *select_ev;

	select_ev = talloc_zero(ev, struct select_event_context);
	if (!select_ev) return -1;
	select_ev->ev = ev;

	ev->additional_data = select_ev;
	return 0;
}

/*
  recalculate the maxfd
*/
static void calc_maxfd(struct select_event_context *select_ev)
{
	struct tevent_fd *fde;

	select_ev->maxfd = 0;
	for (fde = select_ev->fd_events; fde; fde = fde->next) {
		if (fde->fd > select_ev->maxfd) {
			select_ev->maxfd = fde->fd;
		}
	}
}


/* to mark the ev->maxfd invalid
 * this means we need to recalculate it
 */
#define EVENT_INVALID_MAXFD (-1)

/*
  destroy an fd_event
*/
static int select_event_fd_destructor(struct tevent_fd *fde)
{
	struct tevent_context *ev = fde->event_ctx;
	struct select_event_context *select_ev = talloc_get_type(ev->additional_data,
							   struct select_event_context);

	if (select_ev->maxfd == fde->fd) {
		select_ev->maxfd = EVENT_INVALID_MAXFD;
	}

	DLIST_REMOVE(select_ev->fd_events, fde);
	select_ev->destruction_count++;

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
static struct tevent_fd *select_event_add_fd(struct tevent_context *ev, TALLOC_CTX *mem_ctx,
					 int fd, uint16_t flags,
					 event_fd_handler_t handler,
					 void *private_data)
{
	struct select_event_context *select_ev = talloc_get_type(ev->additional_data,
							   struct select_event_context);
	struct tevent_fd *fde;

	fde = talloc(mem_ctx?mem_ctx:ev, struct tevent_fd);
	if (!fde) return NULL;

	fde->event_ctx		= ev;
	fde->fd			= fd;
	fde->flags		= flags;
	fde->handler		= handler;
	fde->private_data	= private_data;
	fde->additional_flags	= 0;
	fde->additional_data	= NULL;

	DLIST_ADD(select_ev->fd_events, fde);
	if (fde->fd > select_ev->maxfd) {
		select_ev->maxfd = fde->fd;
	}
	talloc_set_destructor(fde, select_event_fd_destructor);

	return fde;
}


/*
  return the fd event flags
*/
static uint16_t select_event_get_fd_flags(struct tevent_fd *fde)
{
	return fde->flags;
}

/*
  set the fd event flags
*/
static void select_event_set_fd_flags(struct tevent_fd *fde, uint16_t flags)
{
	struct tevent_context *ev;
	struct select_event_context *select_ev;

	if (fde->flags == flags) return;

	ev = fde->event_ctx;
	select_ev = talloc_get_type(ev->additional_data, struct select_event_context);

	fde->flags = flags;
}

/*
  event loop handling using select()
*/
static int select_event_loop_select(struct select_event_context *select_ev, struct timeval *tvalp)
{
	fd_set r_fds, w_fds;
	struct tevent_fd *fde;
	int selrtn;
	uint32_t destruction_count = ++select_ev->destruction_count;

	/* we maybe need to recalculate the maxfd */
	if (select_ev->maxfd == EVENT_INVALID_MAXFD) {
		calc_maxfd(select_ev);
	}

	FD_ZERO(&r_fds);
	FD_ZERO(&w_fds);

	/* setup any fd events */
	for (fde = select_ev->fd_events; fde; fde = fde->next) {
		if (fde->flags & EVENT_FD_READ) {
			FD_SET(fde->fd, &r_fds);
		}
		if (fde->flags & EVENT_FD_WRITE) {
			FD_SET(fde->fd, &w_fds);
		}
	}

	if (select_ev->ev->num_signal_handlers && 
	    common_event_check_signal(select_ev->ev)) {
		return 0;
	}

	selrtn = select(select_ev->maxfd+1, &r_fds, &w_fds, NULL, tvalp);

	if (selrtn == -1 && errno == EINTR && 
	    select_ev->ev->num_signal_handlers) {
		common_event_check_signal(select_ev->ev);
		return 0;
	}

	if (selrtn == -1 && errno == EBADF) {
		/* the socket is dead! this should never
		   happen as the socket should have first been
		   made readable and that should have removed
		   the event, so this must be a bug. This is a
		   fatal error. */
		ev_debug(select_ev->ev, EV_DEBUG_FATAL,
			 "ERROR: EBADF on select_event_loop_once\n");
		select_ev->exit_code = EBADF;
		return -1;
	}

	if (selrtn == 0 && tvalp) {
		/* we don't care about a possible delay here */
		common_event_loop_timer_delay(select_ev->ev);
		return 0;
	}

	if (selrtn > 0) {
		/* at least one file descriptor is ready - check
		   which ones and call the handler, being careful to allow
		   the handler to remove itself when called */
		for (fde = select_ev->fd_events; fde; fde = fde->next) {
			uint16_t flags = 0;

			if (FD_ISSET(fde->fd, &r_fds)) flags |= EVENT_FD_READ;
			if (FD_ISSET(fde->fd, &w_fds)) flags |= EVENT_FD_WRITE;
			if (flags) {
				fde->handler(select_ev->ev, fde, flags, fde->private_data);
				if (destruction_count != select_ev->destruction_count) {
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
static int select_event_loop_once(struct tevent_context *ev)
{
	struct select_event_context *select_ev = talloc_get_type(ev->additional_data,
		 					   struct select_event_context);
	struct timeval tval;

	tval = common_event_loop_timer_delay(ev);
	if (ev_timeval_is_zero(&tval)) {
		return 0;
	}

	return select_event_loop_select(select_ev, &tval);
}

/*
  return on failure or (with 0) if all fd events are removed
*/
static int select_event_loop_wait(struct tevent_context *ev)
{
	struct select_event_context *select_ev = talloc_get_type(ev->additional_data,
							   struct select_event_context);
	select_ev->exit_code = 0;

	while (select_ev->fd_events && select_ev->exit_code == 0) {
		if (select_event_loop_once(ev) != 0) {
			break;
		}
	}

	return select_ev->exit_code;
}

static const struct event_ops select_event_ops = {
	.context_init	= select_event_context_init,
	.add_fd		= select_event_add_fd,
	.get_fd_flags	= select_event_get_fd_flags,
	.set_fd_flags	= select_event_set_fd_flags,
	.add_timer	= common_event_add_timed,
	.add_signal	= common_event_add_signal,
	.loop_once	= select_event_loop_once,
	.loop_wait	= select_event_loop_wait,
};

bool events_select_init(void)
{
	return event_register_backend("select", &select_event_ops);
}

