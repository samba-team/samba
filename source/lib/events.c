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

  There are 4 types of event handling that are handled in this module:

  1) a file descriptor becoming readable or writeable. This is mostly
     used for network sockets, but can be used for any type of file
     descriptor. You may only register one handler for each file
     descriptor/io combination or you will get unpredictable results
     (this means that you can have a handler for read events, and a
     separate handler for write events, but not two handlers that are
     both handling read events)

  2) a timed event. You can register an event that happens at a
     specific time.  You can register as many of these as you
     like. When they are called the handler can choose to set the time
     for the next event. If next_event is not set then the event is removed.

  3) an event that happens every time through the select loop. These
     sorts of events should be very fast, as they will occur a
     lot. Mostly used for things like destroying a talloc context or
     checking a signal flag.

  4) an event triggered by a signal. These can be one shot or
     repeated. You can have more than one handler registered for a
     single signal if you want to.

  To setup a set of events you first need to create a event_context
  structure using the function event_context_init(); This returns a
  'struct event_context' that you use in all subsequent calls.

  After that you can add/remove events that you are interested in
  using event_add_*() and event_remove_*().

  Finally, you call event_loop_wait() to block waiting for one of the
  events to occor. In normal operation event_loop_wait() will loop
  forever, unless you call event_loop_exit() from inside one of your
  handler functions.

*/

#include "includes.h"
#include "system/time.h"
#include "system/select.h"

/*
  create a event_context structure. This must be the first events
  call, and all subsequent calls pass this event_context as the first
  element. Event handlers also receive this as their first argument.
*/
struct event_context *event_context_init(TALLOC_CTX *mem_ctx)
{
	struct event_context *ev;

	ev = talloc_p(mem_ctx, struct event_context);
	if (!ev) return NULL;

	/* start off with no events */
	ZERO_STRUCTP(ev);

	ev->events = talloc(ev, 0);

	return ev;
}

/*
  destroy an events context, also destroying any remaining events
*/
void event_context_destroy(struct event_context *ev)
{
	talloc_free(ev);
}


/*
  recalculate the maxfd
*/
static void calc_maxfd(struct event_context *ev)
{
	struct fd_event *e;
	ev->maxfd = 0;
	for (e=ev->fd_events; e; e=e->next) {
		if (e->ref_count && 
		    e->fd > ev->maxfd) {
			ev->maxfd = e->fd;
		}
	}
}

/*
  move the event structures from ev2 into ev, upping the reference
  count on ev. The event context ev2 is then destroyed.

  this is used by modules that need to call on the events of a lower module
*/
struct event_context *event_context_merge(struct event_context *ev, struct event_context *ev2)
{
	DLIST_CONCATENATE(ev->fd_events, ev2->fd_events, struct fd_event *);
	DLIST_CONCATENATE(ev->timed_events, ev2->timed_events, struct timed_event *);
	DLIST_CONCATENATE(ev->loop_events, ev2->loop_events, struct loop_event *);

	ev2->fd_events = NULL;
	ev2->timed_events = NULL;
	ev2->loop_events = NULL;

	talloc_steal(ev->events, ev2->events);

	event_context_destroy(ev2);

	calc_maxfd(ev);

	return ev;
}


/*
  add a fd based event
  return NULL on failure (memory allocation error)
*/
struct fd_event *event_add_fd(struct event_context *ev, struct fd_event *e) 
{
	e = talloc_memdup(ev->events, e, sizeof(*e));
	if (!e) return NULL;
	DLIST_ADD(ev->fd_events, e);
	e->ref_count = 1;
	if (e->fd > ev->maxfd) {
		ev->maxfd = e->fd;
	}
	return e;
}


/* to mark the ev->maxfd invalid
 * this means we need to recalculate it
 */
#define EVENT_INVALID_MAXFD (-1)

/*
  remove a fd based event
  the event to remove is matched by looking at the handler
  function and the file descriptor
  return False on failure (event not found)
*/
BOOL event_remove_fd(struct event_context *ev, struct fd_event *e1)
{
	struct fd_event *e;
	for (e=ev->fd_events; e; e=e->next) {
		if (e->ref_count &&
		    e->fd == e1->fd && 
		    e->handler == e1->handler) {
			e->ref_count--;
			return True;
		}
	}
	return False;
}

/*
  remove all fd based events that match a specified fd
*/
void event_remove_fd_all(struct event_context *ev, int fd)
{
	struct fd_event *e;
	for (e=ev->fd_events; e; e=e->next) {
		if (e->ref_count && e->fd == fd) {
			e->ref_count--;
		}
	}
}

/*
  remove all fd based events that match a specified handler
*/
void event_remove_fd_all_handler(struct event_context *ev, void *handler)
{
	struct fd_event *e;
	for (e=ev->fd_events; e; e=e->next) {
		if (e->ref_count &&
		    handler == (void *)e->handler) {
			e->ref_count--;
		}
	}
}


/*
  add a timed event
  return NULL on failure (memory allocation error)
*/
struct timed_event *event_add_timed(struct event_context *ev, struct timed_event *e) 
{
	e = talloc_memdup(ev->events, e, sizeof(*e));
	if (!e) return NULL;
	e->ref_count = 1;
	DLIST_ADD(ev->timed_events, e);
	return e;
}

/*
  remove a timed event
  return False on failure (event not found)
*/
BOOL event_remove_timed(struct event_context *ev, struct timed_event *e1) 
{
	struct timed_event *e;
	for (e=ev->timed_events; e; e=e->next) {
		if (e->ref_count && e == e1) {
			e->ref_count--;
			return True;
		}
	}
	return False;
}

/*
  add a loop event
  return NULL on failure (memory allocation error)
*/
struct loop_event *event_add_loop(struct event_context *ev, struct loop_event *e)
{
	e = talloc_memdup(ev->events, e, sizeof(*e));
	if (!e) return NULL;
	e->ref_count = 1;
	DLIST_ADD(ev->loop_events, e);
	return e;
}

/*
  remove a loop event
  the event to remove is matched only on the handler function
  return False on failure (memory allocation error)
*/
BOOL event_remove_loop(struct event_context *ev, struct loop_event *e1) 
{
	struct loop_event *e;
	for (e=ev->loop_events; e; e=e->next) {
		if (e->ref_count &&
		    e->handler == e1->handler) {
			e->ref_count--;
			return True;
		}
	}
	return False;
}


/*
  tell the event loop to exit with the specified code
*/
void event_loop_exit(struct event_context *ev, int code)
{
	ev->exit.exit_now = True;
	ev->exit.code = code;
}

/*
  do a single event loop using the events defined in ev this function
*/
int event_loop_once(struct event_context *ev)
{
	time_t t;
	fd_set r_fds, w_fds;
	struct fd_event *fe;
	struct loop_event *le;
	struct timed_event *te;
	int selrtn;
	struct timeval tval;

	t = time(NULL);

	/* the loop events are called on each loop. Be careful to allow the 
	   event to remove itself */
	for (le=ev->loop_events;le;) {
		struct loop_event *next = le->next;
		if (le->ref_count == 0) {
			DLIST_REMOVE(ev->loop_events, le);
			talloc_free(le);
		} else {
			le->ref_count++;
			le->handler(ev, le, t);
			le->ref_count--;
		}
		le = next;
	}

	ZERO_STRUCT(tval);
	FD_ZERO(&r_fds);
	FD_ZERO(&w_fds);

	/* setup any fd events */
	for (fe=ev->fd_events; fe; ) {
		struct fd_event *next = fe->next;
		if (fe->ref_count == 0) {
			DLIST_REMOVE(ev->fd_events, fe);
			if (ev->maxfd == fe->fd) {
				ev->maxfd = EVENT_INVALID_MAXFD;
			}
			talloc_free(fe);
		} else {
			if (fe->flags & EVENT_FD_READ) {
				FD_SET(fe->fd, &r_fds);
			}
			if (fe->flags & EVENT_FD_WRITE) {
				FD_SET(fe->fd, &w_fds);
			}
		}
		fe = next;
	}

	/* start with a reasonable max timeout */
	tval.tv_sec = 600;
		
	/* work out the right timeout for all timed events */
	for (te=ev->timed_events;te;te=te->next) {
		int timeout = te->next_event - t;
		if (timeout < 0) {
			timeout = 0;
		}
		if (te->ref_count &&
		    timeout < tval.tv_sec) {
			tval.tv_sec = timeout;
		}
	}

	/* only do a select() if there're fd_events
	 * otherwise we would block for a the time in tval,
	 * and if there're no fd_events present anymore we want to
	 * leave the event loop directly
	 */
	if (ev->fd_events) {
		/* we maybe need to recalculate the maxfd */
		if (ev->maxfd == EVENT_INVALID_MAXFD) {
			calc_maxfd(ev);
		}
		
		/* TODO:
		 * we don't use sys_select() as it isn't thread
		 * safe. We need to replace the magic pipe handling in
		 * sys_select() with something in the events
		 * structure - for now just use select() 
		 */
		selrtn = select(ev->maxfd+1, &r_fds, &w_fds, NULL, &tval);
		
		t = time(NULL);
		
		if (selrtn == -1 && errno == EBADF) {
			/* the socket is dead! this should never
			   happen as the socket should have first been
			   made readable and that should have removed
			   the event, so this must be a bug. This is a
			   fatal error. */
			DEBUG(0,("EBADF on event_loop_once - exiting\n"));
			ev->exit.code = EBADF;
			return -1;
		}
		
		if (selrtn > 0) {
			/* at least one file descriptor is ready - check
			   which ones and call the handler, being careful to allow
			   the handler to remove itself when called */
			for (fe=ev->fd_events; fe; fe=fe->next) {
				uint16_t flags = 0;
				if (FD_ISSET(fe->fd, &r_fds)) flags |= EVENT_FD_READ;
				if (FD_ISSET(fe->fd, &w_fds)) flags |= EVENT_FD_WRITE;
				if (fe->ref_count && flags) {
					fe->ref_count++;
					fe->handler(ev, fe, t, flags);
					fe->ref_count--;
				}
			}
		}
	}

	/* call any timed events that are now due */
	for (te=ev->timed_events;te;) {
		struct timed_event *next = te->next;
		if (te->ref_count == 0) {
			DLIST_REMOVE(ev->timed_events, te);
			talloc_free(te);
		} else if (te->next_event <= t) {
			te->ref_count++;
			te->handler(ev, te, t);
			te->ref_count--;
			if (te->next_event <= t) {
				/* the handler didn't set a time for the 
				   next event - remove the event */
				event_remove_timed(ev, te);
			}
		}
		te = next;
	}		
	
	return 0;
}

/*
  go into an event loop using the events defined in ev this function
  will return with the specified code if one of the handlers calls
  event_loop_exit()

  also return (with code 0) if all fd events are removed
*/
int event_loop_wait(struct event_context *ev)
{
	ZERO_STRUCT(ev->exit);
	ev->maxfd = EVENT_INVALID_MAXFD;

	ev->exit.exit_now = False;

	while (ev->fd_events && !ev->exit.exit_now) {
		if (event_loop_once(ev) != 0) {
			break;
		}
	}

	return ev->exit.code;
}
