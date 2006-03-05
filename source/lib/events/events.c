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

  Finally, you call event_loop_wait_once() to block waiting for one of the
  events to occor or event_loop_wait() which will loop
  forever.

*/

#include "includes.h"
#include "lib/events/events.h"
#include "lib/events/events_internal.h"

/*
  create a event_context structure for a specific implemementation.
  This must be the first events call, and all subsequent calls pass
  this event_context as the first element. Event handlers also
  receive this as their first argument.

  This function is for allowing third-party-applications to hook in gluecode
  to their own event loop code, so that they can make async usage of our client libs

  NOTE: use event_context_init() inside of samba!
*/
struct event_context *event_context_init_ops(TALLOC_CTX *mem_ctx, const struct event_ops *ops, void *private_data)
{
	struct event_context *ev;
	int ret;

	ev = talloc_zero(mem_ctx, struct event_context);
	if (!ev) return NULL;

	ev->ops = ops;

	ret = ev->ops->context_init(ev, private_data);
	if (ret != 0) {
		talloc_free(ev);
		return NULL;
	}

	return ev;
}

/*
  create a event_context structure. This must be the first events
  call, and all subsequent calls pass this event_context as the first
  element. Event handlers also receive this as their first argument.
*/
struct event_context *event_context_init(TALLOC_CTX *mem_ctx)
{
	const struct event_ops *ops = event_standard_get_ops();
	return event_context_init_ops(mem_ctx, ops, NULL);
}

/*
  add a fd based event
  return NULL on failure (memory allocation error)
*/
struct fd_event *event_add_fd(struct event_context *ev, TALLOC_CTX *mem_ctx,
			      int fd, uint16_t flags, event_fd_handler_t handler,
			      void *private_data)
{
	return ev->ops->add_fd(ev, mem_ctx, fd, flags, handler, private_data);
}

/*
  return the fd event flags
*/
uint16_t event_get_fd_flags(struct fd_event *fde)
{
	if (!fde) return 0;
	return fde->event_ctx->ops->get_fd_flags(fde);
}

/*
  set the fd event flags
*/
void event_set_fd_flags(struct fd_event *fde, uint16_t flags)
{
	if (!fde) return;
	fde->event_ctx->ops->set_fd_flags(fde, flags);
}

/*
  add a timed event
  return NULL on failure
*/
struct timed_event *event_add_timed(struct event_context *ev, TALLOC_CTX *mem_ctx,
				    struct timeval next_event, 
				    event_timed_handler_t handler, 
				    void *private_data)
{
	return ev->ops->add_timed(ev, mem_ctx, next_event, handler, private_data);
}

/*
  do a single event loop using the events defined in ev 
*/
_PUBLIC_ int event_loop_once(struct event_context *ev)
{
	return ev->ops->loop_once(ev);
}

/*
  return on failure or (with 0) if all fd events are removed
*/
int event_loop_wait(struct event_context *ev)
{
	return ev->ops->loop_wait(ev);
}

/*
  find an event context that is a parent of the given memory context,
  or create a new event context as a child of the given context if
  none is found

  This should be used in preference to event_context_init() in places
  where you would prefer to use the existing event context if possible
  (which is most situations)
*/
struct event_context *event_context_find(TALLOC_CTX *mem_ctx)
{
	struct event_context *ev = talloc_find_parent_bytype(mem_ctx, struct event_context);
	if (ev == NULL) {
		ev = event_context_init(mem_ctx);
	}
	return ev;
}
