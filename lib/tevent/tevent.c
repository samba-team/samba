/* 
   Unix SMB/CIFS implementation.
   main select loop and event handling
   Copyright (C) Andrew Tridgell 2003
   
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
  'struct tevent_context' that you use in all subsequent calls.

  After that you can add/remove events that you are interested in
  using event_add_*() and talloc_free()

  Finally, you call tevent_loop_wait_once() to block waiting for one of the
  events to occor or tevent_loop_wait() which will loop
  forever.

*/
#include "replace.h"
#include "tevent.h"
#include "tevent_internal.h"
#include "tevent_util.h"

struct event_ops_list {
	struct event_ops_list *next, *prev;
	const char *name;
	const struct event_ops *ops;
};

/* list of registered event backends */
static struct event_ops_list *event_backends = NULL;
static char *tevent_default_backend = NULL;

/*
  register an events backend
*/
bool event_register_backend(const char *name, const struct event_ops *ops)
{
	struct event_ops_list *e;

	for (e = event_backends; e != NULL; e = e->next) {
		if (0 == strcmp(e->name, name)) {
			/* already registered, skip it */
			return true;
		}
	}

	e = talloc(talloc_autofree_context(), struct event_ops_list);
	if (e == NULL) return false;

	e->name = name;
	e->ops = ops;
	DLIST_ADD(event_backends, e);

	return true;
}

/*
  set the default event backend
 */
void tevent_set_default_backend(const char *backend)
{
	talloc_free(tevent_default_backend);
	tevent_default_backend = talloc_strdup(talloc_autofree_context(),
					       backend);
}

/*
  initialise backends if not already done
*/
static void event_backend_init(void)
{
	events_select_init();
	events_standard_init();
#if HAVE_EVENTS_EPOLL
	events_epoll_init();
#endif
#if HAVE_LINUX_AIO
	events_aio_init();
#endif
}

/*
  list available backends
*/
const char **event_backend_list(TALLOC_CTX *mem_ctx)
{
	const char **list = NULL;
	struct event_ops_list *e;

	event_backend_init();

	for (e=event_backends;e;e=e->next) {
		list = ev_str_list_add(list, e->name);
	}

	talloc_steal(mem_ctx, list);

	return list;
}

/*
  create a event_context structure for a specific implemementation.
  This must be the first events call, and all subsequent calls pass
  this event_context as the first element. Event handlers also
  receive this as their first argument.

  This function is for allowing third-party-applications to hook in gluecode
  to their own event loop code, so that they can make async usage of our client libs

  NOTE: use event_context_init() inside of samba!
*/
static struct tevent_context *event_context_init_ops(TALLOC_CTX *mem_ctx, 
						    const struct event_ops *ops)
{
	struct tevent_context *ev;
	int ret;

	ev = talloc_zero(mem_ctx, struct tevent_context);
	if (!ev) return NULL;

	ev->ops = ops;

	ret = ev->ops->context_init(ev);
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
struct tevent_context *event_context_init_byname(TALLOC_CTX *mem_ctx, const char *name)
{
	struct event_ops_list *e;

	event_backend_init();

	if (name == NULL) {
		name = tevent_default_backend;
	}
	if (name == NULL) {
		name = "standard";
	}

	for (e=event_backends;e;e=e->next) {
		if (strcmp(name, e->name) == 0) {
			return event_context_init_ops(mem_ctx, e->ops);
		}
	}
	return NULL;
}


/*
  create a event_context structure. This must be the first events
  call, and all subsequent calls pass this event_context as the first
  element. Event handlers also receive this as their first argument.
*/
struct tevent_context *event_context_init(TALLOC_CTX *mem_ctx)
{
	return event_context_init_byname(mem_ctx, NULL);
}

/*
  add a fd based event
  return NULL on failure (memory allocation error)

  if flags contains EVENT_FD_AUTOCLOSE then the fd will be closed when
  the returned fd_event context is freed
*/
struct tevent_fd *event_add_fd(struct tevent_context *ev, TALLOC_CTX *mem_ctx,
			      int fd, uint16_t flags, event_fd_handler_t handler,
			      void *private_data)
{
	return ev->ops->add_fd(ev, mem_ctx, fd, flags, handler, private_data);
}

/*
  add a disk aio event
*/
struct aio_event *event_add_aio(struct tevent_context *ev,
				TALLOC_CTX *mem_ctx,
				struct iocb *iocb,
				event_aio_handler_t handler,
				void *private_data)
{
	if (ev->ops->add_aio == NULL) return NULL;
	return ev->ops->add_aio(ev, mem_ctx, iocb, handler, private_data);
}

/*
  return the fd event flags
*/
uint16_t tevent_fd_get_flags(struct tevent_fd *fde)
{
	if (!fde) return 0;
	return fde->event_ctx->ops->get_fd_flags(fde);
}

/*
  set the fd event flags
*/
void tevent_fd_set_flags(struct tevent_fd *fde, uint16_t flags)
{
	if (!fde) return;
	fde->event_ctx->ops->set_fd_flags(fde, flags);
}

/*
  add a timed event
  return NULL on failure
*/
struct tevent_timer *event_add_timed(struct tevent_context *ev, TALLOC_CTX *mem_ctx,
				    struct timeval next_event, 
				    event_timed_handler_t handler, 
				    void *private_data)
{
	return ev->ops->add_timer(ev, mem_ctx, next_event, handler, private_data);
}

/*
  add a signal event

  sa_flags are flags to sigaction(2)

  return NULL on failure
*/
struct signal_event *event_add_signal(struct tevent_context *ev, TALLOC_CTX *mem_ctx,
				      int signum,
				      int sa_flags,
				      event_signal_handler_t handler, 
				      void *private_data)
{
	return ev->ops->add_signal(ev, mem_ctx, signum, sa_flags, handler, private_data);
}

/*
  do a single event loop using the events defined in ev 
*/
int tevent_loop_once(struct tevent_context *ev)
{
	return ev->ops->loop_once(ev);
}

/*
  return on failure or (with 0) if all fd events are removed
*/
int tevent_loop_wait(struct tevent_context *ev)
{
	return ev->ops->loop_wait(ev);
}
