/*
   Unix SMB/CIFS implementation.
   Timed event library.
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Volker Lendecke 2005

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

#include "includes.h"
#include <tevent_internal.h>

struct s3_event_context {
	struct tevent_context *ev;
	struct tevent_fd *fd_events;
};

static int s3_event_timer_destructor(struct tevent_timer *te)
{
	DEBUG(10, ("Destroying timer event %p \"%s\"\n",
		  te, te->handler_name));
	if (te->event_ctx != NULL) {
		DLIST_REMOVE(te->event_ctx->timer_events, te);
	}
	return 0;
}

/****************************************************************************
 Add te by time.
****************************************************************************/

static void add_event_by_time(struct tevent_timer *te)
{
	struct tevent_context *ctx = te->event_ctx;
	struct tevent_timer *last_te, *cur_te;

	/* Keep the list ordered by time. We must preserve this. */
	last_te = NULL;
	for (cur_te = ctx->timer_events; cur_te; cur_te = cur_te->next) {
		/* if the new event comes before the current one break */
		if (!timeval_is_zero(&cur_te->next_event) &&
		    timeval_compare(&te->next_event, &cur_te->next_event) < 0) {
			break;
		}
		last_te = cur_te;
	}

	DLIST_ADD_AFTER(ctx->timer_events, te, last_te);
}

/****************************************************************************
 Schedule a function for future calling, cancel with TALLOC_FREE().
 It's the responsibility of the handler to call TALLOC_FREE() on the event
 handed to it.
****************************************************************************/

static struct tevent_timer *s3_event_add_timer(struct tevent_context *event_ctx,
					       TALLOC_CTX *mem_ctx,
					       struct timeval when,
					       tevent_timer_handler_t handler,
					       void *private_data,
					       const char *handler_name,
					       const char *location)
{
	struct tevent_timer *te;

	te = TALLOC_P(mem_ctx, struct tevent_timer);
	if (te == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	te->event_ctx = event_ctx;
	te->next_event = when;
	te->handler = handler;
	te->private_data = private_data;
	te->handler_name = handler_name;
	te->location = location;
	te->additional_data = NULL;

	add_event_by_time(te);

	talloc_set_destructor(te, s3_event_timer_destructor);

	DEBUG(10, ("Added timed event \"%s\": %p\n", handler_name, te));
	return te;
}

static int s3_event_fd_destructor(struct tevent_fd *fde)
{
	if (fde->event_ctx != NULL) {
		struct s3_event_context *ev3;
		ev3 = talloc_get_type(fde->event_ctx->additional_data,
				      struct s3_event_context);
		DLIST_REMOVE(ev3->fd_events, fde);
	}
	if (fde->close_fn) {
		fde->close_fn(fde->event_ctx, fde, fde->fd, fde->private_data);
		fde->fd = -1;
	}
	return 0;
}

static struct tevent_fd *s3_event_add_fd(struct tevent_context *ev,
					 TALLOC_CTX *mem_ctx,
					 int fd,
					 uint16_t flags,
					 tevent_fd_handler_t handler,
					 void *private_data,
					 const char *handler_name,
					 const char *location)
{
	struct s3_event_context *ev3 = talloc_get_type(ev->additional_data,
						       struct s3_event_context);
	struct tevent_fd *fde;

	if (!(fde = TALLOC_P(mem_ctx, struct tevent_fd))) {
		return NULL;
	}

	fde->event_ctx = ev;
	fde->fd = fd;
	fde->flags = flags;
	fde->handler = handler;
	fde->close_fn = NULL;
	fde->private_data = private_data;
	fde->handler_name = handler_name;
	fde->location = location;

	DLIST_ADD(ev3->fd_events, fde);

	talloc_set_destructor(fde, s3_event_fd_destructor);
	return fde;
}

void event_fd_set_writeable(struct tevent_fd *fde)
{
	TEVENT_FD_WRITEABLE(fde);
}

void event_fd_set_not_writeable(struct tevent_fd *fde)
{
	TEVENT_FD_NOT_WRITEABLE(fde);
}

void event_fd_set_readable(struct tevent_fd *fde)
{
	TEVENT_FD_READABLE(fde);
}

void event_fd_set_not_readable(struct tevent_fd *fde)
{
	TEVENT_FD_NOT_READABLE(fde);
}

/*
 * Return if there's something in the queue
 */

bool event_add_to_select_args(struct tevent_context *ev,
			      const struct timeval *now,
			      fd_set *read_fds, fd_set *write_fds,
			      struct timeval *timeout, int *maxfd)
{
	struct s3_event_context *ev3 = talloc_get_type(ev->additional_data,
						       struct s3_event_context);
	struct tevent_fd *fde;
	struct timeval diff;
	bool ret = false;

	for (fde = ev3->fd_events; fde; fde = fde->next) {
		if (fde->flags & EVENT_FD_READ) {
			FD_SET(fde->fd, read_fds);
			ret = true;
		}
		if (fde->flags & EVENT_FD_WRITE) {
			FD_SET(fde->fd, write_fds);
			ret = true;
		}

		if ((fde->flags & (EVENT_FD_READ|EVENT_FD_WRITE))
		    && (fde->fd > *maxfd)) {
			*maxfd = fde->fd;
		}
	}

	if (ev->timer_events == NULL) {
		return ret;
	}

	diff = timeval_until(now, &ev->timer_events->next_event);
	*timeout = timeval_min(timeout, &diff);

	return true;
}

bool run_events(struct tevent_context *ev,
		int selrtn, fd_set *read_fds, fd_set *write_fds)
{
	struct s3_event_context *ev3 = talloc_get_type(ev->additional_data,
						       struct s3_event_context);
	bool fired = false;
	struct tevent_fd *fde, *next;

	/* Run all events that are pending, not just one (as we
	   did previously. */

	while (ev->timer_events) {
		struct timeval now;
		GetTimeOfDay(&now);

		if (timeval_compare(
			    &now, &ev->timer_events->next_event) < 0) {
			/* Nothing to do yet */
			DEBUG(11, ("run_events: Nothing to do\n"));
			break;
		}

		DEBUG(10, ("Running event \"%s\" %p\n",
			   ev->timer_events->handler_name,
			   ev->timer_events));

		ev->timer_events->handler(
			ev,
			ev->timer_events, now,
			ev->timer_events->private_data);

		fired = true;
	}

	if (fired) {
		/*
		 * We might have changed the socket status during the timed
		 * events, return to run select again.
		 */
		return true;
	}

	if (selrtn == 0) {
		/*
		 * No fd ready
		 */
		return fired;
	}

	for (fde = ev3->fd_events; fde; fde = next) {
		uint16 flags = 0;

		next = fde->next;
		if (FD_ISSET(fde->fd, read_fds)) flags |= EVENT_FD_READ;
		if (FD_ISSET(fde->fd, write_fds)) flags |= EVENT_FD_WRITE;

		if (flags & fde->flags) {
			fde->handler(ev, fde, flags, fde->private_data);
			fired = true;
		}
	}

	return fired;
}


struct timeval *get_timed_events_timeout(struct tevent_context *ev,
					 struct timeval *to_ret)
{
	struct timeval now;

	if (ev->timer_events == NULL) {
		return NULL;
	}

	now = timeval_current();
	*to_ret = timeval_until(&now, &ev->timer_events->next_event);

	DEBUG(10, ("timed_events_timeout: %d/%d\n", (int)to_ret->tv_sec,
		(int)to_ret->tv_usec));

	return to_ret;
}

static int s3_event_loop_once(struct tevent_context *ev)
{
	struct timeval now, to;
	fd_set r_fds, w_fds;
	int maxfd = 0;
	int ret;

	FD_ZERO(&r_fds);
	FD_ZERO(&w_fds);

	to.tv_sec = 9999;	/* Max timeout */
	to.tv_usec = 0;

	GetTimeOfDay(&now);

	if (!event_add_to_select_args(ev, &now, &r_fds, &w_fds, &to, &maxfd)) {
		return -1;
	}

	if (timeval_is_zero(&to)) {
		run_events(ev, 0, NULL, NULL);
		return 0;
	}

	ret = sys_select(maxfd+1, &r_fds, &w_fds, NULL, &to);

	if (ret == -1 && errno != EINTR) {
		return -1;
	}

	run_events(ev, ret, &r_fds, &w_fds);
	return 0;
}

static int s3_event_loop_wait(struct tevent_context *ev)
{
	int ret = 0;

	while (ret == 0) {
		ret = s3_event_loop_once(ev);
	}

	return ret;
}

static int s3_event_context_destructor(struct tevent_context *ev)
{
	struct s3_event_context *ev3 = talloc_get_type(ev->additional_data,
						       struct s3_event_context);
	while (ev3->fd_events != NULL) {
		ev3->fd_events->event_ctx = NULL;
		DLIST_REMOVE(ev3->fd_events, ev3->fd_events);
	}
	while (ev->timer_events != NULL) {
		ev->timer_events->event_ctx = NULL;
		DLIST_REMOVE(ev->timer_events, ev3->ev->timer_events);
	}
	return 0;
}

void event_context_reinit(struct tevent_context *ev)
{
	s3_event_context_destructor(ev);
	return;
}

static int s3_event_context_init(struct tevent_context *ev)
{
	struct s3_event_context *ev3;

	ev3 = talloc_zero(ev, struct s3_event_context);
	if (!ev3) return -1;
	ev3->ev = ev;

	ev->additional_data = ev3;
	talloc_set_destructor(ev, s3_event_context_destructor);
	return 0;
}

void dump_event_list(struct tevent_context *ev)
{
	struct s3_event_context *ev3 = talloc_get_type(ev->additional_data,
						       struct s3_event_context);
	struct tevent_timer *te;
	struct tevent_fd *fe;
	struct timeval evt, now;

	if (!ev) {
		return;
	}

	now = timeval_current();

	DEBUG(10,("dump_event_list:\n"));

	for (te = ev->timer_events; te; te = te->next) {

		evt = timeval_until(&now, &te->next_event);

		DEBUGADD(10,("Timed Event \"%s\" %p handled in %d seconds (at %s)\n",
			   te->handler_name,
			   te,
			   (int)evt.tv_sec,
			   http_timestring(talloc_tos(), te->next_event.tv_sec)));
	}

	for (fe = ev3->fd_events; fe; fe = fe->next) {

		DEBUGADD(10,("FD Event %d %p, flags: 0x%04x\n",
			   fe->fd,
			   fe,
			   fe->flags));
	}
}

static const struct tevent_ops s3_event_ops = {
	.context_init	= s3_event_context_init,
	.add_fd		= s3_event_add_fd,
	.set_fd_close_fn= tevent_common_fd_set_close_fn,
	.get_fd_flags	= tevent_common_fd_get_flags,
	.set_fd_flags	= tevent_common_fd_set_flags,
	.add_timer	= s3_event_add_timer,
	.loop_once	= s3_event_loop_once,
	.loop_wait	= s3_event_loop_wait,
};

static bool s3_tevent_init(void)
{
	static bool initialized;
	if (initialized) {
		return true;
	}
	initialized = tevent_register_backend("s3", &s3_event_ops);
	tevent_set_default_backend("s3");
	return initialized;
}

struct tevent_context *s3_tevent_context_init(TALLOC_CTX *mem_ctx)
{
	s3_tevent_init();
	return tevent_context_init_byname(mem_ctx, "s3");
}
