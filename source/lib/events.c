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

struct timed_event {
	struct timed_event *next, *prev;
	struct event_context *event_ctx;
	struct timeval when;
	const char *event_name;
	void (*handler)(struct event_context *event_ctx,
			struct timed_event *te,
			struct timeval now,
			void *private_data);
	void *private_data;
};

struct fd_event {
	struct fd_event *prev, *next;
	struct event_context *event_ctx;
	int fd;
	uint16_t flags; /* see EVENT_FD_* flags */
	void (*handler)(struct event_context *event_ctx,
			struct fd_event *event,
			uint16 flags,
			void *private_data);
	void *private_data;
};

struct event_context {
	struct timed_event *timed_events;
	struct fd_event *fd_events;
};

static int timed_event_destructor(struct timed_event *te)
{
	DEBUG(10, ("Destroying timed event %lx \"%s\"\n", (unsigned long)te,
		te->event_name));
	if (te->event_ctx != NULL) {
		DLIST_REMOVE(te->event_ctx->timed_events, te);
	}
	return 0;
}

/****************************************************************************
 Add te by time.
****************************************************************************/

static void add_event_by_time(struct timed_event *te)
{
	struct event_context *ctx = te->event_ctx;
	struct timed_event *last_te, *cur_te;

	/* Keep the list ordered by time. We must preserve this. */
	last_te = NULL;
	for (cur_te = ctx->timed_events; cur_te; cur_te = cur_te->next) {
		/* if the new event comes before the current one break */
		if (!timeval_is_zero(&cur_te->when) &&
				timeval_compare(&te->when, &cur_te->when) < 0) {
			break;
		}
		last_te = cur_te;
	}

	DLIST_ADD_AFTER(ctx->timed_events, te, last_te);
}

/****************************************************************************
 Schedule a function for future calling, cancel with TALLOC_FREE().
 It's the responsibility of the handler to call TALLOC_FREE() on the event
 handed to it.
****************************************************************************/

struct timed_event *_event_add_timed(struct event_context *event_ctx,
				TALLOC_CTX *mem_ctx,
				struct timeval when,
				const char *event_name,
				void (*handler)(struct event_context *event_ctx,
						struct timed_event *te,
						struct timeval now,
						void *private_data),
				void *private_data)
{
	struct timed_event *te;

	te = TALLOC_P(mem_ctx, struct timed_event);
	if (te == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	te->event_ctx = event_ctx;
	te->when = when;
	te->event_name = event_name;
	te->handler = handler;
	te->private_data = private_data;

	add_event_by_time(te);

	talloc_set_destructor(te, timed_event_destructor);

	DEBUG(10, ("Added timed event \"%s\": %lx\n", event_name,
			(unsigned long)te));
	return te;
}

static int fd_event_destructor(struct fd_event *fde)
{
	if (fde->event_ctx != NULL) {
		DLIST_REMOVE(fde->event_ctx->fd_events, fde);
	}
	return 0;
}

struct fd_event *event_add_fd(struct event_context *event_ctx,
			      TALLOC_CTX *mem_ctx,
			      int fd, uint16_t flags,
			      void (*handler)(struct event_context *event_ctx,
					      struct fd_event *event,
					      uint16 flags,
					      void *private_data),
			      void *private_data)
{
	struct fd_event *fde;

	if (!(fde = TALLOC_P(mem_ctx, struct fd_event))) {
		return NULL;
	}

	fde->event_ctx = event_ctx;
	fde->fd = fd;
	fde->flags = flags;
	fde->handler = handler;
	fde->private_data = private_data;

	DLIST_ADD(event_ctx->fd_events, fde);

	talloc_set_destructor(fde, fd_event_destructor);
	return fde;
}

void event_fd_set_writeable(struct fd_event *fde)
{
	fde->flags |= EVENT_FD_WRITE;
}

void event_fd_set_not_writeable(struct fd_event *fde)
{
	fde->flags &= ~EVENT_FD_WRITE;
}

void event_fd_set_readable(struct fd_event *fde)
{
	fde->flags |= EVENT_FD_READ;
}

void event_fd_set_not_readable(struct fd_event *fde)
{
	fde->flags &= ~EVENT_FD_READ;
}

/*
 * Return if there's something in the queue
 */

bool event_add_to_select_args(struct event_context *event_ctx,
			      const struct timeval *now,
			      fd_set *read_fds, fd_set *write_fds,
			      struct timeval *timeout, int *maxfd)
{
	struct fd_event *fde;
	struct timeval diff;
	bool ret = False;

	for (fde = event_ctx->fd_events; fde; fde = fde->next) {
		if (fde->flags & EVENT_FD_READ) {
			FD_SET(fde->fd, read_fds);
			ret = True;
		}
		if (fde->flags & EVENT_FD_WRITE) {
			FD_SET(fde->fd, write_fds);
			ret = True;
		}

		if ((fde->flags & (EVENT_FD_READ|EVENT_FD_WRITE))
		    && (fde->fd > *maxfd)) {
			*maxfd = fde->fd;
		}
	}

	if (event_ctx->timed_events == NULL) {
		return ret;
	}

	diff = timeval_until(now, &event_ctx->timed_events->when);
	*timeout = timeval_min(timeout, &diff);

	return True;
}

bool run_events(struct event_context *event_ctx,
		int selrtn, fd_set *read_fds, fd_set *write_fds)
{
	bool fired = False;
	struct fd_event *fde, *next;

	/* Run all events that are pending, not just one (as we
	   did previously. */

	while (event_ctx->timed_events) {
		struct timeval now;
		GetTimeOfDay(&now);

		if (timeval_compare(
			    &now, &event_ctx->timed_events->when) < 0) {
			/* Nothing to do yet */
			DEBUG(11, ("run_events: Nothing to do\n"));
			break;
		}

		DEBUG(10, ("Running event \"%s\" %lx\n",
			   event_ctx->timed_events->event_name,
			   (unsigned long)event_ctx->timed_events));

		event_ctx->timed_events->handler(
			event_ctx,
			event_ctx->timed_events, now,
			event_ctx->timed_events->private_data);

		fired = True;
	}

	if (fired) {
		/*
		 * We might have changed the socket status during the timed
		 * events, return to run select again.
		 */
		return True;
	}

	if (selrtn == 0) {
		/*
		 * No fd ready
		 */
		return fired;
	}

	for (fde = event_ctx->fd_events; fde; fde = next) {
		uint16 flags = 0;

		next = fde->next;
		if (FD_ISSET(fde->fd, read_fds)) flags |= EVENT_FD_READ;
		if (FD_ISSET(fde->fd, write_fds)) flags |= EVENT_FD_WRITE;

		if (flags & fde->flags) {
			fde->handler(event_ctx, fde, flags, fde->private_data);
			fired = True;
		}
	}

	return fired;
}


struct timeval *get_timed_events_timeout(struct event_context *event_ctx,
					 struct timeval *to_ret)
{
	struct timeval now;

	if (event_ctx->timed_events == NULL) {
		return NULL;
	}

	now = timeval_current();
	*to_ret = timeval_until(&now, &event_ctx->timed_events->when);

	DEBUG(10, ("timed_events_timeout: %d/%d\n", (int)to_ret->tv_sec,
		(int)to_ret->tv_usec));

	return to_ret;
}

int event_loop_once(struct event_context *ev)
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

static int event_context_destructor(struct event_context *ev)
{
	while (ev->fd_events != NULL) {
		ev->fd_events->event_ctx = NULL;
		DLIST_REMOVE(ev->fd_events, ev->fd_events);
	}
	while (ev->timed_events != NULL) {
		ev->timed_events->event_ctx = NULL;
		DLIST_REMOVE(ev->timed_events, ev->timed_events);
	}
	return 0;
}

void event_context_reinit(struct event_context *ev)
{
	event_context_destructor(ev);
	return;
}

struct event_context *event_context_init(TALLOC_CTX *mem_ctx)
{
	struct event_context *result;

	result = TALLOC_ZERO_P(mem_ctx, struct event_context);
	if (result == NULL) {
		return NULL;
	}

	talloc_set_destructor(result, event_context_destructor);
	return result;
}

void dump_event_list(struct event_context *event_ctx)
{
	struct timed_event *te;
	struct fd_event *fe;
	struct timeval evt, now;

	if (!event_ctx) {
		return;
	}

	now = timeval_current();

	DEBUG(10,("dump_event_list:\n"));

	for (te = event_ctx->timed_events; te; te = te->next) {

		evt = timeval_until(&now, &te->when);

		DEBUGADD(10,("Timed Event \"%s\" %lx handled in %d seconds (at %s)\n",
			   te->event_name,
			   (unsigned long)te,
			   (int)evt.tv_sec,
			   http_timestring(te->when.tv_sec)));
	}

	for (fe = event_ctx->fd_events; fe; fe = fe->next) {

		DEBUGADD(10,("FD Event %d %lx, flags: 0x%04x\n",
			   fe->fd,
			   (unsigned long)fe,
			   fe->flags));
	}
}
