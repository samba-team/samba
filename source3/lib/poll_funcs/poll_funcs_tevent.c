/*
 * Unix SMB/CIFS implementation.
 * Copyright (C) Volker Lendecke 2013
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "poll_funcs_tevent.h"
#include "tevent.h"
#include "system/select.h"

struct poll_watch {
	struct tevent_fd *fde;
	int fd;
	void (*callback)(struct poll_watch *w, int fd, short events,
			 void *private_data);
	void *private_data;
};

static uint16_t poll_events_to_tevent(short events)
{
	uint16_t ret = 0;

	if (events & POLLIN) {
		ret |= TEVENT_FD_READ;
	}
	if (events & POLLOUT) {
		ret |= TEVENT_FD_WRITE;
	}
	return ret;
}

static short tevent_to_poll_events(uint16_t flags)
{
	short ret = 0;

	if (flags & TEVENT_FD_READ) {
		ret |= POLLIN;
	}
	if (flags & TEVENT_FD_WRITE) {
		ret |= POLLOUT;
	}
	return ret;
}

static void tevent_watch_handler(struct tevent_context *ev,
				 struct tevent_fd *fde, uint16_t flags,
				 void *private_data);

static struct poll_watch *tevent_watch_new(
	const struct poll_funcs *funcs, int fd, short events,
	void (*callback)(struct poll_watch *w, int fd, short events,
			 void *private_data),
	void *private_data)
{
	struct tevent_context *ev = talloc_get_type_abort(
		funcs->private_data, struct tevent_context);
	struct poll_watch *w;

	w = talloc(ev, struct poll_watch);
	if (w == NULL) {
		return NULL;
	}
	w->fde = tevent_add_fd(ev, w, fd, poll_events_to_tevent(events),
			       tevent_watch_handler, w);
	if (w->fde == NULL) {
		TALLOC_FREE(w);
		return NULL;
	}
	w->fd = fd;
	w->callback = callback;
	w->private_data = private_data;
	return w;
}

static void tevent_watch_handler(struct tevent_context *ev,
				 struct tevent_fd *fde, uint16_t flags,
				 void *private_data)
{
	struct poll_watch *w = talloc_get_type_abort(
		private_data, struct poll_watch);

	w->callback(w, w->fd, tevent_to_poll_events(flags),
		    w->private_data);
}

static void tevent_watch_update(struct poll_watch *w, short events)
{
	tevent_fd_set_flags(w->fde, poll_events_to_tevent(events));
}

static short tevent_watch_get_events(struct poll_watch *w)
{
	return tevent_to_poll_events(tevent_fd_get_flags(w->fde));
}

static void tevent_watch_free(struct poll_watch *w)
{
	TALLOC_FREE(w);
}

static struct poll_timeout *tevent_timeout_new(
	const struct poll_funcs *funcs, const struct timeval *tv,
	void (*callback)(struct poll_timeout *t, void *private_data),
	void *private_data)
{
	/* not implemented yet */
	return NULL;
}

static void tevent_timeout_update(struct poll_timeout *t,
				  const struct timespec *ts)
{
	return;
}

static void tevent_timeout_free(struct poll_timeout *t)
{
	return;
}

void poll_funcs_init_tevent(struct poll_funcs *f, struct tevent_context *ev)
{
	f->watch_new = tevent_watch_new;
	f->watch_update = tevent_watch_update;
	f->watch_get_events = tevent_watch_get_events;
	f->watch_free = tevent_watch_free;
	f->timeout_new = tevent_timeout_new;
	f->timeout_update = tevent_timeout_update;
	f->timeout_free = tevent_timeout_free;
	f->private_data = ev;
}
