/*
   Unix SMB/CIFS implementation.
   Timed event library.
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Volker Lendecke 2005-2007

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
#include "util_event.h"

struct idle_event {
	struct tevent_timer *te;
	struct timeval interval;
	char *name;
	bool (*handler)(const struct timeval *now, void *private_data);
	void *private_data;
};

static void smbd_idle_event_handler(struct tevent_context *ctx,
				    struct tevent_timer *te,
				    struct timeval now,
				    void *private_data)
{
	struct idle_event *event =
		talloc_get_type_abort(private_data, struct idle_event);

	TALLOC_FREE(event->te);

	DEBUG(10,("smbd_idle_event_handler: %s %p called\n",
		  event->name, event->te));

	if (!event->handler(&now, event->private_data)) {
		DEBUG(10,("smbd_idle_event_handler: %s %p stopped\n",
			  event->name, event->te));
		/* Don't repeat, delete ourselves */
		TALLOC_FREE(event);
		return;
	}

	DEBUG(10,("smbd_idle_event_handler: %s %p rescheduled\n",
		  event->name, event->te));

	event->te = tevent_add_timer(ctx, event,
				     timeval_sum(&now, &event->interval),
				     smbd_idle_event_handler, event);

	/* We can't do much but fail here. */
	SMB_ASSERT(event->te != NULL);
}

struct idle_event *event_add_idle(struct tevent_context *event_ctx,
				  TALLOC_CTX *mem_ctx,
				  struct timeval interval,
				  const char *name,
				  bool (*handler)(const struct timeval *now,
						  void *private_data),
				  void *private_data)
{
	struct idle_event *result;
	struct timeval now = timeval_current();

	result = talloc(mem_ctx, struct idle_event);
	if (result == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	result->interval = interval;
	result->handler = handler;
	result->private_data = private_data;

	if (!(result->name = talloc_asprintf(result, "idle_evt(%s)", name))) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(result);
		return NULL;
	}

	result->te = tevent_add_timer(event_ctx, result,
				      timeval_sum(&now, &interval),
				      smbd_idle_event_handler, result);
	if (result->te == NULL) {
		DEBUG(0, ("event_add_timed failed\n"));
		TALLOC_FREE(result);
		return NULL;
	}

	DEBUG(10,("event_add_idle: %s %p\n", result->name, result->te));
	return result;
}
