/* 
   Unix SMB/CIFS implementation.

   common events code for timed events

   Copyright (C) Andrew Tridgell	2003-2006
   Copyright (C) Stefan Metzmacher	2005
   
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

#include "includes.h"
#include "system/filesys.h"
#include "system/select.h"
#include "lib/util/dlinklist.h"
#include "lib/events/events.h"
#include "lib/events/events_internal.h"

/*
  destroy a timed event
*/
static int common_event_timed_destructor(struct timed_event *te)
{
	struct event_context *ev = talloc_get_type(te->event_ctx->additional_data,
							   struct event_context);
	DLIST_REMOVE(ev->timed_events, te);
	return 0;
}

static int common_event_timed_deny_destructor(struct timed_event *te)
{
	return -1;
}

/*
  add a timed event
  return NULL on failure (memory allocation error)
*/
struct timed_event *common_event_add_timed(struct event_context *ev, TALLOC_CTX *mem_ctx,
					   struct timeval next_event, 
					   event_timed_handler_t handler, 
					   void *private_data) 
{
	struct timed_event *te, *last_te, *cur_te;

	te = talloc(mem_ctx?mem_ctx:ev, struct timed_event);
	if (te == NULL) return NULL;

	te->event_ctx		= ev;
	te->next_event		= next_event;
	te->handler		= handler;
	te->private_data	= private_data;
	te->additional_data	= NULL;

	/* keep the list ordered */
	last_te = NULL;
	for (cur_te = ev->timed_events; cur_te; cur_te = cur_te->next) {
		/* if the new event comes before the current one break */
		if (!timeval_is_zero(&cur_te->next_event) &&
		    timeval_compare(&te->next_event,
				    &cur_te->next_event) < 0) {
			break;
		}

		last_te = cur_te;
	}

	DLIST_ADD_AFTER(ev->timed_events, te, last_te);

	talloc_set_destructor(te, common_event_timed_destructor);

	return te;
}

/*
  a timer has gone off - call it
*/
void common_event_loop_timer(struct event_context *ev)
{
	struct timeval t = timeval_current();
	struct timed_event *te = ev->timed_events;

	if (te == NULL) {
		return;
	}

	/* deny the handler to free the event */
	talloc_set_destructor(te, common_event_timed_deny_destructor);

	/* We need to remove the timer from the list before calling the
	 * handler because in a semi-async inner event loop called from the
	 * handler we don't want to come across this event again -- vl */
	DLIST_REMOVE(ev->timed_events, te);

	te->handler(ev, te, t, te->private_data);

	/* The destructor isn't necessary anymore, we've already removed the
	 * event from the list. */
	talloc_set_destructor(te, NULL);

	talloc_free(te);
}

/*
  do a single event loop using the events defined in ev 
*/
struct timeval common_event_loop_delay(struct event_context *ev)
{
	struct timeval tval;

	/* work out the right timeout for all timed events */
	if (ev->timed_events) {
		struct timeval t = timeval_current();
		tval = timeval_until(&t, &ev->timed_events->next_event);
	} else {
		/* have a default tick time of 30 seconds. This guarantees
		   that code that uses its own timeout checking will be
		   able to proceeed eventually */
		tval = timeval_set(30, 0);
	}
	
	return tval;
}

