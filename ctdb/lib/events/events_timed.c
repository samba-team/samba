/* 
   Unix SMB/CIFS implementation.

   common events code for timed events

   Copyright (C) Andrew Tridgell	2003-2006
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
	struct event_context *ev = talloc_get_type(te->event_ctx,
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
		if (timeval_compare(&te->next_event, &cur_te->next_event) < 0) {
			break;
		}

		last_te = cur_te;
	}

	DLIST_ADD_AFTER(ev->timed_events, te, last_te);

	talloc_set_destructor(te, common_event_timed_destructor);

	return te;
}

/*
  do a single event loop using the events defined in ev

  return the delay untill the next timed event,
  or zero if a timed event was triggered
*/
struct timeval common_event_loop_timer_delay(struct event_context *ev)
{
	struct timeval current_time = timeval_zero();
	struct timed_event *te = ev->timed_events;

	if (!te) {
		/* have a default tick time of 30 seconds. This guarantees
		   that code that uses its own timeout checking will be
		   able to proceeed eventually */
		return timeval_set(30, 0);
	}

	/*
	 * work out the right timeout for the next timed event
	 *
	 * avoid the syscall to gettimeofday() if the timed event should
	 * be triggered directly
	 *
	 * if there's a delay till the next timed event, we're done
	 * with just returning the delay
	 */
	if (!timeval_is_zero(&te->next_event)) {
		struct timeval delay;

		current_time = timeval_current();

		delay = timeval_until(&current_time, &te->next_event);
		if (!timeval_is_zero(&delay)) {
			return delay;
		}
	}

	/*
	 * ok, we have a timed event that we'll process ...
	 */

	/* deny the handler to free the event */
	talloc_set_destructor(te, common_event_timed_deny_destructor);

	/* We need to remove the timer from the list before calling the
	 * handler because in a semi-async inner event loop called from the
	 * handler we don't want to come across this event again -- vl */
	DLIST_REMOVE(ev->timed_events, te);

	/*
	 * If the timed event was registered for a zero current_time,
	 * then we pass a zero timeval here too! To avoid the
	 * overhead of gettimeofday() calls.
	 *
	 * otherwise we pass the current time
	 */
	te->handler(ev, te, current_time, te->private_data);

	/* The destructor isn't necessary anymore, we've already removed the
	 * event from the list. */
	talloc_set_destructor(te, NULL);

	talloc_free(te);

	return timeval_zero();
}

