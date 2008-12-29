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

#include <sys/time.h>
#include <time.h>
#include "replace.h"
#include "system/filesys.h"
#include "system/select.h"
#include "tevent.h"
#include "tevent_internal.h"
#include "tevent_util.h"

/**
  compare two timeval structures. 
  Return -1 if tv1 < tv2
  Return 0 if tv1 == tv2
  Return 1 if tv1 > tv2
*/
static int ev_timeval_compare(const struct timeval *tv1, const struct timeval *tv2)
{
	if (tv1->tv_sec  > tv2->tv_sec)  return 1;
	if (tv1->tv_sec  < tv2->tv_sec)  return -1;
	if (tv1->tv_usec > tv2->tv_usec) return 1;
	if (tv1->tv_usec < tv2->tv_usec) return -1;
	return 0;
}

/**
  return a zero timeval
*/
static struct timeval ev_timeval_zero(void)
{
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	return tv;
}

/**
  return a timeval for the current time
*/
static struct timeval ev_timeval_current(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv;
}

/**
  return a timeval struct with the given elements
*/
static struct timeval ev_timeval_set(uint32_t secs, uint32_t usecs)
{
	struct timeval tv;
	tv.tv_sec = secs;
	tv.tv_usec = usecs;
	return tv;
}

/**
  return the difference between two timevals as a timeval
  if tv1 comes after tv2, then return a zero timeval
  (this is *tv2 - *tv1)
*/
static struct timeval ev_timeval_until(const struct timeval *tv1,
					const struct timeval *tv2)
{
	struct timeval t;
	if (ev_timeval_compare(tv1, tv2) >= 0) {
		return ev_timeval_zero();
	}
	t.tv_sec = tv2->tv_sec - tv1->tv_sec;
	if (tv1->tv_usec > tv2->tv_usec) {
		t.tv_sec--;
		t.tv_usec = 1000000 - (tv1->tv_usec - tv2->tv_usec);
	} else {
		t.tv_usec = tv2->tv_usec - tv1->tv_usec;
	}
	return t;
}

/**
  return true if a timeval is zero
*/
bool ev_timeval_is_zero(const struct timeval *tv)
{
	return tv->tv_sec == 0 && tv->tv_usec == 0;
}

/*
  destroy a timed event
*/
static int common_event_timed_destructor(struct tevent_timer *te)
{
	struct tevent_context *ev = talloc_get_type(te->event_ctx,
						   struct tevent_context);
	DLIST_REMOVE(ev->timer_events, te);
	return 0;
}

static int common_event_timed_deny_destructor(struct tevent_timer *te)
{
	return -1;
}

/*
  add a timed event
  return NULL on failure (memory allocation error)
*/
struct tevent_timer *common_event_add_timed(struct tevent_context *ev, TALLOC_CTX *mem_ctx,
					   struct timeval next_event, 
					   event_timed_handler_t handler, 
					   void *private_data) 
{
	struct tevent_timer *te, *last_te, *cur_te;

	te = talloc(mem_ctx?mem_ctx:ev, struct tevent_timer);
	if (te == NULL) return NULL;

	te->event_ctx		= ev;
	te->next_event		= next_event;
	te->handler		= handler;
	te->private_data	= private_data;
	te->additional_data	= NULL;

	/* keep the list ordered */
	last_te = NULL;
	for (cur_te = ev->timer_events; cur_te; cur_te = cur_te->next) {
		/* if the new event comes before the current one break */
		if (ev_timeval_compare(&te->next_event, &cur_te->next_event) < 0) {
			break;
		}

		last_te = cur_te;
	}

	DLIST_ADD_AFTER(ev->timer_events, te, last_te);

	talloc_set_destructor(te, common_event_timed_destructor);

	return te;
}

/*
  do a single event loop using the events defined in ev

  return the delay untill the next timed event,
  or zero if a timed event was triggered
*/
struct timeval common_event_loop_timer_delay(struct tevent_context *ev)
{
	struct timeval current_time = ev_timeval_zero();
	struct tevent_timer *te = ev->timer_events;

	if (!te) {
		/* have a default tick time of 30 seconds. This guarantees
		   that code that uses its own timeout checking will be
		   able to proceeed eventually */
		return ev_timeval_set(30, 0);
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
	if (!ev_timeval_is_zero(&te->next_event)) {
		struct timeval delay;

		current_time = ev_timeval_current();

		delay = ev_timeval_until(&current_time, &te->next_event);
		if (!ev_timeval_is_zero(&delay)) {
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
	DLIST_REMOVE(ev->timer_events, te);

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

	return ev_timeval_zero();
}

