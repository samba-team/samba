/* 
   Unix SMB/CIFS implementation.

   common events code for timed events

   Copyright (C) Andrew Tridgell	2003-2006
   Copyright (C) Stefan Metzmacher	2005-2009

     ** NOTE! The following LGPL license applies to the tevent
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/time.h"
#define TEVENT_DEPRECATED 1
#include "tevent.h"
#include "tevent_internal.h"
#include "tevent_util.h"

/**
  compare two timeval structures. 
  Return -1 if tv1 < tv2
  Return 0 if tv1 == tv2
  Return 1 if tv1 > tv2
*/
int tevent_timeval_compare(const struct timeval *tv1, const struct timeval *tv2)
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
struct timeval tevent_timeval_zero(void)
{
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	return tv;
}

/**
  return a timeval for the current time
*/
struct timeval tevent_timeval_current(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv;
}

/**
  return a timeval struct with the given elements
*/
struct timeval tevent_timeval_set(uint32_t secs, uint32_t usecs)
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
struct timeval tevent_timeval_until(const struct timeval *tv1,
				    const struct timeval *tv2)
{
	struct timeval t;
	if (tevent_timeval_compare(tv1, tv2) >= 0) {
		return tevent_timeval_zero();
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
bool tevent_timeval_is_zero(const struct timeval *tv)
{
	return tv->tv_sec == 0 && tv->tv_usec == 0;
}

struct timeval tevent_timeval_add(const struct timeval *tv, uint32_t secs,
				  uint32_t usecs)
{
	struct timeval tv2 = *tv;
	tv2.tv_sec += secs;
	tv2.tv_usec += usecs;
	tv2.tv_sec += tv2.tv_usec / 1000000;
	tv2.tv_usec = tv2.tv_usec % 1000000;

	return tv2;
}

/**
  return a timeval in the future with a specified offset
*/
struct timeval tevent_timeval_current_ofs(uint32_t secs, uint32_t usecs)
{
	struct timeval tv = tevent_timeval_current();
	return tevent_timeval_add(&tv, secs, usecs);
}

/*
  destroy a timed event
*/
static int tevent_common_timed_destructor(struct tevent_timer *te)
{
	if (te->destroyed) {
		tevent_common_check_double_free(te, "tevent_timer double free");
		goto done;
	}
	te->destroyed = true;

	if (te->event_ctx == NULL) {
		return 0;
	}

	tevent_debug(te->event_ctx, TEVENT_DEBUG_TRACE,
		     "Destroying timer event %p \"%s\"\n",
		     te, te->handler_name);

	if (te->event_ctx->last_zero_timer == te) {
		te->event_ctx->last_zero_timer = DLIST_PREV(te);
	}
	DLIST_REMOVE(te->event_ctx->timer_events, te);

	te->event_ctx = NULL;
done:
	if (te->busy) {
		return -1;
	}
	te->wrapper = NULL;

	return 0;
}

static void tevent_common_insert_timer(struct tevent_context *ev,
				       struct tevent_timer *te,
				       bool optimize_zero)
{
	struct tevent_timer *prev_te = NULL;

	if (te->destroyed) {
		tevent_abort(ev, "tevent_timer use after free");
		return;
	}

	/* keep the list ordered */
	if (optimize_zero && tevent_timeval_is_zero(&te->next_event)) {
		/*
		 * Some callers use zero tevent_timer
		 * instead of tevent_immediate events.
		 *
		 * As these can happen very often,
		 * we remember the last zero timer
		 * in the list.
		 */
		prev_te = ev->last_zero_timer;
		ev->last_zero_timer = te;
	} else {
		struct tevent_timer *cur_te;

		/*
		 * we traverse the list from the tail
		 * because it's much more likely that
		 * timers are added at the end of the list
		 */
		for (cur_te = DLIST_TAIL(ev->timer_events);
		     cur_te != NULL;
		     cur_te = DLIST_PREV(cur_te))
		{
			int ret;

			/*
			 * if the new event comes before the current
			 * we continue searching
			 */
			ret = tevent_timeval_compare(&te->next_event,
						     &cur_te->next_event);
			if (ret < 0) {
				continue;
			}

			break;
		}

		prev_te = cur_te;
	}

	DLIST_ADD_AFTER(ev->timer_events, te, prev_te);
}

/*
  add a timed event
  return NULL on failure (memory allocation error)
*/
static struct tevent_timer *tevent_common_add_timer_internal(
					struct tevent_context *ev,
					TALLOC_CTX *mem_ctx,
					struct timeval next_event,
					tevent_timer_handler_t handler,
					void *private_data,
					const char *handler_name,
					const char *location,
					bool optimize_zero)
{
	struct tevent_timer *te;

	te = talloc(mem_ctx?mem_ctx:ev, struct tevent_timer);
	if (te == NULL) return NULL;

	*te = (struct tevent_timer) {
		.event_ctx	= ev,
		.next_event	= next_event,
		.handler	= handler,
		.private_data	= private_data,
		.handler_name	= handler_name,
		.location	= location,
	};

	if (ev->timer_events == NULL) {
		ev->last_zero_timer = NULL;
	}

	tevent_common_insert_timer(ev, te, optimize_zero);

	talloc_set_destructor(te, tevent_common_timed_destructor);

	tevent_debug(ev, TEVENT_DEBUG_TRACE,
		     "Added timed event \"%s\": %p\n",
		     handler_name, te);
	return te;
}

struct tevent_timer *tevent_common_add_timer(struct tevent_context *ev,
					     TALLOC_CTX *mem_ctx,
					     struct timeval next_event,
					     tevent_timer_handler_t handler,
					     void *private_data,
					     const char *handler_name,
					     const char *location)
{
	/*
	 * do not use optimization, there are broken Samba
	 * versions which use tevent_common_add_timer()
	 * without using tevent_common_loop_timer_delay(),
	 * it just uses DLIST_REMOVE(ev->timer_events, te)
	 * and would leave ev->last_zero_timer behind.
	 */
	return tevent_common_add_timer_internal(ev, mem_ctx, next_event,
						handler, private_data,
						handler_name, location,
						false);
}

struct tevent_timer *tevent_common_add_timer_v2(struct tevent_context *ev,
						TALLOC_CTX *mem_ctx,
					        struct timeval next_event,
					        tevent_timer_handler_t handler,
					        void *private_data,
					        const char *handler_name,
					        const char *location)
{
	/*
	 * Here we turn on last_zero_timer optimization
	 */
	return tevent_common_add_timer_internal(ev, mem_ctx, next_event,
						handler, private_data,
						handler_name, location,
						true);
}

void tevent_update_timer(struct tevent_timer *te, struct timeval next_event)
{
	struct tevent_context *ev = te->event_ctx;

	if (ev->last_zero_timer == te) {
		te->event_ctx->last_zero_timer = DLIST_PREV(te);
	}
	DLIST_REMOVE(ev->timer_events, te);

	te->next_event = next_event;

	/*
	 * Not doing the zero_timer optimization. This is for new code
	 * that should know about immediates.
	 */
	tevent_common_insert_timer(ev, te, false);
}

int tevent_common_invoke_timer_handler(struct tevent_timer *te,
				       struct timeval current_time,
				       bool *removed)
{
	struct tevent_context *handler_ev = te->event_ctx;

	if (removed != NULL) {
		*removed = false;
	}

	if (te->event_ctx == NULL) {
		return 0;
	}

	/*
	 * We need to remove the timer from the list before calling the
	 * handler because in a semi-async inner event loop called from the
	 * handler we don't want to come across this event again -- vl
	 */
	if (te->event_ctx->last_zero_timer == te) {
		te->event_ctx->last_zero_timer = DLIST_PREV(te);
	}
	DLIST_REMOVE(te->event_ctx->timer_events, te);

	tevent_debug(te->event_ctx, TEVENT_DEBUG_TRACE,
		     "Running timer event %p \"%s\"\n",
		     te, te->handler_name);

	/*
	 * If the timed event was registered for a zero current_time,
	 * then we pass a zero timeval here too! To avoid the
	 * overhead of gettimeofday() calls.
	 *
	 * otherwise we pass the current time
	 */
	te->busy = true;
	if (te->wrapper != NULL) {
		handler_ev = te->wrapper->wrap_ev;

		tevent_wrapper_push_use_internal(handler_ev, te->wrapper);
		te->wrapper->ops->before_timer_handler(
					te->wrapper->wrap_ev,
					te->wrapper->private_state,
					te->wrapper->main_ev,
					te,
					te->next_event,
					current_time,
					te->handler_name,
					te->location);
	}
	te->handler(handler_ev, te, current_time, te->private_data);
	if (te->wrapper != NULL) {
		te->wrapper->ops->after_timer_handler(
					te->wrapper->wrap_ev,
					te->wrapper->private_state,
					te->wrapper->main_ev,
					te,
					te->next_event,
					current_time,
					te->handler_name,
					te->location);
		tevent_wrapper_pop_use_internal(handler_ev, te->wrapper);
	}
	te->busy = false;

	tevent_debug(te->event_ctx, TEVENT_DEBUG_TRACE,
		     "Ending timer event %p \"%s\"\n",
		     te, te->handler_name);

	te->wrapper = NULL;
	te->event_ctx = NULL;
	talloc_set_destructor(te, NULL);
	TALLOC_FREE(te);

	if (removed != NULL) {
		*removed = true;
	}

	return 0;
}
/*
  do a single event loop using the events defined in ev

  return the delay until the next timed event,
  or zero if a timed event was triggered
*/
struct timeval tevent_common_loop_timer_delay(struct tevent_context *ev)
{
	struct timeval current_time = tevent_timeval_zero();
	struct tevent_timer *te = ev->timer_events;
	int ret;

	if (!te) {
		/* have a default tick time of 30 seconds. This guarantees
		   that code that uses its own timeout checking will be
		   able to proceed eventually */
		return tevent_timeval_set(30, 0);
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
	if (!tevent_timeval_is_zero(&te->next_event)) {
		struct timeval delay;

		current_time = tevent_timeval_current();

		delay = tevent_timeval_until(&current_time, &te->next_event);
		if (!tevent_timeval_is_zero(&delay)) {
			return delay;
		}
	}

	/*
	 * ok, we have a timed event that we'll process ...
	 */
	ret = tevent_common_invoke_timer_handler(te, current_time, NULL);
	if (ret != 0) {
		tevent_abort(ev, "tevent_common_invoke_timer_handler() failed");
	}

	return tevent_timeval_zero();
}

