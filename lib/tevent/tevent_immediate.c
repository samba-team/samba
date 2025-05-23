/*
   Unix SMB/CIFS implementation.

   common events code for immediate events

   Copyright (C) Stefan Metzmacher 2009

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
#define TEVENT_DEPRECATED 1
#include "tevent.h"
#include "tevent_internal.h"
#include "tevent_util.h"

void tevent_common_immediate_cancel(struct tevent_immediate *im)
{
	const char *create_location = im->create_location;
	bool busy = im->busy;
	uint64_t tag = im->tag;
	struct tevent_context *detach_ev_ctx = NULL;

	if (im->destroyed) {
		tevent_abort(im->event_ctx, "tevent_immediate use after free");
		return;
	}

	if (im->detach_ev_ctx != NULL) {
		detach_ev_ctx = im->detach_ev_ctx;
		im->detach_ev_ctx = NULL;
		tevent_trace_immediate_callback(detach_ev_ctx,
						im,
						TEVENT_EVENT_TRACE_DETACH);
		return;
	}

	if (!im->event_ctx) {
		return;
	}

	if (im->handler_name != NULL) {
		TEVENT_DEBUG(im->event_ctx, TEVENT_DEBUG_TRACE,
			     "Cancel immediate event %p \"%s\"\n",
			     im, im->handler_name);
	}

	/* let the backend free im->additional_data */
	if (im->cancel_fn) {
		im->cancel_fn(im);
	}

	if (busy && im->handler_name == NULL) {
		detach_ev_ctx = im->event_ctx;
	} else {
		tevent_trace_immediate_callback(im->event_ctx,
						im,
						TEVENT_EVENT_TRACE_DETACH);
	}
	DLIST_REMOVE(im->event_ctx->immediate_events, im);

	*im = (struct tevent_immediate) {
		.create_location	= create_location,
		.busy			= busy,
		.tag			= tag,
		.detach_ev_ctx		= detach_ev_ctx,
	};

	if (!busy) {
		talloc_set_destructor(im, NULL);
	}
}

/*
  destroy an immediate event
*/
static int tevent_common_immediate_destructor(struct tevent_immediate *im)
{
	if (im->destroyed) {
		tevent_common_check_double_free(im,
						"tevent_immediate double free");
		goto done;
	}

	tevent_common_immediate_cancel(im);

	im->destroyed = true;

done:
	if (im->busy) {
		return -1;
	}

	return 0;
}

/*
 * schedule an immediate event on
 */
void tevent_common_schedule_immediate(struct tevent_immediate *im,
				      struct tevent_context *ev,
				      tevent_immediate_handler_t handler,
				      void *private_data,
				      const char *handler_name,
				      const char *location)
{
	const char *create_location = im->create_location;
	bool busy = im->busy;
	uint64_t tag = im->tag;
	struct tevent_wrapper_glue *glue = im->wrapper;

	tevent_common_immediate_cancel(im);

	if (!handler) {
		return;
	}

	*im = (struct tevent_immediate) {
		.event_ctx		= ev,
		.wrapper		= glue,
		.handler		= handler,
		.private_data		= private_data,
		.handler_name		= handler_name,
		.create_location	= create_location,
		.schedule_location	= location,
		.busy			= busy,
		.tag			= tag,
	};

	tevent_trace_immediate_callback(im->event_ctx, im, TEVENT_EVENT_TRACE_ATTACH);
	DLIST_ADD_END(ev->immediate_events, im);
	talloc_set_destructor(im, tevent_common_immediate_destructor);

	TEVENT_DEBUG(ev, TEVENT_DEBUG_TRACE,
		     "Schedule immediate event \"%s\": %p\n",
		     handler_name, im);
}

int tevent_common_invoke_immediate_handler(struct tevent_immediate *im,
					   bool *removed)
{
	struct tevent_context *handler_ev = im->event_ctx;
	struct tevent_context *ev = im->event_ctx;
	struct tevent_immediate cur = *im;

	if (removed != NULL) {
		*removed = false;
	}

	TEVENT_DEBUG(ev, TEVENT_DEBUG_TRACE,
		     "Run immediate event \"%s\": %p\n",
		     im->handler_name, im);

	/*
	 * remember the handler and then clear the event
	 * the handler might reschedule the event
	 */

	im->busy = true;
	im->handler_name = NULL;
	tevent_common_immediate_cancel(im);
	if (cur.wrapper != NULL) {
		handler_ev = cur.wrapper->wrap_ev;

		tevent_wrapper_push_use_internal(handler_ev, cur.wrapper);
		cur.wrapper->ops->before_immediate_handler(
					cur.wrapper->wrap_ev,
					cur.wrapper->private_state,
					cur.wrapper->main_ev,
					im,
					cur.handler_name,
					cur.schedule_location);
	}
	tevent_trace_immediate_callback(cur.event_ctx, im, TEVENT_EVENT_TRACE_BEFORE_HANDLER);
	cur.handler(handler_ev, im, cur.private_data);
	if (cur.wrapper != NULL) {
		cur.wrapper->ops->after_immediate_handler(
					cur.wrapper->wrap_ev,
					cur.wrapper->private_state,
					cur.wrapper->main_ev,
					im,
					cur.handler_name,
					cur.schedule_location);
		tevent_wrapper_pop_use_internal(handler_ev, cur.wrapper);
	}
	im->busy = false;

	/* The event was removed in tevent_common_immediate_cancel(). */
	if (im->detach_ev_ctx != NULL) {
		struct tevent_context *detach_ev_ctx = im->detach_ev_ctx;
		im->detach_ev_ctx = NULL;
		tevent_trace_immediate_callback(detach_ev_ctx,
						im,
						TEVENT_EVENT_TRACE_DETACH);
	}

	if (im->destroyed) {
		talloc_set_destructor(im, NULL);
		TALLOC_FREE(im);
		if (removed != NULL) {
			*removed = true;
		}
	}

	return 0;
}

/*
  trigger the first immediate event and return true
  if no event was triggered return false
*/
bool tevent_common_loop_immediate(struct tevent_context *ev)
{
	struct tevent_immediate *im = ev->immediate_events;
	int ret;

	if (!im) {
		return false;
	}

	ret = tevent_common_invoke_immediate_handler(im, NULL);
	if (ret != 0) {
		tevent_abort(ev, "tevent_common_invoke_immediate_handler() failed");
	}

	return true;
}


void tevent_immediate_set_tag(struct tevent_immediate *im, uint64_t tag)
{
	if (im == NULL) {
		return;
	}

	im->tag = tag;
}

uint64_t tevent_immediate_get_tag(const struct tevent_immediate *im)
{
	if (im == NULL) {
		return 0;
	}

	return im->tag;
}
