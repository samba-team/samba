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

static void tevent_common_immediate_cancel(struct tevent_immediate *im)
{
	const char *create_location = im->create_location;
	bool busy = im->busy;

	if (im->destroyed) {
		tevent_abort(im->event_ctx, "tevent_immediate use after free");
		return;
	}

	if (!im->event_ctx) {
		return;
	}

	if (im->handler_name != NULL) {
		tevent_debug(im->event_ctx, TEVENT_DEBUG_TRACE,
			     "Cancel immediate event %p \"%s\"\n",
			     im, im->handler_name);
	}

	/* let the backend free im->additional_data */
	if (im->cancel_fn) {
		im->cancel_fn(im);
	}

	DLIST_REMOVE(im->event_ctx->immediate_events, im);

	*im = (struct tevent_immediate) {
		.create_location	= create_location,
		.busy			= busy,
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
	};

	DLIST_ADD_END(ev->immediate_events, im);
	talloc_set_destructor(im, tevent_common_immediate_destructor);

	tevent_debug(ev, TEVENT_DEBUG_TRACE,
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

	tevent_debug(ev, TEVENT_DEBUG_TRACE,
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

