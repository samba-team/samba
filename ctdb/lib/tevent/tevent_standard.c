/* 
   Unix SMB/CIFS implementation.
   main select loop and event handling
   Copyright (C) Stefan Metzmacher      2013
   Copyright (C) Jeremy Allison         2013

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

/*
  This is SAMBA's default event loop code

  - we try to use epoll if configure detected support for it
    otherwise we use poll()
  - if epoll is broken on the system or the kernel doesn't support it
    at runtime we fallback to poll()
*/

#include "replace.h"
#include "tevent.h"
#include "tevent_util.h"
#include "tevent_internal.h"

struct std_event_glue {
	const struct tevent_ops *epoll_ops;
	const struct tevent_ops *poll_ops;
	struct tevent_ops *glue_ops;
	bool fallback_replay;
};

static int std_event_context_init(struct tevent_context *ev);

static const struct tevent_ops std_event_ops = {
	.context_init           = std_event_context_init,
};

/*
  If this function gets called. epoll failed at runtime.
  Move us to using poll instead. If we return false here,
  caller should abort().
*/
static bool std_fallback_to_poll(struct tevent_context *ev, bool replay)
{
	void *glue_ptr = talloc_parent(ev->ops);
	struct std_event_glue *glue =
		talloc_get_type_abort(glue_ptr,
		struct std_event_glue);
	int ret;
	struct tevent_fd *fde;
	struct tevent_fd *fde_next;

	glue->fallback_replay = replay;

	/* First switch all the ops to poll. */
	glue->epoll_ops = NULL;

	/*
	 * Set custom_ops the same as poll.
	 */
	*glue->glue_ops = *glue->poll_ops;
	glue->glue_ops->context_init = std_event_context_init;

	/* Next initialize the poll backend. */
	ret = glue->poll_ops->context_init(ev);
	if (ret != 0) {
		return false;
	}

	/*
	 * Now we have to change all the existing file descriptor
	 * events from the epoll backend to the poll backend.
	 */
	for (fde = ev->fd_events; fde; fde = fde_next) {
		/*
		 * We must remove this fde off the ev->fd_events list.
		 */
		fde_next = fde->next;

		/* Remove from the ev->fd_events list. */
		DLIST_REMOVE(ev->fd_events, fde);

		/* Re-add this event as a poll backend event. */
		tevent_poll_event_add_fd_internal(ev, fde);
	}

	return true;
}

static int std_event_loop_once(struct tevent_context *ev, const char *location)
{
	void *glue_ptr = talloc_parent(ev->ops);
	struct std_event_glue *glue =
		talloc_get_type_abort(glue_ptr,
		struct std_event_glue);
	int ret;

	ret = glue->epoll_ops->loop_once(ev, location);
	if (glue->epoll_ops != NULL) {
		/* No fallback */
		return ret;
	}

	if (!glue->fallback_replay) {
		/*
		 * The problem happened while modifying an event.
		 * An event handler was triggered in this case
		 * and there is no need to call loop_once() again.
		 */
		return ret;
	}

	return glue->poll_ops->loop_once(ev, location);
}

static int std_event_loop_wait(struct tevent_context *ev, const char *location)
{
	void *glue_ptr = talloc_parent(ev->ops);
	struct std_event_glue *glue =
		talloc_get_type_abort(glue_ptr,
		struct std_event_glue);
	int ret;

	ret = glue->epoll_ops->loop_wait(ev, location);
	if (glue->epoll_ops != NULL) {
		/* No fallback */
		return ret;
	}

	return glue->poll_ops->loop_wait(ev, location);
}
/*
  Initialize the epoll backend and allow it to call a
  switch function if epoll fails at runtime.
*/
static int std_event_context_init(struct tevent_context *ev)
{
	struct std_event_glue *glue;
	int ret;

	/*
	 * If this is the first initialization
	 * we need to set up the allocated ops
	 * pointers.
	 */

	if (ev->ops == &std_event_ops) {
		glue = talloc_zero(ev, struct std_event_glue);
		if (glue == NULL) {
			return -1;
		}

		glue->epoll_ops = tevent_find_ops_byname("epoll");

		glue->poll_ops = tevent_find_ops_byname("poll");
		if (glue->poll_ops == NULL) {
			return -1;
		}

		/*
		 * Allocate space for our custom ops.
		 * Allocate as a child of our epoll_ops pointer
		 * so we can easily get to it using talloc_parent.
		 */
		glue->glue_ops = talloc_zero(glue, struct tevent_ops);
		if (glue->glue_ops == NULL) {
			talloc_free(glue);
			return -1;
		}

		ev->ops = glue->glue_ops;
	} else {
		void *glue_ptr = talloc_parent(ev->ops);
		glue = talloc_get_type_abort(glue_ptr, struct std_event_glue);
	}

	if (glue->epoll_ops != NULL) {
		/*
		 * Set custom_ops the same as epoll,
		 * except re-init using std_event_context_init()
		 * and use std_event_loop_once() to add the
		 * ability to fallback to a poll backend on
		 * epoll runtime error.
		 */
		*glue->glue_ops = *glue->epoll_ops;
		glue->glue_ops->context_init = std_event_context_init;
		glue->glue_ops->loop_once = std_event_loop_once;
		glue->glue_ops->loop_wait = std_event_loop_wait;

		ret = glue->epoll_ops->context_init(ev);
		if (ret == -1) {
			goto fallback;
		}
#ifdef HAVE_EPOLL
		if (!tevent_epoll_set_panic_fallback(ev, std_fallback_to_poll)) {
			TALLOC_FREE(ev->additional_data);
			goto fallback;
		}
#endif

		return ret;
	}

fallback:
	glue->epoll_ops = NULL;

	/*
	 * Set custom_ops the same as poll.
	 */
	*glue->glue_ops = *glue->poll_ops;
	glue->glue_ops->context_init = std_event_context_init;

	return glue->poll_ops->context_init(ev);
}

_PRIVATE_ bool tevent_standard_init(void)
{
	return tevent_register_backend("standard", &std_event_ops);
}
