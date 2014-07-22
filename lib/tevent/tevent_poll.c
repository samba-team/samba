/*
   Unix SMB/CIFS implementation.
   main select loop and event handling
   Copyright (C) Andrew Tridgell	2003-2005
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
#include "system/filesys.h"
#include "system/select.h"
#include "tevent.h"
#include "tevent_util.h"
#include "tevent_internal.h"

struct poll_event_context {
	/* a pointer back to the generic event_context */
	struct tevent_context *ev;

	/*
	 * one or more events were deleted or disabled
	 */
	bool deleted;

	/*
	 * These two arrays are maintained together.
	 *
	 * The following is always true:
	 * num_fds <= num_fdes
	 *
	 * new 'fresh' elements are added at the end
	 * of the 'fdes' array and picked up later
	 * to the 'fds' array in poll_event_sync_arrays()
	 * before the poll() syscall.
	 */
	struct pollfd *fds;
	size_t num_fds;
	struct tevent_fd **fdes;
	size_t num_fdes;

	/*
	 * use tevent_common_wakeup(ev) to wake the poll() thread
	 */
	bool use_mt_mode;
};

/*
  create a poll_event_context structure.
*/
static int poll_event_context_init(struct tevent_context *ev)
{
	struct poll_event_context *poll_ev;

	/*
	 * we might be called during tevent_re_initialise()
	 * which means we need to free our old additional_data
	 * in order to detach old fd events from the
	 * poll_ev->fresh list
	 */
	TALLOC_FREE(ev->additional_data);

	poll_ev = talloc_zero(ev, struct poll_event_context);
	if (poll_ev == NULL) {
		return -1;
	}
	poll_ev->ev = ev;
	ev->additional_data = poll_ev;
	return 0;
}

static int poll_event_context_init_mt(struct tevent_context *ev)
{
	struct poll_event_context *poll_ev;
	int ret;

	ret = poll_event_context_init(ev);
	if (ret == -1) {
		return ret;
	}

	poll_ev = talloc_get_type_abort(
		ev->additional_data, struct poll_event_context);

	ret = tevent_common_wakeup_init(ev);
	if (ret != 0) {
		return ret;
	}

	poll_ev->use_mt_mode = true;

	return 0;
}

static void poll_event_wake_pollthread(struct poll_event_context *poll_ev)
{
	if (!poll_ev->use_mt_mode) {
		return;
	}
	tevent_common_wakeup(poll_ev->ev);
}

/*
  destroy an fd_event
*/
static int poll_event_fd_destructor(struct tevent_fd *fde)
{
	struct tevent_context *ev = fde->event_ctx;
	struct poll_event_context *poll_ev;
	uint64_t del_idx = fde->additional_flags;

	if (ev == NULL) {
		goto done;
	}

	poll_ev = talloc_get_type_abort(
		ev->additional_data, struct poll_event_context);

	if (del_idx == UINT64_MAX) {
		goto done;
	}

	poll_ev->fdes[del_idx] = NULL;
	poll_ev->deleted = true;
	poll_event_wake_pollthread(poll_ev);
done:
	return tevent_common_fd_destructor(fde);
}

static void poll_event_schedule_immediate(struct tevent_immediate *im,
					  struct tevent_context *ev,
					  tevent_immediate_handler_t handler,
					  void *private_data,
					  const char *handler_name,
					  const char *location)
{
	struct poll_event_context *poll_ev = talloc_get_type_abort(
		ev->additional_data, struct poll_event_context);

	tevent_common_schedule_immediate(im, ev, handler, private_data,
					 handler_name, location);
	poll_event_wake_pollthread(poll_ev);
}

/*
  Private function called by "standard" backend fallback.
  Note this only allows fallback to "poll" backend, not "poll-mt".
*/
_PRIVATE_ bool tevent_poll_event_add_fd_internal(struct tevent_context *ev,
						 struct tevent_fd *fde)
{
	struct poll_event_context *poll_ev = talloc_get_type_abort(
		ev->additional_data, struct poll_event_context);
	uint64_t fde_idx = UINT64_MAX;
	size_t num_fdes;

	fde->additional_flags = UINT64_MAX;
	talloc_set_destructor(fde, poll_event_fd_destructor);

	if (fde->flags == 0) {
		/*
		 * Nothing more to do...
		 */
		return true;
	}

	/*
	 * We need to add it to the end of the 'fdes' array.
	 */
	num_fdes = poll_ev->num_fdes + 1;
	if (num_fdes > talloc_array_length(poll_ev->fdes)) {
		struct tevent_fd **tmp_fdes = NULL;
		size_t array_length;

		array_length = (num_fdes + 15) & ~15; /* round up to 16 */

		tmp_fdes = talloc_realloc(poll_ev,
					  poll_ev->fdes,
					  struct tevent_fd *,
					  array_length);
		if (tmp_fdes == NULL) {
			return false;
		}
		poll_ev->fdes = tmp_fdes;
	}

	fde_idx = poll_ev->num_fdes;
	fde->additional_flags = fde_idx;
	poll_ev->fdes[fde_idx] = fde;
	poll_ev->num_fdes++;

	return true;
}

/*
  add a fd based event
  return NULL on failure (memory allocation error)
*/
static struct tevent_fd *poll_event_add_fd(struct tevent_context *ev,
					   TALLOC_CTX *mem_ctx,
					   int fd, uint16_t flags,
					   tevent_fd_handler_t handler,
					   void *private_data,
					   const char *handler_name,
					   const char *location)
{
	struct poll_event_context *poll_ev = talloc_get_type_abort(
		ev->additional_data, struct poll_event_context);
	struct tevent_fd *fde;
	bool ok;

	if (fd < 0) {
		return NULL;
	}

	fde = tevent_common_add_fd(ev,
				   mem_ctx,
				   fd,
				   flags,
				   handler,
				   private_data,
				   handler_name,
				   location);
	if (fde == NULL) {
		return NULL;
	}

	ok = tevent_poll_event_add_fd_internal(ev, fde);
	if (!ok) {
		TALLOC_FREE(fde);
		return NULL;
	}
	poll_event_wake_pollthread(poll_ev);

	/*
	 * poll_event_loop_poll will take care of the rest in
	 * poll_event_setup_fresh
	 */
	return fde;
}

/*
  set the fd event flags
*/
static void poll_event_set_fd_flags(struct tevent_fd *fde, uint16_t flags)
{
	struct tevent_context *ev = fde->event_ctx;
	struct poll_event_context *poll_ev;
	uint64_t idx = fde->additional_flags;
	uint16_t pollflags;

	if (ev == NULL) {
		return;
	}

	if (fde->flags == flags) {
		return;
	}

	poll_ev = talloc_get_type_abort(
		ev->additional_data, struct poll_event_context);

	fde->flags = flags;

	if (idx == UINT64_MAX) {
		/*
		 * We move it between the fresh and disabled lists.
		 */
		tevent_poll_event_add_fd_internal(ev, fde);
		poll_event_wake_pollthread(poll_ev);
		return;
	}

	if (fde->flags == 0) {
		/*
		 * We need to remove it from the array
		 * and move it to the disabled list.
		 */
		poll_ev->fdes[idx] = NULL;
		poll_ev->deleted = true;
		fde->additional_flags = UINT64_MAX;
		poll_event_wake_pollthread(poll_ev);
		return;
	}

	if (idx >= poll_ev->num_fds) {
		/*
		 * Not yet added to the
		 * poll_ev->fds array.
		 */
		poll_event_wake_pollthread(poll_ev);
		return;
	}

	pollflags = 0;

	if (flags & TEVENT_FD_READ) {
		pollflags |= (POLLIN|POLLHUP);
	}
	if (flags & TEVENT_FD_WRITE) {
		pollflags |= (POLLOUT);
	}
	poll_ev->fds[idx].events = pollflags;

	poll_event_wake_pollthread(poll_ev);
}

static bool poll_event_sync_arrays(struct tevent_context *ev,
				   struct poll_event_context *poll_ev)
{
	size_t i;
	size_t array_length;

	if (poll_ev->deleted) {

		for (i=0; i < poll_ev->num_fds;) {
			struct tevent_fd *fde = poll_ev->fdes[i];
			size_t ci;

			if (fde != NULL) {
				i++;
				continue;
			}

			/*
			 * This fde was talloc_free()'ed. Delete it
			 * from the arrays
			 */
			poll_ev->num_fds -= 1;
			ci = poll_ev->num_fds;
			if (ci > i) {
				poll_ev->fds[i] = poll_ev->fds[ci];
				poll_ev->fdes[i] = poll_ev->fdes[ci];
				if (poll_ev->fdes[i] != NULL) {
					poll_ev->fdes[i]->additional_flags = i;
				}
			}
			poll_ev->fds[ci] = (struct pollfd) { .fd = -1 };
			poll_ev->fdes[ci] = NULL;
		}
		poll_ev->deleted = false;
	}

	if (poll_ev->num_fds == poll_ev->num_fdes) {
		return true;
	}

	/*
	 * Recheck the size of both arrays and make sure
	 * poll_fd->fds array has at least the size of the
	 * in use poll_ev->fdes array.
	 */
	if (poll_ev->num_fdes > talloc_array_length(poll_ev->fds)) {
		struct pollfd *tmp_fds = NULL;

		/*
		 * Make sure both allocated the same length.
		 */
		array_length = talloc_array_length(poll_ev->fdes);

		tmp_fds = talloc_realloc(poll_ev,
					 poll_ev->fds,
					 struct pollfd,
					 array_length);
		if (tmp_fds == NULL) {
			return false;
		}
		poll_ev->fds = tmp_fds;
	}

	/*
	 * Now setup the new elements.
	 */
	for (i = poll_ev->num_fds; i < poll_ev->num_fdes; i++) {
		struct tevent_fd *fde = poll_ev->fdes[i];
		struct pollfd *pfd = &poll_ev->fds[poll_ev->num_fds];

		if (fde == NULL) {
			continue;
		}

		if (i > poll_ev->num_fds) {
			poll_ev->fdes[poll_ev->num_fds] = fde;
			fde->additional_flags = poll_ev->num_fds;
			poll_ev->fdes[i] = NULL;
		}

		pfd->fd = fde->fd;
		pfd->events = 0;
		pfd->revents = 0;

		if (fde->flags & TEVENT_FD_READ) {
			pfd->events |= (POLLIN|POLLHUP);
		}
		if (fde->flags & TEVENT_FD_WRITE) {
			pfd->events |= (POLLOUT);
		}

		poll_ev->num_fds += 1;
	}
	/* Both are in sync again */
	poll_ev->num_fdes = poll_ev->num_fds;

	/*
	 * Check if we should shrink the arrays
	 * But keep at least 16 elements.
	 */

	array_length = (poll_ev->num_fds + 15) & ~15; /* round up to 16 */
	array_length = MAX(array_length, 16);
	if (array_length < talloc_array_length(poll_ev->fdes)) {
		struct tevent_fd **tmp_fdes = NULL;
		struct pollfd *tmp_fds = NULL;

		tmp_fdes = talloc_realloc(poll_ev,
					  poll_ev->fdes,
					  struct tevent_fd *,
					  array_length);
		if (tmp_fdes == NULL) {
			return false;
		}
		poll_ev->fdes = tmp_fdes;

		tmp_fds = talloc_realloc(poll_ev,
					 poll_ev->fds,
					 struct pollfd,
					 array_length);
		if (tmp_fds == NULL) {
			return false;
		}
		poll_ev->fds = tmp_fds;
	}

	return true;
}

/*
  event loop handling using poll()
*/
static int poll_event_loop_poll(struct tevent_context *ev,
				struct timeval *tvalp)
{
	struct poll_event_context *poll_ev = talloc_get_type_abort(
		ev->additional_data, struct poll_event_context);
	int pollrtn;
	int timeout = -1;
	int poll_errno;
	struct tevent_fd *fde = NULL;
	struct tevent_fd *next = NULL;
	unsigned i;
	bool ok;

	if (ev->signal_events && tevent_common_check_signal(ev)) {
		return 0;
	}

	if (tvalp != NULL) {
		timeout = tvalp->tv_sec * 1000;
		timeout += (tvalp->tv_usec + 999) / 1000;
	}

	ok = poll_event_sync_arrays(ev, poll_ev);
	if (!ok) {
		return -1;
	}

	tevent_trace_point_callback(poll_ev->ev, TEVENT_TRACE_BEFORE_WAIT);
	pollrtn = poll(poll_ev->fds, poll_ev->num_fds, timeout);
	poll_errno = errno;
	tevent_trace_point_callback(poll_ev->ev, TEVENT_TRACE_AFTER_WAIT);

	if (pollrtn == -1 && poll_errno == EINTR && ev->signal_events) {
		tevent_common_check_signal(ev);
		return 0;
	}

	if (pollrtn == 0 && tvalp) {
		/* we don't care about a possible delay here */
		tevent_common_loop_timer_delay(ev);
		return 0;
	}

	if (pollrtn <= 0) {
		/*
		 * No fd's ready
		 */
		return 0;
	}

	/* at least one file descriptor is ready - check
	   which ones and call the handler, being careful to allow
	   the handler to remove itself when called */

	for (fde = ev->fd_events; fde; fde = next) {
		uint64_t idx = fde->additional_flags;
		struct pollfd *pfd;
		uint16_t flags = 0;

		next = fde->next;

		if (idx == UINT64_MAX) {
			continue;
		}

		pfd = &poll_ev->fds[idx];

		if (pfd->revents & POLLNVAL) {
			/*
			 * the socket is dead! this should never
			 * happen as the socket should have first been
			 * made readable and that should have removed
			 * the event, so this must be a bug.
			 *
			 * We ignore it here to match the epoll
			 * behavior.
			 */
			tevent_debug(ev, TEVENT_DEBUG_ERROR,
				     "POLLNVAL on fde[%p] fd[%d] - disabling\n",
				     fde, pfd->fd);
			poll_ev->fdes[idx] = NULL;
			poll_ev->deleted = true;
			DLIST_REMOVE(ev->fd_events, fde);
			fde->wrapper = NULL;
			fde->event_ctx = NULL;
			continue;
		}

		if (pfd->revents & (POLLHUP|POLLERR)) {
			/* If we only wait for TEVENT_FD_WRITE, we
			   should not tell the event handler about it,
			   and remove the writable flag, as we only
			   report errors when waiting for read events
			   to match the select behavior. */
			if (!(fde->flags & TEVENT_FD_READ)) {
				TEVENT_FD_NOT_WRITEABLE(fde);
				continue;
			}
			flags |= TEVENT_FD_READ;
		}
		if (pfd->revents & POLLIN) {
			flags |= TEVENT_FD_READ;
		}
		if (pfd->revents & POLLOUT) {
			flags |= TEVENT_FD_WRITE;
		}
		/*
		 * Note that fde->flags could be changed when using
		 * the poll_mt backend together with threads,
		 * that why we need to check pfd->revents and fde->flags
		 */
		flags &= fde->flags;
		if (flags != 0) {
			DLIST_DEMOTE(ev->fd_events, fde);
			return tevent_common_invoke_fd_handler(fde, flags, NULL);
		}
	}

	for (i = 0; i < poll_ev->num_fds; i++) {
		if (poll_ev->fds[i].revents & POLLNVAL) {
			/*
			 * the socket is dead! this should never
			 * happen as the socket should have first been
			 * made readable and that should have removed
			 * the event, so this must be a bug or
			 * a race in the poll_mt usage.
			 */
			fde = poll_ev->fdes[i];
			tevent_debug(ev, TEVENT_DEBUG_WARNING,
				     "POLLNVAL on dangling fd[%d] fde[%p] - disabling\n",
				     poll_ev->fds[i].fd, fde);
			poll_ev->fdes[i] = NULL;
			poll_ev->deleted = true;
			if (fde != NULL) {
				DLIST_REMOVE(ev->fd_events, fde);
				fde->wrapper = NULL;
				fde->event_ctx = NULL;
			}
		}
	}

	return 0;
}

/*
  do a single event loop using the events defined in ev
*/
static int poll_event_loop_once(struct tevent_context *ev,
				const char *location)
{
	struct timeval tval;

	if (ev->signal_events &&
	    tevent_common_check_signal(ev)) {
		return 0;
	}

	if (ev->threaded_contexts != NULL) {
		tevent_common_threaded_activate_immediate(ev);
	}

	if (ev->immediate_events &&
	    tevent_common_loop_immediate(ev)) {
		return 0;
	}

	tval = tevent_common_loop_timer_delay(ev);
	if (tevent_timeval_is_zero(&tval)) {
		return 0;
	}

	return poll_event_loop_poll(ev, &tval);
}

static const struct tevent_ops poll_event_ops = {
	.context_init		= poll_event_context_init,
	.add_fd			= poll_event_add_fd,
	.set_fd_close_fn	= tevent_common_fd_set_close_fn,
	.get_fd_flags		= tevent_common_fd_get_flags,
	.set_fd_flags		= poll_event_set_fd_flags,
	.add_timer		= tevent_common_add_timer_v2,
	.schedule_immediate	= tevent_common_schedule_immediate,
	.add_signal		= tevent_common_add_signal,
	.loop_once		= poll_event_loop_once,
	.loop_wait		= tevent_common_loop_wait,
};

_PRIVATE_ bool tevent_poll_init(void)
{
	return tevent_register_backend("poll", &poll_event_ops);
}

static const struct tevent_ops poll_event_mt_ops = {
	.context_init		= poll_event_context_init_mt,
	.add_fd			= poll_event_add_fd,
	.set_fd_close_fn	= tevent_common_fd_set_close_fn,
	.get_fd_flags		= tevent_common_fd_get_flags,
	.set_fd_flags		= poll_event_set_fd_flags,
	.add_timer		= tevent_common_add_timer_v2,
	.schedule_immediate	= poll_event_schedule_immediate,
	.add_signal		= tevent_common_add_signal,
	.loop_once		= poll_event_loop_once,
	.loop_wait		= tevent_common_loop_wait,
};

_PRIVATE_ bool tevent_poll_mt_init(void)
{
	return tevent_register_backend("poll_mt", &poll_event_mt_ops);
}
