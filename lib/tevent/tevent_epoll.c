/*
   Unix SMB/CIFS implementation.

   main select loop and event handling - epoll implementation

   Copyright (C) Andrew Tridgell	2003-2005
   Copyright (C) Stefan Metzmacher	2005-2013
   Copyright (C) Jeremy Allison		2013

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
#include "tevent_internal.h"
#include "tevent_util.h"

struct epoll_event_context {
	/* a pointer back to the generic event_context */
	struct tevent_context *ev;

	/* when using epoll this is the handle from epoll_create1(2) */
	int epoll_fd;

	pid_t pid;

	bool panic_force_replay;
	bool *panic_state;
	bool (*panic_fallback)(struct tevent_context *ev, bool replay);
};

#define EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT	(1<<0)
#define EPOLL_ADDITIONAL_FD_FLAG_GOT_ERROR	(1<<1)

#ifdef TEST_PANIC_FALLBACK

static int epoll_create1_panic_fallback(struct epoll_event_context *epoll_ev,
					int flags)
{
	if (epoll_ev->panic_fallback == NULL) {
		return epoll_create1(flags);
	}

	/* 50% of the time, fail... */
	if ((random() % 2) == 0) {
		errno = EINVAL;
		return -1;
	}

	return epoll_create1(flags);
}

static int epoll_ctl_panic_fallback(struct epoll_event_context *epoll_ev,
				    int epfd, int op, int fd,
				    struct epoll_event *event)
{
	if (epoll_ev->panic_fallback == NULL) {
		return epoll_ctl(epfd, op, fd, event);
	}

	/* 50% of the time, fail... */
	if ((random() % 2) == 0) {
		errno = EINVAL;
		return -1;
	}

	return epoll_ctl(epfd, op, fd, event);
}

static int epoll_wait_panic_fallback(struct epoll_event_context *epoll_ev,
				     int epfd,
				     struct epoll_event *events,
				     int maxevents,
				     int timeout)
{
	if (epoll_ev->panic_fallback == NULL) {
		return epoll_wait(epfd, events, maxevents, timeout);
	}

	/* 50% of the time, fail... */
	if ((random() % 2) == 0) {
		errno = EINVAL;
		return -1;
	}

	return epoll_wait(epfd, events, maxevents, timeout);
}

#define epoll_create1(_flags) \
	epoll_create1_panic_fallback(epoll_ev, _flags)
#define epoll_ctl(_epfd, _op, _fd, _event) \
	epoll_ctl_panic_fallback(epoll_ev,_epfd, _op, _fd, _event)
#define epoll_wait(_epfd, _events, _maxevents, _timeout) \
	epoll_wait_panic_fallback(epoll_ev, _epfd, _events, _maxevents, _timeout)
#endif

/*
  called to set the panic fallback function.
*/
_PRIVATE_ void tevent_epoll_set_panic_fallback(struct tevent_context *ev,
				bool (*panic_fallback)(struct tevent_context *ev,
						       bool replay))
{
	struct epoll_event_context *epoll_ev =
		talloc_get_type_abort(ev->additional_data,
		struct epoll_event_context);

	epoll_ev->panic_fallback = panic_fallback;
}

/*
  called when a epoll call fails
*/
static void epoll_panic(struct epoll_event_context *epoll_ev,
			const char *reason, bool replay)
{
	struct tevent_context *ev = epoll_ev->ev;
	bool (*panic_fallback)(struct tevent_context *ev, bool replay);

	panic_fallback = epoll_ev->panic_fallback;

	if (epoll_ev->panic_state != NULL) {
		*epoll_ev->panic_state = true;
	}

	if (epoll_ev->panic_force_replay) {
		replay = true;
	}

	TALLOC_FREE(ev->additional_data);

	if (panic_fallback == NULL) {
		tevent_debug(ev, TEVENT_DEBUG_FATAL,
			"%s (%s) replay[%u] - calling abort()\n",
			reason, strerror(errno), (unsigned)replay);
		abort();
	}

	tevent_debug(ev, TEVENT_DEBUG_ERROR,
		     "%s (%s) replay[%u] - calling panic_fallback\n",
		     reason, strerror(errno), (unsigned)replay);

	if (!panic_fallback(ev, replay)) {
		/* Fallback failed. */
		tevent_debug(ev, TEVENT_DEBUG_FATAL,
			"%s (%s) replay[%u] - calling abort()\n",
			reason, strerror(errno), (unsigned)replay);
		abort();
	}
}

/*
  map from TEVENT_FD_* to EPOLLIN/EPOLLOUT
*/
static uint32_t epoll_map_flags(uint16_t flags)
{
	uint32_t ret = 0;

	/*
	 * we do not need to specify EPOLLERR | EPOLLHUP
	 * they are always reported.
	 */

	if (flags & TEVENT_FD_READ) {
		/*
		 * Note that EPOLLRDHUP always
		 * returns EPOLLIN in addition,
		 * so EPOLLRDHUP is not strictly needed,
		 * but we want to make it explicit.
		 */
		ret |= EPOLLIN | EPOLLRDHUP;
	}
	if (flags & TEVENT_FD_WRITE) {
		ret |= EPOLLOUT;
	}
	if (flags & TEVENT_FD_ERROR) {
		ret |= EPOLLRDHUP;
	}
	return ret;
}

/*
 free the epoll fd
*/
static int epoll_ctx_destructor(struct epoll_event_context *epoll_ev)
{
	close(epoll_ev->epoll_fd);
	epoll_ev->epoll_fd = -1;
	return 0;
}

/*
 init the epoll fd
*/
static int epoll_init_ctx(struct epoll_event_context *epoll_ev)
{
	epoll_ev->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_ev->epoll_fd == -1) {
		tevent_debug(epoll_ev->ev, TEVENT_DEBUG_FATAL,
			     "Failed to create epoll handle (%s).\n",
			     strerror(errno));
		return -1;
	}

	epoll_ev->pid = tevent_cached_getpid();
	talloc_set_destructor(epoll_ev, epoll_ctx_destructor);

	return 0;
}

static void epoll_update_event(struct epoll_event_context *epoll_ev, struct tevent_fd *fde);

/*
  reopen the epoll handle when our pid changes
  see http://junkcode.samba.org/ftp/unpacked/junkcode/epoll_fork.c for an
  demonstration of why this is needed
 */
static void epoll_check_reopen(struct epoll_event_context *epoll_ev)
{
	struct tevent_fd *fde;
	bool *caller_panic_state = epoll_ev->panic_state;
	bool panic_triggered = false;
	pid_t pid = tevent_cached_getpid();

	if (epoll_ev->pid == pid) {
		return;
	}

	close(epoll_ev->epoll_fd);
	epoll_ev->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_ev->epoll_fd == -1) {
		epoll_panic(epoll_ev, "epoll_create() failed", false);
		return;
	}

	epoll_ev->pid = pid;
	epoll_ev->panic_state = &panic_triggered;
	for (fde=epoll_ev->ev->fd_events;fde;fde=fde->next) {
		/*
		 * We leave the mpx mappings alive
		 * so that we'll just re-add events for
		 * the existing primary events in the loop
		 * below.
		 */
		fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;
	}
	for (fde=epoll_ev->ev->fd_events;fde;fde=fde->next) {
		epoll_update_event(epoll_ev, fde);

		if (panic_triggered) {
			if (caller_panic_state != NULL) {
				*caller_panic_state = true;
			}
			return;
		}
	}
	epoll_ev->panic_state = NULL;
}

/*
 epoll cannot add the same file descriptor twice, once
 with read, once with write which is allowed by the
 tevent poll backend. Multiplex the existing fde, flag it
 as such so we can search for the correct fde on
 event triggering.
*/

static int epoll_add_multiplex_fd(struct epoll_event_context *epoll_ev,
				  struct tevent_fd *add_fde)
{
	struct tevent_fd *primary = NULL;
	uint16_t effective_flags;
	struct epoll_event event;
	uint64_t clear_flags = 0;
	uint64_t add_flags = 0;
	int ret;

	/*
	 * Check if there is another fde we can attach to
	 */
	primary = tevent_common_fd_mpx_add(add_fde);
	if (primary == NULL) {
		/* the caller calls epoll_panic() */
		return -1;
	}

	/*
	 * First propagate the HAS_EVENT flag from
	 * the primary to all others (mainly add_fde)
	 */
	if (primary->additional_flags & EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT) {
		add_flags |= EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;
		tevent_common_fd_mpx_additional_flags(primary, 0, add_flags);
	}

	/*
	 * Update the mpx internals and check if
	 * there is an update needed.
	 */
	primary = tevent_common_fd_mpx_update(primary);
	if (primary == NULL) {
		/*
		 * It seems the primary was already
		 * watching (at least) the same flags
		 * as add_fde, so we are done.
		 */
		return 0;
	}

	/*
	 * Before me modify the low level epoll state,
	 * we clear HAS_EVENT on all fdes.
	 */
	clear_flags |= EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;
	tevent_common_fd_mpx_additional_flags(primary, clear_flags, 0);

	effective_flags = tevent_common_fd_mpx_flags(primary);

	/*
	 * Modify the low level epoll state to reflect
	 * the effective flags we want to monitor.
	 */
	ZERO_STRUCT(event);
	event.events = epoll_map_flags(effective_flags);
	event.data.ptr = primary;
	ret = epoll_ctl(epoll_ev->epoll_fd,
			EPOLL_CTL_MOD,
			primary->fd,
			&event);
	if (ret != 0 && errno == EBADF) {
		struct tevent_common_fd_buf pbuf = {};
		TEVENT_DEBUG(epoll_ev->ev, TEVENT_DEBUG_ERROR,
			     "EPOLL_CTL_MOD EBADF for "
			     "%s - disabling\n",
			     tevent_common_fd_str(&pbuf, "primary", primary));
		tevent_common_fd_mpx_disarm_all(primary);
		return 0;
	} else if (ret != 0) {
		struct tevent_common_fd_buf pbuf = {};
		TEVENT_DEBUG(epoll_ev->ev, TEVENT_DEBUG_FATAL,
			     "EPOLL_CTL_MOD for %s - failed - %s",
			     tevent_common_fd_str(&pbuf, "primary", primary),
			     strerror(errno));
		/* the caller calls epoll_panic() */
		return ret;
	}

	/*
	 * Finally re-add HAS_EVENT to all fdes
	 */
	add_flags |= EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;
	tevent_common_fd_mpx_additional_flags(primary, 0, add_flags);

	return 0;
}

/*
 add the epoll event to the given fd_event
*/
static void epoll_add_event(struct epoll_event_context *epoll_ev,
			    struct tevent_fd *_primary)
{
	struct tevent_fd *primary = tevent_common_fd_mpx_primary(_primary);
	uint16_t effective_flags = tevent_common_fd_mpx_flags(primary);
	struct epoll_event event;
	uint64_t clear_flags = 0;
	uint64_t add_flags = 0;
	int ret;

	/*
	 * Before me modify the low level epoll state,
	 * we clear HAS_EVENT on all fdes.
	 */
	clear_flags |= EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;
	tevent_common_fd_mpx_additional_flags(primary, clear_flags, 0);

	/*
	 * Modify the low level epoll state to reflect
	 * the effective flags we want to monitor.
	 *
	 * Most likely we won't trigger the EEXIST
	 * case, so it's much cheaper to try and
	 * react on EEXIST if needed, than to always
	 * scan the list of all existing events.
	 */
	ZERO_STRUCT(event);
	event.events = epoll_map_flags(effective_flags);
	event.data.ptr = primary;
	ret = epoll_ctl(epoll_ev->epoll_fd,
			EPOLL_CTL_ADD,
			primary->fd,
			&event);
	if (ret != 0 && errno == EBADF) {
		struct tevent_common_fd_buf pbuf = {};
		TEVENT_DEBUG(epoll_ev->ev, TEVENT_DEBUG_ERROR,
			     "EPOLL_CTL_ADD EBADF for "
			     "%s - disabling\n",
			     tevent_common_fd_str(&pbuf, "primary", primary));
		tevent_common_fd_mpx_disarm_all(primary);
		return;
	} else if (ret != 0 && errno == EEXIST) {
		ret = epoll_add_multiplex_fd(epoll_ev, primary);
		if (ret != 0) {
			epoll_panic(epoll_ev, "epoll_add_multiplex_fd failed",
				    false);
			return;
		}
		/*
		 * epoll_add_multiplex_fd() already
		 * added EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT
		 */
		return;
	} else if (ret != 0) {
		epoll_panic(epoll_ev, "EPOLL_CTL_ADD failed", false);
		return;
	}

	/*
	 * Finally re-add HAS_EVENT to all fdes
	 */
	add_flags |= EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;
	tevent_common_fd_mpx_additional_flags(primary, 0, add_flags);
}

/*
 delete the epoll event for given fd_event
*/
static void epoll_del_event(struct epoll_event_context *epoll_ev,
			    struct tevent_fd *_primary)
{
	struct tevent_fd *primary = tevent_common_fd_mpx_primary(_primary);
	struct epoll_event event;
	uint64_t clear_flags = 0;
	int ret;

	/*
	 * Before me delete the low level epoll state,
	 * we clear HAS_EVENT on all fdes.
	 */
	clear_flags |= EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;
	tevent_common_fd_mpx_additional_flags(primary, clear_flags, 0);

	/*
	 * Delete the low level epoll state to reflect
	 * the effective flags we want to monitor.
	 */
	ZERO_STRUCT(event);
	ret = epoll_ctl(epoll_ev->epoll_fd,
			EPOLL_CTL_DEL,
			primary->fd,
			&event);
	if (ret != 0 && errno == ENOENT) {
		struct tevent_common_fd_buf pbuf = {};
		/*
		 * This can happen after a epoll_check_reopen
		 * within epoll_event_fd_destructor.
		 */
		TEVENT_DEBUG(epoll_ev->ev, TEVENT_DEBUG_TRACE,
			     "EPOLL_CTL_DEL ignoring ENOENT for %s\n",
			     tevent_common_fd_str(&pbuf, "primary", primary));
		return;
	} else if (ret != 0 && errno == EBADF) {
		struct tevent_common_fd_buf pbuf = {};
		TEVENT_DEBUG(epoll_ev->ev, TEVENT_DEBUG_WARNING,
			     "EPOLL_CTL_DEL EBADF for %s - disabling\n",
			     tevent_common_fd_str(&pbuf, "primary", primary));
		tevent_common_fd_mpx_disarm_all(primary);
		return;
	} else if (ret != 0) {
		struct tevent_common_fd_buf pbuf = {};
		TEVENT_DEBUG(epoll_ev->ev, TEVENT_DEBUG_FATAL,
			     "EPOLL_CTL_DEL for %s - failed - %s",
			     tevent_common_fd_str(&pbuf, "primary", primary),
			     strerror(errno));
		epoll_panic(epoll_ev, "EPOLL_CTL_DEL failed", false);
		return;
	}
}

/*
 change the epoll event to the given fd_event
*/
static void epoll_mod_event(struct epoll_event_context *epoll_ev,
			    struct tevent_fd *_primary)
{
	struct tevent_fd *primary = tevent_common_fd_mpx_primary(_primary);
	uint16_t effective_flags = tevent_common_fd_mpx_flags(primary);
	struct epoll_event event;
	uint64_t clear_flags = 0;
	uint64_t add_flags = 0;
	int ret;

	/*
	 * Before me modify the low level epoll state,
	 * we clear HAS_EVENT on all fdes.
	 */
	clear_flags |= EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;
	tevent_common_fd_mpx_additional_flags(primary, clear_flags, 0);

	/*
	 * Modify the low level epoll state to reflect
	 * the effective flags we want to monitor.
	 */
	ZERO_STRUCT(event);
	event.events = epoll_map_flags(effective_flags);
	event.data.ptr = primary;
	ret = epoll_ctl(epoll_ev->epoll_fd,
			EPOLL_CTL_MOD,
			primary->fd,
			&event);
	if (ret != 0 && errno == EBADF) {
		struct tevent_common_fd_buf pbuf = {};
		TEVENT_DEBUG(epoll_ev->ev, TEVENT_DEBUG_ERROR,
			     "EPOLL_CTL_MOD EBADF for %s - disabling\n",
			     tevent_common_fd_str(&pbuf, "primary", primary));
		tevent_common_fd_mpx_disarm_all(primary);
		return;
	} else if (ret != 0) {
		struct tevent_common_fd_buf pbuf = {};
		TEVENT_DEBUG(epoll_ev->ev, TEVENT_DEBUG_FATAL,
			     "EPOLL_CTL_MOD for %s - failed - %s",
			     tevent_common_fd_str(&pbuf, "primary", primary),
			     strerror(errno));
		epoll_panic(epoll_ev, "EPOLL_CTL_MOD failed", false);
		return;
	}

	/*
	 * Finally re-add HAS_EVENT to all fdes
	 */
	add_flags |= EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;
	tevent_common_fd_mpx_additional_flags(primary, 0, add_flags);
}

static void epoll_update_event(struct epoll_event_context *epoll_ev, struct tevent_fd *fde)
{
	struct tevent_fd *primary = tevent_common_fd_mpx_primary(fde);
	uint64_t _paf = primary->additional_flags;
	bool got_error = (_paf & EPOLL_ADDITIONAL_FD_FLAG_GOT_ERROR);
	uint16_t effective_flags = tevent_common_fd_mpx_flags(primary);
	bool want_read = (effective_flags & TEVENT_FD_READ);
	bool want_write= (effective_flags & TEVENT_FD_WRITE);
	bool want_error= (effective_flags & TEVENT_FD_ERROR);

	/* there's already an event */
	if (primary->additional_flags & EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT) {
		if (want_read || want_error || (want_write && !got_error)) {
			epoll_mod_event(epoll_ev, primary);
			return;
		}
		/*
		 * if we want to match the select behavior, we need to remove the epoll_event
		 * when the caller isn't interested in events.
		 *
		 * this is because epoll reports EPOLLERR and EPOLLHUP, even without asking for them
		 */
		epoll_del_event(epoll_ev, primary);
		return;
	}

	/* there's no epoll_event attached to the fde */
	if (want_read || want_error || (want_write && !got_error)) {
		epoll_add_event(epoll_ev, primary);
		return;
	}
}

/*
  event loop handling using epoll
*/
static int epoll_event_loop(struct epoll_event_context *epoll_ev, struct timeval *tvalp)
{
	int ret, i;
#define MAXEVENTS 1
	struct epoll_event events[MAXEVENTS];
	int timeout = -1;
	int wait_errno;

	if (tvalp) {
		/* it's better to trigger timed events a bit later than too early */
		timeout = ((tvalp->tv_usec+999) / 1000) + (tvalp->tv_sec*1000);
	}

	if (epoll_ev->ev->signal_events &&
	    tevent_common_check_signal(epoll_ev->ev)) {
		return 0;
	}

	tevent_trace_point_callback(epoll_ev->ev, TEVENT_TRACE_BEFORE_WAIT);
	ret = epoll_wait(epoll_ev->epoll_fd, events, MAXEVENTS, timeout);
	wait_errno = errno;
	tevent_trace_point_callback(epoll_ev->ev, TEVENT_TRACE_AFTER_WAIT);

	if (ret == -1 && wait_errno == EINTR && epoll_ev->ev->signal_events) {
		if (tevent_common_check_signal(epoll_ev->ev)) {
			return 0;
		}
	}

	if (ret == -1 && wait_errno != EINTR) {
		epoll_panic(epoll_ev, "epoll_wait() failed", true);
		return -1;
	}

	if (ret == 0 && tvalp) {
		/* we don't care about a possible delay here */
		tevent_common_loop_timer_delay(epoll_ev->ev);
		return 0;
	}

	for (i=0;i<ret;i++) {
		struct tevent_fd *fde = talloc_get_type(events[i].data.ptr,
						       struct tevent_fd);
		struct tevent_fd *selected = NULL;
		uint16_t effective_flags;
		uint16_t flags = 0;
		bool got_error = false;

		if (fde == NULL) {
			epoll_panic(epoll_ev, "epoll_wait() gave bad data", true);
			return -1;
		}
		effective_flags = tevent_common_fd_mpx_flags(fde);
		if (events[i].events & (EPOLLHUP|EPOLLERR|EPOLLRDHUP)) {
			uint64_t add_flags = 0;

			add_flags |= EPOLL_ADDITIONAL_FD_FLAG_GOT_ERROR;
			tevent_common_fd_mpx_additional_flags(fde,
							      0,
							      add_flags);

			if (effective_flags & TEVENT_FD_ERROR) {
				flags |= TEVENT_FD_ERROR;
			}
			if (effective_flags & TEVENT_FD_READ) {
				flags |= TEVENT_FD_READ;
			}
		}
		if (events[i].events & EPOLLIN) {
			if (effective_flags & TEVENT_FD_READ) {
				flags |= TEVENT_FD_READ;
			}
		}
		if (events[i].events & EPOLLOUT) {
			if (effective_flags & TEVENT_FD_WRITE) {
				flags |= TEVENT_FD_WRITE;
			}
		}

		if (fde->additional_flags & EPOLL_ADDITIONAL_FD_FLAG_GOT_ERROR)
		{
			got_error = true;
		}

		selected = tevent_common_fd_mpx_select(fde, flags, got_error);
		if (selected == NULL) {
			if (got_error) {
				/*
				 * if we only wait for TEVENT_FD_WRITE, we
				 * should not tell the event handler about it,
				 * and remove the epoll_event, as we only
				 * report errors when waiting for read events,
				 * to match the select() behavior
				 *
				 * Do the same as the poll backend and
				 * remove the writeable flag.
				 */
				tevent_common_fd_mpx_clear_writeable(fde);
				epoll_update_event(epoll_ev, fde);
			}
			continue;
		}

		/*
		 * make sure we only pass the flags
		 * the handler is expecting.
		 */
		flags &= selected->flags;
		return tevent_common_invoke_fd_handler(selected,
						       flags,
						       NULL);
	}

	return 0;
}

/*
  create a epoll_event_context structure.
*/
static int epoll_event_context_init(struct tevent_context *ev)
{
	int ret;
	struct epoll_event_context *epoll_ev;

	/*
	 * We might be called during tevent_re_initialise()
	 * which means we need to free our old additional_data.
	 */
	TALLOC_FREE(ev->additional_data);

	epoll_ev = talloc_zero(ev, struct epoll_event_context);
	if (!epoll_ev) return -1;
	epoll_ev->ev = ev;
	epoll_ev->epoll_fd = -1;

	ret = epoll_init_ctx(epoll_ev);
	if (ret != 0) {
		talloc_free(epoll_ev);
		return ret;
	}

	ev->additional_data = epoll_ev;
	return 0;
}

/*
  destroy an fd_event
*/
static int epoll_event_fd_destructor(struct tevent_fd *fde)
{
	struct tevent_fd *old_primary = NULL;
	struct tevent_fd *new_primary = NULL;
	struct tevent_fd *update_primary = NULL;
	struct tevent_context *ev = fde->event_ctx;
	struct epoll_event_context *epoll_ev = NULL;
	bool panic_triggered = false;

	if (ev == NULL) {
		tevent_common_fd_mpx_reinit(fde);
		return tevent_common_fd_destructor(fde);
	}

	epoll_ev = talloc_get_type_abort(ev->additional_data,
					 struct epoll_event_context);

	/*
	 * we must remove the event from the list
	 * otherwise a panic fallback handler may
	 * reuse invalid memory
	 */
	DLIST_REMOVE(ev->fd_events, fde);

	epoll_ev->panic_state = &panic_triggered;
	if (epoll_ev->pid != tevent_cached_getpid()) {
		epoll_check_reopen(epoll_ev);
		if (panic_triggered) {
			tevent_common_fd_mpx_reinit(fde);
			return tevent_common_fd_destructor(fde);
		}
	}

	old_primary = tevent_common_fd_mpx_primary(fde);

	if (old_primary == fde) {
		epoll_del_event(epoll_ev, fde);
		if (panic_triggered) {
			tevent_common_fd_mpx_reinit(fde);
			return tevent_common_fd_destructor(fde);
		}
	}

	new_primary = tevent_common_fd_mpx_remove(fde);
	if (new_primary == NULL) {
		epoll_ev->panic_state = NULL;
		return tevent_common_fd_destructor(fde);
	}
	update_primary = tevent_common_fd_mpx_update(new_primary);
	if (update_primary == NULL) {
		epoll_ev->panic_state = NULL;
		return tevent_common_fd_destructor(fde);
	}

	epoll_update_event(epoll_ev, update_primary);
	if (panic_triggered) {
		return tevent_common_fd_destructor(fde);
	}
	epoll_ev->panic_state = NULL;

	return tevent_common_fd_destructor(fde);
}

/*
  add a fd based event
  return NULL on failure (memory allocation error)
*/
static struct tevent_fd *epoll_event_add_fd(struct tevent_context *ev, TALLOC_CTX *mem_ctx,
					    int fd, uint16_t flags,
					    tevent_fd_handler_t handler,
					    void *private_data,
					    const char *handler_name,
					    const char *location)
{
	struct epoll_event_context *epoll_ev =
		talloc_get_type_abort(ev->additional_data,
		struct epoll_event_context);
	struct tevent_fd *fde;
	bool panic_triggered = false;
	pid_t old_pid = epoll_ev->pid;

	fde = tevent_common_add_fd(ev, mem_ctx, fd, flags,
				   handler, private_data,
				   handler_name, location);
	if (!fde) return NULL;

	talloc_set_destructor(fde, epoll_event_fd_destructor);

	/*
	 * prepare for tevent_common_fd_mpx_flags()
	 * in epoll_update_event()
	 */
	tevent_common_fd_mpx_update_flags(fde);

	if (epoll_ev->pid != tevent_cached_getpid()) {
		epoll_ev->panic_state = &panic_triggered;
		epoll_check_reopen(epoll_ev);
		if (panic_triggered) {
			return fde;
		}
		epoll_ev->panic_state = NULL;
	}

	if (epoll_ev->pid == old_pid) {
		epoll_update_event(epoll_ev, fde);
	}

	return fde;
}

/*
  set the fd event flags
*/
static void epoll_event_set_fd_flags(struct tevent_fd *fde, uint16_t flags)
{
	struct tevent_context *ev;
	struct epoll_event_context *epoll_ev;
	bool panic_triggered = false;
	pid_t old_pid;

	if (fde->flags == flags) return;

	ev = fde->event_ctx;
	epoll_ev = talloc_get_type_abort(ev->additional_data,
					 struct epoll_event_context);
	old_pid = epoll_ev->pid;

	fde->flags = flags;
	/*
	 * prepare for tevent_common_fd_mpx_flags()
	 * in epoll_update_event()
	 */
	tevent_common_fd_mpx_update_flags(fde);

	if (epoll_ev->pid != tevent_cached_getpid()) {
		epoll_ev->panic_state = &panic_triggered;
		epoll_check_reopen(epoll_ev);
		if (panic_triggered) {
			return;
		}
		epoll_ev->panic_state = NULL;
	}

	if (epoll_ev->pid == old_pid) {
		epoll_update_event(epoll_ev, fde);
	}
}

/*
  do a single event loop using the events defined in ev
*/
static int epoll_event_loop_once(struct tevent_context *ev, const char *location)
{
	struct epoll_event_context *epoll_ev =
		talloc_get_type_abort(ev->additional_data,
		struct epoll_event_context);
	struct timeval tval;
	bool panic_triggered = false;

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

	if (epoll_ev->pid != tevent_cached_getpid()) {
		epoll_ev->panic_state = &panic_triggered;
		epoll_ev->panic_force_replay = true;
		epoll_check_reopen(epoll_ev);
		if (panic_triggered) {
			errno = EINVAL;
			return -1;
		}
		epoll_ev->panic_force_replay = false;
		epoll_ev->panic_state = NULL;
	}

	return epoll_event_loop(epoll_ev, &tval);
}

static const struct tevent_ops epoll_event_ops = {
	.context_init		= epoll_event_context_init,
	.add_fd			= epoll_event_add_fd,
	.set_fd_close_fn	= tevent_common_fd_set_close_fn,
	.get_fd_flags		= tevent_common_fd_get_flags,
	.set_fd_flags		= epoll_event_set_fd_flags,
	.add_timer		= tevent_common_add_timer_v2,
	.schedule_immediate	= tevent_common_schedule_immediate,
	.add_signal		= tevent_common_add_signal,
	.loop_once		= epoll_event_loop_once,
	.loop_wait		= tevent_common_loop_wait,
};

_PRIVATE_ bool tevent_epoll_init(void)
{
	return tevent_register_backend("epoll", &epoll_event_ops);
}
