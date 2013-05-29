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

	/* when using epoll this is the handle from epoll_create */
	int epoll_fd;

	pid_t pid;

	bool panic_force_replay;
	bool *panic_state;
	bool (*panic_fallback)(struct tevent_context *ev, bool replay);
};

#define EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT	(1<<0)
#define EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR	(1<<1)
#define EPOLL_ADDITIONAL_FD_FLAG_GOT_ERROR	(1<<2)
#define EPOLL_ADDITIONAL_FD_FLAG_HAS_MPX	(1<<3)

#ifdef TEST_PANIC_FALLBACK

static int epoll_create_panic_fallback(struct epoll_event_context *epoll_ev,
				       int size)
{
	if (epoll_ev->panic_fallback == NULL) {
		return epoll_create(size);
	}

	/* 50% of the time, fail... */
	if ((random() % 2) == 0) {
		errno = EINVAL;
		return -1;
	}

	return epoll_create(size);
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

#define epoll_create(_size) \
	epoll_create_panic_fallback(epoll_ev, _size)
#define epoll_ctl(_epfd, _op, _fd, _event) \
	epoll_ctl_panic_fallback(epoll_ev,_epfd, _op, _fd, _event)
#define epoll_wait(_epfd, _events, _maxevents, _timeout) \
	epoll_wait_panic_fallback(epoll_ev, _epfd, _events, _maxevents, _timeout)
#endif

/*
  called to set the panic fallback function.
*/
_PRIVATE_ bool tevent_epoll_set_panic_fallback(struct tevent_context *ev,
				bool (*panic_fallback)(struct tevent_context *ev,
						       bool replay))
{
	struct epoll_event_context *epoll_ev;

	if (ev->additional_data == NULL) {
		return false;
	}

	epoll_ev = talloc_get_type(ev->additional_data,
				struct epoll_event_context);
	if (epoll_ev == NULL) {
		return false;
	}
	epoll_ev->panic_fallback = panic_fallback;
	return true;
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
	if (flags & TEVENT_FD_READ) ret |= (EPOLLIN | EPOLLERR | EPOLLHUP);
	if (flags & TEVENT_FD_WRITE) ret |= (EPOLLOUT | EPOLLERR | EPOLLHUP);
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
	epoll_ev->epoll_fd = epoll_create(64);
	if (epoll_ev->epoll_fd == -1) {
		tevent_debug(epoll_ev->ev, TEVENT_DEBUG_FATAL,
			     "Failed to create epoll handle.\n");
		return -1;
	}

	if (!ev_set_close_on_exec(epoll_ev->epoll_fd)) {
		tevent_debug(epoll_ev->ev, TEVENT_DEBUG_WARNING,
			     "Failed to set close-on-exec, file descriptor may be leaked to children.\n");
	}

	epoll_ev->pid = getpid();
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

	if (epoll_ev->pid == getpid()) {
		return;
	}

	close(epoll_ev->epoll_fd);
	epoll_ev->epoll_fd = epoll_create(64);
	if (epoll_ev->epoll_fd == -1) {
		epoll_panic(epoll_ev, "epoll_create() failed", false);
		return;
	}

	if (!ev_set_close_on_exec(epoll_ev->epoll_fd)) {
		tevent_debug(epoll_ev->ev, TEVENT_DEBUG_WARNING,
			     "Failed to set close-on-exec, file descriptor may be leaked to children.\n");
	}

	epoll_ev->pid = getpid();
	epoll_ev->panic_state = &panic_triggered;
	for (fde=epoll_ev->ev->fd_events;fde;fde=fde->next) {
		fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;
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
 tevent backend. Multiplex the existing fde, flag it
 as such so we can search for the correct fde on
 event triggering.
*/

static int epoll_add_multiplex_fd(struct epoll_event_context *epoll_ev,
				  struct tevent_fd *add_fde)
{
	struct epoll_event event;
	struct tevent_fd *mpx_fde;
	int ret;

	/* Find the existing fde that caused the EEXIST error. */
	for (mpx_fde = epoll_ev->ev->fd_events; mpx_fde; mpx_fde = mpx_fde->next) {
		if (mpx_fde->fd != add_fde->fd) {
			continue;
		}

		if (mpx_fde == add_fde) {
			continue;
		}

		break;
	}
	if (mpx_fde == NULL) {
		tevent_debug(epoll_ev->ev, TEVENT_DEBUG_FATAL,
			     "can't find multiplex fde for fd[%d]",
			     add_fde->fd);
		return -1;
	}

	if (mpx_fde->additional_flags & EPOLL_ADDITIONAL_FD_FLAG_HAS_MPX) {
		/* Logic error. Can't have more than 2 multiplexed fde's. */
		tevent_debug(epoll_ev->ev, TEVENT_DEBUG_FATAL,
			     "multiplex fde for fd[%d] is already multiplexed\n",
			     mpx_fde->fd);
		return -1;
	}

	/*
	 * The multiplex fde must have the same fd, and also
	 * already have an epoll event attached.
	 */
	if (!(mpx_fde->additional_flags & EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT)) {
		/* Logic error. Can't have more than 2 multiplexed fde's. */
		tevent_debug(epoll_ev->ev, TEVENT_DEBUG_FATAL,
			     "multiplex fde for fd[%d] has no event\n",
			     mpx_fde->fd);
		return -1;
	}

	/* Modify the mpx_fde to add in the new flags. */
	ZERO_STRUCT(event);
	event.events = epoll_map_flags(mpx_fde->flags);
	event.events |= epoll_map_flags(add_fde->flags);
	event.data.ptr = mpx_fde;
	ret = epoll_ctl(epoll_ev->epoll_fd, EPOLL_CTL_MOD, mpx_fde->fd, &event);
	if (ret != 0 && errno == EBADF) {
		tevent_debug(epoll_ev->ev, TEVENT_DEBUG_ERROR,
			     "EPOLL_CTL_MOD EBADF for "
			     "add_fde[%p] mpx_fde[%p] fd[%d] - disabling\n",
			     add_fde, mpx_fde, add_fde->fd);
		DLIST_REMOVE(epoll_ev->ev->fd_events, mpx_fde);
		mpx_fde->event_ctx = NULL;
		DLIST_REMOVE(epoll_ev->ev->fd_events, add_fde);
		add_fde->event_ctx = NULL;
		return 0;
	} else if (ret != 0) {
		return ret;
	}

	/*
	 * Make each fde->additional_data pointers point at each other
	 * so we can look them up from each other. They are now paired.
	 */
	mpx_fde->additional_data = (struct tevent_fd *)add_fde;
	add_fde->additional_data = (struct tevent_fd *)mpx_fde;

	/* Now flag both fde's as being multiplexed. */
	mpx_fde->additional_flags |= EPOLL_ADDITIONAL_FD_FLAG_HAS_MPX;
	add_fde->additional_flags |= EPOLL_ADDITIONAL_FD_FLAG_HAS_MPX;

	/* we need to keep the GOT_ERROR flag */
	if (mpx_fde->additional_flags & EPOLL_ADDITIONAL_FD_FLAG_GOT_ERROR) {
		add_fde->additional_flags |= EPOLL_ADDITIONAL_FD_FLAG_GOT_ERROR;
	}

	return 0;
}

/*
 add the epoll event to the given fd_event
*/
static void epoll_add_event(struct epoll_event_context *epoll_ev, struct tevent_fd *fde)
{
	struct epoll_event event;
	int ret;
	struct tevent_fd *mpx_fde = NULL;

	fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;
	fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR;

	if (fde->additional_flags & EPOLL_ADDITIONAL_FD_FLAG_HAS_MPX) {
		/*
		 * This is a multiplexed fde, we need to include both
		 * flags in the modified event.
		 */
		mpx_fde = talloc_get_type_abort(fde->additional_data,
						struct tevent_fd);

		mpx_fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;
		mpx_fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR;
	}

	ZERO_STRUCT(event);
	event.events = epoll_map_flags(fde->flags);
	if (mpx_fde != NULL) {
		event.events |= epoll_map_flags(mpx_fde->flags);
	}
	event.data.ptr = fde;
	ret = epoll_ctl(epoll_ev->epoll_fd, EPOLL_CTL_ADD, fde->fd, &event);
	if (ret != 0 && errno == EBADF) {
		tevent_debug(epoll_ev->ev, TEVENT_DEBUG_ERROR,
			     "EPOLL_CTL_ADD EBADF for "
			     "fde[%p] mpx_fde[%p] fd[%d] - disabling\n",
			     fde, mpx_fde, fde->fd);
		DLIST_REMOVE(epoll_ev->ev->fd_events, fde);
		fde->event_ctx = NULL;
		if (mpx_fde != NULL) {
			DLIST_REMOVE(epoll_ev->ev->fd_events, mpx_fde);
			mpx_fde->event_ctx = NULL;
		}
		return;
	} else if (ret != 0 && errno == EEXIST && mpx_fde == NULL) {
		ret = epoll_add_multiplex_fd(epoll_ev, fde);
		if (ret != 0) {
			epoll_panic(epoll_ev, "epoll_add_multiplex_fd failed",
				    false);
			return;
		}
	} else if (ret != 0) {
		epoll_panic(epoll_ev, "EPOLL_CTL_ADD failed", false);
		return;
	}

	fde->additional_flags |= EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;
	/* only if we want to read we want to tell the event handler about errors */
	if (fde->flags & TEVENT_FD_READ) {
		fde->additional_flags |= EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR;
	}

	if (mpx_fde == NULL) {
		return;
	}

	mpx_fde->additional_flags |= EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;
	/* only if we want to read we want to tell the event handler about errors */
	if (mpx_fde->flags & TEVENT_FD_READ) {
		mpx_fde->additional_flags |= EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR;
	}
}

/*
 delete the epoll event for given fd_event
*/
static void epoll_del_event(struct epoll_event_context *epoll_ev, struct tevent_fd *fde)
{
	struct epoll_event event;
	int ret;
	struct tevent_fd *mpx_fde = NULL;

	fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;
	fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR;

	if (fde->additional_flags & EPOLL_ADDITIONAL_FD_FLAG_HAS_MPX) {
		/*
		 * This is a multiplexed fde, we need to modify both events.
		 */
		mpx_fde = talloc_get_type_abort(fde->additional_data,
						struct tevent_fd);

		mpx_fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;
		mpx_fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR;
	}

	ZERO_STRUCT(event);
	ret = epoll_ctl(epoll_ev->epoll_fd, EPOLL_CTL_DEL, fde->fd, &event);
	if (ret != 0 && errno == ENOENT) {
		/*
		 * This can happen after a epoll_check_reopen
		 * within epoll_event_fd_destructor.
		 */
		tevent_debug(epoll_ev->ev, TEVENT_DEBUG_TRACE,
			     "EPOLL_CTL_DEL ignoring ENOENT for fd[%d]\n",
			     fde->fd);
		return;
	} else if (ret != 0 && errno == EBADF) {
		tevent_debug(epoll_ev->ev, TEVENT_DEBUG_WARNING,
			     "EPOLL_CTL_DEL EBADF for "
			     "fde[%p] mpx_fde[%p] fd[%d] - disabling\n",
			     fde, mpx_fde, fde->fd);
		DLIST_REMOVE(epoll_ev->ev->fd_events, fde);
		fde->event_ctx = NULL;
		if (mpx_fde != NULL) {
			DLIST_REMOVE(epoll_ev->ev->fd_events, mpx_fde);
			mpx_fde->event_ctx = NULL;
		}
		return;
	} else if (ret != 0) {
		epoll_panic(epoll_ev, "EPOLL_CTL_DEL failed", false);
		return;
	}
}

/*
 change the epoll event to the given fd_event
*/
static void epoll_mod_event(struct epoll_event_context *epoll_ev, struct tevent_fd *fde)
{
	struct tevent_fd *mpx_fde = NULL;
	struct epoll_event event;
	int ret;

	fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;
	fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR;

	if (fde->additional_flags & EPOLL_ADDITIONAL_FD_FLAG_HAS_MPX) {
		/*
		 * This is a multiplexed fde, we need to include both
		 * flags in the modified event.
		 */
		mpx_fde = talloc_get_type_abort(fde->additional_data,
						struct tevent_fd);

		mpx_fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;
		mpx_fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR;
	}

	ZERO_STRUCT(event);
	event.events = epoll_map_flags(fde->flags);
	if (mpx_fde != NULL) {
		event.events |= epoll_map_flags(mpx_fde->flags);
	}
	event.data.ptr = fde;
	ret = epoll_ctl(epoll_ev->epoll_fd, EPOLL_CTL_MOD, fde->fd, &event);
	if (ret != 0 && errno == EBADF) {
		tevent_debug(epoll_ev->ev, TEVENT_DEBUG_ERROR,
			     "EPOLL_CTL_MOD EBADF for "
			     "fde[%p] mpx_fde[%p] fd[%d] - disabling\n",
			     fde, mpx_fde, fde->fd);
		DLIST_REMOVE(epoll_ev->ev->fd_events, fde);
		fde->event_ctx = NULL;
		if (mpx_fde != NULL) {
			DLIST_REMOVE(epoll_ev->ev->fd_events, mpx_fde);
			mpx_fde->event_ctx = NULL;
		}
		return;
	} else if (ret != 0) {
		epoll_panic(epoll_ev, "EPOLL_CTL_MOD failed", false);
		return;
	}

	fde->additional_flags |= EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;
	/* only if we want to read we want to tell the event handler about errors */
	if (fde->flags & TEVENT_FD_READ) {
		fde->additional_flags |= EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR;
	}

	if (mpx_fde == NULL) {
		return;
	}

	mpx_fde->additional_flags |= EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;
	/* only if we want to read we want to tell the event handler about errors */
	if (mpx_fde->flags & TEVENT_FD_READ) {
		mpx_fde->additional_flags |= EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR;
	}
}

static void epoll_update_event(struct epoll_event_context *epoll_ev, struct tevent_fd *fde)
{
	bool got_error = (fde->additional_flags & EPOLL_ADDITIONAL_FD_FLAG_GOT_ERROR);
	bool want_read = (fde->flags & TEVENT_FD_READ);
	bool want_write= (fde->flags & TEVENT_FD_WRITE);
	struct tevent_fd *mpx_fde = NULL;

	if (fde->additional_flags & EPOLL_ADDITIONAL_FD_FLAG_HAS_MPX) {
		/*
		 * work out what the multiplexed fde wants.
		 */
		mpx_fde = talloc_get_type_abort(fde->additional_data,
						struct tevent_fd);

		if (mpx_fde->flags & TEVENT_FD_READ) {
			want_read = true;
		}

		if (mpx_fde->flags & TEVENT_FD_WRITE) {
			want_write = true;
		}
	}

	/* there's already an event */
	if (fde->additional_flags & EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT) {
		if (want_read || (want_write && !got_error)) {
			epoll_mod_event(epoll_ev, fde);
			return;
		}
		/* 
		 * if we want to match the select behavior, we need to remove the epoll_event
		 * when the caller isn't interested in events.
		 *
		 * this is because epoll reports EPOLLERR and EPOLLHUP, even without asking for them
		 */
		epoll_del_event(epoll_ev, fde);
		return;
	}

	/* there's no epoll_event attached to the fde */
	if (want_read || (want_write && !got_error)) {
		epoll_add_event(epoll_ev, fde);
		return;
	}
}

/*
  Cope with epoll returning EPOLLHUP|EPOLLERR on an event.
  Return true if there's nothing else to do, false if
  this event needs further handling.
*/
static bool epoll_handle_hup_or_err(struct epoll_event_context *epoll_ev,
				struct tevent_fd *fde)
{
	if (fde == NULL) {
		/* Nothing to do if no event. */
		return true;
	}

	fde->additional_flags |= EPOLL_ADDITIONAL_FD_FLAG_GOT_ERROR;
	/*
	 * if we only wait for TEVENT_FD_WRITE, we should not tell the
	 * event handler about it, and remove the epoll_event,
	 * as we only report errors when waiting for read events,
	 * to match the select() behavior
	 */
	if (!(fde->additional_flags & EPOLL_ADDITIONAL_FD_FLAG_REPORT_ERROR)) {
		/*
		 * Do the same as the poll backend and
		 * remove the writeable flag.
		 */
		fde->flags &= ~TEVENT_FD_WRITE;
		return true;
	}
	/* This has TEVENT_FD_READ set, we're not finished. */
	return false;
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
		uint16_t flags = 0;
		struct tevent_fd *mpx_fde = NULL;

		if (fde == NULL) {
			epoll_panic(epoll_ev, "epoll_wait() gave bad data", true);
			return -1;
		}
		if (fde->additional_flags & EPOLL_ADDITIONAL_FD_FLAG_HAS_MPX) {
			/*
			 * Save off the multiplexed event in case we need
			 * to use it to call the handler function.
			 */
			mpx_fde = talloc_get_type_abort(fde->additional_data,
							struct tevent_fd);
		}
		if (events[i].events & (EPOLLHUP|EPOLLERR)) {
			bool handled_fde = epoll_handle_hup_or_err(epoll_ev, fde);
			bool handled_mpx = epoll_handle_hup_or_err(epoll_ev, mpx_fde);

			if (handled_fde && handled_mpx) {
				epoll_update_event(epoll_ev, fde);
				continue;
			}

			if (!handled_mpx) {
				/*
				 * If the mpx event was the one that needs
				 * further handling, it's the TEVENT_FD_READ
				 * event so switch over and call that handler.
				 */
				fde = mpx_fde;
				mpx_fde = NULL;
			}
			flags |= TEVENT_FD_READ;
		}
		if (events[i].events & EPOLLIN) flags |= TEVENT_FD_READ;
		if (events[i].events & EPOLLOUT) flags |= TEVENT_FD_WRITE;

		if (flags & TEVENT_FD_WRITE) {
			if (fde->flags & TEVENT_FD_WRITE) {
				mpx_fde = NULL;
			}
			if (mpx_fde && mpx_fde->flags & TEVENT_FD_WRITE) {
				fde = mpx_fde;
				mpx_fde = NULL;
			}
		}

		if (mpx_fde) {
			/* Ensure we got the right fde. */
			if ((flags & fde->flags) == 0) {
				fde = mpx_fde;
				mpx_fde = NULL;
			}
		}

		/*
		 * make sure we only pass the flags
		 * the handler is expecting.
		 */
		flags &= fde->flags;
		if (flags) {
			fde->handler(epoll_ev->ev, fde, flags, fde->private_data);
			break;
		}
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
	struct tevent_context *ev = fde->event_ctx;
	struct epoll_event_context *epoll_ev = NULL;
	bool panic_triggered = false;
	struct tevent_fd *mpx_fde = NULL;
	int flags = fde->flags;

	if (ev == NULL) {
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

	if (fde->additional_flags & EPOLL_ADDITIONAL_FD_FLAG_HAS_MPX) {
		mpx_fde = talloc_get_type_abort(fde->additional_data,
						struct tevent_fd);

		fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_HAS_MPX;
		mpx_fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_HAS_MPX;

		fde->additional_data = NULL;
		mpx_fde->additional_data = NULL;

		fde->additional_flags &= ~EPOLL_ADDITIONAL_FD_FLAG_HAS_EVENT;
	}

	epoll_ev->panic_state = &panic_triggered;
	epoll_check_reopen(epoll_ev);
	if (panic_triggered) {
		return tevent_common_fd_destructor(fde);
	}

	if (mpx_fde != NULL) {
		epoll_update_event(epoll_ev, mpx_fde);
		if (panic_triggered) {
			return tevent_common_fd_destructor(fde);
		}
	}

	fde->flags = 0;
	epoll_update_event(epoll_ev, fde);
	fde->flags = flags;
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
	struct epoll_event_context *epoll_ev = talloc_get_type(ev->additional_data,
							   struct epoll_event_context);
	struct tevent_fd *fde;
	bool panic_triggered = false;

	fde = tevent_common_add_fd(ev, mem_ctx, fd, flags,
				   handler, private_data,
				   handler_name, location);
	if (!fde) return NULL;

	talloc_set_destructor(fde, epoll_event_fd_destructor);

	epoll_ev->panic_state = &panic_triggered;
	epoll_check_reopen(epoll_ev);
	if (panic_triggered) {
		return fde;
	}
	epoll_ev->panic_state = NULL;

	epoll_update_event(epoll_ev, fde);

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

	if (fde->flags == flags) return;

	ev = fde->event_ctx;
	epoll_ev = talloc_get_type(ev->additional_data, struct epoll_event_context);

	fde->flags = flags;

	epoll_ev->panic_state = &panic_triggered;
	epoll_check_reopen(epoll_ev);
	if (panic_triggered) {
		return;
	}
	epoll_ev->panic_state = NULL;

	epoll_update_event(epoll_ev, fde);
}

/*
  do a single event loop using the events defined in ev 
*/
static int epoll_event_loop_once(struct tevent_context *ev, const char *location)
{
	struct epoll_event_context *epoll_ev = talloc_get_type(ev->additional_data,
		 					   struct epoll_event_context);
	struct timeval tval;
	bool panic_triggered = false;

	if (ev->signal_events &&
	    tevent_common_check_signal(ev)) {
		return 0;
	}

	if (ev->immediate_events &&
	    tevent_common_loop_immediate(ev)) {
		return 0;
	}

	tval = tevent_common_loop_timer_delay(ev);
	if (tevent_timeval_is_zero(&tval)) {
		return 0;
	}

	epoll_ev->panic_state = &panic_triggered;
	epoll_ev->panic_force_replay = true;
	epoll_check_reopen(epoll_ev);
	if (panic_triggered) {
		errno = EINVAL;
		return -1;
	}
	epoll_ev->panic_force_replay = false;
	epoll_ev->panic_state = NULL;

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
