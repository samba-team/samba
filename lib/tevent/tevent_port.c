/*
   Unix SMB/CIFS implementation.

   Main select loop and event handling - Solaris port implementation.
   Losely based on the Linux epoll backend.

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

struct port_associate_vals {
	struct port_associate_vals *prev, *next;
	struct port_event_context *port_ev;
	int events;
	struct tevent_fd *fde;
	bool associated_event;
};

struct port_event_context {
	/* a pointer back to the generic event_context */
	struct tevent_context *ev;

	/* This is the handle from port_create */
	int port_fd;

	pid_t pid;

	/* List of associations. */
	struct port_associate_vals *po_vals;
};

#define PORT_ADDITIONAL_FD_FLAG_HAS_ASSOCIATION	(1<<0)
#define PORT_ADDITIONAL_FD_FLAG_REPORT_ERROR	(1<<1)
#define PORT_ADDITIONAL_FD_FLAG_GOT_ERROR	(1<<2)
#define PORT_ADDITIONAL_FD_FLAG_HAS_MPX		(1<<3)

/*
  Map from TEVENT_FD_* to POLLIN/POLLOUT
*/
static int port_map_flags(uint16_t flags)
{
	int ret = 0;
	if (flags & TEVENT_FD_READ) ret |= (POLLIN | POLLERR | POLLHUP);
	if (flags & TEVENT_FD_WRITE) ret |= (POLLOUT | POLLERR | POLLHUP);
	return ret;
}

/*
 Free the port fd
*/
static int port_ctx_destructor(struct port_event_context *port_ev)
{
	close(port_ev->port_fd);
	port_ev->port_fd = -1;
	return 0;
}

/*
 Init the port fd
*/
static int port_init_ctx(struct port_event_context *port_ev)
{
	port_ev->port_fd = port_create();
	if (port_ev->port_fd == -1) {
		tevent_debug(port_ev->ev, TEVENT_DEBUG_FATAL,
			     "Failed to create port handle.\n");
		return -1;
	}

	if (!ev_set_close_on_exec(port_ev->port_fd)) {
		tevent_debug(port_ev->ev, TEVENT_DEBUG_WARNING,
			     "Failed to set close-on-exec, file descriptor may be leaked to children.\n");
	}

	port_ev->pid = getpid();
	talloc_set_destructor(port_ev, port_ctx_destructor);

	return 0;
}

/*
 Functions to manage the lower level cache of associated events on the port_fd.
*/

static int port_associate_vals_destructor(struct port_associate_vals *val)
{
	DLIST_REMOVE(val->port_ev->po_vals, val);
	memset(val, '\0', sizeof(struct port_associate_vals));
	return 0;
}

/*
 * TODO: As the port_association is per-fde, it should be possible to store it
 * directly in fde->additional_data, alongside any multiplexed-fde. That way the
 * lookup on store and delete would be avoided, and associate_all_events() could
 * walk the ev->fd_events list.
 */
static bool store_port_association(struct port_event_context *port_ev,
				struct tevent_fd *fde,
				int events)
{
	struct port_associate_vals *val;

	for (val = port_ev->po_vals; val; val = val->next) {
		if (val->fde->fd == fde->fd) {
			/* Association already attached to fd. */
			if (val->events != events) {
				val->events = events;
				val->associated_event = false;
			}
			return true;
		}
	}

	val = talloc_zero(port_ev, struct port_associate_vals);
	if (val == NULL) {
		return false;
	}

	val->port_ev = port_ev;
	val->fde = fde;
	val->events = events;
	val->associated_event = false;

	DLIST_ADD(port_ev->po_vals, val);
	talloc_set_destructor(val, port_associate_vals_destructor);

	return true;
}

static void delete_port_association(struct port_event_context *port_ev,
				struct tevent_fd *fde)
{
	struct port_associate_vals *val;

	for (val = port_ev->po_vals; val; val = val->next) {
		if (val->fde == fde) {
			if (val->associated_event) {
				(void)port_dissociate(port_ev->port_fd,
							PORT_SOURCE_FD,
							fde->fd);
			}
			talloc_free(val);
			return;
		}
	}
}

static int associate_all_events(struct port_event_context *port_ev)
{
	struct port_associate_vals *val;

	for (val = port_ev->po_vals; val; val = val->next) {
		if (val->associated_event) {
			continue;
		}
		int ret = port_associate(port_ev->port_fd,
					PORT_SOURCE_FD,
					(uintptr_t)val->fde->fd,
					val->events,
					(void *)val);
		if (ret != 0) {
			return -1;
		}
		val->associated_event = true;
	}
	return 0;
}

static int port_update_event(struct port_event_context *port_ev, struct tevent_fd *fde);

/*
  Reopen the port handle when our pid changes.
 */
static int port_check_reopen(struct port_event_context *port_ev)
{
	struct tevent_fd *fde;

	if (port_ev->pid == getpid()) {
		return 0;
	}

	close(port_ev->port_fd);
	port_ev->port_fd = port_create();
	if (port_ev->port_fd == -1) {
		tevent_debug(port_ev->ev, TEVENT_DEBUG_FATAL,
				"port_create() failed");
		return -1;
	}

	if (!ev_set_close_on_exec(port_ev->port_fd)) {
		tevent_debug(port_ev->ev, TEVENT_DEBUG_WARNING,
			     "Failed to set close-on-exec, file descriptor may be leaked to children.\n");
	}

	port_ev->pid = getpid();
	for (fde=port_ev->ev->fd_events;fde;fde=fde->next) {
		fde->additional_flags &= PORT_ADDITIONAL_FD_FLAG_HAS_ASSOCIATION;
		if (port_update_event(port_ev, fde) != 0) {
			return -1;
		}
	}
	return 0;
}

/*
 * Solaris ports cannot add the same file descriptor twice, once
 * with read, once with write which is allowed by the tevent backend.
 * Multiplex the existing fde, flag it as such so we can search for the
 * correct fde on event triggering.
 */

static void port_setup_multiplex_fd(struct port_event_context *port_ev,
				struct tevent_fd *add_fde,
				struct tevent_fd *mpx_fde)
{
	/*
	 * Make each fde->additional_data pointers point at each other
	 * so we can look them up from each other. They are now paired.
	 */
	mpx_fde->additional_data = add_fde;
	add_fde->additional_data = mpx_fde;

	/* Now flag both fde's as being multiplexed. */
	mpx_fde->additional_flags |= PORT_ADDITIONAL_FD_FLAG_HAS_MPX;
	add_fde->additional_flags |= PORT_ADDITIONAL_FD_FLAG_HAS_MPX;

	/* We need to keep the GOT_ERROR flag. */
	if (mpx_fde->additional_flags & PORT_ADDITIONAL_FD_FLAG_GOT_ERROR) {
		add_fde->additional_flags |= PORT_ADDITIONAL_FD_FLAG_GOT_ERROR;
	}
}

/*
 Add the port event to the given fd_event,
 Or modify an existing event.
*/

static int port_add_event(struct port_event_context *port_ev, struct tevent_fd *fde)
{
	int flags = port_map_flags(fde->flags);
	struct tevent_fd *mpx_fde = NULL;

	fde->additional_flags &= ~PORT_ADDITIONAL_FD_FLAG_HAS_ASSOCIATION;
	fde->additional_flags &= ~PORT_ADDITIONAL_FD_FLAG_REPORT_ERROR;

	if (fde->additional_flags & PORT_ADDITIONAL_FD_FLAG_HAS_MPX) {
		/*
		 * This is already a multiplexed fde, we need to include both
		 * flags in the modified event.
		 */
		mpx_fde = talloc_get_type_abort(fde->additional_data,
						struct tevent_fd);

		mpx_fde->additional_flags &= ~PORT_ADDITIONAL_FD_FLAG_HAS_ASSOCIATION;
		mpx_fde->additional_flags &= ~PORT_ADDITIONAL_FD_FLAG_REPORT_ERROR;

		flags |= port_map_flags(mpx_fde->flags);
	} else {
		/*
		 * Not (yet) a multiplexed event. See if there
		 * is already an event with the same fd.
		 */
		for (mpx_fde = port_ev->ev->fd_events; mpx_fde; mpx_fde = mpx_fde->next) {
			if (mpx_fde->fd != fde->fd) {
				continue;
			}
			if (mpx_fde == fde) {
				continue;
			}
			/* Same fd. */
			break;
		}
		if (mpx_fde) {
			if (mpx_fde->additional_flags & PORT_ADDITIONAL_FD_FLAG_HAS_MPX) {
				/* Logic error. Can't have more then 2 multiplexed fde's. */
				tevent_debug(port_ev->ev, TEVENT_DEBUG_FATAL,
					"multiplex fde for fd[%d] is already multiplexed\n",
					mpx_fde->fd);
				return -1;
			}
			flags |= port_map_flags(mpx_fde->flags);
		}
	}

	if (!store_port_association(port_ev,
				fde,
				flags)) {
		tevent_debug(port_ev->ev, TEVENT_DEBUG_FATAL,
			"store_port_association failed for fd[%d]\n",
			fde->fd);
		return -1;
	}

	/* Note we have an association now. */
	fde->additional_flags |= PORT_ADDITIONAL_FD_FLAG_HAS_ASSOCIATION;
	/* Only if we want to read do we tell the event handler about errors. */
	if (fde->flags & TEVENT_FD_READ) {
		fde->additional_flags |= PORT_ADDITIONAL_FD_FLAG_REPORT_ERROR;
	}
	if (mpx_fde == NULL) {
		return 0;
	}
	/* Set up the multiplex pointer. Does no harm if already multiplexed. */
	port_setup_multiplex_fd(port_ev,
				fde,
				mpx_fde);

	mpx_fde->additional_flags |= PORT_ADDITIONAL_FD_FLAG_HAS_ASSOCIATION;
	/* Only if we want to read do we tell the event handler about errors. */
	if (mpx_fde->flags & TEVENT_FD_READ) {
		mpx_fde->additional_flags |= PORT_ADDITIONAL_FD_FLAG_REPORT_ERROR;
	}

	return 0;
}

/*
 Delete the port association for the given fd_event.
*/

static void port_del_event(struct port_event_context *port_ev, struct tevent_fd *fde)
{
	struct tevent_fd *mpx_fde = NULL;

	fde->additional_flags &= ~PORT_ADDITIONAL_FD_FLAG_HAS_ASSOCIATION;
	fde->additional_flags &= ~PORT_ADDITIONAL_FD_FLAG_REPORT_ERROR;

	if (fde->additional_flags & PORT_ADDITIONAL_FD_FLAG_HAS_MPX) {
		/*
		 * This is a multiplexed fde, we need to remove
		 * both associations.
		 */
		mpx_fde = talloc_get_type_abort(fde->additional_data,
						struct tevent_fd);

		mpx_fde->additional_flags &= ~PORT_ADDITIONAL_FD_FLAG_HAS_ASSOCIATION;
		mpx_fde->additional_flags &= ~PORT_ADDITIONAL_FD_FLAG_REPORT_ERROR;
		mpx_fde->additional_data = NULL;

		fde->additional_data = NULL;
	}
	delete_port_association(port_ev, fde);
}

/*
 Add or remove the port event from the given fd_event
*/
static int port_update_event(struct port_event_context *port_ev, struct tevent_fd *fde)
{
	bool got_error = (fde->additional_flags & PORT_ADDITIONAL_FD_FLAG_GOT_ERROR);
	bool want_read = (fde->flags & TEVENT_FD_READ);
	bool want_write = (fde->flags & TEVENT_FD_WRITE);
	struct tevent_fd *mpx_fde = NULL;

	if (fde->additional_flags & PORT_ADDITIONAL_FD_FLAG_HAS_MPX) {
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

	if (fde->additional_flags & PORT_ADDITIONAL_FD_FLAG_HAS_ASSOCIATION) {
		/* There's already an association. */
		if (want_read || (want_write && !got_error)) {
			return port_add_event(port_ev, fde);
		}
		/*
		 * If we want to match the select behavior, we need to remove the port event
		 * when the caller isn't interested in events.
		 */
		port_del_event(port_ev, fde);
		return 0;
	}

	/* There's no port event attached to the fde. */
	if (want_read || (want_write && !got_error)) {
		return port_add_event(port_ev, fde);
	}
	return 0;
}

/*
 Cope with port_get returning EPOLLHP|EPOLLERR on an association.
 Return true if there's nothing else to do, false if this event
 needs further handling.
*/

static bool port_handle_hup_or_err(struct port_event_context *port_ev,
				struct tevent_fd *fde)
{
	if (fde == NULL) {
		return true;
	}

	fde->additional_flags |= PORT_ADDITIONAL_FD_FLAG_GOT_ERROR;
	/*
	 * If we only wait for TEVENT_FD_WRITE, we should not tell the
	 * event handler about it, and remove the port association,
	 * as we only report error when waiting for read events,
	 * to match the select() behavior.
	 */
	if (!(fde->additional_flags & PORT_ADDITIONAL_FD_FLAG_REPORT_ERROR)) {
		/*
		 * Do the same as the poll backend and
		 * remove the writable flag.
		 */
		fde->flags &= ~TEVENT_FD_WRITE;
		return true;
	}
	/* This has TEVENT_FD_READ set, we're not finished. */
	return false;
}

/*
  Event loop handling using Solaris ports.
*/
static int port_event_loop(struct port_event_context *port_ev, struct timeval *tvalp)
{
	int ret;
#define MAXEVENTS 1
	port_event_t events[MAXEVENTS];
	uint_t nget = 1;
	uint_t max_events = MAXEVENTS;
	uint_t i;
	int port_errno;
	struct timespec ts;
	struct tevent_context *ev = port_ev->ev;

	if (tvalp) {
		ts.tv_sec = tvalp->tv_sec;
		ts.tv_nsec = tvalp->tv_usec * 1000;
	}

	if (port_ev->ev->signal_events &&
	    tevent_common_check_signal(ev)) {
		return 0;
	}

	/*
	 * Solaris triggers sending the event to the port
	 * at the time the port association is done. Postpone
	 * associating fd's until just before we get the events,
	 * otherwise we can deadlock.
	 */

	if (associate_all_events(port_ev) != 0) {
		return -1;
	}

	tevent_trace_point_callback(ev, TEVENT_TRACE_BEFORE_WAIT);
	ret = port_getn(port_ev->port_fd, events, max_events, &nget, &ts);
	port_errno = errno;
	tevent_trace_point_callback(ev, TEVENT_TRACE_AFTER_WAIT);

	if (ret == -1 && port_errno == EINTR) {
		if (ev->signal_events) {
			tevent_common_check_signal(ev);
		}
		/*
		 * If no signal handlers we got an unsolicited
		 * signal wakeup. This can happen with epoll
		 * too. Just return and ignore.
		 */
		return 0;
	}

	if (ret == -1 && port_errno == ETIME && tvalp) {
		/* we don't care about a possible delay here */
		tevent_common_loop_timer_delay(ev);
		return 0;
	}

	if (ret == -1) {
		tevent_debug(ev, TEVENT_DEBUG_ERROR,
				"port_get failed (%s)\n",
				strerror(errno));
		return -1;
	}

	for (i = 0; i < nget; i++) {
		struct tevent_fd *mpx_fde = NULL;
		struct tevent_fd *fde = NULL;
		uint16_t flags = 0;
		struct port_associate_vals *val = talloc_get_type(events[i].portev_user,
							struct port_associate_vals);
		if (val == NULL) {
			tevent_debug(ev, TEVENT_DEBUG_ERROR,
				"port_getn() gave bad data");
			return -1;
		}

		/* Mark this event as needing to be re-associated. */
		val->associated_event = false;

		fde = val->fde;

		if (fde->additional_flags & PORT_ADDITIONAL_FD_FLAG_HAS_MPX) {
			/*
			 * Save off the multiplexed event in case we need
			 * to use it to call the handler function.
			 */
			mpx_fde = talloc_get_type_abort(fde->additional_data,
						struct tevent_fd);
		}

		if (events[i].portev_events & (POLLHUP|POLLERR)) {
			bool handled_fde = port_handle_hup_or_err(port_ev, fde);
			bool handled_mpx = port_handle_hup_or_err(port_ev, mpx_fde);

			if (handled_fde && handled_mpx) {
				return port_update_event(port_ev, fde);
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

		if (events[i].portev_events & POLLIN) {
			flags |= TEVENT_FD_READ;
		}
		if (events[i].portev_events & POLLOUT) {
			flags |= TEVENT_FD_WRITE;
		}

		if (flags & TEVENT_FD_WRITE) {
			if (fde->flags & TEVENT_FD_WRITE) {
				mpx_fde = NULL;
			}
			if (mpx_fde && (mpx_fde->flags & TEVENT_FD_WRITE)) {
				fde = mpx_fde;
				mpx_fde = NULL;
			}

			if (mpx_fde) {
				/* Ensure we got the right fde. */
				if ((flags & fde->flags) == 0) {
					fde = mpx_fde;
					mpx_fde = NULL;
				}
			}
		}

		/*
		 * Make sure we only pass the flags
		 * the handler is expecting.
		 */
		flags &= fde->flags;
		if (flags) {
			fde->handler(ev, fde, flags, fde->private_data);
			break;
		}
	}

	return 0;
}


/*
  create a port_event_context structure.
*/
static int port_event_context_init(struct tevent_context *ev)
{
	int ret;
	struct port_event_context *port_ev;

	/*
	 * We might be called during tevent_re_initialise()
	 * which means we need to free our old additional_data.
	 */
	TALLOC_FREE(ev->additional_data);

	port_ev = talloc_zero(ev, struct port_event_context);
	if (!port_ev) {
		return -1;
	}
	port_ev->ev = ev;
	port_ev->port_fd = -1;
	port_ev->pid = (pid_t)-1;

	ret = port_init_ctx(port_ev);
	if (ret != 0) {
		talloc_free(port_ev);
		return ret;
	}

	ev->additional_data = port_ev;
	return 0;
}

/*
  destroy an fd_event
*/
static int port_event_fd_destructor(struct tevent_fd *fde)
{
	struct tevent_context *ev = fde->event_ctx;
	struct port_event_context *port_ev = NULL;
	struct tevent_fd *mpx_fde = NULL;
	int flags = (int)fde->flags;

	if (ev == NULL) {
		return tevent_common_fd_destructor(fde);
	}

	port_ev = talloc_get_type_abort(ev->additional_data,
					 struct port_event_context);

	DLIST_REMOVE(ev->fd_events, fde);

	if (fde->additional_flags & PORT_ADDITIONAL_FD_FLAG_HAS_MPX) {
		mpx_fde = talloc_get_type_abort(fde->additional_data,
						struct tevent_fd);

		fde->additional_flags &= ~PORT_ADDITIONAL_FD_FLAG_HAS_MPX;
		mpx_fde->additional_flags &= ~PORT_ADDITIONAL_FD_FLAG_HAS_MPX;

		fde->additional_data = NULL;
		mpx_fde->additional_data = NULL;

		fde->additional_flags &= PORT_ADDITIONAL_FD_FLAG_HAS_ASSOCIATION;
	}

	(void)port_check_reopen(port_ev);

	if (mpx_fde != NULL) {
		(void)port_update_event(port_ev, mpx_fde);
	}

	fde->flags = 0;
	(void)port_update_event(port_ev, fde);
	fde->flags = flags;

	return tevent_common_fd_destructor(fde);
}

/*
  add a fd based event
  return NULL on failure (memory allocation error)
*/
static struct tevent_fd *port_event_add_fd(struct tevent_context *ev, TALLOC_CTX *mem_ctx,
					    int fd, uint16_t flags,
					    tevent_fd_handler_t handler,
					    void *private_data,
					    const char *handler_name,
					    const char *location)
{
	struct port_event_context *port_ev =
				talloc_get_type_abort(ev->additional_data,
				struct port_event_context);
	struct tevent_fd *fde;

	fde = tevent_common_add_fd(ev, mem_ctx, fd, flags,
				   handler, private_data,
				   handler_name, location);
	if (!fde) {
		return NULL;
	}

	talloc_set_destructor(fde, port_event_fd_destructor);

	if (port_check_reopen(port_ev) != 0) {
		TALLOC_FREE(fde);
		return NULL;
	}

	if (port_update_event(port_ev, fde) != 0) {
		TALLOC_FREE(fde);
		return NULL;
	}

	return fde;
}

/*
  set the fd event flags
*/
static void port_event_set_fd_flags(struct tevent_fd *fde, uint16_t flags)
{
	struct tevent_context *ev;
	struct port_event_context *port_ev;

	if (fde->flags == flags) {
		return;
	}

	ev = fde->event_ctx;
	port_ev = talloc_get_type_abort(ev->additional_data,
				struct port_event_context);

	fde->flags = flags;

	(void)port_check_reopen(port_ev);
	(void)port_update_event(port_ev, fde);
}

/*
  do a single event loop using the events defined in ev
*/
static int port_event_loop_once(struct tevent_context *ev, const char *location)
{
	struct port_event_context *port_ev = talloc_get_type(ev->additional_data,
							   struct port_event_context);
	struct timeval tval;

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

	if (port_check_reopen(port_ev) != 0) {
		errno = EINVAL;
		return -1;
	}
	return port_event_loop(port_ev, &tval);
}

static const struct tevent_ops port_event_ops = {
	.context_init		= port_event_context_init,
	.add_fd			= port_event_add_fd,
	.set_fd_close_fn	= tevent_common_fd_set_close_fn,
	.get_fd_flags		= tevent_common_fd_get_flags,
	.set_fd_flags		= port_event_set_fd_flags,
	.add_timer		= tevent_common_add_timer_v2,
	.schedule_immediate	= tevent_common_schedule_immediate,
	.add_signal		= tevent_common_add_signal,
	.loop_once		= port_event_loop_once,
	.loop_wait		= tevent_common_loop_wait,
};

_PRIVATE_ bool tevent_port_init(void)
{
	if (!tevent_register_backend("port", &port_event_ops)) {
		return false;
	}
	tevent_set_default_backend("port");
	return true;
}
