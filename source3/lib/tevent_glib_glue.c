/*
   Unix SMB/CIFS implementation.
   Integration of a glib g_main_context into a tevent_context
   Copyright (C) Stefan Metzmacher 2016
   Copyright (C) Ralph Boehme 2016

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
#include "lib/util/debug.h"
#include "lib/util/select.h"
#include <tevent.h>

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_TEVENT

#ifdef HAVE_GLIB
#include <glib.h>
#include "tevent_glib_glue.h"

struct fd_map {
	struct tevent_glib_glue *glue;
	int fd;
	struct tevent_fd *fd_event;
};

struct tevent_glib_glue {
	/*
	 * The tevent context we're feeding.
	 */
	struct tevent_context *ev;

	/*
	 * The glib gmain context we're polling and whether we're currently
	 * owning it by virtue of g_main_context_acquire().
	 */
	GMainContext *gmain_ctx;
	bool gmain_owner;

	/*
	 * Set by samba_tevent_glib_glue_quit().
	 */
	bool quit;

	/*
	 * tevent trace callback and data we got from tevent_get_trace_callback()
	 * before installing our own trace callback.
	 */
	tevent_trace_callback_t prev_tevent_trace_cb;
	void *prev_tevent_trace_data;

	/*
	 * Don't call tevent_glib_prepare() in the tevent tracepoint handler if
	 * explicity told so. This is an optimisation for the case that glib
	 * event sources are created from glib event callbacks.
	 */
	bool skip_glib_refresh;

	/*
	 * Used when acquiring the glib gmain context failed.
	 */
	struct tevent_timer *acquire_retry_timer;

	/*
	 * glib gmain context timeout and priority for the current event look
	 * iteration. gtimeout is translated to a tevent timer event, unless it
	 * is 0 which signals some event source is pending. In that case we
	 * dispatch an immediate event. gpriority is ignored by us, just passed
	 * to the glib relevant functions.
	 */
	gint gtimeout;
	gint gpriority;
	struct tevent_timer *timer;
	struct tevent_immediate *im;
	bool scheduled_im;

	/*
	 * glib gmain context fds returned from g_main_context_query(). These
	 * get translated to tevent fd events.
	 */
	GPollFD *gpollfds;
	gint num_gpollfds;

	/*
	 * A copy of gpollfds and num_gpollfds from the previous event loop
	 * iteration, used to detect changes in the set of fds.
	 */
	GPollFD *prev_gpollfds;
	gint num_prev_gpollfds;

	/*
	 * An array of pointers to fd_map's. The fd_map'd contain the tevent
	 * event fd as well as a pointer to the corresponding glib GPollFD.
	 */
	struct fd_map **fd_map;
	size_t num_maps;
};

static bool tevent_glib_prepare(struct tevent_glib_glue *glue);
static bool tevent_glib_process(struct tevent_glib_glue *glue);
static bool tevent_glib_glue_reinit(struct tevent_glib_glue *glue);
static void tevent_glib_fd_handler(struct tevent_context *ev,
				   struct tevent_fd *fde,
				   uint16_t flags,
				   void *private_data);

typedef int (*gfds_cmp_cb)(const void *fd1, const void *fd2);
typedef bool (*gfds_found_cb)(struct tevent_glib_glue *glue,
			      const GPollFD *new,
			      const GPollFD *old);
typedef bool (*gfds_new_cb)(struct tevent_glib_glue *glue,
			    const GPollFD *fd);
typedef bool (*gfds_removed_cb)(struct tevent_glib_glue *glue,
				const GPollFD *fd);

/**
 * Compare two sorted GPollFD arrays
 *
 * For every element that exists in gfds and prev_gfds found_fn() is called.
 * For every element in gfds but not in prev_gfds, new_fn() is called.
 * For every element in prev_gfds but not in gfds removed_fn() is called.
 **/
static bool cmp_gfds(struct tevent_glib_glue *glue,
		     GPollFD *gfds,
		     GPollFD *prev_gfds,
		     size_t num_gfds,
		     size_t num_prev_gfds,
		     gfds_cmp_cb cmp_cb,
		     gfds_found_cb found_cb,
		     gfds_new_cb new_cb,
		     gfds_removed_cb removed_cb)
{
	bool ok;
	size_t i = 0, j = 0;
	int cmp;

	while (i < num_gfds && j < num_prev_gfds) {
		cmp = cmp_cb(&gfds[i], &prev_gfds[j]);
		if (cmp == 0) {
			ok = found_cb(glue, &gfds[i], &prev_gfds[j]);
			if (!ok) {
				return false;
			}
			i++;
			j++;
		} else if (cmp < 0) {
			ok = new_cb(glue, &gfds[i]);
			if (!ok) {
				return false;
			}
			i++;
		} else {
			ok = removed_cb(glue, &prev_gfds[j]);
			if (!ok) {
				return false;
			}
			j++;
		}
	}

	while (i < num_gfds) {
		ok = new_cb(glue, &gfds[i++]);
		if (!ok) {
			return false;
		}
	}

	while (j < num_prev_gfds) {
		ok = removed_cb(glue, &prev_gfds[j++]);
		if (!ok) {
			return false;
		}
	}

	return true;
}

static int glib_fd_cmp_func(const void *p1, const void *p2)
{
	const GPollFD *lhs = p1;
	const GPollFD *rhs = p2;

	if (lhs->fd < rhs->fd) {
		return -1;
	} else if (lhs->fd > rhs->fd) {
		return 1;
	}

	return 0;
}

/*
 * We already have a tevent fd event for the glib GPollFD, but we may have to
 * update flags.
 */
static bool match_gfd_cb(struct tevent_glib_glue *glue,
			 const GPollFD *new_gfd,
			 const GPollFD *old_gfd)
{
	size_t i;
	struct fd_map *fd_map = NULL;
	struct tevent_fd *fd_event = NULL;

	if (new_gfd->events == old_gfd->events) {
		return true;
	}

	for (i = 0; i < glue->num_maps; i++) {
		if (glue->fd_map[i]->fd == new_gfd->fd) {
			break;
		}
	}

	if (i == glue->num_maps) {
		DBG_ERR("match_gfd_cb: glib fd %d not in map\n", new_gfd->fd);
		return false;
	}

	fd_map = glue->fd_map[i];
	if (fd_map == NULL) {
		DBG_ERR("fd_map for fd %d is NULL\n", new_gfd->fd);
		return false;
	}

	fd_event = fd_map->fd_event;
	if (fd_event == NULL) {
		DBG_ERR("fd_event for fd %d is NULL\n", new_gfd->fd);
		return false;
	}

	tevent_fd_set_flags(fd_event, 0);

	if (new_gfd->events & (G_IO_IN | G_IO_HUP | G_IO_ERR)) {
		TEVENT_FD_READABLE(fd_event);
	}
	if (new_gfd->events & G_IO_OUT) {
		TEVENT_FD_WRITEABLE(fd_event);
	}

	return true;
}

static bool new_gfd_cb(struct tevent_glib_glue *glue, const GPollFD *gfd)
{
	struct tevent_fd *fd_event = NULL;
	struct fd_map *fd_map = NULL;
	uint16_t events = 0;
	bool revent;
	bool wevent;

	revent = (gfd->events & (G_IO_IN | G_IO_HUP | G_IO_ERR));
	wevent = (gfd->events & G_IO_OUT);
	if (revent) {
		events |= TEVENT_FD_READ;
	}
	if (wevent) {
		events |= TEVENT_FD_WRITE;
	}

	glue->fd_map = talloc_realloc(glue,
				      glue->fd_map,
				      struct fd_map *,
				      glue->num_maps + 1);
	if (glue->fd_map == NULL) {
		DBG_ERR("talloc_realloc failed\n");
		return false;
	}
	fd_map = talloc_zero(glue->fd_map, struct fd_map);
	if (fd_map == NULL) {
		DBG_ERR("talloc_realloc failed\n");
		return false;
	}
	glue->fd_map[glue->num_maps] = fd_map;
	glue->num_maps++;

	fd_event = tevent_add_fd(glue->ev,
				 glue->fd_map,
				 gfd->fd,
				 events,
				 tevent_glib_fd_handler,
				 fd_map);
	if (fd_event == NULL) {
		DBG_ERR("tevent_add_fd failed\n");
		return false;
	}

	*fd_map = (struct fd_map) {
		.glue = glue,
		.fd = gfd->fd,
		.fd_event = fd_event,
	};

	DBG_DEBUG("added tevent_fd for glib fd %d\n", gfd->fd);

	return true;
}

static bool remove_gfd_cb(struct tevent_glib_glue *glue, const GPollFD *gfd)
{
	size_t i;

	for (i = 0; i < glue->num_maps; i++) {
		if (glue->fd_map[i]->fd == gfd->fd) {
			break;
		}
	}

	if (i == glue->num_maps) {
		DBG_ERR("remove_gfd_cb: glib fd %d not in map\n", gfd->fd);
		return false;
	}

	TALLOC_FREE(glue->fd_map[i]->fd_event);
	TALLOC_FREE(glue->fd_map[i]);

	if (i + 1 < glue->num_maps) {
		memmove(&glue->fd_map[i],
			&glue->fd_map[i+1],
			(glue->num_maps - (i + 1)) * sizeof(struct fd_map *));
	}

	glue->fd_map = talloc_realloc(glue,
				      glue->fd_map,
				      struct fd_map *,
				      glue->num_maps - 1);
	if (glue->num_maps > 0 && glue->fd_map == NULL) {
		DBG_ERR("talloc_realloc failed\n");
		return false;
	}
	glue->num_maps--;

	return true;
}

static short gpoll_to_poll_event(gushort gevent)
{
	short pevent = 0;

	if (gevent & G_IO_IN) {
		pevent |= POLLIN;
	}
	if (gevent & G_IO_OUT) {
		pevent |= POLLOUT;
	}
	if (gevent & G_IO_HUP) {
		pevent |= POLLHUP;
	}
	if (gevent & G_IO_ERR) {
		pevent |= POLLERR;
	}

	return pevent;
}

static gushort poll_to_gpoll_event(short pevent)
{
	gushort gevent = 0;

	if (pevent & POLLIN) {
		gevent |= G_IO_IN;
	}
	if (pevent & POLLOUT) {
		gevent |= G_IO_OUT;
	}
	if (pevent & POLLHUP) {
		gevent |= G_IO_HUP;
	}
	if (pevent & POLLERR) {
		gevent |= G_IO_ERR;
	}

	return gevent;
}

static void tevent_glib_fd_handler(struct tevent_context *ev,
				   struct tevent_fd *fde,
				   uint16_t flags,
				   void *private_data)
{
	struct fd_map *fd_map = talloc_get_type_abort(
		private_data, struct fd_map);
	struct tevent_glib_glue *glue = NULL;
	GPollFD *gpollfd = NULL;
	struct pollfd fd;
	int ret;
	int i;

	glue = fd_map->glue;

	for (i = 0; i < glue->num_gpollfds; i++) {
		if (glue->gpollfds[i].fd != fd_map->fd) {
			continue;
		}
		gpollfd = &glue->gpollfds[i];
		break;
	}
	if (gpollfd == NULL) {
		DBG_ERR("No gpollfd for fd_map [%p] fd [%d]\n",
			fd_map, fd_map->fd);
		return;
	}
	/*
	 * We have to poll() the fd to get the correct fd event for glib. tevent
	 * only tells us about readable/writable in flags, but we need the full
	 * glory for glib.
	 */

	fd = (struct pollfd) {
		.fd = gpollfd->fd,
		.events = gpoll_to_poll_event(gpollfd->events),
	};

	ret = sys_poll_intr(&fd, 1, 0);
	if (ret == -1) {
		DBG_ERR("poll: %s\n", strerror(errno));
		return;
	}
	if (ret == 0) {
		return;
	}

	gpollfd->revents = poll_to_gpoll_event(fd.revents);

	tevent_glib_process(glue);
	return;
}

static void tevent_glib_timer_handler(struct tevent_context *ev,
				      struct tevent_timer *te,
				      struct timeval current_time,
				      void *private_data)
{
	struct tevent_glib_glue *glue = talloc_get_type_abort(
		private_data, struct tevent_glib_glue);

	glue->timer = NULL;
	tevent_glib_process(glue);
	return;
}

static void tevent_glib_im_handler(struct tevent_context *ev,
				   struct tevent_immediate *im,
				   void *private_data)
{
	struct tevent_glib_glue *glue = talloc_get_type_abort(
		private_data, struct tevent_glib_glue);

	glue->scheduled_im = false;
	tevent_glib_process(glue);
	return;
}

static bool save_current_fdset(struct tevent_glib_glue *glue)
{
	/*
	 * Save old glib fds. We only grow the prev array.
	 */

	if (glue->num_prev_gpollfds < glue->num_gpollfds) {
		glue->prev_gpollfds = talloc_realloc(glue,
						     glue->prev_gpollfds,
						     GPollFD,
						     glue->num_gpollfds);
		if (glue->prev_gpollfds == NULL) {
			DBG_ERR("talloc_realloc failed\n");
			return false;
		}
	}
	glue->num_prev_gpollfds = glue->num_gpollfds;
	if (glue->num_gpollfds > 0) {
		memcpy(glue->prev_gpollfds, glue->gpollfds,
		       sizeof(GPollFD) * glue->num_gpollfds);
		memset(glue->gpollfds, 0, sizeof(GPollFD) * glue->num_gpollfds);
	}

	return true;
}

static bool get_glib_fds_and_timeout(struct tevent_glib_glue *glue)
{
	bool ok;
	gint num_fds;

	ok = save_current_fdset(glue);
	if (!ok) {
		return false;
	}

	while (true) {
		num_fds = g_main_context_query(glue->gmain_ctx,
					       glue->gpriority,
					       &glue->gtimeout,
					       glue->gpollfds,
					       glue->num_gpollfds);
		if (num_fds == glue->num_gpollfds) {
			break;
		}
		glue->gpollfds = talloc_realloc(glue,
						glue->gpollfds,
						GPollFD,
						num_fds);
		if (num_fds > 0 && glue->gpollfds == NULL) {
			DBG_ERR("talloc_realloc failed\n");
			return false;
		}
		glue->num_gpollfds = num_fds;
	};

	if (glue->num_gpollfds > 0) {
		qsort(glue->gpollfds,
		      num_fds,
		      sizeof(GPollFD),
		      glib_fd_cmp_func);
	}

	DBG_DEBUG("num fds: %d, timeout: %d ms\n",
		  num_fds, glue->gtimeout);

	return true;
}

static bool tevent_glib_update_events(struct tevent_glib_glue *glue)
{
	uint64_t microsec;
	struct timeval tv;
	bool ok;

	ok = cmp_gfds(glue,
		      glue->gpollfds,
		      glue->prev_gpollfds,
		      glue->num_gpollfds,
		      glue->num_prev_gpollfds,
		      glib_fd_cmp_func,
		      match_gfd_cb,
		      new_gfd_cb,
		      remove_gfd_cb);
	if (!ok) {
		return false;
	}

	TALLOC_FREE(glue->timer);

	if (glue->gtimeout == -1) {
		return true;
	}

	if (glue->gtimeout == 0) {
		/*
		 * glue->gtimeout is 0 if g_main_context_query() returned
		 * timeout=0. That means there are pending events ready to be
		 * dispatched. We only want to run one event handler per loop
		 * iteration, so we schedule an immediate event to run it in the
		 * next iteration.
		 */
		if (glue->scheduled_im) {
			return true;
		}
		tevent_schedule_immediate(glue->im,
					  glue->ev,
					  tevent_glib_im_handler,
					  glue);
		glue->scheduled_im = true;
		return true;
	}

	microsec = glue->gtimeout * 1000;
	tv = tevent_timeval_current_ofs(microsec / 1000000,
					microsec % 1000000);

	glue->timer = tevent_add_timer(glue->ev,
				       glue,
				       tv,
				       tevent_glib_timer_handler,
				       glue);
	if (glue->timer == NULL) {
		DBG_ERR("tevent_add_timer failed\n");
		return false;
	}

	return true;
}

static void tevent_glib_retry_timer(struct tevent_context *ev,
				    struct tevent_timer *te,
				    struct timeval current_time,
				    void *private_data)
{
	struct tevent_glib_glue *glue = talloc_get_type_abort(
		private_data, struct tevent_glib_glue);

	glue->acquire_retry_timer = NULL;
	(void)tevent_glib_prepare(glue);
}

/**
 * Fetch glib event sources and add them to tevent
 *
 * Fetch glib event sources and attach corresponding tevent events to our tevent
 * context. get_glib_fds_and_timeout() gets the relevant glib event sources: the
 * set of active fds and the next timer. tevent_glib_update_events() then
 * translates those to tevent and creates tevent events.
 *
 * When called, the thread must NOT be the owner to the glib main
 * context. tevent_glib_prepare() is either the first function when the
 * tevent_glib_glue is created, or after tevent_glib_process() has been called
 * to process pending event, which will have ceased ownership.
 **/
static bool tevent_glib_prepare(struct tevent_glib_glue *glue)
{
	bool ok;
	gboolean gok;

	if (glue->quit) {
		/* Set via samba_tevent_glib_glue_quit() */
		return true;
	}

	if (glue->acquire_retry_timer != NULL) {
		/*
		 * We're still waiting on the below g_main_context_acquire() to
		 * succeed, just return.
		 */
		return true;
	}

	if (glue->gmain_owner) {
		g_main_context_release(glue->gmain_ctx);
		glue->gmain_owner = false;
	}

	gok = g_main_context_acquire(glue->gmain_ctx);
	if (!gok) {
		DBG_ERR("couldn't acquire g_main_context\n");

		/*
		 * Ensure no tevent event fires while we're not the gmain
		 * context owner. The event handler would call
		 * tevent_glib_process() and that expects being the owner of the
		 * context.
		 */
		ok = tevent_glib_glue_reinit(glue);
		if (!ok) {
			DBG_ERR("tevent_glib_glue_reinit failed\n");
			samba_tevent_glib_glue_quit(glue);
			return false;
		}

		glue->acquire_retry_timer = tevent_add_timer(
			glue->ev,
			glue,
			tevent_timeval_current_ofs(0, 1000),
			tevent_glib_retry_timer,
			glue);
		if (glue->acquire_retry_timer == NULL) {
			DBG_ERR("tevent_add_timer failed\n");
			samba_tevent_glib_glue_quit(glue);
			return false;
		}
		return true;
	}
	glue->gmain_owner = true;

	/*
	 * Discard "ready" return value from g_main_context_prepare(). We don't
	 * want to dispatch events here, thats only done in from the tevent loop.
	 */
	(void)g_main_context_prepare(glue->gmain_ctx, &glue->gpriority);

	ok = get_glib_fds_and_timeout(glue);
	if (!ok) {
		DBG_ERR("get_glib_fds_and_timeout failed\n");
		samba_tevent_glib_glue_quit(glue);
		return false;
	}

	ok = tevent_glib_update_events(glue);
	if (!ok) {
		DBG_ERR("tevent_glib_update_events failed\n");
		samba_tevent_glib_glue_quit(glue);
		return false;
	}

	return true;
}

/**
 * Process pending glib events
 *
 * tevent_glib_process() gets called to process pending glib events via
 * g_main_context_check() and then g_main_context_dispatch().
 *
 * After pending event handlers are dispatched, we rearm the glib glue event
 * handlers in tevent by calling tevent_glib_prepare().
 *
 * When tevent_glib_process() is called the thread must own the glib
 * gmain_ctx. That is achieved by tevent_glib_prepare() being the only function
 * that acuires context ownership.
 *
 * To give other threads that are blocked on g_main_context_acquire(gmain_ctx) a
 * chance to acquire context ownership (eg needed to attach event sources), we
 * release context ownership before calling tevent_glib_prepare() which will
 * acquire it again.
 */
static bool tevent_glib_process(struct tevent_glib_glue *glue)
{
	bool ok;

	DBG_DEBUG("tevent_glib_process\n");

	/*
	 * Ignore the "sources_ready" return from g_main_context_check(). glib
	 * itself also ignores it in g_main_context_iterate(). In theory only
	 * calling g_main_context_dispatch() if g_main_context_check() returns
	 * true should work, but older glib versions had a bug where
	 * g_main_context_check() returns false even though events are pending.
	 *
	 * https://bugzilla.gnome.org/show_bug.cgi?id=11059
	 */
	(void)g_main_context_check(glue->gmain_ctx,
				   glue->gpriority,
				   glue->gpollfds,
				   glue->num_gpollfds);

	g_main_context_dispatch(glue->gmain_ctx);

	ok = tevent_glib_prepare(glue);
	if (!ok) {
		return false;
	}
	glue->skip_glib_refresh = true;
	return true;
}

static void tevent_glib_glue_trace_callback(enum tevent_trace_point point,
					    void *private_data)
{
	struct tevent_glib_glue *glue = talloc_get_type_abort(
		private_data, struct tevent_glib_glue);

	if (point == TEVENT_TRACE_AFTER_LOOP_ONCE) {
		if (!glue->skip_glib_refresh) {
			tevent_glib_prepare(glue);
		}
		glue->skip_glib_refresh = false;
	}

	/* chain previous handler */
	if (glue->prev_tevent_trace_cb != NULL) {
		glue->prev_tevent_trace_cb(point, glue->prev_tevent_trace_data);
	}
}

static void tevent_glib_glue_cleanup(struct tevent_glib_glue *glue)
{
	size_t n = talloc_array_length(glue->fd_map);
	size_t i;

	for (i = 0; i < n; i++) {
		TALLOC_FREE(glue->fd_map[i]->fd_event);
		TALLOC_FREE(glue->fd_map[i]);
	}

	tevent_set_trace_callback(glue->ev,
				  glue->prev_tevent_trace_cb,
				  glue->prev_tevent_trace_data);
	glue->prev_tevent_trace_cb = NULL;
	glue->prev_tevent_trace_data = NULL;

	TALLOC_FREE(glue->fd_map);
	glue->num_maps = 0;

	TALLOC_FREE(glue->gpollfds);
	glue->num_gpollfds = 0;

	TALLOC_FREE(glue->prev_gpollfds);
	glue->num_prev_gpollfds = 0;

	TALLOC_FREE(glue->timer);
	TALLOC_FREE(glue->acquire_retry_timer);
	TALLOC_FREE(glue->im);

	/*
	 * These are not really needed, but let's wipe the slate clean.
	 */
	glue->skip_glib_refresh = false;
	glue->gtimeout = 0;
	glue->gpriority = 0;
}

static bool tevent_glib_glue_reinit(struct tevent_glib_glue *glue)
{
	tevent_glib_glue_cleanup(glue);

	glue->im = tevent_create_immediate(glue);
	if (glue->im == NULL) {
		return false;
	}

	tevent_get_trace_callback(glue->ev,
				  &glue->prev_tevent_trace_cb,
				  &glue->prev_tevent_trace_data);
	tevent_set_trace_callback(glue->ev,
				  tevent_glib_glue_trace_callback,
				  glue);

	return true;
}

void samba_tevent_glib_glue_quit(struct tevent_glib_glue *glue)
{
	tevent_glib_glue_cleanup(glue);
	glue->quit = true;
	return;
}

struct tevent_glib_glue *samba_tevent_glib_glue_create(TALLOC_CTX *mem_ctx,
						       struct tevent_context *ev,
						       GMainContext *gmain_ctx)
{
	bool ok;
	struct tevent_glib_glue *glue = NULL;

	glue = talloc_zero(mem_ctx, struct tevent_glib_glue);
	if (glue == NULL) {
		DBG_ERR("talloc_zero failed\n");
		return NULL;
	}

	*glue = (struct tevent_glib_glue) {
		.ev = ev,
		.gmain_ctx = gmain_ctx,
	};

	glue->im = tevent_create_immediate(glue);

	tevent_get_trace_callback(glue->ev,
				  &glue->prev_tevent_trace_cb,
				  &glue->prev_tevent_trace_data);
	tevent_set_trace_callback(glue->ev,
				  tevent_glib_glue_trace_callback,
				  glue);

	ok = tevent_glib_prepare(glue);
	if (!ok) {
		TALLOC_FREE(glue);
		return NULL;
	}

	return glue;
}

#else /* HAVE_GLIB */

struct tevent_glib_glue *samba_tevent_glib_glue_create(TALLOC_CTX *mem_ctx,
						       struct tevent_context *ev,
						       GMainContext *gmain_ctx)
{
	errno = ENOSYS;
	return NULL;
}

void samba_tevent_glib_glue_quit(struct tevent_glib_glue *glue)
{
	return;
}
#endif /* HAVE_GLIB */
