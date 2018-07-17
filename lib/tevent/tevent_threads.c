/*
   tevent event library.

   Copyright (C) Jeremy Allison 2015

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
#include "talloc.h"
#include "tevent.h"
#include "tevent_internal.h"
#include "tevent_util.h"

#ifdef HAVE_PTHREAD
#include "system/threads.h"

struct tevent_immediate_list {
	struct tevent_immediate_list *next, *prev;
	tevent_immediate_handler_t handler;
	struct tevent_immediate *im;
	void *private_ptr;
};

struct tevent_thread_proxy {
	pthread_mutex_t mutex;
	struct tevent_context *dest_ev_ctx;
	int read_fd;
	int write_fd;
	struct tevent_fd *pipe_read_fde;
	/* Pending events list. */
	struct tevent_immediate_list *im_list;
	/* Completed events list. */
	struct tevent_immediate_list *tofree_im_list;
	struct tevent_immediate *free_im;
};

static void free_im_list(struct tevent_immediate_list **pp_list_head)
{
	struct tevent_immediate_list *im_entry = NULL;
	struct tevent_immediate_list *im_next = NULL;

	for (im_entry = *pp_list_head; im_entry; im_entry = im_next) {
		im_next = im_entry->next;
		DLIST_REMOVE(*pp_list_head, im_entry);
		TALLOC_FREE(im_entry);
	}
}

static void free_list_handler(struct tevent_context *ev,
				struct tevent_immediate *im,
				void *private_ptr)
{
	struct tevent_thread_proxy *tp =
		talloc_get_type_abort(private_ptr, struct tevent_thread_proxy);
	int ret;

	ret = pthread_mutex_lock(&tp->mutex);
	if (ret != 0) {
		abort();
		/* Notreached. */
		return;
	}

	free_im_list(&tp->tofree_im_list);

	ret = pthread_mutex_unlock(&tp->mutex);
	if (ret != 0) {
		abort();
		/* Notreached. */
		return;
	}
}

static void schedule_immediate_functions(struct tevent_thread_proxy *tp)
{
	struct tevent_immediate_list *im_entry = NULL;
	struct tevent_immediate_list *im_next = NULL;

	for (im_entry = tp->im_list; im_entry; im_entry = im_next) {
		im_next = im_entry->next;
		DLIST_REMOVE(tp->im_list, im_entry);

		tevent_schedule_immediate(im_entry->im,
					tp->dest_ev_ctx,
					im_entry->handler,
					im_entry->private_ptr);

		/* Move from pending list to free list. */
		DLIST_ADD(tp->tofree_im_list, im_entry);
	}
	if (tp->tofree_im_list != NULL) {
		/*
		 * Once the current immediate events
		 * are processed, we need to reschedule
		 * ourselves to free them. This works
		 * as tevent_schedule_immediate()
		 * always adds events to the *END* of
		 * the immediate events list.
		 */
		tevent_schedule_immediate(tp->free_im,
					tp->dest_ev_ctx,
					free_list_handler,
					tp);
	}
}

static void pipe_read_handler(struct tevent_context *ev,
				struct tevent_fd *fde,
				uint16_t flags,
				void *private_ptr)
{
	struct tevent_thread_proxy *tp =
		talloc_get_type_abort(private_ptr, struct tevent_thread_proxy);
	ssize_t len = 64;
	int ret;

	ret = pthread_mutex_lock(&tp->mutex);
	if (ret != 0) {
		abort();
		/* Notreached. */
		return;
	}

	/*
	 * Clear out all data in the pipe. We
	 * don't really care if this returns -1.
	 */
	while (len == 64) {
		char buf[64];
		len = read(tp->read_fd, buf, 64);
	};

	schedule_immediate_functions(tp);

	ret = pthread_mutex_unlock(&tp->mutex);
	if (ret != 0) {
		abort();
		/* Notreached. */
		return;
	}
}

static int tevent_thread_proxy_destructor(struct tevent_thread_proxy *tp)
{
	int ret;

	ret = pthread_mutex_lock(&tp->mutex);
	if (ret != 0) {
		abort();
		/* Notreached. */
		return 0;
	}

	TALLOC_FREE(tp->pipe_read_fde);

	if (tp->read_fd != -1) {
		(void)close(tp->read_fd);
		tp->read_fd = -1;
	}
	if (tp->write_fd != -1) {
		(void)close(tp->write_fd);
		tp->write_fd = -1;
	}

	/* Hmmm. It's probably an error if we get here with
	   any non-NULL immediate entries.. */

	free_im_list(&tp->im_list);
	free_im_list(&tp->tofree_im_list);

	TALLOC_FREE(tp->free_im);

	ret = pthread_mutex_unlock(&tp->mutex);
	if (ret != 0) {
		abort();
		/* Notreached. */
		return 0;
	}

	ret = pthread_mutex_destroy(&tp->mutex);
	if (ret != 0) {
		abort();
		/* Notreached. */
		return 0;
	}

	return 0;
}

/*
 * Create a struct that can be passed to other threads
 * to allow them to signal the struct tevent_context *
 * passed in.
 */

struct tevent_thread_proxy *tevent_thread_proxy_create(
		struct tevent_context *dest_ev_ctx)
{
	int ret;
	int pipefds[2];
	struct tevent_thread_proxy *tp;

	if (dest_ev_ctx->wrapper.glue != NULL) {
		/*
		 * stacking of wrappers is not supported
		 */
		tevent_debug(dest_ev_ctx->wrapper.glue->main_ev,
			     TEVENT_DEBUG_FATAL,
			     "%s() not allowed on a wrapper context\n",
			     __func__);
		errno = EINVAL;
		return NULL;
	}

	tp = talloc_zero(dest_ev_ctx, struct tevent_thread_proxy);
	if (tp == NULL) {
		return NULL;
	}

	ret = pthread_mutex_init(&tp->mutex, NULL);
	if (ret != 0) {
		goto fail;
	}

	tp->dest_ev_ctx = dest_ev_ctx;
	tp->read_fd = -1;
	tp->write_fd = -1;

	talloc_set_destructor(tp, tevent_thread_proxy_destructor);

	ret = pipe(pipefds);
	if (ret == -1) {
		goto fail;
	}

	tp->read_fd = pipefds[0];
	tp->write_fd = pipefds[1];

	ret = ev_set_blocking(pipefds[0], false);
	if (ret != 0) {
		goto fail;
	}
	ret = ev_set_blocking(pipefds[1], false);
	if (ret != 0) {
		goto fail;
	}
	if (!ev_set_close_on_exec(pipefds[0])) {
		goto fail;
	}
	if (!ev_set_close_on_exec(pipefds[1])) {
		goto fail;
	}

	tp->pipe_read_fde = tevent_add_fd(dest_ev_ctx,
				tp,
				tp->read_fd,
				TEVENT_FD_READ,
				pipe_read_handler,
				tp);
	if (tp->pipe_read_fde == NULL) {
		goto fail;
	}

	/*
	 * Create an immediate event to free
	 * completed lists.
	 */
	tp->free_im = tevent_create_immediate(tp);
	if (tp->free_im == NULL) {
		goto fail;
	}

	return tp;

  fail:

	TALLOC_FREE(tp);
	return NULL;
}

/*
 * This function schedules an immediate event to be called with argument
 * *pp_private in the thread context of dest_ev_ctx. Caller doesn't
 * wait for activation to take place, this is simply fire-and-forget.
 *
 * pp_im must be a pointer to an immediate event talloced on
 * a context owned by the calling thread, or the NULL context.
 * Ownership of *pp_im will be transfered to the tevent library.
 *
 * pp_private can be null, or contents of *pp_private must be
 * talloc'ed memory on a context owned by the calling thread
 * or the NULL context. If non-null, ownership of *pp_private will
 * be transfered to the tevent library.
 *
 * If you want to return a message, have the destination use the
 * same function call to send back to the caller.
 */


void tevent_thread_proxy_schedule(struct tevent_thread_proxy *tp,
				  struct tevent_immediate **pp_im,
				  tevent_immediate_handler_t handler,
				  void *pp_private_data)
{
	struct tevent_immediate_list *im_entry;
	int ret;
	char c;
	ssize_t written;

	ret = pthread_mutex_lock(&tp->mutex);
	if (ret != 0) {
		abort();
		/* Notreached. */
		return;
	}

	if (tp->write_fd == -1) {
		/* In the process of being destroyed. Ignore. */
		goto end;
	}

	/* Create a new immediate_list entry. MUST BE ON THE NULL CONTEXT */
	im_entry = talloc_zero(NULL, struct tevent_immediate_list);
	if (im_entry == NULL) {
		goto end;
	}

	im_entry->handler = handler;
	im_entry->im = talloc_move(im_entry, pp_im);

	if (pp_private_data != NULL) {
		void **pptr = (void **)pp_private_data;
		im_entry->private_ptr = talloc_move(im_entry, pptr);
	}

	DLIST_ADD(tp->im_list, im_entry);

	/* And notify the dest_ev_ctx to wake up. */
	c = '\0';
	do {
		written = write(tp->write_fd, &c, 1);
	} while (written == -1 && errno == EINTR);

  end:

	ret = pthread_mutex_unlock(&tp->mutex);
	if (ret != 0) {
		abort();
		/* Notreached. */
	}
}
#else
/* !HAVE_PTHREAD */
struct tevent_thread_proxy *tevent_thread_proxy_create(
		struct tevent_context *dest_ev_ctx)
{
	errno = ENOSYS;
	return NULL;
}

void tevent_thread_proxy_schedule(struct tevent_thread_proxy *tp,
				  struct tevent_immediate **pp_im,
				  tevent_immediate_handler_t handler,
				  void *pp_private_data)
{
	;
}
#endif

static int tevent_threaded_context_destructor(
	struct tevent_threaded_context *tctx)
{
	struct tevent_context *main_ev = tevent_wrapper_main_ev(tctx->event_ctx);
	int ret;

	if (main_ev != NULL) {
		DLIST_REMOVE(main_ev->threaded_contexts, tctx);
	}

	/*
	 * We have to coordinate with _tevent_threaded_schedule_immediate's
	 * unlock of the event_ctx_mutex. We're in the main thread here,
	 * and we can be scheduled before the helper thread finalizes its
	 * call _tevent_threaded_schedule_immediate. This means we would
	 * pthreadpool_destroy a locked mutex, which is illegal.
	 */
	ret = pthread_mutex_lock(&tctx->event_ctx_mutex);
	if (ret != 0) {
		abort();
	}

	ret = pthread_mutex_unlock(&tctx->event_ctx_mutex);
	if (ret != 0) {
		abort();
	}

	ret = pthread_mutex_destroy(&tctx->event_ctx_mutex);
	if (ret != 0) {
		abort();
	}

	return 0;
}

struct tevent_threaded_context *tevent_threaded_context_create(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev)
{
#ifdef HAVE_PTHREAD
	struct tevent_context *main_ev = tevent_wrapper_main_ev(ev);
	struct tevent_threaded_context *tctx;
	int ret;

	ret = tevent_common_wakeup_init(main_ev);
	if (ret != 0) {
		errno = ret;
		return NULL;
	}

	tctx = talloc(mem_ctx, struct tevent_threaded_context);
	if (tctx == NULL) {
		return NULL;
	}
	tctx->event_ctx = ev;

	ret = pthread_mutex_init(&tctx->event_ctx_mutex, NULL);
	if (ret != 0) {
		TALLOC_FREE(tctx);
		return NULL;
	}

	DLIST_ADD(main_ev->threaded_contexts, tctx);
	talloc_set_destructor(tctx, tevent_threaded_context_destructor);

	return tctx;
#else
	errno = ENOSYS;
	return NULL;
#endif
}

static int tevent_threaded_schedule_immediate_destructor(struct tevent_immediate *im)
{
	if (im->event_ctx != NULL) {
		abort();
	}
	return 0;
}

void _tevent_threaded_schedule_immediate(struct tevent_threaded_context *tctx,
					 struct tevent_immediate *im,
					 tevent_immediate_handler_t handler,
					 void *private_data,
					 const char *handler_name,
					 const char *location)
{
#ifdef HAVE_PTHREAD
	const char *create_location = im->create_location;
	struct tevent_context *main_ev = NULL;
	struct tevent_wrapper_glue *glue = NULL;
	int ret, wakeup_fd;

	ret = pthread_mutex_lock(&tctx->event_ctx_mutex);
	if (ret != 0) {
		abort();
	}

	if (tctx->event_ctx == NULL) {
		/*
		 * Our event context is already gone.
		 */
		ret = pthread_mutex_unlock(&tctx->event_ctx_mutex);
		if (ret != 0) {
			abort();
		}
		return;
	}

	glue = tctx->event_ctx->wrapper.glue;

	if ((im->event_ctx != NULL) || (handler == NULL)) {
		abort();
	}
	if (im->destroyed) {
		abort();
	}
	if (im->busy) {
		abort();
	}

	main_ev = tevent_wrapper_main_ev(tctx->event_ctx);

	*im = (struct tevent_immediate) {
		.event_ctx		= tctx->event_ctx,
		.wrapper		= glue,
		.handler		= handler,
		.private_data		= private_data,
		.handler_name		= handler_name,
		.create_location	= create_location,
		.schedule_location	= location,
	};

	/*
	 * Make sure the event won't be destroyed while
	 * it's part of the ev->scheduled_immediates list.
	 * _tevent_schedule_immediate() will reset the destructor
	 * in tevent_common_threaded_activate_immediate().
	 */
	talloc_set_destructor(im, tevent_threaded_schedule_immediate_destructor);

	ret = pthread_mutex_lock(&main_ev->scheduled_mutex);
	if (ret != 0) {
		abort();
	}

	DLIST_ADD_END(main_ev->scheduled_immediates, im);
	wakeup_fd = main_ev->wakeup_fd;

	ret = pthread_mutex_unlock(&main_ev->scheduled_mutex);
	if (ret != 0) {
		abort();
	}

	ret = pthread_mutex_unlock(&tctx->event_ctx_mutex);
	if (ret != 0) {
		abort();
	}

	/*
	 * We might want to wake up the main thread under the lock. We
	 * had a slightly similar situation in pthreadpool, changed
	 * with 1c4284c7395f23. This is not exactly the same, as the
	 * wakeup is only a last-resort thing in case the main thread
	 * is sleeping. Doing the wakeup under the lock can easily
	 * lead to a contended mutex, which is much more expensive
	 * than a noncontended one. So I'd opt for the lower footprint
	 * initially. Maybe we have to change that later.
	 */
	tevent_common_wakeup_fd(wakeup_fd);
#else
	/*
	 * tevent_threaded_context_create() returned NULL with ENOSYS...
	 */
	abort();
#endif
}

void tevent_common_threaded_activate_immediate(struct tevent_context *ev)
{
#ifdef HAVE_PTHREAD
	int ret;
	ret = pthread_mutex_lock(&ev->scheduled_mutex);
	if (ret != 0) {
		abort();
	}

	while (ev->scheduled_immediates != NULL) {
		struct tevent_immediate *im = ev->scheduled_immediates;
		struct tevent_immediate copy = *im;

		DLIST_REMOVE(ev->scheduled_immediates, im);

		tevent_debug(ev, TEVENT_DEBUG_TRACE,
			     "Schedule immediate event \"%s\": %p from thread into main\n",
			     im->handler_name, im);
		im->handler_name = NULL;
		_tevent_schedule_immediate(im,
					   ev,
					   copy.handler,
					   copy.private_data,
					   copy.handler_name,
					   copy.schedule_location);
	}

	ret = pthread_mutex_unlock(&ev->scheduled_mutex);
	if (ret != 0) {
		abort();
	}
#else
	/*
	 * tevent_threaded_context_create() returned NULL with ENOSYS...
	 */
	abort();
#endif
}
