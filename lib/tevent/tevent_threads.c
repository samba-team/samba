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

#if defined(HAVE_PTHREAD)
#include <pthread.h>

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
		 * are processed, we need to reshedule
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
	(void)write(tp->write_fd, &c, 1);

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
