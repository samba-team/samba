/*
   Infrastructure for event context wrappers

   Copyright (C) Stefan Metzmacher 2014

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
#ifdef HAVE_PTHREAD
#include "system/threads.h"
#endif
#define TEVENT_DEPRECATED 1
#include "tevent.h"
#include "tevent_internal.h"
#include "tevent_util.h"

static int tevent_wrapper_glue_context_init(struct tevent_context *ev)
{
	tevent_abort(ev, "tevent_wrapper_glue_context_init() called");
	errno = ENOSYS;
	return -1;
}

static struct tevent_fd *tevent_wrapper_glue_add_fd(struct tevent_context *ev,
						    TALLOC_CTX *mem_ctx,
						    int fd, uint16_t flags,
						    tevent_fd_handler_t handler,
						    void *private_data,
						    const char *handler_name,
						    const char *location)
{
	struct tevent_wrapper_glue *glue = ev->wrapper.glue;
	struct tevent_fd *fde = NULL;

	if (glue->destroyed) {
		tevent_abort(ev, "add_fd wrapper use after free");
		return NULL;
	}

	if (glue->main_ev == NULL) {
		errno = EINVAL;
		return NULL;
	}

	fde = _tevent_add_fd(glue->main_ev, mem_ctx, fd, flags,
			     handler, private_data,
			     handler_name, location);
	if (fde == NULL) {
		return NULL;
	}

	fde->wrapper = glue;

	return fde;
}

static struct tevent_timer *tevent_wrapper_glue_add_timer(struct tevent_context *ev,
							  TALLOC_CTX *mem_ctx,
							  struct timeval next_event,
							  tevent_timer_handler_t handler,
							  void *private_data,
							  const char *handler_name,
							  const char *location)
{
	struct tevent_wrapper_glue *glue = ev->wrapper.glue;
	struct tevent_timer *te = NULL;

	if (glue->destroyed) {
		tevent_abort(ev, "add_timer wrapper use after free");
		return NULL;
	}

	if (glue->main_ev == NULL) {
		errno = EINVAL;
		return NULL;
	}

	te = _tevent_add_timer(glue->main_ev, mem_ctx, next_event,
			       handler, private_data,
			       handler_name, location);
	if (te == NULL) {
		return NULL;
	}

	te->wrapper = glue;

	return te;
}

static void tevent_wrapper_glue_schedule_immediate(struct tevent_immediate *im,
						   struct tevent_context *ev,
						   tevent_immediate_handler_t handler,
						   void *private_data,
						   const char *handler_name,
						   const char *location)
{
	struct tevent_wrapper_glue *glue = ev->wrapper.glue;

	if (glue->destroyed) {
		tevent_abort(ev, "scheduke_immediate wrapper use after free");
		return;
	}

	if (glue->main_ev == NULL) {
		tevent_abort(ev, location);
		errno = EINVAL;
		return;
	}

	_tevent_schedule_immediate(im, glue->main_ev,
				   handler, private_data,
				   handler_name, location);

	im->wrapper = glue;

	return;
}

static struct tevent_signal *tevent_wrapper_glue_add_signal(struct tevent_context *ev,
							    TALLOC_CTX *mem_ctx,
							    int signum, int sa_flags,
							    tevent_signal_handler_t handler,
							    void *private_data,
							    const char *handler_name,
							    const char *location)
{
	struct tevent_wrapper_glue *glue = ev->wrapper.glue;
	struct tevent_signal *se = NULL;

	if (glue->destroyed) {
		tevent_abort(ev, "add_signal wrapper use after free");
		return NULL;
	}

	if (glue->main_ev == NULL) {
		errno = EINVAL;
		return NULL;
	}

	se = _tevent_add_signal(glue->main_ev, mem_ctx,
				signum, sa_flags,
				handler, private_data,
				handler_name, location);
	if (se == NULL) {
		return NULL;
	}

	se->wrapper = glue;

	return se;
}

static int tevent_wrapper_glue_loop_once(struct tevent_context *ev, const char *location)
{
	tevent_abort(ev, "tevent_wrapper_glue_loop_once() called");
	errno = ENOSYS;
	return -1;
}

static int tevent_wrapper_glue_loop_wait(struct tevent_context *ev, const char *location)
{
	tevent_abort(ev, "tevent_wrapper_glue_loop_wait() called");
	errno = ENOSYS;
	return -1;
}

static const struct tevent_ops tevent_wrapper_glue_ops = {
	.context_init		= tevent_wrapper_glue_context_init,
	.add_fd			= tevent_wrapper_glue_add_fd,
	.set_fd_close_fn	= tevent_common_fd_set_close_fn,
	.get_fd_flags		= tevent_common_fd_get_flags,
	.set_fd_flags		= tevent_common_fd_set_flags,
	.add_timer		= tevent_wrapper_glue_add_timer,
	.schedule_immediate	= tevent_wrapper_glue_schedule_immediate,
	.add_signal		= tevent_wrapper_glue_add_signal,
	.loop_once		= tevent_wrapper_glue_loop_once,
	.loop_wait		= tevent_wrapper_glue_loop_wait,
};

static int tevent_wrapper_context_destructor(struct tevent_context *wrap_ev)
{
	struct tevent_wrapper_glue *glue = wrap_ev->wrapper.glue;
	struct tevent_context *main_ev = NULL;
	struct tevent_fd *fd = NULL, *fn = NULL;
	struct tevent_timer *te = NULL, *tn = NULL;
	struct tevent_immediate *ie = NULL, *in = NULL;
	struct tevent_signal *se = NULL, *sn = NULL;
#ifdef HAVE_PTHREAD
	struct tevent_threaded_context *tctx = NULL, *tctxn = NULL;
#endif

	if (glue == NULL) {
		tevent_abort(wrap_ev,
			"tevent_wrapper_context_destructor() active on main");
		/* static checker support, return below is never reached */
		return -1;
	}

	if (glue->destroyed && glue->busy) {
		tevent_common_check_double_free(wrap_ev,
			"tevent_context wrapper double free");
	}
	glue->destroyed = true;

	if (glue->busy) {
		return -1;
	}

	main_ev = glue->main_ev;
	if (main_ev == NULL) {
		return 0;
	}

	tevent_debug(wrap_ev, TEVENT_DEBUG_TRACE,
		     "Destroying wrapper context %p \"%s\"\n",
		     wrap_ev, talloc_get_name(glue->private_state));

	glue->main_ev = NULL;
	DLIST_REMOVE(main_ev->wrapper.list, glue);

#ifdef HAVE_PTHREAD
	for (tctx = main_ev->threaded_contexts; tctx != NULL; tctx = tctxn) {
		int ret;

		tctxn = tctx->next;

		if (tctx->event_ctx != glue->wrap_ev) {
			continue;
		}

		ret = pthread_mutex_lock(&tctx->event_ctx_mutex);
		if (ret != 0) {
			abort();
		}

		/*
		 * Indicate to the thread that the tevent_context is
		 * gone. The counterpart of this is in
		 * _tevent_threaded_schedule_immediate, there we read
		 * this under the threaded_context's mutex.
		 */

		tctx->event_ctx = NULL;

		ret = pthread_mutex_unlock(&tctx->event_ctx_mutex);
		if (ret != 0) {
			abort();
		}

		DLIST_REMOVE(main_ev->threaded_contexts, tctx);
	}
#endif

	for (fd = main_ev->fd_events; fd; fd = fn) {
		fn = fd->next;

		if (fd->wrapper != glue) {
			continue;
		}

		tevent_fd_set_flags(fd, 0);

		fd->wrapper = NULL;
		fd->event_ctx = NULL;
		DLIST_REMOVE(main_ev->fd_events, fd);
	}

	for (te = main_ev->timer_events; te; te = tn) {
		tn = te->next;

		if (te->wrapper != glue) {
			continue;
		}

		te->wrapper = NULL;
		te->event_ctx = NULL;

		if (main_ev->last_zero_timer == te) {
			main_ev->last_zero_timer = DLIST_PREV(te);
		}
		DLIST_REMOVE(main_ev->timer_events, te);
	}

	for (ie = main_ev->immediate_events; ie; ie = in) {
		in = ie->next;

		if (ie->wrapper != glue) {
			continue;
		}

		ie->wrapper = NULL;
		ie->event_ctx = NULL;
		ie->cancel_fn = NULL;
		DLIST_REMOVE(main_ev->immediate_events, ie);
	}

	for (se = main_ev->signal_events; se; se = sn) {
		sn = se->next;

		if (se->wrapper != glue) {
			continue;
		}

		se->wrapper = NULL;
		tevent_cleanup_pending_signal_handlers(se);
	}

	return 0;
}

struct tevent_context *_tevent_context_wrapper_create(struct tevent_context *main_ev,
						TALLOC_CTX *mem_ctx,
						const struct tevent_wrapper_ops *ops,
						void *pstate,
						size_t psize,
						const char *type,
						const char *location)
{
	void **ppstate = (void **)pstate;
	struct tevent_context *ev = NULL;

	if (main_ev->wrapper.glue != NULL) {
		/*
		 * stacking of wrappers is not supported
		 */
		tevent_debug(main_ev->wrapper.glue->main_ev, TEVENT_DEBUG_FATAL,
			     "%s: %s() stacking not allowed\n",
			     __func__, location);
		errno = EINVAL;
		return NULL;
	}

	if (main_ev->nesting.allowed) {
		/*
		 * wrappers conflict with nesting
		 */
		tevent_debug(main_ev, TEVENT_DEBUG_FATAL,
			     "%s: %s() conflicts with nesting\n",
			     __func__, location);
		errno = EINVAL;
		return NULL;
	}

	ev = talloc_zero(mem_ctx, struct tevent_context);
	if (ev == NULL) {
		return NULL;
	}
	ev->ops = &tevent_wrapper_glue_ops;

	ev->wrapper.glue = talloc_zero(ev, struct tevent_wrapper_glue);
	if (ev->wrapper.glue == NULL) {
		talloc_free(ev);
		return NULL;
	}

	talloc_set_destructor(ev, tevent_wrapper_context_destructor);

	ev->wrapper.glue->wrap_ev = ev;
	ev->wrapper.glue->main_ev = main_ev;
	ev->wrapper.glue->ops = ops;
	ev->wrapper.glue->private_state = talloc_zero_size(ev->wrapper.glue, psize);
	if (ev->wrapper.glue->private_state == NULL) {
		talloc_free(ev);
		return NULL;
	}
	talloc_set_name_const(ev->wrapper.glue->private_state, type);

	DLIST_ADD_END(main_ev->wrapper.list, ev->wrapper.glue);

	*ppstate = ev->wrapper.glue->private_state;
	return ev;
}

bool tevent_context_is_wrapper(struct tevent_context *ev)
{
	if (ev->wrapper.glue != NULL) {
		return true;
	}

	return false;
}

_PRIVATE_
struct tevent_context *tevent_wrapper_main_ev(struct tevent_context *ev)
{
	if (ev == NULL) {
		return NULL;
	}

	if (ev->wrapper.glue == NULL) {
		return ev;
	}

	return ev->wrapper.glue->main_ev;
}

/*
 * 32 stack elements should be more than enough
 *
 * e.g. Samba uses just 8 elements for [un]become_{root,user}()
 */
#define TEVENT_WRAPPER_STACK_SIZE 32

static struct tevent_wrapper_stack {
	const void *ev_ptr;
	const struct tevent_wrapper_glue *wrapper;
} wrapper_stack[TEVENT_WRAPPER_STACK_SIZE];

static size_t wrapper_stack_idx;

_PRIVATE_
void tevent_wrapper_push_use_internal(struct tevent_context *ev,
				      struct tevent_wrapper_glue *wrapper)
{
	/*
	 * ev and wrapper need to belong together!
	 * It's also fine to only have a raw ev
	 * without a wrapper.
	 */
	if (unlikely(ev->wrapper.glue != wrapper)) {
		tevent_abort(ev, "tevent_wrapper_push_use_internal() invalid arguments");
		return;
	}

	if (wrapper != NULL) {
		if (unlikely(wrapper->busy)) {
			tevent_abort(ev, "wrapper already busy!");
			return;
		}
		wrapper->busy = true;
	}

	if (unlikely(wrapper_stack_idx >= TEVENT_WRAPPER_STACK_SIZE)) {
		tevent_abort(ev, "TEVENT_WRAPPER_STACK_SIZE overflow");
		return;
	}

	wrapper_stack[wrapper_stack_idx] = (struct tevent_wrapper_stack) {
		.ev_ptr = ev,
		.wrapper = wrapper,
	};
	wrapper_stack_idx++;
}

_PRIVATE_
void tevent_wrapper_pop_use_internal(const struct tevent_context *__ev_ptr,
				     struct tevent_wrapper_glue *wrapper)
{
	struct tevent_context *main_ev = NULL;

	/*
	 * Note that __ev_ptr might a a stale pointer and should not
	 * be touched, we just compare the pointer value in order
	 * to enforce the stack order.
	 */

	if (wrapper != NULL) {
		main_ev = wrapper->main_ev;
	}

	if (unlikely(wrapper_stack_idx == 0)) {
		tevent_abort(main_ev, "tevent_wrapper stack already empty");
		return;
	}
	wrapper_stack_idx--;

	if (wrapper != NULL) {
		wrapper->busy = false;
	}

	if (wrapper_stack[wrapper_stack_idx].ev_ptr != __ev_ptr) {
		tevent_abort(main_ev, "tevent_wrapper_pop_use mismatch ev!");
		return;
	}
	if (wrapper_stack[wrapper_stack_idx].wrapper != wrapper) {
		tevent_abort(main_ev, "tevent_wrapper_pop_use mismatch wrap!");
		return;
	}

	if (wrapper == NULL) {
		return;
	}

	if (wrapper->destroyed) {
		/*
		 * Notice that we can't use TALLOC_FREE()
		 * here because wrapper is a talloc child
		 * of wrapper->wrap_ev.
		 */
		talloc_free(wrapper->wrap_ev);
	}
}

bool _tevent_context_push_use(struct tevent_context *ev,
			      const char *location)
{
	bool ok;

	if (ev->wrapper.glue == NULL) {
		tevent_wrapper_push_use_internal(ev, NULL);
		return true;
	}

	if (ev->wrapper.glue->main_ev == NULL) {
		return false;
	}

	tevent_wrapper_push_use_internal(ev, ev->wrapper.glue);
	ok = ev->wrapper.glue->ops->before_use(ev->wrapper.glue->wrap_ev,
					       ev->wrapper.glue->private_state,
					       ev->wrapper.glue->main_ev,
					       location);
	if (!ok) {
		tevent_wrapper_pop_use_internal(ev, ev->wrapper.glue);
		return false;
	}

	return true;
}

void _tevent_context_pop_use(struct tevent_context *ev,
			     const char *location)
{
	tevent_wrapper_pop_use_internal(ev, ev->wrapper.glue);

	if (ev->wrapper.glue == NULL) {
		return;
	}

	if (ev->wrapper.glue->main_ev == NULL) {
		return;
	}

	ev->wrapper.glue->ops->after_use(ev->wrapper.glue->wrap_ev,
					 ev->wrapper.glue->private_state,
					 ev->wrapper.glue->main_ev,
					 location);
}

bool tevent_context_same_loop(struct tevent_context *ev1,
			      struct tevent_context *ev2)
{
	struct tevent_context *main_ev1 = tevent_wrapper_main_ev(ev1);
	struct tevent_context *main_ev2 = tevent_wrapper_main_ev(ev2);

	if (main_ev1 == NULL) {
		return false;
	}

	if (main_ev1 == main_ev2) {
		return true;
	}

	return false;
}
