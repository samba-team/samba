/*
 * Unix SMB/CIFS implementation.
 *
 * testing of some tevent_req aspects
 *
 * Copyright (C) Pavel Březina <pbrezina@redhat.com> 2021
 *
 *   ** NOTE! The following LGPL license applies to the tevent
 *   ** library. This does NOT imply that all of Samba is released
 *   ** under the LGPL
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <setjmp.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>

#include <talloc.h>
#include <tevent.h>
#include <cmocka.h>

struct test_ctx {
	struct tevent_context *ev;

	bool handler_skipped;
	bool reattach_reset;

	uint64_t (*get_tag)(const void *event);
	void (*set_tag)(void *event, uint64_t tag);
	uint64_t current_tag;

	bool attach;
	bool before_handler;
	bool handler_called;
	bool detach;
};

static void fd_handler(struct tevent_context *ev,
		       struct tevent_fd *fde,
		       uint16_t flags,
		       void *private_data)
{
	struct test_ctx *tctx = (struct test_ctx *)private_data;
	uint64_t tag = tevent_fd_get_tag(fde);
	assert_true(tctx->attach);
	assert_true(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);
	tctx->handler_called = true;
	assert_int_equal(tag, tctx->current_tag);
	return;
}

static void timer_handler(struct tevent_context *ev,
			  struct tevent_timer *te,
			  struct timeval current_time,
			  void *private_data)
{
	struct test_ctx *tctx = (struct test_ctx *)private_data;
	uint64_t tag = tevent_timer_get_tag(te);
	assert_true(tctx->attach);
	assert_true(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);
	tctx->handler_called = true;
	assert_int_equal(tag, tctx->current_tag);
	return;
}

static void signal_handler(struct tevent_context *ev,
			   struct tevent_signal *se,
			   int signum,
			   int count,
			   void *siginfo,
			   void *private_data)
{
	struct test_ctx *tctx = (struct test_ctx *)private_data;
	uint64_t tag = tevent_signal_get_tag(se);
	assert_true(tctx->attach);
	assert_true(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);
	tctx->handler_called = true;
	assert_int_equal(tag, tctx->current_tag);
	return;
}

static void immediate_handler(struct tevent_context *ctx,
			      struct tevent_immediate *im,
			      void *private_data)
{
	struct test_ctx *tctx = (struct test_ctx *)private_data;
	uint64_t tag = tevent_immediate_get_tag(im);
	assert_true(tctx->attach);
	assert_true(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);
	tctx->handler_called = true;
	assert_int_equal(tag, tctx->current_tag);
	return;
}

static void immediate_handler_reschedule(struct tevent_context *ctx,
					 struct tevent_immediate *im,
					 void *private_data)
{
	struct test_ctx *tctx = (struct test_ctx *)private_data;
	uint64_t tag = tevent_immediate_get_tag(im);
	assert_true(tctx->attach);
	assert_true(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);
	tctx->handler_called = true;
	assert_int_equal(tag, tctx->current_tag);

	assert_false(tctx->reattach_reset);
	tctx->reattach_reset = true;
	tevent_schedule_immediate(im, tctx->ev, immediate_handler, tctx);
	assert_false(tctx->reattach_reset);
	assert_false(tctx->handler_skipped);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);
	assert_int_not_equal(tag, tctx->current_tag);
	tag = tevent_immediate_get_tag(im);
	assert_int_equal(tag, tctx->current_tag);

	tctx->handler_skipped = true;
	tctx->reattach_reset = true;
	tevent_schedule_immediate(im, tctx->ev, immediate_handler, tctx);
	assert_false(tctx->reattach_reset);
	assert_false(tctx->handler_skipped);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);
	assert_int_not_equal(tag, tctx->current_tag);
	tag = tevent_immediate_get_tag(im);
	assert_int_equal(tag, tctx->current_tag);
}

static void fd_handler_free(struct tevent_context *ev,
			    struct tevent_fd *fde,
			    uint16_t flags,
			    void *private_data)
{
	struct test_ctx *tctx = (struct test_ctx *)private_data;
	uint64_t tag = tevent_fd_get_tag(fde);
	assert_true(tctx->attach);
	assert_true(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);
	tctx->handler_called = true;
	assert_int_equal(tag, tctx->current_tag);
	TALLOC_FREE(fde);
	assert_true(tctx->detach);
	return;
}

static void timer_handler_free(struct tevent_context *ev,
			       struct tevent_timer *te,
			       struct timeval current_time,
			       void *private_data)
{
	struct test_ctx *tctx = (struct test_ctx *)private_data;
	uint64_t tag = tevent_timer_get_tag(te);
	assert_true(tctx->attach);
	assert_true(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);
	tctx->handler_called = true;
	assert_int_equal(tag, tctx->current_tag);
	TALLOC_FREE(te);
	assert_true(tctx->detach);
	return;
}

static void signal_handler_free(struct tevent_context *ev,
				struct tevent_signal *se,
				int signum,
				int count,
				void *siginfo,
				void *private_data)
{
	struct test_ctx *tctx = (struct test_ctx *)private_data;
	uint64_t tag = tevent_signal_get_tag(se);
	assert_true(tctx->attach);
	assert_true(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);
	tctx->handler_called = true;
	assert_int_equal(tag, tctx->current_tag);
	TALLOC_FREE(se);
	assert_true(tctx->detach);
	return;
}

static void immediate_handler_free(struct tevent_context *ctx,
				   struct tevent_immediate *im,
				   void *private_data)
{
	struct test_ctx *tctx = (struct test_ctx *)private_data;
	uint64_t tag = tevent_immediate_get_tag(im);
	assert_true(tctx->attach);
	assert_true(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);
	tctx->handler_called = true;
	assert_int_equal(tag, tctx->current_tag);
	TALLOC_FREE(im);
	assert_true(tctx->detach);
	return;
}

static void trace_event_cb(void *event,
			   enum tevent_event_trace_point point,
			   void *private_data)
{
	struct test_ctx *tctx = (struct test_ctx *)private_data;
	uint64_t tag = tctx->get_tag(event);

	switch (point) {
	case TEVENT_EVENT_TRACE_ATTACH:
		if (tctx->reattach_reset) {
			assert_true(tctx->attach);
			assert_true(tctx->detach);
			tctx->attach = false;
			tctx->before_handler = false;
			tctx->handler_called = false;
			tctx->detach = false;
			tctx->handler_skipped = false;
			tctx->reattach_reset = false;
		}
		assert_false(tctx->attach);
		assert_false(tctx->before_handler);
		assert_false(tctx->handler_called);
		assert_false(tctx->detach);
		tctx->attach = true;
		assert_int_equal(tag, tctx->current_tag);
		tag = ++tctx->current_tag;
		tctx->set_tag(event, tag);
		break;
	case TEVENT_EVENT_TRACE_BEFORE_HANDLER:
		assert_true(tctx->attach);
		assert_false(tctx->before_handler);
		assert_false(tctx->handler_called);
		assert_false(tctx->detach);
		tctx->before_handler = true;
		assert_int_equal(tag, tctx->current_tag);
		break;
	case TEVENT_EVENT_TRACE_DETACH:
		assert_true(tctx->attach);
		if (tctx->handler_skipped) {
			assert_false(tctx->before_handler);
			assert_false(tctx->handler_called);
		} else {
			assert_true(tctx->before_handler);
			assert_true(tctx->handler_called);
		}
		assert_false(tctx->detach);
		tctx->detach = true;
		assert_int_equal(tag, tctx->current_tag);
		break;
	}
}

static int test_setup(void **state)
{
	struct test_ctx *tctx;

	tctx = talloc_zero(NULL, struct test_ctx);
	assert_non_null(tctx);

	tctx->ev = tevent_context_init(tctx);
	assert_non_null(tctx->ev);

	*state = tctx;
	return 0;
}

static int test_teardown(void **state)
{
	struct test_ctx *tctx = (struct test_ctx *)(*state);
	tctx->get_tag = NULL;
	tctx->set_tag = NULL;
	tevent_set_trace_fd_callback(tctx->ev, NULL, NULL);
	tevent_set_trace_timer_callback(tctx->ev, NULL, NULL);
	tevent_set_trace_signal_callback(tctx->ev, NULL, NULL);
	tevent_set_trace_immediate_callback(tctx->ev, NULL, NULL);
	TALLOC_FREE(tctx);
	return 0;
}

static uint64_t fd_get_tag(const void *_event)
{
	const struct tevent_fd *event =
		(const struct tevent_fd *)_event;

	return tevent_fd_get_tag(event);
}

static void fd_set_tag(void *_event, uint64_t tag)
{
	struct tevent_fd *event =
		(struct tevent_fd *)_event;

	tevent_fd_set_tag(event, tag);
}

static uint64_t timer_get_tag(const void *_event)
{
	const struct tevent_timer *event =
		(const struct tevent_timer *)_event;

	return tevent_timer_get_tag(event);
}

static void timer_set_tag(void *_event, uint64_t tag)
{
	struct tevent_timer *event =
		(struct tevent_timer *)_event;

	tevent_timer_set_tag(event, tag);
}

static uint64_t signal_get_tag(const void *_event)
{
	const struct tevent_signal *event =
		(const struct tevent_signal *)_event;

	return tevent_signal_get_tag(event);
}

static void signal_set_tag(void *_event, uint64_t tag)
{
	struct tevent_signal *event =
		(struct tevent_signal *)_event;

	tevent_signal_set_tag(event, tag);
}

static uint64_t immediate_get_tag(const void *_event)
{
	const struct tevent_immediate *event =
		(const struct tevent_immediate *)_event;

	return tevent_immediate_get_tag(event);
}

static void immediate_set_tag(void *_event, uint64_t tag)
{
	struct tevent_immediate *event =
		(struct tevent_immediate *)_event;

	tevent_immediate_set_tag(event, tag);
}

static void test_trace_event_fd__loop(void **state)
{
	struct test_ctx *tctx = (struct test_ctx *)(*state);
	struct tevent_fd *fde;

	tctx->get_tag = fd_get_tag;
	tctx->set_tag = fd_set_tag;
	tevent_set_trace_fd_callback(tctx->ev, (tevent_trace_fd_callback_t)trace_event_cb, tctx);

	assert_false(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	fde = tevent_add_fd(tctx->ev, tctx, 0, TEVENT_FD_WRITE, fd_handler, tctx);
	assert_non_null(fde);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	TEVENT_FD_WRITEABLE(fde);
	tevent_loop_once(tctx->ev);
	assert_true(tctx->attach);
	assert_true(tctx->before_handler);
	assert_true(tctx->handler_called);
	assert_false(tctx->detach);

	TALLOC_FREE(fde);
	assert_true(tctx->attach);
	assert_true(tctx->before_handler);
	assert_true(tctx->handler_called);
	assert_true(tctx->detach);
}

static void test_trace_event_fd__reset(void **state)
{
	struct test_ctx *tctx = (struct test_ctx *)(*state);
	struct tevent_fd *fde;

	tctx->get_tag = fd_get_tag;
	tctx->set_tag = fd_set_tag;
	tevent_set_trace_fd_callback(tctx->ev, (tevent_trace_fd_callback_t)trace_event_cb, tctx);

	assert_false(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	fde = tevent_add_fd(tctx->ev, tctx, 0, TEVENT_FD_WRITE, fd_handler, tctx);
	assert_non_null(fde);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	tctx->handler_skipped = true;
	tevent_re_initialise(tctx->ev);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_true(tctx->detach);
}

static void test_trace_event_fd__free(void **state)
{
	struct test_ctx *tctx = (struct test_ctx *)(*state);
	struct tevent_fd *fde;

	tctx->get_tag = fd_get_tag;
	tctx->set_tag = fd_set_tag;
	tevent_set_trace_fd_callback(tctx->ev, (tevent_trace_fd_callback_t)trace_event_cb, tctx);

	assert_false(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	fde = tevent_add_fd(tctx->ev, tctx, 0, TEVENT_FD_WRITE, fd_handler, tctx);
	assert_non_null(fde);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	tctx->handler_skipped = true;
	TALLOC_FREE(fde);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_true(tctx->detach);
}

static void test_trace_event_fd__free_in_handler(void **state)
{
	struct test_ctx *tctx = (struct test_ctx *)(*state);
	struct tevent_fd *fde;

	tctx->get_tag = fd_get_tag;
	tctx->set_tag = fd_set_tag;
	tevent_set_trace_fd_callback(tctx->ev, (tevent_trace_fd_callback_t)trace_event_cb, tctx);

	assert_false(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	fde = tevent_add_fd(tctx->ev, tctx, 0, TEVENT_FD_WRITE, fd_handler_free, tctx);
	assert_non_null(fde);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	TEVENT_FD_WRITEABLE(fde);
	tevent_loop_once(tctx->ev);
	assert_true(tctx->attach);
	assert_true(tctx->before_handler);
	assert_true(tctx->handler_called);
	assert_true(tctx->detach);
}

static void test_trace_event_timer__loop(void **state)
{
	struct test_ctx *tctx = (struct test_ctx *)(*state);
	struct tevent_timer *te;
	struct timeval next;

	tctx->get_tag = timer_get_tag;
	tctx->set_tag = timer_set_tag;
	tevent_set_trace_timer_callback(tctx->ev, (tevent_trace_timer_callback_t)trace_event_cb, tctx);

	assert_false(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	next = tevent_timeval_current();
	te = tevent_add_timer(tctx->ev, tctx, next, timer_handler, tctx);
	assert_non_null(te);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	tevent_loop_once(tctx->ev);
	assert_true(tctx->attach);
	assert_true(tctx->before_handler);
	assert_true(tctx->handler_called);
	/* timer events are self destructing after calling the handler */
	assert_true(tctx->detach);
}

static void test_trace_event_timer__reset(void **state)
{
	struct test_ctx *tctx = (struct test_ctx *)(*state);
	struct tevent_timer *te;
	struct timeval next;

	tctx->get_tag = timer_get_tag;
	tctx->set_tag = timer_set_tag;
	tevent_set_trace_timer_callback(tctx->ev, (tevent_trace_timer_callback_t)trace_event_cb, tctx);

	assert_false(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	next = tevent_timeval_current();
	te = tevent_add_timer(tctx->ev, tctx, next, timer_handler, tctx);
	assert_non_null(te);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);
	assert_true(tctx->attach);

	assert_false(tctx->reattach_reset);
	tctx->handler_skipped = true;
	tctx->reattach_reset = true;
	next = tevent_timeval_current();
	tevent_update_timer(te, next);
	assert_false(tctx->reattach_reset);
	assert_false(tctx->handler_skipped);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	tctx->handler_skipped = true;
	tevent_re_initialise(tctx->ev);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_true(tctx->detach);
}

static void test_trace_event_timer__free(void **state)
{
	struct test_ctx *tctx = (struct test_ctx *)(*state);
	struct tevent_timer *te;
	struct timeval next;

	tctx->get_tag = timer_get_tag;
	tctx->set_tag = timer_set_tag;
	tevent_set_trace_timer_callback(tctx->ev, (tevent_trace_timer_callback_t)trace_event_cb, tctx);

	assert_false(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	next = tevent_timeval_current();
	te = tevent_add_timer(tctx->ev, tctx, next, timer_handler, tctx);
	assert_non_null(te);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);
	assert_true(tctx->attach);

	tctx->handler_skipped = true;
	TALLOC_FREE(te);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_true(tctx->detach);
}

static void test_trace_event_timer__free_in_handler(void **state)
{
	struct test_ctx *tctx = (struct test_ctx *)(*state);
	struct tevent_timer *te;
	struct timeval next;

	tctx->get_tag = timer_get_tag;
	tctx->set_tag = timer_set_tag;
	tevent_set_trace_timer_callback(tctx->ev, (tevent_trace_timer_callback_t)trace_event_cb, tctx);

	assert_false(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	next = tevent_timeval_current();
	te = tevent_add_timer(tctx->ev, tctx, next, timer_handler_free, tctx);
	assert_non_null(te);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	tevent_loop_once(tctx->ev);
	assert_true(tctx->attach);
	assert_true(tctx->before_handler);
	assert_true(tctx->handler_called);
	assert_true(tctx->detach);
}

static void test_trace_event_signal__loop(void **state)
{
	struct test_ctx *tctx = (struct test_ctx *)(*state);
	struct tevent_signal *se;

	tctx->get_tag = signal_get_tag;
	tctx->set_tag = signal_set_tag;
	tevent_set_trace_signal_callback(tctx->ev, (tevent_trace_signal_callback_t)trace_event_cb, tctx);

	assert_false(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	se = tevent_add_signal(tctx->ev, tctx, SIGUSR1, 0, signal_handler, tctx);
	assert_non_null(se);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	kill(getpid(), SIGUSR1);
	tevent_loop_once(tctx->ev);
	assert_true(tctx->attach);
	assert_true(tctx->before_handler);
	assert_true(tctx->handler_called);
	assert_false(tctx->detach);

	TALLOC_FREE(se);
	assert_true(tctx->attach);
	assert_true(tctx->before_handler);
	assert_true(tctx->handler_called);
	assert_true(tctx->detach);
}

static void test_trace_event_signal__reset(void **state)
{
	struct test_ctx *tctx = (struct test_ctx *)(*state);
	struct tevent_signal *se;

	tctx->get_tag = signal_get_tag;
	tctx->set_tag = signal_set_tag;
	tevent_set_trace_signal_callback(tctx->ev, (tevent_trace_signal_callback_t)trace_event_cb, tctx);

	assert_false(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	se = tevent_add_signal(tctx->ev, tctx, SIGUSR1, 0, signal_handler, tctx);
	assert_non_null(se);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	tctx->handler_skipped = true;
	TALLOC_FREE(se);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_true(tctx->detach);
}

static void test_trace_event_signal__free(void **state)
{
	struct test_ctx *tctx = (struct test_ctx *)(*state);
	struct tevent_signal *se;

	tctx->get_tag = signal_get_tag;
	tctx->set_tag = signal_set_tag;
	tevent_set_trace_signal_callback(tctx->ev, (tevent_trace_signal_callback_t)trace_event_cb, tctx);

	assert_false(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	se = tevent_add_signal(tctx->ev, tctx, SIGUSR1, 0, signal_handler, tctx);
	assert_non_null(se);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	tctx->handler_skipped = true;
	TALLOC_FREE(se);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_true(tctx->detach);
}

static void test_trace_event_signal__free_in_handler(void **state)
{
	struct test_ctx *tctx = (struct test_ctx *)(*state);
	struct tevent_signal *se;

	tctx->get_tag = signal_get_tag;
	tctx->set_tag = signal_set_tag;
	tevent_set_trace_signal_callback(tctx->ev, (tevent_trace_signal_callback_t)trace_event_cb, tctx);

	assert_false(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	se = tevent_add_signal(tctx->ev, tctx, SIGUSR1, 0, signal_handler_free, tctx);
	assert_non_null(se);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	kill(getpid(), SIGUSR1);
	tevent_loop_once(tctx->ev);
	assert_true(tctx->attach);
	assert_true(tctx->before_handler);
	assert_true(tctx->handler_called);
	assert_true(tctx->detach);
}

static void test_trace_event_immediate__loop(void **state)
{
	struct test_ctx *tctx = (struct test_ctx *)(*state);
	struct tevent_immediate *im;

	tctx->get_tag = immediate_get_tag;
	tctx->set_tag = immediate_set_tag;
	tevent_set_trace_immediate_callback(tctx->ev, (tevent_trace_immediate_callback_t)trace_event_cb, tctx);

	assert_false(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	im = tevent_create_immediate(tctx);
	assert_non_null(im);

	assert_false(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	tevent_schedule_immediate(im, tctx->ev, immediate_handler, tctx);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	tevent_loop_once(tctx->ev);
	assert_true(tctx->attach);
	assert_true(tctx->before_handler);
	assert_true(tctx->handler_called);
	/* immediate events are self detaching */
	assert_true(tctx->detach);
}

static void test_trace_event_immediate__reset(void **state)
{
	struct test_ctx *tctx = (struct test_ctx *)(*state);
	struct tevent_immediate *im;

	tctx->get_tag = immediate_get_tag;
	tctx->set_tag = immediate_set_tag;
	tevent_set_trace_immediate_callback(tctx->ev, (tevent_trace_immediate_callback_t)trace_event_cb, tctx);

	assert_false(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	im = tevent_create_immediate(tctx);
	assert_non_null(im);

	assert_false(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	tevent_schedule_immediate(im, tctx->ev, immediate_handler, tctx);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	tctx->handler_skipped = true;
	tevent_re_initialise(tctx->ev);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_true(tctx->detach);
}

static void test_trace_event_immediate__free(void **state)
{
	struct test_ctx *tctx = (struct test_ctx *)(*state);
	struct tevent_immediate *im;

	tctx->get_tag = immediate_get_tag;
	tctx->set_tag = immediate_set_tag;
	tevent_set_trace_immediate_callback(tctx->ev, (tevent_trace_immediate_callback_t)trace_event_cb, tctx);

	assert_false(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	im = tevent_create_immediate(tctx);
	assert_non_null(im);

	assert_false(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	tevent_schedule_immediate(im, tctx->ev, immediate_handler, tctx);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	tctx->handler_skipped = true;
	TALLOC_FREE(im);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_true(tctx->detach);
}

static void test_trace_event_immediate__free_in_handler(void **state)
{
	struct test_ctx *tctx = (struct test_ctx *)(*state);
	struct tevent_immediate *im;

	tctx->get_tag = immediate_get_tag;
	tctx->set_tag = immediate_set_tag;
	tevent_set_trace_immediate_callback(tctx->ev, (tevent_trace_immediate_callback_t)trace_event_cb, tctx);

	assert_false(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	im = tevent_create_immediate(tctx);
	assert_non_null(im);

	assert_false(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	tevent_schedule_immediate(im, tctx->ev, immediate_handler_free, tctx);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	tevent_loop_once(tctx->ev);
	assert_true(tctx->attach);
	assert_true(tctx->before_handler);
	assert_true(tctx->handler_called);
	assert_true(tctx->detach);
}

static void test_trace_event_immediate__reschedule(void **state)
{
	struct test_ctx *tctx = (struct test_ctx *)(*state);
	struct tevent_immediate *im;

	tctx->get_tag = immediate_get_tag;
	tctx->set_tag = immediate_set_tag;
	tevent_set_trace_immediate_callback(tctx->ev, (tevent_trace_immediate_callback_t)trace_event_cb, tctx);

	assert_false(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	im = tevent_create_immediate(tctx);
	assert_non_null(im);

	assert_false(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	tevent_schedule_immediate(im, tctx->ev, immediate_handler, tctx);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	assert_false(tctx->reattach_reset);
	tctx->handler_skipped = true;
	tctx->reattach_reset = true;
	tevent_schedule_immediate(im, tctx->ev, immediate_handler_reschedule, tctx);
	assert_false(tctx->reattach_reset);
	assert_false(tctx->handler_skipped);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	tevent_loop_once(tctx->ev);
	assert_false(tctx->reattach_reset);
	assert_true(tctx->attach);
	assert_false(tctx->before_handler);
	assert_false(tctx->handler_called);
	assert_false(tctx->detach);

	tevent_loop_once(tctx->ev);
	assert_true(tctx->attach);
	assert_true(tctx->before_handler);
	assert_true(tctx->handler_called);
	/* immediate events are self detaching */
	assert_true(tctx->detach);
}

static void test_get_set_trace_fd_callback(void **state)
{
	struct test_ctx *tctx = (struct test_ctx *)(*state);
	tevent_trace_fd_callback_t cb;
	void *pvt;

	tevent_get_trace_fd_callback(tctx->ev, &cb, &pvt);
	assert_null(cb);
	assert_null(pvt);

	tevent_set_trace_fd_callback(tctx->ev, (tevent_trace_fd_callback_t)trace_event_cb, tctx);
	tevent_get_trace_fd_callback(tctx->ev, &cb, &pvt);
	assert_ptr_equal(cb, trace_event_cb);
	assert_ptr_equal(pvt, tctx);

	tevent_set_trace_fd_callback(tctx->ev, NULL, NULL);
	tevent_get_trace_fd_callback(tctx->ev, &cb, &pvt);
	assert_null(cb);
	assert_null(pvt);
}

static void test_get_set_trace_timer_callback(void **state)
{
	struct test_ctx *tctx = (struct test_ctx *)(*state);
	tevent_trace_timer_callback_t cb;
	void *pvt;

	tevent_get_trace_timer_callback(tctx->ev, &cb, &pvt);
	assert_null(cb);
	assert_null(pvt);

	tevent_set_trace_timer_callback(tctx->ev, (tevent_trace_timer_callback_t)trace_event_cb, tctx);
	tevent_get_trace_timer_callback(tctx->ev, &cb, &pvt);
	assert_ptr_equal(cb, trace_event_cb);
	assert_ptr_equal(pvt, tctx);

	tevent_set_trace_timer_callback(tctx->ev, NULL, NULL);
	tevent_get_trace_timer_callback(tctx->ev, &cb, &pvt);
	assert_null(cb);
	assert_null(pvt);
}

static void test_get_set_trace_signal_callback(void **state)
{
	struct test_ctx *tctx = (struct test_ctx *)(*state);
	tevent_trace_signal_callback_t cb;
	void *pvt;

	tevent_get_trace_signal_callback(tctx->ev, &cb, &pvt);
	assert_null(cb);
	assert_null(pvt);

	tevent_set_trace_signal_callback(tctx->ev, (tevent_trace_signal_callback_t)trace_event_cb, tctx);
	tevent_get_trace_signal_callback(tctx->ev, &cb, &pvt);
	assert_ptr_equal(cb, trace_event_cb);
	assert_ptr_equal(pvt, tctx);

	tevent_set_trace_signal_callback(tctx->ev, NULL, NULL);
	tevent_get_trace_signal_callback(tctx->ev, &cb, &pvt);
	assert_null(cb);
	assert_null(pvt);
}

static void test_get_set_trace_immediate_callback(void **state)
{
	struct test_ctx *tctx = (struct test_ctx *)(*state);
	tevent_trace_immediate_callback_t cb;
	void *pvt;

	tevent_get_trace_immediate_callback(tctx->ev, &cb, &pvt);
	assert_null(cb);
	assert_null(pvt);

	tevent_set_trace_immediate_callback(tctx->ev, (tevent_trace_immediate_callback_t)trace_event_cb, tctx);
	tevent_get_trace_immediate_callback(tctx->ev, &cb, &pvt);
	assert_ptr_equal(cb, trace_event_cb);
	assert_ptr_equal(pvt, tctx);

	tevent_set_trace_immediate_callback(tctx->ev, NULL, NULL);
	tevent_get_trace_immediate_callback(tctx->ev, &cb, &pvt);
	assert_null(cb);
	assert_null(pvt);
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_trace_event_fd__loop, test_setup, test_teardown),
		cmocka_unit_test_setup_teardown(test_trace_event_fd__reset, test_setup, test_teardown),
		cmocka_unit_test_setup_teardown(test_trace_event_fd__free, test_setup, test_teardown),
		cmocka_unit_test_setup_teardown(test_trace_event_fd__free_in_handler, test_setup, test_teardown),
		cmocka_unit_test_setup_teardown(test_trace_event_timer__loop, test_setup, test_teardown),
		cmocka_unit_test_setup_teardown(test_trace_event_timer__reset, test_setup, test_teardown),
		cmocka_unit_test_setup_teardown(test_trace_event_timer__free, test_setup, test_teardown),
		cmocka_unit_test_setup_teardown(test_trace_event_timer__free_in_handler, test_setup, test_teardown),
		cmocka_unit_test_setup_teardown(test_trace_event_signal__loop, test_setup, test_teardown),
		cmocka_unit_test_setup_teardown(test_trace_event_signal__reset, test_setup, test_teardown),
		cmocka_unit_test_setup_teardown(test_trace_event_signal__free, test_setup, test_teardown),
		cmocka_unit_test_setup_teardown(test_trace_event_signal__free_in_handler, test_setup, test_teardown),
		cmocka_unit_test_setup_teardown(test_trace_event_immediate__loop, test_setup, test_teardown),
		cmocka_unit_test_setup_teardown(test_trace_event_immediate__reset, test_setup, test_teardown),
		cmocka_unit_test_setup_teardown(test_trace_event_immediate__free, test_setup, test_teardown),
		cmocka_unit_test_setup_teardown(test_trace_event_immediate__free_in_handler, test_setup, test_teardown),
		cmocka_unit_test_setup_teardown(test_trace_event_immediate__reschedule, test_setup, test_teardown),
		cmocka_unit_test_setup_teardown(test_get_set_trace_fd_callback, test_setup, test_teardown),
		cmocka_unit_test_setup_teardown(test_get_set_trace_timer_callback, test_setup, test_teardown),
		cmocka_unit_test_setup_teardown(test_get_set_trace_signal_callback, test_setup, test_teardown),
		cmocka_unit_test_setup_teardown(test_get_set_trace_immediate_callback, test_setup, test_teardown),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
