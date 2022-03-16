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

#include <talloc.h>
#include <tevent.h>
#include <cmocka.h>

static void queue_trigger(struct tevent_req *req, void *private_data)
{
	/* Dummy handler. Just return. */
	return;
}

static void fd_handler(struct tevent_context *ev,
		       struct tevent_fd *fde,
		       uint16_t flags,
		       void *private_data)
{
	/* Dummy handler. Just return. */
	return;
}

static void timer_handler(struct tevent_context *ev,
			  struct tevent_timer *te,
			  struct timeval current_time,
			  void *private_data)
{
	/* Dummy handler. Just return. */
	return;
}

static void signal_handler(struct tevent_context *ev,
			   struct tevent_signal *se,
			   int signum,
			   int count,
			   void *siginfo,
			   void *private_data)
{
	/* Dummy handler. Just return. */
	return;
}

static void immediate_handler(struct tevent_context *ctx,
			      struct tevent_immediate *im,
			      void *private_data)
{
	/* Dummy handler. Just return. */
	return;
}

static int test_setup(void **state)
{
	struct tevent_context *ev;

	ev = tevent_context_init(NULL);
	assert_non_null(ev);

	*state = ev;
	return 0;
}

static int test_teardown(void **state)
{
	struct tevent_context *ev = (struct tevent_context *)(*state);
	talloc_free(ev);
	return 0;
}

static void test_fd_tag(void **state)
{
	struct tevent_context *ev = (struct tevent_context *)(*state);
	struct tevent_fd *fde;
	uint64_t tag;

	fde = tevent_add_fd(ev, ev, 0, TEVENT_FD_READ, fd_handler, NULL);
	assert_non_null(fde);

	tag = tevent_fd_get_tag(fde);
	assert_int_equal(0, tag);

	tevent_fd_set_tag(fde, 1);
	tag = tevent_fd_get_tag(fde);
	assert_int_equal(1, tag);

	tevent_re_initialise(ev);

	tag = tevent_fd_get_tag(fde);
	assert_int_equal(1, tag);

	TALLOC_FREE(fde);
}

static void test_timer_tag(void **state)
{
	struct tevent_context *ev = (struct tevent_context *)(*state);
	struct tevent_timer *te;
	struct timeval next;
	uint64_t tag;

	next = tevent_timeval_current();
	te = tevent_add_timer(ev, ev, next, timer_handler, NULL);
	assert_non_null(te);

	tag = tevent_timer_get_tag(te);
	assert_int_equal(0, tag);

	tevent_timer_set_tag(te, 1);
	tag = tevent_timer_get_tag(te);
	assert_int_equal(1, tag);

	next = tevent_timeval_current();
	tevent_update_timer(te, next);

	tag = tevent_timer_get_tag(te);
	assert_int_equal(1, tag);

	tevent_re_initialise(ev);

	tag = tevent_timer_get_tag(te);
	assert_int_equal(1, tag);

	TALLOC_FREE(te);
}

static void test_signal_tag(void **state)
{
	struct tevent_context *ev = (struct tevent_context *)(*state);
	struct tevent_signal *se;
	uint64_t tag;

	se = tevent_add_signal(ev, ev, SIGUSR1, 0, signal_handler, NULL);
	assert_non_null(se);

	tag = tevent_signal_get_tag(se);
	assert_int_equal(0, tag);

	tevent_signal_set_tag(se, 1);
	tag = tevent_signal_get_tag(se);
	assert_int_equal(1, tag);

	tevent_re_initialise(ev);

	tag = tevent_signal_get_tag(se);
	assert_int_equal(1, tag);

	TALLOC_FREE(se);
}

static void test_immediate_tag(void **state)
{
	struct tevent_context *ev = (struct tevent_context *)(*state);
	struct tevent_immediate *im;
	uint64_t tag;

	im = tevent_create_immediate(ev);
	assert_non_null(im);

	tag = tevent_immediate_get_tag(im);
	assert_int_equal(0, tag);

	tevent_immediate_set_tag(im, 1);
	tag = tevent_immediate_get_tag(im);
	assert_int_equal(1, tag);

	tevent_schedule_immediate(im, ev, immediate_handler, NULL);

	tag = tevent_immediate_get_tag(im);
	assert_int_equal(1, tag);

	tevent_re_initialise(ev);

	tag = tevent_immediate_get_tag(im);
	assert_int_equal(1, tag);

	TALLOC_FREE(im);
}

static void test_queue_entry_tag(void **state)
{
	struct tevent_context *ev = (struct tevent_context *)(*state);
	struct tevent_queue *q;
	struct tevent_queue_entry *e1, *e2;
	struct tevent_req *r1, *r2;
	int *s1, *s2;
	uint64_t tag;

	q = tevent_queue_create(ev, "test_queue");
	assert_non_null(q);

	r1 = tevent_req_create(ev, &s1, int);
	r2 = tevent_req_create(ev, &s2, int);
	e1 = tevent_queue_add_entry(q, ev, r1, queue_trigger, NULL);
	e2 = tevent_queue_add_entry(q, ev, r2, queue_trigger, NULL);

	tag = tevent_queue_entry_get_tag(e1);
	assert_int_equal(0, tag);
	tag = tevent_queue_entry_get_tag(e2);
	assert_int_equal(0, tag);

	tevent_queue_entry_set_tag(e1, 1);
	tevent_queue_entry_set_tag(e2, 2);

	tag = tevent_queue_entry_get_tag(e1);
	assert_int_equal(1, tag);

	tag = tevent_queue_entry_get_tag(e2);
	assert_int_equal(2, tag);

	TALLOC_FREE(q);
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_fd_tag, test_setup, test_teardown),
		cmocka_unit_test_setup_teardown(test_timer_tag, test_setup, test_teardown),
		cmocka_unit_test_setup_teardown(test_signal_tag, test_setup, test_teardown),
		cmocka_unit_test_setup_teardown(test_immediate_tag, test_setup, test_teardown),
		cmocka_unit_test_setup_teardown(test_queue_entry_tag, test_setup, test_teardown),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
