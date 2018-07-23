/*
 * Unix SMB/CIFS implementation.
 * cmocka tests for thread pool implementation
 * Copyright (C) Christof Schmitt 2017
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <talloc.h>
#include <tevent.h>
#include <pthreadpool_tevent.h>

#include <cmocka.h>
#include <poll.h>

struct pthreadpool_tevent_test {
	struct tevent_context *ev;
	struct pthreadpool_tevent *upool;
	struct pthreadpool_tevent *spool;
	struct pthreadpool_tevent *opool;
};

static int setup_pthreadpool_tevent(void **state)
{
	struct pthreadpool_tevent_test *t;
	int ret;
	size_t max_threads;

	t = talloc_zero(NULL, struct pthreadpool_tevent_test);
	assert_non_null(t);

	t->ev = tevent_context_init(t);
	assert_non_null(t->ev);

	ret = pthreadpool_tevent_init(t->ev, UINT_MAX, &t->upool);
	assert_int_equal(ret, 0);

	max_threads = pthreadpool_tevent_max_threads(t->upool);
	assert_int_equal(max_threads, UINT_MAX);

	ret = pthreadpool_tevent_init(t->ev, 1, &t->opool);
	assert_int_equal(ret, 0);

	max_threads = pthreadpool_tevent_max_threads(t->opool);
	assert_int_equal(max_threads, 1);

	ret = pthreadpool_tevent_init(t->ev, 0, &t->spool);
	assert_int_equal(ret, 0);

	max_threads = pthreadpool_tevent_max_threads(t->spool);
	assert_int_equal(max_threads, 0);

	*state = t;

	return 0;
}

static int teardown_pthreadpool_tevent(void **state)
{
	struct pthreadpool_tevent_test *t = *state;

	TALLOC_FREE(t);

	return 0;
}

int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
			  void *(*start_routine) (void *), void *arg);
int __real_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
			  void *(*start_routine) (void *),  void *arg);

int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
			  void *(*start_routine) (void *), void *arg)
{
	int error;

	error = mock_type(int);
	if (error != 0) {
		return error;
	}

	return __real_pthread_create(thread, attr, start_routine, arg);
}

static void test_job_threadid(void *ptr)
{
	pthread_t *threadid = ptr;

	*threadid = pthread_self();
}

static int test_create_do(struct tevent_context *ev,
			  struct pthreadpool_tevent *pool,
			  bool *executed,
			  bool *in_main_thread)
{
	struct tevent_req *req;
	pthread_t zero_thread;
	pthread_t main_thread;
	pthread_t worker_thread;
	bool ok;
	int ret;

	*executed = false;
	*in_main_thread = false;

	memset(&zero_thread, 0, sizeof(zero_thread));
	main_thread = pthread_self();
	worker_thread = zero_thread;

	req = pthreadpool_tevent_job_send(
		ev, ev, pool, test_job_threadid, &worker_thread);
	if (req == NULL) {
		fprintf(stderr, "pthreadpool_tevent_job_send failed\n");
		return ENOMEM;
	}

	ok = tevent_req_poll(req, ev);
	if (!ok) {
		ret = errno;
		fprintf(stderr, "tevent_req_poll failed: %s\n",
			strerror(ret));
		*executed = !pthread_equal(worker_thread, zero_thread);
		*in_main_thread = pthread_equal(worker_thread, main_thread);
		return ret;
	}


	ret = pthreadpool_tevent_job_recv(req);
	TALLOC_FREE(req);
	*executed = !pthread_equal(worker_thread, zero_thread);
	*in_main_thread = pthread_equal(worker_thread, main_thread);
	if (ret != 0) {
		fprintf(stderr, "tevent_req_recv failed: %s\n",
			strerror(ret));
		return ret;
	}

	return 0;
}

static void test_create(void **state)
{
	struct pthreadpool_tevent_test *t = *state;
	bool executed;
	bool in_main_thread;
	int ret;

	/*
	 * When pthreadpool cannot create the first worker thread,
	 * this job will run in the sync fallback in the main thread.
	 */
	will_return(__wrap_pthread_create, EAGAIN);
	ret = test_create_do(t->ev, t->upool, &executed, &in_main_thread);
	assert_int_equal(ret, EAGAIN);
	assert_false(executed);
	assert_false(in_main_thread);

	/*
	 * The sync pool won't trigger pthread_create()
	 * It will be triggered by the one pool.
	 */
	will_return(__wrap_pthread_create, EAGAIN);

	ret = test_create_do(t->ev, t->spool, &executed, &in_main_thread);
	assert_int_equal(ret, 0);
	assert_true(executed);
	assert_true(in_main_thread);

	ret = test_create_do(t->ev, t->opool, &executed, &in_main_thread);
	assert_int_equal(ret, EAGAIN);
	assert_false(executed);
	assert_false(in_main_thread);

	/*
	 * When a thread can be created, the job will run in the worker thread.
	 */
	will_return(__wrap_pthread_create, 0);
	ret = test_create_do(t->ev, t->upool, &executed, &in_main_thread);
	assert_int_equal(ret, 0);
	assert_true(executed);
	assert_false(in_main_thread);

	poll(NULL, 0, 10);

	/*
	 * Workerthread will still be active for a second; immediately
	 * running another job will also use the worker thread, even
	 * if a new thread cannot be created.
	 */
	ret = test_create_do(t->ev, t->upool, &executed, &in_main_thread);
	assert_int_equal(ret, 0);
	assert_true(executed);
	assert_false(in_main_thread);

	/*
	 * When a thread can be created, the job will run in the worker thread.
	 */
	will_return(__wrap_pthread_create, 0);
	ret = test_create_do(t->ev, t->opool, &executed, &in_main_thread);
	assert_int_equal(ret, 0);
	assert_true(executed);
	assert_false(in_main_thread);

	poll(NULL, 0, 10);

	/*
	 * Workerthread will still be active for a second; immediately
	 * running another job will also use the worker thread, even
	 * if a new thread cannot be created.
	 */
	ret = test_create_do(t->ev, t->opool, &executed, &in_main_thread);
	assert_int_equal(ret, 0);
	assert_true(executed);
	assert_false(in_main_thread);
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_create,
						setup_pthreadpool_tevent,
						teardown_pthreadpool_tevent),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
