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

#include "config.h"
#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <talloc.h>
#include <tevent.h>
#include <pthreadpool_tevent.h>

#include <cmocka.h>
#include <poll.h>

#ifdef HAVE_VALGRIND_HELGRIND_H
#include <valgrind/helgrind.h>
#endif
#ifndef ANNOTATE_BENIGN_RACE_SIZED
#define ANNOTATE_BENIGN_RACE_SIZED(address, size, describtion)
#endif

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

static void test_per_thread_cwd_job(void *ptr)
{
	const bool *per_thread_cwd_ptr = ptr;
	bool per_thread_cwd;
	char cwdbuf[PATH_MAX] = {0,};
	char *cwdstr = NULL;
	int ret;

	/*
	 * This needs to be consistent.
	 */
	per_thread_cwd = pthreadpool_tevent_current_job_per_thread_cwd();
	assert_int_equal(per_thread_cwd, *per_thread_cwd_ptr);

	if (!per_thread_cwd) {
		return;
	}

	/*
	 * Check we're not already in "/".
	 */
	cwdstr = getcwd(cwdbuf, sizeof(cwdbuf));
	assert_non_null(cwdstr);
	assert_string_not_equal(cwdstr, "/");

	ret = chdir("/");
	assert_int_equal(ret, 0);

	/*
	 * Check we're in "/" now.
	 */
	cwdstr = getcwd(cwdbuf, sizeof(cwdbuf));
	assert_non_null(cwdstr);
	assert_string_equal(cwdstr, "/");
}

static int test_per_thread_cwd_do(struct tevent_context *ev,
				  struct pthreadpool_tevent *pool)
{
	struct tevent_req *req;
	bool per_thread_cwd;
	bool ok;
	int ret;
	per_thread_cwd = pthreadpool_tevent_per_thread_cwd(pool);

	req = pthreadpool_tevent_job_send(
		ev, ev, pool, test_per_thread_cwd_job, &per_thread_cwd);
	if (req == NULL) {
		fprintf(stderr, "pthreadpool_tevent_job_send failed\n");
		return ENOMEM;
	}

	ok = tevent_req_poll(req, ev);
	if (!ok) {
		ret = errno;
		fprintf(stderr, "tevent_req_poll failed: %s\n",
			strerror(ret));
		return ret;
	}

	ret = pthreadpool_tevent_job_recv(req);
	TALLOC_FREE(req);
	if (ret != 0) {
		fprintf(stderr, "tevent_req_recv failed: %s\n",
			strerror(ret));
		return ret;
	}

	return 0;
}

static void test_per_thread_cwd(void **state)
{
	struct pthreadpool_tevent_test *t = *state;
	int ret;
	bool per_thread_cwd_u;
	bool per_thread_cwd_o;
	bool per_thread_cwd_s;
	char cwdbuf1[PATH_MAX] = {0,};
	char *cwdstr1 = NULL;
	char cwdbuf2[PATH_MAX] = {0,};
	char *cwdstr2 = NULL;

	/*
	 * The unlimited and one pools
	 * should be consistent.
	 *
	 * We can't enforce this as some constraint
	 * container environments disable unshare()
	 * completely, even just with CLONE_FS.
	 */
	per_thread_cwd_u = pthreadpool_tevent_per_thread_cwd(t->upool);
	per_thread_cwd_o = pthreadpool_tevent_per_thread_cwd(t->opool);
	assert_int_equal(per_thread_cwd_u, per_thread_cwd_o);

	/*
	 * The sync pool should never support this.
	 */
	per_thread_cwd_s = pthreadpool_tevent_per_thread_cwd(t->spool);
	assert_false(per_thread_cwd_s);

	/*
	 * Check we're not already in "/".
	 */
	cwdstr1 = getcwd(cwdbuf1, sizeof(cwdbuf1));
	assert_non_null(cwdstr1);
	assert_string_not_equal(cwdstr1, "/");

	will_return(__wrap_pthread_create, 0);
	ret = test_per_thread_cwd_do(t->ev, t->upool);
	assert_int_equal(ret, 0);

	/*
	 * Check we're still in the same directory.
	 */
	cwdstr2 = getcwd(cwdbuf2, sizeof(cwdbuf2));
	assert_non_null(cwdstr2);
	assert_string_equal(cwdstr2, cwdstr1);

	will_return(__wrap_pthread_create, 0);
	ret = test_per_thread_cwd_do(t->ev, t->opool);
	assert_int_equal(ret, 0);

	/*
	 * Check we're still in the same directory.
	 */
	cwdstr2 = getcwd(cwdbuf2, sizeof(cwdbuf2));
	assert_non_null(cwdstr2);
	assert_string_equal(cwdstr2, cwdstr1);

	ret = test_per_thread_cwd_do(t->ev, t->spool);
	assert_int_equal(ret, 0);

	/*
	 * Check we're still in the same directory.
	 */
	cwdstr2 = getcwd(cwdbuf2, sizeof(cwdbuf2));
	assert_non_null(cwdstr2);
	assert_string_equal(cwdstr2, cwdstr1);
}

struct test_cancel_job {
	int fdm; /* the main end of socketpair */
	int fdj; /* the job end of socketpair */
	bool started;
	bool canceled;
	bool orphaned;
	bool finished;
	size_t polls;
	size_t timeouts;
	int sleep_msec;
	struct tevent_req *req;
	bool completed;
	int ret;
};

static void test_cancel_job_done(struct tevent_req *req);

static int test_cancel_job_destructor(struct test_cancel_job *job)
{
	ANNOTATE_BENIGN_RACE_SIZED(&job->started,
				   sizeof(job->started),
				   "protected by pthreadpool_tevent code");
	if (job->started) {
		ANNOTATE_BENIGN_RACE_SIZED(&job->finished,
					   sizeof(job->finished),
					   "protected by pthreadpool_tevent code");
		assert_true(job->finished);
	}

	ANNOTATE_BENIGN_RACE_SIZED(&job->fdj,
				   sizeof(job->fdj),
				   "protected by pthreadpool_tevent code");

	if (job->fdm != -1) {
		close(job->fdm);
		job->fdm = -1;
	}
	if (job->fdj != -1) {
		close(job->fdj);
		job->fdj = -1;
	}

	return 0;
}

static struct test_cancel_job *test_cancel_job_create(TALLOC_CTX *mem_ctx)
{
	struct test_cancel_job *job = NULL;

	job = talloc(mem_ctx, struct test_cancel_job);
	if (job == NULL) {
		return NULL;
	}
	*job = (struct test_cancel_job) {
		.fdm = -1,
		.fdj = -1,
		.sleep_msec = 50,
	};

	talloc_set_destructor(job, test_cancel_job_destructor);
	return job;
}

static void test_cancel_job_fn(void *ptr)
{
	struct test_cancel_job *job = (struct test_cancel_job *)ptr;
	int fdj = -1;
	char c = 0;
	int ret;

	assert_non_null(job); /* make sure we abort without a job pointer */

	job->started = true;
	fdj = job->fdj;
	job->fdj = -1;

	if (!pthreadpool_tevent_current_job_continue()) {
		job->canceled = pthreadpool_tevent_current_job_canceled();
		job->orphaned = pthreadpool_tevent_current_job_orphaned();
		job->finished = true;
		close(fdj);
		return;
	}

	/*
	 * Notify that we main thread
	 *
	 * write of 1 byte should always work!
	 */
	ret = write(fdj, &c, 1);
	assert_int_equal(ret, 1);

	/*
	 * loop until the job was tried to
	 * be canceled or becomes orphaned.
	 *
	 * If there's some activity on the fd
	 * we directly finish.
	 */
	do {
		struct pollfd pfd = {
			.fd = fdj,
			.events = POLLIN,
		};

		job->polls += 1;

		ret = poll(&pfd, 1, job->sleep_msec);
		if (ret == 1) {
			job->finished = true;
			close(fdj);
			return;
		}
		assert_int_equal(ret, 0);

		job->timeouts += 1;

	} while (pthreadpool_tevent_current_job_continue());

	job->canceled = pthreadpool_tevent_current_job_canceled();
	job->orphaned = pthreadpool_tevent_current_job_orphaned();
	job->finished = true;
	close(fdj);
}

static void test_cancel_job_done(struct tevent_req *req)
{
	struct test_cancel_job *job =
		tevent_req_callback_data(req,
		struct test_cancel_job);

	job->ret = pthreadpool_tevent_job_recv(job->req);
	TALLOC_FREE(job->req);
	job->completed = true;
}

static void test_cancel_job_wait(struct test_cancel_job *job,
				 struct tevent_context *ev)
{
	/*
	 * We have to keep looping until
	 * test_cancel_job_done was triggered
	 */
	while (!job->completed) {
		int ret;

		ret = tevent_loop_once(ev);
		assert_int_equal(ret, 0);
	}
}

struct test_cancel_state {
	struct test_cancel_job *job1;
	struct test_cancel_job *job2;
	struct test_cancel_job *job3;
	struct test_cancel_job *job4;
	struct test_cancel_job *job5;
	struct test_cancel_job *job6;
};

static void test_cancel_job(void **private_data)
{
	struct pthreadpool_tevent_test *t = *private_data;
	struct tevent_context *ev = t->ev;
	struct pthreadpool_tevent *pool = t->opool;
	struct test_cancel_state *state = NULL;
	int ret;
	bool ok;
	int fdpair[2] = { -1, -1 };
	char c = 0;

	state = talloc_zero(t, struct test_cancel_state);
	assert_non_null(state);
	state->job1 = test_cancel_job_create(state);
	assert_non_null(state->job1);
	state->job2 = test_cancel_job_create(state);
	assert_non_null(state->job2);
	state->job3 = test_cancel_job_create(state);
	assert_non_null(state->job3);

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fdpair);
	assert_int_equal(ret, 0);

	state->job1->fdm = fdpair[0];
	state->job1->fdj = fdpair[1];

	assert_int_equal(pthreadpool_tevent_queued_jobs(pool), 0);

	will_return(__wrap_pthread_create, 0);
	state->job1->req = pthreadpool_tevent_job_send(
		state->job1, ev, pool, test_cancel_job_fn, state->job1);
	assert_non_null(state->job1->req);
	tevent_req_set_callback(state->job1->req,
				test_cancel_job_done,
				state->job1);

	state->job2->req = pthreadpool_tevent_job_send(
		state->job2, ev, pool, test_cancel_job_fn, NULL);
	assert_non_null(state->job2->req);
	tevent_req_set_callback(state->job2->req,
				test_cancel_job_done,
				state->job2);

	state->job3->req = pthreadpool_tevent_job_send(
		state->job3, ev, pool, test_cancel_job_fn, NULL);
	assert_non_null(state->job3->req);
	tevent_req_set_callback(state->job3->req,
				test_cancel_job_done,
				state->job3);

	/*
	 * Wait for the job 1 to start.
	 */
	ret = read(state->job1->fdm, &c, 1);
	assert_int_equal(ret, 1);

	/*
	 * We cancel job 3 and destroy job2.
	 * Both should never be executed.
	 */
	assert_int_equal(pthreadpool_tevent_queued_jobs(pool), 2);
	TALLOC_FREE(state->job2->req);
	assert_int_equal(pthreadpool_tevent_queued_jobs(pool), 1);
	ok = tevent_req_cancel(state->job3->req);
	assert_true(ok);
	assert_int_equal(pthreadpool_tevent_queued_jobs(pool), 0);

	/*
	 * Job 3 should complete as canceled, while
	 * job 1 is still running.
	 */
	test_cancel_job_wait(state->job3, ev);
	assert_int_equal(state->job3->ret, ECANCELED);
	assert_null(state->job3->req);
	assert_false(state->job3->started);

	/*
	 * Now job1 is canceled while it's running,
	 * this should let it stop it's loop.
	 */
	ok = tevent_req_cancel(state->job1->req);
	assert_false(ok);

	/*
	 * Job 1 completes, It got at least one sleep
	 * timeout loop and has state->job1->canceled set.
	 */
	test_cancel_job_wait(state->job1, ev);
	assert_int_equal(state->job1->ret, 0);
	assert_null(state->job1->req);
	assert_true(state->job1->started);
	assert_true(state->job1->finished);
	assert_true(state->job1->canceled);
	assert_false(state->job1->orphaned);
	assert_in_range(state->job1->polls, 1, 100);
	assert_int_equal(state->job1->timeouts, state->job1->polls);

	/*
	 * Now we create jobs 4 and 5
	 * Both should execute.
	 * Job 4 is orphaned while running by a TALLOC_FREE()
	 * This should stop job 4 and let job 5 start.
	 * We do a "normal" exit in job 5 by creating some activity
	 * on the socketpair.
	 */

	state->job4 = test_cancel_job_create(state);
	assert_non_null(state->job4);

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fdpair);
	assert_int_equal(ret, 0);

	state->job4->fdm = fdpair[0];
	state->job4->fdj = fdpair[1];

	state->job4->req = pthreadpool_tevent_job_send(
		state->job4, ev, pool, test_cancel_job_fn, state->job4);
	assert_non_null(state->job4->req);
	tevent_req_set_callback(state->job4->req,
				test_cancel_job_done,
				state->job4);

	state->job5 = test_cancel_job_create(state);
	assert_non_null(state->job5);

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fdpair);
	assert_int_equal(ret, 0);

	state->job5->fdm = fdpair[0];
	state->job5->fdj = fdpair[1];

	state->job5->req = pthreadpool_tevent_job_send(
		state->job5, ev, pool, test_cancel_job_fn, state->job5);
	assert_non_null(state->job5->req);
	tevent_req_set_callback(state->job5->req,
				test_cancel_job_done,
				state->job5);

	/*
	 * Make sure job 5 can exit as soon as possible.
	 * It will never get a sleep/poll timeout.
	 */
	ret = write(state->job5->fdm, &c, 1);
	assert_int_equal(ret, 1);

	/*
	 * Wait for the job 4 to start
	 */
	ret = read(state->job4->fdm, &c, 1);
	assert_int_equal(ret, 1);

	assert_int_equal(pthreadpool_tevent_queued_jobs(pool), 1);

	/*
	 * destroy the request so that it's marked
	 * as orphaned.
	 */
	TALLOC_FREE(state->job4->req);

	/*
	 * Job 5 completes, It got no sleep timeout loop.
	 */
	test_cancel_job_wait(state->job5, ev);
	assert_int_equal(state->job5->ret, 0);
	assert_null(state->job5->req);
	assert_true(state->job5->started);
	assert_true(state->job5->finished);
	assert_false(state->job5->canceled);
	assert_false(state->job5->orphaned);
	assert_int_equal(state->job5->polls, 1);
	assert_int_equal(state->job5->timeouts, 0);

	assert_int_equal(pthreadpool_tevent_queued_jobs(pool), 0);

	/*
	 * Job 2 is still not executed as we did a TALLOC_FREE()
	 * before is was scheduled.
	 */
	assert_false(state->job2->completed);
	assert_false(state->job2->started);

	/*
	 * Job 4 is still wasn't completed as we did a TALLOC_FREE()
	 * while it is was running. but it was started and has
	 * orphaned set
	 */
	assert_false(state->job4->completed);
	assert_true(state->job4->started);
	assert_true(state->job4->finished);
	assert_false(state->job4->canceled);
	assert_true(state->job4->orphaned);
	assert_in_range(state->job4->polls, 1, 100);
	assert_int_equal(state->job4->timeouts, state->job4->polls);

	/*
	 * Now we create jobs 6
	 * We destroy the pool while it's executing.
	 */

	state->job6 = test_cancel_job_create(state);
	assert_non_null(state->job6);

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fdpair);
	assert_int_equal(ret, 0);

	state->job6->fdm = fdpair[0];
	state->job6->fdj = fdpair[1];

	state->job6->req = pthreadpool_tevent_job_send(
		state->job6, ev, pool, test_cancel_job_fn, state->job6);
	assert_non_null(state->job6->req);
	tevent_req_set_callback(state->job6->req,
				test_cancel_job_done,
				state->job6);

	/*
	 * Wait for the job 6 to start
	 */
	ret = read(state->job6->fdm, &c, 1);
	assert_int_equal(ret, 1);

	assert_int_equal(pthreadpool_tevent_queued_jobs(pool), 0);

	/*
	 * destroy the request so that it's marked
	 * as orphaned.
	 */
	pool = NULL;
	TALLOC_FREE(t->opool);

	/*
	 * Wait until the job finished.
	 */
	ret = read(state->job6->fdm, &c, 1);
	assert_int_equal(ret, 0);

	/*
	 * Job 6 is still dangling arround.
	 *
	 * We need to convince valgrind --tool={drd,helgrind}
	 * that the read above is good enough to be
	 * sure the job is finished and closed the other end of
	 * the socketpair.
	 */
	ANNOTATE_BENIGN_RACE_SIZED(state->job6,
				   sizeof(*state->job6),
				   "protected by thread fence");
	assert_non_null(state->job6->req);
	assert_true(tevent_req_is_in_progress(state->job6->req));
	assert_false(state->job6->completed);
	assert_true(state->job6->started);
	assert_true(state->job6->finished);
	assert_false(state->job6->canceled);
	assert_true(state->job6->orphaned);
	assert_in_range(state->job6->polls, 1, 100);
	assert_int_equal(state->job6->timeouts, state->job4->polls);

	TALLOC_FREE(state);
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_create,
						setup_pthreadpool_tevent,
						teardown_pthreadpool_tevent),
		cmocka_unit_test_setup_teardown(test_per_thread_cwd,
						setup_pthreadpool_tevent,
						teardown_pthreadpool_tevent),
		cmocka_unit_test_setup_teardown(test_cancel_job,
						setup_pthreadpool_tevent,
						teardown_pthreadpool_tevent),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
