/*
 * Unix SMB/CIFS implementation.
 * cmocka tests for pthreadpool implementation
 * Copyright (C) 2025
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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <talloc.h>
#include <tevent.h>
#include <stdlib.h>
#include <poll.h>
#include "pthreadpool_tevent.h"

struct mutex_int {
	int num;
	/* protect num */
	pthread_mutex_t mutex;
};

static void safe_increment(struct mutex_int *counter)
{
	int ret;

	ret = pthread_mutex_lock(&counter->mutex);
	assert_int_equal(ret, 0);
	counter->num++;
	ret = pthread_mutex_unlock(&counter->mutex);
	assert_int_equal(ret, 0);
}

/* Test fixture structure */
struct test_context {
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct pthreadpool_tevent *pool;
	int g_job_executed;
};

/* Global state for tracking callbacks */

/* Reset global test state */
static void reset_test_state(struct test_context *state)
{
	state->g_job_executed = 0;
}

/* Setup function - called before each test */
static int setup(void **state)
{
	struct test_context *ctx;

	ctx = talloc_zero(NULL, struct test_context);
	assert_non_null(ctx);

	ctx->ev = tevent_context_init(ctx);
	assert_non_null(ctx->ev);

	reset_test_state(ctx);

	*state = ctx;
	return 0;
}

/* Teardown function - called after each test */
static int teardown(void **state)
{
	struct test_context *ctx = talloc_get_type_abort(*state,
							 struct test_context);
	TALLOC_FREE(ctx->pool);
	TALLOC_FREE(ctx->ev);
	TALLOC_FREE(ctx);
	return 0;
}

/* Mock job function for testing */
static void mock_job_fn(void *private_data)
{
	struct test_context *state = talloc_get_type_abort(private_data,
							   struct test_context);
	/* Simulate some work */
	usleep(10000); /* 10ms */
	state->g_job_executed++;
}

/* Quick job function */
static void quick_job_fn(void *private_data)
{
	struct mutex_int *counter = (struct mutex_int *)private_data;
	safe_increment(counter);
}

/* Slow job function */
static void slow_job_fn(void *private_data)
{
	struct mutex_int *counter = (struct mutex_int *)private_data;
	/* Simulate some work */
	usleep(10000); /* 10ms */
	safe_increment(counter);
}

/* Slower job function */
static void wait_fn(void *private_data)
{
	int *timeout = private_data;
	poll(NULL, 0, *timeout);
}

struct job_completion_state
{
	int num_jobs;
	int status;
	struct test_context *ctx;
};

/* Tevent request callback */
static void job_completion_callback(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct job_completion_state *state = tevent_req_data(req, struct job_completion_state);
	state->status = pthreadpool_tevent_job_recv(subreq);
	TALLOC_FREE(subreq);
	state->num_jobs = state->num_jobs - 1;
	if (state->num_jobs == 0) {
		tevent_req_done(req);
	}
}

/*
 * Test: pthreadpool_tevent_init with valid parameters
 */
static void test_pthreadpool_tevent_init_valid(void **state)
{
	struct test_context *ctx = talloc_get_type_abort(*state,
							 struct test_context);
	int ret;

	ret = pthreadpool_tevent_init(ctx, 4, &ctx->pool);

	assert_int_equal(ret, 0);
	assert_non_null(ctx->pool);
}

/*
 * Test: pthreadpool_tevent_init with zero max_threads (sync mode)
 */
static void test_pthreadpool_tevent_init_unlimited(void **state)
{
	struct test_context *ctx = talloc_get_type_abort(*state,
							 struct test_context);
	int ret;

	ret = pthreadpool_tevent_init(ctx, 0, &ctx->pool);

	assert_int_equal(ret, 0);
	assert_non_null(ctx->pool);
}

/*
 * Test: pthreadpool_tevent_init with large thread count
 */
static void test_pthreadpool_tevent_init_large_threads(void **state)
{
	struct test_context *ctx = talloc_get_type_abort(*state,
							 struct test_context);
	int ret;

	ret = pthreadpool_tevent_init(ctx, UINT_MAX, &ctx->pool);

	/* Should handle large values gracefully */
	if (ret == 0) {
		assert_non_null(ctx->pool);
	}
}

/*
 * Test: pthreadpool_tevent_max_threads returns correct value
 */
static void test_pthreadpool_tevent_max_threads(void **state)
{
	struct test_context *ctx = talloc_get_type_abort(*state,
							 struct test_context);
	size_t max_threads;
	int ret;

	ret = pthreadpool_tevent_init(ctx, 8, &ctx->pool);
	assert_int_equal(ret, 0);

	max_threads = pthreadpool_tevent_max_threads(ctx->pool);
	assert_int_equal(max_threads, 8);
}

/*
 * Test: pthreadpool_tevent_max_threads with sync mode
 */
static void test_pthreadpool_tevent_max_threads_unlimited(void **state)
{
	struct test_context *ctx = talloc_get_type_abort(*state,
							 struct test_context);
	size_t max_threads;
	int ret;

	ret = pthreadpool_tevent_init(ctx, 0, &ctx->pool);
	assert_int_equal(ret, 0);

	max_threads = pthreadpool_tevent_max_threads(ctx->pool);
	assert_int_equal(max_threads, 0);
}

/*
 * Test: pthreadpool_tevent_queued_jobs initially returns zero
 */
static void test_pthreadpool_tevent_queued_jobs_empty(void **state)
{
	struct test_context *ctx = talloc_get_type_abort(*state,
							 struct test_context);
	size_t queued;
	int ret;

	ret = pthreadpool_tevent_init(ctx, 4, &ctx->pool);
	assert_int_equal(ret, 0);

	queued = pthreadpool_tevent_queued_jobs(ctx->pool);
	assert_int_equal(queued, 0);
}

/*
 * Test: pthreadpool_tevent_job_send with valid parameters
 */
static void test_pthreadpool_tevent_job_send_valid(void **ppstate)
{
	struct test_context *ctx = talloc_get_type_abort(*ppstate,
							 struct test_context);
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct job_completion_state *state = NULL;
	int ret;

	req = tevent_req_create(ctx, &state, struct job_completion_state);
	assert_non_null(req);

	state->ctx = ctx;
	state->num_jobs = 1;
	ret = pthreadpool_tevent_init(ctx, 4, &ctx->pool);
	assert_int_equal(ret, 0);

	subreq = pthreadpool_tevent_job_send(
		ctx->mem_ctx, ctx->ev, ctx->pool, mock_job_fn, ctx);

	assert_non_null(subreq);

	/* Set callback */
	tevent_req_set_callback(subreq, job_completion_callback, req);

	/* wait for event to complete*/
	assert_true(tevent_req_poll(req,ctx->ev));
	TALLOC_FREE(req);
}

/*
 * Test: pthreadpool_tevent_job_send with private data
 */
static void test_pthreadpool_tevent_job_send_with_private_data(void **ppstate)
{
	struct test_context *ctx = talloc_get_type_abort(*ppstate,
							 struct test_context);
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct mutex_int test_data = {0};
	struct job_completion_state *state = NULL;

	int ret;

	ret = pthreadpool_tevent_init(ctx, 4, &ctx->pool);
	assert_int_equal(ret, 0);

	ret = pthread_mutex_init(&test_data.mutex, NULL);
	assert_int_equal(ret, 0);

	test_data.num = 42;

	req = tevent_req_create(ctx, &state, struct job_completion_state);
	assert_non_null(req);

	state->ctx = ctx;
	state->num_jobs = 1;

	subreq = pthreadpool_tevent_job_send(
		ctx->mem_ctx, ctx->ev, ctx->pool, quick_job_fn, &test_data);

	assert_non_null(subreq);

	tevent_req_set_callback(subreq, job_completion_callback, req);

	/* wait for event to complete*/
	assert_true(tevent_req_poll(req, ctx->ev));
	/* Job should have incremented test_data */
	assert_int_equal(test_data.num, 43);
	pthread_mutex_destroy(&test_data.mutex);
}

/*
 * Test: pthreadpool_tevent_job_send multiple jobs
 */
static void test_pthreadpool_tevent_job_send_multiple(void **ppstate)
{
	struct test_context *ctx = talloc_get_type_abort(*ppstate,
							 struct test_context);
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct mutex_int counter = {0};
	struct job_completion_state *state = NULL;
	int num_jobs = 5;

	int ret;
	int num;
	int i;

	req = tevent_req_create(ctx, &state, struct job_completion_state);
	assert_non_null(req);

	state->ctx = ctx;
	state->num_jobs = num_jobs;

	ret = pthreadpool_tevent_init(ctx, 4, &ctx->pool);
	assert_int_equal(ret, 0);

	ret = pthread_mutex_init(&counter.mutex, NULL);
	assert_int_equal(ret, 0);

	/* Submit multiple jobs */
	for (i = 0; i < num_jobs; i++) {
		subreq = pthreadpool_tevent_job_send(ctx->mem_ctx,
						  ctx->ev,
						  ctx->pool,
						  slow_job_fn,
						  &counter);
		assert_non_null(subreq);
		tevent_req_set_callback(subreq, job_completion_callback, req);
	}

	/* wait for events to complete*/
	assert_true(tevent_req_poll(req,ctx->ev));

	/* All jobs should have completed */
	assert_int_equal(state->num_jobs, 0);
	num = counter.num;
	assert_int_equal(num, 5);
	pthread_mutex_destroy(&counter.mutex);
	TALLOC_FREE(req);
}

/*
 * Test: pthreadpool_tevent_job_send multiple jobs, mixing
 * sync and async.
 */
static void test_pthreadpool_tevent_job_send_multiple_2(void **ppstate)
{
	struct test_context *ctx = talloc_get_type_abort(*ppstate,
							 struct test_context);
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct job_completion_state *state = NULL;
	int num_jobs = 10;
	int timeout10 = 10;
	int timeout100 = 100;

	int i;
	int ret;

	req = tevent_req_create(ctx, &state, struct job_completion_state);
	assert_non_null(req);

	state->ctx = ctx;
	state->num_jobs = num_jobs;

	ret = pthreadpool_tevent_init(ctx, UINT_MAX, &ctx->pool);
	assert_int_equal(ret, 0);

	/*
         * Intersperse pthreadpool_tevent jobs processed synchronously
         * (with temporary sub-event context) and pthreadpool_tevent
         * processed asynchronously.
         * This is analogous to smb_vfs_fsync_sync calls happening
         * concurrently with other asynchronous io calls in smbd
	 */
	for (i = 0; i < num_jobs; i++) {
		if (i % 2) {
			subreq = pthreadpool_tevent_job_send(ctx->mem_ctx,
						  ctx->ev,
						  ctx->pool,
						  wait_fn,
						  &timeout100);
			assert_non_null(subreq);
			tevent_req_set_callback(subreq, job_completion_callback, req);
		} else {
			TALLOC_CTX *mem_ctx = talloc_new(NULL);
			bool ok;
			struct tevent_context *tmp_ev =
				tevent_context_init(mem_ctx);
			subreq = pthreadpool_tevent_job_send(tmp_ev,
					tmp_ev,
					ctx->pool,
					wait_fn,
					&timeout10);
			assert_non_null(subreq);
			ok = tevent_req_poll(subreq, tmp_ev);
			assert_true(ok);
			ret = pthreadpool_tevent_job_recv(subreq);
			assert_int_equal(ret, 0);
			state->num_jobs -= 1;
			if (state->num_jobs == 0) {
				tevent_req_done(req);
			}
			TALLOC_FREE(mem_ctx);
		}
	}

	/* wait for events to complete*/
	assert_true(tevent_req_poll(req,ctx->ev));

	/* All jobs should have completed */
	assert_int_equal(state->num_jobs, 0);
	TALLOC_FREE(req);
}

struct nested_state {
	struct pthreadpool_tevent *pool;
	int timeout;
};

static void do_nested_pthread_job(void *private_data)
{
	struct nested_state *state = private_data;
	TALLOC_CTX *ctx = talloc_new(NULL);
	bool ok;
	struct tevent_context *tmp_ev = tevent_context_init(ctx);
	struct tevent_req *subreq = NULL;
	int ret;
	assert_non_null(tmp_ev);
	subreq = pthreadpool_tevent_job_send(
			tmp_ev, tmp_ev, state->pool,
			wait_fn, &state->timeout);

	assert_non_null(subreq);
	ok = tevent_req_poll(subreq, tmp_ev);
	assert_true(ok);
	ret = pthreadpool_tevent_job_recv(subreq);
	assert_int_equal(ret,0);
	TALLOC_FREE(ctx);
}

/*
 * Test: pthreadpool_tevent_job_send multiple jobs,
 *       where jobs can themselves initiate a nested job
 */
static void test_pthreadpool_tevent_job_send_multiple_3(void **ppstate)
{
	struct test_context *ctx = talloc_get_type_abort(*ppstate,
							 struct test_context);
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct job_completion_state *state = NULL;
	int num_jobs = 10;
	int timeout100 = 100;

	int i;
	int ret;

	req = tevent_req_create(ctx, &state, struct job_completion_state);
	assert_non_null(req);

	state->ctx = ctx;
	state->num_jobs = num_jobs;

	ret = pthreadpool_tevent_init(ctx, UINT_MAX, &ctx->pool);
	assert_int_equal(ret, 0);

	/*
         * Intersperse pthreadpool_tevent jobs processed synchronously
         * (with temporary sub-event context) and pthreadpool_tevent
         * processed asynchronously.
         * This is analogous to smb_vfs_fsync_sync calls happening
         * concurrently with other asynchronous io calls in smbd
	 */
	for (i = 0; i < num_jobs; i++) {
		struct nested_state *nested_state =
			talloc_zero(ctx->mem_ctx, struct nested_state);
		assert_non_null(nested_state);
		nested_state->pool = ctx->pool;
		nested_state->timeout = timeout100;

		subreq = pthreadpool_tevent_job_send(ctx->mem_ctx,
						  ctx->ev,
						  ctx->pool,
						  do_nested_pthread_job,
						  nested_state);
		assert_non_null(subreq);
		tevent_req_set_callback(subreq, job_completion_callback, req);
	}

	/* wait for events to complete*/
	assert_true(tevent_req_poll(req,ctx->ev));

	/* All jobs should have completed */
	assert_int_equal(state->num_jobs, 0);
	TALLOC_FREE(req);
}

/*
 * Test: pthreadpool_tevent_job_recv with valid request
 */
static void test_pthreadpool_tevent_job_recv_valid(void **state)
{
	struct test_context *ctx = talloc_get_type_abort(*state,
							 struct test_context);
	struct tevent_req *req;
	int ret;
	bool ok;

	ret = pthreadpool_tevent_init(ctx, 4, &ctx->pool);
	assert_int_equal(ret, 0);

	req = pthreadpool_tevent_job_send(
		ctx->mem_ctx, ctx->ev, ctx->pool, mock_job_fn, ctx);
	assert_non_null(req);

	ok = tevent_req_poll(req, ctx->ev);
	assert_true(ok);
	/* Receive result */
	ret = pthreadpool_tevent_job_recv(req);
	assert_int_equal(ret, 0);

	TALLOC_FREE(req);
}

/*
 * Test: pthreadpool_tevent_queued_jobs tracking
 */
static void test_pthreadpool_tevent_queued_jobs_tracking(void **ppstate)
{
	struct test_context *ctx = talloc_get_type_abort(*ppstate,
							 struct test_context);
	struct tevent_req *req = NULL;
	struct job_completion_state *state = NULL;
	int ret;
	int i;
	size_t queued;
	struct mutex_int counter = {0};

	req = tevent_req_create(ctx, &state, struct job_completion_state);
	assert_non_null(req);

	state->ctx = ctx;
	state->num_jobs = 3;

	ret = pthreadpool_tevent_init(ctx, 1, &ctx->pool);
	assert_int_equal(ret, 0);

	ret = pthread_mutex_init(&counter.mutex, NULL);
	assert_int_equal(ret, 0);

	/* Submit jobs faster than they can be processed */
	for (i = 0; i < state->num_jobs; i++) {
		struct tevent_req *subreq = NULL;
		subreq = pthreadpool_tevent_job_send(ctx->mem_ctx,
						     ctx->ev,
						     ctx->pool,
						     slow_job_fn,
						     &counter);
		assert_non_null(subreq);
		tevent_req_set_callback(subreq, job_completion_callback, req);
	}

	/* Check queued jobs (some may be queued) */
	queued = pthreadpool_tevent_queued_jobs(ctx->pool);
	assert_true(queued > 0);
	/* Should have at least some jobs queued or processing */
	/* Exact number depends on timing */

	/* wait for events to complete*/
	assert_true(tevent_req_poll(req,ctx->ev));
	/* Clean up */
	assert_int_equal(state->num_jobs, 0);
	TALLOC_FREE(req);

	pthread_mutex_destroy(&counter.mutex);
}

/*
 * Test: Memory cleanup with talloc
 */
static void test_memory_cleanup(void **state)
{
	struct test_context *ctx = talloc_get_type_abort(*state,
							 struct test_context);
	TALLOC_CTX *tmp_ctx;
	struct tevent_req *req;
	int ret;
	int i;
	struct mutex_int counter = {0};

	ret = pthreadpool_tevent_init(ctx, 4, &ctx->pool);
	assert_int_equal(ret, 0);

	ret = pthread_mutex_init(&counter.mutex, NULL);
	assert_int_equal(ret, 0);

	/* Create temporary context */
	tmp_ctx = talloc_new(ctx->mem_ctx);
	assert_non_null(tmp_ctx);

	/* Allocate request in temporary context */
	req = pthreadpool_tevent_job_send(
		tmp_ctx, ctx->ev, ctx->pool, quick_job_fn, &counter);
	assert_non_null(req);

	/*
	 * wait for work to be done, but don't interact with tevent
	 * e.g. don't call any tevent poll etc.
	 */
	for (i = 0; i < 100; i++) {
		int num;
		usleep(10000);
		ret = pthread_mutex_lock(&counter.mutex);
		assert_int_equal(ret, 0);
		num = counter.num;
		ret = pthread_mutex_unlock(&counter.mutex);
		assert_int_equal(ret, 0);
		if (num == 1) {
			break;
		}
	}

	/* Free temporary context - should clean up request */
	TALLOC_FREE(tmp_ctx);

	/* Pool should still be valid */
	assert_non_null(ctx->pool);
	pthread_mutex_destroy(&counter.mutex);
}

/*
 * Test: Callback execution
 */
static void test_callback_execution(void **ppstate)
{
	struct test_context *ctx = talloc_get_type_abort(*ppstate,
							 struct test_context);
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	int ret;
	struct job_completion_state *state = NULL;

	reset_test_state(ctx);

	req = tevent_req_create(ctx, &state, struct job_completion_state);
	assert_non_null(req);

	state->ctx = ctx;
	state->num_jobs = 1;

	ret = pthreadpool_tevent_init(ctx, 4, &ctx->pool);
	assert_int_equal(ret, 0);

	subreq = pthreadpool_tevent_job_send(
		ctx->mem_ctx, ctx->ev, ctx->pool, mock_job_fn, ctx);
	assert_non_null(subreq);

	tevent_req_set_callback(subreq, job_completion_callback, req);

	/* wait for event to complete*/
	assert_true(tevent_req_poll(req,ctx->ev));
	/* Callback should have been executed */
	assert_int_equal(state->num_jobs, 0);
	assert_int_equal(state->status, 0);
	TALLOC_FREE(req);
}

/*
 * Test: Job execution verification
 */
static void test_job_execution(void **state)
{
	struct test_context *ctx = talloc_get_type_abort(*state,
							 struct test_context);
	struct tevent_req *req;
	int ret;
	bool ok;

	reset_test_state(ctx);

	ret = pthreadpool_tevent_init(ctx, 4, &ctx->pool);
	assert_int_equal(ret, 0);

	req = pthreadpool_tevent_job_send(
		ctx->mem_ctx, ctx->ev, ctx->pool, mock_job_fn, ctx);
	assert_non_null(req);

	ok = tevent_req_poll(req, ctx->ev);
	assert_true(ok);

	/* Job should have been executed */
	assert_int_equal(ctx->g_job_executed, 1);

	TALLOC_FREE(req);
}

int main(void)
{
	const struct CMUnitTest tests[] =
	{ cmocka_unit_test_setup_teardown(test_pthreadpool_tevent_init_valid,
					  setup,
					  teardown),
	  cmocka_unit_test_setup_teardown(
		  test_pthreadpool_tevent_init_unlimited, setup, teardown),
	  cmocka_unit_test_setup_teardown(
		  test_pthreadpool_tevent_init_large_threads, setup, teardown),
	  cmocka_unit_test_setup_teardown(test_pthreadpool_tevent_max_threads,
					  setup,
					  teardown),
	  cmocka_unit_test_setup_teardown(
		  test_pthreadpool_tevent_max_threads_unlimited,
		  setup,
		  teardown),
	  cmocka_unit_test_setup_teardown(
		  test_pthreadpool_tevent_queued_jobs_empty, setup, teardown),
	  cmocka_unit_test_setup_teardown(
		  test_pthreadpool_tevent_job_send_valid, setup, teardown),
	  cmocka_unit_test_setup_teardown(
		  test_pthreadpool_tevent_job_send_with_private_data,
		  setup,
		  teardown),
	  cmocka_unit_test_setup_teardown(
		  test_pthreadpool_tevent_job_send_multiple, setup, teardown),
	  cmocka_unit_test_setup_teardown(
		  test_pthreadpool_tevent_job_send_multiple_2, setup, teardown),
	  cmocka_unit_test_setup_teardown(
		  test_pthreadpool_tevent_job_send_multiple_3, setup, teardown),
	  cmocka_unit_test_setup_teardown(
		  test_pthreadpool_tevent_job_recv_valid, setup, teardown),
	  cmocka_unit_test_setup_teardown(
		  test_pthreadpool_tevent_queued_jobs_tracking,
		  setup,
		  teardown),
	  cmocka_unit_test_setup_teardown(test_memory_cleanup, setup, teardown),
	  cmocka_unit_test_setup_teardown(test_callback_execution,
					  setup,
					  teardown),
	  cmocka_unit_test_setup_teardown(test_job_execution, setup, teardown),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
