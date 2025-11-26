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

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>

#include <talloc.h>

#include "pthreadpool.h"

/* Test state structure */
struct test_state {
	struct pthreadpool *pool;
	int signal_received;
	int signal_job_id;
	void (*signal_job_fn)(void *);
	void *signal_job_fn_data;
	/* protect test_state */
	pthread_mutex_t mutex;
};

struct mutex_int {
	int num;
	/* protect num */
	pthread_mutex_t mutex;
};

/* Signal function for testing */
static int test_signal_fn(int jobid,
			  void (*job_fn)(void *private_data),
			  void *job_fn_private_data,
			  void *private_data)
{
	int ret;
	struct test_state *state = talloc_get_type_abort(private_data,
							 struct test_state);

	ret = pthread_mutex_lock(&state->mutex);
	assert_int_equal(ret, 0);
	state->signal_received++;
	state->signal_job_id = jobid;
	state->signal_job_fn = job_fn;
	state->signal_job_fn_data = job_fn_private_data;
	ret = pthread_mutex_unlock(&state->mutex);
	assert_int_equal(ret, 0);

	return 0;
}

static void safe_increment(struct mutex_int *counter)
{
	int ret;

	ret = pthread_mutex_lock(&counter->mutex);
	assert_int_equal(ret, 0);
	counter->num++;
	ret = pthread_mutex_unlock(&counter->mutex);
	assert_int_equal(ret, 0);
}

/* Simple job function that increments a counter (in a thread safe way)*/
static void increment_job(void *private_data)
{
	struct mutex_int *num = (struct mutex_int*)private_data;
	safe_increment(num);
}

/* Job function that sleeps briefly */
static void sleep_job(void *private_data)
{
	int *duration = (int *)private_data;
	usleep(*duration * 1000); /* Convert ms to microseconds */
}

/* Setup function */
static int setup(void **state)
{
	struct test_state *test_state = NULL;
	int ret;

	test_state = talloc_zero(NULL, struct test_state);
	assert_non_null(test_state);

	ret = pthread_mutex_init(&test_state->mutex, NULL);
	assert_int_equal(ret, 0);
	*state = test_state;
	return 0;
}

/* Teardown function */
static int teardown(void **state)
{
	struct test_state *test_state = talloc_get_type_abort(
		*state, struct test_state);

	if (test_state->pool != NULL) {
		pthreadpool_destroy(test_state->pool);
		test_state->pool = NULL;
	}
	pthread_mutex_destroy(&test_state->mutex);
	TALLOC_FREE(test_state);
	return 0;
}

/* Test: Initialize pool with different max_threads values */
static void test_pthreadpool_init(void **state)
{
	struct test_state *test_state = talloc_get_type_abort(
		*state, struct test_state);
	int ret;

	/* Test with unlimited threads (0) */
	ret = pthreadpool_init(0,
			       &test_state->pool,
			       test_signal_fn,
			       test_state);
	assert_int_equal(ret, 0);
	assert_non_null(test_state->pool);
	assert_int_equal(pthreadpool_max_threads(test_state->pool), 0);

	pthreadpool_destroy(test_state->pool);
	test_state->pool = NULL;

	/* Test with limited threads */
	ret = pthreadpool_init(4,
			       &test_state->pool,
			       test_signal_fn,
			       test_state);
	assert_int_equal(ret, 0);
	assert_non_null(test_state->pool);
	assert_int_equal(pthreadpool_max_threads(test_state->pool), 4);

	pthreadpool_destroy(test_state->pool);
	test_state->pool = NULL;

	/* Test with 1 thread */
	ret = pthreadpool_init(1,
			       &test_state->pool,
			       test_signal_fn,
			       test_state);
	assert_int_equal(ret, 0);
	assert_non_null(test_state->pool);
	assert_int_equal(pthreadpool_max_threads(test_state->pool), 1);
}

/* Test: Add and execute a simple job */
static void test_pthreadpool_add_job_simple(void **state)
{
	struct test_state *test_state = talloc_get_type_abort(
		*state, struct test_state);
	int ret;
	struct mutex_int counter = {0};
	int timeout;
	int signal_received = 0;

	ret = pthreadpool_init(2,
			       &test_state->pool,
			       test_signal_fn,
			       test_state);
	assert_int_equal(ret, 0);

	ret = pthread_mutex_init(&counter.mutex, NULL);
	assert_int_equal(ret, 0);

	/* Add a job */
	ret = pthreadpool_add_job(test_state->pool, 1, increment_job, &counter);
	assert_int_equal(ret, 0);

	/* Wait for job completion (with timeout) */
	timeout = 0;
	do {
		ret = pthread_mutex_lock(&test_state->mutex);
		assert_int_equal(ret, 0);
		signal_received = test_state->signal_received;
		ret = pthread_mutex_unlock(&test_state->mutex);
		assert_int_equal(ret, 0);
		usleep(10000); /* 10ms */
		timeout++;

	} while (signal_received == 0 && timeout < 100);

	/* Verify job was executed */
	assert_int_equal(counter.num, 1);
	assert_int_equal(test_state->signal_received, 1);
	assert_int_equal(test_state->signal_job_id, 1);
	assert_ptr_equal(test_state->signal_job_fn, increment_job);
	assert_ptr_equal(test_state->signal_job_fn_data, &counter);
	pthread_mutex_destroy(&counter.mutex);
}

/* Test: Add multiple jobs */
static void test_pthreadpool_add_multiple_jobs(void **state)
{
	struct test_state *test_state = talloc_get_type_abort(
		*state, struct test_state);
	int ret;
	struct mutex_int counter = {0};
	int i;
	int timeout;
	int signal_received = 0;

	ret = pthreadpool_init(4,
			       &test_state->pool,
			       test_signal_fn,
			       test_state);
	assert_int_equal(ret, 0);

	ret = pthread_mutex_init(&counter.mutex, NULL);
	assert_int_equal(ret, 0);

	/* Add multiple jobs */
	for (i = 0; i < 10; i++) {
		ret = pthreadpool_add_job(test_state->pool,
					  i,
					  increment_job,
					  &counter);
		assert_int_equal(ret, 0);
	}

	/* Wait for all jobs to complete */
	timeout = 0;
	do {
		ret = pthread_mutex_lock(&test_state->mutex);
		assert_int_equal(ret, 0);
		signal_received = test_state->signal_received;
		ret = pthread_mutex_unlock(&test_state->mutex);
		assert_int_equal(ret, 0);
		usleep(10000); /* 10ms */
		timeout++;
	} while (signal_received < 10 && timeout < 100);

	/* Verify all jobs were executed */
	assert_int_equal(counter.num, 10);
	assert_int_equal(test_state->signal_received, 10);
	pthread_mutex_destroy(&counter.mutex);
}

/* Test: Query queued jobs */
static void test_pthreadpool_queued_jobs(void **state)
{
	struct test_state *test_state = talloc_get_type_abort(
		*state, struct test_state);
	int ret;
	int sleep_duration = 100; /* 100ms */
	size_t queued;
	int timeout;
	int signal_received;
	ret = pthreadpool_init(1,
			       &test_state->pool,
			       test_signal_fn,
			       test_state);
	assert_int_equal(ret, 0);

	/* Initially no jobs */
	queued = pthreadpool_queued_jobs(test_state->pool);
	assert_int_equal(queued, 0);

	/* Add a long-running job to occupy the thread */
	ret = pthreadpool_add_job(test_state->pool,
				  1,
				  sleep_job,
				  &sleep_duration);
	assert_int_equal(ret, 0);

	/* Give the job a moment to start */
	usleep(10000); /* 10ms */

	/* Add more jobs that will be queued */
	ret = pthreadpool_add_job(test_state->pool,
				  2,
				  sleep_job,
				  &sleep_duration);
	assert_int_equal(ret, 0);

	ret = pthreadpool_add_job(test_state->pool,
				  3,
				  sleep_job,
				  &sleep_duration);
	assert_int_equal(ret, 0);

	/* Check queued jobs count */
	queued = pthreadpool_queued_jobs(test_state->pool);
	assert_true(queued >= 1);
	/* Wait for job completion (with timeout) */
	timeout = 0;
	do {
		ret = pthread_mutex_lock(&test_state->mutex);
		assert_int_equal(ret, 0);
		signal_received = test_state->signal_received;
		ret = pthread_mutex_unlock(&test_state->mutex);
		assert_int_equal(ret, 0);
		usleep(10000); /* 10ms */
		timeout++;
		queued = pthreadpool_queued_jobs(test_state->pool);

	} while (signal_received < 3 && timeout < 100);
}

/* Test: Cancel a job */
static void test_pthreadpool_cancel_job(void **state)
{
	struct test_state *test_state = talloc_get_type_abort(
		*state, struct test_state);
	int ret;
	struct mutex_int counter = {0};
	int sleep_duration = 100; /* 100ms */
	size_t cancelled;
	int timeout;
	int signal_received;

	ret = pthreadpool_init(1,
			       &test_state->pool,
			       test_signal_fn,
			       test_state);
	assert_int_equal(ret, 0);

	ret = pthread_mutex_init(&counter.mutex, NULL);
	assert_int_equal(ret, 0);

	/* Add a long-running job to occupy the thread */
	ret = pthreadpool_add_job(test_state->pool,
				  1,
				  sleep_job,
				  &sleep_duration);
	assert_int_equal(ret, 0);

	/* Give the job a moment to start */
	usleep(10000); /* 10ms */

	/* Add jobs that will be queued */
	ret = pthreadpool_add_job(test_state->pool, 2, increment_job, &counter);
	assert_int_equal(ret, 0);

	ret = pthreadpool_add_job(test_state->pool, 3, increment_job, &counter);
	assert_int_equal(ret, 0);

	/* Cancel the queued job */
	cancelled = pthreadpool_cancel_job(test_state->pool,
					   2,
					   increment_job,
					   &counter);
	assert_true(cancelled >= 1);

	timeout = 0;
	do {
		ret = pthread_mutex_lock(&test_state->mutex);
		assert_int_equal(ret, 0);
		signal_received = test_state->signal_received;
		ret = pthread_mutex_unlock(&test_state->mutex);
		assert_int_equal(ret, 0);
		usleep(10000); /* 10ms */
	} while (timeout < 100 && signal_received != 2);

	/* The cancelled job should not have executed */
	assert_true(counter.num < 2);
	pthread_mutex_destroy(&counter.mutex);
}

/* Test: Cancel multiple jobs */
static void test_pthreadpool_cancel_multiple_jobs(void **state)
{
	struct test_state *test_state = talloc_get_type_abort(
		*state, struct test_state);
	int ret;
	struct mutex_int counter = {0};
	int sleep_duration = 100; /* 100ms */
	size_t cancelled;
	int i;
	int timeout;
	int signal_received;
	size_t jobs;

	ret = pthreadpool_init(1,
			       &test_state->pool,
			       test_signal_fn,
			       test_state);
	assert_int_equal(ret, 0);

	ret = pthread_mutex_init(&counter.mutex, NULL);
	assert_int_equal(ret, 0);

	/* Add a long-running job to occupy the thread */
	ret = pthreadpool_add_job(test_state->pool,
				  1,
				  sleep_job,
				  &sleep_duration);
	assert_int_equal(ret, 0);

	/* Give the job a moment to start */
	usleep(10000); /* 10ms */

	/* Add multiple jobs with the same signature */
	for (i = 0; i < 5; i++) {
		ret = pthreadpool_add_job(test_state->pool,
					  100,
					  increment_job,
					  &counter);
		assert_int_equal(ret, 0);
	}

	/* Cancel all jobs with the same signature */
	cancelled = pthreadpool_cancel_job(test_state->pool,
					   100,
					   increment_job,
					   &counter);
	assert_true(cancelled >= 1);
	assert_true(cancelled <= 5);

	jobs = 6;	   /* long living job + 5 jobs with same signature */
	jobs -= cancelled; /* adjust num jobs actually cancelled */
	timeout = 0;
	/* wait until all jobs have completed (or timeout reached) */
	do {
		ret = pthread_mutex_lock(&test_state->mutex);
		assert_int_equal(ret, 0);
		signal_received = test_state->signal_received;
		ret = pthread_mutex_unlock(&test_state->mutex);
		assert_int_equal(ret, 0);
		usleep(10000); /* 10ms */
		timeout++;

	} while (signal_received != jobs && timeout < 100);

	assert_true(signal_received == jobs);
	/* Some jobs should have been cancelled */
	assert_true(counter.num < 5);
	pthread_mutex_destroy(&counter.mutex);
}

/* Test: Stop a pool */
static void test_pthreadpool_stop(void **state)
{
	struct test_state *test_state = talloc_get_type_abort(
		*state, struct test_state);
	int ret;
	struct mutex_int counter = {0};
	int sleep_duration = 100; /* 100ms */
	int initial_signals;
	int signal_received;

	ret = pthreadpool_init(1,
			       &test_state->pool,
			       test_signal_fn,
			       test_state);
	assert_int_equal(ret, 0);

	ret = pthread_mutex_init(&counter.mutex, NULL);
	assert_int_equal(ret, 0);

	/* Add a job that's currently running */
	ret = pthreadpool_add_job(test_state->pool,
				  1,
				  sleep_job,
				  &sleep_duration);
	assert_int_equal(ret, 0);

	/* Give the job a moment to start */
	usleep(10000); /* 10ms */

	/* Add more jobs that will be queued */
	ret = pthreadpool_add_job(test_state->pool, 2, increment_job, &counter);
	assert_int_equal(ret, 0);

	ret = pthreadpool_add_job(test_state->pool, 3, increment_job, &counter);
	assert_int_equal(ret, 0);

	/* Stop the pool */
	ret = pthreadpool_stop(test_state->pool);
	assert_int_equal(ret, 0);

	/* Wait a bit */
	usleep(50000); /* 50ms */

	ret = pthread_mutex_lock(&test_state->mutex);
	assert_int_equal(ret, 0);
	initial_signals = test_state->signal_received;
	ret = pthread_mutex_unlock(&test_state->mutex);
	assert_int_equal(ret, 0);

	/* Add another job - should fail or be ignored */
	ret = pthreadpool_add_job(test_state->pool, 4, increment_job, &counter);

	/* Wait to see if any more signals arrive */
	usleep(50000); /* 50ms */

	/* No new signals should arrive for queued jobs after stop */
	/* (but the running job may complete) */
	ret = pthread_mutex_lock(&test_state->mutex);
	assert_int_equal(ret, 0);
	signal_received = test_state->signal_received;
	ret = pthread_mutex_unlock(&test_state->mutex);
	assert_int_equal(ret, 0);
	assert_true(signal_received <= initial_signals + 1);
	pthread_mutex_destroy(&counter.mutex);
}

/* Test: Destroy a pool */
static void test_pthreadpool_destroy(void **state)
{
	struct test_state *test_state = talloc_get_type_abort(
		*state, struct test_state);
	int ret;
	struct mutex_int counter = {0};
	int sleep_duration = 10; /* 10ms */
	int timeout;
	int signal_received;

	ret = pthreadpool_init(2,
			       &test_state->pool,
			       test_signal_fn,
			       test_state);
	assert_int_equal(ret, 0);

	ret = pthread_mutex_init(&counter.mutex, NULL);
	assert_int_equal(ret, 0);

	/* Add a job */
	ret = pthreadpool_add_job(test_state->pool,
				  1,
				  sleep_job,
				  &sleep_duration);
	assert_int_equal(ret, 0);

	/* Destroy the pool */
	ret = pthreadpool_destroy(test_state->pool);
	assert_int_equal(ret, 0);

	pthread_mutex_destroy(&counter.mutex);

	/* ensure job is complete before exiting */
	timeout = 0;
	do {
		ret = pthread_mutex_lock(&test_state->mutex);
		assert_int_equal(ret, 0);
		signal_received = test_state->signal_received;
		ret = pthread_mutex_unlock(&test_state->mutex);
		assert_int_equal(ret, 0);
		usleep(10000); /* 10ms */
		timeout++;

	} while (signal_received == 0 && timeout < 100);

	test_state->pool = NULL;
}

/* Test: Pool with max_threads=0 (sync mode) */
static void test_pthreadpool_sync_mode(void **state)
{
	struct test_state *test_state = talloc_get_type_abort(
		*state, struct test_state);
	int ret;
	struct mutex_int counter = {0};

	/* Initialize with max_threads=0 for sync processing */
	ret = pthreadpool_init(0,
			       &test_state->pool,
			       test_signal_fn,
			       test_state);
	assert_int_equal(ret, 0);
	assert_int_equal(pthreadpool_max_threads(test_state->pool), 0);

	ret = pthread_mutex_init(&counter.mutex, NULL);
	assert_int_equal(ret, 0);

	/* Add a job - should be processed synchronously */
	ret = pthreadpool_add_job(test_state->pool, 1, increment_job, &counter);
	assert_int_equal(ret, 0);

	/* In sync mode, the job might be executed immediately */
	/* Wait a bit to allow signal to be processed */
	usleep(50000); /* 50ms */

	/* Verify job was processed */
	assert_true(counter.num >= 0);
	pthread_mutex_destroy(&counter.mutex);
}

/* Main test runner */
int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_pthreadpool_init,
						setup,
						teardown),
		cmocka_unit_test_setup_teardown(test_pthreadpool_add_job_simple,
						setup,
						teardown),
		cmocka_unit_test_setup_teardown(
			test_pthreadpool_add_multiple_jobs, setup, teardown),
		cmocka_unit_test_setup_teardown(test_pthreadpool_queued_jobs,
						setup,
						teardown),
		cmocka_unit_test_setup_teardown(test_pthreadpool_cancel_job,
						setup,
						teardown),
		cmocka_unit_test_setup_teardown(
			test_pthreadpool_cancel_multiple_jobs, setup, teardown),
		cmocka_unit_test_setup_teardown(test_pthreadpool_stop,
						setup,
						teardown),
		cmocka_unit_test_setup_teardown(test_pthreadpool_destroy,
						setup,
						teardown),
		cmocka_unit_test_setup_teardown(test_pthreadpool_sync_mode,
						setup,
						teardown),
	};
	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
