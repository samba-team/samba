/*
 * Unit tests for pthreadpool_pipe using CMocka
 * Copyright (C) 2025
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <string.h>
#include <sys/wait.h>
#include <talloc.h>
#include "pthreadpool_pipe.h"

/* Test fixture structure */
struct test_state {
	struct pthreadpool_pipe *pool;
	int job_executed;
	pthread_mutex_t mutex;
};

/* Setup function - runs before each test */
static int setup(void **state)
{
	struct test_state *test_state = talloc_zero(NULL, struct test_state);
	assert_non_null(test_state);

	pthread_mutex_init(&test_state->mutex, NULL);
	test_state->job_executed = 0;

	*state = test_state;
	return 0;
}

/* Teardown function - runs after each test */
static int teardown(void **state)
{
	struct test_state *test_state = *state;

	if (test_state->pool != NULL) {
		pthreadpool_pipe_destroy(test_state->pool);
	}

	pthread_mutex_destroy(&test_state->mutex);
	TALLOC_FREE(test_state);
	return 0;
}

/* Job function that uses mutex */
static void mutex_job(void *private_data)
{
	struct test_state *state = talloc_get_type_abort(private_data,
							 struct test_state);
	pthread_mutex_lock(&state->mutex);
	state->job_executed++;
	pthread_mutex_unlock(&state->mutex);
}

static int get_id_from_jobs(int id, int *jobs, int num_jobs)
{
	int i;
	for (i = 0; i < num_jobs; i++) {
		if (jobs[i] == id) {
			return id;
		}
	}
	return -1;
}

/* Test: Initialize pool with valid parameters */
static void test_init_valid(void **state)
{
	struct test_state *test_state = *state;
	int ret;

	ret = pthreadpool_pipe_init(4, &test_state->pool);
	assert_int_equal(ret, 0);
	assert_non_null(test_state->pool);
}

/* Test: Initialize pool with zero threads */
static void test_init_zero_threads(void **state)
{
	struct test_state *test_state = *state;
	int ret;

	ret = pthreadpool_pipe_init(0, &test_state->pool);
	assert_true(ret == 0);
}

/* Test: Get signal fd from valid pool */
static void test_signal_fd_valid(void **state)
{
	struct test_state *test_state = *state;
	int ret, fd;

	ret = pthreadpool_pipe_init(4, &test_state->pool);
	assert_int_equal(ret, 0);

	fd = pthreadpool_pipe_signal_fd(test_state->pool);
	assert_true(fd >= 0);
}

/* Test: Add single job */
static void test_add_single_job(void **state)
{
	struct test_state *test_state = *state;
	int ret = 0;
	int job;
	ret = pthreadpool_pipe_init(4, &test_state->pool);
	assert_int_equal(ret, 0);

	ret = pthreadpool_pipe_add_job(test_state->pool,
				       99,
				       mutex_job,
				       test_state);
	assert_int_equal(ret, 0);

	ret = pthreadpool_pipe_finished_jobs(test_state->pool,
					     &job,
					     1);
	assert_int_equal(ret, 1);
	assert_int_equal(job, 99);
	assert_int_equal(test_state->job_executed, 1);
}

/* Test: Add multiple jobs */
static void test_add_multiple_jobs(void **state)
{
	struct test_state *test_state = *state;
	int ret, i;
	int num_jobs = 100;
	int jobs_complete_ids[num_jobs];
	int jobs[num_jobs];
	int jobs_complete = 0;

	ret = pthreadpool_pipe_init(4, &test_state->pool);
	assert_int_equal(ret, 0);

	for (i = 0; i < num_jobs; i++) {
		ret = pthreadpool_pipe_add_job(test_state->pool,
					       i,
					       mutex_job,
					       test_state);
		assert_int_equal(ret, 0);
	}

	do {
		ret = pthreadpool_pipe_finished_jobs(test_state->pool,
					     jobs,
					     num_jobs);
		memcpy(jobs_complete_ids + jobs_complete,
		       jobs,
		       (ret * sizeof(int)));
		jobs_complete += ret;
	} while (jobs_complete < num_jobs);

	for (i = 0; i < num_jobs; i++) {
		assert_int_equal(i, get_id_from_jobs(i,
						     jobs_complete_ids,
						     num_jobs));
	}
	assert_int_equal(test_state->job_executed, num_jobs);
}

/* Test: Signal fd becomes readable after job completion */
static void test_signal_fd_readable(void **state)
{
	struct test_state *test_state = *state;
	int ret, fd;
	struct pollfd pfd;
	int job;

	ret = pthreadpool_pipe_init(4, &test_state->pool);
	assert_int_equal(ret, 0);

	fd = pthreadpool_pipe_signal_fd(test_state->pool);
	assert_true(fd >= 0);

	/* Add a job */
	ret = pthreadpool_pipe_add_job(test_state->pool,
				       101,
				       mutex_job,
				       test_state);
	assert_int_equal(ret, 0);

	/* Wait for fd to become readable */
	pfd.fd = fd;
	pfd.events = POLLIN;
	ret = poll(&pfd, 1, 2000); /* 2 second timeout */

	assert_true(ret > 0);
	assert_true(pfd.revents & POLLIN);
	ret = pthreadpool_pipe_finished_jobs(test_state->pool,
					     &job,
					     1);
	assert_int_equal(job, 101);
}

/* Test: Thread safety with mutex-protected job */
static void test_thread_safety(void **state)
{
	struct test_state *test_state = *state;
	int ret, i;
	int num_jobs = 100;
	int jobs_complete = 0;
	int jobs[num_jobs];
	ret = pthreadpool_pipe_init(4, &test_state->pool);
	assert_int_equal(ret, 0);

	for (i = 0; i < num_jobs; i++) {
		ret = pthreadpool_pipe_add_job(test_state->pool,
					       i,
					       mutex_job,
					       test_state);
		assert_int_equal(ret, 0);
	}

	do {
		ret = pthreadpool_pipe_finished_jobs(test_state->pool,
					     jobs,
					     num_jobs);
		jobs_complete += ret;
	} while (jobs_complete < num_jobs);

	assert_int_equal(test_state->job_executed, num_jobs);
}

static void fork_job(void *private_data)
{
	int status;
	struct test_state *test_state =
		talloc_get_type_abort(private_data, struct test_state);
	pid_t pid, wpid;
	pid = fork();
	/* Ensure fork success */
	assert_true(!(pid < 0));
	if (pid == 0) {
		/* child */
		int ret = 0;
		int job;
		ret = pthreadpool_pipe_add_job(test_state->pool,
					       99,
					       mutex_job,
					       test_state);
		assert_int_equal(ret, 0);
		ret = pthreadpool_pipe_finished_jobs(test_state->pool,
						     &job,
						     1);
		assert_int_equal(ret, 1);
		assert_int_equal(job, 99);
		assert_int_equal(test_state->job_executed, 1);
		exit(0);
	} else {
		wpid = waitpid(pid, &status, 0);
		assert_true(wpid != -1);
	}
}

static void test_fork(void **state)
{
	struct test_state *test_state =
		talloc_get_type_abort(*state, struct test_state);
	int ret;
	int job;
	ret = pthreadpool_pipe_init(4, &test_state->pool);
	assert_int_equal(ret, 0);
	ret = pthreadpool_pipe_add_job(test_state->pool,
				       999,
				       fork_job,
				       test_state);
	assert_int_equal(ret, 0);
	ret = pthreadpool_pipe_finished_jobs(test_state->pool,
					     &job,
					     1);
	assert_int_equal(ret, 1);
	assert_int_equal(job, 999);
}

/* Main test runner */
int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_init_valid,
						setup,
						teardown),
		cmocka_unit_test_setup_teardown(test_init_zero_threads,
						setup,
						teardown),
		cmocka_unit_test_setup_teardown(test_signal_fd_valid,
						setup,
						teardown),
		cmocka_unit_test_setup_teardown(test_add_single_job,
						setup,
						teardown),
		cmocka_unit_test_setup_teardown(test_add_multiple_jobs,
						setup,
						teardown),
		cmocka_unit_test_setup_teardown(test_signal_fd_readable,
						setup,
						teardown),
		cmocka_unit_test_setup_teardown(test_thread_safety,
						setup,
						teardown),
		cmocka_unit_test_setup_teardown(test_fork,
						setup,
						teardown),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
