/*
 * Unix SMB/CIFS implementation.
 *
 * Test that a thread's wakeup write does not hit a reused fd
 *
 * Copyright (C) Volker Lendecke 2026
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* RTLD_NEXT */
#endif

#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <talloc.h>
#include <tevent.h>
#include <cmocka.h>

/*
 * _tevent_threaded_schedule_immediate() wakes up the main thread by
 * writing to the event context's wakeup fd. libtevent calls write()
 * through the dynamic linker, so the definition below takes
 * precedence over the one in libc. It stops the first write() of the
 * worker thread before it reaches the kernel until the main thread
 * has freed the event context and reopened the fd number, or until a
 * timeout after the main thread started freeing expires.
 */

struct write_gate {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	bool armed;
	pthread_t worker;
	bool at_write;
	bool worker_done;
	int fd;
	bool freeing;
	bool reopened;
};

static struct write_gate gate = {
	.mutex = PTHREAD_MUTEX_INITIALIZER,
	.cond = PTHREAD_COND_INITIALIZER,
	.fd = -1,
};

static void gate_wait_reopened(void)
{
	struct timespec abstime = {};
	int ret;

	while (!gate.freeing) {
		ret = pthread_cond_wait(&gate.cond, &gate.mutex);
		if (ret != 0) {
			abort();
		}
	}

	ret = clock_gettime(CLOCK_REALTIME, &abstime);
	if (ret != 0) {
		abort();
	}

	/*
	 * Without the fix the main thread frees the event context and
	 * reopens the fd quickly. With the fix it waits for this write
	 * to finish, so time out.
	 */
	abstime.tv_sec += 1;

	while (!gate.reopened) {
		ret = pthread_cond_timedwait(&gate.cond,
					     &gate.mutex,
					     &abstime);
		if (ret == ETIMEDOUT) {
			break;
		}
		if (ret != 0) {
			abort();
		}
	}
}

ssize_t write(int fd, const void *buf, size_t count)
{
	static ssize_t (*real_write)(int, const void *, size_t) = NULL;
	pthread_t self = pthread_self();
	bool is_worker = false;
	int ret;

	if (real_write == NULL) {
		real_write = dlsym(RTLD_NEXT, "write");
		if (real_write == NULL) {
			abort();
		}
	}

	ret = pthread_mutex_lock(&gate.mutex);
	if (ret != 0) {
		abort();
	}

	if (gate.armed) {
		is_worker = (pthread_equal(gate.worker, self) != 0);
	}

	if (is_worker) {
		gate.armed = false;
		gate.fd = fd;
		gate.at_write = true;

		ret = pthread_cond_broadcast(&gate.cond);
		if (ret != 0) {
			abort();
		}

		gate_wait_reopened();
	}

	ret = pthread_mutex_unlock(&gate.mutex);
	if (ret != 0) {
		abort();
	}

	return real_write(fd, buf, count);
}

struct worker_state {
	struct tevent_threaded_context *tctx;
	struct tevent_immediate *im;
	bool done;
};

static void immediate_handler(struct tevent_context *ev,
			      struct tevent_immediate *im,
			      void *private_data)
{
	struct worker_state *state = private_data;

	state->done = true;
}

static void *worker_fn(void *private_data)
{
	struct worker_state *state = private_data;
	int ret;

	ret = pthread_mutex_lock(&gate.mutex);
	if (ret != 0) {
		abort();
	}
	gate.worker = pthread_self();
	gate.armed = true;
	ret = pthread_mutex_unlock(&gate.mutex);
	if (ret != 0) {
		abort();
	}

	tevent_threaded_schedule_immediate(state->tctx,
					   state->im,
					   immediate_handler,
					   state);

	/*
	 * Don't let the main thread hang if write() was not
	 * interposed.
	 */
	ret = pthread_mutex_lock(&gate.mutex);
	if (ret != 0) {
		abort();
	}
	gate.worker_done = true;
	ret = pthread_cond_broadcast(&gate.cond);
	if (ret != 0) {
		abort();
	}
	ret = pthread_mutex_unlock(&gate.mutex);
	if (ret != 0) {
		abort();
	}

	return NULL;
}

static void test_wakeup_after_free(void **private_data)
{
	struct tevent_context *ev = NULL;
	struct worker_state state = {};
	FILE *files[16] = {};
	FILE *victim = NULL;
	struct stat st = {};
	pthread_t worker;
	size_t i;
	int fd;
	int ret;

	ev = tevent_context_init(NULL);
	assert_non_null(ev);

	state.tctx = tevent_threaded_context_create(ev, ev);
	assert_non_null(state.tctx);

	state.im = tevent_create_immediate(ev);
	assert_non_null(state.im);

	ret = pthread_create(&worker, NULL, worker_fn, &state);
	assert_int_equal(ret, 0);

	/*
	 * Wait until the worker has queued the immediate and is about
	 * to write the wakeup.
	 */
	ret = pthread_mutex_lock(&gate.mutex);
	assert_int_equal(ret, 0);
	while (!gate.at_write && !gate.worker_done) {
		ret = pthread_cond_wait(&gate.cond, &gate.mutex);
		assert_int_equal(ret, 0);
	}
	ret = pthread_mutex_unlock(&gate.mutex);
	assert_int_equal(ret, 0);
	assert_true(gate.at_write);

	/*
	 * The loop picks up the queued immediate without needing the
	 * wakeup.
	 */
	ret = tevent_loop_once(ev);
	assert_int_equal(ret, 0);
	assert_true(state.done);

	ret = pthread_mutex_lock(&gate.mutex);
	assert_int_equal(ret, 0);
	gate.freeing = true;
	ret = pthread_cond_broadcast(&gate.cond);
	assert_int_equal(ret, 0);
	ret = pthread_mutex_unlock(&gate.mutex);
	assert_int_equal(ret, 0);

	/*
	 * Free the threaded context first, as documented. Freeing the
	 * event context closes the wakeup fd.
	 */
	TALLOC_FREE(state.tctx);
	TALLOC_FREE(ev);

	for (i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
		files[i] = tmpfile();
		assert_non_null(files[i]);

		fd = fileno(files[i]);
		if (fd == gate.fd) {
			victim = files[i];
			break;
		}
	}
	assert_non_null(victim);

	ret = pthread_mutex_lock(&gate.mutex);
	assert_int_equal(ret, 0);
	gate.reopened = true;
	ret = pthread_cond_broadcast(&gate.cond);
	assert_int_equal(ret, 0);
	ret = pthread_mutex_unlock(&gate.mutex);
	assert_int_equal(ret, 0);

	ret = pthread_join(worker, NULL);
	assert_int_equal(ret, 0);

	/*
	 * The wakeup write must not have ended up in the file that
	 * reused the wakeup fd number.
	 */
	fd = fileno(victim);
	ret = fstat(fd, &st);
	assert_int_equal(ret, 0);
	assert_int_equal(st.st_size, 0);

	for (i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
		if (files[i] != NULL) {
			fclose(files[i]);
		}
	}
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_wakeup_after_free),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
