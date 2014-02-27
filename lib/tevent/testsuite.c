/* 
   Unix SMB/CIFS implementation.

   testing of the events subsystem

   Copyright (C) Stefan Metzmacher 2006-2009
   Copyright (C) Jeremy Allison    2013

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

#include "includes.h"
#include "lib/tevent/tevent.h"
#include "system/filesys.h"
#include "system/select.h"
#include "system/network.h"
#include "torture/torture.h"
#include "torture/local/proto.h"
#ifdef HAVE_PTHREAD
#include <pthread.h>
#include <assert.h>
#endif

static int fde_count;

static void fde_handler_read(struct tevent_context *ev_ctx, struct tevent_fd *f,
			uint16_t flags, void *private_data)
{
	int *fd = (int *)private_data;
	char c;
#ifdef SA_SIGINFO
	kill(getpid(), SIGUSR1);
#endif
	kill(getpid(), SIGALRM);

	read(fd[0], &c, 1);
	fde_count++;
}

static void fde_handler_write(struct tevent_context *ev_ctx, struct tevent_fd *f,
			uint16_t flags, void *private_data)
{
	int *fd = (int *)private_data;
	char c = 0;
	write(fd[1], &c, 1);
}


/* This will only fire if the fd's returned from pipe() are bi-directional. */
static void fde_handler_read_1(struct tevent_context *ev_ctx, struct tevent_fd *f,
			uint16_t flags, void *private_data)
{
	int *fd = (int *)private_data;
	char c;
#ifdef SA_SIGINFO
	kill(getpid(), SIGUSR1);
#endif
	kill(getpid(), SIGALRM);

	read(fd[1], &c, 1);
	fde_count++;
}

/* This will only fire if the fd's returned from pipe() are bi-directional. */
static void fde_handler_write_1(struct tevent_context *ev_ctx, struct tevent_fd *f,
			uint16_t flags, void *private_data)
{
	int *fd = (int *)private_data;
	char c = 0;
	write(fd[0], &c, 1);
}

static void finished_handler(struct tevent_context *ev_ctx, struct tevent_timer *te,
			     struct timeval tval, void *private_data)
{
	int *finished = (int *)private_data;
	(*finished) = 1;
}

static void count_handler(struct tevent_context *ev_ctx, struct tevent_signal *te,
			  int signum, int count, void *info, void *private_data)
{
	int *countp = (int *)private_data;
	(*countp) += count;
}

static bool test_event_context(struct torture_context *test,
			       const void *test_data)
{
	struct tevent_context *ev_ctx;
	int fd[2] = { -1, -1 };
	const char *backend = (const char *)test_data;
	int alarm_count=0, info_count=0;
	struct tevent_fd *fde_read;
	struct tevent_fd *fde_read_1;
	struct tevent_fd *fde_write;
	struct tevent_fd *fde_write_1;
#ifdef SA_RESTART
	struct tevent_signal *se1 = NULL;
#endif
#ifdef SA_RESETHAND
	struct tevent_signal *se2 = NULL;
#endif
#ifdef SA_SIGINFO
	struct tevent_signal *se3 = NULL;
#endif
	int finished=0;
	struct timeval t;

	ev_ctx = tevent_context_init_byname(test, backend);
	if (ev_ctx == NULL) {
		torture_comment(test, "event backend '%s' not supported\n", backend);
		return true;
	}

	torture_comment(test, "backend '%s' - %s\n",
			backend, __FUNCTION__);

	/* reset globals */
	fde_count = 0;

	/* create a pipe */
	pipe(fd);

	fde_read = tevent_add_fd(ev_ctx, ev_ctx, fd[0], TEVENT_FD_READ,
			    fde_handler_read, fd);
	fde_write_1 = tevent_add_fd(ev_ctx, ev_ctx, fd[0], TEVENT_FD_WRITE,
			    fde_handler_write_1, fd);

	fde_write = tevent_add_fd(ev_ctx, ev_ctx, fd[1], TEVENT_FD_WRITE,
			    fde_handler_write, fd);
	fde_read_1 = tevent_add_fd(ev_ctx, ev_ctx, fd[1], TEVENT_FD_READ,
			    fde_handler_read_1, fd);

	tevent_fd_set_auto_close(fde_read);
	tevent_fd_set_auto_close(fde_write);

	tevent_add_timer(ev_ctx, ev_ctx, timeval_current_ofs(2,0),
			 finished_handler, &finished);

#ifdef SA_RESTART
	se1 = tevent_add_signal(ev_ctx, ev_ctx, SIGALRM, SA_RESTART, count_handler, &alarm_count);
	torture_assert(test, se1 != NULL, "failed to setup se1");
#endif
#ifdef SA_RESETHAND
	se2 = tevent_add_signal(ev_ctx, ev_ctx, SIGALRM, SA_RESETHAND, count_handler, &alarm_count);
	torture_assert(test, se2 != NULL, "failed to setup se2");
#endif
#ifdef SA_SIGINFO
	se3 = tevent_add_signal(ev_ctx, ev_ctx, SIGUSR1, SA_SIGINFO, count_handler, &info_count);
	torture_assert(test, se3 != NULL, "failed to setup se3");
#endif

	t = timeval_current();
	while (!finished) {
		errno = 0;
		if (tevent_loop_once(ev_ctx) == -1) {
			talloc_free(ev_ctx);
			torture_fail(test, talloc_asprintf(test, "Failed event loop %s\n", strerror(errno)));
		}
	}

	talloc_free(fde_read);
	talloc_free(fde_write);
	talloc_free(fde_read_1);
	talloc_free(fde_write_1);

	while (alarm_count < fde_count+1) {
		if (tevent_loop_once(ev_ctx) == -1) {
			break;
		}
	}

	torture_comment(test, "Got %.2f pipe events/sec\n", fde_count/timeval_elapsed(&t));

#ifdef SA_RESTART
	talloc_free(se1);
#endif

	torture_assert_int_equal(test, alarm_count, 1+fde_count, "alarm count mismatch");

#ifdef SA_RESETHAND
	/*
	 * we do not call talloc_free(se2)
	 * because it is already gone,
	 * after triggering the event handler.
	 */
#endif

#ifdef SA_SIGINFO
	talloc_free(se3);
	torture_assert_int_equal(test, info_count, fde_count, "info count mismatch");
#endif

	talloc_free(ev_ctx);

	return true;
}

struct test_event_fd1_state {
	struct torture_context *tctx;
	const char *backend;
	struct tevent_context *ev;
	int sock[2];
	struct tevent_timer *te;
	struct tevent_fd *fde0;
	struct tevent_fd *fde1;
	bool got_write;
	bool got_read;
	bool drain;
	bool drain_done;
	unsigned loop_count;
	bool finished;
	const char *error;
};

static void test_event_fd1_fde_handler(struct tevent_context *ev_ctx,
				       struct tevent_fd *fde,
				       uint16_t flags,
				       void *private_data)
{
	struct test_event_fd1_state *state =
		(struct test_event_fd1_state *)private_data;

	if (state->drain_done) {
		state->finished = true;
		state->error = __location__;
		return;
	}

	if (state->drain) {
		ssize_t ret;
		uint8_t c = 0;

		if (!(flags & TEVENT_FD_READ)) {
			state->finished = true;
			state->error = __location__;
			return;
		}

		ret = read(state->sock[0], &c, 1);
		if (ret == 1) {
			return;
		}

		/*
		 * end of test...
		 */
		tevent_fd_set_flags(fde, 0);
		state->drain_done = true;
		return;
	}

	if (!state->got_write) {
		uint8_t c = 0;

		if (flags != TEVENT_FD_WRITE) {
			state->finished = true;
			state->error = __location__;
			return;
		}
		state->got_write = true;

		/*
		 * we write to the other socket...
		 */
		write(state->sock[1], &c, 1);
		TEVENT_FD_NOT_WRITEABLE(fde);
		TEVENT_FD_READABLE(fde);
		return;
	}

	if (!state->got_read) {
		if (flags != TEVENT_FD_READ) {
			state->finished = true;
			state->error = __location__;
			return;
		}
		state->got_read = true;

		TEVENT_FD_NOT_READABLE(fde);
		return;
	}

	state->finished = true;
	state->error = __location__;
	return;
}

static void test_event_fd1_finished(struct tevent_context *ev_ctx,
				    struct tevent_timer *te,
				    struct timeval tval,
				    void *private_data)
{
	struct test_event_fd1_state *state =
		(struct test_event_fd1_state *)private_data;

	if (state->drain_done) {
		state->finished = true;
		return;
	}

	if (!state->got_write) {
		state->finished = true;
		state->error = __location__;
		return;
	}

	if (!state->got_read) {
		state->finished = true;
		state->error = __location__;
		return;
	}

	state->loop_count++;
	if (state->loop_count > 3) {
		state->finished = true;
		state->error = __location__;
		return;
	}

	state->got_write = false;
	state->got_read = false;

	tevent_fd_set_flags(state->fde0, TEVENT_FD_WRITE);

	if (state->loop_count > 2) {
		state->drain = true;
		TALLOC_FREE(state->fde1);
		TEVENT_FD_READABLE(state->fde0);
	}

	state->te = tevent_add_timer(state->ev, state->ev,
				    timeval_current_ofs(0,2000),
				    test_event_fd1_finished, state);
}

static bool test_event_fd1(struct torture_context *tctx,
			   const void *test_data)
{
	struct test_event_fd1_state state;

	ZERO_STRUCT(state);
	state.tctx = tctx;
	state.backend = (const char *)test_data;

	state.ev = tevent_context_init_byname(tctx, state.backend);
	if (state.ev == NULL) {
		torture_skip(tctx, talloc_asprintf(tctx,
			     "event backend '%s' not supported\n",
			     state.backend));
		return true;
	}

	tevent_set_debug_stderr(state.ev);
	torture_comment(tctx, "backend '%s' - %s\n",
			state.backend, __FUNCTION__);

	/*
	 * This tests the following:
	 *
	 * It monitors the state of state.sock[0]
	 * with tevent_fd, but we never read/write on state.sock[0]
	 * while state.sock[1] * is only used to write a few bytes.
	 *
	 * We have a loop:
	 *   - we wait only for TEVENT_FD_WRITE on state.sock[0]
	 *   - we write 1 byte to state.sock[1]
	 *   - we wait only for TEVENT_FD_READ on state.sock[0]
	 *   - we disable events on state.sock[0]
	 *   - the timer event restarts the loop
	 * Then we close state.sock[1]
	 * We have a loop:
	 *   - we wait for TEVENT_FD_READ/WRITE on state.sock[0]
	 *   - we try to read 1 byte
	 *   - if the read gets an error of returns 0
	 *     we disable the event handler
	 *   - the timer finishes the test
	 */
	state.sock[0] = -1;
	state.sock[1] = -1;
	socketpair(AF_UNIX, SOCK_STREAM, 0, state.sock);

	state.te = tevent_add_timer(state.ev, state.ev,
				    timeval_current_ofs(0,1000),
				    test_event_fd1_finished, &state);
	state.fde0 = tevent_add_fd(state.ev, state.ev,
				   state.sock[0], TEVENT_FD_WRITE,
				   test_event_fd1_fde_handler, &state);
	/* state.fde1 is only used to auto close */
	state.fde1 = tevent_add_fd(state.ev, state.ev,
				   state.sock[1], 0,
				   test_event_fd1_fde_handler, &state);

	tevent_fd_set_auto_close(state.fde0);
	tevent_fd_set_auto_close(state.fde1);

	while (!state.finished) {
		errno = 0;
		if (tevent_loop_once(state.ev) == -1) {
			talloc_free(state.ev);
			torture_fail(tctx, talloc_asprintf(tctx,
				     "Failed event loop %s\n",
				     strerror(errno)));
		}
	}

	talloc_free(state.ev);

	torture_assert(tctx, state.error == NULL, talloc_asprintf(tctx,
		       "%s", state.error));

	return true;
}

struct test_event_fd2_state {
	struct torture_context *tctx;
	const char *backend;
	struct tevent_context *ev;
	struct tevent_timer *te;
	struct test_event_fd2_sock {
		struct test_event_fd2_state *state;
		int fd;
		struct tevent_fd *fde;
		size_t num_written;
		size_t num_read;
		bool got_full;
	} sock0, sock1;
	bool finished;
	const char *error;
};

static void test_event_fd2_sock_handler(struct tevent_context *ev_ctx,
					struct tevent_fd *fde,
					uint16_t flags,
					void *private_data)
{
	struct test_event_fd2_sock *cur_sock =
		(struct test_event_fd2_sock *)private_data;
	struct test_event_fd2_state *state = cur_sock->state;
	struct test_event_fd2_sock *oth_sock = NULL;
	uint8_t v = 0, c;
	ssize_t ret;

	if (cur_sock == &state->sock0) {
		oth_sock = &state->sock1;
	} else {
		oth_sock = &state->sock0;
	}

	if (oth_sock->num_written == 1) {
		if (flags != (TEVENT_FD_READ | TEVENT_FD_WRITE)) {
			state->finished = true;
			state->error = __location__;
			return;
		}
	}

	if (cur_sock->num_read == oth_sock->num_written) {
		state->finished = true;
		state->error = __location__;
		return;
	}

	if (!(flags & TEVENT_FD_READ)) {
		state->finished = true;
		state->error = __location__;
		return;
	}

	if (oth_sock->num_read >= PIPE_BUF) {
		/*
		 * On Linux we become writable once we've read
		 * one byte. On Solaris we only become writable
		 * again once we've read 4096 bytes. PIPE_BUF
		 * is probably a safe bet to test against.
		 *
		 * There should be room to write a byte again
		 */
		if (!(flags & TEVENT_FD_WRITE)) {
			state->finished = true;
			state->error = __location__;
			return;
		}
	}

	if ((flags & TEVENT_FD_WRITE) && !cur_sock->got_full) {
		v = (uint8_t)cur_sock->num_written;
		ret = write(cur_sock->fd, &v, 1);
		if (ret != 1) {
			state->finished = true;
			state->error = __location__;
			return;
		}
		cur_sock->num_written++;
		if (cur_sock->num_written > 0x80000000) {
			state->finished = true;
			state->error = __location__;
			return;
		}
		return;
	}

	if (!cur_sock->got_full) {
		cur_sock->got_full = true;

		if (!oth_sock->got_full) {
			/*
			 * cur_sock is full,
			 * lets wait for oth_sock
			 * to be filled
			 */
			tevent_fd_set_flags(cur_sock->fde, 0);
			return;
		}

		/*
		 * oth_sock waited for cur_sock,
		 * lets restart it
		 */
		tevent_fd_set_flags(oth_sock->fde,
				    TEVENT_FD_READ|TEVENT_FD_WRITE);
	}

	ret = read(cur_sock->fd, &v, 1);
	if (ret != 1) {
		state->finished = true;
		state->error = __location__;
		return;
	}
	c = (uint8_t)cur_sock->num_read;
	if (c != v) {
		state->finished = true;
		state->error = __location__;
		return;
	}
	cur_sock->num_read++;

	if (cur_sock->num_read < oth_sock->num_written) {
		/* there is more to read */
		return;
	}
	/*
	 * we read everything, we need to remove TEVENT_FD_WRITE
	 * to avoid spinning
	 */
	TEVENT_FD_NOT_WRITEABLE(cur_sock->fde);

	if (oth_sock->num_read == cur_sock->num_written) {
		/*
		 * both directions are finished
		 */
		state->finished = true;
	}

	return;
}

static void test_event_fd2_finished(struct tevent_context *ev_ctx,
				    struct tevent_timer *te,
				    struct timeval tval,
				    void *private_data)
{
	struct test_event_fd2_state *state =
		(struct test_event_fd2_state *)private_data;

	/*
	 * this should never be triggered
	 */
	state->finished = true;
	state->error = __location__;
}

static bool test_event_fd2(struct torture_context *tctx,
			   const void *test_data)
{
	struct test_event_fd2_state state;
	int sock[2];
	uint8_t c = 0;

	ZERO_STRUCT(state);
	state.tctx = tctx;
	state.backend = (const char *)test_data;

	state.ev = tevent_context_init_byname(tctx, state.backend);
	if (state.ev == NULL) {
		torture_skip(tctx, talloc_asprintf(tctx,
			     "event backend '%s' not supported\n",
			     state.backend));
		return true;
	}

	tevent_set_debug_stderr(state.ev);
	torture_comment(tctx, "backend '%s' - %s\n",
			state.backend, __FUNCTION__);

	/*
	 * This tests the following
	 *
	 * - We write 1 byte to each socket
	 * - We wait for TEVENT_FD_READ/WRITE on both sockets
	 * - When we get TEVENT_FD_WRITE we write 1 byte
	 *   until both socket buffers are full, which
	 *   means both sockets only get TEVENT_FD_READ.
	 * - Then we read 1 byte until we have consumed
	 *   all bytes the other end has written.
	 */
	sock[0] = -1;
	sock[1] = -1;
	socketpair(AF_UNIX, SOCK_STREAM, 0, sock);

	/*
	 * the timer should never expire
	 */
	state.te = tevent_add_timer(state.ev, state.ev,
				    timeval_current_ofs(600, 0),
				    test_event_fd2_finished, &state);
	state.sock0.state = &state;
	state.sock0.fd = sock[0];
	state.sock0.fde = tevent_add_fd(state.ev, state.ev,
					state.sock0.fd,
					TEVENT_FD_READ | TEVENT_FD_WRITE,
					test_event_fd2_sock_handler,
					&state.sock0);
	state.sock1.state = &state;
	state.sock1.fd = sock[1];
	state.sock1.fde = tevent_add_fd(state.ev, state.ev,
					state.sock1.fd,
					TEVENT_FD_READ | TEVENT_FD_WRITE,
					test_event_fd2_sock_handler,
					&state.sock1);

	tevent_fd_set_auto_close(state.sock0.fde);
	tevent_fd_set_auto_close(state.sock1.fde);

	write(state.sock0.fd, &c, 1);
	state.sock0.num_written++;
	write(state.sock1.fd, &c, 1);
	state.sock1.num_written++;

	while (!state.finished) {
		errno = 0;
		if (tevent_loop_once(state.ev) == -1) {
			talloc_free(state.ev);
			torture_fail(tctx, talloc_asprintf(tctx,
				     "Failed event loop %s\n",
				     strerror(errno)));
		}
	}

	talloc_free(state.ev);

	torture_assert(tctx, state.error == NULL, talloc_asprintf(tctx,
		       "%s", state.error));

	return true;
}

#ifdef HAVE_PTHREAD

static pthread_mutex_t threaded_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool do_shutdown = false;

static void test_event_threaded_lock(void)
{
	int ret;
	ret = pthread_mutex_lock(&threaded_mutex);
	assert(ret == 0);
}

static void test_event_threaded_unlock(void)
{
	int ret;
	ret = pthread_mutex_unlock(&threaded_mutex);
	assert(ret == 0);
}

static void test_event_threaded_trace(enum tevent_trace_point point,
				      void *private_data)
{
	switch (point) {
	case TEVENT_TRACE_BEFORE_WAIT:
		test_event_threaded_unlock();
		break;
	case TEVENT_TRACE_AFTER_WAIT:
		test_event_threaded_lock();
		break;
	case TEVENT_TRACE_BEFORE_LOOP_ONCE:
	case TEVENT_TRACE_AFTER_LOOP_ONCE:
		break;
	}
}

static void test_event_threaded_timer(struct tevent_context *ev,
				      struct tevent_timer *te,
				      struct timeval current_time,
				      void *private_data)
{
	return;
}

static void *test_event_poll_thread(void *private_data)
{
	struct tevent_context *ev = (struct tevent_context *)private_data;

	test_event_threaded_lock();

	while (true) {
		int ret;
		ret = tevent_loop_once(ev);
		assert(ret == 0);
		if (do_shutdown) {
			test_event_threaded_unlock();
			return NULL;
		}
	}

}

static void test_event_threaded_read_handler(struct tevent_context *ev,
					     struct tevent_fd *fde,
					     uint16_t flags,
					     void *private_data)
{
	int *pfd = (int *)private_data;
	char c;
	ssize_t nread;

	if ((flags & TEVENT_FD_READ) == 0) {
		return;
	}

	do {
		nread = read(*pfd, &c, 1);
	} while ((nread == -1) && (errno == EINTR));

	assert(nread == 1);
}

static bool test_event_context_threaded(struct torture_context *test,
					const void *test_data)
{
	struct tevent_context *ev;
	struct tevent_timer *te;
	struct tevent_fd *fde;
	pthread_t poll_thread;
	int fds[2];
	int ret;
	char c = 0;

	ev = tevent_context_init_byname(test, "poll_mt");
	torture_assert(test, ev != NULL, "poll_mt not supported");

	tevent_set_trace_callback(ev, test_event_threaded_trace, NULL);

	te = tevent_add_timer(ev, ev, timeval_current_ofs(5, 0),
			      test_event_threaded_timer, NULL);
	torture_assert(test, te != NULL, "Could not add timer");

	ret = pthread_create(&poll_thread, NULL, test_event_poll_thread, ev);
	torture_assert(test, ret == 0, "Could not create poll thread");

	ret = pipe(fds);
	torture_assert(test, ret == 0, "Could not create pipe");

	poll(NULL, 0, 100);

	test_event_threaded_lock();

	fde = tevent_add_fd(ev, ev, fds[0], TEVENT_FD_READ,
			    test_event_threaded_read_handler, &fds[0]);
	torture_assert(test, fde != NULL, "Could not add fd event");

	test_event_threaded_unlock();

	poll(NULL, 0, 100);

	write(fds[1], &c, 1);

	poll(NULL, 0, 100);

	test_event_threaded_lock();
	do_shutdown = true;
	test_event_threaded_unlock();

	write(fds[1], &c, 1);

	ret = pthread_join(poll_thread, NULL);
	torture_assert(test, ret == 0, "pthread_join failed");

	return true;
}

#endif

struct torture_suite *torture_local_event(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "event");
	const char **list = tevent_backend_list(suite);
	int i;

	for (i=0;list && list[i];i++) {
		struct torture_suite *backend_suite;

		backend_suite = torture_suite_create(mem_ctx, list[i]);

		torture_suite_add_simple_tcase_const(backend_suite,
					       "context",
					       test_event_context,
					       (const void *)list[i]);
		torture_suite_add_simple_tcase_const(backend_suite,
					       "fd1",
					       test_event_fd1,
					       (const void *)list[i]);
		torture_suite_add_simple_tcase_const(backend_suite,
					       "fd2",
					       test_event_fd2,
					       (const void *)list[i]);

		torture_suite_add_suite(suite, backend_suite);
	}

#ifdef HAVE_PTHREAD
	torture_suite_add_simple_tcase_const(suite, "threaded_poll_mt",
					     test_event_context_threaded,
					     NULL);
#endif

	return suite;
}
