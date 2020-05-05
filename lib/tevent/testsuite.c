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
#define TEVENT_DEPRECATED 1
#include "tevent.h"
#include "system/filesys.h"
#include "system/select.h"
#include "system/network.h"
#include "torture/torture.h"
#include "torture/local/proto.h"
#ifdef HAVE_PTHREAD
#include "system/threads.h"
#include <assert.h>
#endif

static int fde_count;

static void do_read(int fd, void *buf, size_t count)
{
	ssize_t ret;

	do {
		ret = read(fd, buf, count);
	} while (ret == -1 && errno == EINTR);
}

static void fde_handler_read(struct tevent_context *ev_ctx, struct tevent_fd *f,
			uint16_t flags, void *private_data)
{
	int *fd = (int *)private_data;
	char c;
#ifdef SA_SIGINFO
	kill(getpid(), SIGUSR1);
#endif
	kill(getpid(), SIGALRM);

	do_read(fd[0], &c, 1);
	fde_count++;
}

static void do_write(int fd, void *buf, size_t count)
{
	ssize_t ret;

	do {
		ret = write(fd, buf, count);
	} while (ret == -1 && errno == EINTR);
}

static void fde_handler_write(struct tevent_context *ev_ctx, struct tevent_fd *f,
			uint16_t flags, void *private_data)
{
	int *fd = (int *)private_data;
	char c = 0;

	do_write(fd[1], &c, 1);
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

	do_read(fd[1], &c, 1);
	fde_count++;
}

/* This will only fire if the fd's returned from pipe() are bi-directional. */
static void fde_handler_write_1(struct tevent_context *ev_ctx, struct tevent_fd *f,
			uint16_t flags, void *private_data)
{
	int *fd = (int *)private_data;
	char c = 0;
	do_write(fd[0], &c, 1);
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
	int ret;

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
	ret = pipe(fd);
	torture_assert_int_equal(test, ret, 0, "pipe failed");

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
			TALLOC_FREE(ev_ctx);
			torture_fail(test, talloc_asprintf(test, "Failed event loop %s\n", strerror(errno)));
			return false;
		}
	}

	talloc_free(fde_read_1);
	talloc_free(fde_write_1);
	talloc_free(fde_read);
	talloc_free(fde_write);

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
		do_write(state->sock[1], &c, 1);
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
	int ret;

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

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, state.sock);
	torture_assert(tctx, ret == 0, "socketpair() failed");

	state.te = tevent_add_timer(state.ev, state.ev,
				    timeval_current_ofs(0,10000),
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

	do_write(state.sock0.fd, &c, 1);
	state.sock0.num_written++;
	do_write(state.sock1.fd, &c, 1);
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

struct test_wrapper_state {
	struct torture_context *tctx;
	int num_events;
	int num_wrap_handlers;
};

static bool test_wrapper_before_use(struct tevent_context *wrap_ev,
				    void *private_data,
				    struct tevent_context *main_ev,
				    const char *location)
{
	struct test_wrapper_state *state =
		talloc_get_type_abort(private_data,
		struct test_wrapper_state);

	torture_comment(state->tctx, "%s\n", __func__);
	state->num_wrap_handlers++;
	return true;
}

static void test_wrapper_after_use(struct tevent_context *wrap_ev,
				   void *private_data,
				   struct tevent_context *main_ev,
				   const char *location)
{
	struct test_wrapper_state *state =
		talloc_get_type_abort(private_data,
		struct test_wrapper_state);

	torture_comment(state->tctx, "%s\n", __func__);
	state->num_wrap_handlers++;
}

static void test_wrapper_before_fd_handler(struct tevent_context *wrap_ev,
					   void *private_data,
					   struct tevent_context *main_ev,
					   struct tevent_fd *fde,
					   uint16_t flags,
					   const char *handler_name,
					   const char *location)
{
	struct test_wrapper_state *state =
		talloc_get_type_abort(private_data,
		struct test_wrapper_state);

	torture_comment(state->tctx, "%s\n", __func__);
	state->num_wrap_handlers++;
}

static void test_wrapper_after_fd_handler(struct tevent_context *wrap_ev,
					  void *private_data,
					  struct tevent_context *main_ev,
					  struct tevent_fd *fde,
					  uint16_t flags,
					  const char *handler_name,
					  const char *location)
{
	struct test_wrapper_state *state =
		talloc_get_type_abort(private_data,
		struct test_wrapper_state);

	torture_comment(state->tctx, "%s\n", __func__);
	state->num_wrap_handlers++;
}

static void test_wrapper_before_timer_handler(struct tevent_context *wrap_ev,
					      void *private_data,
					      struct tevent_context *main_ev,
					      struct tevent_timer *te,
					      struct timeval requested_time,
					      struct timeval trigger_time,
					      const char *handler_name,
					      const char *location)
{
	struct test_wrapper_state *state =
		talloc_get_type_abort(private_data,
		struct test_wrapper_state);

	torture_comment(state->tctx, "%s\n", __func__);
	state->num_wrap_handlers++;
}

static void test_wrapper_after_timer_handler(struct tevent_context *wrap_ev,
					     void *private_data,
					     struct tevent_context *main_ev,
					     struct tevent_timer *te,
					     struct timeval requested_time,
					     struct timeval trigger_time,
					     const char *handler_name,
					     const char *location)
{
	struct test_wrapper_state *state =
		talloc_get_type_abort(private_data,
		struct test_wrapper_state);

	torture_comment(state->tctx, "%s\n", __func__);
	state->num_wrap_handlers++;
}

static void test_wrapper_before_immediate_handler(struct tevent_context *wrap_ev,
						  void *private_data,
						  struct tevent_context *main_ev,
						  struct tevent_immediate *im,
						  const char *handler_name,
						  const char *location)
{
	struct test_wrapper_state *state =
		talloc_get_type_abort(private_data,
		struct test_wrapper_state);

	torture_comment(state->tctx, "%s\n", __func__);
	state->num_wrap_handlers++;
}

static void test_wrapper_after_immediate_handler(struct tevent_context *wrap_ev,
						 void *private_data,
						 struct tevent_context *main_ev,
						 struct tevent_immediate *im,
						 const char *handler_name,
						 const char *location)
{
	struct test_wrapper_state *state =
		talloc_get_type_abort(private_data,
		struct test_wrapper_state);

	torture_comment(state->tctx, "%s\n", __func__);
	state->num_wrap_handlers++;
}

static void test_wrapper_before_signal_handler(struct tevent_context *wrap_ev,
					       void *private_data,
					       struct tevent_context *main_ev,
					       struct tevent_signal *se,
					       int signum,
					       int count,
					       void *siginfo,
					       const char *handler_name,
					       const char *location)
{
	struct test_wrapper_state *state =
		talloc_get_type_abort(private_data,
		struct test_wrapper_state);

	torture_comment(state->tctx, "%s\n", __func__);
	state->num_wrap_handlers++;
}

static void test_wrapper_after_signal_handler(struct tevent_context *wrap_ev,
					      void *private_data,
					      struct tevent_context *main_ev,
					      struct tevent_signal *se,
					      int signum,
					      int count,
					      void *siginfo,
					      const char *handler_name,
					      const char *location)
{
	struct test_wrapper_state *state =
		talloc_get_type_abort(private_data,
		struct test_wrapper_state);

	torture_comment(state->tctx, "%s\n", __func__);
	state->num_wrap_handlers++;
}

static const struct tevent_wrapper_ops test_wrapper_ops = {
	.name				= "test_wrapper",
	.before_use			= test_wrapper_before_use,
	.after_use			= test_wrapper_after_use,
	.before_fd_handler		= test_wrapper_before_fd_handler,
	.after_fd_handler		= test_wrapper_after_fd_handler,
	.before_timer_handler		= test_wrapper_before_timer_handler,
	.after_timer_handler		= test_wrapper_after_timer_handler,
	.before_immediate_handler	= test_wrapper_before_immediate_handler,
	.after_immediate_handler	= test_wrapper_after_immediate_handler,
	.before_signal_handler		= test_wrapper_before_signal_handler,
	.after_signal_handler		= test_wrapper_after_signal_handler,
};

static void test_wrapper_timer_handler(struct tevent_context *ev,
				       struct tevent_timer *te,
				       struct timeval tv,
				       void *private_data)
{
	struct test_wrapper_state *state =
		(struct test_wrapper_state *)private_data;


	torture_comment(state->tctx, "timer handler\n");

	state->num_events++;
	talloc_free(te);
	return;
}

static void test_wrapper_fd_handler(struct tevent_context *ev,
				    struct tevent_fd *fde,
				    unsigned short fd_flags,
				    void *private_data)
{
	struct test_wrapper_state *state =
		(struct test_wrapper_state *)private_data;

	torture_comment(state->tctx, "fd handler\n");

	state->num_events++;
	talloc_free(fde);
	return;
}

static void test_wrapper_immediate_handler(struct tevent_context *ev,
					   struct tevent_immediate *im,
					   void *private_data)
{
	struct test_wrapper_state *state =
		(struct test_wrapper_state *)private_data;

	state->num_events++;
	talloc_free(im);

	torture_comment(state->tctx, "immediate handler\n");
	return;
}

static void test_wrapper_signal_handler(struct tevent_context *ev,
					struct tevent_signal *se,
					int signum,
					int count,
					void *siginfo,
					void *private_data)
{
	struct test_wrapper_state *state =
		(struct test_wrapper_state *)private_data;

	torture_comment(state->tctx, "signal handler\n");

	state->num_events++;
	talloc_free(se);
	return;
}

static bool test_wrapper(struct torture_context *tctx,
			 const void *test_data)
{
	struct test_wrapper_state *state = NULL;
	int sock[2] = { -1, -1};
	uint8_t c = 0;
	const int num_events = 4;
	const char *backend = (const char *)test_data;
	struct tevent_context *ev = NULL;
	struct tevent_context *wrap_ev = NULL;
	struct tevent_fd *fde = NULL;
	struct tevent_timer *te = NULL;
	struct tevent_signal *se = NULL;
	struct tevent_immediate *im = NULL;
	int ret;
	bool ok = false;
	bool ret2;

	ev = tevent_context_init_byname(tctx, backend);
	if (ev == NULL) {
		torture_skip(tctx, talloc_asprintf(tctx,
			     "event backend '%s' not supported\n",
			     backend));
		return true;
	}

	tevent_set_debug_stderr(ev);
	torture_comment(tctx, "tevent backend '%s'\n", backend);

	wrap_ev = tevent_context_wrapper_create(
		ev, ev,	&test_wrapper_ops, &state, struct test_wrapper_state);
	torture_assert_not_null_goto(tctx, wrap_ev, ok, done,
				     "tevent_context_wrapper_create failed\n");
	*state = (struct test_wrapper_state) {
		.tctx = tctx,
	};

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sock);
	torture_assert_goto(tctx, ret == 0, ok, done, "socketpair failed\n");

	te = tevent_add_timer(wrap_ev, wrap_ev,
			      timeval_current_ofs(0, 0),
			      test_wrapper_timer_handler, state);
	torture_assert_not_null_goto(tctx, te, ok, done,
				     "tevent_add_timer failed\n");

	fde = tevent_add_fd(wrap_ev, wrap_ev,
			    sock[1],
			    TEVENT_FD_READ,
			    test_wrapper_fd_handler,
			    state);
	torture_assert_not_null_goto(tctx, fde, ok, done,
				     "tevent_add_fd failed\n");

	im = tevent_create_immediate(wrap_ev);
	torture_assert_not_null_goto(tctx, im, ok, done,
				     "tevent_create_immediate failed\n");

	se = tevent_add_signal(wrap_ev, wrap_ev,
			       SIGUSR1,
			       0,
			       test_wrapper_signal_handler,
			       state);
	torture_assert_not_null_goto(tctx, se, ok, done,
				     "tevent_add_signal failed\n");

	do_write(sock[0], &c, 1);
	kill(getpid(), SIGUSR1);
	tevent_schedule_immediate(im,
				  wrap_ev,
				  test_wrapper_immediate_handler,
				  state);

	ret2 = tevent_context_push_use(wrap_ev);
	torture_assert_goto(tctx, ret2, ok, done, "tevent_context_push_use(wrap_ev) failed\n");
	ret2 = tevent_context_push_use(ev);
	torture_assert_goto(tctx, ret2, ok, pop_use, "tevent_context_push_use(ev) failed\n");
	tevent_context_pop_use(ev);
	tevent_context_pop_use(wrap_ev);

	ret = tevent_loop_wait(ev);
	torture_assert_int_equal_goto(tctx, ret, 0, ok, done, "tevent_loop_wait failed\n");

	torture_comment(tctx, "Num events: %d\n", state->num_events);
	torture_comment(tctx, "Num wrap handlers: %d\n",
			state->num_wrap_handlers);

	torture_assert_int_equal_goto(tctx, state->num_events, num_events, ok, done,
				      "Wrong event count\n");
	torture_assert_int_equal_goto(tctx, state->num_wrap_handlers,
				      num_events*2+2,
				      ok, done, "Wrong wrapper count\n");

	ok = true;

done:
	TALLOC_FREE(wrap_ev);
	TALLOC_FREE(ev);

	if (sock[0] != -1) {
		close(sock[0]);
	}
	if (sock[1] != -1) {
		close(sock[1]);
	}
	return ok;
pop_use:
	tevent_context_pop_use(wrap_ev);
	goto done;
}

static void test_free_wrapper_signal_handler(struct tevent_context *ev,
					struct tevent_signal *se,
					int signum,
					int count,
					void *siginfo,
					void *private_data)
{
	struct torture_context *tctx =
		talloc_get_type_abort(private_data,
		struct torture_context);

	torture_comment(tctx, "signal handler\n");

	talloc_free(se);

	/*
	 * signal handlers have highest priority in tevent, so this signal
	 * handler will always be started before the other handlers
	 * below. Freeing the (wrapper) event context here tests that the
	 * wrapper implementation correclty handles the wrapper ev going away
	 * with pending events.
	 */
	talloc_free(ev);
	return;
}

static void test_free_wrapper_fd_handler(struct tevent_context *ev,
					 struct tevent_fd *fde,
					 unsigned short fd_flags,
					 void *private_data)
{
	/*
	 * This should never be called as
	 * test_free_wrapper_signal_handler()
	 * already destroyed the wrapper tevent_context.
	 */
	abort();
}

static void test_free_wrapper_immediate_handler(struct tevent_context *ev,
					   struct tevent_immediate *im,
					   void *private_data)
{
	/*
	 * This should never be called as
	 * test_free_wrapper_signal_handler()
	 * already destroyed the wrapper tevent_context.
	 */
	abort();
}

static void test_free_wrapper_timer_handler(struct tevent_context *ev,
				       struct tevent_timer *te,
				       struct timeval tv,
				       void *private_data)
{
	/*
	 * This should never be called as
	 * test_free_wrapper_signal_handler()
	 * already destroyed the wrapper tevent_context.
	 */
	abort();
}

static bool test_free_wrapper(struct torture_context *tctx,
			      const void *test_data)
{
	struct test_wrapper_state *state = NULL;
	int sock[2] = { -1, -1};
	uint8_t c = 0;
	const char *backend = (const char *)test_data;
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev = NULL;
	struct tevent_context *wrap_ev = NULL;
	struct tevent_fd *fde = NULL;
	struct tevent_timer *te = NULL;
	struct tevent_signal *se = NULL;
	struct tevent_immediate *im = NULL;
	int ret;
	bool ok = false;

	ev = tevent_context_init_byname(frame, backend);
	if (ev == NULL) {
		torture_skip(tctx, talloc_asprintf(tctx,
			     "event backend '%s' not supported\n",
			     backend));
		return true;
	}

	tevent_set_debug_stderr(ev);
	torture_comment(tctx, "tevent backend '%s'\n", backend);

	wrap_ev = tevent_context_wrapper_create(
		ev, ev,	&test_wrapper_ops, &state, struct test_wrapper_state);
	torture_assert_not_null_goto(tctx, wrap_ev, ok, done,
				     "tevent_context_wrapper_create failed\n");
	*state = (struct test_wrapper_state) {
		.tctx = tctx,
	};

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sock);
	torture_assert_goto(tctx, ret == 0, ok, done, "socketpair failed\n");

	fde = tevent_add_fd(wrap_ev, frame,
			    sock[1],
			    TEVENT_FD_READ,
			    test_free_wrapper_fd_handler,
			    NULL);
	torture_assert_not_null_goto(tctx, fde, ok, done,
				     "tevent_add_fd failed\n");

	te = tevent_add_timer(wrap_ev, frame,
			      timeval_current_ofs(0, 0),
			      test_free_wrapper_timer_handler, NULL);
	torture_assert_not_null_goto(tctx, te, ok, done,
				     "tevent_add_timer failed\n");

	im = tevent_create_immediate(frame);
	torture_assert_not_null_goto(tctx, im, ok, done,
				     "tevent_create_immediate failed\n");

	se = tevent_add_signal(wrap_ev, frame,
			       SIGUSR1,
			       0,
			       test_free_wrapper_signal_handler,
			       tctx);
	torture_assert_not_null_goto(tctx, se, ok, done,
				     "tevent_add_signal failed\n");

	do_write(sock[0], &c, 1);
	kill(getpid(), SIGUSR1);
	tevent_schedule_immediate(im,
				  wrap_ev,
				  test_free_wrapper_immediate_handler,
				  NULL);

	ret = tevent_loop_wait(ev);
	torture_assert_goto(tctx, ret == 0, ok, done, "tevent_loop_wait failed\n");

	ok = true;

done:
	TALLOC_FREE(frame);

	if (sock[0] != -1) {
		close(sock[0]);
	}
	if (sock[1] != -1) {
		close(sock[1]);
	}
	return ok;
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

	do_write(fds[1], &c, 1);

	poll(NULL, 0, 100);

	test_event_threaded_lock();
	do_shutdown = true;
	test_event_threaded_unlock();

	do_write(fds[1], &c, 1);

	ret = pthread_join(poll_thread, NULL);
	torture_assert(test, ret == 0, "pthread_join failed");

	return true;
}

#define NUM_TEVENT_THREADS 100

/* Ugly, but needed for torture_comment... */
static struct torture_context *thread_test_ctx;
static pthread_t thread_map[NUM_TEVENT_THREADS];
static unsigned thread_counter;

/* Called in master thread context */
static void callback_nowait(struct tevent_context *ev,
				struct tevent_immediate *im,
				void *private_ptr)
{
	pthread_t *thread_id_ptr =
		talloc_get_type_abort(private_ptr, pthread_t);
	unsigned i;

	for (i = 0; i < NUM_TEVENT_THREADS; i++) {
		if (pthread_equal(*thread_id_ptr,
				thread_map[i])) {
			break;
		}
	}
	torture_comment(thread_test_ctx,
			"Callback %u from thread %u\n",
			thread_counter,
			i);
	thread_counter++;
}

/* Blast the master tevent_context with a callback, no waiting. */
static void *thread_fn_nowait(void *private_ptr)
{
	struct tevent_thread_proxy *master_tp =
		talloc_get_type_abort(private_ptr, struct tevent_thread_proxy);
	struct tevent_immediate *im;
	pthread_t *thread_id_ptr;

	im = tevent_create_immediate(NULL);
	if (im == NULL) {
		return NULL;
	}
	thread_id_ptr = talloc(NULL, pthread_t);
	if (thread_id_ptr == NULL) {
		return NULL;
	}
	*thread_id_ptr = pthread_self();

	tevent_thread_proxy_schedule(master_tp,
				&im,
				callback_nowait,
				&thread_id_ptr);
	return NULL;
}

static void timeout_fn(struct tevent_context *ev,
			struct tevent_timer *te,
			struct timeval tv, void *p)
{
	thread_counter = NUM_TEVENT_THREADS * 10;
}

static bool test_multi_tevent_threaded(struct torture_context *test,
					const void *test_data)
{
	unsigned i;
	struct tevent_context *master_ev;
	struct tevent_thread_proxy *tp;

	talloc_disable_null_tracking();

	/* Ugly global stuff. */
	thread_test_ctx = test;
	thread_counter = 0;

	master_ev = tevent_context_init(NULL);
	if (master_ev == NULL) {
		return false;
	}
	tevent_set_debug_stderr(master_ev);

	tp = tevent_thread_proxy_create(master_ev);
	if (tp == NULL) {
		torture_fail(test,
			talloc_asprintf(test,
				"tevent_thread_proxy_create failed\n"));
		talloc_free(master_ev);
		return false;
	}

	for (i = 0; i < NUM_TEVENT_THREADS; i++) {
		int ret = pthread_create(&thread_map[i],
				NULL,
				thread_fn_nowait,
				tp);
		if (ret != 0) {
			torture_fail(test,
				talloc_asprintf(test,
					"Failed to create thread %i, %d\n",
					i, ret));
			return false;
		}
	}

	/* Ensure we don't wait more than 10 seconds. */
	tevent_add_timer(master_ev,
			master_ev,
			timeval_current_ofs(10,0),
			timeout_fn,
			NULL);

	while (thread_counter < NUM_TEVENT_THREADS) {
		int ret = tevent_loop_once(master_ev);
		torture_assert(test, ret == 0, "tevent_loop_once failed");
	}

	torture_assert(test, thread_counter == NUM_TEVENT_THREADS,
		"thread_counter fail\n");

	talloc_free(master_ev);
	return true;
}

struct reply_state {
	struct tevent_thread_proxy *reply_tp;
	pthread_t thread_id;
	int *p_finished;
};

static void thread_timeout_fn(struct tevent_context *ev,
			struct tevent_timer *te,
			struct timeval tv, void *p)
{
	int *p_finished = (int *)p;

	*p_finished = 2;
}

/* Called in child-thread context */
static void thread_callback(struct tevent_context *ev,
				struct tevent_immediate *im,
				void *private_ptr)
{
	struct reply_state *rsp =
		talloc_get_type_abort(private_ptr, struct reply_state);

	talloc_steal(ev, rsp);
	*rsp->p_finished = 1;
}

/* Called in master thread context */
static void master_callback(struct tevent_context *ev,
				struct tevent_immediate *im,
				void *private_ptr)
{
	struct reply_state *rsp =
		talloc_get_type_abort(private_ptr, struct reply_state);
	unsigned i;

	talloc_steal(ev, rsp);

	for (i = 0; i < NUM_TEVENT_THREADS; i++) {
		if (pthread_equal(rsp->thread_id,
				thread_map[i])) {
			break;
		}
	}
	torture_comment(thread_test_ctx,
			"Callback %u from thread %u\n",
			thread_counter,
			i);
	/* Now reply to the thread ! */
	tevent_thread_proxy_schedule(rsp->reply_tp,
				&im,
				thread_callback,
				&rsp);

	thread_counter++;
}

static void *thread_fn_1(void *private_ptr)
{
	struct tevent_thread_proxy *master_tp =
		talloc_get_type_abort(private_ptr, struct tevent_thread_proxy);
	struct tevent_thread_proxy *tp;
	struct tevent_immediate *im;
	struct tevent_context *ev;
	struct reply_state *rsp;
	int finished = 0;
	int ret;

	ev = tevent_context_init(NULL);
	if (ev == NULL) {
		return NULL;
	}

	tp = tevent_thread_proxy_create(ev);
	if (tp == NULL) {
		talloc_free(ev);
		return NULL;
	}

	im = tevent_create_immediate(ev);
	if (im == NULL) {
		talloc_free(ev);
		return NULL;
	}

	rsp = talloc(ev, struct reply_state);
	if (rsp == NULL) {
		talloc_free(ev);
		return NULL;
	}

	rsp->thread_id = pthread_self();
	rsp->reply_tp = tp;
	rsp->p_finished = &finished;

	/* Introduce a little randomness into the mix.. */
	usleep(random() % 7000);

	tevent_thread_proxy_schedule(master_tp,
				&im,
				master_callback,
				&rsp);

	/* Ensure we don't wait more than 10 seconds. */
	tevent_add_timer(ev,
			ev,
			timeval_current_ofs(10,0),
			thread_timeout_fn,
			&finished);

	while (finished == 0) {
		ret = tevent_loop_once(ev);
		assert(ret == 0);
	}

	if (finished > 1) {
		/* Timeout ! */
		abort();
	}

	/*
	 * NB. We should talloc_free(ev) here, but if we do
	 * we currently get hit by helgrind Fix #323432
	 * "When calling pthread_cond_destroy or pthread_mutex_destroy
	 * with initializers as argument Helgrind (incorrectly) reports errors."
	 *
	 * http://valgrind.10908.n7.nabble.com/Helgrind-3-9-0-false-positive-
	 * with-pthread-mutex-destroy-td47757.html
	 *
	 * Helgrind doesn't understand that the request/reply
	 * messages provide synchronization between the lock/unlock
	 * in tevent_thread_proxy_schedule(), and the pthread_destroy()
	 * when the struct tevent_thread_proxy object is talloc_free'd.
	 *
	 * As a work-around for now return ev for the parent thread to free.
	 */
	return ev;
}

static bool test_multi_tevent_threaded_1(struct torture_context *test,
					const void *test_data)
{
	unsigned i;
	struct tevent_context *master_ev;
	struct tevent_thread_proxy *master_tp;
	int ret;

	talloc_disable_null_tracking();

	/* Ugly global stuff. */
	thread_test_ctx = test;
	thread_counter = 0;

	master_ev = tevent_context_init(NULL);
	if (master_ev == NULL) {
		return false;
	}
	tevent_set_debug_stderr(master_ev);

	master_tp = tevent_thread_proxy_create(master_ev);
	if (master_tp == NULL) {
		torture_fail(test,
			talloc_asprintf(test,
				"tevent_thread_proxy_create failed\n"));
		talloc_free(master_ev);
		return false;
	}

	for (i = 0; i < NUM_TEVENT_THREADS; i++) {
		ret = pthread_create(&thread_map[i],
				NULL,
				thread_fn_1,
				master_tp);
		if (ret != 0) {
			torture_fail(test,
				talloc_asprintf(test,
					"Failed to create thread %i, %d\n",
					i, ret));
				return false;
		}
	}

	while (thread_counter < NUM_TEVENT_THREADS) {
		ret = tevent_loop_once(master_ev);
		torture_assert(test, ret == 0, "tevent_loop_once failed");
	}

	/* Wait for all the threads to finish - join 'em. */
	for (i = 0; i < NUM_TEVENT_THREADS; i++) {
		void *retval;
		ret = pthread_join(thread_map[i], &retval);
		torture_assert(test, ret == 0, "pthread_join failed");
		/* Free the child thread event context. */
		talloc_free(retval);
	}

	talloc_free(master_ev);
	return true;
}

struct threaded_test_2 {
	struct tevent_threaded_context *tctx;
	struct tevent_immediate *im;
	pthread_t thread_id;
};

static void master_callback_2(struct tevent_context *ev,
			      struct tevent_immediate *im,
			      void *private_data);

static void *thread_fn_2(void *private_data)
{
	struct threaded_test_2 *state = private_data;

	state->thread_id = pthread_self();

	usleep(random() % 7000);

	tevent_threaded_schedule_immediate(
		state->tctx, state->im, master_callback_2, state);

	return NULL;
}

static void master_callback_2(struct tevent_context *ev,
			      struct tevent_immediate *im,
			      void *private_data)
{
	struct threaded_test_2 *state = private_data;
	int i;

	for (i = 0; i < NUM_TEVENT_THREADS; i++) {
		if (pthread_equal(state->thread_id, thread_map[i])) {
			break;
		}
	}
	torture_comment(thread_test_ctx,
			"Callback_2 %u from thread %u\n",
			thread_counter,
			i);
	thread_counter++;
}

static bool test_multi_tevent_threaded_2(struct torture_context *test,
					 const void *test_data)
{
	unsigned i;

	struct tevent_context *ev;
	struct tevent_threaded_context *tctx;
	int ret;

	thread_test_ctx = test;
	thread_counter = 0;

	ev = tevent_context_init(test);
	torture_assert(test, ev != NULL, "tevent_context_init failed");

	/*
	 * tevent_re_initialise used to have a bug where it did not
	 * re-initialise the thread support after taking it
	 * down. Exercise that code path.
	 */
	ret = tevent_re_initialise(ev);
	torture_assert(test, ret == 0, "tevent_re_initialise failed");

	tctx = tevent_threaded_context_create(ev, ev);
	torture_assert(test, tctx != NULL,
		       "tevent_threaded_context_create failed");

	for (i=0; i<NUM_TEVENT_THREADS; i++) {
		struct threaded_test_2 *state;

		state = talloc(ev, struct threaded_test_2);
		torture_assert(test, state != NULL, "talloc failed");

		state->tctx = tctx;
		state->im = tevent_create_immediate(state);
		torture_assert(test, state->im != NULL,
			       "tevent_create_immediate failed");

		ret = pthread_create(&thread_map[i], NULL, thread_fn_2, state);
		torture_assert(test, ret == 0, "pthread_create failed");
	}

	while (thread_counter < NUM_TEVENT_THREADS) {
		ret = tevent_loop_once(ev);
		torture_assert(test, ret == 0, "tevent_loop_once failed");
	}

	/* Wait for all the threads to finish - join 'em. */
	for (i = 0; i < NUM_TEVENT_THREADS; i++) {
		void *retval;
		ret = pthread_join(thread_map[i], &retval);
		torture_assert(test, ret == 0, "pthread_join failed");
		/* Free the child thread event context. */
	}

	talloc_free(tctx);
	talloc_free(ev);
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
		torture_suite_add_simple_tcase_const(backend_suite,
					       "wrapper",
					       test_wrapper,
					       (const void *)list[i]);
		torture_suite_add_simple_tcase_const(backend_suite,
					       "free_wrapper",
					       test_free_wrapper,
					       (const void *)list[i]);

		torture_suite_add_suite(suite, backend_suite);
	}

#ifdef HAVE_PTHREAD
	torture_suite_add_simple_tcase_const(suite, "threaded_poll_mt",
					     test_event_context_threaded,
					     NULL);

	torture_suite_add_simple_tcase_const(suite, "multi_tevent_threaded",
					     test_multi_tevent_threaded,
					     NULL);

	torture_suite_add_simple_tcase_const(suite, "multi_tevent_threaded_1",
					     test_multi_tevent_threaded_1,
					     NULL);

	torture_suite_add_simple_tcase_const(suite, "multi_tevent_threaded_2",
					     test_multi_tevent_threaded_2,
					     NULL);

#endif

	return suite;
}
