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
#include "torture/torture.h"
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


/* These should never fire... */
static void fde_handler_read_1(struct tevent_context *ev_ctx, struct tevent_fd *f,
			uint16_t flags, void *private_data)
{
	struct torture_context *test = (struct torture_context *)private_data;
	torture_comment(test, "fde_handler_read_1 should never fire !\n");
	abort();
}

/* These should never fire... */
static void fde_handler_write_1(struct tevent_context *ev_ctx, struct tevent_fd *f,
			uint16_t flags, void *private_data)
{
	struct torture_context *test = (struct torture_context *)private_data;
	torture_comment(test, "fde_handler_write_1 should never fire !\n");
	abort();
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
			    fde_handler_write_1, test);

	fde_write = tevent_add_fd(ev_ctx, ev_ctx, fd[1], TEVENT_FD_WRITE,
			    fde_handler_write, fd);
	fde_read_1 = tevent_add_fd(ev_ctx, ev_ctx, fd[1], TEVENT_FD_READ,
			    fde_handler_read_1, test);

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
		torture_suite_add_simple_tcase_const(suite, list[i],
					       test_event_context,
					       (const void *)list[i]);
	}

#ifdef HAVE_PTHREAD
	torture_suite_add_simple_tcase_const(suite, "poll_mt_threaded",
					     test_event_context_threaded,
					     NULL);
#endif

	return suite;
}
