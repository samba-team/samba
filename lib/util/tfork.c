/*
   fork on steroids to avoid SIGCHLD and waitpid

   Copyright (C) Stefan Metzmacher 2010
   Copyright (C) Ralph Boehme 2017

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/wait.h"
#include "system/filesys.h"
#include "system/network.h"
#include "lib/util/samba_util.h"
#include "lib/util/sys_rw.h"
#include "lib/util/tfork.h"
#include "lib/util/debug.h"
#include "lib/util/util_process.h"

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>

/*
 * This is how the process hierarchy looks like:
 *
 *   +----------+
 *   |  caller  |
 *   +----------+
 *         |
 *       fork
 *         |
 *         v
 *   +----------+
 *   |  waiter  |
 *   +----------+
 *         |
 *       fork
 *         |
 *         v
 *   +----------+
 *   |  worker  |
 *   +----------+
 */

#ifdef HAVE_VALGRIND_HELGRIND_H
#include <valgrind/helgrind.h>
#endif
#ifndef ANNOTATE_BENIGN_RACE_SIZED
#define ANNOTATE_BENIGN_RACE_SIZED(obj, size, description)
#endif

#define TFORK_ANNOTATE_BENIGN_RACE(obj)					\
	ANNOTATE_BENIGN_RACE_SIZED(					\
		(obj), sizeof(*(obj)),					\
		"no race, serialized by tfork_[un]install_sigchld_handler");

/*
 * The resulting (private) state per tfork_create() call, returned as a opaque
 * handle to the caller.
 */
struct tfork {
	/*
	 * This is returned to the caller with tfork_event_fd()
	 */
	int event_fd;

	/*
	 * This is used in the caller by tfork_status() to read the worker exit
	 * status and to tell the waiter to exit by closing the fd.
	 */
	int status_fd;

	pid_t waiter_pid;
	pid_t worker_pid;
};

/*
 * Internal per-thread state maintained while inside tfork.
 */
struct tfork_state {
	pid_t waiter_pid;
	int waiter_errno;

	pid_t worker_pid;
};

/*
 * A global state that synchronizes access to handling SIGCHLD and waiting for
 * childs.
 */
struct tfork_signal_state {
	bool available;

#ifdef HAVE_PTHREAD
	pthread_cond_t cond;
	pthread_mutex_t mutex;
#endif

	/*
	 * pid of the waiter child. This points at waiter_pid in either struct
	 * tfork or struct tfork_state, depending on who called
	 * tfork_install_sigchld_handler().
	 *
	 * When tfork_install_sigchld_handler() is called the waiter_pid is
	 * still -1 and only set later after fork(), that's why this is must be
	 * a pointer. The signal handler checks this.
	 */
	pid_t *pid;

	struct sigaction oldact;
	sigset_t oldset;
};

static struct tfork_signal_state signal_state;

#ifdef HAVE_PTHREAD
static pthread_once_t tfork_global_is_initialized = PTHREAD_ONCE_INIT;
static pthread_key_t tfork_global_key;
#else
static struct tfork_state *global_state;
#endif

static void tfork_sigchld_handler(int signum, siginfo_t *si, void *p);

#ifdef HAVE_PTHREAD
static void tfork_global_destructor(void *state)
{
	anonymous_shared_free(state);
}
#endif

static int tfork_acquire_sighandling(void)
{
	int ret = 0;

#ifdef HAVE_PTHREAD
	ret = pthread_mutex_lock(&signal_state.mutex);
	if (ret != 0) {
		return ret;
	}

	while (!signal_state.available) {
		ret = pthread_cond_wait(&signal_state.cond,
					&signal_state.mutex);
		if (ret != 0) {
			return ret;
		}
	}

	signal_state.available = false;

	ret = pthread_mutex_unlock(&signal_state.mutex);
	if (ret != 0) {
		return ret;
	}
#endif

	return ret;
}

static int tfork_release_sighandling(void)
{
	int ret = 0;

#ifdef HAVE_PTHREAD
	ret = pthread_mutex_lock(&signal_state.mutex);
	if (ret != 0) {
		return ret;
	}

	signal_state.available = true;

	ret = pthread_cond_signal(&signal_state.cond);
	if (ret != 0) {
		pthread_mutex_unlock(&signal_state.mutex);
		return ret;
	}

	ret = pthread_mutex_unlock(&signal_state.mutex);
	if (ret != 0) {
		return ret;
	}
#endif

	return ret;
}

#ifdef HAVE_PTHREAD
static void tfork_atfork_prepare(void)
{
	int ret;

	ret = pthread_mutex_lock(&signal_state.mutex);
	assert(ret == 0);
}

static void tfork_atfork_parent(void)
{
	int ret;

	ret = pthread_mutex_unlock(&signal_state.mutex);
	assert(ret == 0);
}
#endif

static void tfork_atfork_child(void)
{
	int ret;

#ifdef HAVE_PTHREAD
	ret = pthread_mutex_unlock(&signal_state.mutex);
	assert(ret == 0);

	ret = pthread_key_delete(tfork_global_key);
	assert(ret == 0);

	ret = pthread_key_create(&tfork_global_key, tfork_global_destructor);
	assert(ret == 0);

	/*
	 * There's no data race on the cond variable from the signal state, we
	 * are writing here, but there are no readers yet. Some data race
	 * detection tools report a race, but the readers are in the parent
	 * process.
	 */
	TFORK_ANNOTATE_BENIGN_RACE(&signal_state.cond);

	/*
	 * There's no way to destroy a condition variable if there are waiters,
	 * pthread_cond_destroy() will return EBUSY. Just zero out memory and
	 * then initialize again. This is not backed by POSIX but should be ok.
	 */
	ZERO_STRUCT(signal_state.cond);
	ret = pthread_cond_init(&signal_state.cond, NULL);
	assert(ret == 0);
#endif

	if (signal_state.pid != NULL) {

		ret = sigaction(SIGCHLD, &signal_state.oldact, NULL);
		assert(ret == 0);

#ifdef HAVE_PTHREAD
		ret = pthread_sigmask(SIG_SETMASK, &signal_state.oldset, NULL);
#else
		ret = sigprocmask(SIG_SETMASK, &signal_state.oldset, NULL);
#endif
		assert(ret == 0);

		signal_state.pid = NULL;
	}

	signal_state.available = true;
}

static void tfork_global_initialize(void)
{
#ifdef HAVE_PTHREAD
	int ret;

	pthread_atfork(tfork_atfork_prepare,
		       tfork_atfork_parent,
		       tfork_atfork_child);

	ret = pthread_key_create(&tfork_global_key, tfork_global_destructor);
	assert(ret == 0);

	ret = pthread_mutex_init(&signal_state.mutex, NULL);
	assert(ret == 0);

	ret = pthread_cond_init(&signal_state.cond, NULL);
	assert(ret == 0);

	/*
	 * In a threaded process there's no data race on t->waiter_pid as
	 * we're serializing globally via tfork_acquire_sighandling() and
	 * tfork_release_sighandling().
	 */
	TFORK_ANNOTATE_BENIGN_RACE(&signal_state.pid);
#endif

	signal_state.available = true;
}

static struct tfork_state *tfork_global_get(void)
{
	struct tfork_state *state = NULL;
#ifdef HAVE_PTHREAD
	int ret;
#endif

#ifdef HAVE_PTHREAD
	state = (struct tfork_state *)pthread_getspecific(tfork_global_key);
#else
	state = global_state;
#endif
	if (state != NULL) {
		return state;
	}

	state = (struct tfork_state *)anonymous_shared_allocate(
		sizeof(struct tfork_state));
	if (state == NULL) {
		return NULL;
	}

#ifdef HAVE_PTHREAD
	ret = pthread_setspecific(tfork_global_key, state);
	if (ret != 0) {
		anonymous_shared_free(state);
		return NULL;
	}
#endif
	return state;
}

static void tfork_global_free(void)
{
	struct tfork_state *state = NULL;
#ifdef HAVE_PTHREAD
	int ret;
#endif

#ifdef HAVE_PTHREAD
	state = (struct tfork_state *)pthread_getspecific(tfork_global_key);
#else
	state = global_state;
#endif
	if (state == NULL) {
		return;
	}

#ifdef HAVE_PTHREAD
	ret = pthread_setspecific(tfork_global_key, NULL);
	if (ret != 0) {
		return;
	}
#endif
	anonymous_shared_free(state);
}

/**
 * Only one thread at a time is allowed to handle SIGCHLD signals
 **/
static int tfork_install_sigchld_handler(pid_t *pid)
{
	int ret;
	struct sigaction act;
	sigset_t set;

	ret = tfork_acquire_sighandling();
	if (ret != 0) {
		return -1;
	}

	assert(signal_state.pid == NULL);
	signal_state.pid = pid;

	act = (struct sigaction) {
		.sa_sigaction = tfork_sigchld_handler,
		.sa_flags = SA_SIGINFO,
	};

	ret = sigaction(SIGCHLD, &act, &signal_state.oldact);
	if (ret != 0) {
		return -1;
	}

	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
#ifdef HAVE_PTHREAD
	ret = pthread_sigmask(SIG_UNBLOCK, &set, &signal_state.oldset);
#else
	ret = sigprocmask(SIG_UNBLOCK, &set, &signal_state.oldset);
#endif
	if (ret != 0) {
		return -1;
	}

	return 0;
}

static int tfork_uninstall_sigchld_handler(void)
{
	int ret;

	signal_state.pid = NULL;

	ret = sigaction(SIGCHLD, &signal_state.oldact, NULL);
	if (ret != 0) {
		return -1;
	}

#ifdef HAVE_PTHREAD
	ret = pthread_sigmask(SIG_SETMASK, &signal_state.oldset, NULL);
#else
	ret = sigprocmask(SIG_SETMASK, &signal_state.oldset, NULL);
#endif
	if (ret != 0) {
		return -1;
	}

	ret = tfork_release_sighandling();
	if (ret != 0) {
		return -1;
	}

	return 0;
}

static void tfork_sigchld_handler(int signum, siginfo_t *si, void *p)
{
	if ((signal_state.pid != NULL) &&
	    (*signal_state.pid != -1) &&
	    (si->si_pid == *signal_state.pid))
	{
		return;
	}

	/*
	 * Not our child, forward to old handler
	 */
	if (signal_state.oldact.sa_flags & SA_SIGINFO) {
		signal_state.oldact.sa_sigaction(signum, si, p);
		return;
	}

	if (signal_state.oldact.sa_handler == SIG_IGN) {
		return;
	}
	if (signal_state.oldact.sa_handler == SIG_DFL) {
		return;
	}
	signal_state.oldact.sa_handler(signum);
}

static pid_t tfork_start_waiter_and_worker(struct tfork_state *state,
					   int *_event_fd,
					   int *_status_fd)
{
	int p[2];
	int status_sp_caller_fd = -1;
	int status_sp_waiter_fd = -1;
	int event_pipe_caller_fd = -1;
	int event_pipe_waiter_fd = -1;
	int ready_pipe_caller_fd = -1;
	int ready_pipe_worker_fd = -1;
	ssize_t nwritten;
	ssize_t nread;
	pid_t pid;
	int status;
	int fd;
	char c;
	int ret;

	*_event_fd = -1;
	*_status_fd = -1;

	if (state == NULL) {
		return -1;
	}

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, p);
	if (ret != 0) {
		return -1;
	}
	set_close_on_exec(p[0]);
	set_close_on_exec(p[1]);
	status_sp_caller_fd = p[0];
	status_sp_waiter_fd = p[1];

	ret = pipe(p);
	if (ret != 0) {
		close(status_sp_caller_fd);
		close(status_sp_waiter_fd);
		return -1;
	}
	set_close_on_exec(p[0]);
	set_close_on_exec(p[1]);
	event_pipe_caller_fd = p[0];
	event_pipe_waiter_fd = p[1];


	ret = pipe(p);
	if (ret != 0) {
		close(status_sp_caller_fd);
		close(status_sp_waiter_fd);
		close(event_pipe_caller_fd);
		close(event_pipe_waiter_fd);
		return -1;
	}
	set_close_on_exec(p[0]);
	set_close_on_exec(p[1]);
	ready_pipe_worker_fd = p[0];
	ready_pipe_caller_fd = p[1];

	pid = fork();
	if (pid == -1) {
		close(status_sp_caller_fd);
		close(status_sp_waiter_fd);
		close(event_pipe_caller_fd);
		close(event_pipe_waiter_fd);
		close(ready_pipe_caller_fd);
		close(ready_pipe_worker_fd);
		return -1;
	}
	if (pid != 0) {
		/* The caller */

		/*
		 * In a threaded process there's no data race on
		 * state->waiter_pid as we're serializing globally via
		 * tfork_acquire_sighandling() and tfork_release_sighandling().
		 */
		TFORK_ANNOTATE_BENIGN_RACE(&state->waiter_pid);

		state->waiter_pid = pid;

		close(status_sp_waiter_fd);
		close(event_pipe_waiter_fd);
		close(ready_pipe_worker_fd);

		set_blocking(event_pipe_caller_fd, false);

		/*
		 * wait for the waiter to get ready.
		 */
		nread = sys_read(status_sp_caller_fd, &c, sizeof(char));
		if (nread != sizeof(char)) {
			return -1;
		}

		/*
		 * Notify the worker to start.
		 */
		nwritten = sys_write(ready_pipe_caller_fd,
				     &(char){0}, sizeof(char));
		if (nwritten != sizeof(char)) {
			close(ready_pipe_caller_fd);
			return -1;
		}
		close(ready_pipe_caller_fd);

		*_event_fd = event_pipe_caller_fd;
		*_status_fd = status_sp_caller_fd;

		return pid;
	}

#ifndef HAVE_PTHREAD
	/* cleanup sigchld_handler */
	tfork_atfork_child();
#endif

	/*
	 * The "waiter" child.
	 */
	setproctitle("tfork waiter process");
	prctl_set_comment("tfork waiter");
	CatchSignal(SIGCHLD, SIG_DFL);

	close(status_sp_caller_fd);
	close(event_pipe_caller_fd);
	close(ready_pipe_caller_fd);

	pid = fork();
	if (pid == -1) {
		state->waiter_errno = errno;
		_exit(0);
	}
	if (pid == 0) {
		/*
		 * The worker child.
		 */

		close(status_sp_waiter_fd);
		close(event_pipe_waiter_fd);

		/*
		 * Wait for the caller to give us a go!
		 */
		nread = sys_read(ready_pipe_worker_fd, &c, sizeof(char));
		if (nread != sizeof(char)) {
			_exit(1);
		}
		close(ready_pipe_worker_fd);

		return 0;
	}
	state->worker_pid = pid;
	setproctitle("tfork waiter process(%d)", pid);
	prctl_set_comment("tfork(%d)", pid);

	close(ready_pipe_worker_fd);

	/*
	 * We're going to stay around until child2 exits, so lets close all fds
	 * other then the pipe fd we may have inherited from the caller.
	 *
	 * Dup event_sp_waiter_fd and status_sp_waiter_fd onto fds 0 and 1 so we
	 * can then call closefrom(2).
	 */
	if (event_pipe_waiter_fd > 0) {
		int dup_fd = 0;

		if (status_sp_waiter_fd == 0) {
			dup_fd = 1;
		}

		do {
			fd = dup2(event_pipe_waiter_fd, dup_fd);
		} while ((fd == -1) && (errno == EINTR));
		if (fd == -1) {
			state->waiter_errno = errno;
			kill(state->worker_pid, SIGKILL);
			state->worker_pid = -1;
			_exit(1);
		}
		event_pipe_waiter_fd = fd;
	}

	if (status_sp_waiter_fd > 1) {
		do {
			fd = dup2(status_sp_waiter_fd, 1);
		} while ((fd == -1) && (errno == EINTR));
		if (fd == -1) {
			state->waiter_errno = errno;
			kill(state->worker_pid, SIGKILL);
			state->worker_pid = -1;
			_exit(1);
		}
		status_sp_waiter_fd = fd;
	}

	closefrom(2);

	/* Tell the caller we're ready */
	nwritten = sys_write(status_sp_waiter_fd, &(char){0}, sizeof(char));
	if (nwritten != sizeof(char)) {
		_exit(1);
	}

	tfork_global_free();
	state = NULL;

	do {
		ret = waitpid(pid, &status, 0);
	} while ((ret == -1) && (errno == EINTR));
	if (ret == -1) {
		status = errno;
		kill(pid, SIGKILL);
	}

	/*
	 * This writes the worker child exit status via our internal socketpair
	 * so the tfork_status() implementation can read it from its end.
	 */
	nwritten = sys_write(status_sp_waiter_fd, &status, sizeof(status));
	if (nwritten == -1) {
		if (errno != EPIPE && errno != ECONNRESET) {
			_exit(errno);
		}
		/*
		 * The caller exitted and didn't call tfork_status().
		 */
		_exit(0);
	}
	if (nwritten != sizeof(status)) {
		_exit(1);
	}

	/*
	 * This write to the event_fd returned by tfork_event_fd() and notifies
	 * the caller that the worker child is done and he may now call
	 * tfork_status().
	 */
	nwritten = sys_write(event_pipe_waiter_fd, &(char){0}, sizeof(char));
	if (nwritten != sizeof(char)) {
		_exit(1);
	}

	/*
	 * Wait for our parent (the process that called tfork_create()) to
	 * close() the socketpair fd in tfork_status().
	 *
	 * Again, the caller might have exitted without calling tfork_status().
	 */
	nread = sys_read(status_sp_waiter_fd, &c, 1);
	if (nread == -1) {
		if (errno == EPIPE || errno == ECONNRESET) {
			_exit(0);
		}
		_exit(errno);
	}
	if (nread != 1) {
		_exit(255);
	}

	_exit(0);
}

static int tfork_create_reap_waiter(pid_t waiter_pid)
{
	pid_t pid;
	int waiter_status;

	if (waiter_pid == -1) {
		return 0;
	}

	kill(waiter_pid, SIGKILL);

	do {
		pid = waitpid(waiter_pid, &waiter_status, 0);
	} while ((pid == -1) && (errno == EINTR));
	assert(pid == waiter_pid);

	return 0;
}

struct tfork *tfork_create(void)
{
	struct tfork_state *state = NULL;
	struct tfork *t = NULL;
	pid_t pid;
	int saved_errno;
	int ret = 0;

#ifdef HAVE_PTHREAD
	ret = pthread_once(&tfork_global_is_initialized,
			   tfork_global_initialize);
	if (ret != 0) {
		return NULL;
	}
#else
	tfork_global_initialize();
#endif

	state = tfork_global_get();
	if (state == NULL) {
		return NULL;
	}
	*state = (struct tfork_state) {
		.waiter_pid = -1,
		.waiter_errno = ECANCELED,
		.worker_pid = -1,
	};

	t = malloc(sizeof(struct tfork));
	if (t == NULL) {
		ret = -1;
		goto cleanup;
	}

	*t = (struct tfork) {
		.event_fd = -1,
		.status_fd = -1,
		.waiter_pid = -1,
		.worker_pid = -1,
	};

	ret = tfork_install_sigchld_handler(&state->waiter_pid);
	if (ret != 0) {
		goto cleanup;
	}

	pid = tfork_start_waiter_and_worker(state,
					    &t->event_fd,
					    &t->status_fd);
	if (pid == -1) {
		ret = -1;
		goto cleanup;
	}
	if (pid == 0) {
		/* In the worker */
		tfork_global_free();
		t->worker_pid = 0;
		return t;
	}

	/*
	 * In a threaded process there's no data race on t->waiter_pid as
	 * we're serializing globally via tfork_acquire_sighandling() and
	 * tfork_release_sighandling().
	 */
	TFORK_ANNOTATE_BENIGN_RACE(&t->waiter_pid);

	t->waiter_pid = pid;
	t->worker_pid = state->worker_pid;

cleanup:
	if (ret == -1) {
		saved_errno = errno;

		if (t != NULL) {
			if (t->status_fd != -1) {
				close(t->status_fd);
			}
			if (t->event_fd != -1) {
				close(t->event_fd);
			}

			ret = tfork_create_reap_waiter(state->waiter_pid);
			assert(ret == 0);

			free(t);
			t = NULL;
		}
	}

	ret = tfork_uninstall_sigchld_handler();
	assert(ret == 0);

	tfork_global_free();

	if (ret == -1) {
		errno = saved_errno;
	}
	return t;
}

pid_t tfork_child_pid(const struct tfork *t)
{
	return t->worker_pid;
}

int tfork_event_fd(struct tfork *t)
{
	int fd = t->event_fd;

	assert(t->event_fd != -1);
	t->event_fd = -1;

	return fd;
}

int tfork_status(struct tfork **_t, bool wait)
{
	struct tfork *t = *_t;
	int status;
	ssize_t nread;
	int waiter_status;
	pid_t pid;
	int ret;

	if (t == NULL) {
		return -1;
	}

	if (wait) {
		set_blocking(t->status_fd, true);

		nread = sys_read(t->status_fd, &status, sizeof(int));
	} else {
		set_blocking(t->status_fd, false);

		nread = read(t->status_fd, &status, sizeof(int));
		if ((nread == -1) &&
		    ((errno == EAGAIN) || (errno == EWOULDBLOCK) || errno == EINTR)) {
			errno = EAGAIN;
			return -1;
		}
	}
	if (nread != sizeof(int)) {
		return -1;
	}

	ret = tfork_install_sigchld_handler(&t->waiter_pid);
	if (ret != 0) {
		return -1;
	}

	/*
	 * This triggers process exit in the waiter.
	 * We write to the fd as well as closing it, as any tforked sibling
	 * processes will also have the writable end of this socket open.
	 *
	 */
	{
		size_t nwritten;
		nwritten = sys_write(t->status_fd, &(char){0}, sizeof(char));
		if (nwritten != sizeof(char)) {
			close(t->status_fd);
			return -1;
		}
	}
	close(t->status_fd);

	do {
		pid = waitpid(t->waiter_pid, &waiter_status, 0);
	} while ((pid == -1) && (errno == EINTR));
	assert(pid == t->waiter_pid);

	if (t->event_fd != -1) {
		close(t->event_fd);
		t->event_fd = -1;
	}

	free(t);
	t = NULL;
	*_t = NULL;

	ret = tfork_uninstall_sigchld_handler();
	assert(ret == 0);

	return status;
}

int tfork_destroy(struct tfork **_t)
{
        struct tfork *t = *_t;
        int ret;

        if (t == NULL) {
                errno = EINVAL;
                return -1;
        }

        kill(t->worker_pid, SIGKILL);

        ret = tfork_status(_t, true);
        if (ret == -1) {
                return -1;
        }

        return 0;
}
