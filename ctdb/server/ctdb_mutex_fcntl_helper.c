/*
   CTDB mutex fcntl lock file helper

   Copyright (C) Martin Schwenke 2015

   wait_for_parent() code from ctdb_lock_helper.c:

   Copyright (C) Amitay Isaacs  2013

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/filesys.h"
#include "system/network.h"
#include "system/wait.h"
#include "system/dir.h"

#include <tevent.h>

#include "lib/util/sys_rw.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/util.h"
#include "lib/util/smb_strtox.h"

/* protocol.h is just needed for ctdb_sock_addr, which is used in system.h */
#include "protocol/protocol.h"
#include "common/system.h"
#include "common/tmon.h"

static char progpath[PATH_MAX];
static char *progname = NULL;

static int fcntl_lock_fd(int fd, bool block, off_t start)
{
	static struct flock lock = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_len = 1,
		.l_pid = 0,
	};
	int cmd = block ? F_SETLKW : F_SETLK;

	lock.l_start = start;
	if (fcntl(fd, cmd, &lock) != 0) {
		return errno;
	}

	return 0;
}

static char fcntl_lock(const char *file, int *outfd)
{
	int fd;
	int ret;

	fd = open(file, O_RDWR|O_CREAT, 0600);
	if (fd == -1) {
		fprintf(stderr, "%s: Unable to open %s - (%s)\n",
			progname, file, strerror(errno));
		return '3';
	}

	ret = fcntl_lock_fd(fd, false, 0);
	if (ret != 0) {
		close(fd);
		if (ret == EACCES || ret == EAGAIN) {
			/* Lock contention, fail silently */
			return '1';
		}

		/* Log an error for any other failure */
		fprintf(stderr,
			"%s: Failed to get lock on '%s' - (%s)\n",
			progname,
			file,
			strerror(ret));
		return '3';
	}

	*outfd = fd;

	return '0';
}

/*
 * Wait and see if the parent exits
 */

struct wait_for_parent_state {
	struct tevent_context *ev;
	pid_t ppid;
};

static void wait_for_parent_check(struct tevent_req *subreq);

static struct tevent_req *wait_for_parent_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       pid_t ppid)
{
	struct tevent_req *req, *subreq;
	struct wait_for_parent_state *state;

	req = tevent_req_create(mem_ctx, &state, struct wait_for_parent_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->ppid = ppid;

	if (ppid == 1) {
		fprintf(stderr, "parent == 1\n");
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	subreq = tevent_wakeup_send(state, ev,
				    tevent_timeval_current_ofs(5,0));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wait_for_parent_check, req);

	return req;
}

static void wait_for_parent_check(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wait_for_parent_state *state = tevent_req_data(
		req, struct wait_for_parent_state);
	bool status;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (! status) {
		/* Ignore error */
		fprintf(stderr, "%s: tevent_wakeup_recv() failed\n", progname);
	}

	if (kill(state->ppid, 0) == -1 && errno == ESRCH) {
		fprintf(stderr, "parent gone\n");
		tevent_req_done(req);
		return;
	}

	subreq = tevent_wakeup_send(state, state->ev,
				    tevent_timeval_current_ofs(5,0));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wait_for_parent_check, req);
}

static bool wait_for_parent_recv(struct tevent_req *req, int *perr)
{
	if (tevent_req_is_unix_error(req, perr)) {
		return false;
	}

	return true;
}

/*
 * Perform I/O on lock in a loop - complete when file removed or replaced
 */

struct lock_io_check_state {
	struct tevent_context *ev;
	const char *lock_file;
	ino_t inode;
	unsigned long recheck_interval;
};

static void lock_io_check_loop(struct tevent_req *subreq);

static struct tevent_req *lock_io_check_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     const char *lock_file,
					     ino_t inode,
					     unsigned long recheck_interval)
{
	struct tevent_req *req, *subreq;
	struct lock_io_check_state *state;

	req = tevent_req_create(mem_ctx, &state, struct lock_io_check_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->lock_file = lock_file;
	state->inode = inode;
	state->recheck_interval = recheck_interval;

	subreq = tevent_wakeup_send(
			state,
			ev,
			tevent_timeval_current_ofs(state->recheck_interval, 0));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, lock_io_check_loop, req);

	return req;
}

static void lock_io_check_loop(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct lock_io_check_state *state = tevent_req_data(
		req, struct lock_io_check_state);
	bool status;
	struct stat sb;
	int fd = -1;
	int ret;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (! status) {
		/* Ignore error */
		fprintf(stderr, "%s: tevent_wakeup_recv() failed\n", progname);
	}

	fd = open(state->lock_file, O_RDWR);
	if (fd == -1) {
		fprintf(stderr,
			"%s: "
			"lock lost - lock file \"%s\" open failed (ret=%d)\n",
			progname,
			state->lock_file,
			errno);
		goto done;
	}

	ret = fstat(fd, &sb);
	if (ret != 0) {
		fprintf(stderr,
			"%s: "
			"lock lost - lock file \"%s\" check failed (ret=%d)\n",
			progname,
			state->lock_file,
			errno);
		goto done;
	}

	if (sb.st_ino != state->inode) {
		fprintf(stderr,
			"%s: lock lost - lock file \"%s\" inode changed\n",
			progname,
			state->lock_file);
		goto done;
	}

	/*
	 * Attempt to lock a 2nd byte range.  Using a blocking lock
	 * encourages ping timeouts if the cluster filesystem is in a
	 * bad state.  It also makes testing easier.
	 */
	ret = fcntl_lock_fd(fd, true, 1);
	if (ret != 0) {
		fprintf(stderr,
			"%s: "
			"lock fail - lock file \"%s\" test lock error (%d)\n",
			progname,
			state->lock_file,
			ret);
		goto done;
	}

	/* Unlock occurs on close */
	close(fd);

	subreq = tevent_wakeup_send(
			state,
			state->ev,
			tevent_timeval_current_ofs(state->recheck_interval, 0));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, lock_io_check_loop, req);

	return;

done:
	if (fd != -1) {
		close(fd);
	}
	tevent_req_done(req);
}

static bool lock_io_check_recv(struct tevent_req *req, int *perr)
{
	if (tevent_req_is_unix_error(req, perr)) {
		return false;
	}

	return true;
}

struct lock_test_child_state {
};

static void lock_test_child_ping_done(struct tevent_req *subreq);
static void lock_test_child_io_check_done(struct tevent_req *subreq);

static struct tevent_req *lock_test_child_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       const char *lock_file,
					       int fd,
					       ino_t inode,
					       unsigned long recheck_interval,
					       bool send_pings)
{
	struct tevent_req *req, *subreq;
	struct lock_test_child_state *state;
	unsigned int interval = send_pings ? 1 : 0;

	req = tevent_req_create(mem_ctx, &state, struct lock_test_child_state);
	if (req == NULL) {
		return NULL;
	}

	subreq = tmon_ping_send(state, ev, fd, TMON_FD_BOTH, 0, interval);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, lock_test_child_ping_done, req);

	subreq = lock_io_check_send(state,
				    ev,
				    lock_file,
				    inode,
				    recheck_interval);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, lock_test_child_io_check_done, req);

	return req;
}

static void lock_test_child_ping_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	bool status;
	int err;

	status = tmon_ping_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (!status) {
		tevent_req_error(req, err);
		return;
	}

	tevent_req_done(req);
}

static void lock_test_child_io_check_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	bool status;
	int err;

	status = lock_io_check_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (!status) {
		tevent_req_error(req, err);
		return;
	}

	tevent_req_done(req);
}

static bool lock_test_child_recv(struct tevent_req *req, int *perr)
{
	if (tevent_req_is_unix_error(req, perr)) {
		/* Parent exit is expected */
		if (*perr == EPIPE) {
			return true;
		}
		return false;
	}

	return true;
}

static void lock_test_child(const char *lock_file,
			    int lock_fd,
			    int pipe_fd,
			    unsigned long recheck_interval,
			    bool send_pings)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	struct stat sb;
	ino_t inode;
	bool status;
	int ret;

	ret = fstat(lock_fd, &sb);
	if (ret != 0) {
		fprintf(stderr,
			"%s: lock lost - "
			"lock file \"%s\" stat failed (ret=%d)\n",
			progname,
			lock_file,
			errno);
		_exit(1);
	}
	inode = sb.st_ino;
	close(lock_fd);

	ev = tevent_context_init(NULL);
	if (ev == NULL) {
		fprintf(stderr, "%s: tevent_context_init() failed\n", progname);
		_exit(1);
	}

	req = lock_test_child_send(ev,
				   ev,
				   lock_file,
				   pipe_fd,
				   inode,
				   recheck_interval,
				   send_pings);
	if (req == NULL) {
		fprintf(stderr,
			"%s: lock_test_child_send() failed\n",
			progname);
		_exit(1);
	}

	tevent_req_poll(req, ev);

	status = lock_test_child_recv(req, &ret);
	if (! status) {
		fprintf(stderr,
			"%s: lock_test_child_recv() failed (%d)\n",
			progname,
			ret);
		_exit(1);
	}

	_exit(0);
}

struct lock_test_state {
	int *lock_fdp;
	int pipe_fd;
	pid_t child_pid;
};

static void lock_test_ping_done(struct tevent_req *subreq);

static struct tevent_req *lock_test_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 const char *lock_file,
					 int *fdp,
					 unsigned long recheck_interval,
					 unsigned long ping_timeout)
{
	struct tevent_req *req, *subreq;
	struct lock_test_state *state;
	pid_t pid;
	int sv[2];
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct lock_test_state);
	if (req == NULL) {
		return NULL;
	}

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	if (ret != 0) {
		fprintf(stderr,
			"%s: socketpair() failed (errno=%d)\n",
			progname,
			errno);
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	pid = fork();
	if (pid == -1) {

		int err = errno;
		fprintf(stderr, "%s: fork() failed (errno=%d)\n", progname, err);
		close(sv[0]);
		close(sv[1]);
		tevent_req_error(req, err);
		return tevent_req_post(req, ev);
	}
	if (pid == 0) {
		/* Child */
		close(sv[0]);
		TALLOC_FREE(ev);

		lock_test_child(lock_file,
				*fdp,
				sv[1],
				recheck_interval,
				ping_timeout != 0);
		/* Above does not return */
	}

	/* Parent */
	close(sv[1]);

	state->lock_fdp = fdp;
	state->pipe_fd = sv[0];
	state->child_pid = pid;

	subreq = tmon_ping_send(state, ev, sv[0], TMON_FD_BOTH, ping_timeout, 0);
	if (tevent_req_nomem(subreq, req)) {
		close(sv[0]);
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, lock_test_ping_done, req);

	return req;
}

static void lock_test_ping_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct lock_test_state *state = tevent_req_data(
		req, struct lock_test_state);
	int wstatus;
	bool status;
	int err;

	status = tmon_ping_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (! status) {
		switch (err) {
		case EPIPE:
			/* Child exit, child already printed message */
			break;
		case ETIMEDOUT:
			fprintf(stderr,
				"%s: ping timeout from lock test child\n",
				progname);
			break;
		default:
			fprintf(stderr,
				"%s: tmon_ping_recv() failed (%d)\n",
				progname,
				err);
		}
		/* Ignore error */
	}

	/*
	 * Lock checking child is gone or not sending pings.  Release
	 * the lock, close this end of pipe, send SIGKILL to the child
	 * process and wait for the child to exit.
	 */
	close(*state->lock_fdp);
	*state->lock_fdp = -1;
	close(state->pipe_fd);
	kill(state->child_pid, SIGKILL);
	waitpid(state->child_pid, &wstatus, 0);

	tevent_req_done(req);
}

static bool lock_test_recv(struct tevent_req *req, int *perr)
{
	if (tevent_req_is_unix_error(req, perr)) {
		return false;
	}

	return true;
}

/*
 * Wait for a reason to exit, indicating that parent has exited or I/O
 * on lock failed
 */

struct wait_for_exit_state {
};

static void wait_for_exit_parent_done(struct tevent_req *subreq);
static void wait_for_exit_lock_test_done(struct tevent_req *subreq);

static struct tevent_req *wait_for_exit_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     pid_t ppid,
					     const char *lock_file,
					     int *fdp,
					     unsigned long recheck_interval,
					     unsigned long ping_timeout)
{
	struct tevent_req *req, *subreq;
	struct wait_for_exit_state *state;

	req = tevent_req_create(mem_ctx, &state, struct wait_for_exit_state);
	if (req == NULL) {
		return NULL;
	}

	subreq = wait_for_parent_send(state, ev, ppid);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wait_for_exit_parent_done, req);

	if (recheck_interval > 0) {
		subreq = lock_test_send(state,
					ev,
					lock_file,
					fdp,
					recheck_interval,
					ping_timeout);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq,
					wait_for_exit_lock_test_done,
					req);
	}

	return req;
}

static void wait_for_exit_parent_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	bool status;
	int err;

	status = wait_for_parent_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (! status) {
		/* Ignore error */
		fprintf(stderr,
			"%s: "
			"wait_for_parent_recv() failed (%d)\n",
			progname,
			err);
	}

	tevent_req_done(req);
}

static void wait_for_exit_lock_test_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	bool status;
	int err;

	status = lock_test_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (! status) {
		fprintf(stderr,
			"%s: "
			"lock_test_recv() failed (%d)\n",
			progname,
			err);
		/* Ignore error, fall through to done */
	}

	tevent_req_done(req);
}

static bool wait_for_exit_recv(struct tevent_req *req, int *perr)
{
	if (tevent_req_is_unix_error(req, perr)) {
		return false;
	}

	return true;
}

static void usage(void)
{
	fprintf(stderr,
		"Usage: %s <file> [recheck_interval [ping_timeout]]\n",
		progname);
}

int main(int argc, char *argv[])
{
	struct tevent_context *ev;
	char result;
	int ppid;
	const char *file = NULL;
	unsigned long recheck_interval;
	unsigned long ping_timeout;
	int ret;
	int fd = -1;
	struct tevent_req *req;
	bool status;

	strlcpy(progpath, argv[0], sizeof(progpath));
	progname = basename(progpath);

	if (argc < 2 || argc > 4) {
		usage();
		exit(1);
	}

	ev = tevent_context_init(NULL);
	if (ev == NULL) {
		fprintf(stderr, "locking: tevent_context_init() failed\n");
		exit(1);
	}

	ppid = getppid();

	file = argv[1];

	recheck_interval = 5;
	ping_timeout = 0;
	if (argc >= 3) {
		recheck_interval = smb_strtoul(argv[2],
					       NULL,
					       10,
					       &ret,
					       SMB_STR_STANDARD);
		if (ret != 0) {
			usage();
			exit(1);
		}
	}
	if (argc >= 4) {
		ping_timeout = smb_strtoul(argv[3],
					   NULL,
					   10,
					   &ret,
					   SMB_STR_STANDARD);
		if (ret != 0) {
			usage();
			exit(1);
		}
	}

	result = fcntl_lock(file, &fd);
	sys_write(STDOUT_FILENO, &result, 1);

	if (result != '0') {
		return 0;
	}

	req = wait_for_exit_send(ev,
				 ev,
				 ppid,
				 file,
				 &fd,
				 recheck_interval,
				 ping_timeout);
	if (req == NULL) {
		fprintf(stderr,
			"%s: wait_for_exit_send() failed\n",
			progname);
		exit(1);
	}

	tevent_req_poll(req, ev);

	status = wait_for_exit_recv(req, &ret);
	if (! status) {
		fprintf(stderr,
			"%s: wait_for_exit_recv() failed (%d)\n",
			progname,
			ret);
	}

	if (fd != -1) {
		close(fd);
	}

	return 0;
}
