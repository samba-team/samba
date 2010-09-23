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
#include "lib/util/samba_util.h"
#include "lib/util/sys_rw.h"
#include "lib/util/tfork.h"
#include "lib/util/debug.h"

struct tfork_state {
	void (*old_sig_chld)(int);
	int status_pipe[2];
	pid_t *parent;

	pid_t level0_pid;
	int level0_status;

	pid_t level1_pid;
	int level1_errno;

	pid_t level2_pid;
	int level2_errno;

	pid_t level3_pid;
};

/*
 * TODO: We should make this global thread local
 */
static struct tfork_state *tfork_global;

static void tfork_sig_chld(int signum)
{
	if (tfork_global->level1_pid > 0) {
		int ret = waitpid(tfork_global->level1_pid,
			      &tfork_global->level0_status,
			      WNOHANG);
		if (ret == tfork_global->level1_pid) {
			tfork_global->level1_pid = -1;
			return;
		}
	}

	/*
	 * Not our child, forward to old handler
	 */

	if (tfork_global->old_sig_chld == SIG_IGN) {
		return;
	}

	if (tfork_global->old_sig_chld == SIG_DFL) {
		return;
	}

	tfork_global->old_sig_chld(signum);
}

static pid_t level2_fork_and_wait(int child_ready_fd)
{
	int status;
	ssize_t written;
	pid_t pid;
	int fd;
	bool wait;

	/*
	 * Child level 2.
	 *
	 * Do a final fork and if the tfork() caller passed a status_fd, wait
	 * for child3 and return its exit status via status_fd.
	 */

	pid = fork();
	if (pid == 0) {
		/*
		 * Child level 3, this one finally returns from tfork() as child
		 * with pid 0.
		 *
		 * Cleanup all ressources we allocated before returning.
		 */
		close(child_ready_fd);
		close(tfork_global->status_pipe[1]);

		if (tfork_global->parent != NULL) {
			/*
			 * we're in the child and return the level0 parent pid
			 */
			*tfork_global->parent = tfork_global->level0_pid;
		}

		anonymous_shared_free(tfork_global);
		tfork_global = NULL;

		return 0;
	}

	tfork_global->level3_pid = pid;
	if (tfork_global->level3_pid == -1) {
		tfork_global->level2_errno = errno;
		_exit(0);
	}

	sys_write(child_ready_fd, &(char){0}, 1);

	if (tfork_global->status_pipe[1] == -1) {
		_exit(0);
	}
	wait = true;

	/*
	 * We're going to stay around until child3 exits, so lets close all fds
	 * other then the pipe fd we may have inherited from the caller.
	 */
	fd = dup2(tfork_global->status_pipe[1], 0);
	if (fd == -1) {
		status = errno;
		kill(tfork_global->level3_pid, SIGKILL);
		wait = false;
	}
	closefrom(1);

	while (wait) {
		int ret = waitpid(tfork_global->level3_pid, &status, 0);
		if (ret == -1) {
			if (errno == EINTR) {
				continue;
			}
			status = errno;
		}
		break;
	}

	written = sys_write(fd, &status, sizeof(status));
	if (written != sizeof(status)) {
		abort();
	}

	_exit(0);
}

pid_t tfork(int *status_fd, pid_t *parent)
{
	int ret;
	pid_t pid;
	pid_t child;

	tfork_global = (struct tfork_state *)
		anonymous_shared_allocate(sizeof(struct tfork_state));
	if (tfork_global == NULL) {
		return -1;
	}

	tfork_global->parent = parent;
	tfork_global->status_pipe[0] = -1;
	tfork_global->status_pipe[1] = -1;

	tfork_global->level0_pid = getpid();
	tfork_global->level0_status = -1;
	tfork_global->level1_pid = -1;
	tfork_global->level1_errno = ECANCELED;
	tfork_global->level2_pid = -1;
	tfork_global->level2_errno = ECANCELED;
	tfork_global->level3_pid = -1;

	if (status_fd != NULL) {
		ret = pipe(&tfork_global->status_pipe[0]);
		if (ret != 0) {
			int saved_errno = errno;

			anonymous_shared_free(tfork_global);
			tfork_global = NULL;
			errno = saved_errno;
			return -1;
		}

		*status_fd = tfork_global->status_pipe[0];
	}

	/*
	 * We need to set our own signal handler to prevent any existing signal
	 * handler from reaping our child.
	 */
	tfork_global->old_sig_chld = CatchSignal(SIGCHLD, tfork_sig_chld);

	pid = fork();
	if (pid == 0) {
		int level2_pipe[2];
		char c;
		ssize_t nread;

		/*
		 * Child level 1.
		 *
		 * Restore SIGCHLD handler
		 */
		CatchSignal(SIGCHLD, SIG_DFL);

		/*
		 * Close read end of the signal pipe, we don't need it anymore
		 * and don't want to leak it into childs.
		 */
		if (tfork_global->status_pipe[0] != -1) {
			close(tfork_global->status_pipe[0]);
			tfork_global->status_pipe[0] = -1;
		}

		/*
		 * Create a pipe for waiting for the child level 2 to finish
		 * forking.
		 */
		ret = pipe(&level2_pipe[0]);
		if (ret != 0) {
			tfork_global->level1_errno = errno;
			_exit(0);
		}

		pid = fork();
		if (pid == 0) {

			/*
			 * Child level 2.
			 */

			close(level2_pipe[0]);
			return level2_fork_and_wait(level2_pipe[1]);
		}

		tfork_global->level2_pid = pid;
		if (tfork_global->level2_pid == -1) {
			tfork_global->level1_errno = errno;
			_exit(0);
		}

		close(level2_pipe[1]);
		level2_pipe[1] = -1;

		nread = sys_read(level2_pipe[0], &c, 1);
		if (nread != 1) {
			abort();
		}
		_exit(0);
	}

	tfork_global->level1_pid = pid;
	if (tfork_global->level1_pid == -1) {
		int saved_errno = errno;

		anonymous_shared_free(tfork_global);
		tfork_global = NULL;
		errno = saved_errno;
		return -1;
	}

	/*
	 * By using the helper variable pid we avoid a TOCTOU with the signal
	 * handler that will set tfork_global->level1_pid to -1 (which would
	 * cause waitpid() to block waiting for another exitted child).
	 *
	 * We can't avoid the race waiting for pid twice (in the signal handler
	 * and then again here in the while loop), but we must avoid waiting for
	 * -1 and this does the trick.
	 */
	pid = tfork_global->level1_pid;

	while (tfork_global->level1_pid != -1) {
		ret = waitpid(pid, &tfork_global->level0_status, 0);
		if (ret == -1 && errno == EINTR) {
			continue;
		}

		break;
	}

	CatchSignal(SIGCHLD, tfork_global->old_sig_chld);

	if (tfork_global->level0_status != 0) {
		anonymous_shared_free(tfork_global);
		tfork_global = NULL;
		errno = ECHILD;
		return -1;
	}

	if (tfork_global->level2_pid == -1) {
		int saved_errno = tfork_global->level1_errno;

		anonymous_shared_free(tfork_global);
		tfork_global = NULL;
		errno = saved_errno;
		return -1;
	}

	if (tfork_global->level3_pid == -1) {
		int saved_errno = tfork_global->level2_errno;

		anonymous_shared_free(tfork_global);
		tfork_global = NULL;
		errno = saved_errno;
		return -1;
	}

	child = tfork_global->level3_pid;
	anonymous_shared_free(tfork_global);
	tfork_global = NULL;

	return child;
}
