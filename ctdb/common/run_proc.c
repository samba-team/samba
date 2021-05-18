/*
   Run a child process and collect the output

   Copyright (C) Amitay Isaacs  2016

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
#include "system/wait.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/util/tevent_unix.h"
#include "lib/util/sys_rw.h"
#include "lib/util/blocking.h"
#include "lib/util/dlinklist.h"

#include "common/run_proc.h"

/*
 * Process abstraction
 */

struct run_proc_context;

struct proc_context {
	struct proc_context *prev, *next;

	pid_t pid;

	int fd;
	struct tevent_fd *fde;

	char *output;
	struct run_proc_result result;

	struct tevent_req *req;
};

static int proc_destructor(struct proc_context *proc);

static struct proc_context *proc_new(TALLOC_CTX *mem_ctx,
				     struct run_proc_context *run_ctx)
{
	struct proc_context *proc;

	proc = talloc_zero(mem_ctx, struct proc_context);
	if (proc == NULL) {
		return NULL;
	}

	proc->pid = -1;
	proc->fd = -1;

	talloc_set_destructor(proc, proc_destructor);

	return proc;
}

static void run_proc_kill(struct tevent_req *req);

static int proc_destructor(struct proc_context *proc)
{
	if (proc->req != NULL) {
		run_proc_kill(proc->req);
	}

	talloc_free(proc->fde);
	if (proc->pid != -1) {
		kill(-proc->pid, SIGKILL);
	}

	return 0;
}

static void proc_read_handler(struct tevent_context *ev,
			      struct tevent_fd *fde, uint16_t flags,
			      void *private_data);

static int proc_start(struct proc_context *proc, struct tevent_context *ev,
		      const char *path, const char **argv, int stdin_fd)
{
	int fd[2];
	int ret;

	ret = pipe(fd);
	if (ret != 0) {
		return ret;
	}

	proc->pid = fork();
	if (proc->pid == -1) {
		ret = errno;
		close(fd[0]);
		close(fd[1]);
		return ret;
	}

	if (proc->pid == 0) {
		close(fd[0]);

		ret = dup2(fd[1], STDOUT_FILENO);
		if (ret == -1) {
			exit(64 + errno);
		}
		ret = dup2(fd[1], STDERR_FILENO);
		if (ret == -1) {
			exit(64 + errno);
		}

		close(fd[1]);

		if (stdin_fd != -1) {
			ret = dup2(stdin_fd, STDIN_FILENO);
			if (ret == -1) {
				exit(64 + errno);
			}
		}

		ret = setpgid(0, 0);
		if (ret != 0) {
			exit(64 + errno);
		}

		ret = execv(path, discard_const(argv));
		if (ret != 0) {
			exit(64 + errno);
		}

		exit(64 + ENOEXEC);
	}

	close(fd[1]);

	proc->fd = fd[0];
	proc->fde = tevent_add_fd(ev, proc, fd[0], TEVENT_FD_READ,
				  proc_read_handler, proc);
	if (proc->fde == NULL) {
		close(fd[0]);
		return ENOMEM;
	}

	tevent_fd_set_auto_close(proc->fde);

	return 0;
}

static void proc_read_handler(struct tevent_context *ev,
			      struct tevent_fd *fde, uint16_t flags,
			      void *private_data)
{
	struct proc_context *proc = talloc_get_type_abort(
		private_data, struct proc_context);
	size_t offset;
	ssize_t nread;
	int len = 0;
	int ret;

	ret = ioctl(proc->fd, FIONREAD, &len);
	if (ret != 0) {
		goto fail;
	}

	if (len == 0) {
		/* pipe closed */
		goto close;
	}

	offset = (proc->output == NULL) ? 0 : strlen(proc->output);

	proc->output = talloc_realloc(proc, proc->output, char, offset+len+1);
	if (proc->output == NULL) {
		goto fail;
	}

	nread = sys_read(proc->fd, proc->output + offset, len);
	if (nread == -1) {
		goto fail;
	}
	proc->output[offset+nread] = '\0';
	return;

fail:
	if (proc->pid != -1) {
		kill(-proc->pid, SIGKILL);
		proc->pid = -1;
	}
close:
	TALLOC_FREE(proc->fde);
	proc->fd = -1;
}


/*
 * Run proc abstraction
 */

struct run_proc_context {
	struct tevent_context *ev;
	struct tevent_signal *se;
	struct proc_context *plist;
};

static void run_proc_signal_handler(struct tevent_context *ev,
				    struct tevent_signal *se,
				    int signum, int count, void *siginfo,
				    void *private_data);
static int run_proc_context_destructor(struct run_proc_context *run_ctx);
static void run_proc_done(struct tevent_req *req);

int run_proc_init(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		  struct run_proc_context **result)
{
	struct run_proc_context *run_ctx;

	run_ctx = talloc_zero(mem_ctx, struct run_proc_context);
	if (run_ctx == NULL) {
		return ENOMEM;
	}

	run_ctx->ev = ev;
	run_ctx->se = tevent_add_signal(ev, run_ctx, SIGCHLD, 0,
				       run_proc_signal_handler, run_ctx);
	if (run_ctx->se == NULL) {
		talloc_free(run_ctx);
		return ENOMEM;
	}

	talloc_set_destructor(run_ctx, run_proc_context_destructor);

	*result = run_ctx;
	return 0;
}

static void run_proc_signal_handler(struct tevent_context *ev,
				    struct tevent_signal *se,
				    int signum, int count, void *siginfo,
				    void *private_data)
{
	struct run_proc_context *run_ctx = talloc_get_type_abort(
		private_data, struct run_proc_context);
	struct proc_context *proc;
	pid_t pid = -1;
	int status;

again:
	pid = waitpid(-1, &status, WNOHANG);
	if (pid == -1) {
		return;
	}

	if (pid == 0) {
		return;
	}

	for (proc = run_ctx->plist; proc != NULL; proc = proc->next) {
		if (proc->pid == pid) {
			break;
		}
	}

	if (proc == NULL) {
		/* unknown process */
		goto again;
	}

	/* Mark the process as terminated */
	proc->pid = -1;

	/* Update process status */
	if (WIFEXITED(status)) {
		int pstatus = WEXITSTATUS(status);
		if (WIFSIGNALED(status)) {
			proc->result.sig = WTERMSIG(status);
		} else if (pstatus >= 64 && pstatus < 255) {
			proc->result.err = pstatus-64;
		} else {
			proc->result.status = pstatus;
		}
	} else if (WIFSIGNALED(status)) {
		proc->result.sig = WTERMSIG(status);
	}

	/* Confirm that all data has been read from the pipe */
	if (proc->fd != -1) {
		proc_read_handler(ev, proc->fde, 0, proc);
		TALLOC_FREE(proc->fde);
		proc->fd = -1;
	}

	DLIST_REMOVE(run_ctx->plist, proc);

	/* Active run_proc request */
	if (proc->req != NULL) {
		run_proc_done(proc->req);
	} else {
		talloc_free(proc);
	}

	goto again;
}

static int run_proc_context_destructor(struct run_proc_context *run_ctx)
{
	struct proc_context *proc;

	/* Get rid of signal handler */
	TALLOC_FREE(run_ctx->se);

	/* Kill any pending processes */
	while ((proc = run_ctx->plist) != NULL) {
		DLIST_REMOVE(run_ctx->plist, proc);
		talloc_free(proc);
	}

	return 0;
}

struct run_proc_state {
	struct tevent_context *ev;
	struct run_proc_context *run_ctx;
	struct proc_context *proc;

	struct run_proc_result result;
	char *output;
	pid_t pid;
};

static int run_proc_state_destructor(struct run_proc_state *state);
static void run_proc_timedout(struct tevent_req *subreq);

struct tevent_req *run_proc_send(TALLOC_CTX *mem_ctx,
				 struct tevent_context *ev,
				 struct run_proc_context *run_ctx,
				 const char *path, const char **argv,
				 int stdin_fd, struct timeval timeout)
{
	struct tevent_req *req;
	struct run_proc_state *state;
	struct stat st;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct run_proc_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->run_ctx = run_ctx;
	state->pid = -1;

	ret = stat(path, &st);
	if (ret != 0) {
		state->result.err = errno;
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	if (! (st.st_mode & S_IXUSR)) {
		state->result.err = EACCES;
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	state->proc = proc_new(run_ctx, run_ctx);
	if (tevent_req_nomem(state->proc, req)) {
		return tevent_req_post(req, ev);
	}

	state->proc->req = req;
	DLIST_ADD(run_ctx->plist, state->proc);

	ret = proc_start(state->proc, ev, path, argv, stdin_fd);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	talloc_set_destructor(state, run_proc_state_destructor);

	if (! tevent_timeval_is_zero(&timeout)) {
		struct tevent_req *subreq;

		subreq = tevent_wakeup_send(state, ev, timeout);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, run_proc_timedout, req);
	}

	return req;
}

static int run_proc_state_destructor(struct run_proc_state *state)
{
	/* Do not get rid of the child process if timeout has occurred */
	if (state->proc->req != NULL) {
		state->proc->req = NULL;
		DLIST_REMOVE(state->run_ctx->plist, state->proc);
		talloc_free(state->proc);
	}

	return 0;
}

static void run_proc_done(struct tevent_req *req)
{
	struct run_proc_state *state = tevent_req_data(
		req, struct run_proc_state);

	state->proc->req = NULL;

	state->result = state->proc->result;
	if (state->proc->output != NULL) {
		state->output = talloc_move(state, &state->proc->output);
	}
	talloc_steal(state, state->proc);

	tevent_req_done(req);
}

static void run_proc_kill(struct tevent_req *req)
{
	struct run_proc_state *state = tevent_req_data(
		req, struct run_proc_state);

	state->proc->req = NULL;

	state->result.sig = SIGKILL;

	tevent_req_done(req);
}

static void run_proc_timedout(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct run_proc_state *state = tevent_req_data(
		req, struct run_proc_state);
	bool status;

	state->proc->req = NULL;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, EIO);
		return;
	}

	state->result.err = ETIMEDOUT;
	if (state->proc->output != NULL) {
		state->output = talloc_move(state, &state->proc->output);
	}
	state->pid = state->proc->pid;

	tevent_req_done(req);
}

bool run_proc_recv(struct tevent_req *req, int *perr,
		   struct run_proc_result *result, pid_t *pid,
		   TALLOC_CTX *mem_ctx, char **output)
{
	struct run_proc_state *state = tevent_req_data(
		req, struct run_proc_state);
	int ret;

	if (tevent_req_is_unix_error(req, &ret)) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	if (result != NULL) {
		*result = state->result;
	}

	if (pid != NULL) {
		*pid = state->pid;
	}

	if (output != NULL) {
		*output = talloc_move(mem_ctx, &state->output);
	}

	return true;
}
