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

#include "common/db_hash.h"
#include "common/run_proc.h"

/*
 * Process abstraction
 */

struct proc_context {
	pid_t pid;

	int fd;
	struct tevent_fd *fde;

	char *output;
	struct run_proc_result result;

	struct tevent_req *req;
};

static struct proc_context *proc_new(TALLOC_CTX *mem_ctx)
{
	struct proc_context *proc;

	proc = talloc_zero(mem_ctx, struct proc_context);
	if (proc == NULL) {
		return NULL;
	}

	proc->pid = -1;
	proc->fd = -1;

	return proc;
}

static void proc_read_handler(struct tevent_context *ev,
			      struct tevent_fd *fde, uint16_t flags,
			      void *private_data);

static int proc_start(struct proc_context *proc, struct tevent_context *ev,
		      const char *path, const char **argv)
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
	kill(-proc->pid, SIGKILL);
close:
	TALLOC_FREE(proc->fde);
	proc->fd = -1;
}

/*
 * Processes database
 */

static int proc_db_init(TALLOC_CTX *mem_ctx, struct db_hash_context **result)
{
	struct db_hash_context *pdb = NULL;
	int ret;

	ret = db_hash_init(pdb, "proc_db", 1001, DB_HASH_COMPLEX, &pdb);
	if (ret != 0) {
		return ret;
	}

	*result = pdb;
	return 0;
}

static int proc_db_add(struct db_hash_context *pdb, pid_t pid,
		       struct proc_context *proc)
{
	return db_hash_insert(pdb, (uint8_t *)&pid, sizeof(pid_t),
			      (uint8_t *)&proc, sizeof(struct proc_context *));
}

static int proc_db_remove(struct db_hash_context *pdb, pid_t pid)
{
	return db_hash_delete(pdb, (uint8_t *)&pid, sizeof(pid_t));
}

static int proc_db_fetch_parser(uint8_t *keybuf, size_t keylen,
				uint8_t *databuf, size_t datalen,
				void *private_data)
{
	struct proc_context **result = (struct proc_context **)private_data;

	if (datalen != sizeof(struct proc_context *)) {
		return EINVAL;
	}

	*result = *(struct proc_context **)databuf;
	return 0;
}

static int proc_db_fetch(struct db_hash_context *pdb, pid_t pid,
			 struct proc_context **result)
{
	return db_hash_fetch(pdb, (uint8_t *)&pid, sizeof(pid_t),
			     proc_db_fetch_parser, result);
}

static int proc_db_killall_parser(uint8_t *keybuf, size_t keylen,
				  uint8_t *databuf, size_t datalen,
				  void *private_data)
{
	struct db_hash_context *pdb = talloc_get_type_abort(
		private_data, struct db_hash_context);
	struct proc_context *proc;
	pid_t pid;

	if (keylen != sizeof(pid_t) ||
	    datalen != sizeof(struct proc_context *)) {
		/* skip */
		return 0;
	}

	pid = *(pid_t *)keybuf;
	proc = talloc_steal(pdb, *(struct proc_context **)databuf);

	TALLOC_FREE(proc->req);
	TALLOC_FREE(proc->fde);

	kill(-pid, SIGKILL);
	return 0;
}

static void proc_db_killall(struct db_hash_context *pdb)
{
	(void) db_hash_traverse(pdb, proc_db_killall_parser, pdb, NULL);
}


/*
 * Run proc abstraction
 */

struct run_proc_context {
	struct tevent_context *ev;
	struct tevent_signal *se;
	struct db_hash_context *pdb;
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
	int ret;

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

	ret = proc_db_init(run_ctx, &run_ctx->pdb);
	if (ret != 0) {
		talloc_free(run_ctx);
		return ret;
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
	int ret, status;

again:
	pid = waitpid(-1, &status, WNOHANG);
	if (pid == -1) {
		return;
	}

	if (pid == 0) {
		return;
	}

	ret = proc_db_fetch(run_ctx->pdb, pid, &proc);
	if (ret != 0) {
		/* unknown process */
		return;
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

	/* Active run_proc request */
	if (proc->req != NULL) {
		run_proc_done(proc->req);
	}

	proc_db_remove(run_ctx->pdb, pid);
	talloc_free(proc);

	goto again;

}

static int run_proc_context_destructor(struct run_proc_context *run_ctx)
{
	/* Get rid of signal handler */
	TALLOC_FREE(run_ctx->se);

	/* Kill any pending processes */
	proc_db_killall(run_ctx->pdb);
	TALLOC_FREE(run_ctx->pdb);

	return 0;
}

struct run_proc_state {
	struct tevent_context *ev;
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
				 struct timeval timeout)
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

	state->proc = proc_new(run_ctx);
	if (tevent_req_nomem(state->proc, req)) {
		return tevent_req_post(req, ev);
	}

	ret = proc_start(state->proc, ev, path, argv);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	state->proc->req = req;
	talloc_set_destructor(state, run_proc_state_destructor);

	ret = proc_db_add(run_ctx->pdb, state->proc->pid, state->proc);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

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
		if (state->proc->pid != -1) {
			kill(-state->proc->pid, SIGTERM);
		}
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
		state->output = talloc_steal(state, state->proc->output);
	}

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

	state->result.err = ETIME;
	if (state->proc->output != NULL) {
		state->output = talloc_steal(state, state->proc->output);
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
		*output = talloc_steal(mem_ctx, state->output);
	}

	return true;
}
