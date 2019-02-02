/*
   Unix SMB/CIFS implementation.

   run a child command

   Copyright (C) Andrew Tridgell 2010

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

/*
  this runs a child command with stdout and stderr going to the Samba
  log
 */

#include "includes.h"
#include "system/filesys.h"
#include <tevent.h>
#include "../lib/util/tevent_unix.h"
#include "../lib/util/tfork.h"
#include "../lib/util/sys_rw.h"

struct samba_runcmd_state {
	int stdout_log_level;
	int stderr_log_level;
	struct tevent_fd *fde_stdout;
	struct tevent_fd *fde_stderr;
	struct tevent_fd *fde_status;
	int fd_stdin, fd_stdout, fd_stderr, fd_status;
	char *arg0;
	pid_t pid;
	struct tfork *tfork;
	char buf[1024];
	uint16_t buf_used;
};

static void samba_runcmd_cleanup_fn(struct tevent_req *req,
				    enum tevent_req_state req_state)
{
	struct samba_runcmd_state *state = tevent_req_data(
		req, struct samba_runcmd_state);

	if (state->tfork != NULL) {
		tfork_destroy(&state->tfork);
	}
	state->pid = -1;

	if (state->fd_stdin != -1) {
		close(state->fd_stdin);
		state->fd_stdin = -1;
	}
}

int samba_runcmd_export_stdin(struct tevent_req *req)
{
	struct samba_runcmd_state *state = tevent_req_data(req,
					   struct samba_runcmd_state);
	int ret = state->fd_stdin;

	state->fd_stdin = -1;

	return ret;
}

static void samba_runcmd_io_handler(struct tevent_context *ev,
				    struct tevent_fd *fde,
				    uint16_t flags,
				    void *private_data);

/*
  run a command as a child process, with a timeout.

  any stdout/stderr from the child will appear in the Samba logs with
  the specified log levels
 */
struct tevent_req *samba_runcmd_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct timeval endtime,
				     int stdout_log_level,
				     int stderr_log_level,
				     const char * const *argv0, ...)
{
	struct tevent_req *req;
	struct samba_runcmd_state *state;
	int p1[2], p2[2], p3[2];
	char **argv;
	va_list ap;

	if (argv0 == NULL) {
		return NULL;
	}

	req = tevent_req_create(mem_ctx, &state,
				struct samba_runcmd_state);
	if (req == NULL) {
		return NULL;
	}

	state->stdout_log_level = stdout_log_level;
	state->stderr_log_level = stderr_log_level;
	state->fd_stdin = -1;

	state->arg0 = talloc_strdup(state, argv0[0]);
	if (tevent_req_nomem(state->arg0, req)) {
		return tevent_req_post(req, ev);
	}

	if (pipe(p1) != 0) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}
	if (pipe(p2) != 0) {
		close(p1[0]);
		close(p1[1]);
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}
	if (pipe(p3) != 0) {
		close(p1[0]);
		close(p1[1]);
		close(p2[0]);
		close(p2[1]);
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	state->tfork = tfork_create();
	if (state->tfork == NULL) {
		close(p1[0]);
		close(p1[1]);
		close(p2[0]);
		close(p2[1]);
		close(p3[0]);
		close(p3[1]);
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}
	state->pid = tfork_child_pid(state->tfork);
	if (state->pid != 0) {
		/* the parent */
		close(p1[1]);
		close(p2[1]);
		close(p3[0]);
		state->fd_stdout = p1[0];
		state->fd_stderr = p2[0];
		state->fd_stdin  = p3[1];
		state->fd_status = tfork_event_fd(state->tfork);

		set_blocking(state->fd_stdout, false);
		set_blocking(state->fd_stderr, false);
		set_blocking(state->fd_stdin,  false);
		set_blocking(state->fd_status, false);

		smb_set_close_on_exec(state->fd_stdin);
		smb_set_close_on_exec(state->fd_stdout);
		smb_set_close_on_exec(state->fd_stderr);
		smb_set_close_on_exec(state->fd_status);

		tevent_req_set_cleanup_fn(req, samba_runcmd_cleanup_fn);

		state->fde_stdout = tevent_add_fd(ev, state,
						  state->fd_stdout,
						  TEVENT_FD_READ,
						  samba_runcmd_io_handler,
						  req);
		if (tevent_req_nomem(state->fde_stdout, req)) {
			close(state->fd_stdout);
			close(state->fd_stderr);
			close(state->fd_status);
			return tevent_req_post(req, ev);
		}
		tevent_fd_set_auto_close(state->fde_stdout);

		state->fde_stderr = tevent_add_fd(ev, state,
						  state->fd_stderr,
						  TEVENT_FD_READ,
						  samba_runcmd_io_handler,
						  req);
		if (tevent_req_nomem(state->fde_stdout, req)) {
			close(state->fd_stdout);
			close(state->fd_stderr);
			close(state->fd_status);
			return tevent_req_post(req, ev);
		}
		tevent_fd_set_auto_close(state->fde_stderr);

		state->fde_status = tevent_add_fd(ev, state,
						  state->fd_status,
						  TEVENT_FD_READ,
						  samba_runcmd_io_handler,
						  req);
		if (tevent_req_nomem(state->fde_stdout, req)) {
			close(state->fd_stdout);
			close(state->fd_stderr);
			close(state->fd_status);
			return tevent_req_post(req, ev);
		}
		tevent_fd_set_auto_close(state->fde_status);

		if (!timeval_is_zero(&endtime)) {
			tevent_req_set_endtime(req, ev, endtime);
		}

		return req;
	}

	/* the child */
	close(p1[0]);
	close(p2[0]);
	close(p3[1]);
	close(0);
	close(1);
	close(2);

	/* we want to ensure that all of the network sockets we had
	   open are closed */
	tevent_re_initialise(ev);

	/* setup for logging to go to the parents debug log */
	dup2(p3[0], 0);
	dup2(p1[1], 1);
	dup2(p2[1], 2);

	close(p1[1]);
	close(p2[1]);
	close(p3[0]);

	argv = str_list_copy(state, discard_const_p(const char *, argv0));
	if (!argv) {
		fprintf(stderr, "Out of memory in child\n");
		_exit(255);
	}

	va_start(ap, argv0);
	while (1) {
		const char **l;
		char *arg = va_arg(ap, char *);
		if (arg == NULL) break;
		l = discard_const_p(const char *, argv);
		l = str_list_add(l, arg);
		if (l == NULL) {
			fprintf(stderr, "Out of memory in child\n");
			_exit(255);
		}
		argv = discard_const_p(char *, l);
	}
	va_end(ap);

	(void)execvp(state->arg0, argv);
	fprintf(stderr, "Failed to exec child - %s\n", strerror(errno));
	_exit(255);
	return NULL;
}

/*
  handle stdout/stderr from the child
 */
static void samba_runcmd_io_handler(struct tevent_context *ev,
				    struct tevent_fd *fde,
				    uint16_t flags,
				    void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(private_data,
				 struct tevent_req);
	struct samba_runcmd_state *state = tevent_req_data(req,
					   struct samba_runcmd_state);
	int level;
	char *p;
	int n, fd;

	if (!(flags & TEVENT_FD_READ)) {
		return;
	}

	if (fde == state->fde_stdout) {
		level = state->stdout_log_level;
		fd = state->fd_stdout;
	} else if (fde == state->fde_stderr) {
		level = state->stderr_log_level;
		fd = state->fd_stderr;
	} else {
		int status;

		status = tfork_status(&state->tfork, false);
		if (status == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return;
			}
			DBG_ERR("Bad read on status pipe\n");
			tevent_req_error(req, errno);
			return;
		}
		state->pid = -1;
		TALLOC_FREE(fde);

		if (WIFEXITED(status)) {
			status = WEXITSTATUS(status);
		} else if (WIFSIGNALED(status)) {
			status = WTERMSIG(status);
		} else {
			status = ECHILD;
		}

		DBG_NOTICE("Child %s exited %d\n", state->arg0, status);
		if (status != 0) {
			tevent_req_error(req, status);
			return;
		}

		tevent_req_done(req);
		return;
	}

	n = read(fd, &state->buf[state->buf_used],
		 sizeof(state->buf) - state->buf_used);
	if (n > 0) {
		state->buf_used += n;
	} else if (n == 0) {
		if (fde == state->fde_stdout) {
			talloc_free(fde);
			state->fde_stdout = NULL;
			return;
		}
		if (fde == state->fde_stderr) {
			talloc_free(fde);
			state->fde_stderr = NULL;
			return;
		}
		return;
	}

	while (state->buf_used > 0 &&
	       (p = (char *)memchr(state->buf, '\n', state->buf_used)) != NULL) {
		int n1 = (p - state->buf)+1;
		int n2 = n1 - 1;
		/* swallow \r from child processes */
		if (n2 > 0 && state->buf[n2-1] == '\r') {
			n2--;
		}
		DEBUG(level,("%s: %*.*s\n", state->arg0, n2, n2, state->buf));
		memmove(state->buf, p+1, sizeof(state->buf) - n1);
		state->buf_used -= n1;
	}

	/* the buffer could have completely filled - unfortunately we have
	   no choice but to dump it out straight away */
	if (state->buf_used == sizeof(state->buf)) {
		DEBUG(level,("%s: %*.*s\n",
			     state->arg0, state->buf_used,
			     state->buf_used, state->buf));
		state->buf_used = 0;
	}
}

int samba_runcmd_recv(struct tevent_req *req, int *perrno)
{
	if (tevent_req_is_unix_error(req, perrno)) {
		tevent_req_received(req);
		return -1;
	}

	tevent_req_received(req);
	return 0;
}
