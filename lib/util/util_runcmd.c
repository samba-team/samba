/*
   Unix SMB/CIFS mplementation.

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
#include "lib/tevent/tevent.h"
#include "libcli/composite/composite.h"

struct samba_runcmd {
	int stdout_log_level;
	int stderr_log_level;
	struct tevent_fd *fde_stdout;
	struct tevent_fd *fde_stderr;
	int fd_stdout, fd_stderr;
	char *arg0;
	pid_t pid;
	char buf[1024];
	uint16_t buf_used;
};

/*
  called when a command times out
 */
static void runcmd_timeout(struct tevent_context *ev,
			   struct tevent_timer *te,
			   struct timeval current_time,
			   void *private_data)
{
	struct composite_context *c = talloc_get_type_abort(private_data, struct composite_context);
	struct samba_runcmd *r = talloc_get_type_abort(c->private_data, struct samba_runcmd);
	kill(r->pid, SIGKILL);
	waitpid(r->pid, NULL, 0);
	talloc_free(r->fde_stderr);
	talloc_free(r->fde_stdout);
	composite_error(c, NT_STATUS_IO_TIMEOUT);
}

/*
  handle stdout/stderr from the child
 */
static void runcmd_io_handler(struct tevent_context *ev,
			      struct tevent_fd *fde,
			      uint16_t flags,
			      void *private_data)
{
	struct composite_context *c = talloc_get_type_abort(private_data, struct composite_context);
	struct samba_runcmd *r = talloc_get_type_abort(c->private_data, struct samba_runcmd);
	int level;
	char *p;
	int n, fd;

	if (fde == r->fde_stdout) {
		level = r->stdout_log_level;
		fd = r->fd_stdout;
	} else {
		level = r->stderr_log_level;
		fd = r->fd_stderr;
	}

	if (!(flags & TEVENT_FD_READ)) {
		return;
	}

	n = read(fd, &r->buf[r->buf_used],
		 sizeof(r->buf) - r->buf_used);
	if (n > 0) {
		r->buf_used += n;
	} else if (n == 0) {
		if (fde == r->fde_stdout) {
			talloc_free(fde);
			r->fde_stdout = NULL;
		}
		if (fde == r->fde_stderr) {
			talloc_free(fde);
			r->fde_stderr = NULL;
		}
		if (r->fde_stdout == NULL &&
		    r->fde_stderr == NULL) {
			int status;
			/* the child has closed both stdout and
			 * stderr, assume its dead */
			pid_t pid = waitpid(r->pid, &status, 0);
			if (pid != r->pid) {
				DEBUG(0,("Error in waitpid() for child %s\n", r->arg0));
				composite_error(c, map_nt_error_from_unix(errno));
				return;
			}
			status = WEXITSTATUS(status);
			DEBUG(3,("Child %s exited with status %d\n", r->arg0, status));
			if (status == 0) {
				composite_done(c);
			} else {
				composite_error(c, map_nt_error_from_unix(status));
			}
			return;
		}
		return;
	}

	while (r->buf_used > 0 &&
	       (p = memchr(r->buf, '\n', r->buf_used)) != NULL) {
		int n1 = (p - r->buf)+1;
		int n2 = n1 - 1;
		/* swallow \r from child processes */
		if (n2 > 0 && r->buf[n2-1] == '\r') {
			n2--;
		}
		DEBUG(level,("%s: %*.*s\n", r->arg0, n2, n2, r->buf));
		memmove(r->buf, p+1, sizeof(r->buf) - n1);
		r->buf_used -= n1;
	}

	/* the buffer could have completely filled - unfortunately we have
	   no choice but to dump it out straight away */
	if (r->buf_used == sizeof(r->buf)) {
		DEBUG(level,("%s: %*.*s\n", r->arg0, r->buf_used, r->buf_used, r->buf));
		r->buf_used = 0;
	}
}


/*
  run a command as a child process, with a timeout.

  any stdout/stderr from the child will appear in the Samba logs with
  the specified log levels
 */
struct composite_context *samba_runcmd(struct tevent_context *ev,
				       TALLOC_CTX *mem_ctx,
				       struct timeval timeout,
				       int stdout_log_level,
				       int stderr_log_level,
				       const char *arg0, ...)
{
	struct samba_runcmd *r;
	int p1[2], p2[2];
	char **argv;
	int ret;
	va_list ap;
	struct composite_context *c;

	c = composite_create(mem_ctx, ev);
	if (c == NULL) return NULL;

	r = talloc_zero(c, struct samba_runcmd);
	if (composite_nomem(r, c)) return c;

	c->private_data = r;

	r->stdout_log_level = stdout_log_level;
	r->stderr_log_level = stderr_log_level;

	r->arg0 = talloc_strdup(r, arg0);
	if (composite_nomem(r->arg0, c)) return c;

	if (pipe(p1) != 0) {
		composite_error(c, map_nt_error_from_unix(errno));
		return c;
	}
	if (pipe(p2) != 0) {
		composite_error(c, map_nt_error_from_unix(errno));
		close(p1[0]);
		close(p1[1]);
		return c;
	}

	r->pid = fork();
	if (r->pid == (pid_t)-1) {
		composite_error(c, map_nt_error_from_unix(errno));
		close(p1[0]);
		close(p1[1]);
		close(p2[0]);
		close(p2[1]);
		return c;
	}

	if (r->pid != 0) {
		/* the parent */
		close(p1[1]);
		close(p2[1]);
		r->fd_stdout = p1[0];
		r->fd_stderr = p2[0];
		set_blocking(r->fd_stdout, false);
		set_blocking(r->fd_stderr, false);
		r->fde_stdout = tevent_add_fd(ev, r, r->fd_stdout, TEVENT_FD_READ, runcmd_io_handler, c);
		tevent_fd_set_auto_close(r->fde_stdout);
		r->fde_stderr = tevent_add_fd(ev, r, r->fd_stderr, TEVENT_FD_READ, runcmd_io_handler, c);
		tevent_fd_set_auto_close(r->fde_stderr);
		if (!timeval_is_zero(&timeout)) {
			tevent_add_timer(ev, r, timeout, runcmd_timeout, c);
		}
		return c;
	}

	/* the child */
	close(p1[0]);
	close(p2[0]);
	close(0);
	close(1);
	close(2);

	/* setup for logging to go to the parents debug log */
	open("/dev/null", O_RDONLY); /* for stdin */
	dup2(p1[1], 1);
	dup2(p2[1], 2);

	argv = str_list_make_single(r, r->arg0);
	if (!argv) {
		fprintf(stderr, "Out of memory in child\n");
		_exit(255);
	}

	va_start(ap, arg0);
	while (1) {
		char *arg = va_arg(ap, char *);
		if (arg == NULL) break;
		argv = discard_const_p(char *, str_list_add((const char **)argv, arg));
		if (!argv) {
			fprintf(stderr, "Out of memory in child\n");
			_exit(255);
		}
	}
	va_end(ap);

	ret = execv(arg0, argv);
	fprintf(stderr, "Failed to exec child - %s\n", strerror(errno));
	_exit(255);
	return NULL;
}
