/*
   ctdb logging code

   Copyright (C) Andrew Tridgell  2008

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
#include "system/time.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/util/dlinklist.h"
#include "lib/util/debug.h"
#include "lib/util/blocking.h"
#include "lib/util/sys_rw.h"
#include "lib/util/time.h"

#include "ctdb_private.h"
#include "ctdb_client.h"

#include "common/common.h"
#include "common/logging.h"

struct ctdb_log_state {
	const char *prefix;
	int fd, pfd;
	char buf[1024];
	uint16_t buf_used;
	void (*logfn)(const char *, uint16_t, void *);
	void *logfn_private;
};

/* Used by ctdb_set_child_logging() */
static struct ctdb_log_state *log_state;

/* Initialise logging */
bool ctdb_logging_init(TALLOC_CTX *mem_ctx, const char *logging,
		       const char *debug_level)
{
	int ret;

	log_state = talloc_zero(mem_ctx, struct ctdb_log_state);
	if (log_state == NULL) {
		return false;
	}

	ret = logging_init(mem_ctx, logging, debug_level, "ctdbd");
	if (ret != 0) {
		return false;
	}

	return true;
}

/* Note that do_debug always uses the global log state. */
static void write_to_log(struct ctdb_log_state *log,
			 const char *buf, unsigned int len)
{
	if (script_log_level <= DEBUGLEVEL) {
		if (log != NULL && log->prefix != NULL) {
			dbgtext("%s: %*.*s\n", log->prefix, len, len, buf);
		} else {
			dbgtext("%*.*s\n", len, len, buf);
		}
		/* log it in the eventsystem as well */
		if (log && log->logfn) {
			log->logfn(log->buf, len, log->logfn_private);
		}
	}
}

/*
  called when log data comes in from a child process
 */
static void ctdb_child_log_handler(struct tevent_context *ev,
				   struct tevent_fd *fde,
				   uint16_t flags, void *private)
{
	struct ctdb_log_state *log = talloc_get_type(private, struct ctdb_log_state);
	char *p;
	int n;

	if (!(flags & TEVENT_FD_READ)) {
		return;
	}

	n = sys_read(log->pfd, &log->buf[log->buf_used],
		 sizeof(log->buf) - log->buf_used);
	if (n > 0) {
		log->buf_used += n;
	} else if (n == 0) {
		if (log != log_state) {
			talloc_free(log);
		}
		return;
	}

	while (log->buf_used > 0 &&
	       (p = memchr(log->buf, '\n', log->buf_used)) != NULL) {
		int n1 = (p - log->buf)+1;
		int n2 = n1 - 1;
		/* swallow \r from child processes */
		if (n2 > 0 && log->buf[n2-1] == '\r') {
			n2--;
		}
		write_to_log(log, log->buf, n2);
		memmove(log->buf, p+1, sizeof(log->buf) - n1);
		log->buf_used -= n1;
	}

	/* the buffer could have completely filled - unfortunately we have
	   no choice but to dump it out straight away */
	if (log->buf_used == sizeof(log->buf)) {
		write_to_log(log, log->buf, log->buf_used);
		log->buf_used = 0;
	}
}

/*
  setup for logging of child process stdout
*/
int ctdb_set_child_logging(struct ctdb_context *ctdb)
{
	int p[2];
	int old_stdout, old_stderr;
	struct tevent_fd *fde;

	/* setup a pipe to catch IO from subprocesses */
	if (pipe(p) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to setup for child logging pipe\n"));
		return -1;
	}

	/* We'll fail if stderr/stdout not already open; it's simpler. */
	old_stdout = dup(STDOUT_FILENO);
	if (old_stdout < 0) {
		DEBUG(DEBUG_ERR, ("Failed to dup stdout for child logging\n"));
		return -1;
	}
	old_stderr = dup(STDERR_FILENO);
	if (old_stderr < 0) {
		DEBUG(DEBUG_ERR, ("Failed to dup stderr for child logging\n"));
		close(old_stdout);
		return -1;
	}
	if (dup2(p[1], STDOUT_FILENO) < 0 || dup2(p[1], STDERR_FILENO) < 0) {
		int saved_errno = errno;
		dup2(old_stdout, STDOUT_FILENO);
		dup2(old_stderr, STDERR_FILENO);
		close(old_stdout);
		close(old_stderr);
		close(p[0]);
		close(p[1]);
		errno = saved_errno;

		printf(__location__ " dup2 failed: %s\n",
			strerror(errno));
		return -1;
	}
	close(p[1]);
	close(old_stdout);
	close(old_stderr);

	fde = tevent_add_fd(ctdb->ev, log_state, p[0], TEVENT_FD_READ,
			    ctdb_child_log_handler, log_state);
	tevent_fd_set_auto_close(fde);

	log_state->pfd = p[0];

	DEBUG(DEBUG_DEBUG, (__location__ " Created PIPE FD:%d for logging\n", p[0]));

	return 0;
}
