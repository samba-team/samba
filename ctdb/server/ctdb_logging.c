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
#include "system/syslog.h"
#include "system/time.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/util/dlinklist.h"
#include "lib/util/debug.h"

#include "ctdb_private.h"
#include "ctdb_client.h"

#include "common/system.h"
#include "common/common.h"
#include "common/logging.h"

const char *debug_extra = "";

struct ctdb_log_backend {
	struct ctdb_log_backend *prev, *next;
	const char *prefix;
	ctdb_log_setup_fn_t setup;
};

struct ctdb_log_state {
	const char *prefix;
	int fd, pfd;
	char buf[1024];
	uint16_t buf_used;
	void (*logfn)(const char *, uint16_t, void *);
	void *logfn_private;
	struct ctdb_log_backend *backends;
};

/* Used by ctdb_set_child_logging() */
static struct ctdb_log_state *log_state;

void ctdb_log_register_backend(const char *prefix, ctdb_log_setup_fn_t setup)
{
	struct ctdb_log_backend *b;

	b = talloc_zero(log_state, struct ctdb_log_backend);
	if (b == NULL) {
		printf("Failed to register backend \"%s\" - no memory\n",
		       prefix);
		return;
	}

	b->prefix = prefix;
	b->setup = setup;

	DLIST_ADD_END(log_state->backends, b);
}


/* Initialise logging */
bool ctdb_logging_init(TALLOC_CTX *mem_ctx, const char *logging)
{
	struct ctdb_log_backend *b;
	int ret;

	log_state = talloc_zero(mem_ctx, struct ctdb_log_state);
	if (log_state == NULL) {
		printf("talloc_zero failed\n");
		abort();
	}

	ctdb_log_init_file();
	ctdb_log_init_syslog();

	for (b = log_state->backends; b != NULL; b = b->next) {
		size_t l = strlen(b->prefix);
		/* Exact match with prefix or prefix followed by ':' */
		if (strncmp(b->prefix, logging, l) == 0 &&
		    (logging[l] == '\0' || logging[l] == ':')) {
			ret = b->setup(mem_ctx, logging, "ctdbd");
			if (ret == 0) {
				return true;
			}
			printf("Log init for \"%s\" failed with \"%s\"\n",
			       logging, strerror(ret));
			return false;
		}
	}

	printf("Unable to find log backend for \"%s\"\n", logging);
	return false;
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

static int log_context_destructor(struct ctdb_log_state *log)
{
	/* Flush buffer in case it wasn't \n-terminated. */
	if (log->buf_used > 0) {
		write_to_log(log, log->buf, log->buf_used);
	}
	return 0;
}

/*
 * vfork + exec, redirecting child output to logging and specified callback.
 */
struct ctdb_log_state *ctdb_vfork_with_logging(TALLOC_CTX *mem_ctx,
					       struct ctdb_context *ctdb,
					       const char *log_prefix,
					       const char *helper,
					       int helper_argc,
					       const char **helper_argv,
					       void (*logfn)(const char *, uint16_t, void *),
					       void *logfn_private, pid_t *pid)
{
	int p[2];
	struct ctdb_log_state *log;
	struct tevent_fd *fde;
	char **argv;
	int i;

	log = talloc_zero(mem_ctx, struct ctdb_log_state);
	CTDB_NO_MEMORY_NULL(ctdb, log);

	log->prefix = log_prefix;
	log->logfn = logfn;
	log->logfn_private = logfn_private;

	if (pipe(p) != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Failed to setup pipe for child logging\n"));
		goto free_log;
	}

	argv = talloc_array(mem_ctx, char *, helper_argc + 2);
	if (argv == NULL) {
		DEBUG(DEBUG_ERR, (__location__ "Failed to allocate memory for helper\n"));
		goto free_log;
	}
	argv[0] = discard_const(helper);
	argv[1] = talloc_asprintf(argv, "%d", p[1]);
	if (argv[1] == NULL) {
		DEBUG(DEBUG_ERR, (__location__ "Failed to allocate memory for helper\n"));
		talloc_free(argv);
		goto free_log;
	}

	for (i=0; i<helper_argc; i++) {
		argv[i+2] = discard_const(helper_argv[i]);
	}

	*pid = vfork();
	if (*pid == 0) {
		execv(helper, argv);
		_exit(1);
	}
	close(p[1]);

	if (*pid < 0) {
		DEBUG(DEBUG_ERR, (__location__ "vfork failed for helper process\n"));
		close(p[0]);
		goto free_log;
	}

	ctdb_track_child(ctdb, *pid);

	log->pfd = p[0];
	set_close_on_exec(log->pfd);
	talloc_set_destructor(log, log_context_destructor);
	fde = tevent_add_fd(ctdb->ev, log, log->pfd, TEVENT_FD_READ,
			    ctdb_child_log_handler, log);
	tevent_fd_set_auto_close(fde);

	return log;

free_log:
	talloc_free(log);
	return NULL;
}


/*
  setup for logging of child process stdout
*/
int ctdb_set_child_logging(struct ctdb_context *ctdb)
{
	int p[2];
	int old_stdout, old_stderr;
	struct tevent_fd *fde;

	if (log_state->fd == STDOUT_FILENO) {
		/* not needed for stdout logging */
		return 0;
	}

	/* setup a pipe to catch IO from subprocesses */
	if (pipe(p) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to setup for child logging pipe\n"));
		return -1;
	}

	/* We'll fail if stderr/stdout not already open; it's simpler. */
	old_stdout = dup(STDOUT_FILENO);
	old_stderr = dup(STDERR_FILENO);
	if (old_stdout < 0 || old_stderr < 0) {
		DEBUG(DEBUG_ERR, ("Failed to dup stdout/stderr for child logging\n"));
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


/*
 * set up a log handler to catch logging from TEVENT
 */
static void ctdb_tevent_logging(void *private_data,
				enum tevent_debug_level level,
				const char *fmt,
				va_list ap) PRINTF_ATTRIBUTE(3, 0);
static void ctdb_tevent_logging(void *private_data,
				enum tevent_debug_level level,
				const char *fmt,
				va_list ap)
{
	enum debug_level lvl = DEBUG_CRIT;

	switch (level) {
	case TEVENT_DEBUG_FATAL:
		lvl = DEBUG_CRIT;
		break;
	case TEVENT_DEBUG_ERROR:
		lvl = DEBUG_ERR;
		break;
	case TEVENT_DEBUG_WARNING:
		lvl = DEBUG_WARNING;
		break;
	case TEVENT_DEBUG_TRACE:
		lvl = DEBUG_DEBUG;
		break;
	}

	if (lvl <= DEBUGLEVEL) {
		dbgtext_va(fmt, ap);
	}
}

int ctdb_init_tevent_logging(struct ctdb_context *ctdb)
{
	int ret;

	ret = tevent_set_debug(ctdb->ev,
			ctdb_tevent_logging,
			ctdb);
	return ret;
}
