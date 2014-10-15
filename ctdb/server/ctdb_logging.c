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

#include "includes.h"
#include "../include/ctdb_client.h"
#include "../include/ctdb_private.h"
#include "system/syslog.h"
#include "system/time.h"
#include "system/filesys.h"
#include "lib/util/debug.h"

struct syslog_message {
	uint32_t level;
	uint32_t len;
	char message[1];
};


struct ctdb_syslog_state {
	int syslog_fd;
	int fd[2];
};

static int syslogd_is_started = 0;

/* called when child is finished
 * this is for the syslog daemon, we can not use DEBUG here
 */
static void ctdb_syslog_handler(struct event_context *ev, struct fd_event *fde, 
				      uint16_t flags, void *p)
{
	struct ctdb_syslog_state *state = talloc_get_type(p, struct ctdb_syslog_state);

	int count;
	char str[65536];
	struct syslog_message *msg;

	if (state == NULL) {
		return;
	}

	count = recv(state->syslog_fd, str, sizeof(str), 0);
	if (count < sizeof(struct syslog_message)) {
		return;
	}
	msg = (struct syslog_message *)str;
	if (msg->len >= (sizeof(str) - offsetof(struct syslog_message, message))) {
		msg->len = (sizeof(str)-1) - offsetof(struct syslog_message, message);
	}
	msg->message[msg->len] = '\0';

	syslog(msg->level, "%s", msg->message);
}


/* called when the pipe from the main daemon has closed
 * this is for the syslog daemon, we can not use DEBUG here
 */
static void ctdb_syslog_terminate_handler(struct event_context *ev, struct fd_event *fde, 
				      uint16_t flags, void *p)
{
	syslog(LOG_ERR, "Shutting down SYSLOG daemon with pid:%d", (int)getpid());
	_exit(0);
}



/*
 * this is for the syslog daemon, we can not use DEBUG here
 */
int start_syslog_daemon(struct ctdb_context *ctdb)
{
	struct sockaddr_in syslog_sin;
	struct ctdb_syslog_state *state;
	struct tevent_fd *fde;
	int startup_fd[2];
	int ret = -1;

	state = talloc(ctdb, struct ctdb_syslog_state);
	CTDB_NO_MEMORY(ctdb, state);

	if (pipe(state->fd) != 0) {
		printf("Failed to create syslog pipe\n");
		talloc_free(state);
		return -1;
	}
	
	if (pipe(startup_fd) != 0) {
		printf("Failed to create syslog startup pipe\n");
		close(state->fd[0]);
		close(state->fd[1]);
		talloc_free(state);
		return -1;
	}
	
	ctdb->syslogd_pid = ctdb_fork(ctdb);
	if (ctdb->syslogd_pid == (pid_t)-1) {
		printf("Failed to create syslog child process\n");
		close(state->fd[0]);
		close(state->fd[1]);
		close(startup_fd[0]);
		close(startup_fd[1]);
		talloc_free(state);
		return -1;
	}

	if (ctdb->syslogd_pid != 0) {
		ssize_t n;
		int dummy;

		DEBUG(DEBUG_ERR,("Starting SYSLOG child process with pid:%d\n", (int)ctdb->syslogd_pid));

		close(state->fd[1]);
		set_close_on_exec(state->fd[0]);

		close(startup_fd[1]);
		n = sys_read(startup_fd[0], &dummy, sizeof(dummy));
		close(startup_fd[0]);
		if (n < sizeof(dummy)) {
			return -1;
		}

		syslogd_is_started = 1;
		return 0;
	}

	debug_extra = talloc_asprintf(NULL, "syslogd:");
	talloc_free(ctdb->ev);
	ctdb->ev = event_context_init(NULL);

	syslog(LOG_ERR, "Starting SYSLOG daemon with pid:%d", (int)getpid());
	ctdb_set_process_name("ctdb_syslogd");

	close(state->fd[0]);
	close(startup_fd[0]);
	set_close_on_exec(state->fd[1]);
	set_close_on_exec(startup_fd[1]);
	fde = event_add_fd(ctdb->ev, state, state->fd[1], EVENT_FD_READ,
		     ctdb_syslog_terminate_handler, state);
	tevent_fd_set_auto_close(fde);

	state->syslog_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (state->syslog_fd == -1) {
		printf("Failed to create syslog socket\n");
		close(startup_fd[1]);
		return ret;
	}

	set_close_on_exec(state->syslog_fd);

	syslog_sin.sin_family = AF_INET;
	syslog_sin.sin_port   = htons(CTDB_PORT);
	syslog_sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);	

	if (bind(state->syslog_fd, (struct sockaddr *)&syslog_sin,
		 sizeof(syslog_sin)) == -1)
	{
		printf("syslog daemon failed to bind to socket. errno:%d(%s)\n", errno, strerror(errno));
		close(startup_fd[1]);
		_exit(10);
	}


	fde = event_add_fd(ctdb->ev, state, state->syslog_fd, EVENT_FD_READ,
		     ctdb_syslog_handler, state);
	tevent_fd_set_auto_close(fde);

	/* Tell parent that we're up */
	ret = 0;
	sys_write(startup_fd[1], &ret, sizeof(ret));
	close(startup_fd[1]);

	event_loop_wait(ctdb->ev);

	/* this should not happen */
	_exit(10);
}

struct ctdb_log_state {
	struct ctdb_context *ctdb;
	const char *prefix;
	int fd, pfd;
	char buf[1024];
	uint16_t buf_used;
	bool use_syslog;
	void (*logfn)(const char *, uint16_t, void *);
	void *logfn_private;
};

/* we need this global to keep the DEBUG() syntax */
static struct ctdb_log_state *log_state;

/*
  syslog logging function
 */
static void ctdb_syslog_log(void *private_ptr, int dbglevel, const char *s)
{
	struct syslog_message *msg;
	int level = LOG_DEBUG;
	int len;
	int syslog_fd;
	struct sockaddr_in syslog_sin;

	switch (dbglevel) {
	case DEBUG_EMERG: 
		level = LOG_EMERG; 
		break;
	case DEBUG_ALERT: 
		level = LOG_ALERT; 
		break;
	case DEBUG_CRIT: 
		level = LOG_CRIT; 
		break;
	case DEBUG_ERR: 
		level = LOG_ERR; 
		break;
	case DEBUG_WARNING: 
		level = LOG_WARNING; 
		break;
	case DEBUG_NOTICE: 
		level = LOG_NOTICE;
		break;
	case DEBUG_INFO: 
		level = LOG_INFO;
		break;
	default:
		level = LOG_DEBUG;
		break;		
	}

	len = offsetof(struct syslog_message, message) + strlen(debug_extra) + strlen(s) + 1;
	msg = malloc(len);
	if (msg == NULL) {
		return;
	}
	msg->level = level;
	msg->len   = strlen(debug_extra) + strlen(s);
	strcpy(msg->message, debug_extra);
	strcat(msg->message, s);

	if (syslogd_is_started == 0) {
		syslog(msg->level, "%s", msg->message);
	} else {
		syslog_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (syslog_fd == -1) {
			printf("Failed to create syslog socket\n");
			free(msg);
			return;
		}

		syslog_sin.sin_family = AF_INET;
		syslog_sin.sin_port   = htons(CTDB_PORT);
		syslog_sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

		(void) sendto(syslog_fd, msg, len, 0,
			      (struct sockaddr *)&syslog_sin,
			      sizeof(syslog_sin));
		/* no point in checking here since we cant log an error */

		close(syslog_fd);
	}

	free(msg);
}


/*
  log file logging function
 */
static void ctdb_logfile_log(void *private_ptr, int dbglevel, const char *s)
{
	struct timeval t;
	struct tm *tm;
	char tbuf[100];
	char *s2 = NULL;
	int ret;

	t = timeval_current();
	tm = localtime(&t.tv_sec);

	strftime(tbuf,sizeof(tbuf)-1,"%Y/%m/%d %H:%M:%S", tm);

	ret = asprintf(&s2, "%s.%06u [%s%5u]: %s\n",
		       tbuf, (unsigned)t.tv_usec,
		       debug_extra, (unsigned)getpid(), s);
	if (ret == -1) {
		const char *errstr = "asprintf failed\n";
		sys_write(log_state->fd, errstr, strlen(errstr));
		return;
	}
	if (s2) {
		sys_write(log_state->fd, s2, strlen(s2));
		free(s2);
	}
}

/*
  choose the logfile location
*/
int ctdb_set_logfile(struct ctdb_context *ctdb, const char *logfile, bool use_syslog)
{
	debug_callback_fn callback;
	int ret;

	ctdb->log = talloc_zero(ctdb, struct ctdb_log_state);
	if (ctdb->log == NULL) {
		printf("talloc_zero failed\n");
		abort();
	}

	ctdb->log->ctdb = ctdb;
	log_state = ctdb->log;

	if (use_syslog) {
		callback = ctdb_syslog_log;
		ctdb->log->use_syslog = true;
	} else if (logfile == NULL || strcmp(logfile, "-") == 0) {
		callback = ctdb_logfile_log;
		ctdb->log->fd = 1;
		/* also catch stderr of subcommands to stdout */
		ret = dup2(1, 2);
		if (ret == -1) {
			printf("dup2 failed: %s\n", strerror(errno));
			abort();
		}
	} else {
		callback = ctdb_logfile_log;

		ctdb->log->fd = open(logfile, O_WRONLY|O_APPEND|O_CREAT, 0666);
		if (ctdb->log->fd == -1) {
			printf("Failed to open logfile %s\n", logfile);
			abort();
		}
	}

	debug_set_callback(NULL, callback);

	return 0;
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
static void ctdb_log_handler(struct event_context *ev, struct fd_event *fde, 
			     uint16_t flags, void *private)
{
	struct ctdb_log_state *log = talloc_get_type(private, struct ctdb_log_state);
	char *p;
	int n;

	if (!(flags & EVENT_FD_READ)) {
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

	log->ctdb = ctdb;
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
	fde = tevent_add_fd(ctdb->ev, log, log->pfd, EVENT_FD_READ,
			    ctdb_log_handler, log);
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

	if (ctdb->log->fd == STDOUT_FILENO) {
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

	fde = event_add_fd(ctdb->ev, ctdb->log, p[0],
			   EVENT_FD_READ, ctdb_log_handler, ctdb->log);
	tevent_fd_set_auto_close(fde);

	ctdb->log->pfd = p[0];

	DEBUG(DEBUG_DEBUG, (__location__ " Created PIPE FD:%d for logging\n", p[0]));

	return 0;
}


/*
 * set up a log handler to catch logging from TEVENT
 */
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
		dbgtext(fmt, ap);
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
