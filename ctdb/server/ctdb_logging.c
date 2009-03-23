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
#include "lib/events/events.h"
#include "../include/ctdb_private.h"
#include "system/syslog.h"
#include "system/time.h"
#include "system/filesys.h"

struct ctdb_log_state {
	char *logfile;
	int fd, pfd;
	char buf[1024];
	uint16_t buf_used;
	bool use_syslog;
};

/* we need this global to eep the DEBUG() syntax */
static struct ctdb_log_state *log_state;

/*
  syslog logging function
 */
static void ctdb_syslog_log(const char *format, va_list ap)
{
	int level = LOG_DEBUG;
	switch (this_log_level) {
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
	vsyslog(level, format, ap);
}


/*
  log file logging function
 */
static void ctdb_logfile_log(const char *format, va_list ap)
{
	struct timeval t;
	char *s = NULL;
	struct tm *tm;
	char tbuf[100];
	char *s2 = NULL;

	vasprintf(&s, format, ap);

	t = timeval_current();
	tm = localtime(&t.tv_sec);

	strftime(tbuf,sizeof(tbuf)-1,"%Y/%m/%d %H:%M:%S", tm);

	asprintf(&s2, "%s.%06u [%5u]: %s", 
		 tbuf, (unsigned)t.tv_usec, (unsigned)getpid(), s);
	free(s);
	if (s2) {
		write(log_state->fd, s2, strlen(s2));
		free(s2);	
	}
}

/*
  choose the logfile location
*/
int ctdb_set_logfile(struct ctdb_context *ctdb, const char *logfile, bool use_syslog)
{
	ctdb->log = talloc_zero(ctdb, struct ctdb_log_state);

	log_state = ctdb->log;

	if (use_syslog) {
		do_debug_v = ctdb_syslog_log;
		ctdb->log->use_syslog = true;
	} else if (logfile == NULL || strcmp(logfile, "-") == 0) {
		do_debug_v = ctdb_logfile_log;
		ctdb->log->fd = 1;
		/* also catch stderr of subcommands to stdout */
		dup2(1, 2);
	} else {
		do_debug_v = ctdb_logfile_log;
		ctdb->log->logfile = talloc_strdup(ctdb, logfile);

		ctdb->log->fd = open(logfile, O_WRONLY|O_APPEND|O_CREAT, 0666);
		if (ctdb->log->fd == -1) {
			printf("Failed to open logfile %s\n", ctdb->logfile);
			abort();
		}
	}

	return 0;
}



/*
  called when log data comes in from a child process
 */
static void ctdb_log_handler(struct event_context *ev, struct fd_event *fde, 
			     uint16_t flags, void *private)
{
	struct ctdb_context *ctdb = talloc_get_type(private, struct ctdb_context);
	char *p;
	int n;

	if (!(flags & EVENT_FD_READ)) {
		return;
	}
	
	n = read(ctdb->log->pfd, &ctdb->log->buf[ctdb->log->buf_used],
		 sizeof(ctdb->log->buf) - ctdb->log->buf_used);
	if (n > 0) {
		ctdb->log->buf_used += n;
	}

	this_log_level = script_log_level;

	while (ctdb->log->buf_used > 0 &&
	       (p = memchr(ctdb->log->buf, '\n', ctdb->log->buf_used)) != NULL) {
		int n1 = (p - ctdb->log->buf)+1;
		int n2 = n1 - 1;
		/* swallow \r from child processes */
		if (n2 > 0 && ctdb->log->buf[n2-1] == '\r') {
			n2--;
		}
		if (script_log_level <= LogLevel) {
			do_debug("%*.*s\n", n2, n2, ctdb->log->buf);
			/* log it in the eventsystem as well */
			ctdb_log_event_script_output(ctdb, ctdb->log->buf, n2);
		}
		memmove(ctdb->log->buf, p+1, sizeof(ctdb->log->buf) - n1);
		ctdb->log->buf_used -= n1;
	}

	/* the buffer could have completely filled - unfortunately we have
	   no choice but to dump it out straight away */
	if (ctdb->log->buf_used == sizeof(ctdb->log->buf)) {
		if (script_log_level <= LogLevel) {
			do_debug("%*.*s\n", 
				(int)ctdb->log->buf_used, (int)ctdb->log->buf_used, ctdb->log->buf);
			/* log it in the eventsystem as well */
			ctdb_log_event_script_output(ctdb, ctdb->log->buf, ctdb->log->buf_used);
		}
		ctdb->log->buf_used = 0;
	}
}



/*
  setup for logging of child process stdout
*/
int ctdb_set_child_logging(struct ctdb_context *ctdb)
{
	int p[2];

	if (ctdb->log->fd == 1) {
		/* not needed for stdout logging */
		return 0;
	}

	/* setup a pipe to catch IO from subprocesses */
	if (pipe(p) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to setup for child logging pipe\n"));
		return -1;
	}

	event_add_fd(ctdb->ev, ctdb, p[0], EVENT_FD_READ, 
		     ctdb_log_handler, ctdb);
	set_close_on_exec(p[0]);
	ctdb->log->pfd = p[0];

	close(1);
	close(2);
	if (p[1] != 1) {
		dup2(p[1], 1);
		close(p[1]);
	}
	/* also catch stderr of subcommands to the log */
	dup2(1, 2);

	return 0;
}
