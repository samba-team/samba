/*
   Unix SMB/CIFS implementation.
   Samba debug functions
   Copyright (C) Andrew Tridgell 2003
   Copyright (C) James J Myers	 2003

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

/* this global variable determines what messages are printed */
int DEBUGLEVEL;


/* the registered mutex handlers */
static struct {
	const char *name;
	struct debug_ops ops;
} debug_handlers;

/* state variables for the debug system */
static struct {
	int fd;
	enum debug_logtype logtype;
	const char *prog_name;
} state;

/*
  the backend for debug messages. Note that the DEBUG() macro has already
  ensured that the log level has been met before this is called
*/
void do_debug(const char *format, ...)
{
	va_list ap;
	char *s = NULL;

	if (state.fd == 0) {
		reopen_logs();
	}

	if (state.fd <= 0) return;

	va_start(ap, format);
	vasprintf(&s, format, ap);
	va_end(ap);

	log_task_id();
	
	write(state.fd, s, strlen(s));
	free(s);
}

/*
  reopen the log file (usually called because the log file name might have changed)
*/
void reopen_logs(void)
{
	char *logfile = lp_logfile();
	char *fname = NULL;
	int old_fd = state.fd;

	state.fd = 0;

	switch (state.logtype) {
	case DEBUG_STDOUT:
		state.fd = 1;
		break;

	case DEBUG_STDERR:
		state.fd = 2;
		break;

	case DEBUG_FILE:
		if ((*logfile) == '/') {
			fname = strdup(logfile);
		} else {
			asprintf(&fname, "%s/%s.log", dyn_LOGFILEBASE, logfile);
		}
		if (fname) {
			state.fd = open(fname, O_CREAT|O_APPEND|O_WRONLY, 0644);
			free(fname);
		}
		break;
	}

	if (old_fd > 2) {
		close(old_fd);
	}
}

/*
  control the name of the logfile and whether logging will be to stdout, stderr
  or a file
*/
void setup_logging(const char *prog_name, enum debug_logtype new_logtype)
{
	state.logtype = new_logtype;
	state.prog_name = prog_name;
	reopen_logs();
}

/*
  return a string constant containing n tabs
  no more than 10 tabs are returned
*/
const char *do_debug_tab(uint_t n)
{
	const char *tabs[] = {"", "\t", "\t\t", "\t\t\t", "\t\t\t\t", "\t\t\t\t\t", 
			      "\t\t\t\t\t\t", "\t\t\t\t\t\t\t", "\t\t\t\t\t\t\t\t", 
			      "\t\t\t\t\t\t\t\t\t", "\t\t\t\t\t\t\t\t\t\t"};
	return tabs[MIN(n, 10)];
}


/*
  log/print suspicious usage - print comments and backtrace
*/	
void log_suspicious_usage(const char *from, const char *info)
{
	if (debug_handlers.ops.log_suspicious_usage) {
		debug_handlers.ops.log_suspicious_usage(from, info);
	}
}
void print_suspicious_usage(const char* from, const char* info)
{
	if (debug_handlers.ops.print_suspicious_usage) {
		debug_handlers.ops.print_suspicious_usage(from, info);
	}
}

uint32_t get_task_id(void)
{
	if (debug_handlers.ops.get_task_id) {
		return debug_handlers.ops.get_task_id();
	}
	return getpid();
}

void log_task_id(void)
{
	if (debug_handlers.ops.log_task_id) {
		debug_handlers.ops.log_task_id(state.fd);
	}
}
/*
  register a set of debug handlers. 
*/
void register_debug_handlers(const char *name, struct debug_ops *ops)
{
	debug_handlers.name = name;
	debug_handlers.ops = *ops;
}
