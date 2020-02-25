/*
   Unix SMB/CIFS implementation.
   Critical Fault handling
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Tim Prouty 2009
   Copyright (C) James Peach 2006

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
#include "system/filesys.h"
#include "system/wait.h"
#include "version.h"

#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif


#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include "debug.h"
#include "lib/util/signal.h" /* Avoid /usr/include/signal.h */
#include "substitute.h"
#include "fault.h"

static struct {
	bool disabled;
	smb_panic_handler_t panic_handler;
} fault_state;


/*******************************************************************
setup variables used for fault handling
********************************************************************/
void fault_configure(smb_panic_handler_t panic_handler)
{
	fault_state.panic_handler = panic_handler;
}


/**
   disable setting up fault handlers
   This is used for the bind9 dlz module, as we
   don't want a Samba module in bind9 to override the bind
   fault handling
**/
_PUBLIC_ void fault_setup_disable(void)
{
	fault_state.disabled = true;
}


/*******************************************************************
report a fault
********************************************************************/
static void fault_report(int sig)
{
	static int counter;
	char signal_string[128];

	if (counter) _exit(1);

	counter++;

	snprintf(signal_string, sizeof(signal_string),
		 "Signal %d: %s", sig, strsignal(sig));
	smb_panic(signal_string);

	/* smb_panic() never returns, so this is really redundant */
	exit(1);
}

/****************************************************************************
catch serious errors
****************************************************************************/
static void sig_fault(int sig)
{
	fault_report(sig);
}

/*******************************************************************
setup our fault handlers
********************************************************************/
void fault_setup(void)
{
	if (fault_state.disabled) {
		return;
	}
#if !defined(HAVE_DISABLE_FAULT_HANDLING)
#ifdef SIGSEGV
	CatchSignal(SIGSEGV, sig_fault);
#endif
#ifdef SIGBUS
	CatchSignal(SIGBUS, sig_fault);
#endif
#ifdef SIGABRT
	CatchSignal(SIGABRT, sig_fault);
#endif
#endif
}

_PUBLIC_ const char *panic_action = NULL;

/*
   default smb_panic() implementation
*/
static void smb_panic_default(const char *why) _NORETURN_;
static void smb_panic_default(const char *why)
{
#if defined(HAVE_PRCTL) && defined(PR_SET_PTRACER)
	/*
	 * Make sure all children can attach a debugger.
	 */
	prctl(PR_SET_PTRACER, getpid(), 0, 0, 0);
#endif

	if (panic_action && *panic_action) {
		char cmdstring[200];
		if (strlcpy(cmdstring, panic_action, sizeof(cmdstring)) < sizeof(cmdstring)) {
			int result;
			char pidstr[20];
			snprintf(pidstr, sizeof(pidstr), "%d", (int) getpid());
			all_string_sub(cmdstring, "%d", pidstr, sizeof(cmdstring));
			DEBUG(0, ("smb_panic(): calling panic action [%s]\n", cmdstring));
			result = system(cmdstring);

			if (result == -1)
				DEBUG(0, ("smb_panic(): fork failed in panic action: %s\n",
					  strerror(errno)));
			else
				DEBUG(0, ("smb_panic(): action returned status %d\n",
					  WEXITSTATUS(result)));
		}
	}

#ifdef SIGABRT
	CatchSignal(SIGABRT, SIG_DFL);
#endif
	abort();
}

_PUBLIC_ void smb_panic_log(const char *why)
{
	DEBUGSEP(0);
	DEBUG(0,("INTERNAL ERROR: %s in pid %lld (%s)\n",
		 why,
		 (unsigned long long)getpid(),
		 SAMBA_VERSION_STRING));
	DEBUG(0,("If you are running a recent Samba version, and "
		 "if you think this problem is not yet fixed in the "
		 "latest versions, please consider reporting this "
		 "bug, see "
		 "https://wiki.samba.org/index.php/Bug_Reporting\n"));
	DEBUGSEP(0);
	DEBUG(0,("PANIC (pid %llu): %s in " SAMBA_VERSION_STRING "\n",
		 (unsigned long long)getpid(), why));

	log_stack_trace();
}

/**
   Something really nasty happened - panic !
**/
_PUBLIC_ void smb_panic(const char *why)
{
	smb_panic_log(why);

	if (fault_state.panic_handler) {
		fault_state.panic_handler(why);
		_exit(1);
	}
	smb_panic_default(why);
}

/*******************************************************************
 Print a backtrace of the stack to the debug log. This function
 DELIBERATELY LEAKS MEMORY. The expectation is that you should
 exit shortly after calling it.
********************************************************************/

/* Buffer size to use when printing backtraces */
#define BACKTRACE_STACK_SIZE 64


#ifdef HAVE_LIBUNWIND_H
#include <libunwind.h>
#endif

#ifdef HAVE_EXECINFO_H
#include <execinfo.h>
#endif

void log_stack_trace(void)
{
#ifdef HAVE_LIBUNWIND
	/* Try to use libunwind before any other technique since on ia64
	 * libunwind correctly walks the stack in more circumstances than
	 * backtrace.
	 */
	unw_cursor_t cursor;
	unw_context_t uc;
	unsigned i = 0;

	char procname[256];
	unw_word_t ip, sp, off;

	procname[sizeof(procname) - 1] = '\0';

	if (unw_getcontext(&uc) != 0) {
		goto libunwind_failed;
	}

	if (unw_init_local(&cursor, &uc) != 0) {
		goto libunwind_failed;
	}

	DEBUG(0, ("BACKTRACE:\n"));

	do {
	    ip = sp = 0;
	    unw_get_reg(&cursor, UNW_REG_IP, &ip);
	    unw_get_reg(&cursor, UNW_REG_SP, &sp);

	    switch (unw_get_proc_name(&cursor,
			procname, sizeof(procname) - 1, &off) ) {
	    case 0:
		    /* Name found. */
	    case -UNW_ENOMEM:
		    /* Name truncated. */
		    DEBUGADD(0, (" #%u %s + %#llx [ip=%#llx] [sp=%#llx]\n",
			    i, procname, (long long)off,
			    (long long)ip, (long long) sp));
		    break;
	    default:
	    /* case -UNW_ENOINFO: */
	    /* case -UNW_EUNSPEC: */
		    /* No symbol name found. */
		    DEBUGADD(0, (" #%u %s [ip=%#llx] [sp=%#llx]\n",
			    i, "<unknown symbol>",
			    (long long)ip, (long long) sp));
	    }
	    ++i;
	} while (unw_step(&cursor) > 0);

	return;

libunwind_failed:
	DEBUG(0, ("unable to produce a stack trace with libunwind\n"));

#elif defined(HAVE_BACKTRACE_SYMBOLS)
	void *backtrace_stack[BACKTRACE_STACK_SIZE];
	size_t backtrace_size;
	char **backtrace_strings;

	/* get the backtrace (stack frames) */
	backtrace_size = backtrace(backtrace_stack,BACKTRACE_STACK_SIZE);
	backtrace_strings = backtrace_symbols(backtrace_stack, backtrace_size);

	DEBUG(0, ("BACKTRACE: %lu stack frames:\n",
		  (unsigned long)backtrace_size));

	if (backtrace_strings) {
		size_t i;

		for (i = 0; i < backtrace_size; i++)
			DEBUGADD(0, (" #%zu %s\n", i, backtrace_strings[i]));

		/* Leak the backtrace_strings, rather than risk what free() might do */
	}

#else
	DEBUG(0, ("unable to produce a stack trace on this platform\n"));
#endif
}
