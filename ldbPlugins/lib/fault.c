/* 
   Unix SMB/CIFS implementation.
   Critical Fault handling
   Copyright (C) Andrew Tridgell 1992-1998
   
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
#include "system/wait.h"

static void (*cont_fn)(void *);

/* the registered fault handler */
static struct {
	const char *name;
	void (*fault_handler)(int sig);
} fault_handlers;


#ifdef HAVE_BACKTRACE
#include <execinfo.h>
#define BACKTRACE_STACK_SIZE 64
#elif HAVE_LIBEXC_H
#include <libexc.h>
#endif

void call_backtrace(void)
{
#ifdef HAVE_BACKTRACE
#define BACKTRACE_STACK_SIZE 64
	void *backtrace_stack[BACKTRACE_STACK_SIZE];
	size_t backtrace_size;
	char **backtrace_strings;

	/* get the backtrace (stack frames) */
	backtrace_size = backtrace(backtrace_stack,BACKTRACE_STACK_SIZE);
	backtrace_strings = backtrace_symbols(backtrace_stack, backtrace_size);

	DEBUG(0, ("BACKTRACE: %lu stack frames:\n", 
		  (unsigned long)backtrace_size));
	
	if (backtrace_strings) {
		int i;

		for (i = 0; i < backtrace_size; i++)
			DEBUGADD(0, (" #%u %s\n", i, backtrace_strings[i]));

		/* Leak the backtrace_strings, rather than risk what free() might do */
	}

#elif HAVE_LIBEXC

#define NAMESIZE 32 /* Arbitrary */

	/* The IRIX libexc library provides an API for unwinding the stack. See
	 * libexc(3) for details. Apparantly trace_back_stack leaks memory, but
	 * since we are about to abort anyway, it hardly matters.
	 *
	 * Note that if we paniced due to a SIGSEGV or SIGBUS (or similar) this
	 * will fail with a nasty message upon failing to open the /proc entry.
	 */
	{
		uint64_t	addrs[BACKTRACE_STACK_SIZE];
		char *      	names[BACKTRACE_STACK_SIZE];
		char		namebuf[BACKTRACE_STACK_SIZE * NAMESIZE];

		int		i;
		int		levels;

		ZERO_ARRAY(addrs);
		ZERO_ARRAY(names);
		ZERO_ARRAY(namebuf);

		for (i = 0; i < BACKTRACE_STACK_SIZE; i++) {
			names[i] = namebuf + (i * NAMESIZE);
		}

		levels = trace_back_stack(0, addrs, names,
				BACKTRACE_STACK_SIZE, NAMESIZE);

		DEBUG(0, ("BACKTRACE: %d stack frames:\n", levels));
		for (i = 0; i < levels; i++) {
			DEBUGADD(0, (" #%d 0x%llx %s\n", i, addrs[i], names[i]));
		}
     }
#undef NAMESIZE
#endif
}

/*******************************************************************
 Something really nasty happened - panic !
********************************************************************/
void smb_panic(const char *why)
{
	const char *cmd = lp_panic_action();
	int result;

	if (cmd && *cmd) {
		DEBUG(0, ("smb_panic(): calling panic action [%s]\n", cmd));
		result = system(cmd);

		if (result == -1)
			DEBUG(0, ("smb_panic(): fork failed in panic action: %s\n",
				  strerror(errno)));
		else
			DEBUG(0, ("smb_panic(): action returned status %d\n",
				  WEXITSTATUS(result)));
	}
	DEBUG(0,("PANIC: %s\n", why));

	call_backtrace();

#ifdef SIGABRT
	CatchSignal(SIGABRT,SIGNAL_CAST SIG_DFL);
#endif
	abort();
}

/*******************************************************************
report a fault
********************************************************************/
static void fault_report(int sig)
{
	static int counter;
	
	if (counter) _exit(1);

	DEBUG(0,("===============================================================\n"));
	DEBUG(0,("INTERNAL ERROR: Signal %d in pid %d (%s)",sig,(int)getpid(),SAMBA_VERSION_STRING));
	DEBUG(0,("\nPlease read the file BUGS.txt in the distribution\n"));
	DEBUG(0,("===============================================================\n"));

	smb_panic("internal error");

	if (cont_fn) {
		cont_fn(NULL);
#ifdef SIGSEGV
		CatchSignal(SIGSEGV,SIGNAL_CAST SIG_DFL);
#endif
#ifdef SIGBUS
		CatchSignal(SIGBUS,SIGNAL_CAST SIG_DFL);
#endif
#ifdef SIGABRT
		CatchSignal(SIGABRT,SIGNAL_CAST SIG_DFL);
#endif
		return; /* this should cause a core dump */
	}
	exit(1);
}

/****************************************************************************
catch serious errors
****************************************************************************/
static void sig_fault(int sig)
{
	if (fault_handlers.fault_handler) {
		/* we have a fault handler, call it. It may not return. */
		fault_handlers.fault_handler(sig);
	}
	/* If it returns or doean't exist, use regular reporter */
	fault_report(sig);
}

/*******************************************************************
setup our fault handlers
********************************************************************/
void fault_setup(void (*fn)(void *))
{
	cont_fn = fn;

#ifdef SIGSEGV
	CatchSignal(SIGSEGV,SIGNAL_CAST sig_fault);
#endif
#ifdef SIGBUS
	CatchSignal(SIGBUS,SIGNAL_CAST sig_fault);
#endif
#ifdef SIGABRT
	CatchSignal(SIGABRT,SIGNAL_CAST sig_fault);
#endif
}

/*
  register a fault handler. 
  Should only be called once in the execution of smbd.
*/
BOOL register_fault_handler(const char *name, void (*fault_handler)(int sig))
{
	if (fault_handlers.name != NULL) {
		/* it's already registered! */
		DEBUG(2,("fault handler '%s' already registered - failed '%s'\n", 
			 fault_handlers.name, name));
		return False;
	}

	fault_handlers.name = name;
	fault_handlers.fault_handler = fault_handler;

	DEBUG(2,("fault handler '%s' registered\n", name));
	return True;
}
