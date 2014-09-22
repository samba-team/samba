/*
   Unix SMB/CIFS implementation.
   Critical Fault handling
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Tim Prouty 2009

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

	if (counter) _exit(1);

	counter++;

	DEBUGSEP(0);
	DEBUG(0,("INTERNAL ERROR: Signal %d in pid %d (%s)",sig,(int)getpid(),SAMBA_VERSION_STRING));
	DEBUG(0,("\nPlease read the Trouble-Shooting section of the Samba HOWTO\n"));
	DEBUGSEP(0);

	smb_panic("internal error");

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
	DEBUG(0,("PANIC: %s\n", why));

#ifdef SIGABRT
	CatchSignal(SIGABRT, SIG_DFL);
#endif
	abort();
}


/**
   Something really nasty happened - panic !
**/
_PUBLIC_ void smb_panic(const char *why)
{
	if (fault_state.panic_handler) {
		fault_state.panic_handler(why);
		_exit(1);
	}
	smb_panic_default(why);
}
