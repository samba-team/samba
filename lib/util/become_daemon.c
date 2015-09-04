/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 2001-2002
   Copyright (C) Simo Sorce 2001
   Copyright (C) Jim McDonough (jmcd@us.ibm.com)  2003.
   Copyright (C) James J Myers 2003
   
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

#include "includes.h"
#include "system/filesys.h"
#include "system/locale.h"
#if HAVE_LIBSYSTEMD_DAEMON
#include <systemd/sd-daemon.h>
#endif
#include "lib/util/close_low_fd.h"

/*******************************************************************
 Close the low 3 fd's and open dev/null in their place.
********************************************************************/

_PUBLIC_ void close_low_fds(bool stdin_too, bool stdout_too, bool stderr_too)
{

	if (stdin_too) {
		int ret = close_low_fd(0);
		if (ret != 0) {
			DEBUG(0, ("%s: close_low_fd(0) failed: %s\n",
				  __func__, strerror(ret)));
		}
	}
	if (stdout_too) {
		int ret = close_low_fd(1);
		if (ret != 0) {
			DEBUG(0, ("%s: close_low_fd(1) failed: %s\n",
				  __func__, strerror(ret)));
		}
	}
	if (stderr_too) {
		int ret = close_low_fd(2);
		if (ret != 0) {
			DEBUG(0, ("%s: close_low_fd(2) failed: %s\n",
				  __func__, strerror(ret)));
		}
	}
}

/****************************************************************************
 Become a daemon, discarding the controlling terminal.
****************************************************************************/

_PUBLIC_ void become_daemon(bool do_fork, bool no_process_group, bool log_stdout)
{
	pid_t newpid;
	if (do_fork) {
		newpid = fork();
		if (newpid) {
#if HAVE_LIBSYSTEMD_DAEMON
			sd_notifyf(0, "READY=0\nSTATUS=Starting process...\nMAINPID=%lu", (unsigned long) newpid);
#endif /* HAVE_LIBSYSTEMD_DAEMON */
			_exit(0);
		}
	}

	/* detach from the terminal */
#ifdef HAVE_SETSID
	if (!no_process_group) setsid();
#elif defined(TIOCNOTTY)
	if (!no_process_group) {
		int i = open("/dev/tty", O_RDWR, 0);
		if (i != -1) {
			ioctl(i, (int) TIOCNOTTY, (char *)0);
			close(i);
		}
	}
#endif /* HAVE_SETSID */

	/* Close fd's 0,1,2 as appropriate. Needed if started by rsh. */
	/* stdin must be open if we do not fork, for monitoring for
	 * close.  stdout must be open if we are logging there, and we
	 * never close stderr (but debug might dup it onto a log file) */
	close_low_fds(do_fork, !log_stdout, false);
}

_PUBLIC_ void exit_daemon(const char *msg, int error)
{
#ifdef HAVE_LIBSYSTEMD_DAEMON
	if (msg == NULL) {
		msg = strerror(error);
	}

	sd_notifyf(0, "STATUS=daemon failed to start: %s\n"
				  "ERRNO=%i",
				  msg,
				  error);
#endif
	DEBUG(0, ("STATUS=daemon failed to start: %s, error code %d\n", msg, error));
	exit(1);
}

_PUBLIC_ void daemon_ready(const char *name)
{
	if (name == NULL) {
		name = "Samba";
	}
#ifdef HAVE_LIBSYSTEMD_DAEMON
	sd_notifyf(0, "READY=1\nSTATUS=%s: ready to serve connections...", name);
#endif
	DEBUG(0, ("STATUS=daemon '%s' finished starting up and ready to serve "
		  "connections\n", name));
}

_PUBLIC_ void daemon_status(const char *name, const char *msg)
{
	if (name == NULL) {
		name = "Samba";
	}
#ifdef HAVE_LIBSYSTEMD_DAEMON
	sd_notifyf(0, "\nSTATUS=%s: %s", name, msg);
#endif
	DEBUG(0, ("STATUS=daemon '%s' : %s", name, msg));
}
