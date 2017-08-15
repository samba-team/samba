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

#ifndef _BECOME_DAEMON_H
#define _BECOME_DAEMON_H

#include <stdbool.h>

/**
 * @file become_daemon.h
 *
 * @brief Utilities for demonising
 */

/**
 * @brief Close the low 3 file descriptors and open /dev/null in their place
 *
 * @param[in] stdin_too Should stdin be closed?
 * @param[in] stdout_too Should stdout be closed?
 * @param[in] stderr_too Should stderr be closed?
**/
void close_low_fds(bool stdin_too, bool stdout_too, bool stderr_too);

/**
 * @brief Become a daemon, optionally discarding the controlling terminal
 *
 * @param[in] do_fork Should the process fork?
 * @param[in] no_session Don't start a new session
 * @param[in] log_stdour Should stdout be closed?
**/
void become_daemon(bool do_fork, bool no_session, bool log_stdout);

/**
 * @brief Exit daemon and log an error message at ERR level
 *
 * Optionally report failure to systemd if systemd integration is
 * enabled.
 *
 * @param[in] msg Message to log, generated from error if NULL
 * @param[in] error Errno of error that occurred
**/
void exit_daemon(const char *msg, int error);

/**
 * @brief Log at ERR level that the daemon is ready to serve connections
 *
 * Optionally report status to systemd if systemd integration is enabled.
 *
 * @param[in] daemon Name of daemon to include it message
**/
void daemon_ready(const char *daemon);

/**
 * @brief Log at ERR level the specified daemon status
 *
 * For example if it is not ready to serve connections and is waiting
 * for some event to happen.
 *
 * Optionally report status to systemd if systemd integration is enabled.
 *
 * @param[in] daemon Name of daemon to include it message
 * @param[in] msg Message to log
**/
void daemon_status(const char *daemon, const char *msg);

#endif /* _BECOME_DAEMON_H */
