/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Jeremy Allison 2012.

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

#ifndef _SAMBA_PIDFILE_H_
#define _SAMBA_PIDFILE_H_

/**
 * @file pidfile.h
 *
 * @brief PID file handling
 */

/**
 * @brief Create a PID file
 *
 * Opens file, locks it, and writes PID.  Returns EACCES or EAGAIN if
 * another process has the PID file locked.  Use unlink(2) and
 * pidfile_fd_close() to remove the PID file.
 *
 * @param[in] path PID file name
 * @param[out] outfd File descriptor of open/locked PID file
 * @return 0 on success, errno on failure
 */
int pidfile_path_create(const char *path, int *outfd);

/**
 * @brief Unlock and close a PID file
 *
 * @param[in] fd File descriptor of open/locked PID file
 */
void pidfile_fd_close(int fd);

/**
 * @brief Check a PID file
 *
 * PID file name is <piddir>/<name>.pid
 *
 * @param[in] piddir Directory for PID file
 * @param[in] name PID file process name
 * @return PID of active process, 0 if PID file missing/stale/error
 */
pid_t pidfile_pid(const char *piddir, const char *name);

/**
 * @brief Create a PID file
 *
 * Leave PID file open/locked on success, exit on failure.  On
 * success, use pidfile_unlink() to remove PID file before exiting.
 *
 * PID file name is <piddir>/<name>.pid
 *
 * @param[in] piddir Directory for PID file
 * @param[in] name PID file process name
 */
void pidfile_create(const char *piddir, const char *name);

/**
 * @brief Remove a PID file
 *
 * PID file name is <piddir>/<name>.pid
 *
 * @param[in] piddir Directory for PID file
 * @param[in] name PID file process name
 */
void pidfile_unlink(const char *piddir, const char *name);

#endif
