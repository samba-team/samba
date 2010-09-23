/*
   fork on steroids to avoid SIGCHLD and waitpid

   Copyright (C) Stefan Metzmacher 2010
   Copyright (C) Ralph Boehme 2017

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

#ifndef LIB_UTIL_TFORK_H
#define LIB_UTIL_TFORK_H

/**
 * @brief a fork() that avoids SIGCHLD and waitpid
 *
 * This function is a workaround for the problem of using fork() in
 * library code. In that case the library should avoid to set a global
 * signal handler for SIGCHLD, because the application may wants to use its
 * own handler.
 *
 * The child process will start with SIGCHLD handler set to SIG_DFL, so the
 * child might need to setup its own handler.
 *
 * @param[out] status_fd  If this is not NULL, tfork creates a pipe and returns
 *                        the readable end via this pointer. The caller can
 *                        wait for the process to finish by polling the
 *                        status_fd for readability and can then read the exit
 *                        status (an int).
 *
 * @param[out] parent     The PID of the parent process, if 0 is returned
 *                        otherwise the variable will not be touched at all.
 *                        It is possible to pass NULL.
 *
 * @return                On success, the PID of the child process is returned
 *                        in the parent, and 0 is returned in the child. On
 *                        failure, -1 is returned in the parent, no child
 *                        process is created, and errno is set appropriately.
 */
int tfork(int *status_fd, int *parent);

#endif /* LIB_UTIL_TFORK_H */
