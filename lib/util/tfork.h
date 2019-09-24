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

struct tfork;

/**
 * @brief a fork() that avoids SIGCHLD and waitpid
 *
 * This function is a solution to the problem of fork() requiring special
 * preparations in the caller to handle SIGCHLD signals and to reap the child by
 * wait()ing for it.
 *
 * The advantage over fork() is that the child process termination is signalled
 * to the caller by making a pipe fd readable returned by tfork_event_fd(), in
 * which case the exit status of the child can be fetched with tfork_status()
 * without blocking.
 *
 * The child process will start with SIGCHLD handler set to SIG_DFL.
 *
 * @return                On success, a struct tfork. NULL on failure.
 *                        Use tfork_worker_pid() to get the pid of the created
 *                        child and tfork_event_fd() to get the file descriptor
 *                        that can be used to poll for process termination and
 *                        reading the child process exit status.
 *
 * @note There's one thing this thing can't protect us against and that is if a
 * process installs a SIGCHLD handler from one thread while another thread is
 * running inside tfork_create() or tfork_status() and the signal handler
 * doesn't forward signals for exitted childs it didn't fork, ie our childs.
 **/
struct tfork *tfork_create(void);

/**
 * @brief Return the child pid from tfork_create()
 *
 * @param[in]   t    Pointer to struct tfork returned by tfork_create()
 *
 * @return           In the caller this returns the pid of the child,
 *                   in the child this returns 0.
 **/
pid_t tfork_child_pid(const struct tfork *t);

/**
 * @brief Return an event fd that signals child termination
 *
 * @param[in]   t    Pointer to struct tfork returned by tfork_create()
 *
 * It is the callers responsibility to ensure that the event fd returned by
 * tfork_event_fd() is closed. By calling tfork_event_fd() ownership of the fd
 * is transferred to the caller, calling tfork_event_fd() again will trigger an
 * abort().
 *
 * @return           An fd that becomes readable when the child created with
 *                   tfork_create() terminates. It is guaranteed that a
 *                   subsequent call to tfork_status() will not block and return
 *                   the exit status of the child.
 **/
int tfork_event_fd(struct tfork *t);

/**
 * @brief Wait for the child to terminate and return its exit status
 *
 * @param[in]   t     Pointer-pointer to a struct tfork returned by
 *                    tfork_create(). Upon successful completion t is freed and
 *                    set to NULL.
 *
 * @param[in]   wait  Whether to wait for the child to change state. If wait is
 *                    false, and the child hasn't changed state, tfork_status()
 *                    will return -1 with errno set to EAGAIN. If wait is true,
 *                    tfork_status() will block waiting for the child to change
 *                    runstate.
 *
 * @return            The exit status of the child, -1 on error.
 *
 * @note We overload the return value a bit, but a process exit status is pretty
 * much guaranteed to be a 16-bit int and can't be -1.
 **/
int tfork_status(struct tfork **_t, bool wait);

/**
 * @brief Terminate the child discarding the exit status
 *
 * @param[in]   t     Pointer-pointer to a struct tfork returned by
 *                    tfork_create(). Upon successful completion t is freed and
 *                    set to NULL.
 *
 * @return            0 on success, -1 on error.
 **/
int tfork_destroy(struct tfork **_t);

#endif /* LIB_UTIL_TFORK_H */
