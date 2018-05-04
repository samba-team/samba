/*
   Run a child process and collect the output

   Copyright (C) Amitay Isaacs  2016

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

#ifndef __CTDB_RUN_PROC_H__
#define __CTDB_RUN_PROC_H__

#include <talloc.h>
#include <tevent.h>

/**
 * @file run_proc.h
 *
 * @brief Run a process and capture the output
 *
 * This abstraction allows one to execute scripts with argumunts.
 */

/**
 * @brief The run process context
 */
struct run_proc_context;

/**
 * @brief The exit status structure
 *
 * If the process is terminated due to a signal, sig is set.
 * If the process is terminated due to an error, err is set.
 * If the process terminates normally, status is set.
 */
struct run_proc_result {
	int sig;
	int err;
	int status;
};

/**
 * @brief Initialize the context for running processes
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[out] result New run_proc context
 * @return 0 on success, errno on error
 */
int run_proc_init(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		  struct run_proc_context **result);

/**
 * @brief Async computation start to run an executable
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] run_ctx Run_proc context
 * @param[in] prog The path to the executable
 * @param[in] argv Arguments to the executable
 * @param[in] stdin_fd Assign stdin_fd as stdin for the process, -1 if not
 * @param[in] timeout How long to wait for execution
 * @return new tevent request, or NULL on failure
 *
 * argv must include program name as argv[0] and must be null terminated.
 */
struct tevent_req *run_proc_send(TALLOC_CTX *mem_ctx,
				 struct tevent_context *ev,
				 struct run_proc_context *run_ctx,
				 const char *prog, const char **argv,
				 int stdin_fd, struct timeval timeout);

/**
 * @brief Async computation end to run an executable
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @param[out] result The exit status of the executable
 * @param[out] pid The pid of the child process (still running)
 * @param[in] mem_ctx Talloc memory context
 * @param[out] output The output from the executable (stdio + stderr)
 * @return true on success, false on failure
 *
 * The returned pid is -1 if the process has terminated.
 */
bool run_proc_recv(struct tevent_req *req, int *perr,
		   struct run_proc_result *result, pid_t *pid,
		   TALLOC_CTX *mem_ctx, char **output);

#endif /* __CTDB_RUN_PROC_H__ */
