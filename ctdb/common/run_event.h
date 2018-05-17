/*
   Run scripts in a directory with specific event arguments

   Copyright (C) Amitay Isaacs  2017

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

#ifndef __CTDB_RUN_EVENT_H__
#define __CTDB_RUN_EVENT_H__

#include <talloc.h>
#include <tevent.h>

#include "common/run_proc.h"

/**
 * @file run_event.h
 *
 * @brief Run scripts in a directory with specific event arguments.
 *
 * This abstraction allows one to execute multiple scripts in a directory
 * (specified by script_dir) with given event and arguments.
 *
 * At one time, only one event can be run.  Multiple run_event calls
 * will cause events to be queued up.  They will be run sequentially.
 *
 * A "monitor" event is special and has special semantics.
 *
 * If a monitor event is running and another event is scheduled, the
 * currently running monitor event is cancelled.
 *
 * If an event (not monitor) is running and monitor event is scheduled,
 * then the monior event will be cancelled immediately.
 */

/**
 * @brief The run process context
 */
struct run_event_context;

struct run_event_script {
	char *name;
	struct timeval begin, end;
	struct run_proc_result result;
	int summary;
	char *output;
};

struct run_event_script_list {
	uint32_t num_scripts;
	struct run_event_script *script;
	int summary;
};


/**
 * @brief Initialize the context for running events
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] script_dir Directory containing script to run
 * @param[in] debug_prog Path of a program to run if a script hangs
 * @param[out] result New run_event context
 * @return 0 on success, errno on error
 */
int run_event_init(TALLOC_CTX *mem_ctx, struct run_proc_context *run_proc_ctx,
		   const char *script_dir, const char *debug_prog,
		   struct run_event_context **result);

/**
 * @brief Get a list of scripts
 *
 * @param[in] run_ctx Run_event context
 * @param[in] mem_ctx Talloc memory context
 * @param[out] output List of valid scripts
 * @return 0 on success, errno on failure
 */
int run_event_list(struct run_event_context *run_ctx,
		   TALLOC_CTX *mem_ctx,
		   struct run_event_script_list **output);

/**
 * @brief Enable a script
 *
 * @param[in] run_ctx Run_event context
 * @param[in] script_name Name of the script to enable
 * @return 0 on success, errno on failure
 */
int run_event_script_enable(struct run_event_context *run_ctx,
			    const char *script_name);

/**
 * @brief Disable a script
 *
 * @param[in] run_ctx Run_event context
 * @param[in] script_name Name of the script to disable
 * @return 0 on success, errno on failure
 */
int run_event_script_disable(struct run_event_context *run_ctx,
			     const char *script_name);

/**
 * @brief Async computation start to run an event
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] run_ctx Run_event context
 * @param[in] event_str The event argument to the script
 * @param[in] arg_str Event arguments to the script
 * @param[in] timeout How long to wait for execution
 * @param[in] continue_on_failure Whether to continue to run events on failure
 * @return new tevent request, or NULL on failure
 *
 * arg_str contains optional arguments for an event.
 */
struct tevent_req *run_event_send(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  struct run_event_context *run_ctx,
				  const char *event_str,
				  const char *arg_str,
				  struct timeval timeout,
				  bool continue_on_failure);

/**
 * @brief Async computation end to run an event
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @param[in] mem_ctx Talloc memory context
 * @param[out] output List of scripts executed and their status
 * @return true on success, false on failure
 */
bool run_event_recv(struct tevent_req *req, int *perr,
		    TALLOC_CTX *mem_ctx,
		    struct run_event_script_list **output);

#endif /* __CTDB_RUN_EVENT_H__ */

