/* 
   Unix SMB/CIFS implementation.

   SERVER SERVICE code

   Copyright (C) Andrew Tridgell 2003-2005
   Copyright (C) Stefan (metze) Metzmacher	2004
   
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

#ifndef __SERVICE_H__
#define __SERVICE_H__


#include "smbd/service_stream.h"
#include "smbd/service_task.h"

struct process_details {
	unsigned int instances;
};

static const struct process_details initial_process_details = {
	.instances = 0
};

struct service_details {
	/*
	 * Prevent the standard process model from forking a new worker
	 * process when accepting a new connection.  Do this when the service
	 * relies on shared state, or the over-head of forking would be a
	 * significant part of the response time
	 */
	bool inhibit_fork_on_accept;
	/*
	 * Prevent the pre-fork process model from pre-forking any worker
	 * processes. In this mode pre-fork is equivalent to standard with
	 * inhibit_fork_on_accept set.
	 */
	bool inhibit_pre_fork;
	/*
	 * Initialise the server task.
	 */
	NTSTATUS (*task_init) (struct task_server *);
	/*
	 * post fork processing this is called:
	 *   - standard process model
	 *      immediately after the task_init.
	 *
	 *   - single process model
	 *     immediately after the task_init
	 *
	 *   - prefork process model, inhibit_pre_fork = true
	 *     immediately after the task_init
	 *
	 *   - prefork process model, inhibit_pre_fork = false
	 *     after each service worker has forked. It is not run on the
	 *      service master process.
	 *
	 *   The post fork hook is not called in the standard model if a new
	 *   process is forked on a new connection. It is instead called
	 *   immediately after the task_init.
	 */
	void (*post_fork) (struct task_server *, struct process_details *);
};

#include "smbd/service_proto.h"

#endif /* __SERVICE_H__ */
