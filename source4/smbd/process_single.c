/* 
   Unix SMB/CIFS implementation.

   process model: process (1 process handles all client connections)

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) James J Myers 2003 <myersjj@samba.org>
   Copyright (C) Stefan (metze) Metzmacher 2004
   
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
#include "smbd/process_model.h"
#include "system/filesys.h"
#include "cluster/cluster.h"

NTSTATUS process_model_single_init(TALLOC_CTX *);

/*
  called when the process model is selected
*/
static void single_model_init(void)
{
}

/*
  called when a listening socket becomes readable. 
*/
static void single_accept_connection(struct tevent_context *ev, 
				     struct loadparm_context *lp_ctx,
				     struct socket_context *listen_socket,
				     void (*new_conn)(struct tevent_context *, 
						      struct loadparm_context *,
						      struct socket_context *, 
						      struct server_id, void *,
						      void *),
				     void *private_data,
				     void *process_context)
{
	NTSTATUS status;
	struct socket_context *connected_socket;
	pid_t pid = getpid();

	/* accept an incoming connection. */
	status = socket_accept(listen_socket, &connected_socket);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("single_accept_connection: accept: %s\n",
			nt_errstr(status));
		/* this looks strange, but is correct. 

		   We can only be here if woken up from select, due to
		   an incoming connection.

		   We need to throttle things until the system clears
		   enough resources to handle this new socket. 

		   If we don't then we will spin filling the log and
		   causing more problems. We don't panic as this is
		   probably a temporary resource constraint */
		sleep(1);
		return;
	}

	talloc_steal(private_data, connected_socket);

	/*
	 * We use the PID so we cannot collide in with cluster ids
	 * generated in other single mode tasks, and, and won't
	 * collide with PIDs from process model standard because a the
	 * combination of pid/fd should be unique system-wide
	 */
	new_conn(ev, lp_ctx, connected_socket,
		 cluster_id(pid, socket_get_fd(connected_socket)), private_data,
			    process_context);
}

/*
  called to startup a new task
*/
static void single_new_task(struct tevent_context *ev,
			    struct loadparm_context *lp_ctx,
			    const char *service_name,
			    struct task_server *(*new_task)(struct tevent_context *,
				             struct loadparm_context *,
					     struct server_id, void *, void *),
			    void *private_data,
			    const struct service_details *service_details,
			    int from_parent_fd)
{
	pid_t pid = getpid();
	/* start our taskids at MAX_INT32, the first 2^31 tasks are is reserved for fd numbers */
	static uint32_t taskid = INT32_MAX;
	struct task_server *task = NULL;
	/*
	 * We use the PID so we cannot collide in with cluster ids
	 * generated in other single mode tasks, and, and won't
	 * collide with PIDs from process model starndard because a the
	 * combination of pid/task_id should be unique system-wide
	 *
	 * Using the pid unaltered makes debugging of which process
	 * owns the messaging socket easier.
	 */
	task = new_task(ev, lp_ctx, cluster_id(pid, taskid++), private_data, NULL);
	if (task != NULL && service_details->post_fork != NULL) {
		struct process_details pd = initial_process_details;
		service_details->post_fork(task, &pd);
	}
}

/*
 * Called when a task goes down
 */
static void single_terminate_task(struct tevent_context *ev,
				  struct loadparm_context *lp_ctx,
				  const char *reason,
				  bool fatal,
				  void *process_context)
{
	DBG_NOTICE("single_terminate: reason[%s]\n",reason);
}

/*
 * Called when a connection has ended
 */
static void single_terminate_connection(struct tevent_context *ev,
					struct loadparm_context *lp_ctx,
					const char *reason,
					void *process_context)
{
}

/* called to set a title of a task or connection */
static void single_set_title(struct tevent_context *ev, const char *title) 
{
}

const struct model_ops single_ops = {
	.name			= "single",
	.model_init		= single_model_init,
	.new_task		= single_new_task,
	.accept_connection	= single_accept_connection,
	.terminate_task		= single_terminate_task,
	.terminate_connection	= single_terminate_connection,
	.set_title		= single_set_title,
};

/*
  initialise the single process model, registering ourselves with the
  process model subsystem
 */
NTSTATUS process_model_single_init(TALLOC_CTX *ctx)
{
	return register_process_model(&single_ops);
}
