/* 
   Unix SMB/CIFS implementation.
   process model: process (1 process handles all client connections)
   Copyright (C) Andrew Tridgell 2003
   Copyright (C) James J Myers 2003 <myersjj@samba.org>
   Copyright (C) Stefan (metze) Metzmacher 2004
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "events.h"
#include "dlinklist.h"
#include "smb_server/smb_server.h"
#include "process_model.h"


/*
  called when the process model is selected
*/
static void single_model_init(struct server_context *server)
{
}

static void single_model_exit(struct server_context *server, const char *reason)
{
	DEBUG(1,("single_exit_server: reason[%s]\n",reason));
	talloc_free(server);
	exit(0);
}

/*
  called when a listening socket becomes readable
*/
static void single_accept_connection(struct event_context *ev, struct fd_event *srv_fde, 
				     struct timeval t, uint16_t flags)
{
	NTSTATUS status;
	struct socket_context *sock;
	struct server_stream_socket *stream_socket = srv_fde->private;
	struct server_connection *conn;

	/* accept an incoming connection. */
	status = socket_accept(stream_socket->socket, &sock);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("accept_connection_single: accept: %s\n",
			 nt_errstr(status)));
		return;
	}

	conn = server_setup_connection(ev, stream_socket, sock, t, socket_get_fd(sock));
	if (!conn) {
		DEBUG(10,("server_setup_connection failed\n"));
		return;
	}

	talloc_steal(conn, sock);

	/* return to event handling */
	return;
}



/* called when a SMB connection goes down */
static void single_terminate_connection(struct server_connection *conn, const char *reason) 
{
	DEBUG(2,("single_terminate_connection: reason[%s]\n",reason));

	if (conn) {
		talloc_free(conn);
	}
}

/*
  called to create a new event context for a new task
*/
static void single_create_task(struct server_task *task)
{
	task->task.id	= (uint32_t)task;
	task->event.ctx	= task->service->server->event.ctx;

	/* setup to receive internal messages on this connection */
	task->messaging.ctx = messaging_init(task, task->task.id, task->event.ctx);
	if (!task->messaging.ctx) {
		server_terminate_task(task, "messaging_init() failed");
		return;
	}

	task->task.ops->task_init(task);
	return;
}

/*
  called to exit from a server_task
*/
static void single_terminate_task(struct server_task *task, const char *reason)
{
	DEBUG(1,("single_exit_server: reason[%s]\n",reason));
	talloc_free(task);
	return;
}

static const struct model_ops single_ops = {
	.name			= "single",

	.model_init		= single_model_init,
	.model_exit		= single_model_exit,

	.accept_connection	= single_accept_connection,
	.terminate_connection	= single_terminate_connection,

	.create_task		= single_create_task,
	.terminate_task		= single_terminate_task
};

/*
  initialise the single process model, registering ourselves with the process model subsystem
 */
NTSTATUS process_model_single_init(void)
{
	NTSTATUS ret;

	/* register ourselves with the PROCESS_MODEL subsystem. */
	ret = register_process_model(&single_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register process_model 'single'!\n"));
		return ret;
	}

	return ret;
}
