/* 
   Unix SMB/CIFS implementation.
   process model: standard (1 process per client connection)
   Copyright (C) Andrew Tridgell 1992-2003
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
static void standard_model_init(struct server_context *server)
{
	signal(SIGCHLD, SIG_IGN);
}

static void standard_model_exit(struct server_context *server, const char *reason)
{
	DEBUG(1,("standard_model_exit: reason[%s]\n",reason));
	talloc_free(server);
	exit(0);
}

/*
  called when a listening socket becomes readable
*/
static void standard_accept_connection(struct event_context *ev, struct fd_event *srv_fde,
				       struct timeval t, uint16_t flags)
{
	NTSTATUS status;
	struct socket_context *sock;
	struct server_stream_socket *stream_socket = srv_fde->private;
	struct server_connection *conn;
	pid_t pid;

	/* accept an incoming connection. */
	status = socket_accept(stream_socket->socket, &sock);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("standard_accept_connection: accept: %s\n",
			 nt_errstr(status)));
		return;
	}

	pid = fork();

	if (pid != 0) {
		/* parent or error code ... */

		socket_destroy(sock);
		/* go back to the event loop */
		return;
	}

	/* Child code ... */

	/* close all the listening sockets */
	event_remove_fd_all_handler(ev, server_accept_handler);

	/* we don't care if the dup fails, as its only a select()
	   speed optimisation */
	socket_dup(sock);
			
	/* tdb needs special fork handling */
	if (tdb_reopen_all() == -1) {
		DEBUG(0,("standard_accept_connection: tdb_reopen_all failed.\n"));
	}

	/* Ensure that the forked children do not expose identical random streams */

	set_need_random_reseed();

	conn = server_setup_connection(ev, stream_socket, sock, t, getpid());
	if (!conn) {
		DEBUG(0,("server_setup_connection(ev, server_socket, sock, t) failed\n"));
		exit(1);
		return;
	}

	talloc_steal(conn, sock);

	/* return to the event loop */
}


/* called when a SMB connection goes down */
static void standard_terminate_connection(struct server_connection *conn, const char *reason) 
{
	DEBUG(2,("standard_terminate_connection: reason[%s]\n",reason));

	if (conn) {
		talloc_free(conn->stream_socket->service->server);
	}

	/* this init_iconv() has the effect of freeing the iconv context memory,
	   which makes leak checking easier */
	init_iconv();

	/* the secrets db should really hang off the connection structure */
	secrets_shutdown();

	/* terminate this process */
	exit(0);
}

/*
  called to create a new event context for a new task
*/
static void standard_create_task(struct server_task *task)
{
	pid_t pid;

	pid = fork();

	if (pid != 0) {
		/* parent or error code ... */
		talloc_free(task);
		/* go back to the event loop */
		return;
	}

	/* Child code ... */

	/* close all the listening sockets */
	event_remove_fd_all_handler(task->service->server->event.ctx, server_accept_handler);

	/* tdb needs special fork handling */
	if (tdb_reopen_all() == -1) {
		DEBUG(0,("standard_accept_connection: tdb_reopen_all failed.\n"));
	}

	/* Ensure that the forked children do not expose identical random streams */

	set_need_random_reseed();

	task->task.id	= (uint32)getpid();
	task->event.ctx	= task->service->server->event.ctx;

	/* setup to receive internal messages on this connection */
	task->messaging.ctx = messaging_init(task, task->task.id, task->event.ctx);
	if (!task->messaging.ctx) {
		server_terminate_task(task, "messaging_init() failed");
		return;
	}

	task->task.ops->task_init(task);

	server_terminate_task(task, "exit");
	return;
}

/*
  called to destroy a new event context for a new task
*/
static void standard_terminate_task(struct server_task *task, const char *reason)
{
	DEBUG(2,("standard_terminate_task: reason[%s]\n",reason));

	talloc_free(task);

	/* this init_iconv() has the effect of freeing the iconv context memory,
	   which makes leak checking easier */
	init_iconv();

	/* the secrets db should really hang off the connection structure */
	secrets_shutdown();

	/* terminate this process */
	exit(0);
}

static const struct model_ops standard_ops = {
	.name			= "standard",

	.model_init		= standard_model_init,
	.model_exit		= standard_model_exit,

	.accept_connection	= standard_accept_connection,
	.terminate_connection	= standard_terminate_connection,

	.create_task		= standard_create_task,
	.terminate_task		= standard_terminate_task
};

/*
  initialise the standard process model, registering ourselves with the process model subsystem
 */
NTSTATUS process_model_standard_init(void)
{
	NTSTATUS ret;

	/* register ourselves with the PROCESS_MODEL subsystem. */
	ret = register_process_model(&standard_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register process_model 'standard'!\n"));
		return ret;
	}

	return ret;
}
