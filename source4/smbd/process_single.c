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


/*
  called when the process model is selected
*/
static void single_start_server(void)
{
	smbd_process_init();
}

/*
  called when a listening socket becomes readable
*/
static void single_accept_connection(struct event_context *ev, struct fd_event *srv_fde, time_t t, uint16_t flags)
{
	NTSTATUS status;
	struct socket_context *sock;
	struct server_socket *server_socket = srv_fde->private;
	struct server_connection *conn;

	/* accept an incoming connection. */
	status = socket_accept(server_socket->socket, &sock);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("accept_connection_single: accept: %s\n",
			 nt_errstr(status)));
		return;
	}

	conn = server_setup_connection(ev, server_socket, sock, t, socket_get_fd(sock));
	if (!conn) {
		DEBUG(0,("server_setup_connection(ev, server_socket, sock, t) failed\n"));
		return;
	}

	talloc_steal(conn, sock);

	DLIST_ADD(server_socket->connection_list,conn);

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

static int single_get_id(struct smbsrv_request *req)
{
	return (int)req->smb_conn->pid;
}

static void single_exit_server(struct server_context *srv_ctx, const char *reason)
{
	DEBUG(1,("single_exit_server: reason[%s]\n",reason));
}

/*
  initialise the single process model, registering ourselves with the process model subsystem
 */
NTSTATUS process_model_single_init(void)
{
	NTSTATUS ret;
	struct model_ops ops;

	ZERO_STRUCT(ops);

	/* fill in our name */
	ops.name = "single";

	/* fill in all the operations */
	ops.model_startup		= single_start_server;
	ops.accept_connection		= single_accept_connection;
	ops.terminate_connection	= single_terminate_connection;
	ops.exit_server			= single_exit_server;
	ops.get_id			= single_get_id;

	/* register ourselves with the PROCESS_MODEL subsystem. */
	ret = register_backend("process_model", &ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register process_model 'single'!\n"));
		return ret;
	}

	return ret;
}
