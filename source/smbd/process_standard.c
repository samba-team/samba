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

/*
  called when the process model is selected
*/
static void standard_model_startup(void)
{
	signal(SIGCHLD, SIG_IGN);
	smbd_process_init();
}

/*
  called when a listening socket becomes readable
*/
static void standard_accept_connection(struct event_context *ev, struct fd_event *srv_fde, time_t t, uint16_t flags)
{
	NTSTATUS status;
	struct socket_context *sock;
	struct server_socket *server_socket = srv_fde->private;
	struct server_connection *conn;
	pid_t pid;

	/* accept an incoming connection. */
	status = socket_accept(server_socket->socket, &sock, 0);
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
	event_remove_fd_all_handler(ev, standard_accept_connection);
			
	/* tdb needs special fork handling */
	if (tdb_reopen_all() == -1) {
		DEBUG(0,("standard_accept_connection: tdb_reopen_all failed.\n"));
	}

	/* Ensure that the forked children do not expose identical random streams */

	set_need_random_reseed();

	conn = server_setup_connection(ev, server_socket, sock, t, getpid());
	if (!conn) {
		DEBUG(0,("server_setup_connection(ev, server_socket, sock, t) failed\n"));
		return;
	}

	talloc_steal(conn, sock);

	DLIST_ADD(server_socket->connection_list,conn);

	/* return to the event loop */
}


/* called when a SMB connection goes down */
static void standard_terminate_connection(struct server_connection *conn, const char *reason) 
{
	DEBUG(2,("standard_terminate_connection: reason[%s]\n",reason));

	if (conn) {
		talloc_free(conn->service->srv_ctx);
	}

	/* this init_iconv() has the effect of freeing the iconv context memory,
	   which makes leak checking easier */
	init_iconv();

	/* the secrets db should really hang off the connection structure */
	secrets_shutdown();

	/* terminate this process */
	exit(0);
}

static int standard_get_id(struct smbsrv_request *req)
{
	return (int)req->smb_conn->pid;
}

static void standard_exit_server(struct server_context *srv_ctx, const char *reason)
{
	DEBUG(1,("standard_exit_server: reason[%s]\n",reason));
}

/*
  initialise the standard process model, registering ourselves with the process model subsystem
 */
NTSTATUS process_model_standard_init(void)
{
	NTSTATUS ret;
	struct model_ops ops;

	ZERO_STRUCT(ops);

	/* fill in our name */
	ops.name = "standard";

	/* fill in all the operations */
	ops.model_startup = standard_model_startup;
	ops.accept_connection = standard_accept_connection;
	ops.terminate_connection = standard_terminate_connection;
	ops.exit_server = standard_exit_server;
	ops.get_id = standard_get_id;

	/* register ourselves with the PROCESS_MODEL subsystem. */
	ret = register_backend("process_model", &ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register process_model 'standard'!\n"));
		return ret;
	}

	return ret;
}
