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
	int accepted_fd;
	struct sockaddr addr;
	socklen_t in_addrlen = sizeof(addr);
	pid_t pid;
	struct fd_event fde;
	struct timed_event idle;
	struct server_socket *server_socket = srv_fde->private;
	struct server_connection *conn;
	TALLOC_CTX *mem_ctx;

	/* accept an incoming connection. */
	accepted_fd = accept(srv_fde->fd,&addr,&in_addrlen);
	if (accepted_fd == -1) {
		DEBUG(0,("standard_accept_connection: accept: %s\n",
			 strerror(errno)));
		return;
	}

	pid = fork();

	if (pid != 0) {
		/* parent or error code ... */

		close(accepted_fd);
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

	mem_ctx = talloc_init("server_service_connection");
	if (!mem_ctx) {
		DEBUG(0,("talloc_init(server_service_connection) failed\n"));
		return;
	}

	conn = talloc_p(mem_ctx, struct server_connection);
	if (!conn) {
		DEBUG(0,("talloc_p(mem_ctx, struct server_service_connection) failed\n"));
		talloc_destroy(mem_ctx);
		return;
	}

	ZERO_STRUCTP(conn);
	conn->mem_ctx = mem_ctx;

	fde.private 	= conn;
	fde.fd		= accepted_fd;
	fde.flags	= EVENT_FD_READ;
	fde.handler	= server_io_handler;

	idle.private 	= conn;
	idle.next_event	= t + 300;
	idle.handler	= server_idle_handler;
	

	conn->event.ctx		= ev;
	conn->event.fde		= &fde;
	conn->event.idle	= &idle;
	conn->event.idle_time	= 300;

	conn->server_socket	= server_socket;
	conn->service		= server_socket->service;

	/* TODO: we need a generic socket subsystem */
	conn->socket		= talloc_p(conn->mem_ctx, struct socket_context);
	if (!conn->socket) {
		DEBUG(0,("talloc_p(conn->mem_ctx, struct socket_context) failed\n"));
		talloc_destroy(mem_ctx);
		return;
	}
	conn->socket->private_data	= NULL;
	conn->socket->ops		= NULL;
	conn->socket->client_addr	= NULL;
	conn->socket->pkt_count		= 0;
	conn->socket->fde		= conn->event.fde;

	/* create a smb server context and add it to out event
	   handling */
	server_socket->service->ops->accept_connection(conn);

	/* accpect_connection() of the service may changed idle.next_event */
	conn->event.fde		= event_add_fd(ev,&fde);
	conn->event.idle	= event_add_timed(ev,&idle);

	conn->socket->fde	= conn->event.fde;

	DLIST_ADD(server_socket->connection_list,conn);

	/* return to the event loop */
}


/* called when a SMB connection goes down */
static void standard_terminate_connection(struct server_connection *conn, const char *reason) 
{
	DEBUG(0,("single_terminate_connection: reason[%s]\n",reason));
	conn->service->ops->close_connection(conn,reason);
	close(conn->event.fde->fd);
	event_remove_fd(conn->event.ctx, conn->event.fde);
	event_remove_timed(conn->event.ctx, conn->event.idle);
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
