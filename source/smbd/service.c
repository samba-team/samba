/* 
   Unix SMB/CIFS implementation.

   SERVER SERVICE code

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Stefan (metze) Metzmacher	2004
   
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

struct server_context *server_service_startup(const char *model)
{
	int i;
	const char **server_services = lp_server_services();
	TALLOC_CTX *mem_ctx;
	struct server_context *srv_ctx;
	const struct model_ops *model_ops;

	if (!server_services) {
		DEBUG(0,("process_model_startup: no endpoint servers configured\n"));
		return NULL;
	}

	model_ops = process_model_startup(model);
	if (!model_ops) {
		DEBUG(0,("process_model_startup('%s') failed\n", model));
		return NULL;
	}

	mem_ctx = talloc_init("server_context");
	if (!mem_ctx) {
		DEBUG(0,("talloc_init(server_context) failed\n"));
		return NULL;
	}

	srv_ctx = talloc_p(mem_ctx, struct server_context);
	if (!srv_ctx) {
		DEBUG(0,("talloc_p(mem_ctx, struct server_context) failed\n"));
		return NULL;	
	}

	ZERO_STRUCTP(srv_ctx);
	srv_ctx->mem_ctx = mem_ctx;

	srv_ctx->events = event_context_init();
	if (!srv_ctx->events) {
		DEBUG(0,("event_context_init() failed\n"));
		return NULL;	
	}


	for (i=0;server_services[i];i++) {
		TALLOC_CTX *mem_ctx2;
		const struct server_service_ops *service_ops;
		struct server_service *service;

		service_ops = server_service_byname(server_services[i]);
		if (!service_ops) {
			DEBUG(0,("process_model_startup: failed to find server service = '%s'\n", server_services[i]));
			return NULL;
		}

		mem_ctx2 = talloc_init("server_service");

		service = talloc_p(mem_ctx2, struct server_service);
		if (!service) {
			DEBUG(0,("talloc_p(mem_ctx, struct server_service) failed\n"));
			return NULL;
		}

		ZERO_STRUCTP(service);
		service->mem_ctx	= mem_ctx2;
		service->ops		= service_ops;
		service->model_ops	= model_ops;
		service->srv_ctx	= srv_ctx;
		
		/* TODO: service_init() should return a result */
		service->ops->service_init(service, model_ops);
	}

	return srv_ctx;
}

/*
  setup a single listener of any type
  if you pass *port == 0, then a port < 1024 is used
 */
struct server_socket *service_setup_socket(struct server_service *service,
			 const struct model_ops *model_ops,
			 struct socket_context *socket_ctx,
 			 struct in_addr *ifip, uint16_t *port)
{
	TALLOC_CTX *mem_ctx;
	struct server_socket *sock;
	struct fd_event fde;
	int i;

	mem_ctx = talloc_init("struct server_socket");

	sock = talloc_p(mem_ctx, struct server_socket);
	if (!sock) {
		DEBUG(0,("talloc_p(mem_ctx, struct server_socket) failed\n"));
		return NULL;	
	}

	if (*port == 0) {
		fde.fd = -1;
		for (i=SERVER_TCP_LOW_PORT;i<= SERVER_TCP_HIGH_PORT;i++) {
			fde.fd = open_socket_in(SOCK_STREAM, i, 0, ifip->s_addr, True);			
			if (fde.fd != -1) break;
		}
		if (fde.fd != -1) {
			*port = i;
		}
	} else {
		fde.fd = open_socket_in(SOCK_STREAM, *port, 0, ifip->s_addr, True);
	}

	if (fde.fd == -1) {
		DEBUG(0,("Failed to open socket on %s:%u - %s\n",
			 inet_ntoa(*ifip), *port, strerror(errno)));
		return NULL;
	}

	/* ready to listen */
	set_socket_options(fde.fd, "SO_KEEPALIVE"); 
	set_socket_options(fde.fd, lp_socket_options());
      
	if (listen(fde.fd, SERVER_LISTEN_BACKLOG) == -1) {
		DEBUG(0,("Failed to listen on %s:%u - %s\n",
			 inet_ntoa(*ifip), *port, strerror(errno)));
		close(fde.fd);
		return NULL;
	}

	/* we are only interested in read events on the listen socket */
	fde.flags = EVENT_FD_READ;
	fde.private = sock;
	fde.handler = model_ops->accept_connection;

	ZERO_STRUCTP(sock);
	sock->mem_ctx	= mem_ctx;
	sock->service	= service;
	sock->socket	= socket_ctx;
	sock->event.ctx = service->srv_ctx->events;
	sock->event.fde = event_add_fd(sock->event.ctx, &fde);
	if (!sock->event.fde) {
		DEBUG(0,("event_add_fd(sock->event.ctx, &fde) failed\n"));
		return NULL;
	}

	DLIST_ADD(service->socket_list, sock);

	return sock;
}

struct server_connection *server_setup_connection(struct event_context *ev, struct server_socket *server_socket, int accepted_fd, time_t t)
{
	struct fd_event fde;
	struct timed_event idle;
	struct server_connection *srv_conn;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("server_service_connection");
	if (!mem_ctx) {
		DEBUG(0,("talloc_init(server_service_connection) failed\n"));
		return NULL;
	}

	srv_conn = talloc_p(mem_ctx, struct server_connection);
	if (!srv_conn) {
		DEBUG(0,("talloc_p(mem_ctx, struct server_service_connection) failed\n"));
		talloc_destroy(mem_ctx);
		return NULL;
	}

	ZERO_STRUCTP(srv_conn);
	srv_conn->mem_ctx = mem_ctx;

	fde.private 	= srv_conn;
	fde.fd		= accepted_fd;
	fde.flags	= EVENT_FD_READ;
	fde.handler	= server_io_handler;

	idle.private 	= srv_conn;
	idle.next_event	= t + SERVER_DEFAULT_IDLE_TIME;
	idle.handler	= server_idle_handler;

	srv_conn->event.ctx		= ev;
	srv_conn->event.fde		= &fde;
	srv_conn->event.idle		= &idle;
	srv_conn->event.idle_time	= SERVER_DEFAULT_IDLE_TIME;

	srv_conn->server_socket		= server_socket;
	srv_conn->service		= server_socket->service;

	/* TODO: we need a generic socket subsystem */
	srv_conn->socket		= NULL;

	/* create a smb server context and add it to out event
	   handling */
	server_socket->service->ops->accept_connection(srv_conn);

	/* accpect_connection() of the service may changed idle.next_event */
	srv_conn->event.fde	= event_add_fd(ev,&fde);
	srv_conn->event.idle	= event_add_timed(ev,&idle);

	return srv_conn;
}

/*
  close the socket and shutdown a server_context
*/
void server_terminate_connection(struct server_connection *srv_conn, const char *reason)
{
	DEBUG(0,("server_terminate_connection\n"));
	srv_conn->service->model_ops->terminate_connection(srv_conn, reason);
}

void server_destroy_connection(struct server_connection *srv_conn)
{
	close(srv_conn->event.fde->fd);

	event_remove_fd(srv_conn->event.ctx, srv_conn->event.fde);
	srv_conn->event.fde = NULL;
	event_remove_timed(srv_conn->event.ctx, srv_conn->event.idle);
	srv_conn->event.idle = NULL;

	talloc_destroy(srv_conn->mem_ctx);
}

void server_io_handler(struct event_context *ev, struct fd_event *fde, time_t t, uint16_t flags)
{
	struct server_connection *conn = fde->private;

	conn->event.idle->next_event = t + conn->event.idle_time;

	if (flags & EVENT_FD_WRITE) {
		conn->service->ops->send_handler(conn, t, flags);
		return;
	}

	if (flags & EVENT_FD_READ) {
		conn->service->ops->recv_handler(conn, t, flags);
	}

}

void server_idle_handler(struct event_context *ev, struct timed_event *idle, time_t t)
{
	struct server_connection *conn = idle->private;

	conn->event.idle->next_event = t + conn->event.idle_time;

	conn->service->ops->idle_handler(conn,t);
}
/*
  return the operations structure for a named backend of the specified type
*/
const struct server_service_ops *server_service_byname(const char *name)
{
	if (strcmp("smb",name)==0) {
		return smbsrv_get_ops();
	}
	if (strcmp("rpc",name)==0) {
		return dcesrv_get_ops();
	}
	if (strcmp("ldap",name)==0) {
		return ldapsrv_get_ops();
	}
	return NULL;
}

static NTSTATUS register_server_service_ops(const void *_ops)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*
  initialise the SERVER SERVICE subsystem
*/
BOOL server_service_init(void)
{
	NTSTATUS status;

	status = register_subsystem("service", register_server_service_ops); 
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	/* FIXME: Perhaps panic if a basic endpoint server, such as EPMAPER, fails to initialise? */
	static_init_server_service;

	DEBUG(3,("SERVER SERVICE subsystem version %d initialised\n", SERVER_SERVICE_VERSION));
	return True;
}
