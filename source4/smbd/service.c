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
#include "events.h"
#include "system/dir.h"
#include "dlinklist.h"
#include "process_model.h"

struct server_context *server_service_startup(const char *model)
{
	int i;
	const char **server_services = lp_server_services();
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

	srv_ctx = talloc_p(NULL, struct server_context);
	if (!srv_ctx) {
		return NULL;	
	}

	ZERO_STRUCTP(srv_ctx);

	srv_ctx->events = event_context_init(srv_ctx);
	if (!srv_ctx->events) {
		DEBUG(0,("event_context_init() failed\n"));
		return NULL;	
	}


	for (i=0;server_services[i];i++) {
		const struct server_service_ops *service_ops;
		struct server_service *service;

		service_ops = server_service_byname(server_services[i]);
		if (!service_ops) {
			DEBUG(0,("process_model_startup: failed to find server service = '%s'\n", server_services[i]));
			return NULL;
		}

		service = talloc_p(srv_ctx, struct server_service);
		if (!service) {
			return NULL;
		}

		ZERO_STRUCTP(service);
		service->ops		= service_ops;
		service->model_ops	= model_ops;
		service->srv_ctx	= srv_ctx;
		
		/* TODO: service_init() should return a result */
		service->ops->service_init(service, model_ops);

		DLIST_ADD(srv_ctx->service_list, service);
	}

	return srv_ctx;
}

/*
  setup a listen stream socket
  if you pass *port == 0, then a port > 1024 is used
 */
struct server_socket *service_setup_socket(struct server_service *service,
					   const struct model_ops *model_ops,
					   const char *family,
					   const char *sock_addr,
					   uint16_t *port)
{
	NTSTATUS status;
	struct server_socket *srv_sock;
	struct socket_context *socket_ctx;
	struct fd_event fde;
	int i;

	status = socket_create(family, SOCKET_TYPE_STREAM, &socket_ctx, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to open socket on %s:%u - %s\n",
			sock_addr, *port, nt_errstr(status)));
		return NULL;
	}

	talloc_steal(service, socket_ctx);

	/* ready to listen */
	status = socket_set_option(socket_ctx, "SO_KEEPALIVE SO_REUSEADDR=1", NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("socket_set_option(socket_ctx, SO_KEEPALIVE, NULL): %s\n",
			nt_errstr(status)));
		socket_destroy(socket_ctx);
		return NULL;
	}
	status = socket_set_option(socket_ctx, lp_socket_options(), NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("socket_set_option(socket_ctx, lp_socket_options(), NULL): %s\n",
			nt_errstr(status)));
		socket_destroy(socket_ctx);
		return NULL;
	}

	/* TODO: set socket ACL's here when they're implemented */

	if (*port == 0) {
		for (i=SERVER_TCP_LOW_PORT;i<= SERVER_TCP_HIGH_PORT;i++) {
			status = socket_listen(socket_ctx, sock_addr, i, SERVER_LISTEN_BACKLOG, 0);
			if (NT_STATUS_IS_OK(status)) {
				*port = i;
				break;
			}
		}
	} else {
		status = socket_listen(socket_ctx, sock_addr, *port, SERVER_LISTEN_BACKLOG, 0);
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to listen on %s:%u - %s\n",
			sock_addr, *port, nt_errstr(status)));
		socket_destroy(socket_ctx);
		return NULL;
	}

	srv_sock = talloc_p(service, struct server_socket);
	if (!srv_sock) {
		DEBUG(0,("talloc_p(mem_ctx, struct server_socket) failed\n"));
		socket_destroy(socket_ctx);
		return NULL;
	}

	/* we are only interested in read events on the listen socket */
	fde.fd          = socket_get_fd(socket_ctx);
	fde.flags       = EVENT_FD_READ;
	fde.private     = srv_sock;
	fde.handler     = model_ops->accept_connection;

	ZERO_STRUCTP(srv_sock);
	srv_sock->service       = service;
	srv_sock->socket        = socket_ctx;
	srv_sock->event.ctx     = service->srv_ctx->events;
	srv_sock->event.fde     = event_add_fd(srv_sock->event.ctx, &fde);
	if (!srv_sock->event.fde) {
		DEBUG(0,("event_add_fd(srv_sock->event.ctx, &fde) failed\n"));
		socket_destroy(socket_ctx);
		return NULL;
	}

	DLIST_ADD(service->socket_list, srv_sock);

	return srv_sock;
}

/*
  destructor that handles necessary event context changes
 */
static int server_destructor(void *ptr)
{
	struct server_connection *conn = ptr;

	if (conn->service) {
		conn->service->ops->close_connection(conn, "shutdown");
	}

	socket_destroy(conn->socket);

	event_remove_fd(conn->event.ctx, conn->event.fde);
	conn->event.fde = NULL;
	event_remove_timed(conn->event.ctx, conn->event.idle);
	conn->event.idle = NULL;

	DLIST_REMOVE(conn->server_socket->connection_list, conn);

	return 0;
}

struct server_connection *server_setup_connection(struct event_context *ev, 
						  struct server_socket *server_socket, 
						  struct socket_context *sock, 
						  struct timeval t,
						  servid_t server_id)
{
	struct fd_event fde;
	struct timed_event idle;
	struct server_connection *srv_conn;

	srv_conn = talloc_p(server_socket, struct server_connection);
	if (!srv_conn) {
		DEBUG(0,("talloc_p(mem_ctx, struct server_connection) failed\n"));
		return NULL;
	}

	ZERO_STRUCTP(srv_conn);

	fde.private 	= srv_conn;
	fde.fd		= socket_get_fd(sock);
	fde.flags	= EVENT_FD_READ;
	fde.handler	= server_io_handler;

	idle.private 	= srv_conn;
	idle.next_event	= timeval_add(&t, SERVER_DEFAULT_IDLE_TIME, 0);
	idle.handler	= server_idle_handler;

	srv_conn->event.ctx		= ev;
	srv_conn->event.fde		= &fde;
	srv_conn->event.idle		= &idle;
	srv_conn->event.idle_time	= timeval_set(SERVER_DEFAULT_IDLE_TIME, 0);

	srv_conn->server_socket		= server_socket;
	srv_conn->service		= server_socket->service;
	srv_conn->socket		= sock;
	srv_conn->server_id		= server_id;

	/* create a smb server context and add it to out event
	   handling */
	server_socket->service->ops->accept_connection(srv_conn);

	/* accpect_connection() of the service may changed idle.next_event */
	srv_conn->event.fde	= event_add_fd(ev,&fde);
	srv_conn->event.idle	= event_add_timed(ev,&idle);

	talloc_set_destructor(srv_conn, server_destructor);

	if (!socket_check_access(sock, "smbd", lp_hostsallow(-1), lp_hostsdeny(-1))) {
		server_terminate_connection(srv_conn, "denied by access rules");
		return NULL;
	}

	/* setup to receive internal messages on this connection */
	srv_conn->messaging_ctx = messaging_init(srv_conn, srv_conn->server_id, ev);

	return srv_conn;
}

/*
  close the socket and shutdown a server_context
*/
void server_terminate_connection(struct server_connection *srv_conn, const char *reason)
{
	DEBUG(2,("server_terminate_connection\n"));
	srv_conn->service->model_ops->terminate_connection(srv_conn, reason);
}

void server_io_handler(struct event_context *ev, struct fd_event *fde, 
		       struct timeval t, uint16_t flags)
{
	struct server_connection *conn = fde->private;

	conn->event.idle->next_event = timeval_sum(&t,  &conn->event.idle_time);

	if (flags & EVENT_FD_WRITE) {
		conn->service->ops->send_handler(conn, t, flags);
		return;
	}

	if (flags & EVENT_FD_READ) {
		conn->service->ops->recv_handler(conn, t, flags);
	}

}

void server_idle_handler(struct event_context *ev, struct timed_event *idle, 
			 struct timeval t)
{
	struct server_connection *conn = idle->private;

	conn->event.idle->next_event = timeval_sum(&t, &conn->event.idle_time);

	conn->service->ops->idle_handler(conn, t);
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


/*
  close all listening sockets. This is called by process models that fork, to 
  ensure that the listen sockets from the parent are closed
*/
void service_close_listening_sockets(struct server_context *srv_ctx)
{
	struct server_service *svc;
	for (svc=srv_ctx->service_list;svc;svc=svc->next) {
		struct server_socket *sock;
		for (sock=svc->socket_list;sock;sock=sock->next) {
			event_remove_fd(sock->event.ctx, sock->event.fde);
			sock->event.fde = NULL;
			socket_destroy(sock->socket);
			sock->socket = NULL;
		}
	}
}


/*
  cleanup temporary files. This is the new alternative to
  TDB_CLEAR_IF_FIRST. Unfortunately TDB_CLEAR_IF_FIRST is not
  efficient on unix systems due to the lack of scaling of the byte
  range locking system. So instead of putting the burden on tdb to
  cleanup tmp files, this function deletes them. 
*/
void service_cleanup_tmp_files(void)
{
	char *path;
	DIR *dir;
	struct dirent *de;
	TALLOC_CTX *mem_ctx = talloc_init("service_cleanup_tmp_files");

	path = smbd_tmp_path(mem_ctx, NULL);

	dir = opendir(path);
	if (!dir) {
		talloc_free(mem_ctx);
		return;
	}

	for (de=readdir(dir);de;de=readdir(dir)) {
		char *fname = talloc_asprintf(mem_ctx, "%s/%s", path, de->d_name);
		int ret = unlink(fname);
		if (ret == -1 &&
		    errno != ENOENT &&
		    errno != EISDIR &&
		    errno != EISDIR) {
			DEBUG(0,("Unabled to delete '%s' - %s\n", 
				 fname, strerror(errno)));
			smb_panic("unable to cleanup tmp files");
		}
		talloc_free(fname);
	}
	closedir(dir);

	talloc_free(mem_ctx);
}
