/* 
   Unix SMB/CIFS implementation.

   server side dcerpc using various kinds of sockets (tcp, unix domain)

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Stefan (metze) Metzmacher 2004   
   Copyright (C) Jelmer Vernooij 2004

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

struct dcesrv_socket_context {
	const struct dcesrv_endpoint *endpoint;
	struct dcesrv_context *dcesrv_ctx;	
};

/*
  write_fn callback for dcesrv_output()
*/
static ssize_t dcerpc_write_fn(void *private, DATA_BLOB *out)
{
	NTSTATUS status;
	struct socket_context *sock = private;
	size_t sendlen;

	status = socket_send(sock, sock, out, &sendlen, 0);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}

	return sendlen;
}

void dcesrv_terminate_connection(struct dcesrv_connection *dce_conn, const char *reason)
{
	server_terminate_connection(dce_conn->srv_conn, reason);
}

static void add_socket_rpc_unix(struct server_service *service,
				const struct model_ops *model_ops,
				struct dcesrv_context *dce_ctx,
				struct dcesrv_endpoint *e)
{
	struct server_socket *sock;
	struct dcesrv_socket_context *dcesrv_sock;
	uint16_t port = 1;

	sock = service_setup_socket(service,model_ops, "unix", e->ep_description.endpoint, &port);
	if (!sock) {
		DEBUG(0,("service_setup_socket(path=%s) failed\n",e->ep_description.endpoint));
		return;
	}

	dcesrv_sock = talloc_p(sock, struct dcesrv_socket_context);
	if (!dcesrv_sock) {
		DEBUG(0,("talloc_p(sock->mem_ctx, struct dcesrv_socket_context) failed\n"));
		return;
	}

	/* remember the endpoint of this socket */
	dcesrv_sock->endpoint		= e;
	dcesrv_sock->dcesrv_ctx		= dce_ctx;

	sock->private_data = dcesrv_sock;
}

static void add_socket_rpc_ncalrpc(struct server_service *service,
							const struct model_ops *model_ops,
							struct dcesrv_context *dce_ctx, 
							struct dcesrv_endpoint *e)
{
	struct server_socket *sock;
	struct dcesrv_socket_context *dcesrv_sock;
	uint16_t port = 1;
	char *full_path;

	if (!e->ep_description.endpoint) {
		/* No identifier specified: use DEFAULT. 
		 * DO NOT hardcode this value anywhere else. Rather, specify 
		 * no endpoint and let the epmapper worry about it. */
		e->ep_description.endpoint = talloc_strdup(dce_ctx, "DEFAULT");
	}

	full_path = talloc_asprintf(dce_ctx, "%s/%s", lp_ncalrpc_dir(), e->ep_description.endpoint);

	sock = service_setup_socket(service,model_ops, "unix", full_path, &port);
	if (!sock) {
		DEBUG(0,("service_setup_socket(identifier=%s,path=%s) failed\n",e->ep_description.endpoint, full_path));
		return;
	}

	dcesrv_sock = talloc_p(sock, struct dcesrv_socket_context);
	if (!dcesrv_sock) {
		DEBUG(0,("talloc_p(sock->mem_ctx, struct dcesrv_socket_context) failed\n"));
		return;
	}

	/* remember the endpoint of this socket */
	dcesrv_sock->endpoint		= e;
	dcesrv_sock->dcesrv_ctx		= dce_ctx;

	sock->private_data = dcesrv_sock;

	return;
}

/*
  add a socket address to the list of events, one event per dcerpc endpoint
*/
static void add_socket_rpc_tcp_iface(struct server_service *service, 
		       const struct model_ops *model_ops,
		       struct dcesrv_context *dce_ctx, 
			   struct dcesrv_endpoint *e,
		       struct in_addr *ifip)
{
	struct server_socket *sock;
	struct dcesrv_socket_context *dcesrv_sock;
	uint16_t port = 0;
	const char *ip_str = talloc_strdup(service, inet_ntoa(*ifip));
			
	if (e->ep_description.endpoint) 
		port = atoi(e->ep_description.endpoint);

	sock = service_setup_socket(service,model_ops, "ipv4", ip_str, &port);
	if (!sock) {
		DEBUG(0,("service_setup_socket(port=%u) failed\n",port));
		return;
	}

	if (e->ep_description.endpoint == NULL) {
		e->ep_description.endpoint = talloc_asprintf(dce_ctx, "%d", port);
	}

	dcesrv_sock = talloc_p(sock, struct dcesrv_socket_context);
	if (!dcesrv_sock) {
		DEBUG(0,("talloc_p(sock->mem_ctx, struct dcesrv_socket_context) failed\n"));
		return;
	}

	/* remember the endpoint of this socket */
	dcesrv_sock->endpoint		= e;
	dcesrv_sock->dcesrv_ctx		= dce_ctx;

	sock->private_data = dcesrv_sock;

	talloc_free(ip_str);

	return;
}

static void add_socket_rpc_tcp(struct server_service *service,
							const struct model_ops *model_ops,
							struct dcesrv_context *dce_ctx, 
							struct dcesrv_endpoint *e)
{
	/* Add TCP/IP sockets */
	if (lp_interfaces() && lp_bind_interfaces_only()) {
		int num_interfaces = iface_count();
		int i;
		for(i = 0; i < num_interfaces; i++) {
			struct in_addr *ifip = iface_n_ip(i);
			if (ifip == NULL) {
				continue;
			}
			add_socket_rpc_tcp_iface(service, model_ops, dce_ctx, e, ifip);
		}
	} else {
		struct in_addr *ifip;
		ifip = interpret_addr2(dce_ctx, lp_socket_address());
		add_socket_rpc_tcp_iface(service, model_ops, dce_ctx, e, ifip);
		talloc_free(ifip);
	}

	return;
}

/****************************************************************************
 Open the listening sockets for RPC over NCACN_IP_TCP/NCALRPC/NCACN_UNIX_STREAM
****************************************************************************/
void dcesrv_sock_init(struct server_service *service, const struct model_ops *model_ops, struct dcesrv_context *dce_ctx)
{
	struct dcesrv_endpoint *e;

	DEBUG(1,("dcesrv_sock_init\n"));

	/* Make sure the directory for NCALRPC exists */
	if (!directory_exist(lp_ncalrpc_dir(), NULL)) {
		mkdir(lp_ncalrpc_dir(), S_IWUSR | S_IRUSR | S_IXUSR);
	}

	for (e=dce_ctx->endpoint_list;e;e=e->next) {
		switch (e->ep_description.transport) {
		case NCACN_UNIX_STREAM:
			add_socket_rpc_unix(service, model_ops, dce_ctx, e);
			break;
		
		case NCALRPC:
			add_socket_rpc_ncalrpc(service, model_ops, dce_ctx, e);
			break;

		case NCACN_IP_TCP:
			add_socket_rpc_tcp(service, model_ops, dce_ctx, e);
			break;

		default:
			break;
		}
	}

	return;	
}

void dcesrv_sock_accept(struct server_connection *conn)
{
	NTSTATUS status;
	struct dcesrv_socket_context *dcesrv_sock = conn->server_socket->private_data;
	struct dcesrv_connection *dcesrv_conn = NULL;

	DEBUG(5,("dcesrv_sock_accept\n"));

	status = dcesrv_endpoint_connect(dcesrv_sock->dcesrv_ctx, dcesrv_sock->endpoint, &dcesrv_conn);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("dcesrv_sock_accept: dcesrv_endpoint_connect failed: %s\n", 
			nt_errstr(status)));
		return;
	}

	dcesrv_conn->srv_conn = conn;

	conn->private_data = dcesrv_conn;

	return;	
}

void dcesrv_sock_recv(struct server_connection *conn, time_t t, uint16_t flags)
{
	NTSTATUS status;
	struct dcesrv_connection *dce_conn = conn->private_data;
	DATA_BLOB tmp_blob;

	DEBUG(10,("dcesrv_sock_recv\n"));

	status = socket_recv(conn->socket, conn->socket, &tmp_blob, 0x4000, 0);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_IS_ERR(status)) {
			dcesrv_terminate_connection(dce_conn, "eof on socket");
			return;
		}
		return;
	}

	status = dcesrv_input(dce_conn, &tmp_blob);
	talloc_free(tmp_blob.data);
	if (!NT_STATUS_IS_OK(status)) {
		dcesrv_terminate_connection(dce_conn, "eof on socket");
		return;
	}

	if (dce_conn->call_list && dce_conn->call_list->replies) {
		conn->event.fde->flags |= EVENT_FD_WRITE;
	}

	return;	
}

void dcesrv_sock_send(struct server_connection *conn, time_t t, uint16_t flags)
{
	struct dcesrv_connection *dce_conn = conn->private_data;
	NTSTATUS status;

	DEBUG(10,("dcesrv_sock_send\n"));

	status = dcesrv_output(dce_conn, conn->socket, dcerpc_write_fn);
	if (!NT_STATUS_IS_OK(status)) {
		dcesrv_terminate_connection(dce_conn, "eof on socket");
		return;
	}

	if (!dce_conn->call_list || !dce_conn->call_list->replies) {
		conn->event.fde->flags &= ~EVENT_FD_WRITE;
	}

	return;
}

void dcesrv_sock_idle(struct server_connection *conn, time_t t)
{
	DEBUG(10,("dcesrv_sock_idle\n"));
	conn->event.idle->next_event = t + 5;

	return;	
}

void dcesrv_sock_close(struct server_connection *conn, const char *reason)
{
	struct dcesrv_connection *dce_conn = conn->private_data;

	DEBUG(5,("dcesrv_sock_close: %s\n",reason));

	talloc_free(dce_conn);

	return;
}

void dcesrv_sock_exit(struct server_service *service, const char *reason)
{
	DEBUG(1,("dcesrv_sock_exit: %s\n",reason));
	return;
}
