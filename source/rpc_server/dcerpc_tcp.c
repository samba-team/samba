/* 
   Unix SMB/CIFS implementation.

   server side dcerpc over tcp code

   Copyright (C) Andrew Tridgell 2003
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

/*
  add a socket address to the list of events, one event per dcerpc endpoint
*/
static void add_socket_rpc(struct server_service *service, 
		       const struct model_ops *model_ops,
		       struct dcesrv_context *dce_ctx, 
		       struct in_addr *ifip)
{
	struct dcesrv_endpoint *e;
	char *ip_str = talloc_strdup(service, inet_ntoa(*ifip));

	for (e=dce_ctx->endpoint_list;e;e=e->next) {
		if (e->ep_description.type == NCACN_IP_TCP) {
			struct server_socket *sock;
			struct dcesrv_socket_context *dcesrv_sock;

			sock = service_setup_socket(service,model_ops, ip_str, &e->ep_description.info.tcp_port);
			if (!sock) {
				DEBUG(0,("service_setup_socket(port=%u) failed\n",e->ep_description.info.tcp_port));
				continue;
			}

			dcesrv_sock = talloc_p(sock, struct dcesrv_socket_context);
			if (!dcesrv_sock) {
				DEBUG(0,("talloc_p(sock->mem_ctx, struct dcesrv_socket_context) failed\n"));
				continue;
			}

			/* remember the endpoint of this socket */
			dcesrv_sock->endpoint		= e;
			dcesrv_sock->dcesrv_ctx		= dce_ctx;

			sock->private_data = dcesrv_sock;
		}
	}

	talloc_free(ip_str);
}

/****************************************************************************
 Open the listening sockets for RPC over TCP
****************************************************************************/
void dcesrv_tcp_init(struct server_service *service, const struct model_ops *model_ops, struct dcesrv_context *dce_ctx)
{
	DEBUG(1,("dcesrv_tcp_init\n"));

	if (lp_interfaces() && lp_bind_interfaces_only()) {
		int num_interfaces = iface_count();
		int i;
		for(i = 0; i < num_interfaces; i++) {
			struct in_addr *ifip = iface_n_ip(i);
			if (ifip == NULL) {
				continue;
			}
			add_socket_rpc(service, model_ops, dce_ctx,  ifip);
		}
	} else {
		struct in_addr *ifip;
		ifip = interpret_addr2(dce_ctx, lp_socket_address());
		add_socket_rpc(service, model_ops, dce_ctx,  ifip);
		talloc_free(ifip);
	}

	return;	
}

void dcesrv_tcp_accept(struct server_connection *conn)
{
	NTSTATUS status;
	struct dcesrv_socket_context *dcesrv_sock = conn->server_socket->private_data;
	struct dcesrv_connection *dcesrv_conn = NULL;

	DEBUG(5,("dcesrv_tcp_accept\n"));

	status = dcesrv_endpoint_connect(dcesrv_sock->dcesrv_ctx, dcesrv_sock->endpoint, &dcesrv_conn);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("dcesrv_tcp_accept: dcesrv_endpoint_connect failed: %s\n", 
			nt_errstr(status)));
		return;
	}

	dcesrv_conn->srv_conn = conn;

	conn->private_data = dcesrv_conn;

	return;	
}

void dcesrv_tcp_recv(struct server_connection *conn, time_t t, uint16_t flags)
{
	NTSTATUS status;
	struct dcesrv_connection *dce_conn = conn->private_data;
	DATA_BLOB tmp_blob;

	DEBUG(10,("dcesrv_tcp_recv\n"));

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

void dcesrv_tcp_send(struct server_connection *conn, time_t t, uint16_t flags)
{
	struct dcesrv_connection *dce_conn = conn->private_data;
	NTSTATUS status;

	DEBUG(10,("dcesrv_tcp_send\n"));

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

void dcesrv_tcp_idle(struct server_connection *conn, time_t t)
{
	DEBUG(10,("dcesrv_tcp_idle\n"));
	conn->event.idle->next_event = t + 5;

	return;	
}

void dcesrv_tcp_close(struct server_connection *conn, const char *reason)
{
	struct dcesrv_connection *dce_conn = conn->private_data;

	DEBUG(5,("dcesrv_tcp_close: %s\n",reason));

	talloc_free(dce_conn);

	return;
}

void dcesrv_tcp_exit(struct server_service *service, const char *reason)
{
	DEBUG(1,("dcesrv_tcp_exit: %s\n",reason));
	return;
}
