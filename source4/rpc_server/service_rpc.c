/* 
   Unix SMB/CIFS implementation.

   smbd-specific dcerpc server code

   Copyright (C) Andrew Tridgell 2003-2005
   Copyright (C) Stefan (metze) Metzmacher 2004-2005
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2004,2007
   
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
#include "librpc/gen_ndr/ndr_dcerpc.h"
#include "auth/auth.h"
#include "auth/gensec/gensec.h"
#include "../lib/util/dlinklist.h"
#include "rpc_server/dcerpc_server.h"
#include "rpc_server/dcerpc_server_proto.h"
#include "lib/events/events.h"
#include "smbd/service_task.h"
#include "smbd/service_stream.h"
#include "smbd/service.h"
#include "system/filesys.h"
#include "libcli/security/security.h"
#include "lib/socket/socket.h"
#include "lib/messaging/irpc.h"
#include "system/network.h"
#include "lib/socket/netif.h"
#include "param/param.h"

struct dcesrv_socket_context {
	const struct dcesrv_endpoint *endpoint;
	struct dcesrv_context *dcesrv_ctx;
};

/*
  write_fn callback for dcesrv_output()
*/
static NTSTATUS dcerpc_write_fn(void *private_data, DATA_BLOB *out, size_t *nwritten)
{
	NTSTATUS status;
	struct socket_context *sock = talloc_get_type(private_data, struct socket_context);
	size_t sendlen;

	status = socket_send(sock, out, &sendlen);
	NT_STATUS_IS_ERR_RETURN(status);

	*nwritten = sendlen;
	return status;
}

static void dcesrv_terminate_connection(struct dcesrv_connection *dce_conn, const char *reason)
{
	struct stream_connection *srv_conn;
	srv_conn = talloc_get_type(dce_conn->transport.private_data,
				   struct stream_connection);

	stream_terminate_connection(srv_conn, reason);
}

static void dcesrv_sock_report_output_data(struct dcesrv_connection *dcesrv_conn)
{
	struct stream_connection *srv_conn;
	srv_conn = talloc_get_type(dcesrv_conn->transport.private_data,
				   struct stream_connection);

	if (srv_conn && srv_conn->event.fde) {
		EVENT_FD_WRITEABLE(srv_conn->event.fde);
	}
}

static struct socket_address *dcesrv_sock_get_my_addr(struct dcesrv_connection *dcesrv_conn, TALLOC_CTX *mem_ctx)
{
	struct stream_connection *srv_conn;
	srv_conn = talloc_get_type(dcesrv_conn->transport.private_data,
				   struct stream_connection);

	return socket_get_my_addr(srv_conn->socket, mem_ctx);
}

static struct socket_address *dcesrv_sock_get_peer_addr(struct dcesrv_connection *dcesrv_conn, TALLOC_CTX *mem_ctx)
{
	struct stream_connection *srv_conn;
	srv_conn = talloc_get_type(dcesrv_conn->transport.private_data,
				   struct stream_connection);

	return socket_get_peer_addr(srv_conn->socket, mem_ctx);
}

static void dcesrv_sock_accept(struct stream_connection *srv_conn)
{
	NTSTATUS status;
	struct dcesrv_socket_context *dcesrv_sock = 
		talloc_get_type(srv_conn->private_data, struct dcesrv_socket_context);
	struct dcesrv_connection *dcesrv_conn = NULL;

	if (!srv_conn->session_info) {
		status = auth_anonymous_session_info(srv_conn,
						     srv_conn->event.ctx,
						     srv_conn->lp_ctx,
						     &srv_conn->session_info);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("dcesrv_sock_accept: auth_anonymous_session_info failed: %s\n",
				nt_errstr(status)));
			stream_terminate_connection(srv_conn, nt_errstr(status));
			return;
		}
	}

	status = dcesrv_endpoint_connect(dcesrv_sock->dcesrv_ctx,
					 srv_conn,
					 dcesrv_sock->endpoint,
					 srv_conn->session_info,
					 srv_conn->event.ctx,
					 srv_conn->msg_ctx,
					 srv_conn->server_id,
					 DCESRV_CALL_STATE_FLAG_MAY_ASYNC,
					 &dcesrv_conn);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("dcesrv_sock_accept: dcesrv_endpoint_connect failed: %s\n", 
			nt_errstr(status)));
		stream_terminate_connection(srv_conn, nt_errstr(status));
		return;
	}

	dcesrv_conn->transport.private_data		= srv_conn;
	dcesrv_conn->transport.report_output_data	= dcesrv_sock_report_output_data;
	dcesrv_conn->transport.get_my_addr		= dcesrv_sock_get_my_addr;
	dcesrv_conn->transport.get_peer_addr		= dcesrv_sock_get_peer_addr;

	if (dcesrv_sock->endpoint->ep_description->transport == NCACN_NP) {
		dcesrv_conn->auth_state.session_key = dcesrv_inherited_session_key;
	}

	srv_conn->private_data = dcesrv_conn;

	irpc_add_name(srv_conn->msg_ctx, "rpc_server");

	return;	
}

static void dcesrv_sock_recv(struct stream_connection *conn, uint16_t flags)
{
	NTSTATUS status;
	struct dcesrv_connection *dce_conn = talloc_get_type(conn->private_data, struct dcesrv_connection);
	DATA_BLOB tmp_blob;
	size_t nread;

	if (dce_conn->processing) {
		EVENT_FD_NOT_READABLE(conn->event.fde);
		return;
	}

	tmp_blob = data_blob_talloc(conn->socket, NULL, 0x1000);
	if (tmp_blob.data == NULL) {
		dcesrv_terminate_connection(dce_conn, "out of memory");
		return;
	}

	status = socket_recv(conn->socket, tmp_blob.data, tmp_blob.length, &nread);
	if (NT_STATUS_IS_ERR(status)) {
		dcesrv_terminate_connection(dce_conn, nt_errstr(status));
		return;
	}
	if (nread == 0) {
		talloc_free(tmp_blob.data);
		return;
	}

	tmp_blob.length = nread;

	dce_conn->processing = true;
	status = dcesrv_input(dce_conn, &tmp_blob);
	dce_conn->processing = false;
	talloc_free(tmp_blob.data);

	EVENT_FD_READABLE(conn->event.fde);

	if (!NT_STATUS_IS_OK(status)) {
		dcesrv_terminate_connection(dce_conn, nt_errstr(status));
		return;
	}

	if (dce_conn->call_list && dce_conn->call_list->replies) {
		EVENT_FD_WRITEABLE(conn->event.fde);
	}
}

static void dcesrv_sock_send(struct stream_connection *conn, uint16_t flags)
{
	struct dcesrv_connection *dce_conn = talloc_get_type(conn->private_data, struct dcesrv_connection);
	NTSTATUS status;

	status = dcesrv_output(dce_conn, conn->socket, dcerpc_write_fn);
	if (NT_STATUS_IS_ERR(status)) {
		dcesrv_terminate_connection(dce_conn, "eof on socket");
		return;
	}

	if (!dce_conn->call_list || !dce_conn->call_list->replies) {
		EVENT_FD_NOT_WRITEABLE(conn->event.fde);
	}
}


static const struct stream_server_ops dcesrv_stream_ops = {
	.name			= "rpc",
	.accept_connection	= dcesrv_sock_accept,
	.recv_handler		= dcesrv_sock_recv,
	.send_handler		= dcesrv_sock_send,
};



static NTSTATUS dcesrv_add_ep_unix(struct dcesrv_context *dce_ctx, 
				   struct loadparm_context *lp_ctx,
				   struct dcesrv_endpoint *e,
			    struct tevent_context *event_ctx, const struct model_ops *model_ops)
{
	struct dcesrv_socket_context *dcesrv_sock;
	uint16_t port = 1;
	NTSTATUS status;

	dcesrv_sock = talloc(event_ctx, struct dcesrv_socket_context);
	NT_STATUS_HAVE_NO_MEMORY(dcesrv_sock);

	/* remember the endpoint of this socket */
	dcesrv_sock->endpoint		= e;
	dcesrv_sock->dcesrv_ctx		= talloc_reference(dcesrv_sock, dce_ctx);

	status = stream_setup_socket(event_ctx, lp_ctx,
				     model_ops, &dcesrv_stream_ops, 
				     "unix", e->ep_description->endpoint, &port, 
				     lp_socket_options(lp_ctx), 
				     dcesrv_sock);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("service_setup_stream_socket(path=%s) failed - %s\n",
			 e->ep_description->endpoint, nt_errstr(status)));
	}

	return status;
}

static NTSTATUS dcesrv_add_ep_ncalrpc(struct dcesrv_context *dce_ctx, 
				      struct loadparm_context *lp_ctx,
				      struct dcesrv_endpoint *e,
				      struct tevent_context *event_ctx, const struct model_ops *model_ops)
{
	struct dcesrv_socket_context *dcesrv_sock;
	uint16_t port = 1;
	char *full_path;
	NTSTATUS status;

	if (!e->ep_description->endpoint) {
		/* No identifier specified: use DEFAULT. 
		 * DO NOT hardcode this value anywhere else. Rather, specify 
		 * no endpoint and let the epmapper worry about it. */
		e->ep_description->endpoint = talloc_strdup(dce_ctx, "DEFAULT");
	}

	full_path = talloc_asprintf(dce_ctx, "%s/%s", lp_ncalrpc_dir(lp_ctx), 
				    e->ep_description->endpoint);

	dcesrv_sock = talloc(event_ctx, struct dcesrv_socket_context);
	NT_STATUS_HAVE_NO_MEMORY(dcesrv_sock);

	/* remember the endpoint of this socket */
	dcesrv_sock->endpoint		= e;
	dcesrv_sock->dcesrv_ctx		= talloc_reference(dcesrv_sock, dce_ctx);

	status = stream_setup_socket(event_ctx, lp_ctx,
				     model_ops, &dcesrv_stream_ops, 
				     "unix", full_path, &port, 
				     lp_socket_options(lp_ctx), 
				     dcesrv_sock);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("service_setup_stream_socket(identifier=%s,path=%s) failed - %s\n",
			 e->ep_description->endpoint, full_path, nt_errstr(status)));
	}
	return status;
}

static NTSTATUS dcesrv_add_ep_np(struct dcesrv_context *dce_ctx,
				 struct loadparm_context *lp_ctx,
				 struct dcesrv_endpoint *e,
				 struct tevent_context *event_ctx, const struct model_ops *model_ops)
{
	struct dcesrv_socket_context *dcesrv_sock;
	NTSTATUS status;
			
	if (e->ep_description->endpoint == NULL) {
		DEBUG(0, ("Endpoint mandatory for named pipes\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	dcesrv_sock = talloc(event_ctx, struct dcesrv_socket_context);
	NT_STATUS_HAVE_NO_MEMORY(dcesrv_sock);

	/* remember the endpoint of this socket */
	dcesrv_sock->endpoint		= e;
	dcesrv_sock->dcesrv_ctx		= talloc_reference(dcesrv_sock, dce_ctx);

	status = stream_setup_named_pipe(event_ctx, lp_ctx,
					 model_ops, &dcesrv_stream_ops,
					 e->ep_description->endpoint, dcesrv_sock);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("stream_setup_named_pipe(pipe=%s) failed - %s\n",
			 e->ep_description->endpoint, nt_errstr(status)));
		return status;
	}

	return NT_STATUS_OK;
}

/*
  add a socket address to the list of events, one event per dcerpc endpoint
*/
static NTSTATUS add_socket_rpc_tcp_iface(struct dcesrv_context *dce_ctx, struct dcesrv_endpoint *e,
					 struct tevent_context *event_ctx, const struct model_ops *model_ops,
					 const char *address)
{
	struct dcesrv_socket_context *dcesrv_sock;
	uint16_t port = 0;
	NTSTATUS status;
			
	if (e->ep_description->endpoint) {
		port = atoi(e->ep_description->endpoint);
	}

	dcesrv_sock = talloc(event_ctx, struct dcesrv_socket_context);
	NT_STATUS_HAVE_NO_MEMORY(dcesrv_sock);

	/* remember the endpoint of this socket */
	dcesrv_sock->endpoint		= e;
	dcesrv_sock->dcesrv_ctx		= talloc_reference(dcesrv_sock, dce_ctx);

	status = stream_setup_socket(event_ctx, dce_ctx->lp_ctx,
				     model_ops, &dcesrv_stream_ops, 
				     "ipv4", address, &port, 
				     lp_socket_options(dce_ctx->lp_ctx), 
				     dcesrv_sock);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("service_setup_stream_socket(address=%s,port=%u) failed - %s\n", 
			 address, port, nt_errstr(status)));
	}

	if (e->ep_description->endpoint == NULL) {
		e->ep_description->endpoint = talloc_asprintf(dce_ctx, "%d", port);
	}

	return status;
}

static NTSTATUS dcesrv_add_ep_tcp(struct dcesrv_context *dce_ctx, 
				  struct loadparm_context *lp_ctx,
				  struct dcesrv_endpoint *e,
				  struct tevent_context *event_ctx, const struct model_ops *model_ops)
{
	NTSTATUS status;

	/* Add TCP/IP sockets */
	if (lp_interfaces(lp_ctx) && lp_bind_interfaces_only(lp_ctx)) {
		int num_interfaces;
		int i;
		struct interface *ifaces;

		load_interfaces(dce_ctx, lp_interfaces(lp_ctx), &ifaces);

		num_interfaces = iface_count(ifaces);
		for(i = 0; i < num_interfaces; i++) {
			const char *address = iface_n_ip(ifaces, i);
			status = add_socket_rpc_tcp_iface(dce_ctx, e, event_ctx, model_ops, address);
			NT_STATUS_NOT_OK_RETURN(status);
		}
	} else {
		status = add_socket_rpc_tcp_iface(dce_ctx, e, event_ctx, model_ops, 
						  lp_socket_address(lp_ctx));
		NT_STATUS_NOT_OK_RETURN(status);
	}

	return NT_STATUS_OK;
}


static NTSTATUS dcesrv_add_ep(struct dcesrv_context *dce_ctx, 
			      struct loadparm_context *lp_ctx,
			      struct dcesrv_endpoint *e,
			  struct tevent_context *event_ctx, const struct model_ops *model_ops)
{
	switch (e->ep_description->transport) {
	case NCACN_UNIX_STREAM:
		return dcesrv_add_ep_unix(dce_ctx, lp_ctx, e, event_ctx, model_ops);

	case NCALRPC:
		return dcesrv_add_ep_ncalrpc(dce_ctx, lp_ctx, e, event_ctx, model_ops);

	case NCACN_IP_TCP:
		return dcesrv_add_ep_tcp(dce_ctx, lp_ctx, e, event_ctx, model_ops);

	case NCACN_NP:
		return dcesrv_add_ep_np(dce_ctx, lp_ctx, e, event_ctx, model_ops);

	default:
		return NT_STATUS_NOT_SUPPORTED;
	}
}

/*
  open the dcerpc server sockets
*/
static void dcesrv_task_init(struct task_server *task)
{
	NTSTATUS status;
	struct dcesrv_context *dce_ctx;
	struct dcesrv_endpoint *e;

	dcerpc_server_init(task->lp_ctx);

	task_server_set_title(task, "task[dcesrv]");

	status = dcesrv_init_context(task->event_ctx,
				     task->lp_ctx,
				     lp_dcerpc_endpoint_servers(task->lp_ctx),
				     &dce_ctx);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	/* Make sure the directory for NCALRPC exists */
	if (!directory_exist(lp_ncalrpc_dir(task->lp_ctx))) {
		mkdir(lp_ncalrpc_dir(task->lp_ctx), 0755);
	}

	for (e=dce_ctx->endpoint_list;e;e=e->next) {
		status = dcesrv_add_ep(dce_ctx, task->lp_ctx, e, task->event_ctx, task->model_ops);
		if (!NT_STATUS_IS_OK(status)) goto failed;
	}

	return;
failed:
	task_server_terminate(task, "Failed to startup dcerpc server task");	
}

NTSTATUS server_service_rpc_init(void)
{

	return register_server_service("rpc", dcesrv_task_init);
}
