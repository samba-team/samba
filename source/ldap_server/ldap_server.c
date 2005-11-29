/* 
   Unix SMB/CIFS implementation.

   LDAP server

   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Volker Lendecke 2004
   Copyright (C) Stefan Metzmacher 2004
   
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
#include "lib/events/events.h"
#include "auth/auth.h"
#include "dlinklist.h"
#include "asn_1.h"
#include "ldap_server/ldap_server.h"
#include "smbd/service_task.h"
#include "smbd/service_stream.h"
#include "lib/socket/socket.h"
#include "lib/tls/tls.h"
#include "lib/messaging/irpc.h"
#include "lib/stream/packet.h"

/*
  close the socket and shutdown a server_context
*/
static void ldapsrv_terminate_connection(struct ldapsrv_connection *conn, 
					 const char *reason)
{
	/* we don't actually do the stream termination here as the
	   recv/send functions dereference the connection after the
	   packet processing callbacks. Instead we mark it for
	   termination and do the real termination in the send/recv
	   functions */
	conn->terminate = reason;
}

/*
  handle packet errors
*/
static void ldapsrv_error_handler(void *private, NTSTATUS status)
{
	struct ldapsrv_connection *conn = talloc_get_type(private, 
							  struct ldapsrv_connection);
	ldapsrv_terminate_connection(conn, nt_errstr(status));
}

/*
  process a decoded ldap message
*/
static void ldapsrv_process_message(struct ldapsrv_connection *conn,
				    struct ldap_message *msg)
{
	struct ldapsrv_call *call;
	NTSTATUS status;
	DATA_BLOB blob;
	BOOL enable_wrap = conn->enable_wrap;

	call = talloc(conn, struct ldapsrv_call);
	if (!call) {
		ldapsrv_terminate_connection(conn, "no memory");
		return;		
	}
	
	call->request = talloc_steal(call, msg);
	call->conn = conn;
	call->replies = NULL;

	/* make the call */
	status = ldapsrv_do_call(call);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}
	
	blob = data_blob(NULL, 0);

	if (call->replies == NULL) {
		talloc_free(call);
		return;
	}

	/* build all the replies into a single blob */
	while (call->replies) {
		DATA_BLOB b;

		msg = call->replies->msg;
		if (!ldap_encode(msg, &b, call)) {
			DEBUG(0,("Failed to encode ldap reply of type %d\n", msg->type));
			goto failed;
		}

		status = data_blob_append(call, &blob, b.data, b.length);
		data_blob_free(&b);

		if (!NT_STATUS_IS_OK(status)) goto failed;

		DLIST_REMOVE(call->replies, call->replies);
	}

	/* possibly encrypt/sign the reply */
	if (enable_wrap) {
		DATA_BLOB wrapped;

		status = gensec_wrap(conn->gensec, call, &blob, &wrapped);
		if (!NT_STATUS_IS_OK(status)) {
			goto failed;
		}
		data_blob_free(&blob);
		blob = data_blob_talloc(call, NULL, wrapped.length + 4);
		if (blob.data == NULL) {
			goto failed;
		}
		RSIVAL(blob.data, 0, wrapped.length);
		memcpy(blob.data+4, wrapped.data, wrapped.length);
		data_blob_free(&wrapped);
	}

	packet_send(conn->packet, blob);
	talloc_free(call);
	return;

failed:
	talloc_free(call);
}


/*
  decode the input buffer
*/
static NTSTATUS ldapsrv_decode_plain(struct ldapsrv_connection *conn, DATA_BLOB blob)
{
	struct asn1_data asn1;
	struct ldap_message *msg = talloc(conn, struct ldap_message);

	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!asn1_load(&asn1, blob)) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!ldap_decode(&asn1, msg)) {
		asn1_free(&asn1);
		return NT_STATUS_LDAP(LDAP_PROTOCOL_ERROR);
	}

	data_blob_free(&blob);
	ldapsrv_process_message(conn, msg);
	asn1_free(&asn1);
	return NT_STATUS_OK;
}


/*
  decode/process wrapped data
*/
static NTSTATUS ldapsrv_decode_wrapped(struct ldapsrv_connection *conn, 
				       DATA_BLOB blob)
{
	DATA_BLOB wrapped, unwrapped;
	struct asn1_data asn1;
	struct ldap_message *msg = talloc(conn, struct ldap_message);
	NTSTATUS status;

	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	wrapped = data_blob_const(blob.data+4, blob.length-4);

	status = gensec_unwrap(conn->gensec, msg, &wrapped, &unwrapped);
	if (!NT_STATUS_IS_OK(status)) {
		return NT_STATUS_LDAP(LDAP_PROTOCOL_ERROR);
	}

	data_blob_free(&blob);

	if (!asn1_load(&asn1, unwrapped)) {
		return NT_STATUS_LDAP(LDAP_PROTOCOL_ERROR);
	}

	while (ldap_decode(&asn1, msg)) {
		ldapsrv_process_message(conn, msg);
		msg = talloc(conn, struct ldap_message);
	}

	if (asn1.ofs < asn1.length) {
		return NT_STATUS_LDAP(LDAP_PROTOCOL_ERROR);
	}
		
	talloc_free(msg);
	asn1_free(&asn1);

	return NT_STATUS_OK;
}

/*
  decode/process data
*/
static NTSTATUS ldapsrv_decode(void *private, DATA_BLOB blob)
{
	struct ldapsrv_connection *conn = talloc_get_type(private, 
							  struct ldapsrv_connection);
	if (conn->enable_wrap) {
		return ldapsrv_decode_wrapped(conn, blob);
	}
	return ldapsrv_decode_plain(conn, blob);
}

/*
  called when a LDAP socket becomes readable
*/
static void ldapsrv_recv(struct stream_connection *c, uint16_t flags)
{
	struct ldapsrv_connection *conn = 
		talloc_get_type(c->private, struct ldapsrv_connection);
	
	packet_recv(conn->packet);

	if (conn->terminate) {
		if (conn->tls) {
			talloc_free(conn->tls);
			conn->tls = NULL;
		}
		stream_terminate_connection(conn->connection, conn->terminate);
	}
}

/*
  check if a blob is a complete ldap packet
  handle wrapper or unwrapped connections
*/
NTSTATUS ldapsrv_complete_packet(void *private, DATA_BLOB blob, size_t *size)
{
	struct ldapsrv_connection *conn = talloc_get_type(private, 
							  struct ldapsrv_connection);
	if (conn->enable_wrap) {
		return packet_full_request_u32(private, blob, size);
	}
	return ldap_full_packet(private, blob, size);
}
	
/*
  called when a LDAP socket becomes writable
*/
static void ldapsrv_send(struct stream_connection *c, uint16_t flags)
{
	struct ldapsrv_connection *conn = 
		talloc_get_type(c->private, struct ldapsrv_connection);
	
	packet_queue_run(conn->packet);

	if (conn->terminate) {
		if (conn->tls) {
			talloc_free(conn->tls);
			conn->tls = NULL;
		}
		stream_terminate_connection(conn->connection, conn->terminate);
	}
}

/*
  initialise a server_context from a open socket and register a event handler
  for reading from that socket
*/
static void ldapsrv_accept(struct stream_connection *c)
{
	struct ldapsrv_partition *part;
	struct ldapsrv_service *ldapsrv_service = 
		talloc_get_type(c->private, struct ldapsrv_service);
	struct ldapsrv_connection *conn;
	int port;

	conn = talloc_zero(c, struct ldapsrv_connection);
	if (!conn) {
		stream_terminate_connection(c, "ldapsrv_accept: out of memory");
		return;
	}

	conn->enable_wrap = False;
	conn->packet      = NULL;
	conn->connection  = c;
	conn->service     = ldapsrv_service;
	c->private        = conn;

	port = socket_get_my_port(c->socket);

	conn->tls = tls_init_server(ldapsrv_service->tls_params, c->socket, 
				    c->event.fde, NULL, port != 389);
	if (!conn->tls) {
		ldapsrv_terminate_connection(conn, "ldapsrv_accept: tls_init_server() failed");
		goto done;
	}

	conn->packet = packet_init(conn);
	if (conn->packet == NULL) {
		ldapsrv_terminate_connection(conn, "out of memory");
		goto done;
	}
	packet_set_private(conn->packet, conn);
	packet_set_tls(conn->packet, conn->tls);
	packet_set_callback(conn->packet, ldapsrv_decode);
	packet_set_full_request(conn->packet, ldapsrv_complete_packet);
	packet_set_error_handler(conn->packet, ldapsrv_error_handler);
	packet_set_event_context(conn->packet, c->event.ctx);
	packet_set_fde(conn->packet, c->event.fde);
	packet_set_serialise(conn->packet);

	/* Connections start out anonymous */
	if (!NT_STATUS_IS_OK(auth_anonymous_session_info(conn, &conn->session_info))) {
		ldapsrv_terminate_connection(conn, "failed to setup anonymous session info");
		goto done;
	}

	part = talloc(conn, struct ldapsrv_partition);
	if (part == NULL) {
		ldapsrv_terminate_connection(conn, "talloc failed");
		goto done;
	}

	part->base_dn = "*"; /* default partition */
	part->ops = ldapsrv_get_sldb_partition_ops();
	if (!NT_STATUS_IS_OK(part->ops->Init(part, conn))) {
		ldapsrv_terminate_connection(conn, "default partition Init failed");
		goto done;
	}

	conn->default_partition = part;
	DLIST_ADD_END(conn->partitions, part, struct ldapsrv_partition *);

	irpc_add_name(c->msg_ctx, "ldap_server");

done:
	if (conn->terminate) {
		if (conn->tls) {
			talloc_free(conn->tls);
			conn->tls = NULL;
		}
		stream_terminate_connection(conn->connection, conn->terminate);
	}
}

static const struct stream_server_ops ldap_stream_ops = {
	.name			= "ldap",
	.accept_connection	= ldapsrv_accept,
	.recv_handler		= ldapsrv_recv,
	.send_handler		= ldapsrv_send,
};

/*
  add a socket address to the list of events, one event per port
*/
static NTSTATUS add_socket(struct event_context *event_context,
			   const struct model_ops *model_ops,
			   const char *address, struct ldapsrv_service *ldap_service)
{
	uint16_t port = 389;
	NTSTATUS status;

	status = stream_setup_socket(event_context, model_ops, &ldap_stream_ops, 
				     "ipv4", address, &port, ldap_service);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("ldapsrv failed to bind to %s:%u - %s\n",
			 address, port, nt_errstr(status)));
	}

	if (tls_support(ldap_service->tls_params)) {
		/* add ldaps server */
		port = 636;
		status = stream_setup_socket(event_context, model_ops, &ldap_stream_ops, 
					     "ipv4", address, &port, ldap_service);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("ldapsrv failed to bind to %s:%u - %s\n",
				 address, port, nt_errstr(status)));
		}
	}

	/* if we are a PDC, then also enable the global catalog server port, 3268 */
	if (lp_server_role() == ROLE_DOMAIN_PDC) {
		port = 3268;
		status = stream_setup_socket(event_context, model_ops, &ldap_stream_ops, 
					     "ipv4", address, &port, ldap_service);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("ldapsrv failed to bind to %s:%u - %s\n",
				 address, port, nt_errstr(status)));
		}
	}

	return status;
}

/*
  open the ldap server sockets
*/
static void ldapsrv_task_init(struct task_server *task)
{	
	struct ldapsrv_service *ldap_service;
	NTSTATUS status;

	ldap_service = talloc_zero(task, struct ldapsrv_service);
	if (ldap_service == NULL) goto failed;

	ldap_service->tls_params = tls_initialise(ldap_service);
	if (ldap_service->tls_params == NULL) goto failed;

	if (lp_interfaces() && lp_bind_interfaces_only()) {
		int num_interfaces = iface_count();
		int i;

		/* We have been given an interfaces line, and been 
		   told to only bind to those interfaces. Create a
		   socket per interface and bind to only these.
		*/
		for(i = 0; i < num_interfaces; i++) {
			const char *address = iface_n_ip(i);
			status = add_socket(task->event_ctx, task->model_ops, address, ldap_service);
			if (!NT_STATUS_IS_OK(status)) goto failed;
		}
	} else {
		status = add_socket(task->event_ctx, task->model_ops, lp_socket_address(), ldap_service);
		if (!NT_STATUS_IS_OK(status)) goto failed;
	}

	return;

failed:
	task_server_terminate(task, "Failed to startup ldap server task");	
}

/*
  called on startup of the web server service It's job is to start
  listening on all configured sockets
*/
static NTSTATUS ldapsrv_init(struct event_context *event_context, 
			     const struct model_ops *model_ops)
{	
	return task_server_startup(event_context, model_ops, ldapsrv_task_init);
}


NTSTATUS server_service_ldap_init(void)
{
	return register_server_service("ldap", ldapsrv_init);
}
