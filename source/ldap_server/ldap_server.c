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

/*
  close the socket and shutdown a server_context
*/
static void ldapsrv_terminate_connection(struct ldapsrv_connection *conn, 
					 const char *reason)
{
	talloc_free(conn->tls);
	conn->tls = NULL;
	stream_terminate_connection(conn->connection, reason);
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
	struct ldapsrv_send *q;
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
		if (!ldap_encode(msg, &b)) {
			DEBUG(0,("Failed to encode ldap reply of type %d\n", msg->type));
			goto failed;
		}

		status = data_blob_append(call, &blob, b.data, b.length);
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
		if (q->data.data == NULL) {
			goto failed;
		}
		RSIVAL(blob.data, 0, wrapped.length);
		memcpy(blob.data+4, wrapped.data, wrapped.length);
		data_blob_free(&wrapped);
	}

	q = talloc(conn, struct ldapsrv_send);
	if (q == NULL) goto failed;

	q->data = blob;
	talloc_steal(q, blob.data);
	
	if (conn->send_queue == NULL) {
		EVENT_FD_WRITEABLE(conn->connection->event.fde);
	}
	DLIST_ADD_END(conn->send_queue, q, struct ldapsrv_send *);
	talloc_free(call);
	return;

failed:
	talloc_free(call);
}


/*
  try and decode the partial input buffer
*/
static void ldapsrv_try_decode_plain(struct ldapsrv_connection *conn)
{
	struct asn1_data asn1;

	file_save("asn1.dat", conn->partial.data, conn->partial.length);

	if (!asn1_load(&asn1, conn->partial)) {
		ldapsrv_terminate_connection(conn, "out of memory");
		return;
	}

	/* try and decode - this will fail if we don't have a full packet yet */
	while (asn1.ofs < asn1.length) {
		struct ldap_message *msg = talloc(conn, struct ldap_message);
		off_t saved_ofs = asn1.ofs;
			
		if (msg == NULL) {
			ldapsrv_terminate_connection(conn, "out of memory");
			return;
		}

		if (ldap_decode(&asn1, msg)) {
			ldapsrv_process_message(conn, msg);
		} else {
			if (asn1.ofs < asn1.length) {
				ldapsrv_terminate_connection(conn, "ldap_decode failed");
				return;
			}
			asn1.ofs = saved_ofs;
			talloc_free(msg);
			break;
		}
	}

	/* keep any remaining data in conn->partial */
	data_blob_free(&conn->partial);
	if (asn1.ofs != asn1.length) {
		conn->partial = data_blob_talloc(conn, 
						 asn1.data + asn1.ofs, 
						 asn1.length - asn1.ofs);
	}
	asn1_free(&asn1);
}


/*
  try and decode/process wrapped data
*/
static void ldapsrv_try_decode_wrapped(struct ldapsrv_connection *conn)
{
	uint32_t len;

	/* keep decoding while we have a full wrapped packet */
	while (conn->partial.length >= 4 &&
	       (len=RIVAL(conn->partial.data, 0)) <= conn->partial.length-4) {
		DATA_BLOB wrapped, unwrapped;
		struct asn1_data asn1;
		struct ldap_message *msg = talloc(conn, struct ldap_message);
		NTSTATUS status;

		if (msg == NULL) {
			ldapsrv_terminate_connection(conn, "out of memory");
			return;
		}

		wrapped.data   = conn->partial.data+4;
		wrapped.length = len;

		status = gensec_unwrap(conn->gensec, msg, &wrapped, &unwrapped);
		if (!NT_STATUS_IS_OK(status)) {
			ldapsrv_terminate_connection(conn, "gensec unwrap failed");
			return;
		}

		if (!asn1_load(&asn1, unwrapped)) {
			ldapsrv_terminate_connection(conn, "out of memory");
			return;
		}

		while (ldap_decode(&asn1, msg)) {
			ldapsrv_process_message(conn, msg);
			msg = talloc(conn, struct ldap_message);
		}

		if (asn1.ofs < asn1.length) {
			ldapsrv_terminate_connection(conn, "ldap_decode failed");
			return;
		}
		
		talloc_free(msg);
		asn1_free(&asn1);

		if (conn->partial.length == len + 4) {
			data_blob_free(&conn->partial);
		} else {
			memmove(conn->partial.data, conn->partial.data+len+4,
				conn->partial.length - (len+4));
			conn->partial.length -= len + 4;
		}
	}
}


/*
  called when a LDAP socket becomes readable
*/
static void ldapsrv_recv(struct stream_connection *c, uint16_t flags)
{
	struct ldapsrv_connection *conn = 
		talloc_get_type(c->private, struct ldapsrv_connection);
	NTSTATUS status;
	size_t npending, nread;

	/* work out how much data is pending */
	status = tls_socket_pending(conn->tls, &npending);
	if (!NT_STATUS_IS_OK(status)) {
		ldapsrv_terminate_connection(conn, "socket_pening() failed");
		return;
	}
	if (npending == 0) {
		ldapsrv_terminate_connection(conn, "EOF from client");
		return;
	}

	conn->partial.data = talloc_realloc_size(conn, conn->partial.data, 
						 conn->partial.length + npending);
	if (conn->partial.data == NULL) {
		ldapsrv_terminate_connection(conn, "out of memory");
		return;
	}

	/* receive the data */
	status = tls_socket_recv(conn->tls, conn->partial.data + conn->partial.length,
				 npending, &nread);
	if (NT_STATUS_IS_ERR(status)) {
		ldapsrv_terminate_connection(conn, "socket_recv() failed");
		return;
	}
	if (!NT_STATUS_IS_OK(status)) {
		return;
	}
	if (nread == 0) {
		ldapsrv_terminate_connection(conn, "EOF from client");
		return;
	}
	conn->partial.length += nread;

	/* see if we can decode what we have */
	if (conn->enable_wrap) {
		ldapsrv_try_decode_wrapped(conn);
	} else {
		ldapsrv_try_decode_plain(conn);
	}
}
	
/*
  called when a LDAP socket becomes writable
*/
static void ldapsrv_send(struct stream_connection *c, uint16_t flags)
{
	struct ldapsrv_connection *conn = 
		talloc_get_type(c->private, struct ldapsrv_connection);
	while (conn->send_queue) {
		struct ldapsrv_send *q = conn->send_queue;
		size_t nsent;
		NTSTATUS status;

		status = tls_socket_send(conn->tls, &q->data, &nsent);
		if (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
			break;
		}
		if (!NT_STATUS_IS_OK(status)) {
			ldapsrv_terminate_connection(conn, "socket_send error");
			return;
		}

		q->data.data += nsent;
		q->data.length -= nsent;
		if (q->data.length == 0) {
			DLIST_REMOVE(conn->send_queue, q);
		}
	}
	if (conn->send_queue == NULL) {
		EVENT_FD_NOT_WRITEABLE(c->event.fde);
	}
}

/*
  initialise a server_context from a open socket and register a event handler
  for reading from that socket
*/
static void ldapsrv_accept(struct stream_connection *c)
{
	struct ldapsrv_service *ldapsrv_service = 
		talloc_get_type(c->private, struct ldapsrv_service);
	struct ldapsrv_connection *conn;
	int port;

	conn = talloc_zero(c, struct ldapsrv_connection);
	if (conn == NULL) goto failed;

	conn->enable_wrap = False;
	conn->partial     = data_blob(NULL, 0);
	conn->send_queue  = NULL;
	conn->connection  = c;
	conn->service     = talloc_get_type(c->private, struct ldapsrv_service);
	c->private        = conn;

	port = socket_get_my_port(c->socket);

	/* note that '0' is a ASN1_SEQUENCE(0), which is the first byte on
	   any ldap connection */
	conn->tls = tls_init_server(ldapsrv_service->tls_params, c->socket, 
				    c->event.fde, NULL, port != 389);
	if (conn->tls == NULL) goto failed;

	return;

failed:
	talloc_free(c);
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

	return status;
}

/*
  open the ldap server sockets
*/
static void ldapsrv_task_init(struct task_server *task)
{	
	struct ldapsrv_service *ldap_service;
	struct ldapsrv_partition *rootDSE_part;
	struct ldapsrv_partition *part;
	NTSTATUS status;

	ldap_service = talloc_zero(task, struct ldapsrv_service);
	if (ldap_service == NULL) goto failed;

	ldap_service->tls_params = tls_initialise(ldap_service);
	if (ldap_service->tls_params == NULL) goto failed;

	rootDSE_part = talloc(ldap_service, struct ldapsrv_partition);
	if (rootDSE_part == NULL) goto failed;

	rootDSE_part->base_dn = ""; /* RootDSE */
	rootDSE_part->ops = ldapsrv_get_rootdse_partition_ops();

	ldap_service->rootDSE = rootDSE_part;
	DLIST_ADD_END(ldap_service->partitions, rootDSE_part, struct ldapsrv_partition *);

	part = talloc(ldap_service, struct ldapsrv_partition);
	if (part == NULL) goto failed;

	part->base_dn = "*"; /* default partition */
	if (lp_parm_bool(-1, "ldapsrv", "hacked", False)) {
		part->ops = ldapsrv_get_hldb_partition_ops();
	} else {
		part->ops = ldapsrv_get_sldb_partition_ops();
	}

	ldap_service->default_partition = part;
	DLIST_ADD_END(ldap_service->partitions, part, struct ldapsrv_partition *);

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
	task_terminate(task, "Failed to startup ldap server task");	
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
