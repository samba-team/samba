/* 
   Unix SMB/CIFS implementation.
   LDAP server
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
#include "events.h"
#include "auth/auth.h"
#include "dlinklist.h"
#include "asn_1.h"
#include "ldap_server/ldap_server.h"

/*
  close the socket and shutdown a server_context
*/
static void ldapsrv_terminate_connection(struct ldapsrv_connection *ldap_conn, const char *reason)
{
	server_terminate_connection(ldap_conn->connection, reason);
}

/*
  add a socket address to the list of events, one event per port
*/
static void add_socket(struct server_service *service, 
		       const struct model_ops *model_ops, 
		       struct ipv4_addr *ifip)
{
	struct server_socket *srv_sock;
	uint16_t port = 389;
	char *ip_str = talloc_strdup(service, sys_inet_ntoa(*ifip));

	srv_sock = service_setup_socket(service, model_ops, "ipv4", ip_str, &port);

	port = 3268;
	srv_sock = service_setup_socket(service, model_ops, "ipv4", ip_str, &port);

	talloc_free(ip_str);
}

/****************************************************************************
 Open the socket communication.
****************************************************************************/
static void ldapsrv_init(struct server_service *service,
			 const struct model_ops *model_ops)
{	
	struct ldapsrv_service *ldap_service;
	struct ldapsrv_partition *part;

	DEBUG(10,("ldapsrv_init\n"));

	ldap_service = talloc_p(service, struct ldapsrv_service);
	if (!ldap_service) {
		DEBUG(0,("talloc_p(service, struct ldapsrv_service) failed\n"));
		return;
	}
	ZERO_STRUCTP(ldap_service);

	part = talloc_p(ldap_service, struct ldapsrv_partition);
	if (!ldap_service) {
		DEBUG(0,("talloc_p(ldap_service, struct ldapsrv_partition) failed\n"));
		return;
	}
	part->base_dn = ""; /* RootDSE */
	part->ops = ldapsrv_get_rootdse_partition_ops();

	ldap_service->rootDSE = part;
	DLIST_ADD_END(ldap_service->partitions, part, struct ldapsrv_partition *);

	part = talloc_p(ldap_service, struct ldapsrv_partition);
	if (!ldap_service) {
		DEBUG(0,("talloc_p(ldap_service, struct ldapsrv_partition) failed\n"));
		return;
	}
	part->base_dn = "*"; /* default partition */
	part->ops = ldapsrv_get_sldb_partition_ops();

	ldap_service->default_partition = part;
	DLIST_ADD_END(ldap_service->partitions, part, struct ldapsrv_partition *);

	service->private_data = ldap_service;

	if (lp_interfaces() && lp_bind_interfaces_only()) {
		int num_interfaces = iface_count();
		int i;

		/* We have been given an interfaces line, and been 
		   told to only bind to those interfaces. Create a
		   socket per interface and bind to only these.
		*/
		for(i = 0; i < num_interfaces; i++) {
			struct ipv4_addr *ifip = iface_n_ip(i);

			if (ifip == NULL) {
				DEBUG(0,("ldapsrv_init: interface %d has NULL "
					 "IP address !\n", i));
				continue;
			}

			add_socket(service, model_ops, ifip);
		}
	} else {
		struct ipv4_addr ifip;

		/* Just bind to lp_socket_address() (usually 0.0.0.0) */
		ifip = interpret_addr2(lp_socket_address());
		add_socket(service, model_ops, &ifip);
	}
}

/* This rw-buf api is made to avoid memcpy. For now do that like mad...  The
   idea is to write into a circular list of buffers where the ideal case is
   that a read(2) holds a complete request that is then thrown away
   completely. */

void ldapsrv_consumed_from_buf(struct rw_buffer *buf,
				   size_t length)
{
	memcpy(buf->data, buf->data+length, buf->length-length);
	buf->length -= length;
}

static void peek_into_read_buf(struct rw_buffer *buf, uint8_t **out,
			       size_t *out_length)
{
	*out = buf->data;
	*out_length = buf->length;
}

BOOL ldapsrv_append_to_buf(struct rw_buffer *buf, uint8_t *data, size_t length)
{
	buf->data = realloc(buf->data, buf->length+length);

	if (buf->data == NULL)
		return False;

	memcpy(buf->data+buf->length, data, length);

	buf->length += length;
	return True;
}

static BOOL read_into_buf(struct socket_context *sock, struct rw_buffer *buf)
{
	NTSTATUS status;
	DATA_BLOB tmp_blob;
	BOOL ret;
	size_t nread;

	tmp_blob = data_blob_talloc(sock, NULL, 1024);
	if (tmp_blob.data == NULL) {
		return False;
	}

	status = socket_recv(sock, tmp_blob.data, tmp_blob.length, &nread, 0);
	if (NT_STATUS_IS_ERR(status)) {
		DEBUG(10,("socket_recv: %s\n",nt_errstr(status)));
		talloc_free(tmp_blob.data);
		return False;
	}

	ret = ldapsrv_append_to_buf(buf, tmp_blob.data, tmp_blob.length);

	talloc_free(tmp_blob.data);

	return ret;
}

static BOOL ldapsrv_read_buf(struct ldapsrv_connection *conn)
{
	NTSTATUS status;
	DATA_BLOB tmp_blob;
	DATA_BLOB creds;
	BOOL ret;
	uint8_t *buf;
	int buf_length, sasl_length;
	struct socket_context *sock = conn->connection->socket;
	TALLOC_CTX *mem_ctx;
	size_t nread;

	if (!conn->gensec || !conn->session_info ||
	   !(gensec_have_feature(conn->gensec, GENSEC_WANT_SIGN) &&
	     gensec_have_feature(conn->gensec, GENSEC_WANT_SEAL))) {
		return read_into_buf(sock, &conn->in_buffer);
	}

	mem_ctx = talloc(conn, 0);
	if (!mem_ctx) {
		DEBUG(0,("no memory\n"));
		return False;
	}

	tmp_blob = data_blob_talloc(mem_ctx, NULL, 1024);
	if (tmp_blob.data == NULL) {
		talloc_free(mem_ctx);
		return False;
	}

	status = socket_recv(sock, tmp_blob.data, tmp_blob.length, &nread, 0);
	if (NT_STATUS_IS_ERR(status)) {
		DEBUG(10,("socket_recv: %s\n",nt_errstr(status)));
		talloc_free(mem_ctx);
		return False;
	}
	tmp_blob.length = nread;

	ret = ldapsrv_append_to_buf(&conn->sasl_in_buffer, tmp_blob.data, tmp_blob.length);
	if (!ret) {
		talloc_free(mem_ctx);
		return False;
	}

	peek_into_read_buf(&conn->sasl_in_buffer, &buf, &buf_length);

	if (buf_length < 4) {
		/* not enough yet */
		talloc_free(mem_ctx);
		return True;
	}

	sasl_length = RIVAL(buf, 0);

	if (buf_length < (4 + sasl_length)) {
		/* not enough yet */
		talloc_free(mem_ctx);
		return True;
	}

	creds.data = buf + 4;
	creds.length = gensec_sig_size(conn->gensec);

	if (creds.length > sasl_length) {
		/* invalid packet? */
		talloc_free(mem_ctx);
		return False;
	}

	tmp_blob.data = buf + (4 + creds.length);
	tmp_blob.length = (4 + sasl_length) - (4 + creds.length);

	if (gensec_have_feature(conn->gensec, GENSEC_WANT_SEAL)) {
		status = gensec_unseal_packet(conn->gensec, mem_ctx,
					      tmp_blob.data, tmp_blob.length,
					      tmp_blob.data, tmp_blob.length,
					      &creds);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("gensec_unseal_packet: %s\n",nt_errstr(status)));
			talloc_free(mem_ctx);
			return False;
		}
	} else {
		status = gensec_check_packet(conn->gensec, mem_ctx,
					      tmp_blob.data, tmp_blob.length,
					      tmp_blob.data, tmp_blob.length,
					      &creds);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("gensec_check_packet: %s\n",nt_errstr(status)));
			talloc_free(mem_ctx);
			return False;
		}
	}

	ret = ldapsrv_append_to_buf(&conn->in_buffer, tmp_blob.data, tmp_blob.length);
	if (!ret) {
		talloc_free(mem_ctx);
		return False;
	}

	ldapsrv_consumed_from_buf(&conn->sasl_in_buffer, 4 + sasl_length);

	talloc_free(mem_ctx);
	return ret;
}

static BOOL write_from_buf(struct socket_context *sock, struct rw_buffer *buf)
{
	NTSTATUS status;
	DATA_BLOB tmp_blob;
	size_t sendlen;

	tmp_blob.data = buf->data;
	tmp_blob.length = buf->length;

	status = socket_send(sock, &tmp_blob, &sendlen, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10,("socket_send() %s\n",nt_errstr(status)));
		return False;
	}

	ldapsrv_consumed_from_buf(buf, sendlen);

	return True;
}

static BOOL ldapsrv_write_buf(struct ldapsrv_connection *conn)
{
	NTSTATUS status;
	DATA_BLOB tmp_blob;
	DATA_BLOB creds;
	DATA_BLOB sasl;
	size_t sendlen;
	BOOL ret;
	struct socket_context *sock = conn->connection->socket;
	TALLOC_CTX *mem_ctx;

	if (!conn->gensec || !conn->session_info ||
	   !(gensec_have_feature(conn->gensec, GENSEC_WANT_SIGN) &&
	     gensec_have_feature(conn->gensec, GENSEC_WANT_SEAL))) {
		return write_from_buf(sock, &conn->out_buffer);
	}

	mem_ctx = talloc(conn, 0);
	if (!mem_ctx) {
		DEBUG(0,("no memory\n"));
		return False;
	}

	tmp_blob.data = conn->out_buffer.data;
	tmp_blob.length = conn->out_buffer.length;

	if (tmp_blob.length == 0) {
		goto nodata;
	}

	if (gensec_have_feature(conn->gensec, GENSEC_WANT_SEAL)) {
		status = gensec_seal_packet(conn->gensec, mem_ctx,
					    tmp_blob.data, tmp_blob.length,
					    tmp_blob.data, tmp_blob.length,
					    &creds);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("gensec_seal_packet: %s\n",nt_errstr(status)));
			talloc_free(mem_ctx);
			return False;
		}
	} else {
		status = gensec_sign_packet(conn->gensec, mem_ctx,
					    tmp_blob.data, tmp_blob.length,
					    tmp_blob.data, tmp_blob.length,
					    &creds);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("gensec_sign_packet: %s\n",nt_errstr(status)));
			talloc_free(mem_ctx);
			return False;
		}		
	}

	sasl = data_blob_talloc(mem_ctx, NULL, 4 + creds.length + tmp_blob.length);
	if (!sasl.data) {
		DEBUG(0,("no memory\n"));
		talloc_free(mem_ctx);
		return False;
	}

	RSIVAL(sasl.data, 0, creds.length + tmp_blob.length);
	memcpy(sasl.data + 4, creds.data, creds.length);
	memcpy(sasl.data + 4 + creds.length, tmp_blob.data, tmp_blob.length);

	ret = ldapsrv_append_to_buf(&conn->sasl_out_buffer, sasl.data, sasl.length);
	if (!ret) {
		talloc_free(mem_ctx);
		return False;
	}
	ldapsrv_consumed_from_buf(&conn->out_buffer, tmp_blob.length);
nodata:
	tmp_blob.data = conn->sasl_out_buffer.data;
	tmp_blob.length = conn->sasl_out_buffer.length;

	status = socket_send(sock, &tmp_blob, &sendlen, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10,("socket_send() %s\n",nt_errstr(status)));
		talloc_free(mem_ctx);
		return False;
	}

	ldapsrv_consumed_from_buf(&conn->sasl_out_buffer, sendlen);

	talloc_free(mem_ctx);

	return True;
}

static BOOL ldap_encode_to_buf(struct ldap_message *msg, struct rw_buffer *buf)
{
	DATA_BLOB blob;
	BOOL res;

	if (!ldap_encode(msg, &blob))
		return False;

	res = ldapsrv_append_to_buf(buf, blob.data, blob.length);

	data_blob_free(&blob);
	return res;
}

NTSTATUS ldapsrv_do_responses(struct ldapsrv_connection *conn)
{
	struct ldapsrv_call *call, *next_call = NULL;
	struct ldapsrv_reply *reply, *next_reply = NULL;

	for (call=conn->calls; call; call=next_call) {
		for (reply=call->replies; reply; reply=next_reply) {
			if (!ldap_encode_to_buf(&reply->msg, &conn->out_buffer)) {
				return NT_STATUS_FOOBAR;
			}
			next_reply = reply->next;
			DLIST_REMOVE(call->replies, reply);
			reply->state = LDAPSRV_REPLY_STATE_SEND;
			talloc_free(reply);
		}
		next_call = call->next;
		DLIST_REMOVE(conn->calls, call);
		call->state = LDAPSRV_CALL_STATE_COMPLETE;
		talloc_free(call);
	}

	return NT_STATUS_OK;
}

NTSTATUS ldapsrv_flush_responses(struct ldapsrv_connection *conn)
{
	return NT_STATUS_OK;
}

/*
  called when a LDAP socket becomes readable
*/
static void ldapsrv_recv(struct server_connection *conn, struct timeval t,
			 uint16_t flags)
{
	struct ldapsrv_connection *ldap_conn = conn->private_data;
	uint8_t *buf;
	int buf_length, msg_length;
	DATA_BLOB blob;
	struct asn1_data data;
	struct ldapsrv_call *call;
	NTSTATUS status;

	DEBUG(10,("ldapsrv_recv\n"));

	if (!ldapsrv_read_buf(ldap_conn)) {
		ldapsrv_terminate_connection(ldap_conn, "ldapsrv_read_buf() failed");
		return;
	}

	peek_into_read_buf(&ldap_conn->in_buffer, &buf, &buf_length);

	while (buf_length > 0) {
		/* LDAP Messages are always SEQUENCES */

		if (!asn1_object_length(buf, buf_length, ASN1_SEQUENCE(0),
					&msg_length)) {
			ldapsrv_terminate_connection(ldap_conn, "asn1_object_length() failed");
			return;
		}

		if (buf_length < msg_length) {
			/* Not enough yet */
			break;
		}

		/* We've got a complete LDAP request in the in-buffer, convert
		 * that to a ldap_message and put it into the incoming
		 * queue. */

		blob.data = buf;
		blob.length = msg_length;

		if (!asn1_load(&data, blob)) {
			ldapsrv_terminate_connection(ldap_conn, "asn1_load() failed");
			return;
		}

		call = talloc_p(ldap_conn, struct ldapsrv_call);
		if (!call) {
			ldapsrv_terminate_connection(ldap_conn, "no memory");
			return;		
		}

		ZERO_STRUCTP(call);
		call->state = LDAPSRV_CALL_STATE_NEW;
		call->conn = ldap_conn;
		call->request.mem_ctx = call;

		if (!ldap_decode(&data, &call->request)) {
			dump_data(0,buf, msg_length);
			asn1_free(&data);
			ldapsrv_terminate_connection(ldap_conn, "ldap_decode() failed");
			return;
		}

		asn1_free(&data);

		DLIST_ADD_END(ldap_conn->calls, call,
			      struct ldapsrv_call *);

		ldapsrv_consumed_from_buf(&ldap_conn->in_buffer, msg_length);

		status = ldapsrv_do_call(call);
		if (!NT_STATUS_IS_OK(status)) {
			ldapsrv_terminate_connection(ldap_conn, "ldapsrv_do_call() failed");
			return;
		}

		peek_into_read_buf(&ldap_conn->in_buffer, &buf, &buf_length);
	}

	status = ldapsrv_do_responses(ldap_conn);
	if (!NT_STATUS_IS_OK(status)) {
		ldapsrv_terminate_connection(ldap_conn, "ldapsrv_do_responses() failed");
		return;
	}

	if ((ldap_conn->out_buffer.length > 0)||(ldap_conn->sasl_out_buffer.length > 0)) {
		conn->event.fde->flags |= EVENT_FD_WRITE;
	}

	return;
}
	
/*
  called when a LDAP socket becomes writable
*/
static void ldapsrv_send(struct server_connection *conn, struct timeval t,
			 uint16_t flags)
{
	struct ldapsrv_connection *ldap_conn = conn->private_data;

	DEBUG(10,("ldapsrv_send\n"));

	if (!ldapsrv_write_buf(ldap_conn)) {
		ldapsrv_terminate_connection(ldap_conn, "ldapsrv_write_buf() failed");
		return;
	}

	if (ldap_conn->out_buffer.length == 0 && ldap_conn->sasl_out_buffer.length == 0) {
		conn->event.fde->flags &= ~EVENT_FD_WRITE;
	}

	return;
}

/*
  called when connection is idle
*/
static void ldapsrv_idle(struct server_connection *conn, struct timeval t)
{
	DEBUG(10,("ldapsrv_idle: not implemented!\n"));
	return;
}

static void ldapsrv_close(struct server_connection *conn, const char *reason)
{
	return;
}

/*
  initialise a server_context from a open socket and register a event handler
  for reading from that socket
*/
static void ldapsrv_accept(struct server_connection *conn)
{
	struct ldapsrv_connection *ldap_conn;

	DEBUG(10, ("ldapsrv_accept\n"));

	ldap_conn = talloc_p(conn, struct ldapsrv_connection);

	if (ldap_conn == NULL)
		return;

	ZERO_STRUCTP(ldap_conn);
	ldap_conn->connection = conn;
	ldap_conn->service = talloc_reference(ldap_conn, conn->service->private_data);

	conn->private_data = ldap_conn;

	return;
}

/*
  called on a fatal error that should cause this server to terminate
*/
static void ldapsrv_exit(struct server_service *service, const char *reason)
{
	DEBUG(10,("ldapsrv_exit\n"));
	return;
}

static const struct server_service_ops ldap_server_ops = {
	.name			= "ldap",
	.service_init		= ldapsrv_init,
	.accept_connection	= ldapsrv_accept,
	.recv_handler		= ldapsrv_recv,
	.send_handler		= ldapsrv_send,
	.idle_handler		= ldapsrv_idle,
	.close_connection	= ldapsrv_close,
	.service_exit		= ldapsrv_exit,	
};

const struct server_service_ops *ldapsrv_get_ops(void)
{
	return &ldap_server_ops;
}

NTSTATUS server_service_ldap_init(void)
{
	return NT_STATUS_OK;	
}
