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

/*
  close the socket and shutdown a server_context
*/
void ldapsrv_terminate_connection(struct ldapsrv_connection *ldap_conn, const char *reason)
{
	server_terminate_connection(ldap_conn->connection, reason);
}

/*
  add a socket address to the list of events, one event per port
*/
static void add_socket(struct server_service *service, 
		       const struct model_ops *model_ops, 
		       struct in_addr *ifip)
{
	struct server_socket *srv_sock;
	uint16_t port = 389;
	char *ip_str = talloc_strdup(service->mem_ctx, inet_ntoa(*ifip));

	srv_sock = service_setup_socket(service, model_ops, ip_str, &port);

	talloc_free(ip_str);
}

/****************************************************************************
 Open the socket communication.
****************************************************************************/
static void ldapsrv_init(struct server_service *service,
			 const struct model_ops *model_ops)
{	
	DEBUG(1,("ldapsrv_init\n"));

	if (lp_interfaces() && lp_bind_interfaces_only()) {
		int num_interfaces = iface_count();
		int i;

		/* We have been given an interfaces line, and been 
		   told to only bind to those interfaces. Create a
		   socket per interface and bind to only these.
		*/
		for(i = 0; i < num_interfaces; i++) {
			struct in_addr *ifip = iface_n_ip(i);

			if (ifip == NULL) {
				DEBUG(0,("ldapsrv_init: interface %d has NULL "
					 "IP address !\n", i));
				continue;
			}

			add_socket(service, model_ops, ifip);
		}
	} else {
		struct in_addr *ifip;
		TALLOC_CTX *mem_ctx = talloc_init("ldapsrv_init");

		if (!mem_ctx) {
			smb_panic("No memory");
		}	

		/* Just bind to lp_socket_address() (usually 0.0.0.0) */
		ifip = interpret_addr2(mem_ctx, lp_socket_address());
		add_socket(service, model_ops, ifip);

		talloc_destroy(mem_ctx);
	}
}

/* This rw-buf api is made to avoid memcpy. For now do that like mad...  The
   idea is to write into a circular list of buffers where the ideal case is
   that a read(2) holds a complete request that is then thrown away
   completely. */

static void consumed_from_buf(struct rw_buffer *buf,
				   size_t length)
{
	memcpy(buf->data, buf->data+length, buf->length-length);
	buf->length -= length;
}

static BOOL append_to_buf(struct rw_buffer *buf, uint8_t *data, size_t length)
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

	status = socket_recv(sock, sock, &tmp_blob, 1024, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("socket_recv: %s\n",nt_errstr(status)));
		return False;
	}

	ret = append_to_buf(buf, tmp_blob.data, tmp_blob.length);

	talloc_free(tmp_blob.data);

	return ret;
}

static BOOL write_from_buf(struct socket_context *sock, struct rw_buffer *buf)
{
	NTSTATUS status;
	DATA_BLOB tmp_blob;
	size_t sendlen;

	tmp_blob.data = buf->data;
	tmp_blob.length = buf->length;

	status = socket_send(sock, sock, &tmp_blob, &sendlen, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("socket_send() %s\n",nt_errstr(status)));
		return False;
	}

	consumed_from_buf(buf, sendlen);

	return True;
}

static void peek_into_read_buf(struct rw_buffer *buf, uint8_t **out,
			       size_t *out_length)
{
	*out = buf->data;
	*out_length = buf->length;
}

static BOOL ldap_append_to_buf(struct ldap_message *msg, struct rw_buffer *buf)
{
	DATA_BLOB blob;
	BOOL res;

	if (!ldap_encode(msg, &blob))
		return False;

	res = append_to_buf(buf, blob.data, blob.length);

	data_blob_free(&blob);
	return res;
}

struct ldapsrv_reply *ldapsrv_init_reply(struct ldapsrv_call *call, enum ldap_request_tag type)
{
	struct ldapsrv_reply *reply;

	reply = talloc_p(call, struct ldapsrv_reply);
	if (!reply) {
		return NULL;
	}

	reply->prev = reply->next = NULL;
	reply->state = LDAPSRV_REPLY_STATE_NEW;
	reply->msg.messageid = call->request.messageid;
	reply->msg.type = type;
	reply->msg.mem_ctx = reply;

	return reply;
}

void ldapsrv_queue_reply(struct ldapsrv_call *call, struct ldapsrv_reply *reply)
{
	DLIST_ADD_END(call->replies, reply, struct ldapsrv_reply *);
}

struct ldapsrv_partition *ldapsrv_get_partition(struct ldapsrv_connection *conn, const char *dn)
{
	static const struct ldapsrv_partition_ops null_ops;
	static struct ldapsrv_partition null_part = {
		.ops = &null_ops
	};

	return &null_part;
}

void ldapsrv_unwilling(struct ldapsrv_call *call, int error)
{
	struct ldapsrv_reply *reply;
	struct ldap_ExtendedResponse *r;

	DEBUG(0,("Unwilling type[%d] id[%d]\n", call->request.type, call->request.messageid));

	reply = ldapsrv_init_reply(call, LDAP_TAG_ExtendedResponse);
	if (!reply) {
		ldapsrv_terminate_connection(call->conn, "ldapsrv_init_reply() failed");
		return;
	}

	r = &reply->msg.r.ExtendedResponse;
	r->response.resultcode = error;
	r->response.dn = NULL;
	r->response.errormessage = NULL;
	r->response.referral = NULL;
	r->name = NULL;
	r->value.data = NULL;
	r->value.length = 0;

	ldapsrv_queue_reply(call, reply);
}

static void ldapsrv_BindRequest(struct ldapsrv_call *call)
{
	struct ldap_BindRequest *req = &call->request.r.BindRequest;
	struct ldapsrv_reply *reply;
	struct ldap_BindResponse *resp;

	DEBUG(5, ("BindRequest dn: %s\n",req->dn));

	reply = ldapsrv_init_reply(call, LDAP_TAG_BindResponse);
	if (!reply) {
		ldapsrv_terminate_connection(call->conn, "ldapsrv_init_reply() failed");
		return;
	}

	resp = &reply->msg.r.BindResponse;
	resp->response.resultcode = 0;
	resp->response.dn = NULL;
	resp->response.errormessage = NULL;
	resp->response.referral = NULL;
	resp->SASL.secblob = data_blob(NULL, 0);

	ldapsrv_queue_reply(call, reply);
}

static void ldapsrv_UnbindRequest(struct ldapsrv_call *call)
{
/*	struct ldap_UnbindRequest *req = &call->request->r.UnbindRequest;*/
	DEBUG(10, ("UnbindRequest\n"));
}

static void ldapsrv_SearchRequest(struct ldapsrv_call *call)
{
	struct ldap_SearchRequest *req = &call->request.r.SearchRequest;
	struct ldapsrv_partition *part;

	DEBUG(10, ("SearchRequest"));
	DEBUGADD(10, (" basedn: %s", req->basedn));
	DEBUGADD(10, (" filter: %s\n", req->filter));

	if ((strcasecmp("", req->basedn) == 0) &&
	    (req->scope == LDAP_SEARCH_SCOPE_BASE)) {
		ldapsrv_RootDSE_Search(call, req);
		return;
	} 

	part = ldapsrv_get_partition(call->conn, req->basedn);

	if (!part->ops->Search) {
		ldapsrv_unwilling(call, 2);
		return;
	}

	part->ops->Search(part, call, req);
}

static void ldapsrv_ModifyRequest(struct ldapsrv_call *call)
{
	struct ldap_ModifyRequest *req = &call->request.r.ModifyRequest;
	struct ldapsrv_partition *part;

	DEBUG(10, ("ModifyRequest"));
	DEBUGADD(10, (" dn: %s", req->dn));

	part = ldapsrv_get_partition(call->conn, req->dn);

	if (!part->ops->Modify) {
		ldapsrv_unwilling(call, 2);
		return;
	}

	part->ops->Modify(part, call, req);
}

static void ldapsrv_AddRequest(struct ldapsrv_call *call)
{
	struct ldap_AddRequest *req = &call->request.r.AddRequest;
	struct ldapsrv_partition *part;

	DEBUG(10, ("AddRequest"));
	DEBUGADD(10, (" dn: %s", req->dn));

	part = ldapsrv_get_partition(call->conn, req->dn);

	if (!part->ops->Add) {
		ldapsrv_unwilling(call, 2);
		return;
	}

	part->ops->Add(part, call, req);
}

static void ldapsrv_DelRequest(struct ldapsrv_call *call)
{
	struct ldap_DelRequest *req = &call->request.r.DelRequest;
	struct ldapsrv_partition *part;

	DEBUG(10, ("DelRequest"));
	DEBUGADD(10, (" dn: %s", req->dn));

	part = ldapsrv_get_partition(call->conn, req->dn);

	if (!part->ops->Del) {
		ldapsrv_unwilling(call, 2);
		return;
	}

	part->ops->Del(part, call, req);
}

static void ldapsrv_ModifyDNRequest(struct ldapsrv_call *call)
{
	struct ldap_ModifyDNRequest *req = &call->request.r.ModifyDNRequest;
	struct ldapsrv_partition *part;

	DEBUG(10, ("ModifyDNRequrest"));
	DEBUGADD(10, (" dn: %s", req->dn));
	DEBUGADD(10, (" newrdn: %s", req->newrdn));

	part = ldapsrv_get_partition(call->conn, req->dn);

	if (!part->ops->ModifyDN) {
		ldapsrv_unwilling(call, 2);
		return;
	}

	part->ops->ModifyDN(part, call, req);
}

static void ldapsrv_CompareRequest(struct ldapsrv_call *call)
{
	struct ldap_CompareRequest *req = &call->request.r.CompareRequest;
	struct ldapsrv_partition *part;

	DEBUG(10, ("CompareRequest"));
	DEBUGADD(10, (" dn: %s", req->dn));

	part = ldapsrv_get_partition(call->conn, req->dn);

	if (!part->ops->Compare) {
		ldapsrv_unwilling(call, 2);
		return;
	}

	part->ops->Compare(part, call, req);
}

static void ldapsrv_AbandonRequest(struct ldapsrv_call *call)
{
/*	struct ldap_AbandonRequest *req = &call->request.r.AbandonRequest;*/
	DEBUG(10, ("AbandonRequest\n"));
}

static void ldapsrv_ExtendedRequest(struct ldapsrv_call *call)
{
/*	struct ldap_ExtendedRequest *req = &call->request.r.ExtendedRequest;*/
	struct ldapsrv_reply *reply;

	DEBUG(10, ("Extended\n"));

	reply = ldapsrv_init_reply(call, LDAP_TAG_ExtendedResponse);
	if (!reply) {
		ldapsrv_terminate_connection(call->conn, "ldapsrv_init_reply() failed");
		return;
	}

	ZERO_STRUCT(reply->msg.r);

	ldapsrv_queue_reply(call, reply);
}

static void ldapsrv_do_call(struct ldapsrv_call *call)
{
	switch(call->request.type) {
	case LDAP_TAG_BindRequest:
		ldapsrv_BindRequest(call);
		break;
	case LDAP_TAG_UnbindRequest:
		ldapsrv_UnbindRequest(call);
		break;
	case LDAP_TAG_SearchRequest:
		ldapsrv_SearchRequest(call);
		break;
	case LDAP_TAG_ModifyRequest:
		ldapsrv_ModifyRequest(call);
		break;
	case LDAP_TAG_AddRequest:
		ldapsrv_AddRequest(call);
		break;
	case LDAP_TAG_DelRequest:
		ldapsrv_DelRequest(call);
		break;
	case LDAP_TAG_ModifyDNRequest:
		ldapsrv_ModifyDNRequest(call);
		break;
	case LDAP_TAG_CompareRequest:
		ldapsrv_CompareRequest(call);
		break;
	case LDAP_TAG_AbandonRequest:
		ldapsrv_AbandonRequest(call);
		break;
	case LDAP_TAG_ExtendedRequest:
		ldapsrv_ExtendedRequest(call);
		break;
	default:
		ldapsrv_unwilling(call, 2);
		break;
	}
}

static void ldapsrv_do_responses(struct ldapsrv_connection *conn)
{
	struct ldapsrv_call *call, *next_call = NULL;
	struct ldapsrv_reply *reply, *next_reply = NULL;

	for (call=conn->calls; call; call=next_call) {
		for (reply=call->replies; reply; reply=next_reply) {
			if (!ldap_append_to_buf(&reply->msg, &conn->out_buffer)) {
				ldapsrv_terminate_connection(conn, "append_to_buf() failed");
				return;
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
}

/*
  called when a LDAP socket becomes readable
*/
static void ldapsrv_recv(struct server_connection *conn, time_t t,
			 uint16_t flags)
{
	struct ldapsrv_connection *ldap_conn = conn->private_data;
	uint8_t *buf;
	int buf_length, msg_length;
	DATA_BLOB blob;
	ASN1_DATA data;
	struct ldapsrv_call *call;

	DEBUG(10,("ldapsrv_recv\n"));

	if (!read_into_buf(conn->socket, &ldap_conn->in_buffer)) {
		ldapsrv_terminate_connection(ldap_conn, "read_into_buf() failed");
		return;
	}

	peek_into_read_buf(&ldap_conn->in_buffer, &buf, &buf_length);

	while (buf_length > 0) {

		peek_into_read_buf(&ldap_conn->in_buffer, &buf, &buf_length);
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
			ldapsrv_terminate_connection(ldap_conn, "ldap_decode() failed");
			return;
		}

		DLIST_ADD_END(ldap_conn->calls, call,
			      struct ldapsrv_call *);

		consumed_from_buf(&ldap_conn->in_buffer, msg_length);

		ldapsrv_do_call(call);

		peek_into_read_buf(&ldap_conn->in_buffer, &buf, &buf_length);
	}

	ldapsrv_do_responses(ldap_conn);

	if (ldap_conn->out_buffer.length > 0) {
		conn->event.fde->flags |= EVENT_FD_WRITE;
	}

	return;
}
	
/*
  called when a LDAP socket becomes writable
*/
static void ldapsrv_send(struct server_connection *conn, time_t t,
			 uint16_t flags)
{
	struct ldapsrv_connection *ldap_conn = conn->private_data;

	DEBUG(10,("ldapsrv_send\n"));

	if (!write_from_buf(conn->socket, &ldap_conn->out_buffer)) {
		ldapsrv_terminate_connection(ldap_conn, "write_from_buf() failed");
		return;
	}

	if (ldap_conn->out_buffer.length == 0) {
		conn->event.fde->flags &= ~EVENT_FD_WRITE;
	}

	return;
}

/*
  called when connection is idle
*/
static void ldapsrv_idle(struct server_connection *conn, time_t t)
{
	DEBUG(10,("ldapsrv_idle: not implemented!\n"));
	return;
}

static void ldapsrv_close(struct server_connection *conn, const char *reason)
{
	struct ldapsrv_connection *ldap_conn = conn->private_data;

	talloc_free(ldap_conn);

	return;
}

/*
  initialise a server_context from a open socket and register a event handler
  for reading from that socket
*/
static void ldapsrv_accept(struct server_connection *conn)
{
	struct ldapsrv_connection *ldap_conn;

	DEBUG(5, ("ldapsrv_accept\n"));

	ldap_conn = talloc_p(NULL, struct ldapsrv_connection);

	if (ldap_conn == NULL)
		return;

	ZERO_STRUCTP(ldap_conn);
	ldap_conn->connection = conn;

	conn->private_data = ldap_conn;

	return;
}

/*
  called on a fatal error that should cause this server to terminate
*/
static void ldapsrv_exit(struct server_service *service, const char *reason)
{
	DEBUG(1,("ldapsrv_exit\n"));
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
