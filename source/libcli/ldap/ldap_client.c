/* 
   Unix SMB/CIFS mplementation.
   LDAP protocol helper functions for SAMBA
   
   Copyright (C) Andrew Tridgell  2004
   Copyright (C) Volker Lendecke 2004
   Copyright (C) Stefan Metzmacher 2004
   Copyright (C) Simo Sorce 2004
    
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
#include "asn_1.h"
#include "dlinklist.h"
#include "lib/events/events.h"
#include "lib/socket/socket.h"
#include "lib/tls/tls.h"
#include "libcli/ldap/ldap.h"
#include "libcli/ldap/ldap_client.h"


/*
  create a new ldap_connection stucture. The event context is optional
*/
struct ldap_connection *ldap_new_connection(TALLOC_CTX *mem_ctx, 
					    struct event_context *ev)
{
	struct ldap_connection *conn;

	conn = talloc_zero(mem_ctx, struct ldap_connection);
	if (conn == NULL) {
		return NULL;
	}

	if (ev == NULL) {
		ev = event_context_init(conn);
		if (ev == NULL) {
			talloc_free(conn);
			return NULL;
		}
	}

	conn->next_messageid  = 1;
	conn->event.event_ctx = ev;

	/* set a reasonable request timeout */
	conn->timeout = 60;

	return conn;
}


/*
  the connection is dead
*/
static void ldap_connection_dead(struct ldap_connection *conn)
{
	struct ldap_request *req;

	while (conn->pending) {
		req = conn->pending;
		DLIST_REMOVE(req->conn->pending, req);
		req->state = LDAP_REQUEST_DONE;
		req->status = NT_STATUS_UNEXPECTED_NETWORK_ERROR;
		if (req->async.fn) {
			req->async.fn(req);
		}
	}	

	while (conn->send_queue) {
		req = conn->send_queue;
		DLIST_REMOVE(req->conn->send_queue, req);
		req->state = LDAP_REQUEST_DONE;
		req->status = NT_STATUS_UNEXPECTED_NETWORK_ERROR;
		if (req->async.fn) {
			req->async.fn(req);
		}
	}

	talloc_free(conn->tls);
	conn->tls = NULL;
}


/*
  match up with a pending message, adding to the replies list
*/
static void ldap_match_message(struct ldap_connection *conn, struct ldap_message *msg)
{
	struct ldap_request *req;

	for (req=conn->pending; req; req=req->next) {
		if (req->messageid == msg->messageid) break;
	}
	/* match a zero message id to the last request sent.
	   It seems that servers send 0 if unable to parse */
	if (req == NULL && msg->messageid == 0) {
		req = conn->pending;
	}
	if (req == NULL) {
		DEBUG(0,("ldap: no matching message id for %u\n",
			 msg->messageid));
		talloc_free(msg);
		return;
	}

	/* add to the list of replies received */
	talloc_steal(req, msg);
	req->replies = talloc_realloc(req, req->replies, 
				      struct ldap_message *, req->num_replies+1);
	if (req->replies == NULL) {
		req->status = NT_STATUS_NO_MEMORY;
		req->state = LDAP_REQUEST_DONE;
		DLIST_REMOVE(conn->pending, req);
		if (req->async.fn) {
			req->async.fn(req);
		}
		return;
	}

	req->replies[req->num_replies] = talloc_steal(req->replies, msg);
	req->num_replies++;

	if (msg->type != LDAP_TAG_SearchResultEntry &&
	    msg->type != LDAP_TAG_SearchResultReference) {
		/* currently only search results expect multiple
		   replies */
		req->state = LDAP_REQUEST_DONE;
		DLIST_REMOVE(conn->pending, req);
	}

	if (req->async.fn) {
		req->async.fn(req);
	}
}

/*
  try and decode/process plain data
*/
static void ldap_try_decode_plain(struct ldap_connection *conn)
{
	struct asn1_data asn1;

	if (!asn1_load(&asn1, conn->partial)) {
		ldap_connection_dead(conn);
		return;
	}

	/* try and decode - this will fail if we don't have a full packet yet */
	while (asn1.ofs < asn1.length) {
		struct ldap_message *msg = talloc(conn, struct ldap_message);
		off_t saved_ofs = asn1.ofs;
			
		if (msg == NULL) {
			ldap_connection_dead(conn);
			return;
		}

		if (ldap_decode(&asn1, msg)) {
			ldap_match_message(conn, msg);
		} else {
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
static void ldap_try_decode_wrapped(struct ldap_connection *conn)
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
			ldap_connection_dead(conn);
			return;
		}

		wrapped.data   = conn->partial.data+4;
		wrapped.length = len;

		status = gensec_unwrap(conn->gensec, msg, &wrapped, &unwrapped);
		if (!NT_STATUS_IS_OK(status)) {
			ldap_connection_dead(conn);
			return;
		}

		if (!asn1_load(&asn1, unwrapped)) {
			ldap_connection_dead(conn);
			return;
		}

		while (ldap_decode(&asn1, msg)) {
			ldap_match_message(conn, msg);
			msg = talloc(conn, struct ldap_message);
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
  handle ldap recv events
*/
static void ldap_recv_handler(struct ldap_connection *conn)
{
	NTSTATUS status;
	size_t npending=0, nread;

	/* work out how much data is pending */
	status = tls_socket_pending(conn->tls, &npending);
	if (!NT_STATUS_IS_OK(status) || npending == 0) {
		ldap_connection_dead(conn);
		return;
	}

	conn->partial.data = talloc_realloc_size(conn, conn->partial.data, 
						 conn->partial.length + npending);
	if (conn->partial.data == NULL) {
		ldap_connection_dead(conn);
		return;
	}

	/* receive the pending data */
	status = tls_socket_recv(conn->tls, conn->partial.data + conn->partial.length,
				 npending, &nread);
	if (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
		return;
	}
	if (!NT_STATUS_IS_OK(status)) {
		ldap_connection_dead(conn);
		return;
	}
	conn->partial.length += nread;

	/* see if we can decode what we have */
	if (conn->enable_wrap) {
		ldap_try_decode_wrapped(conn);
	} else {
		ldap_try_decode_plain(conn);
	}
}


/*
  handle ldap send events
*/
static void ldap_send_handler(struct ldap_connection *conn)
{
	while (conn->send_queue) {
		struct ldap_request *req = conn->send_queue;
		size_t nsent;
		NTSTATUS status;

		status = tls_socket_send(conn->tls, &req->data, &nsent);
		if (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
			break;
		}
		if (!NT_STATUS_IS_OK(status)) {
			ldap_connection_dead(conn);
			return;
		}

		req->data.data += nsent;
		req->data.length -= nsent;
		if (req->data.length == 0) {
			req->state = LDAP_REQUEST_PENDING;
			DLIST_REMOVE(conn->send_queue, req);

			/* some types of requests don't expect a reply */
			if (req->type == LDAP_TAG_AbandonRequest ||
			    req->type == LDAP_TAG_UnbindRequest) {
				req->status = NT_STATUS_OK;
				req->state = LDAP_REQUEST_DONE;
				if (req->async.fn) {
					req->async.fn(req);
				}
			} else {
				DLIST_ADD(conn->pending, req);
			}
		}
	}
	if (conn->send_queue == NULL) {
		EVENT_FD_NOT_WRITEABLE(conn->event.fde);
	}
}


/*
  handle ldap socket events
*/
static void ldap_io_handler(struct event_context *ev, struct fd_event *fde, 
			    uint16_t flags, void *private)
{
	struct ldap_connection *conn = talloc_get_type(private, struct ldap_connection);
	if (flags & EVENT_FD_WRITE) {
		ldap_send_handler(conn);
		if (conn->tls == NULL) return;
	}
	if (flags & EVENT_FD_READ) {
		ldap_recv_handler(conn);
	}
}

/*
  parse a ldap URL
*/
static NTSTATUS ldap_parse_basic_url(TALLOC_CTX *mem_ctx, const char *url,
				     char **host, uint16_t *port, BOOL *ldaps)
{
	int tmp_port = 0;
	char protocol[11];
	char tmp_host[255];
	const char *p = url;
	int ret;

	/* skip leading "URL:" (if any) */
	if (strncasecmp(p, "URL:", 4) == 0) {
		p += 4;
	}

	/* Paranoia check */
	SMB_ASSERT(sizeof(protocol)>10 && sizeof(tmp_host)>254);
		
	ret = sscanf(p, "%10[^:]://%254[^:/]:%d", protocol, tmp_host, &tmp_port);
	if (ret < 2) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (strequal(protocol, "ldap")) {
		*port = 389;
		*ldaps = False;
	} else if (strequal(protocol, "ldaps")) {
		*port = 636;
		*ldaps = True;
	} else {
		DEBUG(0, ("unrecognised ldap protocol (%s)!\n", protocol));
		return NT_STATUS_PROTOCOL_UNREACHABLE;
	}

	if (tmp_port != 0)
		*port = tmp_port;

	*host = talloc_strdup(mem_ctx, tmp_host);
	NT_STATUS_HAVE_NO_MEMORY(*host);

	return NT_STATUS_OK;
}

/*
  connect to a ldap server
*/
NTSTATUS ldap_connect(struct ldap_connection *conn, const char *url)
{
	NTSTATUS status;

	status = ldap_parse_basic_url(conn, url, &conn->host,
				      &conn->port, &conn->ldaps);
	NT_STATUS_NOT_OK_RETURN(status);

	status = socket_create("ipv4", SOCKET_TYPE_STREAM, &conn->sock, 0);
	NT_STATUS_NOT_OK_RETURN(status);

	talloc_steal(conn, conn->sock);

	/* connect in a event friendly way */
	status = socket_connect_ev(conn->sock, NULL, 0, conn->host, conn->port, 0, 
				   conn->event.event_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(conn->sock);
		return status;
	}

	/* setup a handler for events on this socket */
	conn->event.fde = event_add_fd(conn->event.event_ctx, conn->sock, 
				       socket_get_fd(conn->sock), 
				       EVENT_FD_READ, ldap_io_handler, conn);
	if (conn->event.fde == NULL) {
		talloc_free(conn->sock);
		return NT_STATUS_INTERNAL_ERROR;
	}

	conn->tls = tls_init_client(conn->sock, conn->event.fde, conn->ldaps);
	if (conn->tls == NULL) {
		talloc_free(conn->sock);
		return NT_STATUS_INTERNAL_ERROR;
	}
	talloc_steal(conn, conn->tls);
	talloc_steal(conn->tls, conn->sock);

	return NT_STATUS_OK;
}

/* destroy an open ldap request */
static int ldap_request_destructor(void *ptr)
{
	struct ldap_request *req = talloc_get_type(ptr, struct ldap_request);
	if (req->state == LDAP_REQUEST_SEND) {
		DLIST_REMOVE(req->conn->send_queue, req);
	}
	if (req->state == LDAP_REQUEST_PENDING) {
		DLIST_REMOVE(req->conn->pending, req);
	}
	return 0;
}

/*
  called on timeout of a ldap request
*/
static void ldap_request_timeout(struct event_context *ev, struct timed_event *te, 
				      struct timeval t, void *private)
{
	struct ldap_request *req = talloc_get_type(private, struct ldap_request);
	req->status = NT_STATUS_IO_TIMEOUT;
	if (req->state == LDAP_REQUEST_SEND) {
		DLIST_REMOVE(req->conn->send_queue, req);
	}
	if (req->state == LDAP_REQUEST_PENDING) {
		DLIST_REMOVE(req->conn->pending, req);
	}
	req->state = LDAP_REQUEST_DONE;
	if (req->async.fn) {
		req->async.fn(req);
	}
}

/*
  send a ldap message - async interface
*/
struct ldap_request *ldap_request_send(struct ldap_connection *conn,
				       struct ldap_message *msg)
{
	struct ldap_request *req;

	if (conn->tls == NULL) {
		return NULL;
	}

	req = talloc_zero(conn, struct ldap_request);
	if (req == NULL) goto failed;

	req->state       = LDAP_REQUEST_SEND;
	req->conn        = conn;
	req->messageid   = conn->next_messageid++;
	if (conn->next_messageid == 0) {
		conn->next_messageid = 1;
	}
	req->type        = msg->type;
	if (req->messageid == -1) {
		goto failed;
	}

	talloc_set_destructor(req, ldap_request_destructor);

	msg->messageid = req->messageid;

	if (!ldap_encode(msg, &req->data)) {
		goto failed;		
	}

	/* possibly encrypt/sign the request */
	if (conn->enable_wrap) {
		DATA_BLOB wrapped;
		NTSTATUS status;

		status = gensec_wrap(conn->gensec, req, &req->data, &wrapped);
		if (!NT_STATUS_IS_OK(status)) {
			goto failed;
		}
		data_blob_free(&req->data);
		req->data = data_blob_talloc(req, NULL, wrapped.length + 4);
		if (req->data.data == NULL) {
			goto failed;
		}
		RSIVAL(req->data.data, 0, wrapped.length);
		memcpy(req->data.data+4, wrapped.data, wrapped.length);
		data_blob_free(&wrapped);
	}


	if (conn->send_queue == NULL) {
		EVENT_FD_WRITEABLE(conn->event.fde);
	}
	DLIST_ADD_END(conn->send_queue, req, struct ldap_request *);

	/* put a timeout on the request */
	event_add_timed(conn->event.event_ctx, req, 
			timeval_current_ofs(conn->timeout, 0),
			ldap_request_timeout, req);

	return req;

failed:
	talloc_free(req);
	return NULL;
}


/*
  wait for a request to complete
  note that this does not destroy the request
*/
NTSTATUS ldap_request_wait(struct ldap_request *req)
{
	while (req->state != LDAP_REQUEST_DONE) {
		if (event_loop_once(req->conn->event.event_ctx) != 0) {
			req->status = NT_STATUS_UNEXPECTED_NETWORK_ERROR;
			break;
		}
	}
	return req->status;
}


/*
  used to setup the status code from a ldap response
*/
NTSTATUS ldap_check_response(struct ldap_connection *conn, struct ldap_Result *r)
{
	if (r->resultcode == LDAP_SUCCESS) {
		return NT_STATUS_OK;
	}

	if (conn->last_error) {
		talloc_free(conn->last_error);
	}
	conn->last_error = talloc_asprintf(conn, "LDAP error %u - %s <%s> <%s>", 
					   r->resultcode,
					   r->dn?r->dn:"(NULL)", 
					   r->errormessage?r->errormessage:"", 
					   r->referral?r->referral:"");
	
	return NT_STATUS_LDAP(r->resultcode);
}

/*
  return error string representing the last error
*/
const char *ldap_errstr(struct ldap_connection *conn, NTSTATUS status)
{
	if (NT_STATUS_IS_LDAP(status) && conn->last_error != NULL) {
		return conn->last_error;
	}
	return nt_errstr(status);
}


/*
  return the Nth result message, waiting if necessary
*/
NTSTATUS ldap_result_n(struct ldap_request *req, int n, struct ldap_message **msg)
{
	*msg = NULL;

	NT_STATUS_HAVE_NO_MEMORY(req);

	while (req->state != LDAP_REQUEST_DONE && n >= req->num_replies) {
		if (event_loop_once(req->conn->event.event_ctx) != 0) {
			return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
		}
	}

	if (n < req->num_replies) {
		*msg = req->replies[n];
		return NT_STATUS_OK;
	}

	if (!NT_STATUS_IS_OK(req->status)) {
		return req->status;
	}

	return NT_STATUS_NO_MORE_ENTRIES;
}


/*
  return a single result message, checking if it is of the expected LDAP type
*/
NTSTATUS ldap_result_one(struct ldap_request *req, struct ldap_message **msg, int type)
{
	NTSTATUS status;
	status = ldap_result_n(req, 0, msg);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if ((*msg)->type != type) {
		*msg = NULL;
		return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}
	return status;
}

/*
  a simple ldap transaction, for single result requests that only need a status code
  this relies on single valued requests having the response type == request type + 1
*/
NTSTATUS ldap_transaction(struct ldap_connection *conn, struct ldap_message *msg)
{
	struct ldap_request *req = ldap_request_send(conn, msg);
	struct ldap_message *res;
	NTSTATUS status;
	status = ldap_result_n(req, 0, &res);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(req);
		return status;
	}
	if (res->type != msg->type + 1) {
		talloc_free(req);
		return NT_STATUS_LDAP(LDAP_PROTOCOL_ERROR);
	}
	status = ldap_check_response(conn, &res->r.GeneralResult);
	talloc_free(req);
	return status;
}
