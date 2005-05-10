/* 
   Unix SMB/CIFS implementation.

   cldap client library

   Copyright (C) Andrew Tridgell 2005
   
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

/*
  see RFC1798 for details of CLDAP

  basic properties
    - carried over UDP on port 389
    - request and response matched by message ID
    - request consists of only a single searchRequest element
    - response can be in one of two forms
       - a single searchResponse, followed by a searchResult
       - a single searchResult
*/

#include "includes.h"
#include "lib/events/events.h"
#include "dlinklist.h"
#include "libcli/ldap/ldap.h"
#include "libcli/cldap/cldap.h"
#include "lib/socket/socket.h"
#include "include/asn_1.h"

#define CLDAP_MAX_PACKET_SIZE 2048
const unsigned CLDAP_PORT = 389;

/*
  destroy a pending request
*/
static int cldap_request_destructor(void *ptr)
{
	struct cldap_request *req = talloc_get_type(ptr, struct cldap_request);
	if (req->state == CLDAP_REQUEST_SEND) {
		DLIST_REMOVE(req->cldap->send_queue, req);
	}
	if (req->message_id != 0) {
		idr_remove(req->cldap->idr, req->message_id);
		req->message_id = 0;
	}
	return 0;
}

/*
  handle recv events on a cldap socket
*/
static void cldap_socket_recv(struct cldap_socket *cldap)
{
	TALLOC_CTX *tmp_ctx = talloc_new(cldap);
	NTSTATUS status;
	const char *src_addr;
	int src_port;
	DATA_BLOB blob;
	size_t nread;
	struct asn1_data asn1;
	struct ldap_message ldap_msg;
	struct cldap_request *req;

	blob = data_blob_talloc(tmp_ctx, NULL, CLDAP_MAX_PACKET_SIZE);
	if (blob.data == NULL) {
		talloc_free(tmp_ctx);
		return;
	}

	status = socket_recvfrom(cldap->sock, blob.data, blob.length, &nread, 0,
				 &src_addr, &src_port);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return;
	}
	talloc_steal(tmp_ctx, src_addr);
	blob.length = nread;

	DEBUG(2,("Received cldap packet of length %d from %s:%d\n", 
		 blob.length, src_addr, src_port));

	if (!asn1_load(&asn1, blob)) {
		DEBUG(2,("Failed to setup for asn.1 decode\n"));
		talloc_free(tmp_ctx);
		return;
	}
	talloc_steal(tmp_ctx, asn1.data);

	ZERO_STRUCT(ldap_msg);
	ldap_msg.mem_ctx = tmp_ctx;

	/* this initial decode is used to find the message id */
	if (!ldap_decode(&asn1, &ldap_msg)) {
		DEBUG(2,("Failed to decode ldap message\n"));
		talloc_free(tmp_ctx);
		return;
	}

	/* find the pending request */
	req = idr_find(cldap->idr, ldap_msg.messageid);
	if (req == NULL) {
		DEBUG(2,("Mismatched cldap reply %u from %s:%d\n",
			 ldap_msg.messageid, src_addr, src_port));
		talloc_free(tmp_ctx);
		return;
	}

	req->asn1 = asn1;
	talloc_steal(req, asn1.data);
	req->asn1.ofs = 0;

	req->state = CLDAP_REQUEST_DONE;
	talloc_free(req->te);

	talloc_free(tmp_ctx);

	if (req->async.fn) {
		req->async.fn(req);
	}
}

/*
  handle request timeouts
*/
static void cldap_request_timeout(struct event_context *event_ctx, 
				  struct timed_event *te, struct timeval t,
				  void *private)
{
	struct cldap_request *req = talloc_get_type(private, struct cldap_request);

	/* possibly try again */
	if (req->num_retries != 0) {
		size_t len = req->encoded.length;

		req->num_retries--;

		socket_sendto(req->cldap->sock, &req->encoded, &len, 0, 
			      req->dest_addr, req->dest_port);

		req->te = event_add_timed(req->cldap->event_ctx, req, 
					  timeval_current_ofs(req->timeout, 0),
					  cldap_request_timeout, req);
		return;
	}

	req->state = CLDAP_REQUEST_TIMEOUT;
	if (req->async.fn) {
		req->async.fn(req);
	}
}

/*
  handle send events on a cldap socket
*/
static void cldap_socket_send(struct cldap_socket *cldap)
{
	struct cldap_request *req;
	NTSTATUS status;

	while ((req = cldap->send_queue)) {
		size_t len;
		
		len = req->encoded.length;
		status = socket_sendto(cldap->sock, &req->encoded, &len, 0, 
				       req->dest_addr, req->dest_port);
		if (NT_STATUS_IS_ERR(status)) {
			DEBUG(3,("Failed to send cldap request of length %u to %s:%d\n",
				 req->encoded.length, req->dest_addr, req->dest_port));
			DLIST_REMOVE(cldap->send_queue, req);
			talloc_free(req);
			continue;
		}

		if (!NT_STATUS_IS_OK(status)) return;

		DLIST_REMOVE(cldap->send_queue, req);

		req->state = CLDAP_REQUEST_WAIT;

		req->te = event_add_timed(cldap->event_ctx, req, 
					  timeval_current_ofs(req->timeout, 0),
					  cldap_request_timeout, req);

		EVENT_FD_READABLE(cldap->fde);
	}

	EVENT_FD_NOT_WRITEABLE(cldap->fde);
	return;
}


/*
  handle fd events on a cldap_socket
*/
static void cldap_socket_handler(struct event_context *ev, struct fd_event *fde,
				 uint16_t flags, void *private)
{
	struct cldap_socket *cldap = talloc_get_type(private, struct cldap_socket);
	if (flags & EVENT_FD_WRITE) {
		cldap_socket_send(cldap);
	} else if (flags & EVENT_FD_READ) {
		cldap_socket_recv(cldap);
	}
}

/*
  initialise a cldap_socket. The event_ctx is optional, if provided
  then operations will use that event context
*/
struct cldap_socket *cldap_socket_init(TALLOC_CTX *mem_ctx, 
				       struct event_context *event_ctx)
{
	struct cldap_socket *cldap;
	NTSTATUS status;

	cldap = talloc(mem_ctx, struct cldap_socket);
	if (cldap == NULL) goto failed;

	if (event_ctx == NULL) {
		cldap->event_ctx = event_context_init(cldap);
	} else {
		cldap->event_ctx = talloc_reference(cldap, event_ctx);
	}
	if (cldap->event_ctx == NULL) goto failed;

	cldap->idr = idr_init(cldap);
	if (cldap->idr == NULL) goto failed;

	status = socket_create("ip", SOCKET_TYPE_DGRAM, &cldap->sock, 0);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	talloc_steal(cldap, cldap->sock);

	cldap->fde = event_add_fd(cldap->event_ctx, cldap, 
				      socket_get_fd(cldap->sock), 0,
				      cldap_socket_handler, cldap);

	cldap->send_queue = NULL;
	
	return cldap;

failed:
	talloc_free(cldap);
	return NULL;
}


/*
  queue a cldap request for send
*/
struct cldap_request *cldap_search_send(struct cldap_socket *cldap, 
					struct cldap_search *io)
{
	struct ldap_message msg;
	struct cldap_request *req;
	struct ldap_SearchRequest *search;

	req = talloc_zero(cldap, struct cldap_request);
	if (req == NULL) goto failed;

	req->cldap       = cldap;
	req->state       = CLDAP_REQUEST_SEND;
	req->timeout     = io->in.timeout;
	req->num_retries = io->in.retries;

	req->dest_addr = talloc_strdup(req, io->in.dest_address);
	if (req->dest_addr == NULL) goto failed;
	req->dest_port = CLDAP_PORT;

	req->message_id = idr_get_new_random(cldap->idr, req, UINT16_MAX);
	if (req->message_id == -1) goto failed;

	talloc_set_destructor(req, cldap_request_destructor);

	msg.mem_ctx         = cldap;
	msg.messageid       = req->message_id;
	msg.type            = LDAP_TAG_SearchRequest;
	msg.num_controls    = 0;
	msg.controls        = NULL;
	search = &msg.r.SearchRequest;

	search->basedn         = "";
	search->scope          = LDAP_SEARCH_SCOPE_BASE;
	search->deref          = LDAP_DEREFERENCE_NEVER;
	search->timelimit      = 0;
	search->sizelimit      = 0;
	search->attributesonly = False;
	search->num_attributes = str_list_length(io->in.attributes);
	search->attributes     = io->in.attributes;
	search->filter         = io->in.filter;

	if (!ldap_encode(&msg, &req->encoded)) {
		DEBUG(0,("Failed to encode cldap message to %s:%d\n",
			 req->dest_addr, req->dest_port));
		goto failed;
	}
	talloc_steal(req, req->encoded.data);

	DLIST_ADD_END(cldap->send_queue, req, struct cldap_request *);

	EVENT_FD_WRITEABLE(cldap->fde);

	return req;

failed:
	talloc_free(req);
	return NULL;
}

/*
  receive a cldap reply
*/
NTSTATUS cldap_search_recv(struct cldap_request *req, 
			   TALLOC_CTX *mem_ctx, 
			   struct cldap_search *io)
{
	struct ldap_message ldap_msg;

	if (req == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	while (req->state < CLDAP_REQUEST_DONE) {
		if (event_loop_once(req->cldap->event_ctx) != 0) {
			talloc_free(req);
			return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
		}
	}

	if (req->state == CLDAP_REQUEST_TIMEOUT) {
		talloc_free(req);
		return NT_STATUS_IO_TIMEOUT;
	}

	ZERO_STRUCT(ldap_msg);
	ldap_msg.mem_ctx = mem_ctx;

	if (!ldap_decode(&req->asn1, &ldap_msg)) {
		talloc_free(req);
		return NT_STATUS_INVALID_PARAMETER;
	}

	ZERO_STRUCT(io->out);

	/* the first possible form has a search result in first place */
	if (ldap_msg.type == LDAP_TAG_SearchResultEntry) {
		io->out.response = talloc(mem_ctx, struct ldap_SearchResEntry);
		NT_STATUS_HAVE_NO_MEMORY(io->out.response);
		*io->out.response = ldap_msg.r.SearchResultEntry;

		/* decode the 2nd part */
		if (!ldap_decode(&req->asn1, &ldap_msg)) {
			talloc_free(req);
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	if (ldap_msg.type != LDAP_TAG_SearchResultDone) {
		talloc_free(req);
		return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}

	io->out.result = talloc(mem_ctx, struct ldap_Result);
	NT_STATUS_HAVE_NO_MEMORY(io->out.result);
	*io->out.result = ldap_msg.r.SearchResultDone;

	talloc_free(req);
	return NT_STATUS_OK;
}


/*
  synchronous cldap search
*/
NTSTATUS cldap_search(struct cldap_socket *cldap, 
		      TALLOC_CTX *mem_ctx, 
		      struct cldap_search *io)
{
	struct cldap_request *req = cldap_search_send(cldap, io);
	return cldap_search_recv(req, mem_ctx, io);
}


/*
  queue a cldap netlogon for send
*/
struct cldap_request *cldap_netlogon_send(struct cldap_socket *cldap, 
					  struct cldap_netlogon *io)
{
	struct cldap_search search;
	char *filter;
	struct cldap_request *req;
	const char *attr[] = { "NetLogon", NULL };

	filter = talloc_asprintf(cldap, 
				 "(&(DnsDomain=%s)(Host=%s)(NtVer=\\%02X\\00\\00\\00))", 
				 io->in.realm, io->in.host, io->in.version);
	if (filter == NULL) return NULL;

	search.in.dest_address = io->in.dest_address;
	search.in.filter       = filter;
	search.in.attributes   = attr;
	search.in.timeout      = 2;
	search.in.retries      = 2;

	req = cldap_search_send(cldap, &search);

	talloc_free(filter);

	return req;
}


/*
  receive a cldap netlogon reply
*/
NTSTATUS cldap_netlogon_recv(struct cldap_request *req, 
			     TALLOC_CTX *mem_ctx, 
			     struct cldap_netlogon *io)
{
	NTSTATUS status;
	struct cldap_search search;
	DATA_BLOB *data;

	status = cldap_search_recv(req, mem_ctx, &search);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (search.out.response == NULL) {
		return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}

	if (search.out.response->num_attributes != 1 ||
	    strcasecmp(search.out.response->attributes[0].name, "netlogon") != 0 ||
	    search.out.response->attributes[0].num_values != 1 ||
	    search.out.response->attributes[0].values->length < 2) {
		return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}
	data = search.out.response->attributes[0].values;

	status = ndr_pull_struct_blob_all(data, mem_ctx, &io->out.netlogon, 
					  (ndr_pull_flags_fn_t)ndr_pull_nbt_cldap_netlogon);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2,("cldap failed to parse netlogon response of type 0x%02x\n",
			 SVAL(data->data, 0)));
		dump_data(10, data->data, data->length);
	}

	return status;
}

/*
  sync cldap netlogon search
*/
NTSTATUS cldap_netlogon(struct cldap_socket *cldap, 
			TALLOC_CTX *mem_ctx, struct cldap_netlogon *io)
{
	struct cldap_request *req = cldap_netlogon_send(cldap, io);
	return cldap_netlogon_recv(req, mem_ctx, io);
}
