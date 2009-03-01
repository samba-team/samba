/* 
   Unix SMB/CIFS implementation.

   cldap client library

   Copyright (C) Andrew Tridgell 2005
   
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
#include "../lib/util/dlinklist.h"
#include "libcli/ldap/ldap.h"
#include "libcli/ldap/ldap_ndr.h"
#include "libcli/cldap/cldap.h"
#include "lib/socket/socket.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_nbt.h"

/*
  destroy a pending request
*/
static int cldap_request_destructor(struct cldap_request *req)
{
	if (req->state == CLDAP_REQUEST_SEND) {
		DLIST_REMOVE(req->cldap->send_queue, req);
	}
	if (!req->is_reply && req->message_id != 0) {
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
	struct socket_address *src;
	DATA_BLOB blob;
	size_t nread, dsize;
	struct asn1_data *asn1 = asn1_init(tmp_ctx);
	struct ldap_message *ldap_msg;
	struct cldap_request *req;

	if (!asn1) return;

	status = socket_pending(cldap->sock, &dsize);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return;
	}

	blob = data_blob_talloc(tmp_ctx, NULL, dsize);
	if (blob.data == NULL) {
		talloc_free(tmp_ctx);
		return;
	}

	status = socket_recvfrom(cldap->sock, blob.data, blob.length, &nread,
				 tmp_ctx, &src);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return;
	}
	blob.length = nread;

	DEBUG(2,("Received cldap packet of length %d from %s:%d\n", 
		 (int)blob.length, src->addr, src->port));

	if (!asn1_load(asn1, blob)) {
		DEBUG(2,("Failed to setup for asn.1 decode\n"));
		talloc_free(tmp_ctx);
		return;
	}

	ldap_msg = talloc(tmp_ctx, struct ldap_message);
	if (ldap_msg == NULL) {
		talloc_free(tmp_ctx);
		return;
	}

	/* this initial decode is used to find the message id */
	status = ldap_decode(asn1, NULL, ldap_msg);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2,("Failed to decode ldap message: %s\n", nt_errstr(status)));
		talloc_free(tmp_ctx);
		return;
	}

	/* find the pending request */
	req = idr_find(cldap->idr, ldap_msg->messageid);
	if (req == NULL) {
		if (cldap->incoming.handler) {
			cldap->incoming.handler(cldap, ldap_msg, src);
		} else {
			DEBUG(2,("Mismatched cldap reply %u from %s:%d\n",
				 ldap_msg->messageid, src->addr, src->port));
		}
		talloc_free(tmp_ctx);
		return;
	}

	req->asn1 = talloc_steal(req, asn1);
	req->asn1->ofs = 0;

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
static void cldap_request_timeout(struct tevent_context *event_ctx, 
				  struct tevent_timer *te, struct timeval t,
				  void *private_data)
{
	struct cldap_request *req = talloc_get_type(private_data, struct cldap_request);

	/* possibly try again */
	if (req->num_retries != 0) {
		size_t len = req->encoded.length;

		req->num_retries--;

		socket_sendto(req->cldap->sock, &req->encoded, &len, 
			      req->dest);

		req->te = event_add_timed(req->cldap->event_ctx, req, 
					  timeval_current_ofs(req->timeout, 0),
					  cldap_request_timeout, req);
		return;
	}

	req->state = CLDAP_REQUEST_ERROR;
	req->status = NT_STATUS_IO_TIMEOUT;
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
		status = socket_sendto(cldap->sock, &req->encoded, &len,
				       req->dest);
		if (NT_STATUS_IS_ERR(status)) {
			DEBUG(0,("Failed to send cldap request of length %u to %s:%d\n",
				 (unsigned)req->encoded.length, req->dest->addr, req->dest->port));
			DLIST_REMOVE(cldap->send_queue, req);
			req->state = CLDAP_REQUEST_ERROR;
			req->status = status;
			if (req->async.fn) {
				req->async.fn(req);
			}
			continue;
		}

		if (!NT_STATUS_IS_OK(status)) return;

		DLIST_REMOVE(cldap->send_queue, req);

		if (req->is_reply) {
			talloc_free(req);
		} else {
			req->state = CLDAP_REQUEST_WAIT;

			req->te = event_add_timed(cldap->event_ctx, req, 
						  timeval_current_ofs(req->timeout, 0),
						  cldap_request_timeout, req);

			EVENT_FD_READABLE(cldap->fde);
		}
	}

	EVENT_FD_NOT_WRITEABLE(cldap->fde);
	return;
}


/*
  handle fd events on a cldap_socket
*/
static void cldap_socket_handler(struct tevent_context *ev, struct tevent_fd *fde,
				 uint16_t flags, void *private_data)
{
	struct cldap_socket *cldap = talloc_get_type(private_data, struct cldap_socket);
	if (flags & EVENT_FD_WRITE) {
		cldap_socket_send(cldap);
	} 
	if (flags & EVENT_FD_READ) {
		cldap_socket_recv(cldap);
	}
}

/*
  initialise a cldap_socket. The event_ctx is optional, if provided
  then operations will use that event context
*/
struct cldap_socket *cldap_socket_init(TALLOC_CTX *mem_ctx, 
				       struct tevent_context *event_ctx,
				       struct smb_iconv_convenience *iconv_convenience)
{
	struct cldap_socket *cldap;
	NTSTATUS status;

	cldap = talloc(mem_ctx, struct cldap_socket);
	if (cldap == NULL) goto failed;

	cldap->event_ctx = talloc_reference(cldap, event_ctx);
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
	cldap->incoming.handler = NULL;
	cldap->iconv_convenience = iconv_convenience;
	
	return cldap;

failed:
	talloc_free(cldap);
	return NULL;
}


/*
  setup a handler for incoming requests
*/
NTSTATUS cldap_set_incoming_handler(struct cldap_socket *cldap,
				  void (*handler)(struct cldap_socket *, struct ldap_message *, 
						  struct socket_address *),
				  void *private_data)
{
	cldap->incoming.handler = handler;
	cldap->incoming.private_data = private_data;
	EVENT_FD_READABLE(cldap->fde);
	return NT_STATUS_OK;
}

/*
  queue a cldap request for send
*/
struct cldap_request *cldap_search_send(struct cldap_socket *cldap, 
					struct cldap_search *io)
{
	struct ldap_message *msg;
	struct cldap_request *req;
	struct ldap_SearchRequest *search;

	req = talloc_zero(cldap, struct cldap_request);
	if (req == NULL) goto failed;

	req->cldap       = cldap;
	req->state       = CLDAP_REQUEST_SEND;
	req->timeout     = io->in.timeout;
	req->num_retries = io->in.retries;
	req->is_reply    = false;
	req->asn1        = asn1_init(req);
	if (!req->asn1) {
		goto failed;
	}

	req->dest = socket_address_from_strings(req, cldap->sock->backend_name,
						io->in.dest_address, 
						io->in.dest_port);
	if (!req->dest) goto failed;

	req->message_id = idr_get_new_random(cldap->idr, req, UINT16_MAX);
	if (req->message_id == -1) goto failed;

	talloc_set_destructor(req, cldap_request_destructor);

	msg = talloc(req, struct ldap_message);
	if (msg == NULL) goto failed;
	msg->messageid       = req->message_id;
	msg->type            = LDAP_TAG_SearchRequest;
	msg->controls        = NULL;
	search = &msg->r.SearchRequest;

	search->basedn         = "";
	search->scope          = LDAP_SEARCH_SCOPE_BASE;
	search->deref          = LDAP_DEREFERENCE_NEVER;
	search->timelimit      = 0;
	search->sizelimit      = 0;
	search->attributesonly = false;
	search->num_attributes = str_list_length(io->in.attributes);
	search->attributes     = io->in.attributes;
	search->tree           = ldb_parse_tree(req, io->in.filter);
	if (search->tree == NULL) {
		goto failed;
	}

	if (!ldap_encode(msg, NULL, &req->encoded, req)) {
		DEBUG(0,("Failed to encode cldap message to %s:%d\n",
			 req->dest->addr, req->dest->port));
		goto failed;
	}

	DLIST_ADD_END(cldap->send_queue, req, struct cldap_request *);

	EVENT_FD_WRITEABLE(cldap->fde);

	return req;

failed:
	talloc_free(req);
	return NULL;
}


/*
  queue a cldap reply for send
*/
NTSTATUS cldap_reply_send(struct cldap_socket *cldap, struct cldap_reply *io)
{
	struct ldap_message *msg;
	struct cldap_request *req;
	DATA_BLOB blob1, blob2;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	req = talloc_zero(cldap, struct cldap_request);
	if (req == NULL) goto failed;

	req->cldap       = cldap;
	req->state       = CLDAP_REQUEST_SEND;
	req->is_reply    = true;
	req->asn1        = asn1_init(req);
	if (!req->asn1) {
		goto failed;
	}

	req->dest        = io->dest;
	if (talloc_reference(req, io->dest) == NULL) goto failed;

	talloc_set_destructor(req, cldap_request_destructor);

	msg = talloc(req, struct ldap_message);
	if (msg == NULL) goto failed;
	msg->messageid       = io->messageid;
	msg->controls        = NULL;
	
	if (io->response) {
		msg->type = LDAP_TAG_SearchResultEntry;
		msg->r.SearchResultEntry = *io->response;

		if (!ldap_encode(msg, NULL, &blob1, req)) {
			DEBUG(0,("Failed to encode cldap message to %s:%d\n",
				 req->dest->addr, req->dest->port));
			status = NT_STATUS_INVALID_PARAMETER;
			goto failed;
		}
	} else {
		blob1 = data_blob(NULL, 0);
	}

	msg->type = LDAP_TAG_SearchResultDone;
	msg->r.SearchResultDone = *io->result;

	if (!ldap_encode(msg, NULL, &blob2, req)) {
		DEBUG(0,("Failed to encode cldap message to %s:%d\n",
			 req->dest->addr, req->dest->port));
		status = NT_STATUS_INVALID_PARAMETER;
		goto failed;
	}

	req->encoded = data_blob_talloc(req, NULL, blob1.length + blob2.length);
	if (req->encoded.data == NULL) goto failed;

	memcpy(req->encoded.data, blob1.data, blob1.length);
	memcpy(req->encoded.data+blob1.length, blob2.data, blob2.length);

	DLIST_ADD_END(cldap->send_queue, req, struct cldap_request *);

	EVENT_FD_WRITEABLE(cldap->fde);

	return NT_STATUS_OK;

failed:
	talloc_free(req);
	return status;
}

/*
  receive a cldap reply
*/
NTSTATUS cldap_search_recv(struct cldap_request *req, 
			   TALLOC_CTX *mem_ctx, 
			   struct cldap_search *io)
{
	struct ldap_message *ldap_msg;
	NTSTATUS status;

	if (req == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	while (req->state < CLDAP_REQUEST_DONE) {
		if (event_loop_once(req->cldap->event_ctx) != 0) {
			talloc_free(req);
			return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
		}
	}

	if (req->state == CLDAP_REQUEST_ERROR) {
		status = req->status;
		talloc_free(req);
		return status;
	}

	ldap_msg = talloc(mem_ctx, struct ldap_message);
	NT_STATUS_HAVE_NO_MEMORY(ldap_msg);

	status = ldap_decode(req->asn1, NULL, ldap_msg);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2,("Failed to decode cldap search reply: %s\n", nt_errstr(status)));
		talloc_free(req);
		return status;
	}

	ZERO_STRUCT(io->out);

	/* the first possible form has a search result in first place */
	if (ldap_msg->type == LDAP_TAG_SearchResultEntry) {
		io->out.response = talloc(mem_ctx, struct ldap_SearchResEntry);
		NT_STATUS_HAVE_NO_MEMORY(io->out.response);
		*io->out.response = ldap_msg->r.SearchResultEntry;

		/* decode the 2nd part */
		status = ldap_decode(req->asn1, NULL, ldap_msg);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(2,("Failed to decode cldap search result entry: %s\n", nt_errstr(status)));
			talloc_free(req);
			return status;
		}
	}

	if (ldap_msg->type != LDAP_TAG_SearchResultDone) {
		talloc_free(req);
		return NT_STATUS_LDAP(LDAP_PROTOCOL_ERROR);
	}

	io->out.result = talloc(mem_ctx, struct ldap_Result);
	NT_STATUS_HAVE_NO_MEMORY(io->out.result);
	*io->out.result = ldap_msg->r.SearchResultDone;

	talloc_free(req);

	if (io->out.result->resultcode != LDAP_SUCCESS) {
		return NT_STATUS_LDAP(io->out.result->resultcode);
	}
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
	TALLOC_CTX *tmp_ctx = talloc_new(cldap);

	filter = talloc_asprintf(tmp_ctx, "(&(NtVer=%s)", 
				 ldap_encode_ndr_uint32(tmp_ctx, io->in.version));
	if (filter == NULL) goto failed;
	if (io->in.user) {
		filter = talloc_asprintf_append_buffer(filter, "(User=%s)", io->in.user);
		if (filter == NULL) goto failed;
	}
	if (io->in.host) {
		filter = talloc_asprintf_append_buffer(filter, "(Host=%s)", io->in.host);
		if (filter == NULL) goto failed;
	}
	if (io->in.realm) {
		filter = talloc_asprintf_append_buffer(filter, "(DnsDomain=%s)", io->in.realm);
		if (filter == NULL) goto failed;
	}
	if (io->in.acct_control != -1) {
		filter = talloc_asprintf_append_buffer(filter, "(AAC=%s)", 
						ldap_encode_ndr_uint32(tmp_ctx, io->in.acct_control));
		if (filter == NULL) goto failed;
	}
	if (io->in.domain_sid) {
		struct dom_sid *sid = dom_sid_parse_talloc(tmp_ctx, io->in.domain_sid);
		if (sid == NULL) goto failed;
		filter = talloc_asprintf_append_buffer(filter, "(domainSid=%s)",
						ldap_encode_ndr_dom_sid(tmp_ctx, sid));
		if (filter == NULL) goto failed;
	}
	if (io->in.domain_guid) {
		struct GUID guid;
		NTSTATUS status;
		status = GUID_from_string(io->in.domain_guid, &guid);
		if (!NT_STATUS_IS_OK(status)) goto failed;
		filter = talloc_asprintf_append_buffer(filter, "(DomainGuid=%s)",
						ldap_encode_ndr_GUID(tmp_ctx, &guid));
		if (filter == NULL) goto failed;
	}
	filter = talloc_asprintf_append_buffer(filter, ")");
	if (filter == NULL) goto failed;

	search.in.dest_address = io->in.dest_address;
	search.in.dest_port    = io->in.dest_port;
	search.in.filter       = filter;
	search.in.attributes   = attr;
	search.in.timeout      = 2;
	search.in.retries      = 2;

	req = cldap_search_send(cldap, &search);

	talloc_free(tmp_ctx);
	return req;
failed:
	talloc_free(tmp_ctx);
	return NULL;
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
	struct cldap_socket *cldap;
	DATA_BLOB *data;

	cldap = req->cldap;

	status = cldap_search_recv(req, mem_ctx, &search);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (search.out.response == NULL) {
		return NT_STATUS_NOT_FOUND;
	}

	if (search.out.response->num_attributes != 1 ||
	    strcasecmp(search.out.response->attributes[0].name, "netlogon") != 0 ||
	    search.out.response->attributes[0].num_values != 1 ||
	    search.out.response->attributes[0].values->length < 2) {
		return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}
	data = search.out.response->attributes[0].values;

	status = pull_netlogon_samlogon_response(data, mem_ctx, req->cldap->iconv_convenience,
						 &io->out.netlogon);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	if (io->in.map_response) {
		map_netlogon_samlogon_response(&io->out.netlogon);
	}
	return NT_STATUS_OK;
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


/*
  send an empty reply (used on any error, so the client doesn't keep waiting
  or send the bad request again)
*/
NTSTATUS cldap_empty_reply(struct cldap_socket *cldap, 
			   uint32_t message_id,
			   struct socket_address *src)
{
	NTSTATUS status;
	struct cldap_reply reply;
	struct ldap_Result result;

	reply.messageid    = message_id;
	reply.dest         = src;
	reply.response     = NULL;
	reply.result       = &result;

	ZERO_STRUCT(result);

	status = cldap_reply_send(cldap, &reply);

	return status;
}

/*
  send an error reply (used on any error, so the client doesn't keep waiting
  or send the bad request again)
*/
NTSTATUS cldap_error_reply(struct cldap_socket *cldap, 
			   uint32_t message_id,
			   struct socket_address *src,
			   int resultcode,
			   const char *errormessage)
{
	NTSTATUS status;
	struct cldap_reply reply;
	struct ldap_Result result;

	reply.messageid    = message_id;
	reply.dest         = src;
	reply.response     = NULL;
	reply.result       = &result;

	ZERO_STRUCT(result);
	result.resultcode	= resultcode;
	result.errormessage	= errormessage;

	status = cldap_reply_send(cldap, &reply);

	return status;
}


/*
  send a netlogon reply 
*/
NTSTATUS cldap_netlogon_reply(struct cldap_socket *cldap, 
			      uint32_t message_id,
			      struct socket_address *src,
			      uint32_t version,
			      struct netlogon_samlogon_response *netlogon)
{
	NTSTATUS status;
	struct cldap_reply reply;
	struct ldap_SearchResEntry response;
	struct ldap_Result result;
	TALLOC_CTX *tmp_ctx = talloc_new(cldap);
	DATA_BLOB blob;

	status = push_netlogon_samlogon_response(&blob, tmp_ctx, cldap->iconv_convenience,
						 netlogon);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	reply.messageid    = message_id;
	reply.dest         = src;
	reply.response     = &response;
	reply.result       = &result;

	ZERO_STRUCT(result);

	response.dn = "";
	response.num_attributes = 1;
	response.attributes = talloc(tmp_ctx, struct ldb_message_element);
	NT_STATUS_HAVE_NO_MEMORY(response.attributes);
	response.attributes->name = "netlogon";
	response.attributes->num_values = 1;
	response.attributes->values = &blob;

	status = cldap_reply_send(cldap, &reply);

	talloc_free(tmp_ctx);

	return status;
}


