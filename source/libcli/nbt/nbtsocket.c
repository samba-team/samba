/* 
   Unix SMB/CIFS implementation.

   low level socket handling for nbt requests

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

#include "includes.h"
#include "events.h"
#include "dlinklist.h"
#include "libcli/nbt/libnbt.h"

#define NBT_MAX_PACKET_SIZE 2048
#define NBT_MAX_REPLIES 1000

/*
  destroy a nbt socket
*/
static int nbtsock_destructor(void *ptr)
{
	struct nbt_name_socket *nbtsock = talloc_get_type(ptr, struct nbt_name_socket);
	event_remove_fd(nbtsock->event_ctx, nbtsock->fde);
	return 0;
}

/*
  destroy a pending request
*/
static int nbt_name_request_destructor(void *ptr)
{
	struct nbt_name_request *req = talloc_get_type(ptr, struct nbt_name_request);
	
	if (req->state == NBT_REQUEST_SEND) {
		DLIST_REMOVE(req->nbtsock->send_queue, req);
	}
	if (req->state == NBT_REQUEST_WAIT) {
		req->nbtsock->num_pending--;
	}
	if (req->request->name_trn_id != 0) {
		idr_remove(req->nbtsock->idr, req->request->name_trn_id);
		req->request->name_trn_id = 0;
	}
	if (req->te) {
		event_remove_timed(req->nbtsock->event_ctx, req->te);
		req->te = NULL;
	}
	if (req->nbtsock->send_queue == NULL) {
		req->nbtsock->fde->flags &= ~EVENT_FD_WRITE;
	}
	if (req->nbtsock->num_pending == 0) {
		req->nbtsock->fde->flags &= ~EVENT_FD_READ;
	}
	return 0;
}


/*
  handle send events on a nbt name socket
*/
static void nbt_name_socket_send(struct nbt_name_socket *nbtsock)
{
	struct nbt_name_request *req = nbtsock->send_queue;
	TALLOC_CTX *tmp_ctx = talloc_new(req);
	NTSTATUS status;

	while ((req = nbtsock->send_queue)) {
		DATA_BLOB blob;
		size_t len;
		
		if (DEBUGLVL(10)) {
			DEBUG(10,("Sending nbt packet to %s:%d\n", 
				  req->dest_addr, req->dest_port));
			NDR_PRINT_DEBUG(nbt_name_packet, req->request);
		}

		status = ndr_push_struct_blob(&blob, tmp_ctx, req->request, 
					      (ndr_push_flags_fn_t)
					      ndr_push_nbt_name_packet);
		if (!NT_STATUS_IS_OK(status)) goto failed;

		if (req->request->operation & NBT_FLAG_BROADCAST) {
			socket_set_option(nbtsock->sock, "SO_BROADCAST", "1");
		}

		len = blob.length;
		status = socket_sendto(nbtsock->sock, &blob, &len, 0, 
				       req->dest_addr, req->dest_port);
		if (NT_STATUS_IS_ERR(status)) goto failed;		

		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(tmp_ctx);
			return;
		}

		DLIST_REMOVE(nbtsock->send_queue, req);
		req->state = NBT_REQUEST_WAIT;
		nbtsock->fde->flags |= EVENT_FD_READ;
		nbtsock->num_pending++;
	}

	nbtsock->fde->flags &= ~EVENT_FD_WRITE;
	talloc_free(tmp_ctx);
	return;

failed:
	DLIST_REMOVE(nbtsock->send_queue, req);
	nbt_name_request_destructor(req);
	req->status = status;
	req->state = NBT_REQUEST_ERROR;
	if (req->async.fn) {
		req->async.fn(req);
	}
	talloc_free(tmp_ctx);
	return;
}


/*
  handle recv events on a nbt name socket
*/
static void nbt_name_socket_recv(struct nbt_name_socket *nbtsock)
{
	TALLOC_CTX *tmp_ctx = talloc_new(nbtsock);
	NTSTATUS status;
	const char *src_addr;
	int src_port;
	DATA_BLOB blob;
	size_t nread;
	struct nbt_name_packet *packet;
	struct nbt_name_request *req;

	blob = data_blob_talloc(tmp_ctx, NULL, NBT_MAX_PACKET_SIZE);
	if (blob.data == NULL) {
		talloc_free(tmp_ctx);
		return;
	}

	status = socket_recvfrom(nbtsock->sock, blob.data, blob.length, &nread, 0,
				 &src_addr, &src_port);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return;
	}
	talloc_steal(tmp_ctx, src_addr);
	blob.length = nread;

	packet = talloc(tmp_ctx, struct nbt_name_packet);
	if (packet == NULL) {
		talloc_free(tmp_ctx);
		return;
	}

	status = ndr_pull_struct_blob(&blob, packet, packet, 
				      (ndr_pull_flags_fn_t)ndr_pull_nbt_name_packet);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2,("Failed to parse incoming NBT name packet - %s\n",
			 nt_errstr(status)));
		talloc_free(tmp_ctx);
		return;
	}

	if (DEBUGLVL(10)) {
		DEBUG(10,("Received nbt packet of length %d from %s:%d\n", 
			  blob.length, src_addr, src_port));
		NDR_PRINT_DEBUG(nbt_name_packet, packet);
	}

	if (!(packet->operation & NBT_FLAG_REPLY)) {
		talloc_free(tmp_ctx);
		return;
	}

	/* find the matching request */
	req = idr_find(nbtsock->idr, packet->name_trn_id);
	if (req == NULL) {
		DEBUG(2,("Failed to match request for incoming name packet id 0x%04x\n",
			 packet->name_trn_id));
		talloc_free(tmp_ctx);
		return;
	}

	req->replies = talloc_realloc(req, req->replies, struct nbt_name_reply, req->num_replies+1);
	if (req->replies == NULL) {
		nbt_name_request_destructor(req);
		req->state = NBT_REQUEST_DONE;
		req->status = NT_STATUS_NO_MEMORY;
		talloc_free(tmp_ctx);
		if (req->async.fn) {
			req->async.fn(req);
		}
		return;
	}

	req->replies[req->num_replies].reply_addr = talloc_steal(req, src_addr);
	req->replies[req->num_replies].reply_port = src_port;
	req->replies[req->num_replies].packet = talloc_steal(req, packet);
	req->num_replies++;

	talloc_free(tmp_ctx);

	/* if we don't want multiple replies then we are done */
	if (!req->allow_multiple_replies ||
	    req->num_replies == NBT_MAX_REPLIES) {
		nbt_name_request_destructor(req);
		req->state = NBT_REQUEST_DONE;
		req->status = NT_STATUS_OK;
		if (req->async.fn) {
			req->async.fn(req);
		}
	}
}

/*
  handle fd events on a nbt_name_socket
*/
static void nbt_name_socket_handler(struct event_context *ev, struct fd_event *fde,
				    struct timeval t, uint16_t flags)
{
	struct nbt_name_socket *nbtsock = talloc_get_type(fde->private, 
							  struct nbt_name_socket);
	if (flags & EVENT_FD_WRITE) {
		nbt_name_socket_send(nbtsock);
	} else if (flags & EVENT_FD_READ) {
		nbt_name_socket_recv(nbtsock);
	}
}


/*
  initialise a nbt_name_socket. The event_ctx is optional, if provided
  then operations will use that event context
*/
struct nbt_name_socket *nbt_name_socket_init(TALLOC_CTX *mem_ctx, 
					     struct event_context *event_ctx)
{
	struct nbt_name_socket *nbtsock;
	NTSTATUS status;
	struct fd_event fde;

	nbtsock = talloc(mem_ctx, struct nbt_name_socket);
	if (nbtsock == NULL) goto failed;

	if (event_ctx == NULL) {
		nbtsock->event_ctx = event_context_init(nbtsock);
	} else {
		nbtsock->event_ctx = talloc_reference(nbtsock, event_ctx);
	}
	if (nbtsock->event_ctx == NULL) goto failed;

	status = socket_create("ip", SOCKET_TYPE_DGRAM, &nbtsock->sock, 0);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	talloc_steal(nbtsock, nbtsock->sock);

	nbtsock->idr = idr_init(nbtsock);
	if (nbtsock->idr == NULL) goto failed;

	nbtsock->send_queue = NULL;
	nbtsock->num_pending = 0;

	fde.fd = socket_get_fd(nbtsock->sock);
	fde.flags = 0;
	fde.handler = nbt_name_socket_handler;
	fde.private = nbtsock;
	nbtsock->fde = event_add_fd(nbtsock->event_ctx, &fde);

	talloc_set_destructor(nbtsock, nbtsock_destructor);
	
	return nbtsock;

failed:
	talloc_free(nbtsock);
	return NULL;
}

/*
  handle a request timeout
*/
static void nbt_name_socket_timeout(struct event_context *ev, struct timed_event *te,
				    struct timeval t)
{
	struct nbt_name_request *req = talloc_get_type(te->private, 
						       struct nbt_name_request);
	nbt_name_request_destructor(req);
	if (req->num_replies == 0) {
		req->state = NBT_REQUEST_TIMEOUT;
		req->status = NT_STATUS_IO_TIMEOUT;
	} else {
		req->state = NBT_REQUEST_DONE;
		req->status = NT_STATUS_OK;
	}
	if (req->async.fn) {
		req->async.fn(req);
	}
}

/*
  send off a nbt name request
*/
struct nbt_name_request *nbt_name_request_send(struct nbt_name_socket *nbtsock, 
					       const char *dest_addr, int dest_port,
					       struct nbt_name_packet *request,
					       struct timeval timeout,
					       BOOL allow_multiple_replies)
{
	struct nbt_name_request *req;
	struct timed_event te;
	int id;

	req = talloc_zero(nbtsock, struct nbt_name_request);
	if (req == NULL) goto failed;

	req->nbtsock = nbtsock;
	req->dest_addr = dest_addr;
	req->dest_port = dest_port;
	req->request = talloc_reference(req, request);
	req->allow_multiple_replies = allow_multiple_replies;
	req->state = NBT_REQUEST_SEND;

	/* we select a random transaction id unless the user supplied one */
	if (req->request->name_trn_id == 0) {
		req->request->name_trn_id = generate_random() % UINT16_MAX;
	}

	/* choose the next available transaction id >= the one asked for.
	   The strange 2nd call is to try to make the ids less guessable
	   and less likely to collide. It's not possible to make NBT secure 
	   to ID guessing, but this at least makes accidential collisions
	   less likely */
	id = idr_get_new_above(req->nbtsock->idr, req, 
			       req->request->name_trn_id, UINT16_MAX);
	if (id == -1) {
		id = idr_get_new_above(req->nbtsock->idr, req, 
				       1+(generate_random()%(UINT16_MAX/2)),
				       UINT16_MAX);
	}
	if (id == -1) goto failed;
	req->request->name_trn_id = id;

	te.next_event = timeout;
	te.handler = nbt_name_socket_timeout;
	te.private = req;
	req->te = event_add_timed(nbtsock->event_ctx, &te);
	
	talloc_set_destructor(req, nbt_name_request_destructor);	

	DLIST_ADD_END(nbtsock->send_queue, req, struct nbt_name_request *);

	nbtsock->fde->flags |= EVENT_FD_WRITE;

	return req;

failed:
	talloc_free(req);
	return NULL;
}

/*
  wait for a nbt request to complete
*/
NTSTATUS nbt_name_request_recv(struct nbt_name_request *req)
{
	if (!req) return NT_STATUS_NO_MEMORY;

	while (req->state < NBT_REQUEST_DONE) {
		if (event_loop_once(req->nbtsock->event_ctx) != 0) {
			req->state = NBT_REQUEST_ERROR;
			req->status = NT_STATUS_UNEXPECTED_NETWORK_ERROR;
			if (req->async.fn) {
				req->async.fn(req);
			}
		}
	}
	return req->status;
}
