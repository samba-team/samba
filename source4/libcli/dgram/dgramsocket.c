/* 
   Unix SMB/CIFS implementation.

   low level socket handling for nbt dgram requests (UDP138)

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

#include "includes.h"
#include "lib/events/events.h"
#include "lib/util/dlinklist.h"
#include "libcli/dgram/libdgram.h"
#include "lib/socket/socket.h"
#include "librpc/gen_ndr/ndr_nbt.h"


/*
  handle recv events on a nbt dgram socket
*/
static void dgm_socket_recv(struct nbt_dgram_socket *dgmsock)
{
	TALLOC_CTX *tmp_ctx = talloc_new(dgmsock);
	NTSTATUS status;
	struct socket_address *src;
	DATA_BLOB blob;
	size_t nread, dsize;
	struct nbt_dgram_packet *packet;
	const char *mailslot_name;

	status = socket_pending(dgmsock->sock, &dsize);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return;
	}

	blob = data_blob_talloc(tmp_ctx, NULL, dsize);
	if (blob.data == NULL) {
		talloc_free(tmp_ctx);
		return;
	}

	status = socket_recvfrom(dgmsock->sock, blob.data, blob.length, &nread,
				 tmp_ctx, &src);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return;
	}
	blob.length = nread;

	DEBUG(2,("Received dgram packet of length %d from %s:%d\n", 
		 (int)blob.length, src->addr, src->port));

	packet = talloc(tmp_ctx, struct nbt_dgram_packet);
	if (packet == NULL) {
		talloc_free(tmp_ctx);
		return;
	}

	/* parse the request */
	status = ndr_pull_struct_blob(&blob, packet, packet, 
				      (ndr_pull_flags_fn_t)ndr_pull_nbt_dgram_packet);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2,("Failed to parse incoming NBT DGRAM packet - %s\n",
			 nt_errstr(status)));
		talloc_free(tmp_ctx);
		return;
	}

	/* if this is a mailslot message, then see if we can dispatch it to a handler */
	mailslot_name = dgram_mailslot_name(packet);
	if (mailslot_name) {
		struct dgram_mailslot_handler *dgmslot;
		dgmslot = dgram_mailslot_find(dgmsock, mailslot_name);
		if (dgmslot) {
			dgmslot->handler(dgmslot, packet, src);
		} else {
			DEBUG(2,("No mailslot handler for '%s'\n", mailslot_name));
		}
	} else {
		/* dispatch if there is a general handler */
		if (dgmsock->incoming.handler) {
			dgmsock->incoming.handler(dgmsock, packet, src);
		}
	}

	talloc_free(tmp_ctx);
}


/*
  handle send events on a nbt dgram socket
*/
static void dgm_socket_send(struct nbt_dgram_socket *dgmsock)
{
	struct nbt_dgram_request *req;
	NTSTATUS status;

	while ((req = dgmsock->send_queue)) {
		size_t len;
		
		len = req->encoded.length;
		status = socket_sendto(dgmsock->sock, &req->encoded, &len,
				       req->dest);
		if (NT_STATUS_IS_ERR(status)) {
			DEBUG(3,("Failed to send datagram of length %u to %s:%d: %s\n",
				 (unsigned)req->encoded.length, req->dest->addr, req->dest->port, 
				 nt_errstr(status)));
			DLIST_REMOVE(dgmsock->send_queue, req);
			talloc_free(req);
			continue;
		}

		if (!NT_STATUS_IS_OK(status)) return;

		DLIST_REMOVE(dgmsock->send_queue, req);
		talloc_free(req);
	}

	EVENT_FD_NOT_WRITEABLE(dgmsock->fde);
	return;
}


/*
  handle fd events on a nbt_dgram_socket
*/
static void dgm_socket_handler(struct event_context *ev, struct fd_event *fde,
			       uint16_t flags, void *private)
{
	struct nbt_dgram_socket *dgmsock = talloc_get_type(private, 
							   struct nbt_dgram_socket);
	if (flags & EVENT_FD_WRITE) {
		dgm_socket_send(dgmsock);
	} 
	if (flags & EVENT_FD_READ) {
		dgm_socket_recv(dgmsock);
	}
}

/*
  initialise a nbt_dgram_socket. The event_ctx is optional, if provided
  then operations will use that event context
*/
struct nbt_dgram_socket *nbt_dgram_socket_init(TALLOC_CTX *mem_ctx, 
					      struct event_context *event_ctx)
{
	struct nbt_dgram_socket *dgmsock;
	NTSTATUS status;

	dgmsock = talloc(mem_ctx, struct nbt_dgram_socket);
	if (dgmsock == NULL) goto failed;

	if (event_ctx == NULL) {
		dgmsock->event_ctx = event_context_init(dgmsock);
	} else {
		dgmsock->event_ctx = talloc_reference(dgmsock, event_ctx);
	}
	if (dgmsock->event_ctx == NULL) goto failed;

	status = socket_create("ip", SOCKET_TYPE_DGRAM, &dgmsock->sock, 0);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	socket_set_option(dgmsock->sock, "SO_BROADCAST", "1");

	talloc_steal(dgmsock, dgmsock->sock);

	dgmsock->fde = event_add_fd(dgmsock->event_ctx, dgmsock, 
				    socket_get_fd(dgmsock->sock), 0,
				    dgm_socket_handler, dgmsock);

	dgmsock->send_queue = NULL;
	dgmsock->incoming.handler = NULL;
	dgmsock->mailslot_handlers = NULL;
	
	return dgmsock;

failed:
	talloc_free(dgmsock);
	return NULL;
}


/*
  setup a handler for generic incoming requests
*/
NTSTATUS dgram_set_incoming_handler(struct nbt_dgram_socket *dgmsock,
				    void (*handler)(struct nbt_dgram_socket *, 
						    struct nbt_dgram_packet *, 
						    struct socket_address *),
				    void *private)
{
	dgmsock->incoming.handler = handler;
	dgmsock->incoming.private = private;
	EVENT_FD_READABLE(dgmsock->fde);
	return NT_STATUS_OK;
}


/*
  queue a datagram for send
*/
NTSTATUS nbt_dgram_send(struct nbt_dgram_socket *dgmsock,
			struct nbt_dgram_packet *packet,
			struct socket_address *dest)
{
	struct nbt_dgram_request *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	req = talloc(dgmsock, struct nbt_dgram_request);
	if (req == NULL) goto failed;

	req->dest = dest;
	if (talloc_reference(req, dest) == NULL) goto failed;

	status = ndr_push_struct_blob(&req->encoded, req, packet, 
				      (ndr_push_flags_fn_t)ndr_push_nbt_dgram_packet);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	DLIST_ADD_END(dgmsock->send_queue, req, struct nbt_dgram_request *);

	EVENT_FD_WRITEABLE(dgmsock->fde);

	return NT_STATUS_OK;

failed:
	talloc_free(req);
	return status;
}
