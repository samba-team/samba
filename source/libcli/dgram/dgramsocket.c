/* 
   Unix SMB/CIFS implementation.

   low level socket handling for nbt dgram requests (UDP138)

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
#include "lib/events/events.h"
#include "dlinklist.h"
#include "libcli/nbt/libnbt.h"
#include "libcli/dgram/libdgram.h"
#include "lib/socket/socket.h"

#define DGRAM_MAX_PACKET_SIZE 2048


/*
  handle recv events on a nbt dgram socket
*/
static void dgm_socket_recv(struct nbt_dgram_socket *nbtsock)
{
	TALLOC_CTX *tmp_ctx = talloc_new(nbtsock);
	NTSTATUS status;
	const char *src_addr;
	int src_port;
	DATA_BLOB blob;
	size_t nread;
	struct nbt_dgram_packet *packet;

	blob = data_blob_talloc(tmp_ctx, NULL, DGRAM_MAX_PACKET_SIZE);
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

	DEBUG(0,("Received dgram packet of length %d from %s:%d\n", 
		 blob.length, src_addr, src_port));

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

	NDR_PRINT_DEBUG(nbt_dgram_packet, packet);

	talloc_free(tmp_ctx);
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
		/* nothing at the moment */
	} else if (flags & EVENT_FD_READ) {
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
	
	return dgmsock;

failed:
	talloc_free(dgmsock);
	return NULL;
}


/*
  setup a handler for incoming requests
*/
NTSTATUS dgram_set_incoming_handler(struct nbt_dgram_socket *dgmsock,
				    void (*handler)(struct nbt_dgram_socket *, 
						    struct nbt_dgram_packet *, 
						    const char *, int ),
				    void *private)
{
	dgmsock->incoming.handler = handler;
	dgmsock->incoming.private = private;
	EVENT_FD_READABLE(dgmsock->fde);
	return NT_STATUS_OK;
}
