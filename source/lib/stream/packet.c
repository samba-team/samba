/* 
   Unix SMB/CIFS mplementation.

   helper layer for breaking up streams into discrete requests
   
   Copyright (C) Andrew Tridgell  2005
    
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
#include "dlinklist.h"
#include "lib/events/events.h"
#include "lib/socket/socket.h"
#include "lib/tls/tls.h"
#include "lib/stream/packet.h"


struct packet_context {
	packet_callback_fn_t callback;
	packet_full_request_fn_t full_request;
	packet_error_handler_fn_t error_handler;
	DATA_BLOB partial;
	uint32_t initial_read_size;
	uint32_t num_read;
	struct tls_context *tls;
	struct socket_context *sock;
	struct event_context *ev;
	size_t packet_size;
	void *private;
};

/*
  initialise a packet receiver
*/
struct packet_context *packet_init(TALLOC_CTX *mem_ctx)
{
	return talloc_zero(mem_ctx, struct packet_context);
}


/*
  set the request callback, called when a full request is ready
*/
void packet_set_callback(struct packet_context *pc, packet_callback_fn_t callback)
{
	pc->callback = callback;
}

/*
  set the error handler
*/
void packet_set_error_handler(struct packet_context *pc, packet_error_handler_fn_t handler)
{
	pc->error_handler = handler;
}

/*
  set the private pointer passed to the callback functions
*/
void packet_set_private(struct packet_context *pc, void *private)
{
	pc->private = private;
}

/*
  set the full request callback. Should return as follows:
     NT_STATUS_OK == blob is a full request.
     STATUS_MORE_ENTRIES == blob is not complete yet
     any error == blob is not a valid 
*/
void packet_set_full_request(struct packet_context *pc, packet_full_request_fn_t callback)
{
	pc->full_request = callback;
}

/*
  set a tls context to use. You must either set a tls_context or a socket_context
*/
void packet_set_tls(struct packet_context *pc, struct tls_context *tls)
{
	pc->tls = tls;
}

/*
  set a socket context to use. You must either set a tls_context or a socket_context
*/
void packet_set_socket(struct packet_context *pc, struct socket_context *sock)
{
	pc->sock = sock;
}

/*
  set an event context. If this is set then the code will ensure that
  packets arrive with separate events, by creating a immediate event
  for any secondary packets when more than one packet is read at one
  time on a socket. This can matter for code that relies on not
  getting more than one packet per event
*/
void packet_set_event_context(struct packet_context *pc, struct event_context *ev)
{
	pc->ev = ev;
}


/*
  tell the caller we have an error
*/
static void packet_error(struct packet_context *pc, NTSTATUS status)
{
	pc->tls = NULL;
	pc->sock = NULL;
	if (pc->error_handler) {
		pc->error_handler(pc->private, status);
		return;
	}
	/* default error handler is to free the callers private pointer */
	if (!NT_STATUS_EQUAL(status, NT_STATUS_END_OF_FILE)) {
		DEBUG(0,("packet_error on %s - %s\n", 
			 talloc_get_name(pc->private), nt_errstr(status)));
	}
	talloc_free(pc->private);
	return;
}


/*
  tell the caller we have EOF
*/
static void packet_eof(struct packet_context *pc)
{
	packet_error(pc, NT_STATUS_END_OF_FILE);
}


/*
  used to put packets on event boundaries
*/
static void packet_next_event(struct event_context *ev, struct timed_event *te, 
			      struct timeval t, void *private)
{
	struct packet_context *pc = talloc_get_type(private, struct packet_context);
	packet_recv(pc);
}

/*
  call this when the socket becomes readable to kick off the whole
  stream parsing process
*/
void packet_recv(struct packet_context *pc)
{
	size_t npending;
	NTSTATUS status;
	size_t nread;
	DATA_BLOB blob;

	if (pc->packet_size != 0 && pc->num_read >= pc->packet_size) {
		goto next_partial;
	}

	if (pc->packet_size != 0) {
		/* we've already worked out how long this next packet is, so skip the
		   socket_pending() call */
		npending = pc->packet_size - pc->num_read;
	} else {
		if (pc->tls) {
			status = tls_socket_pending(pc->tls, &npending);
		} else if (pc->sock) {
			status = socket_pending(pc->sock, &npending);
		} else {
			status = NT_STATUS_CONNECTION_DISCONNECTED;
		}
		if (!NT_STATUS_IS_OK(status)) {
			packet_error(pc, status);
			return;
		}
	}

	if (npending == 0) {
		packet_eof(pc);
		return;
	}

	/* possibly expand the partial packet buffer */
	if (npending + pc->num_read > pc->partial.length) {
		status = data_blob_realloc(pc, &pc->partial, npending+pc->num_read);
		if (!NT_STATUS_IS_OK(status)) {
			packet_error(pc, status);
			return;
		}
	}

	if (pc->tls) {
		status = tls_socket_recv(pc->tls, pc->partial.data + pc->num_read, 
					 npending, &nread);
	} else {
		status = socket_recv(pc->sock, pc->partial.data + pc->num_read, 
				     npending, &nread, 0);
	}
	if (NT_STATUS_IS_ERR(status)) {
		packet_error(pc, status);
		return;
	}
	if (!NT_STATUS_IS_OK(status)) {
		return;
	}

	if (nread == 0) {
		packet_eof(pc);
		return;
	}

	pc->num_read += nread;

	/* see if its a full request */
next_partial:
	blob = pc->partial;
	blob.length = pc->num_read;
	status = pc->full_request(pc->private, blob, &pc->packet_size);
	if (NT_STATUS_IS_ERR(status)) {
		packet_error(pc, status);
		return;
	}
	if (!NT_STATUS_IS_OK(status)) {
		return;
	}

	if (pc->packet_size > pc->num_read) {
		/* the caller made an error */
		DEBUG(0,("Invalid packet_size %u greater than num_read %u\n",
			 pc->packet_size, pc->num_read));
		packet_error(pc, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	/* it is a full request - give it to the caller */
	blob = pc->partial;

	if (pc->packet_size < pc->num_read) {
		pc->partial = data_blob_talloc(pc, blob.data + pc->packet_size, 
					       pc->num_read - pc->packet_size);
		if (pc->partial.data == NULL) {
			packet_error(pc, NT_STATUS_NO_MEMORY);
			return;
		}
		data_blob_realloc(pc, &blob, pc->packet_size);
	} else {
		pc->partial = data_blob(NULL, 0);
	}
	pc->num_read -= pc->packet_size;
	pc->packet_size = 0;

	status = pc->callback(pc->private, blob);
	if (!NT_STATUS_IS_OK(status)) {
		packet_error(pc, status);
		return;
	}

	if (pc->partial.length == 0) {
		return;
	}
	
	/* we got multiple packets in one tcp read */
	if (pc->ev == NULL) {
		goto next_partial;
	}

	blob = pc->partial;
	blob.length = pc->num_read;

	status = pc->full_request(pc->private, blob, &pc->packet_size);
	if (NT_STATUS_IS_ERR(status)) {
		packet_error(pc, status);
		return;
	}

	if (!NT_STATUS_IS_OK(status)) {
		return;
	}

	event_add_timed(pc->ev, pc, timeval_zero(), packet_next_event, pc);
}



/*
  a full request checker for NBT formatted packets (first 3 bytes are length)
*/
NTSTATUS packet_full_request_nbt(void *private, DATA_BLOB blob, size_t *packet_size)
{
	if (blob.length < 4) {
		return STATUS_MORE_ENTRIES;
	}
	*packet_size = 4 + smb_len(blob.data);
	if (*packet_size > blob.length) {
		return STATUS_MORE_ENTRIES;
	}
	return NT_STATUS_OK;
}
