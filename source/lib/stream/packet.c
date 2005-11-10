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
	uint32_t initial_read;
	struct tls_context *tls;
	struct socket_context *sock;
	struct event_context *ev;
	size_t packet_size;
	void *private;
	struct fd_event *fde;
	BOOL serialise;
	BOOL processing;
	BOOL recv_disable;

	struct send_element {
		struct send_element *next, *prev;
		DATA_BLOB blob;
		size_t nsent;
	} *send_queue;
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
  tell the packet layer to serialise requests, so we don't process two requests at once on
  one connection. You must have set the event_context
*/
void packet_set_serialise(struct packet_context *pc, struct fd_event *fde)
{
	pc->serialise = True;
	pc->fde = fde;
}

/*
  tell the packet layer how much to read when starting a new packet
  this ensures it doesn't overread
*/
void packet_set_initial_read(struct packet_context *pc, uint32_t initial_read)
{
	pc->initial_read = initial_read;
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
	if (pc->num_read != 0 && pc->packet_size >= pc->num_read) {
		packet_recv(pc);
	}
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

	if (pc->processing) {
		return;
	}

	if (pc->recv_disable) {
		EVENT_FD_NOT_READABLE(pc->fde);
		return;
	}

	if (pc->packet_size != 0 && pc->num_read >= pc->packet_size) {
		goto next_partial;
	}

	if (pc->packet_size != 0) {
		/* we've already worked out how long this next packet is, so skip the
		   socket_pending() call */
		npending = pc->packet_size - pc->num_read;
	} else if (pc->initial_read != 0) {
		npending = pc->initial_read - pc->num_read;
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
	
	if (pc->serialise) {
		EVENT_FD_NOT_READABLE(pc->fde);
		pc->processing = True;
	}

	status = pc->callback(pc->private, blob);

	if (pc->serialise) {
		EVENT_FD_READABLE(pc->fde);
		pc->processing = False;
	}

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
  temporarily disable receiving 
*/
void packet_recv_disable(struct packet_context *pc)
{
	EVENT_FD_NOT_READABLE(pc->fde);
	pc->recv_disable = True;
}

/*
  re-enable receiving 
*/
void packet_recv_enable(struct packet_context *pc)
{
	EVENT_FD_READABLE(pc->fde);
	pc->recv_disable = False;
	if (pc->num_read != 0 && pc->packet_size >= pc->num_read) {
		event_add_timed(pc->ev, pc, timeval_zero(), packet_next_event, pc);
	}
}

/*
  trigger a run of the send queue
*/
void packet_queue_run(struct packet_context *pc)
{
	while (pc->send_queue) {
		struct send_element *el = pc->send_queue;
		NTSTATUS status;
		size_t nwritten;
		DATA_BLOB blob = data_blob_const(el->blob.data + el->nsent,
						 el->blob.length - el->nsent);

		if (pc->tls) {
			status = tls_socket_send(pc->tls, &blob, &nwritten);
		} else {
			status = socket_send(pc->sock, &blob, &nwritten, 0);
		}
		if (NT_STATUS_IS_ERR(status)) {
			packet_error(pc, NT_STATUS_NET_WRITE_FAULT);
			return;
		}
		if (!NT_STATUS_IS_OK(status)) {
			return;
		}
		el->nsent += nwritten;
		if (el->nsent == el->blob.length) {
			DLIST_REMOVE(pc->send_queue, el);
			talloc_free(el);
		}
	}

	/* we're out of requests to send, so don't wait for write
	   events any more */
	EVENT_FD_NOT_WRITEABLE(pc->fde);
}

/*
  put a packet in the send queue
*/
NTSTATUS packet_send(struct packet_context *pc, DATA_BLOB blob)
{
	struct send_element *el;
	el = talloc(pc, struct send_element);
	NT_STATUS_HAVE_NO_MEMORY(el);

	DLIST_ADD_END(pc->send_queue, el, struct send_element *);
	el->blob = blob;
	el->nsent = 0;
	talloc_steal(el, blob.data);

	EVENT_FD_WRITEABLE(pc->fde);

	return NT_STATUS_OK;
}


/*
  a full request checker for NBT formatted packets (first 3 bytes are length)
*/
NTSTATUS packet_full_request_nbt(void *private, DATA_BLOB blob, size_t *size)
{
	if (blob.length < 4) {
		return STATUS_MORE_ENTRIES;
	}
	*size = 4 + smb_len(blob.data);
	if (*size > blob.length) {
		return STATUS_MORE_ENTRIES;
	}
	return NT_STATUS_OK;
}


/*
  work out if a packet is complete for protocols that use a 32 bit network byte
  order length
*/
NTSTATUS packet_full_request_u32(void *private, DATA_BLOB blob, size_t *size)
{
	if (blob.length < 4) {
		return STATUS_MORE_ENTRIES;
	}
	*size = 4 + RIVAL(blob.data, 0);
	if (*size > blob.length) {
		return STATUS_MORE_ENTRIES;
	}
	return NT_STATUS_OK;
}
