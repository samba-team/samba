/* 
   Unix SMB/CIFS implementation.

   SMB2 client transport context management functions

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
#include "libcli/raw/libcliraw.h"
#include "libcli/raw/raw_proto.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "lib/socket/socket.h"
#include "lib/events/events.h"
#include "lib/stream/packet.h"
#include "../lib/util/dlinklist.h"


/*
  an event has happened on the socket
*/
static void smb2_transport_event_handler(struct tevent_context *ev, 
					 struct tevent_fd *fde, 
					 uint16_t flags, void *private_data)
{
	struct smb2_transport *transport = talloc_get_type(private_data,
							   struct smb2_transport);
	if (flags & EVENT_FD_READ) {
		packet_recv(transport->packet);
		return;
	}
	if (flags & EVENT_FD_WRITE) {
		packet_queue_run(transport->packet);
	}
}

/*
  destroy a transport
 */
static int transport_destructor(struct smb2_transport *transport)
{
	smb2_transport_dead(transport, NT_STATUS_LOCAL_DISCONNECT);
	return 0;
}


/*
  handle receive errors
*/
static void smb2_transport_error(void *private_data, NTSTATUS status)
{
	struct smb2_transport *transport = talloc_get_type(private_data,
							   struct smb2_transport);
	smb2_transport_dead(transport, status);
}

static NTSTATUS smb2_transport_finish_recv(void *private_data, DATA_BLOB blob);

/*
  create a transport structure based on an established socket
*/
struct smb2_transport *smb2_transport_init(struct smbcli_socket *sock,
					   TALLOC_CTX *parent_ctx,
					   struct smbcli_options *options)
{
	struct smb2_transport *transport;

	transport = talloc_zero(parent_ctx, struct smb2_transport);
	if (!transport) return NULL;

	transport->socket = talloc_steal(transport, sock);
	transport->options = *options;

	/* setup the stream -> packet parser */
	transport->packet = packet_init(transport);
	if (transport->packet == NULL) {
		talloc_free(transport);
		return NULL;
	}
	packet_set_private(transport->packet, transport);
	packet_set_socket(transport->packet, transport->socket->sock);
	packet_set_callback(transport->packet, smb2_transport_finish_recv);
	packet_set_full_request(transport->packet, packet_full_request_nbt);
	packet_set_error_handler(transport->packet, smb2_transport_error);
	packet_set_event_context(transport->packet, transport->socket->event.ctx);
	packet_set_nofree(transport->packet);

	/* take over event handling from the socket layer - it only
	   handles events up until we are connected */
	talloc_free(transport->socket->event.fde);
	transport->socket->event.fde = event_add_fd(transport->socket->event.ctx,
						    transport->socket,
						    socket_get_fd(transport->socket->sock),
						    EVENT_FD_READ,
						    smb2_transport_event_handler,
						    transport);

	packet_set_fde(transport->packet, transport->socket->event.fde);
	packet_set_serialise(transport->packet);

	talloc_set_destructor(transport, transport_destructor);

	return transport;
}

/*
  mark the transport as dead
*/
void smb2_transport_dead(struct smb2_transport *transport, NTSTATUS status)
{
	smbcli_sock_dead(transport->socket);

	if (NT_STATUS_EQUAL(NT_STATUS_UNSUCCESSFUL, status)) {
		status = NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}

	/* kill all pending receives */
	while (transport->pending_recv) {
		struct smb2_request *req = transport->pending_recv;
		req->state = SMB2_REQUEST_ERROR;
		req->status = status;
		DLIST_REMOVE(transport->pending_recv, req);
		if (req->async.fn) {
			req->async.fn(req);
		}
	}
}

static NTSTATUS smb2_handle_oplock_break(struct smb2_transport *transport,
					 const DATA_BLOB *blob)
{
	uint8_t *hdr;
	uint16_t opcode;

	hdr = blob->data+NBT_HDR_SIZE;

	if (blob->length < (SMB2_MIN_SIZE+0x18)) {
		DEBUG(1,("Discarding smb2 oplock reply of size %u\n",
			 (unsigned)blob->length));
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	opcode	= SVAL(hdr, SMB2_HDR_OPCODE);

	if (opcode != SMB2_OP_BREAK) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	if (transport->oplock.handler) {
		uint8_t *body = hdr+SMB2_HDR_BODY;
		struct smb2_handle h;
		uint8_t level;

		level = CVAL(body, 0x02);
		smb2_pull_handle(body+0x08, &h);

		transport->oplock.handler(transport, &h, level,
					  transport->oplock.private_data);
	} else {
		DEBUG(5,("Got SMB2 oplock break with no handler\n"));
	}

	return NT_STATUS_OK;
}

/*
  we have a full request in our receive buffer - match it to a pending request
  and process
 */
static NTSTATUS smb2_transport_finish_recv(void *private_data, DATA_BLOB blob)
{
	struct smb2_transport *transport = talloc_get_type(private_data,
							     struct smb2_transport);
	uint8_t *buffer, *hdr;
	int len;
	struct smb2_request *req = NULL;
	uint64_t seqnum;
	uint32_t flags;
	uint16_t buffer_code;
	uint32_t dynamic_size;
	uint32_t i;
	NTSTATUS status;

	buffer = blob.data;
	len = blob.length;

	hdr = buffer+NBT_HDR_SIZE;

	if (len < SMB2_MIN_SIZE) {
		DEBUG(1,("Discarding smb2 reply of size %d\n", len));
		goto error;
	}

	flags	= IVAL(hdr, SMB2_HDR_FLAGS);
	seqnum	= BVAL(hdr, SMB2_HDR_MESSAGE_ID);

	/* see MS-SMB2 3.2.5.19 */
	if (seqnum == UINT64_MAX) {
		return smb2_handle_oplock_break(transport, &blob);
	}

	/* match the incoming request against the list of pending requests */
	for (req=transport->pending_recv; req; req=req->next) {
		if (req->seqnum == seqnum) break;
	}

	if (!req) {
		DEBUG(1,("Discarding unmatched reply with seqnum 0x%llx op %d\n", 
			 (long long)seqnum, SVAL(hdr, SMB2_HDR_OPCODE)));
		goto error;
	}

	/* fill in the 'in' portion of the matching request */
	req->in.buffer = buffer;
	talloc_steal(req, buffer);
	req->in.size = len;
	req->in.allocated = req->in.size;

	req->in.hdr       = hdr;
	req->in.body      = hdr+SMB2_HDR_BODY;
	req->in.body_size = req->in.size - (SMB2_HDR_BODY+NBT_HDR_SIZE);
	req->status       = NT_STATUS(IVAL(hdr, SMB2_HDR_STATUS));

	if ((flags & SMB2_HDR_FLAG_ASYNC) &&
	    NT_STATUS_EQUAL(req->status, STATUS_PENDING)) {
		req->cancel.can_cancel = true;
		req->cancel.pending_id = IVAL(hdr, SMB2_HDR_PID);
		for (i=0; i< req->cancel.do_cancel; i++) {
			smb2_cancel(req);
		}
		talloc_free(buffer);
		return NT_STATUS_OK;
	}

	if (req->session && req->session->signing_active) {
		status = smb2_check_signature(&req->in, 
					      req->session->session_key);
		if (!NT_STATUS_IS_OK(status)) {
			/* the spec says to ignore packets with a bad signature */
			talloc_free(buffer);
			return status;
		}
	}

	buffer_code = SVAL(req->in.body, 0);
	req->in.body_fixed = (buffer_code & ~1);
	req->in.dynamic = NULL;
	dynamic_size = req->in.body_size - req->in.body_fixed;
	if (dynamic_size != 0 && (buffer_code & 1)) {
		req->in.dynamic = req->in.body + req->in.body_fixed;
		if (smb2_oob(&req->in, req->in.dynamic, dynamic_size)) {
			DEBUG(1,("SMB2 request invalid dynamic size 0x%x\n", 
				 dynamic_size));
			goto error;
		}
	}

	smb2_setup_bufinfo(req);

	DEBUG(2, ("SMB2 RECV seqnum=0x%llx\n", (long long)req->seqnum));
	dump_data(5, req->in.body, req->in.body_size);

	/* if this request has an async handler then call that to
	   notify that the reply has been received. This might destroy
	   the request so it must happen last */
	DLIST_REMOVE(transport->pending_recv, req);
	req->state = SMB2_REQUEST_DONE;
	if (req->async.fn) {
		req->async.fn(req);
	}
	return NT_STATUS_OK;

error:
	dump_data(5, buffer, len);
	if (req) {
		DLIST_REMOVE(transport->pending_recv, req);
		req->state = SMB2_REQUEST_ERROR;
		if (req->async.fn) {
			req->async.fn(req);
		}
	} else {
		talloc_free(buffer);
	}
	return NT_STATUS_UNSUCCESSFUL;
}

/*
  handle timeouts of individual smb requests
*/
static void smb2_timeout_handler(struct tevent_context *ev, struct tevent_timer *te, 
				 struct timeval t, void *private_data)
{
	struct smb2_request *req = talloc_get_type(private_data, struct smb2_request);

	if (req->state == SMB2_REQUEST_RECV) {
		DLIST_REMOVE(req->transport->pending_recv, req);
	}
	req->status = NT_STATUS_IO_TIMEOUT;
	req->state = SMB2_REQUEST_ERROR;
	if (req->async.fn) {
		req->async.fn(req);
	}
}


/*
  destroy a request
*/
static int smb2_request_destructor(struct smb2_request *req)
{
	if (req->state == SMB2_REQUEST_RECV) {
		DLIST_REMOVE(req->transport->pending_recv, req);
	}
	return 0;
}


/*
  put a request into the send queue
*/
void smb2_transport_send(struct smb2_request *req)
{
	DATA_BLOB blob;
	NTSTATUS status;

	_smb2_setlen(req->out.buffer, req->out.size - NBT_HDR_SIZE);

	DEBUG(2, ("SMB2 send seqnum=0x%llx\n", (long long)req->seqnum));
	dump_data(5, req->out.body, req->out.body_size);

	/* check if the transport is dead */
	if (req->transport->socket->sock == NULL) {
		req->state = SMB2_REQUEST_ERROR;
		req->status = NT_STATUS_NET_WRITE_FAULT;
		return;
	}

	/* possibly sign the message */
	if (req->session && req->session->signing_active) {
		status = smb2_sign_message(&req->out, req->session->session_key);
		if (!NT_STATUS_IS_OK(status)) {
			req->state = SMB2_REQUEST_ERROR;
			req->status = status;
			return;
		}
	}
	
	blob = data_blob_const(req->out.buffer, req->out.size);
	status = packet_send(req->transport->packet, blob);
	if (!NT_STATUS_IS_OK(status)) {
		req->state = SMB2_REQUEST_ERROR;
		req->status = status;
		return;
	}

	req->state = SMB2_REQUEST_RECV;
	DLIST_ADD(req->transport->pending_recv, req);

	/* add a timeout */
	if (req->transport->options.request_timeout) {
		event_add_timed(req->transport->socket->event.ctx, req, 
				timeval_current_ofs(req->transport->options.request_timeout, 0), 
				smb2_timeout_handler, req);
	}

	talloc_set_destructor(req, smb2_request_destructor);
}

static void idle_handler(struct tevent_context *ev, 
			 struct tevent_timer *te, struct timeval t, void *private_data)
{
	struct smb2_transport *transport = talloc_get_type(private_data,
							   struct smb2_transport);
	struct timeval next = timeval_add(&t, 0, transport->idle.period);
	transport->socket->event.te = event_add_timed(transport->socket->event.ctx, 
						      transport,
						      next,
						      idle_handler, transport);
	transport->idle.func(transport, transport->idle.private_data);
}

/*
  setup the idle handler for a transport
  the period is in microseconds
*/
void smb2_transport_idle_handler(struct smb2_transport *transport, 
				 void (*idle_func)(struct smb2_transport *, void *),
				 uint64_t period,
				 void *private_data)
{
	transport->idle.func = idle_func;
	transport->idle.private_data = private_data;
	transport->idle.period = period;

	if (transport->socket->event.te != NULL) {
		talloc_free(transport->socket->event.te);
	}

	transport->socket->event.te = event_add_timed(transport->socket->event.ctx, 
						      transport,
						      timeval_current_ofs(0, period),
						      idle_handler, transport);
}
