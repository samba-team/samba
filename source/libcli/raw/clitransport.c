/* 
   Unix SMB/CIFS implementation.
   SMB client transport context management functions
   Copyright (C) Andrew Tridgell 1994-2003
   Copyright (C) James Myers 2003 <myersjj@samba.org>
   
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


static void smbcli_transport_process_recv(struct smbcli_transport *transport);
static void smbcli_transport_process_send(struct smbcli_transport *transport);

/*
  an event has happened on the socket
*/
static void smbcli_transport_event_handler(struct event_context *ev, struct fd_event *fde, 
					time_t t, uint16_t flags)
{
	struct smbcli_transport *transport = fde->private;

	if (flags & EVENT_FD_READ) {
		smbcli_transport_process_recv(transport);
	}
	if (flags & EVENT_FD_WRITE) {
		smbcli_transport_process_send(transport);
	}
}

/*
  create a transport structure based on an established socket
*/
struct smbcli_transport *smbcli_transport_init(struct smbcli_socket *sock)
{
	struct smbcli_transport *transport;
	struct fd_event fde;

	transport = talloc_named(NULL, sizeof(*transport), "smbcli_transport");
	if (!transport) return NULL;

	ZERO_STRUCTP(transport);

	transport->event.ctx = event_context_init();
	if (transport->event.ctx == NULL) {
		talloc_free(transport);
		return NULL;
	}

	transport->socket = sock;
	transport->negotiate.protocol = PROTOCOL_NT1;
	transport->options.use_spnego = lp_use_spnego();
	transport->negotiate.max_xmit = ~0;
	
	smbcli_init_signing(transport);

	transport->socket->reference_count++;

	ZERO_STRUCT(transport->called);

	fde.fd = sock->fd;
	fde.flags = EVENT_FD_READ;
	fde.handler = smbcli_transport_event_handler;
	fde.private = transport;
	fde.ref_count = 1;

	transport->event.fde = event_add_fd(transport->event.ctx, &fde);

	return transport;
}

/*
  decrease reference count on a transport, and destroy if it becomes
  zero
*/
void smbcli_transport_close(struct smbcli_transport *transport)
{
	transport->reference_count--;
	if (transport->reference_count <= 0) {
		smbcli_sock_close(transport->socket);
		event_remove_fd(transport->event.ctx, transport->event.fde);
		event_remove_timed(transport->event.ctx, transport->event.te);
		event_context_destroy(transport->event.ctx);
		talloc_free(transport);
	}
}

/*
  mark the transport as dead
*/
void smbcli_transport_dead(struct smbcli_transport *transport)
{
	smbcli_sock_dead(transport->socket);

	/* all pending sends become errors */
	while (transport->pending_send) {
		struct smbcli_request *req = transport->pending_send;
		req->state = SMBCLI_REQUEST_ERROR;
		req->status = NT_STATUS_NET_WRITE_FAULT;
		DLIST_REMOVE(transport->pending_send, req);
		if (req->async.fn) {
			req->async.fn(req);
		}
	}

	/* as do all pending receives */
	while (transport->pending_recv) {
		struct smbcli_request *req = transport->pending_recv;
		req->state = SMBCLI_REQUEST_ERROR;
		req->status = NT_STATUS_NET_WRITE_FAULT;
		DLIST_REMOVE(transport->pending_recv, req);
		if (req->async.fn) {
			req->async.fn(req);
		}
	}
}


/*
  enable select for write on a transport
*/
static void smbcli_transport_write_enable(struct smbcli_transport *transport)
{
	transport->event.fde->flags |= EVENT_FD_WRITE;
}

/*
  disable select for write on a transport
*/
static void smbcli_transport_write_disable(struct smbcli_transport *transport)
{
	transport->event.fde->flags &= ~EVENT_FD_WRITE;
}

/****************************************************************************
send a session request (if appropriate)
****************************************************************************/
BOOL smbcli_transport_connect(struct smbcli_transport *transport,
			   struct nmb_name *calling, 
			   struct nmb_name *called)
{
	char *p;
	int len = NBT_HDR_SIZE;
	struct smbcli_request *req;

	if (called) {
		transport->called = *called;
	}

	/* 445 doesn't have session request */
	if (transport->socket->port == 445) {
		return True;
	}

  	/* allocate output buffer */
	req = smbcli_request_setup_nonsmb(transport, NBT_HDR_SIZE + 2*nbt_mangled_name_len());

	/* put in the destination name */
	p = req->out.buffer + NBT_HDR_SIZE;
	name_mangle(called->name, p, called->name_type);
	len += name_len(p);

	/* and my name */
	p = req->out.buffer+len;
	name_mangle(calling->name, p, calling->name_type);
	len += name_len(p);

	_smb_setlen(req->out.buffer,len-4);
	SCVAL(req->out.buffer,0,0x81);

	if (!smbcli_request_send(req) ||
	    !smbcli_request_receive(req)) {
		smbcli_request_destroy(req);
		return False;
	}
	
	if (CVAL(req->in.buffer,0) != 0x82) {
		transport->error.etype = ETYPE_NBT;
		transport->error.e.nbt_error = CVAL(req->in.buffer,4);
		smbcli_request_destroy(req);
		return False;
	}

	smbcli_request_destroy(req);
	return True;
}


/****************************************************************************
get next mid in sequence
****************************************************************************/
uint16_t smbcli_transport_next_mid(struct smbcli_transport *transport)
{
	uint16_t mid;
	struct smbcli_request *req;

	mid = transport->next_mid;

again:
	/* now check to see if this mid is being used by one of the 
	   pending requests. This is quite efficient because the list is
	   usually very short */

	/* the zero mid is reserved for requests that don't have a mid */
	if (mid == 0) mid = 1;

	for (req=transport->pending_recv; req; req=req->next) {
		if (req->mid == mid) {
			mid++;
			goto again;
		}
	}

	transport->next_mid = mid+1;
	return mid;
}

static void idle_handler(struct event_context *ev, 
			 struct timed_event *te, time_t t)
{
	struct smbcli_transport *transport = te->private;
	te->next_event = t + transport->idle.period;
	transport->idle.func(transport, transport->idle.private);
}

/*
  setup the idle handler for a transport
  the period is in seconds
*/
void smbcli_transport_idle_handler(struct smbcli_transport *transport, 
				void (*idle_func)(struct smbcli_transport *, void *),
				uint_t period,
				void *private)
{
	struct timed_event te;
	transport->idle.func = idle_func;
	transport->idle.private = private;
	transport->idle.period = period;

	if (transport->event.te != NULL) {
		event_remove_timed(transport->event.ctx, transport->event.te);
	}

	te.next_event = time(NULL) + period;
	te.handler = idle_handler;
	te.private = transport;
	transport->event.te = event_add_timed(transport->event.ctx, &te);
}

/*
  process some pending sends
*/
static void smbcli_transport_process_send(struct smbcli_transport *transport)
{
	while (transport->pending_send) {
		struct smbcli_request *req = transport->pending_send;
		ssize_t ret;
		ret = smbcli_sock_write(transport->socket, req->out.buffer, req->out.size);
		if (ret == -1) {
			if (errno == EAGAIN || errno == EINTR) {
				return;
			}
			smbcli_transport_dead(transport);
			return;
		}
		req->out.buffer += ret;
		req->out.size -= ret;
		if (req->out.size == 0) {
			DLIST_REMOVE(transport->pending_send, req);
			if (req->one_way_request) {
				req->state = SMBCLI_REQUEST_DONE;
				smbcli_request_destroy(req);
			} else {
				req->state = SMBCLI_REQUEST_RECV;
				DLIST_ADD(transport->pending_recv, req);
			}
		}
	}

	/* we're out of requests to send, so don't wait for write
	   events any more */
	smbcli_transport_write_disable(transport);
}

/*
  we have a full request in our receive buffer - match it to a pending request
  and process
 */
static void smbcli_transport_finish_recv(struct smbcli_transport *transport)
{
	uint8_t *buffer, *hdr, *vwv;
	int len;
	uint16_t wct=0, mid = 0;
	struct smbcli_request *req;

	buffer = transport->recv_buffer.buffer;
	len = transport->recv_buffer.req_size;

	ZERO_STRUCT(transport->recv_buffer);

	hdr = buffer+NBT_HDR_SIZE;
	vwv = hdr + HDR_VWV;

	/* see if it could be an oplock break request */
	if (handle_oplock_break(transport, len, hdr, vwv)) {
		talloc_free(buffer);
		return;
	}

	/* at this point we need to check for a readbraw reply, as
	   these can be any length */
	if (transport->readbraw_pending) {
		transport->readbraw_pending = 0;

		/* it must match the first entry in the pending queue
		   as the client is not allowed to have outstanding
		   readbraw requests */
		req = transport->pending_recv;
		if (!req) goto error;

		req->in.buffer = buffer;
		talloc_steal(req, buffer);
		req->in.size = len;
		req->in.allocated = req->in.size;
		goto async;
	}

	if (len >= MIN_SMB_SIZE) {
		/* extract the mid for matching to pending requests */
		mid = SVAL(hdr, HDR_MID);
		wct = CVAL(hdr, HDR_WCT);
	}

	/* match the incoming request against the list of pending requests */
	for (req=transport->pending_recv; req; req=req->next) {
		if (req->mid == mid) break;
	}

	if (!req) {
		DEBUG(1,("Discarding unmatched reply with mid %d\n", mid));
		goto error;
	}

	/* fill in the 'in' portion of the matching request */
	req->in.buffer = buffer;
	talloc_steal(req, buffer);
	req->in.size = len;
	req->in.allocated = req->in.size;

	/* handle NBT session replies */
	if (req->in.size >= 4 && req->in.buffer[0] != 0) {
		req->status = NT_STATUS_OK;
		goto async;
	}

	/* handle non-SMB replies */
	if (req->in.size < NBT_HDR_SIZE + MIN_SMB_SIZE) {
		req->state = SMBCLI_REQUEST_ERROR;
		goto error;
	}

	if (req->in.size < NBT_HDR_SIZE + MIN_SMB_SIZE + VWV(wct)) {
		DEBUG(2,("bad reply size for mid %d\n", mid));
		req->status = NT_STATUS_UNSUCCESSFUL;
		req->state = SMBCLI_REQUEST_ERROR;
		goto error;
	}

	req->in.hdr = hdr;
	req->in.vwv = vwv;
	req->in.wct = wct;
	if (req->in.size >= NBT_HDR_SIZE + MIN_SMB_SIZE + VWV(wct)) {
		req->in.data = req->in.vwv + VWV(wct) + 2;
		req->in.data_size = SVAL(req->in.vwv, VWV(wct));
		if (req->in.size < NBT_HDR_SIZE + MIN_SMB_SIZE + VWV(wct) + req->in.data_size) {
			DEBUG(3,("bad data size for mid %d\n", mid));
			/* blergh - w2k3 gives a bogus data size values in some
			   openX replies */
			req->in.data_size = req->in.size - (NBT_HDR_SIZE + MIN_SMB_SIZE + VWV(wct));
		}
	}
	req->in.ptr = req->in.data;
	req->flags2 = SVAL(req->in.hdr, HDR_FLG2);

	if (!(req->flags2 & FLAGS2_32_BIT_ERROR_CODES)) {
		transport->error.etype = ETYPE_DOS;
		transport->error.e.dos.eclass = CVAL(req->in.hdr,HDR_RCLS);
		transport->error.e.dos.ecode = SVAL(req->in.hdr,HDR_ERR);
		req->status = dos_to_ntstatus(transport->error.e.dos.eclass, 
					      transport->error.e.dos.ecode);
	} else {
		transport->error.etype = ETYPE_NT;
		transport->error.e.nt_status = NT_STATUS(IVAL(req->in.hdr, HDR_RCLS));
		req->status = transport->error.e.nt_status;
	}

	if (!smbcli_request_check_sign_mac(req)) {
		transport->error.etype = ETYPE_SOCKET;
		transport->error.e.socket_error = SOCKET_READ_BAD_SIG;
		req->state = SMBCLI_REQUEST_ERROR;
		goto error;
	};

async:
	/* if this request has an async handler then call that to
	   notify that the reply has been received. This might destroy
	   the request so it must happen last */
	DLIST_REMOVE(transport->pending_recv, req);
	req->state = SMBCLI_REQUEST_DONE;
	if (req->async.fn) {
		req->async.fn(req);
	}
	return;

error:
	if (req) {
		DLIST_REMOVE(transport->pending_recv, req);
		req->state = SMBCLI_REQUEST_ERROR;
	}
}

/*
  process some pending receives
*/
static void smbcli_transport_process_recv(struct smbcli_transport *transport)
{
	/* a incoming packet goes through 2 stages - first we read the
	   4 byte header, which tells us how much more is coming. Then
	   we read the rest */
	if (transport->recv_buffer.received < NBT_HDR_SIZE) {
		ssize_t ret;
		ret = smbcli_sock_read(transport->socket, 
				    transport->recv_buffer.header + 
				    transport->recv_buffer.received,
				    NBT_HDR_SIZE - transport->recv_buffer.received);
		if (ret == 0) {
			smbcli_transport_dead(transport);
			return;
		}
		if (ret == -1) {
			if (errno == EINTR || errno == EAGAIN) {
				return;
			}
			smbcli_transport_dead(transport);
			return;
		}

		transport->recv_buffer.received += ret;

		if (transport->recv_buffer.received == NBT_HDR_SIZE) {
			/* we've got a full header */
			transport->recv_buffer.req_size = smb_len(transport->recv_buffer.header) + NBT_HDR_SIZE;
			transport->recv_buffer.buffer = talloc(transport,
							       NBT_HDR_SIZE+transport->recv_buffer.req_size);
			if (transport->recv_buffer.buffer == NULL) {
				smbcli_transport_dead(transport);
				return;
			}
			memcpy(transport->recv_buffer.buffer, transport->recv_buffer.header, NBT_HDR_SIZE);
		}
	}

	if (transport->recv_buffer.received < transport->recv_buffer.req_size) {
		ssize_t ret;
		ret = smbcli_sock_read(transport->socket, 
				    transport->recv_buffer.buffer + 
				    transport->recv_buffer.received,
				    transport->recv_buffer.req_size - 
				    transport->recv_buffer.received);
		if (ret == -1) {
			if (errno == EINTR || errno == EAGAIN) {
				return;
			}
			smbcli_transport_dead(transport);
			return;
		}
		transport->recv_buffer.received += ret;
	}

	if (transport->recv_buffer.received != 0 &&
	    transport->recv_buffer.received == transport->recv_buffer.req_size) {
		smbcli_transport_finish_recv(transport);
	}
}

/*
  process some read/write requests that are pending
  return False if the socket is dead
*/
BOOL smbcli_transport_process(struct smbcli_transport *transport)
{
	smbcli_transport_process_send(transport);
	smbcli_transport_process_recv(transport);
	if (transport->socket->fd == -1) {
		return False;
	}
	return True;
}



/*
  put a request into the send queue
*/
void smbcli_transport_send(struct smbcli_request *req)
{
	/* check if the transport is dead */
	if (req->transport->socket->fd == -1) {
		req->state = SMBCLI_REQUEST_ERROR;
		req->status = NT_STATUS_NET_WRITE_FAULT;
		return;
	}

	/* put it on the outgoing socket queue */
	req->state = SMBCLI_REQUEST_SEND;
	DLIST_ADD_END(req->transport->pending_send, req, struct smbcli_request *);

	/* make sure we look for write events */
	smbcli_transport_write_enable(req->transport);
}
