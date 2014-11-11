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
#include "system/network.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/raw/raw_proto.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "lib/socket/socket.h"
#include "lib/events/events.h"
#include "../lib/util/dlinklist.h"
#include "../libcli/smb/smbXcli_base.h"
#include "librpc/ndr/libndr.h"

/*
  destroy a transport
 */
static int transport_destructor(struct smb2_transport *transport)
{
	smb2_transport_dead(transport, NT_STATUS_LOCAL_DISCONNECT);
	return 0;
}

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

	transport->ev = sock->event.ctx;
	transport->options = *options;

	if (transport->options.max_protocol == PROTOCOL_DEFAULT) {
		transport->options.max_protocol = PROTOCOL_LATEST;
	}

	if (transport->options.max_protocol < PROTOCOL_SMB2_02) {
		transport->options.max_protocol = PROTOCOL_LATEST;
	}

	TALLOC_FREE(sock->event.fde);
	TALLOC_FREE(sock->event.te);

	transport->conn = smbXcli_conn_create(transport,
					      sock->sock->fd,
					      sock->hostname,
					      options->signing,
					      0, /* smb1_capabilities */
					      &options->client_guid,
					      options->smb2_capabilities);
	if (transport->conn == NULL) {
		talloc_free(transport);
		return NULL;
	}
	sock->sock->fd = -1;
	TALLOC_FREE(sock);

	talloc_set_destructor(transport, transport_destructor);

	return transport;
}

/*
  mark the transport as dead
*/
void smb2_transport_dead(struct smb2_transport *transport, NTSTATUS status)
{
	if (NT_STATUS_EQUAL(NT_STATUS_UNSUCCESSFUL, status)) {
		status = NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}
	if (NT_STATUS_IS_OK(status)) {
		status = NT_STATUS_LOCAL_DISCONNECT;
	}

	smbXcli_conn_disconnect(transport->conn, status);
}

static void smb2_request_done(struct tevent_req *subreq);
static void smb2_transport_break_handler(struct tevent_req *subreq);

/*
  put a request into the send queue
*/
void smb2_transport_send(struct smb2_request *req)
{
	NTSTATUS status;
	struct smb2_transport *transport = req->transport;
	struct tevent_req **reqs = transport->compound.reqs;
	size_t num_reqs = talloc_array_length(reqs);
	size_t i;
	uint16_t cmd = SVAL(req->out.hdr, SMB2_HDR_OPCODE);
	uint32_t additional_flags = IVAL(req->out.hdr, SMB2_HDR_FLAGS);
	uint32_t clear_flags = 0;
	struct smbXcli_tcon *tcon = NULL;
	struct smbXcli_session *session = NULL;
	bool need_pending_break = false;
	size_t hdr_ofs;
	size_t pdu_len;
	DATA_BLOB body = data_blob_null;
	DATA_BLOB dyn = data_blob_null;
	uint32_t timeout_msec = transport->options.request_timeout * 1000;

	if (transport->oplock.handler) {
		need_pending_break = true;
	}

	if (transport->lease.handler) {
		need_pending_break = true;
	}

	if (transport->break_subreq) {
		need_pending_break = false;
	}

	if (need_pending_break) {
		struct tevent_req *subreq;

		subreq = smb2cli_req_create(transport,
					    transport->ev,
					    transport->conn,
					    SMB2_OP_BREAK,
					    0, /* additional_flags */
					    0, /*clear_flags */
					    0, /* timeout_msec */
					    NULL, /* tcon */
					    NULL, /* session */
					    NULL, /* body */
					    0, /* body_fixed */
					    NULL, /* dyn */
					    0, /* dyn_len */
					    0); /* max_dyn_len */
		if (subreq != NULL) {
			smbXcli_req_set_pending(subreq);
			tevent_req_set_callback(subreq,
						smb2_transport_break_handler,
						transport);
			transport->break_subreq = subreq;
		}
	}

	if (req->session) {
		session = req->session->smbXcli;
	}

	if (req->tree) {
		tcon = req->tree->smbXcli;
	}

	if (transport->compound.related) {
		additional_flags |= SMB2_HDR_FLAG_CHAINED;
	}

	hdr_ofs = PTR_DIFF(req->out.hdr, req->out.buffer);
	pdu_len = req->out.size - hdr_ofs;
	body.data = req->out.body;
	body.length = req->out.body_fixed;
	dyn.data = req->out.body + req->out.body_fixed;
	dyn.length = pdu_len - (SMB2_HDR_BODY + req->out.body_fixed);

	req->subreq = smb2cli_req_create(req,
					 transport->ev,
					 transport->conn,
					 cmd,
					 additional_flags,
					 clear_flags,
					 timeout_msec,
					 tcon,
					 session,
					 body.data, body.length,
					 dyn.data, dyn.length,
					 0); /* max_dyn_len */
	if (req->subreq == NULL) {
		req->state = SMB2_REQUEST_ERROR;
		req->status = NT_STATUS_NO_MEMORY;
		return;
	}

	if (!tevent_req_is_in_progress(req->subreq)) {
		req->state = SMB2_REQUEST_ERROR;
		req->status = NT_STATUS_INTERNAL_ERROR;/* TODO */
		return;
	}

	tevent_req_set_callback(req->subreq, smb2_request_done, req);

	smb2cli_req_set_notify_async(req->subreq);
	if (req->credit_charge) {
		smb2cli_req_set_credit_charge(req->subreq, req->credit_charge);
	}

	ZERO_STRUCT(req->out);
	req->state = SMB2_REQUEST_RECV;

	if (num_reqs > 0) {
		for (i=0; i < num_reqs; i++) {
			if (reqs[i] != NULL) {
				continue;
			}

			reqs[i] = req->subreq;
			i++;
			break;
		}

		if (i < num_reqs) {
			return;
		}
	} else {
		reqs = &req->subreq;
		num_reqs = 1;
	}
	status = smb2cli_req_compound_submit(reqs, num_reqs);

	TALLOC_FREE(transport->compound.reqs);
	transport->compound.related = false;

	if (!NT_STATUS_IS_OK(status)) {
		req->status = status;
		req->state = SMB2_REQUEST_ERROR;
		smbXcli_conn_disconnect(transport->conn, status);
	}
}

static void smb2_request_done(struct tevent_req *subreq)
{
	struct smb2_request *req =
		tevent_req_callback_data(subreq,
		struct smb2_request);
	ssize_t len;
	size_t i;

	req->recv_iov = NULL;

	req->status = smb2cli_req_recv(req->subreq, req, &req->recv_iov, NULL, 0);
	if (NT_STATUS_EQUAL(req->status, STATUS_PENDING)) {
		req->cancel.can_cancel = true;
		return;
	}
	TALLOC_FREE(req->subreq);
	if (!NT_STATUS_IS_OK(req->status)) {
		if (req->recv_iov == NULL) {
			req->state = SMB2_REQUEST_ERROR;
			if (req->async.fn) {
				req->async.fn(req);
			}
			return;
		}
	}

	len = req->recv_iov[0].iov_len;
	for (i=1; i < 3; i++) {
		uint8_t *p = req->recv_iov[i-1].iov_base;
		uint8_t *c1 = req->recv_iov[i].iov_base;
		uint8_t *c2 = p + req->recv_iov[i-1].iov_len;

		len += req->recv_iov[i].iov_len;

		if (req->recv_iov[i].iov_len == 0) {
			continue;
		}

		if (c1 != c2) {
			req->status = NT_STATUS_INTERNAL_ERROR;
			req->state = SMB2_REQUEST_ERROR;
			if (req->async.fn) {
				req->async.fn(req);
			}
			return;
		}
	}

	req->in.buffer = req->recv_iov[0].iov_base;
	req->in.size = len;
	req->in.allocated = req->in.size;

	req->in.hdr        =  req->recv_iov[0].iov_base;
	req->in.body       =  req->recv_iov[1].iov_base;
	req->in.dynamic    =  req->recv_iov[2].iov_base;
	req->in.body_fixed =  req->recv_iov[1].iov_len;
	req->in.body_size  =  req->in.body_fixed;
	req->in.body_size  += req->recv_iov[2].iov_len;

	smb2_setup_bufinfo(req);

	req->state = SMB2_REQUEST_DONE;
	if (req->async.fn) {
		req->async.fn(req);
	}
}

static void smb2_transport_break_handler(struct tevent_req *subreq)
{
	struct smb2_transport *transport =
		tevent_req_callback_data(subreq,
		struct smb2_transport);
	NTSTATUS status;
	uint8_t *body;
	uint16_t len = 0;
	bool lease;
	struct iovec *recv_iov = NULL;

	transport->break_subreq = NULL;

	status = smb2cli_req_recv(subreq, transport, &recv_iov, NULL, 0);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(recv_iov);
		smb2_transport_dead(transport, status);
		return;
	}

	/*
	 * Setup the subreq to handle the
	 * next incoming SMB2 Break.
	 */
	subreq = smb2cli_req_create(transport,
				    transport->ev,
				    transport->conn,
				    SMB2_OP_BREAK,
				    0, /* additional_flags */
				    0, /*clear_flags */
				    0, /* timeout_msec */
				    NULL, /* tcon */
				    NULL, /* session */
				    NULL, /* body */
				    0, /* body_fixed */
				    NULL, /* dyn */
				    0, /* dyn_len */
				    0); /* max_dyn_len */
	if (subreq != NULL) {
		smbXcli_req_set_pending(subreq);
		tevent_req_set_callback(subreq,
					smb2_transport_break_handler,
					transport);
		transport->break_subreq = subreq;
	}

	body = recv_iov[1].iov_base;

	len = recv_iov[1].iov_len;
	if (recv_iov[1].iov_len >= 2) {
		len = CVAL(body, 0x00);
		if (len != recv_iov[1].iov_len) {
			len = recv_iov[1].iov_len;
		}
	}

	if (len == 24) {
		lease = false;
	} else if (len == 44) {
		lease = true;
	} else {
		DEBUG(1,("Discarding smb2 oplock reply of invalid size %u\n",
			(unsigned)len));
		TALLOC_FREE(recv_iov);
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		smb2_transport_dead(transport, status);
		return;
	}

	if (!lease && transport->oplock.handler) {
		struct smb2_handle h;
		uint8_t level;

		level = CVAL(body, 0x02);
		smb2_pull_handle(body+0x08, &h);

		TALLOC_FREE(recv_iov);

		transport->oplock.handler(transport, &h, level,
					  transport->oplock.private_data);
	} else if (lease && transport->lease.handler) {
		struct smb2_lease_break lb;

		ZERO_STRUCT(lb);
		lb.new_epoch =			SVAL(body, 0x2);
		lb.break_flags =		SVAL(body, 0x4);
		memcpy(&lb.current_lease.lease_key, body+0x8,
		    sizeof(struct smb2_lease_key));
		lb.current_lease.lease_state = 	SVAL(body, 0x18);
		lb.new_lease_state =		SVAL(body, 0x1C);
		lb.break_reason =		SVAL(body, 0x20);
		lb.access_mask_hint = 		SVAL(body, 0x24);
		lb.share_mask_hint = 		SVAL(body, 0x28);

		TALLOC_FREE(recv_iov);

		transport->lease.handler(transport, &lb,
		    transport->lease.private_data);
	} else {
		DEBUG(5,("Got SMB2 %s break with no handler\n",
			lease ? "lease" : "oplock"));
	}
	TALLOC_FREE(recv_iov);
}

NTSTATUS smb2_transport_compound_start(struct smb2_transport *transport,
				       uint32_t num)
{
	TALLOC_FREE(transport->compound.reqs);
	ZERO_STRUCT(transport->compound);

	transport->compound.reqs = talloc_zero_array(transport,
						     struct tevent_req *,
						     num);
	if (transport->compound.reqs == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

void smb2_transport_compound_set_related(struct smb2_transport *transport,
					 bool related)
{
	transport->compound.related = related;
}

void smb2_transport_credits_ask_num(struct smb2_transport *transport,
				    uint16_t ask_num)
{
	smb2cli_conn_set_max_credits(transport->conn, ask_num);
}

static void idle_handler(struct tevent_context *ev, 
			 struct tevent_timer *te, struct timeval t, void *private_data)
{
	struct smb2_transport *transport = talloc_get_type(private_data,
							   struct smb2_transport);
	struct timeval next;

	transport->idle.func(transport, transport->idle.private_data);

	next = timeval_current_ofs_usec(transport->idle.period);
	transport->idle.te = tevent_add_timer(transport->ev,
					      transport,
					      next,
					      idle_handler,
					      transport);
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
	TALLOC_FREE(transport->idle.te);

	transport->idle.func = idle_func;
	transport->idle.private_data = private_data;
	transport->idle.period = period;

	transport->idle.te = tevent_add_timer(transport->ev,
					      transport,
					      timeval_current_ofs_usec(period),
					      idle_handler,
					      transport);
}
