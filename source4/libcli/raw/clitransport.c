/* 
   Unix SMB/CIFS implementation.
   SMB client transport context management functions

   Copyright (C) Andrew Tridgell 1994-2005
   Copyright (C) James Myers 2003 <myersjj@samba.org>
   
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
#include "../lib/async_req/async_sock.h"
#include "../lib/util/tevent_ntstatus.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/raw/raw_proto.h"
#include "lib/socket/socket.h"
#include "lib/events/events.h"
#include "librpc/gen_ndr/ndr_nbt.h"
#include "../libcli/nbt/libnbt.h"
#include "../libcli/smb/smbXcli_base.h"
#include "../libcli/smb/read_smb.h"

/*
  destroy a transport
 */
static int transport_destructor(struct smbcli_transport *transport)
{
	smbcli_transport_dead(transport, NT_STATUS_LOCAL_DISCONNECT);
	return 0;
}

/*
  create a transport structure based on an established socket
*/
struct smbcli_transport *smbcli_transport_init(struct smbcli_socket *sock,
					       TALLOC_CTX *parent_ctx, 
					       bool primary, 
					       struct smbcli_options *options)
{
	struct smbcli_transport *transport;
	uint32_t smb1_capabilities;

	transport = talloc_zero(parent_ctx, struct smbcli_transport);
	if (!transport) return NULL;

	transport->ev = sock->event.ctx;
	transport->options = *options;

	if (transport->options.max_protocol == PROTOCOL_DEFAULT) {
		transport->options.max_protocol = PROTOCOL_NT1;
	}

	if (transport->options.max_protocol > PROTOCOL_NT1) {
		transport->options.max_protocol = PROTOCOL_NT1;
	}

	TALLOC_FREE(sock->event.fde);
	TALLOC_FREE(sock->event.te);

	smb1_capabilities = 0;
	smb1_capabilities |= CAP_LARGE_FILES;
	smb1_capabilities |= CAP_NT_SMBS | CAP_RPC_REMOTE_APIS;
	smb1_capabilities |= CAP_LOCK_AND_READ | CAP_NT_FIND;
	smb1_capabilities |= CAP_DFS | CAP_W2K_SMBS;
	smb1_capabilities |= CAP_LARGE_READX|CAP_LARGE_WRITEX;
	smb1_capabilities |= CAP_LWIO;

	if (options->ntstatus_support) {
		smb1_capabilities |= CAP_STATUS32;
	}

	if (options->unicode) {
		smb1_capabilities |= CAP_UNICODE;
	}

	if (options->use_spnego) {
		smb1_capabilities |= CAP_EXTENDED_SECURITY;
	}

	if (options->use_level2_oplocks) {
		smb1_capabilities |= CAP_LEVEL_II_OPLOCKS;
	}

	transport->conn = smbXcli_conn_create(transport,
					      sock->sock->fd,
					      sock->hostname,
					      options->signing,
					      smb1_capabilities,
					      NULL, /* client_guid */
					      0); /* smb2_capabilities */
	if (transport->conn == NULL) {
		TALLOC_FREE(sock);
		TALLOC_FREE(transport);
		return NULL;
	}
	sock->sock->fd = -1;
	TALLOC_FREE(sock);

	talloc_set_destructor(transport, transport_destructor);

	return transport;
}

/*
  create a transport structure based on an established socket
*/
NTSTATUS smbcli_transport_raw_init(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   struct smbXcli_conn **_conn,
				   const struct smbcli_options *options,
				   struct smbcli_transport **_transport)
{
	struct smbcli_transport *transport = NULL;
	NTSTATUS status;

	if (*_conn == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	transport = talloc_zero(mem_ctx, struct smbcli_transport);
	if (transport == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	transport->ev = ev;
	transport->options = *options;

	/*
	 * First only set the pointer without move.
	 */
	transport->conn = *_conn;
	status = smb_raw_negotiate_fill_transport(transport);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(transport);
		return status;
	}

	talloc_set_destructor(transport, transport_destructor);

	/*
	 * Now move it away from the caller...
	 */
	transport->conn = talloc_move(transport, _conn);
	*_transport = transport;
	return NT_STATUS_OK;
}

/*
  mark the transport as dead
*/
void smbcli_transport_dead(struct smbcli_transport *transport, NTSTATUS status)
{
	if (NT_STATUS_EQUAL(NT_STATUS_UNSUCCESSFUL, status)) {
		status = NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}
	if (NT_STATUS_IS_OK(status)) {
		status = NT_STATUS_LOCAL_DISCONNECT;
	}

	smbXcli_conn_disconnect(transport->conn, status);
}

static void idle_handler(struct tevent_context *ev, 
			 struct tevent_timer *te, struct timeval t, void *private_data)
{
	struct smbcli_transport *transport = talloc_get_type(private_data,
							     struct smbcli_transport);
	struct timeval next;

	transport->idle.func(transport, transport->idle.private_data);

	if (transport->idle.func == NULL) {
		return;
	}

	if (!smbXcli_conn_is_connected(transport->conn)) {
		return;
	}

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
_PUBLIC_ void smbcli_transport_idle_handler(struct smbcli_transport *transport, 
				   void (*idle_func)(struct smbcli_transport *, void *),
				   uint64_t period,
				   void *private_data)
{
	TALLOC_FREE(transport->idle.te);
	ZERO_STRUCT(transport->idle);

	if (idle_func == NULL) {
		return;
	}

	if (!smbXcli_conn_is_connected(transport->conn)) {
		return;
	}

	transport->idle.func = idle_func;
	transport->idle.private_data = private_data;
	transport->idle.period = period;

	transport->idle.te = tevent_add_timer(transport->ev,
					      transport,
					      timeval_current_ofs_usec(period),
					      idle_handler,
					      transport);
}

/*
  process some read/write requests that are pending
  return false if the socket is dead
*/
_PUBLIC_ bool smbcli_transport_process(struct smbcli_transport *transport)
{
	struct tevent_req *subreq = NULL;
	int ret;

	if (!smbXcli_conn_is_connected(transport->conn)) {
		return false;
	}

	if (!smbXcli_conn_has_async_calls(transport->conn)) {
		return true;
	}

	/*
	 * do not block for more than 500 micro seconds
	 */
	subreq = tevent_wakeup_send(transport,
				    transport->ev,
				    timeval_current_ofs_usec(500));
	if (subreq == NULL) {
		return false;
	}

	ret = tevent_loop_once(transport->ev);
	if (ret != 0) {
		return false;
	}

	TALLOC_FREE(subreq);

	if (!smbXcli_conn_is_connected(transport->conn)) {
		return false;
	}

	return true;
}

static void smbcli_transport_break_handler(struct tevent_req *subreq);
static void smbcli_request_done(struct tevent_req *subreq);

struct tevent_req *smbcli_transport_setup_subreq(struct smbcli_request *req)
{
	struct smbcli_transport *transport = req->transport;
	uint8_t smb_command;
	uint8_t additional_flags;
	uint8_t clear_flags;
	uint16_t additional_flags2;
	uint16_t clear_flags2;
	uint32_t pid;
	struct smbXcli_tcon *tcon = NULL;
	struct smbXcli_session *session = NULL;
	uint32_t timeout_msec = transport->options.request_timeout * 1000;
	struct iovec *bytes_iov = NULL;
	struct tevent_req *subreq = NULL;

	smb_command = SVAL(req->out.hdr, HDR_COM);
	additional_flags = CVAL(req->out.hdr, HDR_FLG);
	additional_flags2 = SVAL(req->out.hdr, HDR_FLG2);
	pid  = SVAL(req->out.hdr, HDR_PID);
	pid |= SVAL(req->out.hdr, HDR_PIDHIGH)<<16;

	clear_flags = ~additional_flags;
	clear_flags2 = ~additional_flags2;

	if (req->session) {
		session = req->session->smbXcli;
	}

	if (req->tree) {
		tcon = req->tree->smbXcli;
	}

	bytes_iov = talloc(req, struct iovec);
	if (bytes_iov == NULL) {
		return NULL;
	}
	bytes_iov->iov_base = (void *)req->out.data;
	bytes_iov->iov_len = req->out.data_size;

	subreq = smb1cli_req_create(req,
				    transport->ev,
				    transport->conn,
				    smb_command,
				    additional_flags,
				    clear_flags,
				    additional_flags2,
				    clear_flags2,
				    timeout_msec,
				    pid,
				    tcon,
				    session,
				    req->out.wct,
				    (uint16_t *)req->out.vwv,
				    1, bytes_iov);
	if (subreq == NULL) {
		return NULL;
	}

	ZERO_STRUCT(req->out);

	return subreq;
}

/*
  put a request into the send queue
*/
void smbcli_transport_send(struct smbcli_request *req)
{
	struct smbcli_transport *transport = req->transport;
	NTSTATUS status;
	bool need_pending_break = false;
	struct tevent_req *subreq = NULL;
	size_t i;
	size_t num_subreqs = 0;

	if (transport->oplock.handler) {
		need_pending_break = true;
	}

	if (transport->break_subreq) {
		need_pending_break = false;
	}

	if (need_pending_break) {
		subreq = smb1cli_req_create(transport,
					    transport->ev,
					    transport->conn,
					    0, /* smb_command */
					    0, /* additional_flags */
					    0, /* clear_flags */
					    0, /* additional_flags2 */
					    0, /* clear_flags2 */
					    0, /* timeout_msec */
					    0, /* pid */
					    NULL, /* tcon */
					    NULL, /* session */
					    0, /* wct */
					    NULL, /* vwv */
					    0, /* iov_count */
					    NULL); /* bytes_iov */
		if (subreq != NULL) {
			smb1cli_req_set_mid(subreq, 0xFFFF);
			smbXcli_req_set_pending(subreq);
			tevent_req_set_callback(subreq,
						smbcli_transport_break_handler,
						transport);
			transport->break_subreq = subreq;
			subreq = NULL;
		}
	}

	subreq = smbcli_transport_setup_subreq(req);
	if (subreq == NULL) {
		req->state = SMBCLI_REQUEST_ERROR;
		req->status = NT_STATUS_NO_MEMORY;
		return;
	}

	for (i = 0; i < ARRAY_SIZE(req->subreqs); i++) {
		if (req->subreqs[i] == NULL) {
			req->subreqs[i] = subreq;
			subreq = NULL;
		}
		if (req->subreqs[i] == NULL) {
			break;
		}

		if (!tevent_req_is_in_progress(req->subreqs[i])) {
			req->state = SMBCLI_REQUEST_ERROR;
			req->status = NT_STATUS_INTERNAL_ERROR;
			return;
		}
	}
	num_subreqs = i;

	req->state = SMBCLI_REQUEST_RECV;
	tevent_req_set_callback(req->subreqs[0], smbcli_request_done, req);

	status = smb1cli_req_chain_submit(req->subreqs, num_subreqs);
	if (!NT_STATUS_IS_OK(status)) {
		req->status = status;
		req->state = SMBCLI_REQUEST_ERROR;
		smbXcli_conn_disconnect(transport->conn, status);
	}
}

static void smbcli_request_done(struct tevent_req *subreq)
{
	struct smbcli_request *req =
		tevent_req_callback_data(subreq,
		struct smbcli_request);
	struct smbcli_transport *transport = req->transport;
	ssize_t len;
	size_t i;
	uint8_t *hdr = NULL;
	uint8_t wct = 0;
	uint16_t *vwv = NULL;
	uint32_t num_bytes = 0;
	uint8_t *bytes = NULL;
	struct iovec *recv_iov = NULL;
	uint8_t *inbuf = NULL;

	req->status = smb1cli_req_recv(req->subreqs[0], req,
				       &recv_iov,
				       &hdr,
				       &wct,
				       &vwv,
				       NULL, /* pvwv_offset */
				       &num_bytes,
				       &bytes,
				       NULL, /* pbytes_offset */
				       &inbuf,
				       NULL, 0); /* expected */
	TALLOC_FREE(req->subreqs[0]);
	if (!NT_STATUS_IS_OK(req->status)) {
		if (recv_iov == NULL) {
			req->state = SMBCLI_REQUEST_ERROR;
			transport->error.e.nt_status = req->status;
			transport->error.etype = ETYPE_SOCKET;
			if (req->async.fn) {
				req->async.fn(req);
			}
			return;
		}
	}

	/*
	 * For SMBreadBraw hdr is NULL
	 */
	len = recv_iov[0].iov_len;
	for (i=1; hdr != NULL && i < 3; i++) {
		uint8_t *p = recv_iov[i-1].iov_base;
		uint8_t *c1 = recv_iov[i].iov_base;
		uint8_t *c2 = p + recv_iov[i-1].iov_len;

		len += recv_iov[i].iov_len;

		c2 += i;
		len += i;

		if (recv_iov[i].iov_len == 0) {
			continue;
		}

		if (c1 != c2) {
			req->state = SMBCLI_REQUEST_ERROR;
			req->status = NT_STATUS_INTERNAL_ERROR;
			transport->error.e.nt_status = req->status;
			transport->error.etype = ETYPE_SMB;
			if (req->async.fn) {
				req->async.fn(req);
			}
			return;
		}
	}

	/* fill in the 'in' portion of the matching request */
	req->in.buffer = inbuf;
	req->in.size = NBT_HDR_SIZE + len;
	req->in.allocated = req->in.size;

	req->in.hdr = hdr;
	req->in.vwv = (uint8_t *)vwv;
	req->in.wct = wct;
	req->in.data = bytes;
	req->in.data_size = num_bytes;
	req->in.ptr = req->in.data;
	if (hdr != NULL) {
		req->flags2 = SVAL(req->in.hdr, HDR_FLG2);
	}

	smb_setup_bufinfo(req);

	transport->error.e.nt_status = req->status;
	if (NT_STATUS_IS_OK(req->status)) {
		transport->error.etype = ETYPE_NONE;
	} else {
		transport->error.etype = ETYPE_SMB;
	}

	req->state = SMBCLI_REQUEST_DONE;
	if (req->async.fn) {
		req->async.fn(req);
	}
}

static void smbcli_transport_break_handler(struct tevent_req *subreq)
{
	struct smbcli_transport *transport =
		tevent_req_callback_data(subreq,
		struct smbcli_transport);
	NTSTATUS status;
	struct iovec *recv_iov = NULL;
	uint8_t *hdr = NULL;
	uint16_t *vwv = NULL;
	const struct smb1cli_req_expected_response expected[] = {
	{
		.status = NT_STATUS_OK,
		.wct = 8,
	}
	};
	uint16_t tid;
	uint16_t fnum;
	uint8_t level;

	transport->break_subreq = NULL;

	status = smb1cli_req_recv(subreq, transport,
				  &recv_iov,
				  &hdr,
				  NULL, /* pwct */
				  &vwv,
				  NULL, /* pvwv_offset */
				  NULL, /* pnum_bytes */
				  NULL, /* pbytes */
				  NULL, /* pbytes_offset */
				  NULL, /* pinbuf */
				  expected,
				  ARRAY_SIZE(expected));
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(recv_iov);
		smbcli_transport_dead(transport, status);
		return;
	}

	/*
	 * Setup the subreq to handle the
	 * next incoming SMB2 Break.
	 */
	subreq = smb1cli_req_create(transport,
				    transport->ev,
				    transport->conn,
				    0, /* smb_command */
				    0, /* additional_flags */
				    0, /* clear_flags */
				    0, /* additional_flags2 */
				    0, /* clear_flags2 */
				    0, /* timeout_msec */
				    0, /* pid */
				    NULL, /* tcon */
				    NULL, /* session */
				    0, /* wct */
				    NULL, /* vwv */
				    0, /* iov_count */
				    NULL); /* bytes_iov */
	if (subreq != NULL) {
		smb1cli_req_set_mid(subreq, 0xFFFF);
		smbXcli_req_set_pending(subreq);
		tevent_req_set_callback(subreq,
					smbcli_transport_break_handler,
					transport);
		transport->break_subreq = subreq;
	}

	tid = SVAL(hdr, HDR_TID);
	fnum = SVAL(vwv+2, 0);
	level = CVAL(vwv+3, 1);

	TALLOC_FREE(recv_iov);

	if (transport->oplock.handler) {
		transport->oplock.handler(transport, tid, fnum, level,
					  transport->oplock.private_data);
	} else {
		DEBUG(5,("Got SMB oplock break with no handler\n"));
	}

}


/****************************************************************************
 Send an SMBecho (async send)
*****************************************************************************/
_PUBLIC_ struct smbcli_request *smb_raw_echo_send(struct smbcli_transport *transport,
					 struct smb_echo *p)
{
	struct smbcli_request *req;

	req = smbcli_request_setup_transport(transport, SMBecho, 1, p->in.size);
	if (!req) return NULL;

	SSVAL(req->out.vwv, VWV(0), p->in.repeat_count);

	memcpy(req->out.data, p->in.data, p->in.size);

	ZERO_STRUCT(p->out);

	if (!smbcli_request_send(req)) {
		smbcli_request_destroy(req);
		return NULL;
	}

	return req;
}

/****************************************************************************
 raw echo interface (async recv)
****************************************************************************/
NTSTATUS smb_raw_echo_recv(struct smbcli_request *req, TALLOC_CTX *mem_ctx,
			   struct smb_echo *p)
{
	if (!smbcli_request_receive(req) ||
	    smbcli_request_is_error(req)) {
		goto failed;
	}

	SMBCLI_CHECK_WCT(req, 1);
	p->out.count++;
	p->out.sequence_number = SVAL(req->in.vwv, VWV(0));
	p->out.size = req->in.data_size;
	talloc_free(p->out.data);
	p->out.data = talloc_array(mem_ctx, uint8_t, p->out.size);
	NT_STATUS_HAVE_NO_MEMORY(p->out.data);

	if (!smbcli_raw_pull_data(&req->in.bufinfo, req->in.data, p->out.size, p->out.data)) {
		req->status = NT_STATUS_BUFFER_TOO_SMALL;
	}

	if (p->out.count == p->in.repeat_count) {
		return smbcli_request_destroy(req);
	}

	return NT_STATUS_OK;

failed:
	return smbcli_request_destroy(req);
}

/****************************************************************************
 Send a echo (sync interface)
*****************************************************************************/
NTSTATUS smb_raw_echo(struct smbcli_transport *transport, struct smb_echo *p)
{
	struct smbcli_request *req = smb_raw_echo_send(transport, p);
	return smbcli_request_simple_recv(req);
}
