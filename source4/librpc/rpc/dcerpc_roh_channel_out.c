/*
   Unix SMB/CIFS implementation.

   [MS-RPCH] - RPC over HTTP client

   Copyright (C) 2013 Samuel Cabrero <samuelcabrero@kernevil.me>
   Copyright (C) Julien Kerihuel <j.kerihuel@openchange.org> 2013

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
#include <tevent.h>
#include <talloc.h>
#include "lib/tsocket/tsocket.h"
#include "lib/tls/tls.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/util/util_net.h"
#include "libcli/resolve/resolve.h"
#include "libcli/composite/composite.h"
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_internal.h"
#include <gen_ndr/dcerpc.h>
#include <gen_ndr/ndr_dcerpc.h>

#include "librpc/rpc/dcerpc.h"
#include "librpc/rpc/dcerpc_roh.h"
#include "librpc/rpc/dcerpc_proto.h"
#include "libcli/http/http.h"

struct roh_request_state {
	struct http_request	*request;
	struct http_request	*response;
};

static void roh_send_RPC_DATA_OUT_done(struct tevent_req *subreq);
struct tevent_req *roh_send_RPC_DATA_OUT_send(TALLOC_CTX *mem_ctx,
					      struct loadparm_context *lp_ctx,
					      struct tevent_context *ev,
					      struct cli_credentials *credentials,
					      struct roh_connection *roh,
					      const char *rpc_server,
					      uint32_t rpc_server_port,
					      const char *rpc_proxy,
					      uint8_t http_auth)
{
	struct tevent_req		*req;
	struct tevent_req		*subreq;
	struct roh_request_state	*state;
	const char			*path;
	char				*query;
	char				*uri;

	DEBUG(8, ("%s: Sending RPC_OUT_DATA request\n", __func__));

	req = tevent_req_create(mem_ctx, &state, struct roh_request_state);
	if (req == NULL) {
		return NULL;
	}

	state->request = talloc_zero(state, struct http_request);
	if (tevent_req_nomem(state->request, req)) {
		return tevent_req_post(req, ev);
	}

	/* Build URI, as specified in section 2.2.2 */
	query = talloc_asprintf(state, "%s:%d", rpc_server, rpc_server_port);
	if (tevent_req_nomem(query, req)) {
		return tevent_req_post(req, ev);
	}

	/*
	 * TODO This path changes to "/rpcwithcert/rpcproxy.dll" when using
	 * certificates
	 */
	path = "/rpc/rpcproxy.dll";
	uri = talloc_asprintf(state, "%s?%s", path, query);
	if (tevent_req_nomem(uri, req)) {
		tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
		return tevent_req_post(req, ev);
	}
	TALLOC_FREE(query);

	/*
	 * Create the HTTP channel OUT request as specified in the
	 * section 2.1.2.1.2
	 */
	state->request->type = HTTP_REQ_RPC_OUT_DATA;
	state->request->uri = uri;
	state->request->body.length = 0;
	state->request->body.data = NULL;
	state->request->major = '1';
	state->request->minor = '0';

	http_add_header(state, &state->request->headers,
			"Accept", "application/rpc");
	http_add_header(state, &state->request->headers,
			"User-Agent", "MSRPC");
	http_add_header(state, &state->request->headers,
			"Host", rpc_proxy);
	http_add_header(state, &state->request->headers,
			"Connection", "keep-alive");
	http_add_header(state, &state->request->headers,
			"Content-Length", "76");
	http_add_header(state, &state->request->headers,
			"Cache-Control", "no-cache");
	http_add_header(state, &state->request->headers,
			"Pragma", "no-cache");

	subreq = http_send_auth_request_send(state,
					ev,
					roh->default_channel_out->http_conn,
					state->request,
					credentials,
					lp_ctx,
					http_auth);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, roh_send_RPC_DATA_OUT_done, req);

	return req;
}

static void roh_send_RPC_DATA_OUT_done(struct tevent_req *subreq)
{
	NTSTATUS		status;
	struct tevent_req	*req;

	req = tevent_req_callback_data(subreq, struct tevent_req);

	/* Receive the sent bytes to check if request has been properly sent */
	status = http_send_auth_request_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	DEBUG(8, ("%s: RPC_OUT_DATA sent", __func__));

	tevent_req_done(req);
}

NTSTATUS roh_send_RPC_DATA_OUT_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct roh_send_pdu_state {
	DATA_BLOB	buffer;
	struct iovec	iov;
	int		bytes_written;
	int		sys_errno;
};

static void roh_send_CONN_A1_done(struct tevent_req *subreq);
struct tevent_req *roh_send_CONN_A1_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct roh_connection *roh)
{
	struct tevent_req		*req;
	struct tevent_req		*subreq;
	struct roh_send_pdu_state	*state;
	struct dcerpc_rts		rts;
	struct ncacn_packet		pkt;
	struct ndr_push			*ndr;
	struct tstream_context          *stream = NULL;
	struct tevent_queue             *send_queue = NULL;

	DEBUG(8, ("%s: Sending CONN/A1 request\n", __func__));

	req = tevent_req_create(mem_ctx, &state, struct roh_send_pdu_state);
	if (req == NULL) {
		return NULL;
	}

	rts.Flags = RTS_FLAG_NONE;
	rts.NumberOfCommands = 4;
	rts.Commands = talloc_array(state, struct dcerpc_rts_cmd, 4);

	/* CONN/A1: Version RTS command */
	rts.Commands[0].CommandType = 0x00000006;
	rts.Commands[0].Command.Version.Version = 0x00000001;

	/* CONN/A1: VirtualConnectionCookie RTS command */
	rts.Commands[1].CommandType = 0x00000003;
	rts.Commands[1].Command.Cookie.Cookie.Cookie = roh->connection_cookie;

	/* CONN/A1: OutChannelCookie RTS command */
	rts.Commands[2].CommandType = 0x00000003;
	rts.Commands[2].Command.Cookie.Cookie.Cookie =
			roh->default_channel_out->channel_cookie;

	/* CONN/A1: ReceiveWindowSize */
	rts.Commands[3].CommandType = 0x00000000;
	rts.Commands[3].Command.ReceiveWindowSize.ReceiveWindowSize = 0x40000;

	pkt.rpc_vers = 5;
	pkt.rpc_vers_minor = 0;
	pkt.ptype = DCERPC_PKT_RTS;
	pkt.pfc_flags = DCERPC_PFC_FLAG_LAST | DCERPC_PFC_FLAG_FIRST;
	pkt.drep[0] = DCERPC_DREP_LE;
	pkt.drep[1] = 0;
	pkt.drep[2] = 0;
	pkt.drep[3] = 0;
	pkt.frag_length = 76;
	pkt.auth_length = 0;
	pkt.call_id = 0;
	pkt.u.rts = rts;

	ndr = ndr_push_init_ctx(state);
	if (ndr == NULL) {
		return NULL;
	}
	ndr->offset = 0;
	ndr_push_ncacn_packet(ndr, NDR_SCALARS, &pkt);

	state->buffer = ndr_push_blob(ndr);
	state->iov.iov_base = (char *) state->buffer.data;
	state->iov.iov_len = state->buffer.length;

	stream = http_conn_tstream(roh->default_channel_out->http_conn);
	send_queue = http_conn_send_queue(roh->default_channel_out->http_conn);

	subreq = tstream_writev_queue_send(mem_ctx,
					   ev,
					   stream,
					   send_queue,
					   &state->iov,
					   1);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, roh_send_CONN_A1_done, req);

	return req;
}

static void roh_send_CONN_A1_done(struct tevent_req *subreq)
{
	NTSTATUS			status;
	struct tevent_req		*req;
	struct roh_send_pdu_state	*state;
	int				sys_errno;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_send_pdu_state);

	state->bytes_written = tstream_writev_queue_recv(subreq, &sys_errno);
	state->sys_errno = sys_errno;
	TALLOC_FREE(subreq);
	if (state->bytes_written <= 0 && sys_errno != 0) {
		status = map_nt_error_from_unix_common(sys_errno);
		tevent_req_nterror(req, status);
		return;
	}
	DEBUG(8, ("%s: CONN/A1 sent (%d bytes written)\n",
		  __func__, state->bytes_written));

	tevent_req_done(req);
}

NTSTATUS roh_send_CONN_A1_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct roh_recv_response_state
{
	struct http_request	*response;
};

static void roh_recv_out_channel_response_done(struct tevent_req *);
struct tevent_req *roh_recv_out_channel_response_send(TALLOC_CTX *mem_ctx,
						      struct tevent_context *ev,
						      struct roh_connection *roh)
{
	struct tevent_req		*req;
	struct tevent_req		*subreq;
	struct roh_recv_response_state	*state;

	DEBUG(8, ("%s: Waiting for RPC_OUT_DATA response\n", __func__));

	req = tevent_req_create(mem_ctx, &state, struct roh_recv_response_state);
	if (req == NULL) {
		return NULL;
	}

	subreq = http_read_response_send(state, ev,
					 roh->default_channel_out->http_conn,
					 0); /* we'll get the content later */
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, roh_recv_out_channel_response_done, req);

	return req;
}

static void roh_recv_out_channel_response_done(struct tevent_req *subreq)
{
	NTSTATUS			status;
	struct tevent_req		*req;
	struct roh_recv_response_state	*state;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_recv_response_state);
	status = http_read_response_recv(subreq, state, &state->response);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	DEBUG(8, ("%s: RCP_OUT_DATA response received\n", __func__));

	/* TODO Map response code to nt error */
	switch (state->response->response_code) {
	case 200:
		break;
	case 401:
		DEBUG(0, ("%s: Server response: Access denied\n", __func__));
		tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
		return;
	case 503:
		/* TODO Decode error info as specified in section 2.1.2.1.3 */
		DEBUG(0, ("%s: Server response: RPC error\n", __func__));
		tevent_req_nterror(req, NT_STATUS_GENERIC_NOT_MAPPED);
		return;
	default:
		DEBUG(0, ("%s: Server response: Unknown error\n", __func__));
		tevent_req_nterror(req, NT_STATUS_GENERIC_NOT_MAPPED);
		return;
	}

	tevent_req_done(req);
}

NTSTATUS roh_recv_out_channel_response_recv(struct tevent_req *req,
		TALLOC_CTX *mem_ctx,
		char **response_msg)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct roh_recv_pdu_state {
	struct roh_connection	*roh;
	uint32_t		connection_timeout;
	uint32_t		version;
	uint32_t		recv_window_size;
};

static void roh_recv_CONN_A3_done(struct tevent_req *subreq);
struct tevent_req *roh_recv_CONN_A3_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct roh_connection *roh)
{
	struct tevent_req		*req;
	struct tevent_req		*subreq;
	struct roh_recv_pdu_state	*state;
	struct tstream_context          *stream = NULL;

	req = tevent_req_create(mem_ctx, &state, struct roh_recv_pdu_state);
	if (req == NULL) {
		return NULL;
	}

	DEBUG(8, ("%s: Waiting for CONN/A3\n", __func__));

	stream = http_conn_tstream(roh->default_channel_out->http_conn);

	subreq = dcerpc_read_ncacn_packet_send(state, ev, stream);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, roh_recv_CONN_A3_done, req);

	return req;
}

static void roh_recv_CONN_A3_done(struct tevent_req *subreq)
{
	NTSTATUS			status;
	struct tevent_req		*req;
	struct roh_recv_pdu_state	*state;
	struct ncacn_packet		*pkt;
	DATA_BLOB			buffer;
	struct dcerpc_rts		rts;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_recv_pdu_state);
	status = dcerpc_read_ncacn_packet_recv(subreq, state, &pkt, &buffer);
	TALLOC_FREE(subreq);

	if (tevent_req_nterror(req, status)) {
		DEBUG(0, ("%s: Error receiving PDU\n", __func__));
		return;
	}

	/*
	 * Check if it is a CONN/A3 (2.2.4.4) packet and get the connection
	 * timeout
	 */
	rts = pkt->u.rts;
	if (rts.NumberOfCommands != 1) {
		DEBUG(0, ("%s: Invalid number of commands received\n", __func__));
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	if (rts.Commands[0].CommandType != ROH_CMD_TYPE_CONNECTION_TIMEOUT) {
		DEBUG(0, ("%s: Invalid command type received\n", __func__));
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	/* Extract connection timeout */
	state->connection_timeout = rts.Commands[0].Command.ConnectionTimeout.ConnectionTimeout;

	DEBUG(8, ("%s: CONN/A3 received, connection timeout is %u\n",
		  __func__, state->connection_timeout));
	tevent_req_done(req);
}

NTSTATUS roh_recv_CONN_A3_recv(struct tevent_req *req,
			       unsigned int *connection_timeout)
{
	NTSTATUS			status;
	struct roh_recv_pdu_state	*state;

	state = tevent_req_data(req, struct roh_recv_pdu_state);
	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*connection_timeout = state->connection_timeout;

	tevent_req_received(req);
	return NT_STATUS_OK;
}

static void roh_recv_CONN_C2_done(struct tevent_req *subreq);
struct tevent_req *roh_recv_CONN_C2_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct roh_connection *roh)
{
	struct tevent_req		*req;
	struct tevent_req		*subreq;
	struct roh_recv_pdu_state	*state;
	struct tstream_context		*stream = NULL;

	req = tevent_req_create(mem_ctx, &state, struct roh_recv_pdu_state);
	if (req == NULL) {
		return NULL;
	}

	DEBUG(8, ("%s: Waiting for CONN/C2\n", __func__));
	stream = http_conn_tstream(roh->default_channel_out->http_conn);

	subreq = dcerpc_read_ncacn_packet_send(state, ev, stream);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, roh_recv_CONN_C2_done, req);

	return req;
}

static void roh_recv_CONN_C2_done(struct tevent_req *subreq)
{
	NTSTATUS			status;
	struct tevent_req		*req;
	struct roh_recv_pdu_state	*state;
	struct ncacn_packet		*pkt;
	DATA_BLOB			buffer;
	struct dcerpc_rts		rts;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_recv_pdu_state);

	status = dcerpc_read_ncacn_packet_recv(subreq, state, &pkt, &buffer);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		DEBUG(0, ("%s: Error receiving PDU\n", __func__));
		return;
	}

	/*
	 * Check if it is a CONN/C2 packet (2.2.4.9), and get the version, the
	 * receive windows size and the connection timeout for the IN channel
	 */
	rts = pkt->u.rts;
	if (rts.NumberOfCommands != 3) {
		DEBUG(0, ("%s: Invalid number of commands received\n",
			  __func__));
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}
	if (rts.Commands[0].CommandType != ROH_CMD_TYPE_VERSION) {
		DEBUG(0, ("%s: Invalid command type received\n", __func__));
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}
	if (rts.Commands[1].CommandType != ROH_CMD_TYPE_RECV_WINDOWS_SIZE) {
		DEBUG(0, ("%s: Invalid command type received\n", __func__));
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}
	if (rts.Commands[2].CommandType != ROH_CMD_TYPE_CONNECTION_TIMEOUT) {
		DEBUG(0, ("%s: Invalid command type received\n", __func__));
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	/* Extract data */
	state->version = rts.Commands[0].Command.Version.Version;
	state->recv_window_size = rts.Commands[1].Command.ReceiveWindowSize.ReceiveWindowSize;
	state->connection_timeout = rts.Commands[2].Command.ConnectionTimeout.ConnectionTimeout;

	DEBUG(8, ("%s: CONN/C2 received, version is %u, receive windows size is %u, connection timeout is %u\n",
		  __func__, state->version, state->recv_window_size,
		  state->connection_timeout));
	tevent_req_done(req);
}

NTSTATUS roh_recv_CONN_C2_recv(struct tevent_req *req,
			       unsigned int *version,
			       unsigned int *recv_window_size,
			       unsigned int *connection_timeout)
{
	NTSTATUS			status;
	struct roh_recv_pdu_state	*state;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	state =  tevent_req_data(req, struct roh_recv_pdu_state);
	*version = state->version;
	*recv_window_size = state->recv_window_size;
	*connection_timeout = state->connection_timeout;

	tevent_req_received(req);
	return NT_STATUS_OK;
}
