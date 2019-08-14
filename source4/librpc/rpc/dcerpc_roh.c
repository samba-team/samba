/*
   Unix SMB/CIFS implementation.

   [MS-RPCH] - RPC over HTTP client

   Copyright (C) 2013 Samuel Cabrero <samuelcabrero@kernevil.me>

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
#include "lib/util/tevent_ntstatus.h"
#include "lib/tls/tls.h"
#include "libcli/resolve/resolve.h"
#include "libcli/composite/composite.h"
#include "auth/credentials/credentials.h"
#include "tsocket/tsocket.h"
#include "tsocket/tsocket_internal.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/rpc/dcerpc_roh.h"
#include "librpc/rpc/dcerpc_proto.h"
#include "lib/param/param.h"
#include "libcli/http/http.h"
#include "lib/util/util_net.h"

static ssize_t tstream_roh_pending_bytes(struct tstream_context *stream);
static struct tevent_req * tstream_roh_readv_send(
		TALLOC_CTX *mem_ctx,
		struct tevent_context *ev,
		struct tstream_context *stream,
		struct iovec *vector,
		size_t count);
static int tstream_roh_readv_recv(struct tevent_req *req, int *perrno);
static struct tevent_req * tstream_roh_writev_send(
		TALLOC_CTX *mem_ctx,
		struct tevent_context *ev,
		struct tstream_context *stream,
		const struct iovec *vector,
		size_t count);
static int tstream_roh_writev_recv(struct tevent_req *req, int *perrno);
static struct tevent_req * tstream_roh_disconnect_send(
		TALLOC_CTX *mem_ctx,
		struct tevent_context *ev,
		struct tstream_context *stream);
static int tstream_roh_disconnect_recv(struct tevent_req *req, int *perrno);

static const struct tstream_context_ops tstream_roh_ops = {
	.name			= "roh",
	.pending_bytes		= tstream_roh_pending_bytes,
	.readv_send		= tstream_roh_readv_send,
	.readv_recv		= tstream_roh_readv_recv,
	.writev_send		= tstream_roh_writev_send,
	.writev_recv		= tstream_roh_writev_recv,
	.disconnect_send	= tstream_roh_disconnect_send,
	.disconnect_recv	= tstream_roh_disconnect_recv,
};

struct tstream_roh_context {
	struct roh_connection *roh_conn;
};

struct roh_open_connection_state {
	struct tevent_req		*req;
	struct tevent_context		*event_ctx;
	struct cli_credentials		*credentials;
	struct resolve_context		*resolve_ctx;
	const char			**rpcproxy_addresses;
	unsigned int			rpcproxy_address_index;

	struct dcecli_connection	*conn;
	bool				tls;

	const char			*rpc_proxy;
	unsigned int			rpc_proxy_port;
	const char			*rpc_server;
	unsigned int			rpc_server_port;
	const char			*target_hostname;

	struct roh_connection		*roh;
	struct tstream_tls_params	*tls_params;
	struct loadparm_context		*lp_ctx;
	uint8_t				http_auth;
};

NTSTATUS dcerpc_pipe_open_roh_recv(struct tevent_req *req,
				   TALLOC_CTX *mem_ctx,
				   struct tstream_context **stream,
				   struct tevent_queue **queue)
{
	struct roh_open_connection_state *state;
	struct tstream_roh_context *roh_stream_ctx;
	NTSTATUS status;

	state = tevent_req_data(req, struct roh_open_connection_state);
	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*stream = tstream_context_create(mem_ctx, &tstream_roh_ops,
					 &roh_stream_ctx,
					 struct tstream_roh_context,
					 __location__);
	if (!stream) {
		tevent_req_received(req);
		return NT_STATUS_NO_MEMORY;
	}
	ZERO_STRUCTP(roh_stream_ctx);

	roh_stream_ctx->roh_conn = talloc_move(mem_ctx, &state->roh);
	*queue = http_conn_send_queue(
			roh_stream_ctx->roh_conn->default_channel_in->http_conn);

	tevent_req_received(req);

	return NT_STATUS_OK;
}

struct roh_connect_channel_state {
	struct roh_channel *channel;
};

static void roh_connect_channel_done(struct tevent_req *subreq);
static struct tevent_req *roh_connect_channel_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					const char *rpcproxy_ip_address,
					unsigned int rpcproxy_port,
					struct cli_credentials *credentials,
					bool tls,
					struct tstream_tls_params *tls_params)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct roh_connect_channel_state *state = NULL;

	DBG_DEBUG("Connecting ROH channel socket, RPC proxy is "
		  "%s:%d (TLS: %s)\n", rpcproxy_ip_address, rpcproxy_port,
		  (tls ? "true" : "false"));

	req = tevent_req_create(mem_ctx, &state,
				struct roh_connect_channel_state);
	if (req == NULL) {
		return NULL;
	}

	if (!is_ipaddress(rpcproxy_ip_address)) {
		DBG_ERR("Invalid host (%s), needs to be an IP address\n",
			rpcproxy_ip_address);
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	/* Initialize channel structure */
	state->channel = talloc_zero(state, struct roh_channel);
	if (tevent_req_nomem(state->channel, req)) {
		return tevent_req_post(req, ev);
	}

	state->channel->channel_cookie = GUID_random();

	subreq = http_connect_send(state,
				   ev,
				   rpcproxy_ip_address,
				   rpcproxy_port,
				   credentials,
				   tls ? tls_params : NULL);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, roh_connect_channel_done, req);

	return req;
}

static void roh_connect_channel_done(struct tevent_req *subreq)
{
	struct tevent_req *req = NULL;
	struct roh_connect_channel_state *state = NULL;
	NTSTATUS status;
	int ret;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_connect_channel_state);

	ret = http_connect_recv(subreq,
				state->channel,
				&state->channel->http_conn);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		status = map_nt_error_from_unix_common(ret);
		tevent_req_nterror(req, status);
		return;
	}

	DBG_DEBUG("HTTP connected\n");
	tevent_req_done(req);
}

static NTSTATUS roh_connect_channel_recv(struct tevent_req *req,
					 TALLOC_CTX *mem_ctx,
					 struct roh_channel **channel)
{
	struct roh_connect_channel_state *state = tevent_req_data(
		req, struct roh_connect_channel_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*channel = talloc_move(mem_ctx, &state->channel);
	tevent_req_received(req);

	return NT_STATUS_OK;
}

static void roh_continue_resolve_name(struct composite_context *ctx);

/**
 * Send rpc pipe open request to given host:port using http transport
 */
struct tevent_req *dcerpc_pipe_open_roh_send(struct dcecli_connection *conn,
					     const char *localaddr,
					     const char *rpc_server,
					     uint32_t rpc_server_port,
					     const char *rpc_proxy,
					     uint32_t rpc_proxy_port,
					     const char *http_proxy,
					     uint32_t http_proxy_port,
					     bool use_tls,
					     bool use_proxy,
					     struct cli_credentials *credentials,
					     struct resolve_context *resolve_ctx,
					     struct loadparm_context *lp_ctx,
					     uint8_t http_auth)
{
	NTSTATUS				status;
	struct tevent_req			*req;
	struct composite_context		*ctx;
	struct roh_open_connection_state	*state;
	struct nbt_name				name;

	req = tevent_req_create(conn, &state, struct roh_open_connection_state);
	if (req == NULL) {
		return NULL;
	}

	/* Set state fields */
	state->req = req;
	state->event_ctx = conn->event_ctx;
	state->lp_ctx = lp_ctx,
	state->credentials = credentials;
	state->conn = conn;
	state->tls = use_tls;

	/* Initialize connection structure (3.2.1.3) */
	/* TODO Initialize virtual connection cookie table */
	state->rpc_server = talloc_strdup(state, rpc_server);
	state->rpc_server_port = rpc_server_port;
	state->rpc_proxy = talloc_strdup(state, rpc_proxy);
	state->rpc_proxy_port = rpc_proxy_port;
	state->http_auth = http_auth;

	state->roh = talloc_zero(state, struct roh_connection);
	state->roh->protocol_version = ROH_V2;
	state->roh->connection_state = ROH_STATE_OPEN_START;
	state->roh->connection_cookie = GUID_random();
	state->roh->association_group_id_cookie = GUID_random();

	/* Additional initialization steps (3.2.2.3) */
	state->roh->proxy_use = use_proxy;
	state->roh->current_keep_alive_time = 0;
	state->roh->current_keep_alive_interval = 0;

	/* Initialize TLS */
	if (use_tls) {
		char *ca_file = lpcfg_tls_cafile(state, lp_ctx);
		char *crl_file = lpcfg_tls_crlfile(state, lp_ctx);
		const char *tls_priority = lpcfg_tls_priority(lp_ctx);
		enum tls_verify_peer_state verify_peer =
			lpcfg_tls_verify_peer(lp_ctx);

		status = tstream_tls_params_client(state->roh,
						   ca_file, crl_file,
						   tls_priority,
						   verify_peer,
						   state->rpc_proxy,
						   &state->tls_params);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("%s: Failed tstream_tls_params_client - %s\n",
				 __func__, nt_errstr(status)));
			tevent_req_nterror(req, status);
			return tevent_req_post(req, conn->event_ctx);
		}
	}

	/* Resolve RPC proxy server name */
	make_nbt_name_server(&name, state->rpc_proxy);
	ctx = resolve_name_send(resolve_ctx, state, &name, state->event_ctx);
	if (tevent_req_nomem(ctx, req)) {
		return tevent_req_post(req, state->event_ctx);
	}
	ctx->async.fn = roh_continue_resolve_name;
	ctx->async.private_data = state;

	return req;
}

static void roh_connect_channel_in_done(struct tevent_req *subreq);
static void roh_continue_resolve_name(struct composite_context *ctx)
{
	NTSTATUS				status;
	struct roh_open_connection_state	*state;
	struct tevent_req			*subreq;

	state = talloc_get_type_abort(ctx->async.private_data,
				      struct roh_open_connection_state);
	status = resolve_name_multiple_recv(ctx, state,
					    &state->rpcproxy_addresses);
	if (tevent_req_nterror(state->req, status)) {
		DEBUG(2, ("%s: No server found: %s\n", __func__,
			  nt_errstr(status)));
		return;
	}

	state->rpcproxy_address_index = 0;
	if (state->rpcproxy_addresses[state->rpcproxy_address_index] == NULL) {
		DEBUG(2, ("%s: No server found\n", __func__));
		tevent_req_nterror(state->req, NT_STATUS_OBJECT_NAME_NOT_FOUND);
		return;
	}

	/*
	 * TODO Determine proxy use
	 * If state->roh->proxy_use == true, the client has requested to
	 * always use local proxy. Otherwise, run the proxy use discovery
	 */
	state->roh->connection_state = ROH_STATE_OPEN_START;
	subreq = roh_connect_channel_send(state,
					  state->event_ctx,
					  state->rpcproxy_addresses[state->rpcproxy_address_index],
					  state->rpc_proxy_port,
					  state->credentials,
					  state->tls,
					  state->tls_params);
	if (tevent_req_nomem(subreq, state->req)) {
		return;
	}
	tevent_req_set_callback(subreq, roh_connect_channel_in_done, state->req);
}

static void roh_connect_channel_out_done(struct tevent_req *);
static void roh_connect_channel_in_done(struct tevent_req *subreq)
{
	NTSTATUS				status;
	struct tevent_req			*req;
	struct roh_open_connection_state	*state;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_open_connection_state);

	status = roh_connect_channel_recv(subreq, state->roh,
					  &state->roh->default_channel_in);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = roh_connect_channel_send(state,
					  state->event_ctx,
					  state->rpcproxy_addresses[state->rpcproxy_address_index],
					  state->rpc_proxy_port,
					  state->credentials,
					  state->tls,
					  state->tls_params);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, roh_connect_channel_out_done, req);
}

static void roh_send_RPC_DATA_IN_done(struct tevent_req *);
static void roh_connect_channel_out_done(struct tevent_req *subreq)
{
	NTSTATUS				status;
	struct tevent_req			*req;
	struct roh_open_connection_state	*state;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_open_connection_state);

	status = roh_connect_channel_recv(subreq, state->roh,
					  &state->roh->default_channel_out);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = roh_send_RPC_DATA_IN_send(state, state->lp_ctx,
					   state->event_ctx,
					   state->credentials,
					   state->roh,
					   state->rpc_server,
					   state->rpc_server_port,
					   state->rpc_proxy,
					   state->http_auth);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, roh_send_RPC_DATA_IN_done, req);
}

static void roh_send_RPC_DATA_OUT_done(struct tevent_req *);
static void roh_send_RPC_DATA_IN_done(struct tevent_req *subreq)
{
	NTSTATUS				status;
	struct tevent_req			*req;
	struct roh_open_connection_state	*state;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_open_connection_state);

	status = roh_send_RPC_DATA_IN_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = roh_send_RPC_DATA_OUT_send(state,
					    state->lp_ctx,
					    state->event_ctx,
					    state->credentials,
					    state->roh,
					    state->rpc_server,
					    state->rpc_server_port,
					    state->rpc_proxy,
					    state->http_auth);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, roh_send_RPC_DATA_OUT_done, req);
}

static void roh_send_CONN_A1_done(struct tevent_req *);
static void roh_send_RPC_DATA_OUT_done(struct tevent_req *subreq)
{
	NTSTATUS				status;
	struct tevent_req			*req;
	struct roh_open_connection_state	*state;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_open_connection_state);

	status = roh_send_RPC_DATA_OUT_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = roh_send_CONN_A1_send(state, state->event_ctx, state->roh);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, roh_send_CONN_A1_done, req);
}

static void roh_send_CONN_B1_done(struct tevent_req *);
static void roh_send_CONN_A1_done(struct tevent_req *subreq)
{
	NTSTATUS				status;
	struct tevent_req			*req;
	struct roh_open_connection_state	*state;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_open_connection_state);

	status = roh_send_CONN_A1_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = roh_send_CONN_B1_send(state, state->event_ctx, state->roh);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, roh_send_CONN_B1_done, req);
}

static void roh_recv_out_channel_response_done(struct tevent_req *);
static void roh_send_CONN_B1_done(struct tevent_req *subreq)
{
	NTSTATUS				status;
	struct tevent_req			*req;
	struct roh_open_connection_state	*state;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_open_connection_state);

	status = roh_send_CONN_B1_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->roh->connection_state = ROH_STATE_OUT_CHANNEL_WAIT;
	subreq = roh_recv_out_channel_response_send(state, state->event_ctx,
						    state->roh);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, roh_recv_out_channel_response_done, req);
}

static void roh_recv_CONN_A3_done(struct tevent_req *);
static void roh_recv_out_channel_response_done(struct tevent_req *subreq)
{
	NTSTATUS				status;
	char					*response;
	struct tevent_req			*req;
	struct roh_open_connection_state	*state;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_open_connection_state);

	status = roh_recv_out_channel_response_recv(subreq, state, &response);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->roh->connection_state = ROH_STATE_WAIT_A3W;
	subreq = roh_recv_CONN_A3_send(state, state->event_ctx, state->roh);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, roh_recv_CONN_A3_done, req);
}

static void roh_recv_CONN_C2_done(struct tevent_req *);
static void roh_recv_CONN_A3_done(struct tevent_req *subreq)
{
	NTSTATUS				status;
	struct tevent_req			*req;
	struct roh_open_connection_state	*state;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_open_connection_state);

	status = roh_recv_CONN_A3_recv(subreq, &state->roh->default_channel_out->connection_timeout);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->roh->connection_state = ROH_STATE_WAIT_C2;
	subreq = roh_recv_CONN_C2_send(state, state->event_ctx, state->roh);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, roh_recv_CONN_C2_done, req);
}

static void roh_recv_CONN_C2_done(struct tevent_req *subreq)
{
	NTSTATUS				status;
	struct tevent_req			*req;
	struct roh_open_connection_state	*state;
	unsigned int				version;
	unsigned int				recv;
	unsigned int				timeout;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct roh_open_connection_state);

	status = roh_recv_CONN_C2_recv(subreq, &version, &recv, &timeout);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	state->roh->connection_state = ROH_STATE_OPENED;

	tevent_req_done(req);
}

static ssize_t tstream_roh_pending_bytes(struct tstream_context *stream)
{
	struct tstream_roh_context *ctx = NULL;
	struct tstream_context *tstream = NULL;

	ctx = tstream_context_data(stream, struct tstream_roh_context);
	if (!ctx->roh_conn) {
		errno = ENOTCONN;
		return -1;
	}

	tstream = http_conn_tstream(
		ctx->roh_conn->default_channel_out->http_conn);
	if (tstream == NULL) {
		errno = ENOTCONN;
		return -1;
	}
	return tstream_pending_bytes(tstream);
}

struct tstream_roh_readv_state {
	struct roh_connection *roh_conn;
	int ret;
};

static void tstream_roh_readv_handler(struct tevent_req *subreq);
static struct tevent_req * tstream_roh_readv_send(TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  struct tstream_context *stream,
						  struct iovec *vector,
						  size_t count)
{
	struct tstream_roh_context *ctx = NULL;
	struct tstream_roh_readv_state *state;
	struct tevent_req *req, *subreq;
	struct tstream_context *channel_stream = NULL;

	req = tevent_req_create(mem_ctx, &state, struct tstream_roh_readv_state);
	if (!req) {
		return NULL;
	}

	ctx = tstream_context_data(stream, struct tstream_roh_context);
	if (!ctx->roh_conn) {
		tevent_req_error(req, ENOTCONN);
		goto post;
	}
	if (!ctx->roh_conn->default_channel_out) {
		tevent_req_error(req, ENOTCONN);
		goto post;
	}
	channel_stream = http_conn_tstream(
		ctx->roh_conn->default_channel_out->http_conn);
	if (channel_stream == NULL) {
		tevent_req_error(req, ENOTCONN);
		goto post;
	}

	state->roh_conn = ctx->roh_conn;

	subreq = tstream_readv_send(state, ev,
				    channel_stream,
				    vector, count);
	if (tevent_req_nomem(subreq, req)) {
		goto post;
	}
	tevent_req_set_callback(subreq, tstream_roh_readv_handler, req);

	return req;
post:
	tevent_req_post(req, ev);
	return req;
}

static void tstream_roh_readv_handler(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct tstream_roh_readv_state *state;
	int ret;
	int sys_errno;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct tstream_roh_readv_state);
	ret = tstream_readv_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tevent_req_error(req, sys_errno);
		return;
	}

	state->ret = ret;

	tevent_req_done(req);
}

static int tstream_roh_readv_recv(struct tevent_req *req, int *perrno)
{
	struct tstream_roh_readv_state *state;
	int ret;

	state = tevent_req_data(req, struct tstream_roh_readv_state);
	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		ret = state->ret;
	}

	tevent_req_received(req);
	return ret;
}

struct tstream_roh_writev_state {
	struct roh_connection *roh_conn;
	int nwritten;
};

static void tstream_roh_writev_handler(struct tevent_req *subreq);
static struct tevent_req * tstream_roh_writev_send(TALLOC_CTX *mem_ctx,
						   struct tevent_context *ev,
						   struct tstream_context *stream,
						   const struct iovec *vector,
						   size_t count)
{
	struct tstream_roh_context *ctx = NULL;
	struct tstream_roh_writev_state *state = NULL;
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct tstream_context *channel_stream = NULL;

	req = tevent_req_create(mem_ctx, &state,
			struct tstream_roh_writev_state);
	if (!req) {
		return NULL;
	}

	ctx = tstream_context_data(stream, struct tstream_roh_context);
	if (!ctx->roh_conn) {
		tevent_req_error(req, ENOTCONN);
		goto post;
	}
	if (!ctx->roh_conn->default_channel_in) {
		tevent_req_error(req, ENOTCONN);
		goto post;
	}
	channel_stream = http_conn_tstream(
		ctx->roh_conn->default_channel_in->http_conn);
	if (channel_stream == NULL) {
		tevent_req_error(req, ENOTCONN);
		goto post;
	}

	state->roh_conn = ctx->roh_conn;

	subreq = tstream_writev_send(state, ev,
				     channel_stream,
				     vector, count);
	if (tevent_req_nomem(subreq, req)) {
		goto post;
	}
	tevent_req_set_callback(subreq, tstream_roh_writev_handler, req);

	return req;
post:
	tevent_req_post(req, ev);
	return req;
}

static void tstream_roh_writev_handler(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct tstream_roh_writev_state *state;
	int nwritten;
	int sys_errno;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct tstream_roh_writev_state);
	nwritten = tstream_writev_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);
	if (nwritten == -1) {
		tevent_req_error(req, sys_errno);
		return;
	}
	state->nwritten = nwritten;
	state->roh_conn->default_channel_in->sent_bytes += nwritten;

	tevent_req_done(req);
}

static int tstream_roh_writev_recv(struct tevent_req *req, int *perrno)
{
	struct tstream_roh_writev_state *state;
	int ret;

	state = tevent_req_data(req, struct tstream_roh_writev_state);
	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		ret = state->nwritten;
	}

	return ret;
}

struct tstream_roh_disconnect_state {
	struct tstream_context *stream;
	struct tevent_context *ev;
};

static void tstream_roh_disconnect_channel_in_handler(struct tevent_req *subreq);
static struct tevent_req * tstream_roh_disconnect_send(TALLOC_CTX *mem_ctx,
						       struct tevent_context *ev,
						       struct tstream_context *stream)
{
	struct tstream_roh_context *ctx = NULL;
	struct tevent_req *req, *subreq;
	struct tstream_roh_disconnect_state *state;

	req = tevent_req_create(mem_ctx, &state, struct tstream_roh_disconnect_state);
	if (req == NULL) {
		return NULL;
	}

	state->stream = stream;
	state->ev = ev;

	ctx = tstream_context_data(stream, struct tstream_roh_context);
	if (!ctx->roh_conn) {
		tevent_req_error(req, ENOTCONN);
		goto post;
	}
	if (!ctx->roh_conn->default_channel_in) {
		tevent_req_error(req, ENOTCONN);
		goto post;
	}

	subreq = http_disconnect_send(
			state,
			ev,
			ctx->roh_conn->default_channel_in->http_conn);
	if (tevent_req_nomem(subreq, req)) {
		goto post;
	}
	tevent_req_set_callback(subreq, tstream_roh_disconnect_channel_in_handler, req);

	return req;
post:
	tevent_req_post(req, ev);
	return req;
}

static void tstream_roh_disconnect_channel_out_handler(struct tevent_req *subreq);

static void tstream_roh_disconnect_channel_in_handler(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct tstream_roh_disconnect_state *state;
	struct tstream_context *stream;
	struct tstream_roh_context *roh_stream;
	int ret;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct tstream_roh_disconnect_state);
	stream = state->stream;
	roh_stream = tstream_context_data(stream, struct tstream_roh_context);

	ret = http_disconnect_recv(subreq);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}
	TALLOC_FREE(roh_stream->roh_conn->default_channel_in);

	subreq = http_disconnect_send(
			state,
			state->ev,
			roh_stream->roh_conn->default_channel_out->http_conn);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, tstream_roh_disconnect_channel_out_handler, req);

	return;
}

static void tstream_roh_disconnect_channel_out_handler(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct tstream_roh_disconnect_state *state;
	struct tstream_context *stream;
	struct tstream_roh_context *roh_stream;
	int ret;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct tstream_roh_disconnect_state);
	stream =  state->stream;
	roh_stream = tstream_context_data(stream, struct tstream_roh_context);

	ret = http_disconnect_recv(subreq);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}
	TALLOC_FREE(roh_stream->roh_conn->default_channel_out);

	tevent_req_done(req);
}

static int tstream_roh_disconnect_recv(struct tevent_req *req, int *perrno)
{
	int ret;

	ret = tsocket_simple_int_recv(req, perrno);
	tevent_req_received(req);

	return ret;
}
