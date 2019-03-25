/*
   Unix SMB/CIFS implementation.

   HTTP library

   Copyright (C) 2019 Ralph Boehme <slow@samba.org>

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
#include "lib/util/tevent_ntstatus.h"
#include "libcli/dns/dns_lookup.h"
#include "lib/tsocket/tsocket.h"
#include "lib/util/util_net.h"
#include "lib/tls/tls.h"
#include "lib/util/tevent_unix.h"
#include "http.h"
#include "http_internal.h"

struct http_connect_state {
	struct tevent_context *ev;
	const char *http_server;
	const char *http_server_ip;
	uint16_t http_port;
	struct tsocket_address *local_address;
	struct tsocket_address *remote_address;
	struct cli_credentials *credentials;
	struct tstream_tls_params *tls_params;

	struct http_conn *http_conn;
};

static void http_connect_dns_done(struct tevent_req *subreq);
static void http_connect_tcp_connect(struct tevent_req *req);
static void http_connect_tcp_done(struct tevent_req *subreq);
static void http_connect_tls_done(struct tevent_req *subreq);

struct tevent_req *http_connect_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     const char *http_server,
				     uint16_t http_port,
				     struct cli_credentials *credentials,
				     struct tstream_tls_params *tls_params)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct http_connect_state *state = NULL;
	int ret;

	DBG_DEBUG("Connecting to [%s] over HTTP%s\n",
		  http_server, tls_params != NULL ? "S" : "");

	req = tevent_req_create(mem_ctx, &state, struct http_connect_state);
	if (req == NULL) {
		return NULL;
	}

	*state = (struct http_connect_state) {
		.ev = ev,
		.http_port = http_port,
		.credentials = credentials,
		.tls_params = tls_params,
	};

	state->http_server = talloc_strdup(state, http_server);
	if (tevent_req_nomem(state->http_server, req)) {
		return tevent_req_post(req, ev);
	}

	state->http_conn = talloc_zero(state, struct http_conn);
	if (tevent_req_nomem(state->http_conn, req)) {
		return tevent_req_post(req, ev);
	}

	state->http_conn->send_queue = tevent_queue_create(state->http_conn,
							   "HTTP send queue");
	if (tevent_req_nomem(state->http_conn->send_queue, req)) {
		return tevent_req_post(req, ev);
	}

	ret = tsocket_address_inet_from_strings(state,
						"ip",
						NULL,
						0,
						&state->local_address);
	if (ret != 0) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	if (!is_ipaddress(http_server)) {
		subreq = dns_lookup_send(state,
					 ev,
					 NULL,
					 http_server,
					 DNS_QCLASS_IN,
					 DNS_QTYPE_A);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, http_connect_dns_done, req);
		return req;
	}
	state->http_server_ip = state->http_server;

	http_connect_tcp_connect(req);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void http_connect_dns_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct http_connect_state *state = tevent_req_data(
		req, struct http_connect_state);
	struct dns_name_packet *dns_reply = NULL;
	struct dns_res_rec *an = NULL;
	uint16_t i;
	int ret;

	ret = dns_lookup_recv(subreq, state, &dns_reply);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	for (i = 0; i < dns_reply->ancount; i++) {
		an = &dns_reply->answers[i];
		if (an->rr_type == DNS_QTYPE_A) {
			break;
		}
	}
	if (i >= dns_reply->ancount) {
		tevent_req_error(req, ENOENT);
		return;
	}

	state->http_server_ip = talloc_strdup(state, an->rdata.ipv4_record);
	if (tevent_req_nomem(state->http_server_ip, req)) {
		return;
	}

	return http_connect_tcp_connect(req);
}

static void http_connect_tcp_connect(struct tevent_req *req)
{
	struct http_connect_state *state = tevent_req_data(
		req, struct http_connect_state);
	struct tevent_req *subreq = NULL;
	int ret;

	ret = tsocket_address_inet_from_strings(state,
						"ip",
						state->http_server_ip,
						state->http_port,
						&state->remote_address);
	if (ret != 0) {
		int saved_errno = errno;

		DBG_ERR("Cannot create remote socket address, error: %s (%d)\n",
			strerror(errno), errno);
		tevent_req_error(req, saved_errno);
		return;
	}

	subreq = tstream_inet_tcp_connect_send(state,
					       state->ev,
					       state->local_address,
					       state->remote_address);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, http_connect_tcp_done, req);
}

static void http_connect_tcp_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct http_connect_state *state = tevent_req_data(
		req, struct http_connect_state);
	int error;
	int ret;

	ret = tstream_inet_tcp_connect_recv(subreq,
					    &error,
					    state->http_conn,
					    &state->http_conn->tstreams.raw,
					    NULL);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		tevent_req_error(req, error);
		return;
	}

	state->http_conn->tstreams.active = state->http_conn->tstreams.raw;
	DBG_DEBUG("Socket connected\n");

	if (state->tls_params == NULL) {
		tevent_req_done(req);
		return;
	}

	DBG_DEBUG("Starting TLS\n");

	subreq = tstream_tls_connect_send(state,
					  state->ev,
					  state->http_conn->tstreams.active,
					  state->tls_params);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, http_connect_tls_done, req);
}

static void http_connect_tls_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct http_connect_state *state = tevent_req_data(
		req, struct http_connect_state);
	int error;
	int ret;

	ret = tstream_tls_connect_recv(subreq,
				       &error,
				       state->http_conn,
				       &state->http_conn->tstreams.tls);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		tevent_req_error(req, error);
		return;
	}

	state->http_conn->tstreams.active = state->http_conn->tstreams.tls;

	DBG_DEBUG("TLS handshake completed\n");
	tevent_req_done(req);
}

int http_connect_recv(struct tevent_req *req,
		      TALLOC_CTX *mem_ctx,
		      struct http_conn **http_conn)
{
	struct http_connect_state *state = tevent_req_data(
		req, struct http_connect_state);
	int error;

	if (tevent_req_is_unix_error(req, &error)) {
		tevent_req_received(req);
		return error;
	}

	*http_conn = talloc_move(mem_ctx, &state->http_conn);
	tevent_req_received(req);

	return 0;
}

struct tevent_queue *http_conn_send_queue(struct http_conn *http_conn)
{
	return http_conn->send_queue;
}

struct tstream_context *http_conn_tstream(struct http_conn *http_conn)
{
	return http_conn->tstreams.active;
}

struct http_conn_disconnect_state {
	struct tevent_context *ev;
	struct http_conn *http_conn;
};

static void http_conn_disconnect_done(struct tevent_req *subreq);

struct tevent_req *http_disconnect_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct http_conn *http_conn)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct http_conn_disconnect_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct http_conn_disconnect_state);
	if (req == NULL) {
		return NULL;
	}

	*state = (struct http_conn_disconnect_state) {
		.ev = ev,
		.http_conn = http_conn,
	};

	if (http_conn->tstreams.active == NULL) {
		tevent_req_error(req, ENOTCONN);
		return tevent_req_post(req, ev);
	}

	subreq = tstream_disconnect_send(state, ev, http_conn->tstreams.active);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, http_conn_disconnect_done, req);

	return req;
}

static void http_conn_disconnect_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret;
	int error;

	ret = tstream_disconnect_recv(subreq, &error);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tevent_req_error(req, error);
		return;
	}

	tevent_req_done(req);
}

int http_disconnect_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_unix(req);
}
