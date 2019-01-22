/*
   Unix SMB/CIFS implementation.

   Small async DNS library for Samba with socketwrapper support

   Copyright (C) 2010 Kai Blin  <kai@samba.org>

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

#include "replace.h"
#include "system/network.h"
#include <tevent.h>
#include "lib/tsocket/tsocket.h"
#include "libcli/dns/libdns.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/samba_util.h"
#include "lib/util/debug.h"
#include "libcli/util/error.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_dns.h"

struct dns_udp_request_state {
	struct tevent_context *ev;
	struct tdgram_context *dgram;
	size_t query_len;
	uint8_t *reply;
	size_t reply_len;
};

#define DNS_REQUEST_TIMEOUT 10

/* Declare callback functions used below. */
static void dns_udp_request_get_reply(struct tevent_req *subreq);
static void dns_udp_request_done(struct tevent_req *subreq);

static struct tevent_req *dns_udp_request_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       const char *server_addr_string,
					       const uint8_t *query,
					       size_t query_len)
{
	struct tevent_req *req, *subreq;
	struct dns_udp_request_state *state;
	struct tsocket_address *local_addr, *server_addr;
	struct tdgram_context *dgram;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct dns_udp_request_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;

	/* Use connected UDP sockets */
	ret = tsocket_address_inet_from_strings(state, "ip", NULL, 0,
						&local_addr);
	if (ret != 0) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	ret = tsocket_address_inet_from_strings(state, "ip", server_addr_string,
						DNS_SERVICE_PORT, &server_addr);
	if (ret != 0) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	ret = tdgram_inet_udp_socket(local_addr, server_addr, state, &dgram);
	if (ret != 0) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	state->dgram = dgram;
	state->query_len = query_len;

	dump_data(10, query, query_len);

	subreq = tdgram_sendto_send(state, ev, dgram, query, query_len, NULL);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	if (!tevent_req_set_endtime(req, ev,
				timeval_current_ofs(DNS_REQUEST_TIMEOUT, 0))) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, dns_udp_request_get_reply, req);
	return req;
}

static void dns_udp_request_get_reply(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
						struct tevent_req);
	struct dns_udp_request_state *state = tevent_req_data(req,
						struct dns_udp_request_state);
	ssize_t len;
	int err = 0;

	len = tdgram_sendto_recv(subreq, &err);
	TALLOC_FREE(subreq);

	if (len == -1 && err != 0) {
		tevent_req_error(req, err);
		return;
	}

	if (len != state->query_len) {
		tevent_req_error(req, EIO);
		return;
	}

	subreq = tdgram_recvfrom_send(state, state->ev, state->dgram);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}

	tevent_req_set_callback(subreq, dns_udp_request_done, req);
}

static void dns_udp_request_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
						struct tevent_req);
	struct dns_udp_request_state *state = tevent_req_data(req,
						struct dns_udp_request_state);

	ssize_t len;
	int err = 0;

	len = tdgram_recvfrom_recv(subreq, &err, state, &state->reply, NULL);
	TALLOC_FREE(subreq);

	if (len == -1 && err != 0) {
		tevent_req_error(req, err);
		return;
	}

	state->reply_len = len;
	dump_data(10, state->reply, state->reply_len);
	tevent_req_done(req);
}

static int dns_udp_request_recv(struct tevent_req *req,
				TALLOC_CTX *mem_ctx,
				uint8_t **reply,
				size_t *reply_len)
{
	struct dns_udp_request_state *state = tevent_req_data(req,
			struct dns_udp_request_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		tevent_req_received(req);
		return err;
	}

	*reply = talloc_move(mem_ctx, &state->reply);
	*reply_len = state->reply_len;
	tevent_req_received(req);

	return 0;
}

struct dns_tcp_request_state {
	struct tevent_context *ev;
	struct tstream_context *stream;
	const uint8_t *query;
	size_t query_len;

	uint8_t dns_msglen_hdr[2];
	struct iovec iov[2];

	size_t nread;
	uint8_t *reply;
};

static void dns_tcp_request_connected(struct tevent_req *subreq);
static void dns_tcp_request_sent(struct tevent_req *subreq);
static int dns_tcp_request_next_vector(struct tstream_context *stream,
				       void *private_data,
				       TALLOC_CTX *mem_ctx,
				       struct iovec **_vector,
				       size_t *_count);
static void dns_tcp_request_received(struct tevent_req *subreq);

static struct tevent_req *dns_tcp_request_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       const char *server_addr_string,
					       const uint8_t *query,
					       size_t query_len)
{
	struct tevent_req *req, *subreq;
	struct dns_tcp_request_state *state;
	struct tsocket_address *local, *remote;
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct dns_tcp_request_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->query = query;
	state->query_len = query_len;

	if (query_len > UINT16_MAX) {
		tevent_req_error(req, EMSGSIZE);
		return tevent_req_post(req, ev);
	}

	ret = tsocket_address_inet_from_strings(state, "ip", NULL, 0, &local);
	if (ret != 0) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	ret = tsocket_address_inet_from_strings(
		state, "ip", server_addr_string, DNS_SERVICE_PORT, &remote);
	if (ret != 0) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	subreq = tstream_inet_tcp_connect_send(state, state->ev,
					       local, remote);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, dns_tcp_request_connected, req);

	return req;
}

static void dns_tcp_request_connected(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct dns_tcp_request_state *state = tevent_req_data(
		req, struct dns_tcp_request_state);
	int ret, err;

	ret = tstream_inet_tcp_connect_recv(subreq, &err, state,
					    &state->stream, NULL);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tevent_req_error(req, err);
		return;
	}

	RSSVAL(state->dns_msglen_hdr, 0, state->query_len);
	state->iov[0] = (struct iovec) {
		.iov_base = state->dns_msglen_hdr,
		.iov_len = sizeof(state->dns_msglen_hdr)
	};
	state->iov[1] = (struct iovec) {
		.iov_base = discard_const_p(void, state->query),
		.iov_len = state->query_len
	};

	subreq = tstream_writev_send(state, state->ev, state->stream,
				     state->iov, ARRAY_SIZE(state->iov));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, dns_tcp_request_sent, req);
}

static void dns_tcp_request_sent(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct dns_tcp_request_state *state = tevent_req_data(
		req, struct dns_tcp_request_state);
	int ret, err;

	ret = tstream_writev_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tevent_req_error(req, err);
		return;
	}

	subreq = tstream_readv_pdu_send(state, state->ev, state->stream,
					dns_tcp_request_next_vector, state);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, dns_tcp_request_received, req);
}

static int dns_tcp_request_next_vector(struct tstream_context *stream,
				       void *private_data,
				       TALLOC_CTX *mem_ctx,
				       struct iovec **_vector,
				       size_t *_count)
{
	struct dns_tcp_request_state *state = talloc_get_type_abort(
		private_data, struct dns_tcp_request_state);
	struct iovec *vector;
	uint16_t msglen;

	if (state->nread == 0) {
		vector = talloc_array(mem_ctx, struct iovec, 1);
		if (vector == NULL) {
			return -1;
		}
		vector[0] = (struct iovec) {
			.iov_base = state->dns_msglen_hdr,
			.iov_len = sizeof(state->dns_msglen_hdr)
		};
		state->nread = sizeof(state->dns_msglen_hdr);

		*_vector = vector;
		*_count = 1;
		return 0;
	}

	if (state->nread == sizeof(state->dns_msglen_hdr)) {
		msglen = RSVAL(state->dns_msglen_hdr, 0);

		state->reply = talloc_array(state, uint8_t, msglen);
		if (state->reply == NULL) {
			return -1;
		}

		vector = talloc_array(mem_ctx, struct iovec, 1);
		if (vector == NULL) {
			return -1;
		}
		vector[0] = (struct iovec) {
			.iov_base = state->reply,
			.iov_len = msglen
		};
		state->nread += msglen;

		*_vector = vector;
		*_count = 1;
		return 0;
	}

	*_vector = NULL;
	*_count = 0;
	return 0;
}

static void dns_tcp_request_received(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret, err;

	ret = tstream_readv_pdu_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tevent_req_error(req, err);
		return;
	}

	tevent_req_done(req);
}

static int dns_tcp_request_recv(struct tevent_req *req,
				TALLOC_CTX *mem_ctx,
				uint8_t **reply,
				size_t *reply_len)
{
	struct dns_tcp_request_state *state = tevent_req_data(
		req, struct dns_tcp_request_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		tevent_req_received(req);
		return err;
	}

	*reply_len = talloc_array_length(state->reply);
	*reply = talloc_move(mem_ctx, &state->reply);
	tevent_req_received(req);

	return 0;
}

struct dns_cli_request_state {
	struct tevent_context *ev;
	const char *nameserver;

	uint16_t req_id;

	DATA_BLOB query;

	struct dns_name_packet *reply;
};

static void dns_cli_request_udp_done(struct tevent_req *subreq);
static void dns_cli_request_tcp_done(struct tevent_req *subreq);

struct tevent_req *dns_cli_request_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					const char *nameserver,
					const char *name,
					enum dns_qclass qclass,
					enum dns_qtype qtype)
{
	struct tevent_req *req, *subreq;
	struct dns_cli_request_state *state;
	struct dns_name_question question;
	struct dns_name_packet out_packet;
	enum ndr_err_code ndr_err;

	req = tevent_req_create(mem_ctx, &state,
				struct dns_cli_request_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->nameserver = nameserver;

	DBG_DEBUG("Asking %s for %s/%d/%d via UDP\n", nameserver,
		  name, (int)qclass, (int)qtype);

	generate_random_buffer((uint8_t *)&state->req_id,
			       sizeof(state->req_id));

	question = (struct dns_name_question) {
		.name = discard_const_p(char, name),
		.question_type = qtype, .question_class = qclass
	};

	out_packet = (struct dns_name_packet) {
		.id = state->req_id,
		.operation = DNS_OPCODE_QUERY | DNS_FLAG_RECURSION_DESIRED,
		.qdcount = 1,
		.questions = &question
	};

	ndr_err = ndr_push_struct_blob(
		&state->query, state, &out_packet,
		(ndr_push_flags_fn_t)ndr_push_dns_name_packet);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		tevent_req_error(req, ndr_map_error2errno(ndr_err));
		return tevent_req_post(req, ev);
	}

	subreq = dns_udp_request_send(state, state->ev, state->nameserver,
				      state->query.data, state->query.length);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, dns_cli_request_udp_done, req);
	return req;
}

static void dns_cli_request_udp_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct dns_cli_request_state *state = tevent_req_data(
		req, struct dns_cli_request_state);
	DATA_BLOB reply;
	enum ndr_err_code ndr_err;
	int ret;

	ret = dns_udp_request_recv(subreq, state, &reply.data, &reply.length);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}

	state->reply = talloc(state, struct dns_name_packet);
	if (tevent_req_nomem(state->reply, req)) {
		return;
	}

	ndr_err = ndr_pull_struct_blob(
		&reply, state->reply, state->reply,
		(ndr_pull_flags_fn_t)ndr_pull_dns_name_packet);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		tevent_req_error(req, ndr_map_error2errno(ndr_err));
		return;
	}
	TALLOC_FREE(reply.data);

	if (state->reply->id != state->req_id) {
		DBG_DEBUG("Got id %"PRIu16", expected %"PRIu16"\n",
			  state->reply->id, state->req_id);
		tevent_req_error(req, ENOMSG);
		return;
	}

	if ((state->reply->operation & DNS_FLAG_TRUNCATION) == 0) {
		DBG_DEBUG("Got op=%x %"PRIu16"/%"PRIu16"/%"PRIu16"/%"PRIu16
			  " recs\n", (int)state->reply->operation,
			  state->reply->qdcount, state->reply->ancount,
			  state->reply->nscount, state->reply->nscount);
		tevent_req_done(req);
		return;
	}

	DBG_DEBUG("Reply was truncated, retrying TCP\n");

	TALLOC_FREE(state->reply);

	subreq = dns_tcp_request_send(state, state->ev, state->nameserver,
				      state->query.data, state->query.length);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, dns_cli_request_tcp_done, req);
}

static void dns_cli_request_tcp_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct dns_cli_request_state *state = tevent_req_data(
		req, struct dns_cli_request_state);
	DATA_BLOB reply;
	enum ndr_err_code ndr_err;
	int ret;

	ret = dns_tcp_request_recv(subreq, state, &reply.data, &reply.length);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}

	state->reply = talloc(state, struct dns_name_packet);
	if (tevent_req_nomem(state->reply, req)) {
		return;
	}

	ndr_err = ndr_pull_struct_blob(
		&reply, state->reply, state->reply,
		(ndr_pull_flags_fn_t)ndr_pull_dns_name_packet);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		tevent_req_error(req, ndr_map_error2errno(ndr_err));
		return;
	}
	TALLOC_FREE(reply.data);

	if (state->reply->id != state->req_id) {
		DBG_DEBUG("Got id %"PRIu16", expected %"PRIu16"\n",
			  state->reply->id, state->req_id);
		tevent_req_error(req, ENOMSG);
		return;
	}

	DBG_DEBUG("Got op=%x %"PRIu16"/%"PRIu16"/%"PRIu16"/%"PRIu16
		  " recs\n", (int)state->reply->operation,
		  state->reply->qdcount, state->reply->ancount,
		  state->reply->nscount, state->reply->nscount);

	tevent_req_done(req);
}

int dns_cli_request_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			 struct dns_name_packet **reply)
{
	struct dns_cli_request_state *state = tevent_req_data(
		req, struct dns_cli_request_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}
	*reply = talloc_move(mem_ctx, &state->reply);
	return 0;
}
