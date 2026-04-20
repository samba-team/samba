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
#include "source3/lib/util_tsock.h"
#include "libcli/dns/libdns.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/debug.h"
#include "lib/util/samba_util.h"
#include "libcli/util/error.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_dns.h"

struct dns_udp_request_state {
	struct tevent_context *ev;
	const struct dns_name_packet *q;
	struct tdgram_context *dgram;
	size_t query_len;
	uint8_t *reply;
	size_t reply_len;
};

#define DNS_REQUEST_TIMEOUT 10

/* Declare callback functions used below. */
static void dns_udp_request_sent(struct tevent_req *subreq);
static void dns_udp_request_done(struct tevent_req *subreq);

static struct tevent_req *dns_udp_request_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	const char *server_addr_string,
	const struct dns_name_packet *_q)
{
	struct tevent_req *req, *subreq;
	struct dns_udp_request_state *state;
	struct dns_name_packet *udp_q = NULL;
	DATA_BLOB blob = {};
	enum ndr_err_code ndr_err;
	struct tsocket_address *local_addr, *server_addr;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct dns_udp_request_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->q = _q;

	if (_q->arcount == UINT16_MAX) {
		tevent_req_error(req, EMSGSIZE);
		return tevent_req_post(req, ev);
	}

	/*
	 * Add minimal EDNS0 OPT record to ADDITIONAL section when
	 * sending a DNS request out, indicating we can accept DNS
	 * packets up to 4Kb in size.
	 */
	udp_q = talloc_memdup(state, _q, sizeof(struct dns_name_packet));
	if (tevent_req_nomem(udp_q, req)) {
		return tevent_req_post(req, ev);
	}
	udp_q->additional = talloc_array(udp_q,
					 struct dns_res_rec,
					 _q->arcount + 1);
	if (tevent_req_nomem(udp_q->additional, req)) {
		return tevent_req_post(req, ev);
	}
	memcpy(udp_q->additional,
	       _q->additional,
	       sizeof(struct dns_res_rec) * _q->arcount);

	udp_q->additional[_q->arcount] = (struct dns_res_rec){
		.name = "",
		.rr_type = DNS_QTYPE_OPT,
		.rr_class = 4096 /* 4096 bytes UDP buffer size */
	};
	udp_q->arcount += 1;

	ndr_err = ndr_push_struct_blob(&blob,
				       state,
				       udp_q,
				       (ndr_push_flags_fn_t)
					       ndr_push_dns_name_packet);
	TALLOC_FREE(udp_q);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		tevent_req_error(req, ndr_map_error2errno(ndr_err));
		return tevent_req_post(req, ev);
	}

	/* Use connected UDP sockets */
	ret = tsocket_address_inet_from_strings(state, "ip", NULL, 0,
						&local_addr);
	if (ret != 0) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	ret = tsocket_address_inet_from_hostport_strings(
	    state, "ip", server_addr_string, DNS_SERVICE_PORT, &server_addr);
	if (ret != 0) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	ret = tdgram_inet_udp_socket(local_addr,
				     server_addr,
				     state,
				     &state->dgram);
	if (ret != 0) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	state->query_len = blob.length;

	dump_data(10, blob.data, blob.length);

	subreq = tdgram_sendto_send(
		state, ev, state->dgram, blob.data, blob.length, NULL);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	if (!tevent_req_set_endtime(req, ev,
				timeval_current_ofs(DNS_REQUEST_TIMEOUT, 0))) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, dns_udp_request_sent, req);
	return req;
}

static void dns_udp_request_sent(struct tevent_req *subreq)
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
	struct dns_udp_request_state *state = tevent_req_data(
		req, struct dns_udp_request_state);
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
	const struct dns_name_packet *q;
	struct tstream_context *stream;
	DATA_BLOB query;

	uint8_t dns_msglen_hdr[2];
	struct iovec iov[2];

	size_t nread;
	uint8_t *reply;
};

static void dns_tcp_request_connected(struct tevent_req *subreq);
static void dns_tcp_request_sent(struct tevent_req *subreq);
static ssize_t dns_tcp_request_more(uint8_t *buf,
				    size_t buflen,
				    void *private_data);
static void dns_tcp_request_received(struct tevent_req *subreq);

static struct tevent_req *dns_tcp_request_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       const char *server_addr_string,
					       const struct dns_name_packet *q)
{
	struct tevent_req *req, *subreq;
	struct dns_tcp_request_state *state;
	enum ndr_err_code ndr_err;
	struct tsocket_address *local, *remote;
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct dns_tcp_request_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->q = q;

	ndr_err = ndr_push_struct_blob(&state->query,
				       state,
				       q,
				       (ndr_push_flags_fn_t)
					       ndr_push_dns_name_packet);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		tevent_req_error(req, ndr_map_error2errno(ndr_err));
		return tevent_req_post(req, ev);
	}

	if (state->query.length > UINT16_MAX) {
		tevent_req_error(req, EMSGSIZE);
		return tevent_req_post(req, ev);
	}

	ret = tsocket_address_inet_from_strings(state, "ip", NULL, 0, &local);
	if (ret != 0) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	ret = tsocket_address_inet_from_hostport_strings(
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

	RSSVAL(state->dns_msglen_hdr, 0, state->query.length);
	state->iov[0] = (struct iovec) {
		.iov_base = state->dns_msglen_hdr,
		.iov_len = sizeof(state->dns_msglen_hdr)
	};
	state->iov[1] = (struct iovec){
		.iov_base = discard_const_p(void, state->query.data),
		.iov_len = state->query.length,
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

	subreq = tstream_read_packet_send(state,
					  state->ev,
					  state->stream,
					  2,
					  dns_tcp_request_more,
					  NULL);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, dns_tcp_request_received, req);
}

static ssize_t dns_tcp_request_more(uint8_t *buf,
				    size_t buflen,
				    void *private_data)
{
	if (buflen > 2) {
		return 0; /* We've been here, we're done */
	}
	return PULL_BE_U16(buf, 0);
}

static void dns_tcp_request_received(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct dns_tcp_request_state *state = tevent_req_data(
		req, struct dns_tcp_request_state);
	int ret, err;

	ret = tstream_read_packet_recv(subreq, state, &state->reply, &err);
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

	/*
	 * DNS over TCP prefixes each message with a 2-byte length
	 * header, skip it.
	 */
	*reply_len = talloc_array_length(state->reply) - 2;
	*reply = state->reply + 2;
	talloc_steal(mem_ctx, state->reply);

	tevent_req_received(req);

	return 0;
}

struct dns_cli_request_state {
	struct tevent_context *ev;
	const char *nameserver;

	struct tevent_req *udp_subreq;
	struct tevent_req *tcp_subreq;

	struct dns_name_question question;
	struct dns_name_packet out_packet;

	DATA_BLOB reply;
};

static void dns_cli_request_udp_done(struct tevent_req *subreq);
static void dns_cli_request_trigger_tcp(struct tevent_req *subreq);
static void dns_cli_request_tcp_done(struct tevent_req *subreq);

struct tevent_req *dns_cli_request_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					const char *nameserver,
					const char *name,
					enum dns_qclass qclass,
					enum dns_qtype qtype)
{
	struct tevent_req *req = NULL, *wakeup_subreq = NULL;
	struct dns_cli_request_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct dns_cli_request_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->nameserver = nameserver;

	DBG_DEBUG("Asking %s for %s/%d/%d via UDP\n", nameserver,
		  name, (int)qclass, (int)qtype);

	state->question = (struct dns_name_question){
		.name = discard_const_p(char, name),
		.question_type = qtype,
		.question_class = qclass,
	};

	state->out_packet = (struct dns_name_packet){
		.operation = DNS_OPCODE_QUERY | DNS_FLAG_RECURSION_DESIRED,
		.qdcount = 1,
		.questions = &state->question,
	};

	generate_random_buffer((uint8_t *)&state->out_packet.id,
			       sizeof(state->out_packet.id));

	state->udp_subreq = dns_udp_request_send(state,
						 state->ev,
						 state->nameserver,
						 &state->out_packet);
	if (tevent_req_nomem(state->udp_subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(state->udp_subreq,
				dns_cli_request_udp_done,
				req);

	wakeup_subreq = tevent_wakeup_send(state,
					   state->ev,
					   tevent_timeval_current_ofs(1, 0));
	if (tevent_req_nomem(wakeup_subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(wakeup_subreq,
				dns_cli_request_trigger_tcp,
				req);

	return req;
}

static void dns_cli_request_udp_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct dns_cli_request_state *state = tevent_req_data(
		req, struct dns_cli_request_state);
	uint16_t reply_id, operation;
	int ret;

	SMB_ASSERT(subreq == state->udp_subreq);

	ret = dns_udp_request_recv(subreq,
				   state,
				   &state->reply.data,
				   &state->reply.length);
	TALLOC_FREE(subreq);
	state->udp_subreq = NULL;

	if (ret != 0) {
		DBG_DEBUG("dns_udp_request_recv() returned %d (%s)\n",
			  ret,
			  strerror(ret));
		goto tcp_fallback;
	}

	if (state->reply.length < 4) {
		DBG_DEBUG("Short DNS packet: length=%zu\n",
			  state->reply.length);
		goto tcp_fallback;
	}

	reply_id = PULL_BE_U16(state->reply.data, 0);
	if (reply_id != state->out_packet.id) {
		DBG_DEBUG("Got id %" PRIu16 ", expected %" PRIu16 "\n",
			  reply_id,
			  state->out_packet.id);
		goto tcp_fallback;
	}

	operation = PULL_BE_U16(state->reply.data, 2);
	if ((operation & DNS_FLAG_TRUNCATION) != 0) {
		DBG_DEBUG("Id %" PRIu16 ", truncated\n", state->out_packet.id);
		goto tcp_fallback;
	}

	tevent_req_done(req);
	return;

tcp_fallback:
	if (state->tcp_subreq != NULL) {
		return;
	}

	state->tcp_subreq = dns_tcp_request_send(state,
						 state->ev,
						 state->nameserver,
						 &state->out_packet);
	if (tevent_req_nomem(state->tcp_subreq, req)) {
		return;
	}
	tevent_req_set_callback(state->tcp_subreq,
				dns_cli_request_tcp_done,
				req);
}

static void dns_cli_request_trigger_tcp(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct dns_cli_request_state *state = tevent_req_data(
		req, struct dns_cli_request_state);
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_oom(subreq);
		return;
	}

	if (state->tcp_subreq != NULL) {
		return;
	}

	state->tcp_subreq = dns_tcp_request_send(state,
						 state->ev,
						 state->nameserver,
						 &state->out_packet);
	if (tevent_req_nomem(state->tcp_subreq, req)) {
		return;
	}
	tevent_req_set_callback(state->tcp_subreq,
				dns_cli_request_tcp_done,
				req);
}

static void dns_cli_request_tcp_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct dns_cli_request_state *state = tevent_req_data(
		req, struct dns_cli_request_state);
	int ret;

	SMB_ASSERT(subreq == state->tcp_subreq);

	ret = dns_tcp_request_recv(subreq,
				   state,
				   &state->reply.data,
				   &state->reply.length);
	TALLOC_FREE(subreq);
	state->tcp_subreq = NULL;

	if ((ret != 0) && (state->udp_subreq != NULL)) {
		DBG_DEBUG("dns_tcp_request_recv() failed: (%s), "
			  "waiting for UDP\n",
			  strerror(ret));
		return;
	}

	if (tevent_req_error(req, ret)) {
		return;
	}
	tevent_req_done(req);
}

int dns_cli_request_recv(struct tevent_req *req,
			 TALLOC_CTX *mem_ctx,
			 struct dns_name_packet **_reply)
{
	struct dns_cli_request_state *state = tevent_req_data(
		req, struct dns_cli_request_state);
	struct dns_name_packet *reply = NULL;
	enum ndr_err_code ndr_err;
	int ret, err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}

	reply = talloc(mem_ctx, struct dns_name_packet);
	if (reply == NULL) {
		ret = ENOMEM;
		goto done;
	}

	ndr_err = ndr_pull_struct_blob(&state->reply,
				       reply,
				       reply,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_dns_name_packet);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(reply);
		ret = ndr_map_error2errno(ndr_err);
		goto done;
	}

	if (reply->id != state->out_packet.id) {
		DBG_DEBUG("Got id %" PRIu16 ", expected %" PRIu16 "\n",
			  reply->id,
			  state->out_packet.id);
		ret = ENOMSG;
		goto done;
	}

	*_reply = reply;
	ret = 0;
done:
	if (ret != 0) {
		TALLOC_FREE(reply);
	}
	tevent_req_received(req);
	return ret;
}
