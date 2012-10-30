/*
   Unix SMB/CIFS implementation.
   Test new ctdb API
   Copyright (C) Volker Lendecke 2012

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
#include "torture/proto.h"

#ifdef CLUSTER_SUPPORT

#include "ctdb_conn.h"
#include "lib/util/tevent_unix.h"
#include "tdb.h"

#ifdef HAVE_CTDB_PROTOCOL_H
#include "ctdb_protocol.h"
#else
#include "ctdb_private.h"
#endif

#include "messages.h"

struct ctdb_conn_test_state {
	struct tevent_context *ev;
	struct ctdb_conn *conn;
	struct ctdb_msg_channel *channel;
	int msgno;
};

static void ctdb_conn_test_got_conn(struct tevent_req *subreq);
static void ctdb_conn_test_got_pnn(struct tevent_req *subreq);
static void ctdb_conn_test_got_channel(struct tevent_req *subreq);
static void ctdb_conn_test_got_msg(struct tevent_req *subreq);
static void ctdb_conn_test_msg_sent(struct tevent_req *subreq);

static struct tevent_req *ctdb_conn_test_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev)
{
	struct tevent_req *req, *subreq;
	struct ctdb_conn_test_state *state;

	req = tevent_req_create(mem_ctx, &state, struct ctdb_conn_test_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;

	subreq = ctdb_conn_init_send(mem_ctx, ev, lp_ctdbd_socket());
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_conn_test_got_conn, req);
	return req;
}

static void ctdb_conn_test_got_conn(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_conn_test_state *state = tevent_req_data(
		req, struct ctdb_conn_test_state);
	uint64_t ret;

	ret = ctdb_conn_init_recv(subreq, state, &state->conn);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}
	subreq = ctdb_conn_control_send(state, state->ev, state->conn,
					CTDB_CURRENT_NODE,
					CTDB_CONTROL_GET_PNN, 0, 0, NULL, 0);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ctdb_conn_test_got_pnn, req);
}

static void ctdb_conn_test_got_pnn(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_conn_test_state *state = tevent_req_data(
		req, struct ctdb_conn_test_state);
	int ret;
	struct ctdb_reply_control *reply;

	ret = ctdb_conn_control_recv(subreq, talloc_tos(), &reply);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}
	printf("vnn=%d\n", (int)reply->status);

	subreq = ctdb_msg_channel_init_send(
		state, state->ev, lp_ctdbd_socket(), 999999);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ctdb_conn_test_got_channel, req);
}

static void ctdb_conn_test_got_channel(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_conn_test_state *state = tevent_req_data(
		req, struct ctdb_conn_test_state);
	int ret;

	ret = ctdb_msg_channel_init_recv(subreq, state, &state->channel);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}

	subreq = ctdb_msg_read_send(state, state->ev, state->channel);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ctdb_conn_test_got_msg, req);

	state->msgno += 1;

	subreq = ctdb_conn_msg_write_send(
		state, state->ev, state->conn, CTDB_CURRENT_NODE, 999999,
		(uint8_t *)&state->msgno, sizeof(state->msgno));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ctdb_conn_test_msg_sent, req);
}

static void ctdb_conn_test_got_msg(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_conn_test_state *state = tevent_req_data(
		req, struct ctdb_conn_test_state);
	uint8_t *buf;
	size_t buf_len;
	int ret;

	ret = ctdb_msg_read_recv(subreq, talloc_tos(), &buf, &buf_len);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}
	if (buf_len != sizeof(int)) {
		printf("got invalid msg\n");
		tevent_req_error(req, EINVAL);
		return;
	}
	memcpy(&ret, buf, buf_len);
	printf("got msg %d\n", ret);
	if (ret == 5) {
		tevent_req_done(req);
		return;
	}

	subreq = ctdb_msg_read_send(state, state->ev, state->channel);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ctdb_conn_test_got_msg, req);
}

static void ctdb_conn_test_msg_sent(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_conn_test_state *state = tevent_req_data(
		req, struct ctdb_conn_test_state);
	int ret;

	ret = ctdb_conn_msg_write_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}
	state->msgno += 1;

	if (state->msgno >= 10) {
		return;
	}

	subreq = ctdb_conn_msg_write_send(
		state, state->ev, state->conn, CTDB_CURRENT_NODE, 999999,
		(uint8_t *)&state->msgno, sizeof(state->msgno));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ctdb_conn_test_msg_sent, req);
}

static int ctdb_conn_test_recv(struct tevent_req *req)
{
	int err;
	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}
	return 0;
}

bool run_ctdb_conn(int dummy)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	int ret;

	ev = tevent_context_init(talloc_tos());
	if (ev == NULL) {
		fprintf(stderr, "tevent_context_init failed\n");
		return false;
	}
	req = ctdb_conn_test_send(ev, ev);
	if (req == NULL) {
		fprintf(stderr, "ctdb_conn_test_send failed\n");
		return false;
	}
	if (!tevent_req_poll(req, ev)) {
		fprintf(stderr, "tevent_req_poll failed\n");
		return false;
	}
	ret = ctdb_conn_test_recv(req);
	TALLOC_FREE(req);
	printf("ctdb_conn_test returned %s\n",
	       ret ? strerror(ret) : "success");
	TALLOC_FREE(ev);
	return (ret == 0);
}

#else /* CLUSTER_SUPPORT */

bool run_ctdb_conn(int dummy)
{
	return true;
}

#endif
