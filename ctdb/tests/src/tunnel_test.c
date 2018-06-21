/*
   CTDB tunnel test

   Copyright (C) Amitay Isaacs  2017

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/network.h"

#include "lib/util/debug.h"
#include "lib/util/tevent_unix.h"

#include "protocol/protocol_private.h"
#include "client/client.h"
#include "tests/src/test_options.h"
#include "tests/src/cluster_wait.h"

struct test_data {
	uint32_t pnn;
	uint32_t count;
};

static size_t test_data_len(struct test_data *in)
{
	return ctdb_uint32_len(&in->pnn) + ctdb_uint32_len(&in->count);
}

static void test_data_push(struct test_data *in, uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;

	ctdb_uint32_push(&in->pnn, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&in->count, buf+offset, &np);
	offset += np;

	*npush = offset;
}

static int test_data_pull(uint8_t *buf, size_t buflen, struct test_data *out,
			  size_t *npull)
{
	size_t offset = 0, np;
	int ret;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->pnn, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &out->count, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	*npull = offset;
	return 0;
}

/*
 * Set up 2 tunnels from each node - one to the next node and one to the
 * previous node.  The tunnel to the next node is used for sending data and
 * tunnel to the previous node is used for receiving data.
 */

struct tunnel_test_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	int num_nodes;
	int timelimit;

	uint32_t pnn;
	uint32_t next_node;
	uint32_t prev_node;
	bool done;
	struct ctdb_tunnel_context *send_tunnel;
	struct ctdb_tunnel_context *recv_tunnel;
	uint32_t count;
	uint8_t *buf;
};

static void tunnel_test_send_tunnel_done(struct tevent_req *subreq);
static void tunnel_test_recv_tunnel_done(struct tevent_req *subreq);
static void tunnel_test_start(struct tevent_req *subreq);
static void tunnel_test_msg_send(struct tevent_req *req,
				 struct test_data *tdata);
static void tunnel_test_msg_send_done(struct tevent_req *subreq);
static void tunnel_test_handler(struct ctdb_tunnel_context *tctx,
				uint32_t srcnode, uint32_t reqid,
				uint8_t *buf, size_t buflen,
				void *private_data);
static void tunnel_test_done(struct tevent_req *subreq);
static void tunnel_test_finish(struct tevent_req *subreq);
static void tunnel_test_send_tunnel_closed(struct tevent_req *subreq);
static void tunnel_test_recv_tunnel_closed(struct tevent_req *subreq);

static struct tevent_req *tunnel_test_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct ctdb_client_context *client,
					   int num_nodes, int timelimit)
{
	struct tevent_req *req, *subreq;
	struct tunnel_test_state *state;

	req = tevent_req_create(mem_ctx, &state, struct tunnel_test_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->client = client;
	state->num_nodes = num_nodes;
	state->timelimit = timelimit;
	state->pnn = ctdb_client_pnn(client);
	state->prev_node = (state->pnn + num_nodes - 1) % num_nodes;
	state->next_node = (state->pnn + 1) % num_nodes;
	state->done = false;

	subreq = ctdb_tunnel_setup_send(state, state->ev, state->client,
					CTDB_TUNNEL_TEST | state->pnn,
					tunnel_test_handler, req);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, tunnel_test_send_tunnel_done, req);

	return req;
}

static void tunnel_test_send_tunnel_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct tunnel_test_state *state = tevent_req_data(
		req, struct tunnel_test_state);
	int ret;
	bool status;

	status = ctdb_tunnel_setup_recv(subreq, &ret, &state->send_tunnel);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	subreq = ctdb_tunnel_setup_send(state, state->ev, state->client,
					CTDB_TUNNEL_TEST | state->prev_node,
					tunnel_test_handler, req);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, tunnel_test_recv_tunnel_done, req);
}

static void tunnel_test_recv_tunnel_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct tunnel_test_state *state = tevent_req_data(
		req, struct tunnel_test_state);
	int ret;
	bool status;

	status = ctdb_tunnel_setup_recv(subreq, &ret, &state->recv_tunnel);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	subreq = cluster_wait_send(state, state->ev, state->client,
				   state->num_nodes);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, tunnel_test_start, req);
}

static void tunnel_test_start(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct tunnel_test_state *state = tevent_req_data(
		req, struct tunnel_test_state);
	struct test_data tdata;
	int ret;
	bool status;

	status = cluster_wait_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	subreq = tevent_wakeup_send(state, state->ev,
			tevent_timeval_current_ofs(state->timelimit, 0));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, tunnel_test_done, req);

	tdata.pnn = state->pnn;
	tdata.count = state->count;
	tunnel_test_msg_send(req, &tdata);
}

static void tunnel_test_msg_send(struct tevent_req *req,
				 struct test_data *tdata)
{
	struct tunnel_test_state *state = tevent_req_data(
		req, struct tunnel_test_state);
	struct tevent_req *subreq;
	size_t buflen, np;

	buflen = test_data_len(tdata);
	state->buf = talloc_size(state, buflen);
	if (tevent_req_nomem(state->buf, req)) {
		return;
	}
	test_data_push(tdata, state->buf, &np);

	subreq = ctdb_tunnel_request_send(state, state->ev,
					  state->send_tunnel,
					  state->next_node,
					  tevent_timeval_zero(),
					  state->buf, buflen, false);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, tunnel_test_msg_send_done, req);
}

static void tunnel_test_msg_send_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct tunnel_test_state *state = tevent_req_data(
		req, struct tunnel_test_state);
	int ret;
	bool status;

	status = ctdb_tunnel_request_recv(subreq, &ret, NULL, NULL, NULL);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	TALLOC_FREE(state->buf);
}

static void tunnel_test_handler(struct ctdb_tunnel_context *tctx,
				uint32_t srcnode, uint32_t reqid,
				uint8_t *buf, size_t buflen,
				void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct tunnel_test_state *state = tevent_req_data(
		req, struct tunnel_test_state);
	struct test_data tdata;
	size_t np;
	int ret;

	if (state->done) {
		return;
	}

	if (tctx == state->send_tunnel) {
		fprintf(stderr, "pnn:%u Received data on send tunnel\n",
			state->pnn);
		tevent_req_error(req, EPROTO);
		return;
	}

	ret = test_data_pull(buf, buflen, &tdata, &np);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	if (tdata.pnn == state->pnn) {
		if (tdata.count != state->count) {
			tevent_req_error(req, EPROTO);
			return;
		}

		state->count = tdata.count + 1;
		tdata.count = state->count;
	}

	tunnel_test_msg_send(req, &tdata);
}

static void tunnel_test_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct tunnel_test_state *state = tevent_req_data(
		req, struct tunnel_test_state);
	bool status;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, EIO);
		return;
	}

	printf("pnn[%u] %.1lf msgs/sec\n",
	       state->pnn, (double)state->count / state->timelimit);

	state->done = true;

	/* wait few more seconds */
	subreq = tevent_wakeup_send(state, state->ev,
				    tevent_timeval_current_ofs(3, 0));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, tunnel_test_finish, req);
}

static void tunnel_test_finish(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct tunnel_test_state *state = tevent_req_data(
		req, struct tunnel_test_state);
	bool status;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, EIO);
		return;
	}

	subreq = ctdb_tunnel_destroy_send(state, state->ev,
					  state->send_tunnel);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, tunnel_test_send_tunnel_closed, req);
}

static void tunnel_test_send_tunnel_closed(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct tunnel_test_state *state = tevent_req_data(
		req, struct tunnel_test_state);
	int ret;
	bool status;

	status = ctdb_tunnel_destroy_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}
	state->send_tunnel = NULL;

	subreq = ctdb_tunnel_destroy_send(state, state->ev,
					  state->recv_tunnel);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, tunnel_test_recv_tunnel_closed, req);
}

static void tunnel_test_recv_tunnel_closed(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct tunnel_test_state *state = tevent_req_data(
		req, struct tunnel_test_state);
	int ret;
	bool status;

	status = ctdb_tunnel_destroy_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}
	state->recv_tunnel = NULL;

	tevent_req_done(req);
}

static bool tunnel_test_recv(struct tevent_req *req, int *perr)
{
	int ret;

	if (tevent_req_is_unix_error(req, &ret)) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	return true;
}

int main(int argc, const char *argv[])
{
	const struct test_options *opts;
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct tevent_req *req;
	int ret;
	bool status;

	setup_logging("tunnel_test", DEBUG_STDERR);

	status = process_options_basic(argc, argv, &opts);
	if (! status) {
		exit(1);
	}

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		exit(1);
	}

	ev = tevent_context_init(mem_ctx);
	if (ev == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		exit(1);
	}

	ret = ctdb_client_init(mem_ctx, ev, opts->socket, &client);
	if (ret != 0) {
		fprintf(stderr, "Failed to initialize client, ret=%d\n", ret);
		exit(1);
	}

	if (! ctdb_recovery_wait(ev, client)) {
		fprintf(stderr, "Memory allocation error\n");
		exit(1);
	}

	req = tunnel_test_send(mem_ctx, ev, client, opts->num_nodes,
			       opts->timelimit);
	if (req == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		exit(1);
	}

	tevent_req_poll(req, ev);

	status = tunnel_test_recv(req, &ret);
	if (! status) {
		fprintf(stderr, "tunnel test failed, ret=%d\n", ret);
		exit(1);
	}

	talloc_free(mem_ctx);
	return 0;
}
