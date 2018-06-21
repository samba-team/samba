/*
   simple ctdb benchmark - send messages in a ring around cluster

   Copyright (C) Amitay Isaacs  2015

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
#include "lib/util/time.h"
#include "lib/util/tevent_unix.h"

#include "client/client.h"
#include "tests/src/test_options.h"
#include "tests/src/cluster_wait.h"

#define MSG_ID_BENCH	0

struct message_ring_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	int num_nodes;
	int timelimit;
	int interactive;
	int msg_count;
	int msg_plus, msg_minus;
	struct timeval start_time;
};

static void message_ring_wait(struct tevent_req *subreq);
static void message_ring_start(struct tevent_req *subreq);
static void message_ring_each_second(struct tevent_req *subreq);
static void message_ring_msg_sent(struct tevent_req *subreq);
static void message_ring_msg_handler(uint64_t srvid, TDB_DATA data,
				   void *private_data);
static void message_ring_finish(struct tevent_req *subreq);

static struct tevent_req *message_ring_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct ctdb_client_context *client,
					    int num_nodes, int timelimit,
					    int interactive)
{
	struct tevent_req *req, *subreq;
	struct message_ring_state *state;

	req = tevent_req_create(mem_ctx, &state, struct message_ring_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->client = client;
	state->num_nodes = num_nodes;
	state->timelimit = timelimit;
	state->interactive = interactive;

	subreq = ctdb_client_set_message_handler_send(
					state, state->ev, state->client,
					MSG_ID_BENCH,
					message_ring_msg_handler, req);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, message_ring_wait, req);

	return req;
}

static void message_ring_wait(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct message_ring_state *state = tevent_req_data(
		req, struct message_ring_state);
	bool status;
	int ret;

	status = ctdb_client_set_message_handler_recv(subreq, &ret);
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
	tevent_req_set_callback(subreq, message_ring_start, req);
}

static void message_ring_start(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct message_ring_state *state = tevent_req_data(
		req, struct message_ring_state);
	bool status;
	int ret;

	status = cluster_wait_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	state->start_time = tevent_timeval_current();

	if (ctdb_client_pnn(state->client) == 0) {
		subreq = tevent_wakeup_send(state, state->ev,
					    tevent_timeval_current_ofs(1, 0));
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, message_ring_each_second, req);
	}

	subreq = tevent_wakeup_send(state, state->ev,
				    tevent_timeval_current_ofs(
					    state->timelimit, 0));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, message_ring_finish, req);
}

static uint32_t next_node(struct ctdb_client_context *client,
			  int num_nodes, int incr)
{
	return (ctdb_client_pnn(client) + num_nodes + incr) % num_nodes;
}

static void message_ring_each_second(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct message_ring_state *state = tevent_req_data(
		req, struct message_ring_state);
	struct ctdb_req_message msg;
	uint32_t pnn;
	int incr;
	bool status;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, EIO);
		return;
	}

	pnn = ctdb_client_pnn(state->client);
	if (pnn == 0 && state->interactive == 1) {
		double t;

		t = timeval_elapsed(&state->start_time);
		printf("Ring[%u]: %.2f msgs/sec (+ve=%d -ve=%d)\n",
		       pnn, state->msg_count / t,
		       state->msg_plus, state->msg_minus);
		fflush(stdout);
	}

	if (state->msg_plus == 0) {
		incr = 1;

		msg.srvid = 0;
		msg.data.data.dptr = (uint8_t *)&incr;
		msg.data.data.dsize = sizeof(incr);

		pnn = next_node(state->client, state->num_nodes, incr);

		subreq = ctdb_client_message_send(state, state->ev,
						  state->client, pnn, &msg);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, message_ring_msg_sent, req);
	}

	if (state->msg_minus == 0) {
		incr = -1;

		msg.srvid = 0;
		msg.data.data.dptr = (uint8_t *)&incr;
		msg.data.data.dsize = sizeof(incr);

		pnn = next_node(state->client, state->num_nodes, incr);

		subreq = ctdb_client_message_send(state, state->ev,
						  state->client, pnn, &msg);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, message_ring_msg_sent, req);
	}

	subreq = tevent_wakeup_send(state, state->ev,
				    tevent_timeval_current_ofs(1, 0));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, message_ring_each_second, req);
}

static void message_ring_msg_sent(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	bool status;
	int ret;

	status = ctdb_client_message_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
	}
}

static void message_ring_msg_handler(uint64_t srvid, TDB_DATA data,
				   void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct message_ring_state *state = tevent_req_data(
		req, struct message_ring_state);
	struct ctdb_req_message msg;
	struct tevent_req *subreq;
	int incr;
	uint32_t pnn;

	if (srvid != MSG_ID_BENCH) {
		return;
	}

	if (data.dsize != sizeof(int)) {
		return;
	}
	incr = *(int *)data.dptr;

	state->msg_count += 1;
	if (incr == 1) {
		state->msg_plus += 1;
	} else {
		state->msg_minus += 1;
	}

	pnn = next_node(state->client, state->num_nodes, incr);

	msg.srvid = srvid;
	msg.data.data = data;

	subreq = ctdb_client_message_send(state, state->ev, state->client,
					  pnn, &msg);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, message_ring_msg_sent, req);
}

static void message_ring_finish(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct message_ring_state *state = tevent_req_data(
		req, struct message_ring_state);
	bool status;
	double t;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, EIO);
		return;
	}

	t = timeval_elapsed(&state->start_time);

	printf("Ring[%u]: %.2f msgs/sec (+ve=%d -ve=%d)\n",
	       ctdb_client_pnn(state->client), state->msg_count / t,
	       state->msg_plus, state->msg_minus);

	tevent_req_done(req);
}

static bool message_ring_recv(struct tevent_req *req)
{
	int ret;

	if (tevent_req_is_unix_error(req, &ret)) {
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

	setup_logging("message_ring", DEBUG_STDERR);

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
		fprintf(stderr, "Failed to wait for recovery\n");
		exit(1);
	}

	req = message_ring_send(mem_ctx, ev, client,
				opts->num_nodes, opts->timelimit,
				opts->interactive);
	if (req == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		exit(1);
	}

	tevent_req_poll(req, ev);

	status = message_ring_recv(req);
	if (! status) {
		fprintf(stderr, "message ring test failed\n");
		exit(1);
	}

	talloc_free(mem_ctx);
	return 0;
}
