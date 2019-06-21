/*
   Cluster wide synchronization

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

#include "lib/util/tevent_unix.h"

#include "client/client.h"

#include "tests/src/cluster_wait.h"

#define MSG_ID_JOIN	(CTDB_SRVID_TEST_RANGE | 0x1)
#define MSG_ID_SYNC	(CTDB_SRVID_TEST_RANGE | 0x2)

/* Wait for all the clients to initialize */

struct cluster_wait_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	uint32_t num_nodes;
	bool *ready;
	bool join_done;
};

static void cluster_wait_join_registered(struct tevent_req *subreq);
static void cluster_wait_sync_registered(struct tevent_req *subreq);
static void cluster_wait_join(struct tevent_req *subreq);
static void cluster_wait_join_sent(struct tevent_req *subreq);
static void cluster_wait_join_handler(uint64_t srvid, TDB_DATA data,
				      void *private_data);
static void cluster_wait_join_unregistered(struct tevent_req *subreq);
static void cluster_wait_sync_sent(struct tevent_req *subreq);
static void cluster_wait_sync_handler(uint64_t srvid, TDB_DATA data,
				      void *private_data);
static void cluster_wait_sync_unregistered(struct tevent_req *subreq);

struct tevent_req *cluster_wait_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct ctdb_client_context *client,
				     uint32_t num_nodes)
{
	struct tevent_req *req, *subreq;
	struct cluster_wait_state *state;
	bool ok;

	req = tevent_req_create(mem_ctx, &state, struct cluster_wait_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->client = client;
	state->num_nodes = num_nodes;

	state->join_done = false;

	if (ctdb_client_pnn(client) == 0) {
		state->ready = talloc_zero_array(state, bool, num_nodes);
		if (tevent_req_nomem(state->ready, req)) {
			return tevent_req_post(req, ev);
		}

		subreq = ctdb_client_set_message_handler_send(
					state, ev, client, MSG_ID_JOIN,
					cluster_wait_join_handler, req);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, cluster_wait_join_registered,
					req);
	}

	subreq = ctdb_client_set_message_handler_send(
					state, ev, client, MSG_ID_SYNC,
					cluster_wait_sync_handler, req);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cluster_wait_sync_registered, req);

	/* If cluster is not synchronized within 30 seconds, time out */
	ok = tevent_req_set_endtime(
		req,
		ev,
		tevent_timeval_current_ofs(30, 0));
	if (!ok) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void cluster_wait_join_registered(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	bool status;
	int ret;

	status = ctdb_client_set_message_handler_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	printf("Waiting for cluster\n");
	fflush(stdout);
}

static void cluster_wait_sync_registered(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cluster_wait_state *state = tevent_req_data(
		req, struct cluster_wait_state);
	bool status;
	int ret;

	status = ctdb_client_set_message_handler_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	subreq = tevent_wakeup_send(state, state->ev,
				    tevent_timeval_current_ofs(1, 0));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cluster_wait_join, req);
}

static void cluster_wait_join(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cluster_wait_state *state = tevent_req_data(
		req, struct cluster_wait_state);
	struct ctdb_req_message msg;
	uint32_t pnn;
	bool status;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, EIO);
		return;
	}

	pnn = ctdb_client_pnn(state->client);

	msg.srvid = MSG_ID_JOIN;
	msg.data.data.dsize = sizeof(pnn);
	msg.data.data.dptr = (uint8_t *)&pnn;

	subreq = ctdb_client_message_send(state, state->ev, state->client,
					  0, &msg);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cluster_wait_join_sent, req);
}

static void cluster_wait_join_sent(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cluster_wait_state *state = tevent_req_data(
		req, struct cluster_wait_state);
	bool status;
	int ret;

	status = ctdb_client_message_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	subreq = tevent_wakeup_send(state, state->ev,
				    tevent_timeval_current_ofs(1, 0));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cluster_wait_join, req);
}

static void cluster_wait_join_handler(uint64_t srvid, TDB_DATA data,
				      void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct cluster_wait_state *state = tevent_req_data(
		req, struct cluster_wait_state);
	struct tevent_req *subreq;
	uint32_t pnn;
	uint32_t i;

	if (srvid != MSG_ID_JOIN) {
		return;
	}

	if (data.dsize != sizeof(uint32_t)) {
		return;
	}

	pnn = *(uint32_t *)data.dptr;

	if (pnn > state->num_nodes) {
		return;
	}

	state->ready[pnn] = true;

	for (i=0; i<state->num_nodes; i++) {
		if (! state->ready[i]) {
			return;
		}
	}

	if (state->join_done) {
		return;
	}

	state->join_done = true;
	subreq = ctdb_client_remove_message_handler_send(
					state, state->ev, state->client,
					MSG_ID_JOIN, req);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cluster_wait_join_unregistered, req);
}

static void cluster_wait_join_unregistered(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cluster_wait_state *state = tevent_req_data(
		req, struct cluster_wait_state);
	struct ctdb_req_message msg;
	bool status;
	int ret;

	status = ctdb_client_remove_message_handler_recv(subreq, &ret);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	msg.srvid = MSG_ID_SYNC;
	msg.data.data = tdb_null;

	subreq = ctdb_client_message_send(state, state->ev, state->client,
					  CTDB_BROADCAST_CONNECTED, &msg);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cluster_wait_sync_sent, req);
}

static void cluster_wait_sync_sent(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	bool status;
	int ret;

	status = ctdb_client_message_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}
}

static void cluster_wait_sync_handler(uint64_t srvid, TDB_DATA data,
				      void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct cluster_wait_state *state = tevent_req_data(
		req, struct cluster_wait_state);
	struct tevent_req *subreq;

	if (srvid != MSG_ID_SYNC) {
		return;
	}

	subreq = ctdb_client_remove_message_handler_send(
					state, state->ev, state->client,
					MSG_ID_SYNC, req);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cluster_wait_sync_unregistered, req);
}

static void cluster_wait_sync_unregistered(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	bool status;
	int ret;

	status = ctdb_client_remove_message_handler_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	tevent_req_done(req);
}

bool cluster_wait_recv(struct tevent_req *req, int *perr)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return false;
	}
	return true;
}
