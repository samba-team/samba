/*
   simple ctdb benchmark for g_lock operations

   Copyright (C) Amitay Isaacs  2016

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
#include "lib/util/debug.h"

#include "protocol/protocol_api.h"
#include "client/client.h"
#include "tests/src/test_options.h"
#include "tests/src/cluster_wait.h"

#define TESTKEY "testkey"

struct glock_loop_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct ctdb_db_context *db;
	int num_nodes;
	int timelimit;
	uint32_t pnn;
	uint32_t counter;
	struct ctdb_server_id sid;
	const char *key;
};

static void glock_loop_start(struct tevent_req *subreq);
static void glock_loop_locked(struct tevent_req *subreq);
static void glock_loop_unlocked(struct tevent_req *subreq);
static void glock_loop_finish(struct tevent_req *subreq);

static struct tevent_req *glock_loop_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct ctdb_client_context *client,
				struct ctdb_db_context *db,
				int num_nodes, int timelimit)
{
	struct tevent_req *req, *subreq;
	struct glock_loop_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct glock_loop_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->client = client;
	state->db = db;
	state->num_nodes = num_nodes;
	state->timelimit = timelimit;
	state->pnn = ctdb_client_pnn(client);
	state->counter = 0;
	state->sid = ctdb_client_get_server_id(client, 1);
	state->key = TESTKEY;

	subreq = cluster_wait_send(state, state->ev, state->client,
				   state->num_nodes);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, glock_loop_start, req);

	return req;
}

static void glock_loop_start(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct glock_loop_state *state = tevent_req_data(
		req, struct glock_loop_state);
	bool status;
	int ret;

	status = cluster_wait_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	subreq = ctdb_g_lock_lock_send(state, state->ev, state->client,
				       state->db, state->key, &state->sid,
				       false);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, glock_loop_locked, req);

	subreq = tevent_wakeup_send(state, state->ev,
				    tevent_timeval_current_ofs(
					    state->timelimit, 0));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, glock_loop_finish, req);
}

static void glock_loop_locked(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct glock_loop_state *state = tevent_req_data(
		req, struct glock_loop_state);
	int ret;
	bool status;

	status = ctdb_g_lock_lock_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		fprintf(stderr, "g_lock_lock failed\n");
		tevent_req_error(req, ret);
		return;
	}

	state->counter += 1;

	subreq = ctdb_g_lock_unlock_send(state, state->ev, state->client,
					 state->db, state->key, state->sid);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, glock_loop_unlocked, req);
}

static void glock_loop_unlocked(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct glock_loop_state *state = tevent_req_data(
		req, struct glock_loop_state);
	int ret;
	bool status;

	status = ctdb_g_lock_unlock_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		fprintf(stderr, "g_lock_unlock failed\n");
		tevent_req_error(req, ret);
		return;
	}

	subreq = ctdb_g_lock_lock_send(state, state->ev, state->client,
				       state->db, state->key, &state->sid,
				       false);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, glock_loop_locked, req);
}

static void glock_loop_finish(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct glock_loop_state *state = tevent_req_data(
		req, struct glock_loop_state);
	bool status;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, EIO);
		return;
	}

	printf("PNN:%u counter:%u\n", state->pnn, state->counter);

	tevent_req_done(req);
}

static bool glock_loop_recv(struct tevent_req *req, int *perr)
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

int main(int argc, const char *argv[])
{
	const struct test_options *opts;
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct ctdb_db_context *ctdb_db;
	struct tevent_req *req;
	int ret;
	bool status;

	setup_logging("glock_loop", DEBUG_STDERR);

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

	ret = ctdb_attach(ev, client, tevent_timeval_zero(), "g_lock.tdb",
			  0, &ctdb_db);
	if (ret != 0) {
		fprintf(stderr, "Failed to attach to g_lock.tdb\n");
		exit(1);
	}

	req = glock_loop_send(mem_ctx, ev, client, ctdb_db,
				    opts->num_nodes, opts->timelimit);
	if (req == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		exit(1);
	}

	tevent_req_poll(req, ev);

	status = glock_loop_recv(req, &ret);
	if (! status) {
		fprintf(stderr, "g_lock loop test failed\n");
		exit(1);
	}

	talloc_free(mem_ctx);
	return 0;
}
