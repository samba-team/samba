/*
   simple ctdb benchmark for persistent databases

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

#include "lib/util/debug.h"
#include "lib/util/tevent_unix.h"

#include "client/client.h"
#include "tests/src/test_options.h"
#include "tests/src/cluster_wait.h"

struct transaction_loop_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct ctdb_db_context *ctdb_db;
	int num_nodes;
	int timelimit;
	int interactive;
	TDB_DATA key;
	uint32_t pnn;
	struct ctdb_transaction_handle *h;
	uint32_t *old_counter, *counter;
	struct tevent_req *subreq;
	bool done;
};

static void transaction_loop_start(struct tevent_req *subreq);
static void transaction_loop_started(struct tevent_req *subreq);
static void transaction_loop_committed(struct tevent_req *subreq);
static void transaction_loop_each_second(struct tevent_req *subreq);
static bool transaction_loop_check_counters(struct tevent_req *req);
static void transaction_loop_finish(struct tevent_req *subreq);

static struct tevent_req *transaction_loop_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct ctdb_client_context *client,
				struct ctdb_db_context *ctdb_db,
				int num_nodes, int timelimit, int interactive,
				const char *keystr)
{
	struct tevent_req *req, *subreq;
	struct transaction_loop_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct transaction_loop_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->client = client;
	state->ctdb_db = ctdb_db;
	state->num_nodes = num_nodes;
	state->timelimit = timelimit;
	state->interactive = interactive;
	state->key.dptr = discard_const(keystr);
	state->key.dsize = strlen(keystr);
	state->pnn = ctdb_client_pnn(client);
	state->old_counter = talloc_zero_array(state, uint32_t, num_nodes);
	if (tevent_req_nomem(state->old_counter, req)) {
		return tevent_req_post(req, ev);
	}
	state->counter = talloc_zero_array(state, uint32_t, num_nodes);
	if (tevent_req_nomem(state->counter, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = cluster_wait_send(state, state->ev, state->client,
				   state->num_nodes);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, transaction_loop_start, req);

	return req;
}

static void transaction_loop_start(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct transaction_loop_state *state = tevent_req_data(
		req, struct transaction_loop_state);
	bool status;
	int ret;

	status = cluster_wait_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	subreq = ctdb_transaction_start_send(state, state->ev, state->client,
					     tevent_timeval_current_ofs(
						     state->timelimit, 0),
					     state->ctdb_db, false);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, transaction_loop_started, req);
	state->subreq = subreq;

	if (ctdb_client_pnn(state->client) == 0) {
		subreq = tevent_wakeup_send(state, state->ev,
					    tevent_timeval_current_ofs(1, 0));
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, transaction_loop_each_second,
					req);
	}

	subreq = tevent_wakeup_send(state, state->ev,
				    tevent_timeval_current_ofs(
					    state->timelimit, 0));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, transaction_loop_finish, req);
}

static void transaction_loop_started(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct transaction_loop_state *state = tevent_req_data(
		req, struct transaction_loop_state);
	TDB_DATA data;
	int ret;
	uint32_t *counter;

	state->h = ctdb_transaction_start_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	state->subreq = NULL;
	if (state->h == NULL) {
		fprintf(stderr, "transaction start failed\n");
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_transaction_fetch_record(state->h, state->key,
					    state, &data);
	if (ret != 0) {
		fprintf(stderr, "transaction fetch record failed\n");
		tevent_req_error(req, ret);
		return;
	}

	if (data.dsize < state->num_nodes * sizeof(uint32_t)) {
		TALLOC_FREE(data.dptr);

		data.dsize = state->num_nodes * sizeof(uint32_t);
		data.dptr = (uint8_t *)talloc_zero_array(state, uint32_t,
							 state->num_nodes);
		if (tevent_req_nomem(data.dptr, req)) {
			return;
		}
	}

	counter = (uint32_t *)data.dptr;
	counter[state->pnn] += 1;
	memcpy(state->counter, counter, state->num_nodes * sizeof(uint32_t));

	ret = ctdb_transaction_store_record(state->h, state->key, data);
	if (ret != 0) {
		fprintf(stderr, "transaction store failed\n");
		tevent_req_error(req, ret);
		return;
	}

	subreq = ctdb_transaction_commit_send(state, state->ev,
					      tevent_timeval_current_ofs(
						      state->timelimit, 0),
					      state->h);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, transaction_loop_committed, req);
	state->subreq = subreq;
}

static void transaction_loop_committed(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct transaction_loop_state *state = tevent_req_data(
		req, struct transaction_loop_state);
	int ret;
	bool status;

	status = ctdb_transaction_commit_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	state->subreq = NULL;
	if (! status) {
		fprintf(stderr, "transaction commit failed - %s\n",
			strerror(ret));
		tevent_req_error(req, ret);
		return;
	}

	if (state->pnn == 0) {
		if (! transaction_loop_check_counters(req)) {
			return;
		}
	}

	if (state->done) {
		int i;

		printf("Transaction[%u]: ", ctdb_client_pnn(state->client));
		for (i=0; i<state->num_nodes; i++) {
			printf("%6u ", state->counter[i]);
		}
		printf("\n");

		tevent_req_done(req);

		return;
	}

	subreq = ctdb_transaction_start_send(state, state->ev, state->client,
					     tevent_timeval_current_ofs(
						     state->timelimit, 0),
					     state->ctdb_db, false);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, transaction_loop_started, req);
}

static void transaction_loop_each_second(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct transaction_loop_state *state = tevent_req_data(
		req, struct transaction_loop_state);
	bool status;
	int i;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (! status) {
		fprintf(stderr, "tevent wakeup failed\n");
		tevent_req_error(req, EIO);
		return;
	}

	if (state->interactive == 1) {
		printf("Transaction[%u]: ", ctdb_client_pnn(state->client));
		for (i=0; i<state->num_nodes; i++) {
			printf("%6u ", state->counter[i]);
		}
		printf("\n");
		fflush(stdout);
	}

	subreq = tevent_wakeup_send(state, state->ev,
				    tevent_timeval_current_ofs(1, 0));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, transaction_loop_each_second, req);
}

static bool transaction_loop_check_counters(struct tevent_req *req)
{
	struct transaction_loop_state *state = tevent_req_data(
		req, struct transaction_loop_state);
	int i;
	bool monotonous = true;

	for (i=0; i<state->num_nodes; i++) {
		if (state->counter[i] < state->old_counter[i]) {
			fprintf(stderr,
				"Counter reduced for node %d: %u -> %u\n",
				i, state->old_counter[i], state->counter[i]);
			monotonous = false;
			break;
		}
	}

	if (monotonous) {
		memcpy(state->old_counter, state->counter,
		       state->num_nodes * sizeof(uint32_t));
	}

	return monotonous;
}

static void transaction_loop_finish(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct transaction_loop_state *state = tevent_req_data(
		req, struct transaction_loop_state);
	bool status;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);

	state->done = true;

	if (! status) {
		tevent_req_error(req, EIO);
		return;
	}
}

static bool transaction_loop_recv(struct tevent_req *req, int *perr)
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
	uint8_t db_flags;
	int ret;
	bool status;

	setup_logging("transaction_loop", DEBUG_STDERR);

	status = process_options_database(argc, argv, &opts);
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

	if (strcmp(opts->dbtype, "persistent") == 0) {
		db_flags = CTDB_DB_FLAGS_PERSISTENT;
	} else if (strcmp(opts->dbtype, "replicated") == 0) {
		db_flags = CTDB_DB_FLAGS_REPLICATED;
	} else {
		fprintf(stderr, "Database must be persistent or replicated\n");
		exit(1);
	}

	ret = ctdb_attach(ev, client, tevent_timeval_zero(), opts->dbname,
			  db_flags, &ctdb_db);
	if (ret != 0) {
		fprintf(stderr, "Failed to attach to persistent DB %s\n",
			opts->dbname);
		exit(1);
	}

	req = transaction_loop_send(mem_ctx, ev, client, ctdb_db,
				    opts->num_nodes, opts->timelimit,
				    opts->interactive, opts->keystr);
	if (req == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		exit(1);
	}

	tevent_req_poll(req, ev);

	status = transaction_loop_recv(req, &ret);
	if (! status) {
		fprintf(stderr, "transaction loop test failed, ret=%d\n", ret);
		exit(1);
	}

	talloc_free(mem_ctx);
	return 0;
}
