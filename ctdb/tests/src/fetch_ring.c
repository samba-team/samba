/*
   simple ctdb benchmark

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

#define MSG_ID_FETCH	0

static uint32_t next_node(struct ctdb_client_context *client, uint32_t num_nodes)
{
	return (ctdb_client_pnn(client) + 1) % num_nodes;
}

struct fetch_ring_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct ctdb_db_context *ctdb_db;
	uint32_t num_nodes;
	int timelimit;
	int interactive;
	TDB_DATA key;
	int msg_count;
	struct timeval start_time;
};

static void fetch_ring_msg_handler(uint64_t srvid, TDB_DATA data,
				    void *private_data);
static void fetch_ring_wait(struct tevent_req *subreq);
static void fetch_ring_start(struct tevent_req *subreq);
static void fetch_ring_update(struct tevent_req *subreq);
static void fetch_ring_msg_sent(struct tevent_req *subreq);
static void fetch_ring_finish(struct tevent_req *subreq);
static void fetch_ring_final_read(struct tevent_req *subreq);

static struct tevent_req *fetch_ring_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct ctdb_client_context *client,
					  struct ctdb_db_context *ctdb_db,
					  const char *keystr,
					  uint32_t num_nodes,
					  int timelimit,
					  int interactive)
{
	struct tevent_req *req, *subreq;
	struct fetch_ring_state *state;

	req = tevent_req_create(mem_ctx, &state, struct fetch_ring_state);
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

	subreq = ctdb_client_set_message_handler_send(
					state, ev, client, MSG_ID_FETCH,
					fetch_ring_msg_handler, req);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, fetch_ring_wait, req);

	return req;
}

static void fetch_ring_msg_handler(uint64_t srvid, TDB_DATA data,
				   void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct fetch_ring_state *state = tevent_req_data(
		req, struct fetch_ring_state);
	struct tevent_req *subreq;

	state->msg_count += 1;

	subreq = ctdb_fetch_lock_send(state, state->ev, state->client,
				      state->ctdb_db, state->key, false);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, fetch_ring_update, req);
}

static void fetch_ring_wait(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct fetch_ring_state *state = tevent_req_data(
		req, struct fetch_ring_state);
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
	tevent_req_set_callback(subreq, fetch_ring_start, req);
}

static void fetch_ring_start(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct fetch_ring_state *state = tevent_req_data(
		req, struct fetch_ring_state);
	bool status;
	int ret;

	status = cluster_wait_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	state->start_time = tevent_timeval_current();

	if (ctdb_client_pnn(state->client) == state->num_nodes-1) {
		subreq = ctdb_fetch_lock_send(state, state->ev, state->client,
					      state->ctdb_db, state->key,
					      false);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, fetch_ring_update, req);
	}

	subreq = tevent_wakeup_send(state, state->ev,
				    tevent_timeval_current_ofs(
					    state->timelimit, 0));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, fetch_ring_finish, req);

}

static void fetch_ring_update(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct fetch_ring_state *state = tevent_req_data(
		req, struct fetch_ring_state);
	struct ctdb_record_handle *h;
	struct ctdb_req_message msg;
	TDB_DATA data;
	uint32_t pnn;
	int ret;

	h = ctdb_fetch_lock_recv(subreq, NULL, state, &data, &ret);
	TALLOC_FREE(subreq);
	if (h == NULL) {
		tevent_req_error(req, ret);
		return;
	}

	if (data.dsize > 1000) {
		TALLOC_FREE(data.dptr);
		data.dsize = 0;
	}

	if (data.dsize == 0) {
		data.dptr = (uint8_t *)talloc_asprintf(state, "Test data\n");
		if (tevent_req_nomem(data.dptr, req)) {
			return;
		}
	}

	data.dptr = (uint8_t *)talloc_asprintf_append(
					(char *)data.dptr,
					"msg_count=%d on node %d\n",
					state->msg_count,
					ctdb_client_pnn(state->client));
	if (tevent_req_nomem(data.dptr, req)) {
		return;
	}

	data.dsize = strlen((const char *)data.dptr) + 1;

	ret = ctdb_store_record(h, data);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	talloc_free(data.dptr);
	talloc_free(h);

	msg.srvid = MSG_ID_FETCH;
	msg.data.data = tdb_null;

	pnn = next_node(state->client, state->num_nodes);

	subreq = ctdb_client_message_send(state, state->ev, state->client,
					  pnn, &msg);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, fetch_ring_msg_sent, req);
}

static void fetch_ring_msg_sent(struct tevent_req *subreq)
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

static void fetch_ring_finish(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct fetch_ring_state *state = tevent_req_data(
		req, struct fetch_ring_state);
	bool status;
	double t;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, EIO);
		return;
	}

	t = timeval_elapsed(&state->start_time);

	printf("Fetch[%u]: %.2f msgs/sec\n", ctdb_client_pnn(state->client),
	       state->msg_count / t);

	subreq = ctdb_fetch_lock_send(state, state->ev, state->client,
				      state->ctdb_db, state->key, false);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, fetch_ring_final_read, req);
}

static void fetch_ring_final_read(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct fetch_ring_state *state = tevent_req_data(
		req, struct fetch_ring_state);
	struct ctdb_record_handle *h;
	TDB_DATA data;
	int err;

	h = ctdb_fetch_lock_recv(subreq, NULL, state, &data, &err);
	TALLOC_FREE(subreq);
	if (h == NULL) {
		tevent_req_error(req, err);
		return;
	}

	if (state->interactive == 1) {
		printf("DATA:\n%s\n", (char *)data.dptr);
	}
	talloc_free(data.dptr);
	talloc_free(h);

	tevent_req_done(req);
}

static bool fetch_ring_recv(struct tevent_req *req, int *perr)
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

	setup_logging("fetch_ring", DEBUG_STDERR);

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

	ret = ctdb_attach(ev,
			  client,
			  tevent_timeval_zero(),
			  opts->dbname,
			  0,
			  &ctdb_db);
	if (ret != 0) {
		fprintf(stderr, "Failed to attach to DB %s\n", opts->dbname);
		exit(1);
	}

	req = fetch_ring_send(mem_ctx,
			      ev,
			      client,
			      ctdb_db,
			      opts->keystr,
			      opts->num_nodes,
			      opts->timelimit,
			      opts->interactive);
	if (req == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		exit(1);
	}

	tevent_req_poll(req, ev);

	status = fetch_ring_recv(req, NULL);
	if (! status) {
		fprintf(stderr, "fetch ring test failed\n");
		exit(1);
	}

	talloc_free(mem_ctx);
	return 0;
}
