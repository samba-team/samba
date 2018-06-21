/*
   Update a record in persistent database

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

#include "protocol/protocol_api.h"
#include "client/client.h"
#include "tests/src/test_options.h"
#include "tests/src/cluster_wait.h"

struct update_record_state {
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct ctdb_db_context *db;
	int timelimit;
	TDB_DATA key, data;
};

static void update_record_update_done(struct tevent_req *subreq);

static struct tevent_req *update_record_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct ctdb_client_context *client,
					     struct ctdb_db_context *db,
					     const char *keystr,
					     const char *valuestr,
					     int timelimit)
{
	struct tevent_req *req, *subreq;
	struct update_record_state *state;
	struct ctdb_ltdb_header header;
	struct ctdb_rec_buffer *recbuf;
	struct ctdb_req_control request;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct update_record_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->client = client;
	state->db = db;
	state->timelimit = timelimit;
	state->key.dptr = (uint8_t *)discard_const(keystr);
	state->key.dsize = strlen(keystr);
	state->data.dptr = (uint8_t *)discard_const(valuestr);
	state->data.dsize = strlen(valuestr);

	ret = ctdb_ltdb_fetch(state->db, state->key, &header, NULL, NULL);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	header.rsn += 1;

	recbuf = ctdb_rec_buffer_init(state, ctdb_db_id(state->db));
	if (tevent_req_nomem(recbuf, req)) {
		return tevent_req_post(req, ev);
	}

	ret = ctdb_rec_buffer_add(state, recbuf, 0, &header,
				  state->key, state->data);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	ctdb_req_control_update_record(&request, recbuf);
	subreq = ctdb_client_control_send(state, state->ev, state->client,
					  CTDB_CURRENT_NODE,
					  tevent_timeval_current_ofs(
						  state->timelimit, 0),
					  &request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, update_record_update_done, req);

	talloc_free(recbuf);
	return req;
}

static void update_record_update_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct update_record_state *state = tevent_req_data(
		req, struct update_record_state);
	struct ctdb_reply_control *reply;
	int ret;
	bool status;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_update_record(reply);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	talloc_free(reply);

	tevent_req_done(req);
}

static bool update_record_recv(struct tevent_req *req, int *perr)
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

	setup_logging("update_record_persistene", DEBUG_STDERR);

	status = process_options_database(argc, argv, &opts);
	if (! status) {
		exit(1);
	}

	if (opts->valuestr == NULL) {
		fprintf(stderr, "Error: please specify key value (-v)\n");
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
		fprintf(stderr, "Failed to initialize client (%s), %s\n",
			opts->socket, strerror(ret));
		exit(1);
	}

	if (! ctdb_recovery_wait(ev, client)) {
		fprintf(stderr, "Memory allocation error\n");
		exit(1);
	}

	ret = ctdb_attach(ev, client, tevent_timeval_zero(), opts->dbname,
			  CTDB_DB_FLAGS_PERSISTENT, &ctdb_db);
	if (ret != 0) {
		fprintf(stderr, "Failed to attach DB %s\n", opts->dbname);
		exit(1);
	}

	req = update_record_send(mem_ctx, ev, client, ctdb_db,
				 opts->keystr, opts->valuestr,
				 opts->timelimit);
	if (req == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		exit(1);
	}

	tevent_req_poll(req, ev);

	status = update_record_recv(req, &ret);
	if (! status) {
		fprintf(stderr, "update record failed\n");
		exit(1);
	}

	talloc_free(mem_ctx);
	return 0;
}
