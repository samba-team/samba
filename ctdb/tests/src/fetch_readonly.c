/*
   Fetch a single record using readonly

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


struct fetch_readonly_state {
	struct tevent_context *ev;
};

static void fetch_readonly_done(struct tevent_req *subreq);

static struct tevent_req *fetch_readonly_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct ctdb_client_context *client,
					  struct ctdb_db_context *db,
					  const char *keystr,
					  int timelimit)
{
	struct tevent_req *req, *subreq;
	struct fetch_readonly_state *state;
	TDB_DATA key;

	req = tevent_req_create(mem_ctx, &state, struct fetch_readonly_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;

	key.dptr = (uint8_t *)discard_const(keystr);
	key.dsize = strlen(keystr);

	subreq = ctdb_fetch_lock_send(state, ev, client, db, key, true);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, fetch_readonly_done, req);

	return req;
}

static void fetch_readonly_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct fetch_readonly_state *state = tevent_req_data(
		req, struct fetch_readonly_state);
	struct ctdb_record_handle *h;
	int ret;

	h = ctdb_fetch_lock_recv(subreq, NULL, state, NULL, &ret);
	TALLOC_FREE(subreq);
	if (h == NULL) {
		tevent_req_error(req, ret);
		return;
	}

	talloc_free(h);
	tevent_req_done(req);
}

static bool fetch_readonly_recv(struct tevent_req *req, int *perr)
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

	setup_logging("fetch_readonly", DEBUG_STDERR);

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
		fprintf(stderr, "Failed to initialize client, %s\n",
			strerror(ret));
		exit(1);
	}

	if (! ctdb_recovery_wait(ev, client)) {
		fprintf(stderr, "Memory allocation error\n");
		exit(1);
	}

	ret = ctdb_attach(ev, client, tevent_timeval_zero(), opts->dbname, 0,
			  &ctdb_db);
	if (ret != 0) {
		fprintf(stderr, "Failed to attach to DB %s\n", opts->dbname);
		exit(1);
	}

	req = fetch_readonly_send(mem_ctx, ev, client, ctdb_db,
				  opts->keystr, opts->timelimit);
	if (req == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		exit(1);
	}

	tevent_req_poll(req, ev);

	status = fetch_readonly_recv(req, &ret);
	if (! status) {
		fprintf(stderr, "fetch readonly loop test failed\n");
		exit(1);
	}

	talloc_free(mem_ctx);
	return 0;
}
