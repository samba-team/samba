/*
 * Test cancellation of unconfirmed DB pushes
 *
 * Copyright 2026, DataDirect Networks, Inc. All rights reserved.
 * Author: Martin Schwenke <mschwenke@ddn.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This uses the DB push controls on the local node, like the recovery
 * helper, but without a recovery:
 *
 * 1. Freeze the database, start a transaction, start a push, push a
 *    record and thaw the database without confirming the push.  A
 *    record pushed later with the same SRVID must be ignored.
 *
 * 2. Freeze the database, start a transaction, start a push and then
 *    start another push to replace it.  Push a record using each
 *    push, confirm the push, commit the transaction and thaw the
 *    database.  Only the record from the replacement push must be
 *    stored.
 *
 * 3. Freeze the database, start a transaction and start a push.
 *    Start another transaction, like a retried recovery, and push a
 *    record using the first push.  Start another push, push a record
 *    using it, confirm the push, commit the transaction and thaw the
 *    database.  Only the record from the second push must be stored.
 *
 * 4. Freeze the database, start a transaction, start a push, push a
 *    record and detach the database.  The push must be cancelled
 *    without ctdbd crashing.  Detaching requires AllowClientDBAttach=0,
 *    which would stop this client attaching, so it is set here.
 *
 * Committing the transaction sets the database generation to the
 * transaction ID, so use the current generation.
 */

#include "replace.h"
#include "system/network.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/util/debug.h"

#include "protocol/protocol_api.h"
#include "client/client.h"
#include "client/client_sync.h"
#include "tests/src/test_options.h"
#include "tests/src/cluster_wait.h"

#define TIMEOUT() tevent_timeval_current_ofs(10, 0)

#define SRVID_PUSH_CANCELLED (CTDB_SRVID_RECOVERY | 0x7e57001ULL)
#define SRVID_PUSH_REPLACED (CTDB_SRVID_RECOVERY | 0x7e57002ULL)
#define SRVID_PUSH_REPLACEMENT (CTDB_SRVID_RECOVERY | 0x7e57003ULL)
#define SRVID_PUSH_DETACHED (CTDB_SRVID_RECOVERY | 0x7e57004ULL)
#define SRVID_PUSH_RESTARTED (CTDB_SRVID_RECOVERY | 0x7e57005ULL)
#define SRVID_PUSH_RETRY (CTDB_SRVID_RECOVERY | 0x7e57006ULL)

struct test_context {
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	struct ctdb_db_context *db;
	uint32_t db_id;
	uint32_t pnn;
	uint32_t generation;
};

static void fail(const char *msg)
{
	fprintf(stderr, "FAILED: %s\n", msg);
	exit(1);
}

/*
 * Messages to the local node are dispatched from a timer, so a control
 * sent after a message can be processed before the message.  The
 * timer has run before a second control is processed.
 */
static void sync_messages(struct test_context *t)
{
	uint32_t pnn;
	int i, ret;

	for (i = 0; i < 2; i++) {
		ret = ctdb_ctrl_get_pnn(
			t->mem_ctx, t->ev, t->client, t->pnn, TIMEOUT(), &pnn);
		if (ret != 0) {
			fail("GET_PNN control");
		}
	}
}

static void db_freeze(struct test_context *t)
{
	int ret;

	ret = ctdb_ctrl_db_freeze(
		t->mem_ctx, t->ev, t->client, t->pnn, TIMEOUT(), t->db_id);
	if (ret != 0) {
		fail("DB_FREEZE control");
	}
}

static void db_thaw(struct test_context *t)
{
	int ret;

	ret = ctdb_ctrl_db_thaw(
		t->mem_ctx, t->ev, t->client, t->pnn, TIMEOUT(), t->db_id);
	if (ret != 0) {
		fail("DB_THAW control");
	}
}

static void allow_db_detach(struct test_context *t)
{
	struct ctdb_node_map *nodemap = NULL;
	struct ctdb_tunable tunable = {
		.name = "AllowClientDBAttach",
		.value = 0,
	};
	uint32_t i;
	int ret;

	ret = ctdb_ctrl_get_nodemap(
		t->mem_ctx, t->ev, t->client, t->pnn, TIMEOUT(), &nodemap);
	if (ret != 0) {
		fail("GET_NODEMAP control");
	}

	for (i = 0; i < nodemap->num; i++) {
		ret = ctdb_ctrl_set_tunable(t->mem_ctx,
					    t->ev,
					    t->client,
					    nodemap->node[i].pnn,
					    TIMEOUT(),
					    &tunable);
		if (ret != 0) {
			fail("SET_TUNABLE control");
		}
	}

	talloc_free(nodemap);
}

static void db_detach(struct test_context *t)
{
	int ret;

	ret = ctdb_ctrl_db_detach(
		t->mem_ctx, t->ev, t->client, t->pnn, TIMEOUT(), t->db_id);
	if (ret != 0) {
		fail("DB_DETACH control");
	}
}

static bool db_attached(struct test_context *t)
{
	struct ctdb_dbid_map *dbmap = NULL;
	uint32_t i;
	int ret;

	ret = ctdb_ctrl_get_dbmap(
		t->mem_ctx, t->ev, t->client, t->pnn, TIMEOUT(), &dbmap);
	if (ret != 0) {
		fail("GET_DBMAP control");
	}

	for (i = 0; i < dbmap->num; i++) {
		if (dbmap->dbs[i].db_id == t->db_id) {
			talloc_free(dbmap);
			return true;
		}
	}

	talloc_free(dbmap);
	return false;
}

static void transaction_start(struct test_context *t)
{
	struct ctdb_transdb transdb = {
		.db_id = t->db_id,
		.tid = t->generation,
	};
	int ret;

	ret = ctdb_ctrl_db_transaction_start(
		t->mem_ctx, t->ev, t->client, t->pnn, TIMEOUT(), &transdb);
	if (ret != 0) {
		fail("DB_TRANSACTION_START control");
	}
}

static void transaction_commit(struct test_context *t)
{
	struct ctdb_transdb transdb = {
		.db_id = t->db_id,
		.tid = t->generation,
	};
	int ret;

	ret = ctdb_ctrl_db_transaction_commit(
		t->mem_ctx, t->ev, t->client, t->pnn, TIMEOUT(), &transdb);
	if (ret != 0) {
		fail("DB_TRANSACTION_COMMIT control");
	}
}

static void push_start(struct test_context *t, uint64_t srvid)
{
	struct ctdb_pulldb_ext pulldb_ext = {
		.db_id = t->db_id,
		.srvid = srvid,
	};
	int ret;

	ret = ctdb_ctrl_db_push_start(
		t->mem_ctx, t->ev, t->client, t->pnn, TIMEOUT(), &pulldb_ext);
	if (ret != 0) {
		fail("DB_PUSH_START control");
	}
}

static uint32_t push_confirm(struct test_context *t)
{
	uint32_t num_records = 0;
	int ret;

	ret = ctdb_ctrl_db_push_confirm(t->mem_ctx,
					t->ev,
					t->client,
					t->pnn,
					TIMEOUT(),
					t->db_id,
					&num_records);
	if (ret != 0) {
		fail("DB_PUSH_CONFIRM control");
	}

	return num_records;
}

static void push_record(struct test_context *t,
			uint64_t srvid,
			const char *keystr,
			const char *valuestr)
{
	struct ctdb_ltdb_header header = {
		.rsn = 1,
		.dmaster = t->pnn,
	};
	struct ctdb_rec_buffer *recbuf = NULL;
	struct ctdb_req_message message = {
		.srvid = srvid,
	};
	TDB_DATA key = {
		.dptr = discard_const(keystr),
		.dsize = strlen(keystr),
	};
	TDB_DATA value = {
		.dptr = discard_const(valuestr),
		.dsize = strlen(valuestr),
	};
	TDB_DATA data;
	size_t np;
	int ret;

	recbuf = ctdb_rec_buffer_init(t->mem_ctx, t->db_id);
	if (recbuf == NULL) {
		fail("Memory allocation");
	}

	ret = ctdb_rec_buffer_add(recbuf, recbuf, 0, &header, key, value);
	if (ret != 0) {
		fail("Adding record to buffer");
	}

	data.dsize = ctdb_rec_buffer_len(recbuf);
	data.dptr = talloc_size(recbuf, data.dsize);
	if (data.dptr == NULL) {
		fail("Memory allocation");
	}
	ctdb_rec_buffer_push(recbuf, data.dptr, &np);

	message.data.data = data;

	ret = ctdb_client_message(
		t->mem_ctx, t->ev, t->client, t->pnn, &message);
	if (ret != 0) {
		fail("Sending records");
	}

	talloc_free(recbuf);
}

struct find_record_state {
	const char *keystr;
	char *valuestr;
};

static int find_record_parser(uint32_t reqid,
			      struct ctdb_ltdb_header *header,
			      TDB_DATA key,
			      TDB_DATA data,
			      void *private_data)
{
	struct find_record_state *state = private_data;

	if (key.dsize != strlen(state->keystr) ||
	    memcmp(key.dptr, state->keystr, key.dsize) != 0)
	{
		return 0;
	}

	state->valuestr = talloc_strndup(NULL,
					 (const char *)data.dptr,
					 data.dsize);
	if (state->valuestr == NULL) {
		fail("Memory allocation");
	}

	/* Returning non-zero would be treated as an error */
	return 0;
}

/* Return value of record in local database, or NULL if not present */
static char *find_record(struct test_context *t, const char *keystr)
{
	struct find_record_state state = {
		.keystr = keystr,
	};
	int ret;

	ret = ctdb_db_traverse_local(
		t->db, true, true, find_record_parser, &state);
	if (ret != 0) {
		fail("Traversing local database");
	}

	if (state.valuestr != NULL) {
		talloc_steal(t->mem_ctx, state.valuestr);
	}

	return state.valuestr;
}

static void check_record(struct test_context *t,
			 const char *keystr,
			 const char *expected)
{
	char *value = find_record(t, keystr);

	if (expected == NULL) {
		if (value != NULL) {
			fprintf(stderr,
				"Record %s unexpectedly has value \"%s\"\n",
				keystr,
				value);
			fail("Unexpected record");
		}
		printf("Record %s not present\n", keystr);
		return;
	}

	if (value == NULL) {
		fprintf(stderr, "Record %s not present\n", keystr);
		fail("Missing record");
	}
	if (strcmp(value, expected) != 0) {
		fprintf(stderr,
			"Record %s has value \"%s\", expected \"%s\"\n",
			keystr,
			value,
			expected);
		fail("Wrong record value");
	}
	printf("Record %s has value \"%s\"\n", keystr, value);
}

static void test_thaw_cancels_push(struct test_context *t, const char *prefix)
{
	char *key1 = talloc_asprintf(t->mem_ctx, "%s-cancelled", prefix);
	char *key2 = talloc_asprintf(t->mem_ctx, "%s-late", prefix);

	if (key1 == NULL || key2 == NULL) {
		fail("Memory allocation");
	}

	printf("Pushing record, then thawing without confirming\n");
	db_freeze(t);
	transaction_start(t);
	push_start(t, SRVID_PUSH_CANCELLED);
	push_record(t, SRVID_PUSH_CANCELLED, key1, "1");
	sync_messages(t);
	db_thaw(t);

	printf("Pushing record after thaw\n");
	push_record(t, SRVID_PUSH_CANCELLED, key2, "2");
	sync_messages(t);

	/* Thawing cancels the transaction */
	check_record(t, key1, NULL);
	check_record(t, key2, NULL);
}

static void test_replaced_push(struct test_context *t, const char *prefix)
{
	char *key1 = talloc_asprintf(t->mem_ctx, "%s-replaced", prefix);
	char *key2 = talloc_asprintf(t->mem_ctx, "%s-replacement", prefix);
	uint32_t num_records;

	if (key1 == NULL || key2 == NULL) {
		fail("Memory allocation");
	}

	printf("Replacing push, then confirming\n");
	db_freeze(t);
	transaction_start(t);
	push_start(t, SRVID_PUSH_REPLACED);
	push_start(t, SRVID_PUSH_REPLACEMENT);
	push_record(t, SRVID_PUSH_REPLACED, key1, "3");
	push_record(t, SRVID_PUSH_REPLACEMENT, key2, "4");
	sync_messages(t);
	num_records = push_confirm(t);
	transaction_commit(t);
	db_thaw(t);

	printf("Confirmed %" PRIu32 " records\n", num_records);
	if (num_records != 1) {
		fail("Wrong number of confirmed records");
	}

	check_record(t, key1, NULL);
	check_record(t, key2, "4");
}

static void test_restarted_transaction(struct test_context *t,
				       const char *prefix)
{
	char *key1 = talloc_asprintf(t->mem_ctx, "%s-restarted", prefix);
	char *key2 = talloc_asprintf(t->mem_ctx, "%s-retry", prefix);
	uint32_t num_records;

	if (key1 == NULL || key2 == NULL) {
		fail("Memory allocation");
	}

	printf("Restarting transaction, then confirming\n");
	db_freeze(t);
	transaction_start(t);
	push_start(t, SRVID_PUSH_RESTARTED);
	transaction_start(t);
	push_record(t, SRVID_PUSH_RESTARTED, key1, "5");
	sync_messages(t);
	push_start(t, SRVID_PUSH_RETRY);
	push_record(t, SRVID_PUSH_RETRY, key2, "6");
	sync_messages(t);
	num_records = push_confirm(t);
	transaction_commit(t);
	db_thaw(t);

	printf("Confirmed %" PRIu32 " records\n", num_records);
	if (num_records != 1) {
		fail("Wrong number of confirmed records");
	}

	check_record(t, key1, NULL);
	check_record(t, key2, "6");
}

static void test_detach_cancels_push(struct test_context *t,
				     const char *prefix)
{
	char *key = talloc_asprintf(t->mem_ctx, "%s-detached", prefix);
	int i;

	if (key == NULL) {
		fail("Memory allocation");
	}

	printf("Pushing record, then detaching database\n");
	db_freeze(t);
	transaction_start(t);
	push_start(t, SRVID_PUSH_DETACHED);
	push_record(t, SRVID_PUSH_DETACHED, key, "7");
	sync_messages(t);

	/* Detach is broadcast and done asynchronously */
	allow_db_detach(t);
	db_detach(t);
	for (i = 0; i < 10; i++) {
		if (!db_attached(t)) {
			printf("Database detached\n");
			return;
		}
		sleep(1);
	}

	fail("Database not detached");
}

int main(int argc, const char *argv[])
{
	const struct test_options *opts;
	struct test_context t = {};
	struct ctdb_vnn_map *vnnmap = NULL;
	int ret;
	bool status;

	setup_logging("db_push_test", DEBUG_STDERR);

	status = process_options_database(argc, argv, &opts);
	if (!status) {
		exit(1);
	}

	t.mem_ctx = talloc_new(NULL);
	if (t.mem_ctx == NULL) {
		fail("Memory allocation");
	}

	t.ev = tevent_context_init(t.mem_ctx);
	if (t.ev == NULL) {
		fail("Memory allocation");
	}

	ret = ctdb_client_init(t.mem_ctx, t.ev, opts->socket, &t.client);
	if (ret != 0) {
		fprintf(stderr,
			"Failed to initialize client (%s), %s\n",
			opts->socket,
			strerror(ret));
		exit(1);
	}

	if (!ctdb_recovery_wait(t.ev, t.client)) {
		fail("Waiting for recovery");
	}

	ret = ctdb_attach(
		t.ev, t.client, tevent_timeval_zero(), opts->dbname, 0, &t.db);
	if (ret != 0) {
		fprintf(stderr, "Failed to attach DB %s\n", opts->dbname);
		exit(1);
	}

	t.db_id = ctdb_db_id(t.db);
	t.pnn = ctdb_client_pnn(t.client);

	ret = ctdb_ctrl_getvnnmap(
		t.mem_ctx, t.ev, t.client, t.pnn, TIMEOUT(), &vnnmap);
	if (ret != 0) {
		fail("GETVNNMAP control");
	}
	t.generation = vnnmap->generation;

	test_thaw_cancels_push(&t, opts->keystr);
	test_replaced_push(&t, opts->keystr);
	test_restarted_transaction(&t, opts->keystr);
	/* Last, since it detaches the database */
	test_detach_cancels_push(&t, opts->keystr);

	talloc_free(t.mem_ctx);
	return 0;
}
