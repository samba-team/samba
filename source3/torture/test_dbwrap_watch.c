/*
   Unix SMB/CIFS implementation.
   Test dbwrap_watch API
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
#include "system/filesys.h"
#include "lib/dbwrap/dbwrap.h"
#include "lib/dbwrap/dbwrap_open.h"
#include "lib/dbwrap/dbwrap_watch.h"
#include "lib/util/util_tdb.h"

static bool test_dbwrap_watch_init(
	TALLOC_CTX *mem_ctx,
	const char *dbname,
	struct tevent_context **pev,
	struct messaging_context **pmsg,
	struct db_context **pbackend,
	struct db_context **pdb)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct db_context *backend = NULL;
	struct db_context *db = NULL;

	ev = samba_tevent_context_init(mem_ctx);
	if (ev == NULL) {
		fprintf(stderr, "tevent_context_init failed\n");
		goto fail;
	}

	msg = messaging_init(ev, ev);
	if (msg == NULL) {
		fprintf(stderr, "messaging_init failed\n");
		goto fail;
	}

	backend = db_open(
		msg,
		dbname,
		0,
		TDB_CLEAR_IF_FIRST,
		O_CREAT|O_RDWR,
		0644,
		DBWRAP_LOCK_ORDER_1,
		DBWRAP_FLAG_NONE);
	if (backend == NULL) {
		fprintf(stderr, "db_open failed: %s\n", strerror(errno));
		goto fail;
	}

	{
		struct db_context *backend_copy = backend;

		db = db_open_watched(ev, &backend_copy, msg);
		if (db == NULL) {
			fprintf(stderr, "db_open_watched failed\n");
			goto fail;
		}
	}

	if (pev != NULL) {
		*pev = ev;
	}
	if (pmsg != NULL) {
		*pmsg = msg;
	}
	if (pbackend != NULL) {
		*pbackend = backend;
	}
	if (pdb != NULL) {
		*pdb = db;
	}
	return true;

fail:
	TALLOC_FREE(backend);
	TALLOC_FREE(msg);
	TALLOC_FREE(ev);
	return false;
}

bool run_dbwrap_watch1(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct db_context *backend = NULL;
	struct db_context *db = NULL;
	const char *keystr = "key";
	TDB_DATA key = string_term_tdb_data(keystr);
	struct db_record *rec = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status;
	bool ret = false;

	ret = test_dbwrap_watch_init(
		talloc_tos(), "test_watch.tdb", &ev, &msg, &backend, &db);
	if (!ret) {
		goto fail;
	}

	rec = dbwrap_fetch_locked(db, db, key);
	if (rec == NULL) {
		fprintf(stderr, "dbwrap_fetch_locked failed\n");
		goto fail;
	}
	req = dbwrap_watched_watch_send(talloc_tos(), ev, rec,
					(struct server_id){0});
	if (req == NULL) {
		fprintf(stderr, "dbwrap_record_watch_send failed\n");
		goto fail;
	}
	TALLOC_FREE(rec);

	status = dbwrap_store_int32_bystring(db, "different_key", 1);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "dbwrap_store_int32 failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	status = dbwrap_store_int32_bystring(db, keystr, 1);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "dbwrap_store_int32 failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		fprintf(stderr, "tevent_req_poll failed\n");
		goto fail;
	}

	status = dbwrap_watched_watch_recv(req, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "dbwrap_record_watch_recv failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	(void)unlink("test_watch.tdb");
	ret = true;
fail:
	TALLOC_FREE(req);
	TALLOC_FREE(rec);
	TALLOC_FREE(db);
	TALLOC_FREE(msg);
	TALLOC_FREE(ev);
	return ret;
}

/*
 * Make sure dbwrap_parse_record does not return NT_STATUS_OK on
 * invalid data
 */

bool run_dbwrap_watch2(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct db_context *backend = NULL;
	struct db_context *db = NULL;
	const char *keystr = "key";
	TDB_DATA key = string_term_tdb_data(keystr);
	NTSTATUS status;
	bool ret = false;

	ret = test_dbwrap_watch_init(
		talloc_tos(), "test_watch.tdb", &ev, &msg, &backend, &db);
	if (!ret) {
		goto fail;
	}

	/*
	 * Store invalid data (from the dbwrap_watch point of view)
	 * directly into the backend database
	 */
	status = dbwrap_store_uint32_bystring(backend, keystr, UINT32_MAX);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "dbwrap_store_uint32_bystring failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	status = dbwrap_parse_record(db, key, NULL, NULL);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		fprintf(stderr, "dbwrap_parse_record returned %s, expected "
			"NT_STATUS_NOT_FOUND\n", nt_errstr(status));
		goto fail;
	}

	(void)unlink("test_watch.tdb");
	ret = true;
fail:
	TALLOC_FREE(db);
	TALLOC_FREE(msg);
	TALLOC_FREE(ev);
	return ret;
}

/*
 * Test autocleanup of dead watchers
 */

bool run_dbwrap_watch3(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct db_context *backend = NULL;
	struct db_context *db = NULL;
	const char *keystr = "key";
	TDB_DATA key = string_term_tdb_data(keystr);
	NTSTATUS status;
	bool ret = false;
	pid_t child, waited;
	int wstatus, exit_status;

	BlockSignals(true, SIGCHLD);

	child = fork();
	if (child == -1) {
		fprintf(stderr,
			"fork failed: %s\n",
			strerror(errno));
		goto fail;
	}

	ret = test_dbwrap_watch_init(
		talloc_tos(), "test_watch.tdb", &ev, &msg, &backend, &db);
	if (!ret) {
		goto fail;
	}

	if (child == 0) {
		struct db_record *rec = dbwrap_fetch_locked(db, db, key);
		struct tevent_req *req = NULL;

		if (rec == NULL) {
			fprintf(stderr, "dbwrap_fetch_locked failed\n");
			exit(1);
		}

		req = dbwrap_watched_watch_send(
			db, ev, rec, (struct server_id) { 0 });
		if (req == NULL) {
			fprintf(stderr, "dbwrap_watched_watch_send failed\n");
			exit(2);
		}

		exit(0);
	}

	waited = waitpid(child, &wstatus, 0);
	if (waited == -1) {
		fprintf(stderr, "waitpid failed: %s\n", strerror(errno));
		goto fail;
	}
	if (!WIFEXITED(wstatus)) {
		fprintf(stderr, "child did not exit normally\n");
		goto fail;
	}

	exit_status = WEXITSTATUS(wstatus);
	if (exit_status != 0) {
		fprintf(stderr, "exit status is %d\n", exit_status);
		goto fail;
	}

	status = dbwrap_store_uint32_bystring(db, keystr, 1);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OK)) {
		fprintf(stderr,
			"dbwrap_store_uint32 returned %s\n",
			nt_errstr(status));
		goto fail;
	}

	(void)unlink("test_watch.tdb");
	ret = true;
fail:
	TALLOC_FREE(db);
	TALLOC_FREE(msg);
	TALLOC_FREE(ev);
	return ret;
}

/*
 * Test that we can't add two watchers in the same
 * fetch_lock/do_locked round
 */

struct dbwrap_watch4_state {
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct db_context *db;
	TDB_DATA key;

	NTSTATUS status;

	struct tevent_req *req1;
	NTSTATUS status1;

	struct tevent_req *req2;
	NTSTATUS status2;
};

static void dbwrap_watch4_done1(struct tevent_req *subreq);
static void dbwrap_watch4_done2(struct tevent_req *subreq);

static void dbwrap_watch4_fn(struct db_record *rec,
			     TDB_DATA value,
			     void *private_data)
{
	struct dbwrap_watch4_state *state = private_data;
	bool ok;

	state->req1 = dbwrap_watched_watch_send(
		state->mem_ctx, state->ev, rec, (struct server_id) { .pid=0 });
	if (state->req1 == NULL) {
		goto nomem;
	}
	tevent_req_set_callback(state->req1, dbwrap_watch4_done1, state);
	state->status1 = NT_STATUS_EVENT_PENDING;

	ok = tevent_req_set_endtime(
		state->req1, state->ev, timeval_current_ofs(1, 0));
	if (!ok) {
		goto nomem;
	}

	state->req2 = dbwrap_watched_watch_send(
		state->mem_ctx, state->ev, rec, (struct server_id) { .pid=0 });
	if (state->req2 == NULL) {
		goto nomem;
	}
	tevent_req_set_callback(state->req2, dbwrap_watch4_done2, state);
	state->status2 = NT_STATUS_EVENT_PENDING;

	ok = tevent_req_set_endtime(
		state->req2, state->ev, timeval_current_ofs(1, 0));
	if (!ok) {
		goto nomem;
	}

	state->status = NT_STATUS_OK;
	return;

	nomem:
	state->status = NT_STATUS_NO_MEMORY;
}

static void dbwrap_watch4_done1(struct tevent_req *subreq)
{
	struct dbwrap_watch4_state *state = tevent_req_callback_data_void(subreq);
	state->status1 = dbwrap_watched_watch_recv(subreq, NULL, NULL);
	TALLOC_FREE(subreq);
	printf("req1 finished: %s\n", nt_errstr(state->status1));
	state->req1 = NULL;
}

static void dbwrap_watch4_done2(struct tevent_req *subreq)
{
	struct dbwrap_watch4_state *state = tevent_req_callback_data_void(subreq);
	state->status2 = dbwrap_watched_watch_recv(subreq, NULL, NULL);
	TALLOC_FREE(subreq);
	printf("req2 finished: %s\n", nt_errstr(state->status2));
	state->req2 = NULL;
}

bool run_dbwrap_watch4(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct db_context *backend = NULL;
	struct db_context *db = NULL;
	const char *keystr = "key";
	TDB_DATA key = string_term_tdb_data(keystr);
	struct dbwrap_watch4_state state = { 0 };
	NTSTATUS status;
	bool ret = false;
	bool ok;

	ok = test_dbwrap_watch_init(
		talloc_tos(), "test_watch.tdb", &ev, &msg, &backend, &db);
	if (!ok) {
		goto fail;
	}

	state = (struct dbwrap_watch4_state) {
		.mem_ctx = talloc_tos(),
		.ev = ev,
		.db = db,
		.key = key,
	};

	status = dbwrap_do_locked(db, key, dbwrap_watch4_fn, &state);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr,
			"dbwrap_do_locked failed: %s\n",
			nt_errstr(status));
		goto fail;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		fprintf(stderr,
			"dbwrap_watch4_fn failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	status = dbwrap_store(db, key, key, 0);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr,
			"dbwrap_store failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	while (NT_STATUS_EQUAL(state.status1, NT_STATUS_EVENT_PENDING) ||
	       NT_STATUS_EQUAL(state.status2, NT_STATUS_EVENT_PENDING)) {
		int res = tevent_loop_once(ev);
		if (res != 0) {
			fprintf(stderr,
				"tevent_loop_once failed: %s\n",
				strerror(errno));
			goto fail;
		}
	}

	if (!NT_STATUS_IS_OK(state.status1)) {
		fprintf(stderr,
			"req1 returned %s\n",
			nt_errstr(state.status1));
		goto fail;
	}

	if (!NT_STATUS_EQUAL(state.status2, NT_STATUS_REQUEST_NOT_ACCEPTED)) {
		fprintf(stderr,
			"req2 returned %s\n",
			nt_errstr(state.status2));
		goto fail;
	}

	(void)unlink("test_watch.tdb");
	ret = true;
fail:
	TALLOC_FREE(state.req2);
	TALLOC_FREE(state.req1);
	TALLOC_FREE(db);
	TALLOC_FREE(msg);
	TALLOC_FREE(ev);
	return ret;
}
