/*
 * Unix SMB/CIFS implementation.
 * Test dbwrap_watch API
 * Copyright (C) Volker Lendecke 2017
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "torture/proto.h"
#include "system/filesys.h"
#include "lib/dbwrap/dbwrap.h"
#include "lib/dbwrap/dbwrap_open.h"
#include "lib/dbwrap/dbwrap_watch.h"
#include "lib/util/util_tdb.h"
#include "source3/include/util_tdb.h"

struct do_locked1_state {
	TDB_DATA value;
	NTSTATUS status;
};

static void do_locked1_cb(
	struct db_record *rec,
	TDB_DATA value,
	void *private_data)
{
	struct do_locked1_state *state =
		(struct do_locked1_state *)private_data;

	state->status = dbwrap_record_store(rec, state->value, 0);
}

static void do_locked1_check(TDB_DATA key, TDB_DATA value,
			     void *private_data)
{
	struct do_locked1_state *state =
		(struct do_locked1_state *)private_data;
	int ret;

	ret = tdb_data_cmp(value, state->value);
	if (ret != 0) {
		state->status = NT_STATUS_DATA_ERROR;
		return;
	}

	state->status = NT_STATUS_OK;
}

static void do_locked1_del(
	struct db_record *rec,
	TDB_DATA value,
	void *private_data)
{
	struct do_locked1_state *state =
		(struct do_locked1_state *)private_data;

	state->status = dbwrap_record_delete(rec);
}

bool run_dbwrap_do_locked1(int dummy)
{
	struct tevent_context *ev;
	struct messaging_context *msg;
	struct db_context *backend;
	struct db_context *db;
	const char *dbname = "test_do_locked.tdb";
	const char *keystr = "key";
	TDB_DATA key = string_term_tdb_data(keystr);
	const char *valuestr = "value";
	TDB_DATA value = string_term_tdb_data(valuestr);
	struct do_locked1_state state = { .value = value };
	int ret = false;
	NTSTATUS status;

	ev = global_event_context();
	if (ev == NULL) {
		fprintf(stderr, "global_event_context() failed\n");
		return false;
	}
	msg = global_messaging_context();
	if (msg == NULL) {
		fprintf(stderr, "global_messaging_context() failed\n");
		return false;
	}

	backend = db_open(talloc_tos(), dbname, 0,
			  TDB_CLEAR_IF_FIRST, O_CREAT|O_RDWR, 0644,
			  DBWRAP_LOCK_ORDER_1, DBWRAP_FLAG_NONE);
	if (backend == NULL) {
		fprintf(stderr, "db_open failed: %s\n", strerror(errno));
		return false;
	}

	db = db_open_watched(talloc_tos(), &backend, msg);
	if (db == NULL) {
		fprintf(stderr, "db_open_watched failed: %s\n",
			strerror(errno));
		return false;
	}

	status = dbwrap_do_locked(db, key, do_locked1_cb, &state);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "dbwrap_do_locked failed: %s\n",
			nt_errstr(status));
		goto fail;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		fprintf(stderr, "store returned %s\n",
			nt_errstr(state.status));
		goto fail;
	}

	status = dbwrap_parse_record(db, key, do_locked1_check, &state);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "dbwrap_parse_record failed: %s\n",
			nt_errstr(status));
		goto fail;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		fprintf(stderr, "data compare returned %s\n",
			nt_errstr(status));
		goto fail;
	}

	status = dbwrap_do_locked(db, key, do_locked1_del, &state);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "dbwrap_do_locked failed: %s\n",
			nt_errstr(status));
		goto fail;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		fprintf(stderr, "delete returned %s\n", nt_errstr(status));
		goto fail;
	}

	status = dbwrap_parse_record(db, key, do_locked1_check, &state);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		fprintf(stderr, "parse_record returned %s, "
			"expected NOT_FOUND\n", nt_errstr(status));
		goto fail;
	}

	ret = true;
fail:
	TALLOC_FREE(db);
	unlink(dbname);
	return ret;
}
