/*
 * Unix SMB/CIFS implementation.
 * Test dbwrap per-record persistency API
 * Copyright (C) Ralph Boehme 2018
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

#define CHECK_OK_INTERNAL(expr, msg, log_success)			\
	do {								\
		if (!(expr)) {						\
			fprintf(stderr, "%-50s: failed (at %s)\n",	\
				(msg), __location__);			\
			ok = false;					\
			goto fail;					\
		}							\
		if (log_success) {					\
			fprintf(stdout, "%-50s: OK\n", (msg));		\
		}							\
	} while (false);

#define CHECK_OK(expr, msg) CHECK_OK_INTERNAL((expr), (msg), false)
#define LOG_OK(expr, msg) CHECK_OK_INTERNAL((expr), (msg), true)

struct test_ctx {
	struct tevent_context *ev;
	struct messaging_context *msg;
	struct db_context *db;
	const char *dbname;
	const char *pdbname;
	bool watched;
};

struct wipe_db_flags {
	bool wipe_volatile : 1;
	bool wipe_persistent : 1;
};

static bool wipe_db(struct test_ctx *ctx,
		    struct dbwrap_wipe_flags flags)
{
	int ret;

	ret = dbwrap_wipe(ctx->db, (struct dbwrap_wipe_flags){.wipe_default=true});
	if (ret != 0) {
		fprintf(stderr, "Database %s wipe failed: %s\n",
			ctx->dbname, strerror(ret));
		return false;
	}

	return true;
}

static bool open_db(struct test_ctx *ctx)
{
	struct db_context *watched_db = NULL;

	TALLOC_FREE(ctx->db);

	ctx->db = db_open(talloc_tos(),
			     ctx->dbname,
			     0,
			     TDB_CLEAR_IF_FIRST,
			     O_CREAT | O_RDWR,
			     0644,
			     DBWRAP_LOCK_ORDER_1,
			     DBWRAP_FLAG_PER_REC_PERSISTENT);
	if (ctx->db == NULL) {
		fprintf(stderr, "db_open failed: %s\n",
			strerror(errno));
		return false;
	}

	if (!ctx->watched) {
		return true;
	}

	watched_db = db_open_watched(talloc_tos(),
				     &ctx->db,
				     ctx->msg);
	if (watched_db == NULL) {
		fprintf(stderr, "db_open_watched failed: %s\n",
			strerror(errno));
		return false;
	}
	ctx->db = watched_db;

	return true;
}

/*
 * Wipe the volatile database and then reopen it, which triggers restore of
 * persistent records from the persistent backup database.
 */
static bool reopen_db(struct test_ctx *ctx)
{
	bool ok;

	ok = wipe_db(ctx, (struct dbwrap_wipe_flags){.wipe_default=true});
	CHECK_OK(ok, "wipe_db");

	ok = open_db(ctx);
	CHECK_OK(ok, "open_db");

fail:
	return ok;
}

static bool test_volatile_record(struct test_ctx *ctx)
{
	struct db_record *rec = NULL;
	TDB_DATA key = string_term_tdb_data("key");
	TDB_DATA value = string_term_tdb_data("value");
	TDB_DATA data;
	NTSTATUS status;
	int cmp;
	bool ok = false;

	ok = wipe_db(ctx,
		     (struct dbwrap_wipe_flags){
			     .wipe_default=true,
			     .wipe_persistent_backup_db=true,
		     });
	CHECK_OK(ok, "wipe_db");

	/* 1. Store a volatile record */

	rec = dbwrap_fetch_locked(ctx->db, talloc_tos(), key);
	CHECK_OK(rec != NULL, "dbwrap_fetch_locked()");

	status = dbwrap_record_store(rec, value, 0);
	CHECK_OK(NT_STATUS_IS_OK(status), "dbwrap_record_store()");

	TALLOC_FREE(rec);

	/* 2. Fetch volatile record */

	rec = dbwrap_fetch_locked(ctx->db, talloc_tos(), key);
	CHECK_OK(rec != NULL, "dbwrap_fetch_locked()");

	data = dbwrap_record_get_value(rec);
	cmp = memcmp(value.dptr, data.dptr, MIN(value.dsize, data.dsize));
	CHECK_OK(cmp == 0, "Bad record");

	TALLOC_FREE(rec);

	/* 3. reopen, volatile record should be gone */

	ok = reopen_db(ctx);
	CHECK_OK(ok, "reopen_db");

	rec = dbwrap_fetch_locked(ctx->db, talloc_tos(), key);
	CHECK_OK(rec != NULL, "dbwrap_fetch_locked()");

	data = dbwrap_record_get_value(rec);
	CHECK_OK(data.dsize == 0, "data.dsize == 0");

	ok = true;

fail:
	TALLOC_FREE(rec);
	return ok;
}

static bool test_persistent_record(struct test_ctx *ctx)
{
	struct db_record *rec = NULL;
	TDB_DATA key = string_term_tdb_data("key");
	TDB_DATA value = string_term_tdb_data("value");
	TDB_DATA data;
	int cmp;
	NTSTATUS status;
	bool ok = false;

	ok = wipe_db(ctx,
		     (struct dbwrap_wipe_flags){
			     .wipe_default=true,
			     .wipe_persistent_backup_db=true,
		     });
	CHECK_OK(ok, "wipe_db");

	/* 1. Store a persistent record */

	rec = dbwrap_fetch_locked(ctx->db, talloc_tos(), key);
	CHECK_OK(rec != NULL, "dbwrap_fetch_locked()");

	status = dbwrap_record_store(rec, value, DBWRAP_STORE_PERSISTENT);
	CHECK_OK(NT_STATUS_IS_OK(status), "dbwrap_record_store()");

	TALLOC_FREE(rec);

	/* 2. Close reopen db, persistent record should be there */

	ok = reopen_db(ctx);
	CHECK_OK(ok, "reopen_db");

	rec = dbwrap_fetch_locked(ctx->db, talloc_tos(), key);
	CHECK_OK(rec != NULL, "dbwrap_fetch_locked()");

	data = dbwrap_record_get_value(rec);
	CHECK_OK(data.dsize != 0, "data.dsize != 0");

	CHECK_OK(value.dsize == data.dsize, "value.dsize == data.dsize");

	cmp = memcmp(value.dptr, data.dptr, data.dsize);
	CHECK_OK(cmp == 0, "Bad record");

	TALLOC_FREE(rec);

	status = dbwrap_delete(ctx->db, key);
	CHECK_OK(NT_STATUS_IS_OK(status), "dbwrap_delete");

	ok = true;

fail:
	TALLOC_FREE(rec);
	return ok;
}

static bool test_persistent_then_volatile(struct test_ctx *ctx)
{
	struct db_record *rec = NULL;
	TDB_DATA key = string_term_tdb_data("key");
	TDB_DATA value1 = string_term_tdb_data("value1");
	TDB_DATA value2 = string_term_tdb_data("value2");
	TDB_DATA data;
	NTSTATUS status;
	bool ok = false;

	ok = wipe_db(ctx,
		     (struct dbwrap_wipe_flags){
			     .wipe_default=true,
			     .wipe_persistent_backup_db=true,
		     });
	CHECK_OK(ok, "wipe_db");

	/* 1. Store a persistent record */

	rec = dbwrap_fetch_locked(ctx->db, talloc_tos(), key);
	CHECK_OK(rec != NULL, "dbwrap_fetch_locked()");

	status = dbwrap_record_store(rec, value1, DBWRAP_STORE_PERSISTENT);
	CHECK_OK(NT_STATUS_IS_OK(status), "dbwrap_record_store()");

	TALLOC_FREE(rec);

	/* 2. Reopen db, store record without DBWRAP_STORE_PERSISTENT */

	ok = reopen_db(ctx);
	CHECK_OK(ok, "reopen_db");

	rec = dbwrap_fetch_locked(ctx->db, talloc_tos(), key);
	CHECK_OK(rec != NULL, "dbwrap_fetch_locked()");

	status = dbwrap_record_store(rec, value2, 0);
	CHECK_OK(NT_STATUS_IS_OK(status), "dbwrap_record_store()");

	TALLOC_FREE(rec);

	/*
	 * 3. reopen db, record should be gone (volatile wiped because of
	 * reopen, persistent deleted because last store didn't use
	 * DBWRAP_STORE_PERSISTENT).
	 */

	ok = reopen_db(ctx);
	CHECK_OK(ok, "reopen_db");

	rec = dbwrap_fetch_locked(ctx->db, talloc_tos(), key);
	CHECK_OK(rec != NULL, "dbwrap_fetch_locked()");

	data = dbwrap_record_get_value(rec);
	CHECK_OK(data.dsize == 0, "data.dsize == 0");

	ok = true;

fail:
	TALLOC_FREE(rec);
	return ok;
}

static bool test_volatile_then_persistent(struct test_ctx *ctx)
{
	struct db_record *rec = NULL;
	TDB_DATA key = string_term_tdb_data("key");
	TDB_DATA value1 = string_term_tdb_data("value1");
	TDB_DATA value2 = string_term_tdb_data("value2");
	TDB_DATA data;
	NTSTATUS status;
	int cmp;
	bool ok = false;

	ok = wipe_db(ctx,
		     (struct dbwrap_wipe_flags){
			     .wipe_default=true,
			     .wipe_persistent_backup_db=true,
		     });
	CHECK_OK(ok, "reopen_db");

	/* 1. Store a volatile record */

	rec = dbwrap_fetch_locked(ctx->db, talloc_tos(), key);
	CHECK_OK(rec != NULL, "dbwrap_fetch_locked()");

	status = dbwrap_record_store(rec, value1, 0);
	CHECK_OK(NT_STATUS_IS_OK(status), "dbwrap_record_store()");

	TALLOC_FREE(rec);

	/* 2. Modify record this time requesting persistency */

	rec = dbwrap_fetch_locked(ctx->db, talloc_tos(), key);
	CHECK_OK(rec != NULL, "dbwrap_fetch_locked()");

	data = dbwrap_record_get_value(rec);
	CHECK_OK(data.dptr != NULL, "empty record");

	cmp = memcmp(value1.dptr, data.dptr, MIN(value1.dsize, data.dsize));
	CHECK_OK(cmp == 0, "Bad record");

	status = dbwrap_record_store(rec, value2, DBWRAP_STORE_PERSISTENT);
	CHECK_OK(NT_STATUS_IS_OK(status), "dbwrap_record_store()");

	TALLOC_FREE(rec);

	/* 3. Close and reopen db, record should be there with value2 */

	ok = reopen_db(ctx);
	CHECK_OK(ok, "reopen_db");

	rec = dbwrap_fetch_locked(ctx->db, talloc_tos(), key);
	CHECK_OK(rec != NULL, "dbwrap_fetch_locked()");

	data = dbwrap_record_get_value(rec);
	CHECK_OK(data.dptr != NULL, "dbwrap_record_get_value");

	cmp = memcmp(value2.dptr, data.dptr, MIN(value2.dsize, data.dsize));
	CHECK_OK(cmp == 0, "Bad record");

	TALLOC_FREE(rec);

	status = dbwrap_delete(ctx->db, key);
	CHECK_OK(NT_STATUS_IS_OK(status), "dbwrap_delete");

	ok = true;

fail:
	TALLOC_FREE(rec);
	return ok;
}

static bool test_delete_persistent_record(struct test_ctx *ctx)
{
	struct db_record *rec = NULL;
	TDB_DATA key = string_term_tdb_data("key");
	TDB_DATA value = string_term_tdb_data("value");
	TDB_DATA data;
	NTSTATUS status;
	int cmp;
	bool ok = false;

	ok = wipe_db(ctx,
		     (struct dbwrap_wipe_flags){
			     .wipe_default=true,
			     .wipe_persistent_backup_db=true,
		     });
	CHECK_OK(ok, "wipe_db");

	/* 1. Store a persistent record */

	rec = dbwrap_fetch_locked(ctx->db, talloc_tos(), key);
	CHECK_OK(rec != NULL, "dbwrap_fetch_locked()");

	status = dbwrap_record_store(rec, value, DBWRAP_STORE_PERSISTENT);
	CHECK_OK(NT_STATUS_IS_OK(status), "dbwrap_record_store()");

	TALLOC_FREE(rec);

	/* 2. Close and reopen db, delete record */

	ok = reopen_db(ctx);
	CHECK_OK(ok, "reopen_db");

	rec = dbwrap_fetch_locked(ctx->db, talloc_tos(), key);
	CHECK_OK(rec != NULL, "dbwrap_fetch_locked()");

	data = dbwrap_record_get_value(rec);

	cmp = memcmp(value.dptr, data.dptr, MIN(value.dsize, data.dsize));
	CHECK_OK(cmp == 0, "Bad record");

	status = dbwrap_record_delete(rec);
	CHECK_OK(NT_STATUS_IS_OK(status), "dbwrap_record_delete()");

	TALLOC_FREE(rec);

	/* 3. reopen db, fetch record, should be gone */

	ok = reopen_db(ctx);
	CHECK_OK(ok, "reopen_db");

	rec = dbwrap_fetch_locked(ctx->db, talloc_tos(), key);
	CHECK_OK(rec != NULL, "dbwrap_fetch_locked()");

	data = dbwrap_record_get_value(rec);
	CHECK_OK(data.dsize == 0, "dbwrap_record_get_value");

	ok = true;

fail:
	TALLOC_FREE(rec);
	return ok;
}

static bool test_delete_persistent_record_no_reopen(struct test_ctx *ctx)
{
	struct db_record *rec = NULL;
	TDB_DATA key = string_term_tdb_data("key");
	TDB_DATA value1 = string_term_tdb_data("value1");
	TDB_DATA data;
	NTSTATUS status;
	bool ok = false;

	ok = wipe_db(ctx,
		     (struct dbwrap_wipe_flags){
			     .wipe_default=true,
			     .wipe_persistent_backup_db=true,
		     });
	CHECK_OK(ok, "wipe_db");

	/* 1. Store a persistent record */

	rec = dbwrap_fetch_locked(ctx->db, talloc_tos(), key);
	CHECK_OK(rec != NULL, "dbwrap_fetch_locked()");

	status = dbwrap_record_store(rec, value1, DBWRAP_STORE_PERSISTENT);
	CHECK_OK(NT_STATUS_IS_OK(status), "dbwrap_record_store()");

	TALLOC_FREE(rec);

	/* 2. Delete record */

	rec = dbwrap_fetch_locked(ctx->db, talloc_tos(), key);
	CHECK_OK(rec != NULL, "dbwrap_fetch_locked()");

	status = dbwrap_record_delete(rec);
	CHECK_OK(NT_STATUS_IS_OK(status), "dbwrap_record_delete()");

	TALLOC_FREE(rec);

	/*
	 * 3. record should be gone
	 */

	/* REMOVE!!!!!! reopen_db() */
	ok = reopen_db(ctx);
	CHECK_OK(ok, "reopen_db");

	rec = dbwrap_fetch_locked(ctx->db, talloc_tos(), key);
	CHECK_OK(rec != NULL, "dbwrap_fetch_locked()");

	data = dbwrap_record_get_value(rec);
	CHECK_OK(data.dsize == 0, "data.dsize == 0");

	ok = true;

fail:
	TALLOC_FREE(rec);
	return ok;
}

static int test_traverse_cb(struct db_record *rec, void *private_data)
{
	return 0;
}


static bool test_traverse(struct test_ctx *ctx)
{
	struct db_record *rec = NULL;
	TDB_DATA key1 = string_term_tdb_data("key1");
	TDB_DATA key2 = string_term_tdb_data("key2");
	TDB_DATA value1 = string_term_tdb_data("value1");
	TDB_DATA value2 = string_term_tdb_data("value2");
	NTSTATUS status;
	int nrecs = 0;
	bool ok = false;

	/* Initital state: Traverse, expect no records */

	status = dbwrap_traverse_read(ctx->db, test_traverse_cb,
				      NULL, &nrecs);
	CHECK_OK(NT_STATUS_IS_OK(status), "dbwrap_traverse_read()");

	ok = (nrecs == 0);
	CHECK_OK(ok, "nrecs == 0");

	/* Initial state: Traverse persistent, expect no record */

	nrecs = 0;
	status = dbwrap_traverse_per_rec_persistent_read(
		ctx->db, test_traverse_cb, NULL, &nrecs);
	CHECK_OK(NT_STATUS_IS_OK(status),
		 "dbwrap_traverse_per_rec_persistent_read()");

	ok = (nrecs == 0);
	CHECK_OK(ok, "nrecs == 0");

	/* 1. Store a volatile record */

	rec = dbwrap_fetch_locked(ctx->db, talloc_tos(), key1);
	CHECK_OK(rec != NULL, "dbwrap_fetch_locked()");

	status = dbwrap_record_store(rec, value1, 0);
	CHECK_OK(NT_STATUS_IS_OK(status), "dbwrap_record_store()");

	TALLOC_FREE(rec);

	/* 2. Store a persistent record */

	rec = dbwrap_fetch_locked(ctx->db, talloc_tos(), key2);
	CHECK_OK(rec != NULL, "dbwrap_fetch_locked()");

	status = dbwrap_record_store(rec, value2, DBWRAP_STORE_PERSISTENT);
	CHECK_OK(NT_STATUS_IS_OK(status), "dbwrap_record_store()");

	TALLOC_FREE(rec);

	/* 3. Traverse, expect two records */

	status = dbwrap_traverse_read(ctx->db, test_traverse_cb,
				      NULL, &nrecs);
	CHECK_OK(NT_STATUS_IS_OK(status), "dbwrap_traverse_read()");

	ok = (nrecs == 2);
	CHECK_OK(ok, "nrecs == 2");

	/* 4. Traverse persistent, expect one record */

	nrecs = 0;
	status = dbwrap_traverse_per_rec_persistent_read(
		ctx->db, test_traverse_cb, NULL, &nrecs);
	CHECK_OK(NT_STATUS_IS_OK(status),
		 "dbwrap_traverse_per_rec_persistent_read()");

	ok = (nrecs == 1);
	CHECK_OK(ok, "nrecs == 1");

	/* 5. cleanup */
	status = dbwrap_delete(ctx->db, key1);
	CHECK_OK(NT_STATUS_IS_OK(status), "dbwrap_delete");
	status = dbwrap_delete(ctx->db, key2);
	CHECK_OK(NT_STATUS_IS_OK(status), "dbwrap_delete");

	/* 6. Traverse, expect no records */

	status = dbwrap_traverse_read(ctx->db, test_traverse_cb,
				      NULL, &nrecs);
	CHECK_OK(NT_STATUS_IS_OK(status), "dbwrap_traverse_read()");

	ok = (nrecs == 0);
	CHECK_OK(ok, "nrecs == 0");

	/* 7. Traverse persistent, expect no record */

	nrecs = 0;
	status = dbwrap_traverse_per_rec_persistent_read(
		ctx->db, test_traverse_cb, NULL, &nrecs);
	CHECK_OK(NT_STATUS_IS_OK(status),
		 "dbwrap_traverse_per_rec_persistent_read()");

	ok = (nrecs == 0);
	CHECK_OK(ok, "nrecs == 0");

fail:
	return ok;
}

bool run_dbwrap_per_rec_persistency(int dummy)
{
	TALLOC_CTX *mem_ctx = NULL;
	struct test_ctx *ctx = NULL;
	bool do_cleanup = false;
	bool ok = false;

	mem_ctx = talloc_init(__func__);
	if (mem_ctx == NULL) {
		return false;
	}

	ctx = talloc_zero(mem_ctx, struct test_ctx);
	if (ctx == NULL) {
		goto fail;
	}

	*ctx = (struct test_ctx) {
		.dbname = "test_per_rec_persistency.tdb",
		.pdbname = "test_per_rec_persistency_persistent.tdb",
		.watched = false,
	};

	ctx->ev = samba_tevent_context_init(ctx);
	if (ctx->ev == NULL) {
		fprintf(stderr, "server_event_context() failed\n");
		goto fail;
	}
	ctx->msg = messaging_init(ctx->ev, ctx->ev);
	if (ctx->msg == NULL) {
		fprintf(stderr, "server_messaging_context() failed\n");
		goto fail;
	}

do_tests:
	ok = open_db(ctx);
	LOG_OK(ok, "open_db");

	do_cleanup = true;

	ok = test_volatile_record(ctx);
	LOG_OK(ok, "test_volatile_record");

	ok = test_traverse(ctx);
	LOG_OK(ok, "test_traverse");

	ok = test_persistent_record(ctx);
	LOG_OK(ok, "test_persistent_record");

	ok = test_traverse(ctx);
	LOG_OK(ok, "test_traverse");

	ok = test_persistent_then_volatile(ctx);
	LOG_OK(ok, "test_persistent_then_volatile");

	ok = test_traverse(ctx);
	LOG_OK(ok, "test_traverse");

	ok = test_volatile_then_persistent(ctx);
	LOG_OK(ok, "test_volatile_then_persistent");

	ok = test_traverse(ctx);
	LOG_OK(ok, "test_traverse");

	ok = test_delete_persistent_record(ctx);
	LOG_OK(ok, "test_delete_persistent_record");

	ok = test_traverse(ctx);
	LOG_OK(ok, "test_traverse");

	ok = test_delete_persistent_record_no_reopen(ctx);
	LOG_OK(ok, "test_delete_persistent_record_no_reopen");

	ok = test_traverse(ctx);
	LOG_OK(ok, "test_traverse");

	if (!ctx->watched) {
		ctx->watched = true;
		goto do_tests;
	}

	ok = true;

fail:
	if (!lp_clustering()) {
		unlink(ctx->dbname);
		unlink(ctx->pdbname);
	} else if (do_cleanup) {
		wipe_db(ctx,
			(struct dbwrap_wipe_flags){
				.wipe_default=true,
				.wipe_persistent_backup_db=true,
			});
	}
	TALLOC_FREE(mem_ctx);
	return ok;
}
