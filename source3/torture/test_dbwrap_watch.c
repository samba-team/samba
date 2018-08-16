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

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		fprintf(stderr, "tevent_context_init failed\n");
		goto fail;
	}
	msg = messaging_init(ev, ev);
	if (msg == NULL) {
		fprintf(stderr, "messaging_init failed\n");
		goto fail;
	}
	backend = db_open(msg, "test_watch.tdb", 0, TDB_CLEAR_IF_FIRST,
			  O_CREAT|O_RDWR, 0644, DBWRAP_LOCK_ORDER_1,
			  DBWRAP_FLAG_NONE);
	if (backend == NULL) {
		fprintf(stderr, "db_open failed: %s\n", strerror(errno));
		goto fail;
	}

	db = db_open_watched(ev, &backend, msg);

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

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		fprintf(stderr, "tevent_context_init failed\n");
		goto fail;
	}
	msg = messaging_init(ev, ev);
	if (msg == NULL) {
		fprintf(stderr, "messaging_init failed\n");
		goto fail;
	}
	backend = db_open(msg, "test_watch.tdb", 0, TDB_CLEAR_IF_FIRST,
			  O_CREAT|O_RDWR, 0644, DBWRAP_LOCK_ORDER_1,
			  DBWRAP_FLAG_NONE);
	if (backend == NULL) {
		fprintf(stderr, "db_open failed: %s\n", strerror(errno));
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

	db = db_open_watched(ev, &backend, msg);
	if (db == NULL) {
		fprintf(stderr, "db_open_watched failed\n");
		goto fail;
	}
	backend = NULL;		/* open_watch talloc_moves backend */

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
