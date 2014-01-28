/*
 * Unix SMB/CIFS implementation.
 * Test dbwrap_ctdb API
 * Copyright (C) Volker Lendecke 2012
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
#include "lib/dbwrap/dbwrap_ctdb.h"

bool run_local_dbwrap_ctdb(int dummy)
{
	struct db_context *db;
	int res;
	bool ret = false;
	NTSTATUS status;
	uint32_t val;

	db = db_open_ctdb(talloc_tos(), "torture.tdb", 0, TDB_DEFAULT,
			  O_RDWR, 0755, DBWRAP_LOCK_ORDER_1, DBWRAP_FLAG_NONE);
	if (db == NULL) {
		perror("db_open_ctdb failed");
		goto fail;
	}

	res = dbwrap_transaction_start(db);
	if (res != 0) {
		fprintf(stderr, "dbwrap_transaction_start failed");
		goto fail;
	}
	res = dbwrap_transaction_cancel(db);
	if (res != 0) {
		fprintf(stderr, "dbwrap_transaction_cancel failed");
		goto fail;
	}

	res = dbwrap_transaction_start(db);
	if (res != 0) {
		fprintf(stderr, "dbwrap_transaction_start failed");
		goto fail;
	}

	status = dbwrap_store_uint32_bystring(db, "foo", 1);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "store_uint32 failed: %s\n",
			nt_errstr(status));
		goto fail;
	}
	status = dbwrap_fetch_uint32_bystring(db, "foo", &val);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "fetch_uint32 failed: %s\n",
			nt_errstr(status));
		goto fail;
	}
	if (val != 1) {
		fprintf(stderr, "fetch_uint32 gave %u, expected 1",
			(unsigned)val);
		goto fail;
	}

	status = dbwrap_store_uint32_bystring(db, "bar", 5);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "store_uint32 failed: %s\n",
			nt_errstr(status));
		goto fail;
	}
	status = dbwrap_fetch_uint32_bystring(db, "bar", &val);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "fetch_uint32 failed: %s\n",
			nt_errstr(status));
		goto fail;
	}
	if (val != 5) {
		fprintf(stderr, "fetch_uint32 gave %u, expected 5",
			(unsigned)val);
		goto fail;
	}

	status = dbwrap_store_uint32_bystring(db, "foo", 2);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "store_uint32 failed: %s\n",
			nt_errstr(status));
		goto fail;
	}
	status = dbwrap_fetch_uint32_bystring(db, "foo", &val);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "fetch_uint32 failed: %s\n",
			nt_errstr(status));
		goto fail;
	}
	if (val != 2) {
		fprintf(stderr, "fetch_uint32 gave %u, expected 2",
			(unsigned)val);
		goto fail;
	}

	res = dbwrap_transaction_commit(db);
	if (res != 0) {
		fprintf(stderr, "dbwrap_transaction_commit failed");
		goto fail;
	}

	/*
	 * check that the values have reached the disk
	 */
	status = dbwrap_fetch_uint32_bystring(db, "foo", &val);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "fetch_uint32 failed: %s\n",
			nt_errstr(status));
		goto fail;
	}
	if (val != 2) {
		fprintf(stderr, "fetch_uint32 gave %u, expected 1",
			(unsigned)val);
		goto fail;
	}

	status = dbwrap_fetch_uint32_bystring(db, "bar", &val);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "fetch_uint32 failed: %s\n",
			nt_errstr(status));
		goto fail;
	}
	if (val != 5) {
		fprintf(stderr, "fetch_uint32 gave %u, expected 1",
			(unsigned)val);
		goto fail;
	}

	ret = true;
fail:
	TALLOC_FREE(db);
	return ret;
}
