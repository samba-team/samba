/*
 * Unix SMB/CIFS implementation.
 * Tests for Cluster Functional Level (CFL) infrastructure.
 *
 * Copyright (C) Avan Thakkar 2026
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

#include "includes.h"
#include "torture/proto.h"
#include "librpc/gen_ndr/ndr_cluster_level.h"
#include "lib/cluster_support.h"
#include "lib/cluster_level_db.h"
#include "lib/dbwrap/dbwrap.h"
#include "lib/dbwrap/dbwrap_open.h"
#include "lib/util/util_tdb.h"
#include "messages.h"
#include "lib/messages_ctdb.h"
#include "lib/global_contexts.h"
#include "ctdbd_conn.h"

#ifdef CLUSTER_SUPPORT

/*
 * Assumes a fresh cluster where no explicit upgrade has been performed,
 * so the active level is expected to be the highest level supported by
 * this build.
 */
bool run_cluster_level_db(int dummy)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_context *msg_ctx = NULL;
	struct ctdbd_connection *ctdb_conn = NULL;
	struct db_context *db = NULL;
	TDB_DATA key = {};
	TDB_DATA data = {.dsize = 0};
	struct cluster_level_globalB globalB = {};
	const struct cluster_level_ranges *ranges = NULL;
	const struct cluster_level_range *highest = NULL;
	const struct cluster_level_active *global_level = NULL;
	const struct cluster_level_active *conn_level = NULL;
	enum ndr_err_code ndr_err;
	NTSTATUS status;
	bool ret = false;

	if (!lp_clustering()) {
		fprintf(stderr,
			"FAIL: This test requires a clustered smb.conf "
			"(clustering = yes).\n");
		goto done;
	}

	msg_ctx = global_messaging_context();
	if (msg_ctx == NULL) {
		fprintf(stderr,
			"FAIL: global_messaging_context() returned NULL\n");
		goto done;
	}

	if (!cluster_level_global_is_valid()) {
		fprintf(stderr,
			"FAIL: cluster_level_global_is_valid() false after "
			"init\n");
		goto done;
	}

	/* CFL must be active at least at 1.0 */
	if (!CLUSTER_LEVEL_ACTIVE(1, 0)) {
		fprintf(stderr,
			"FAIL: CLUSTER_LEVEL_ACTIVE(1, 0) false after "
			"init\n");
		goto done;
	}

	ctdb_conn = messaging_ctdb_connection();
	if (ctdb_conn == NULL) {
		fprintf(stderr,
			"FAIL: messaging_ctdb_connection() returned NULL\n");
		goto done;
	}

	db = db_open(frame,
		     CLUSTER_LEVEL_TDB_NAME,
		     0,
		     TDB_DEFAULT,
		     O_RDONLY,
		     0,
		     DBWRAP_LOCK_ORDER_1,
		     DBWRAP_FLAG_NONE);
	if (db == NULL) {
		fprintf(stderr,
			"FAIL: db_open(%s) failed\n",
			CLUSTER_LEVEL_TDB_NAME);
		goto done;
	}

	key = string_tdb_data(CLUSTER_LEVEL_GLOBAL_KEY);
	status = dbwrap_fetch(db, frame, key, &data);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr,
			"FAIL: dbwrap_fetch(CLUSTER_LEVEL_GLOBAL) failed: "
			"%s\n",
			nt_errstr(status));
		goto done;
	}

	if (data.dsize == 0) {
		fprintf(stderr,
			"FAIL: CLUSTER_LEVEL_GLOBAL record is empty\n");
		goto done;
	}

	{
		DATA_BLOB blob = {
			.data = data.dptr,
			.length = data.dsize,
		};
		ndr_err = ndr_pull_struct_blob_all_noalloc(
			&blob,
			&globalB,
			(ndr_pull_flags_fn_t)ndr_pull_cluster_level_globalB);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			fprintf(stderr,
				"FAIL: NDR parse of CLUSTER_LEVEL_GLOBAL "
				"failed: %s\n",
				ndr_errstr(ndr_err));
			goto done;
		}
	}

	if (globalB.version != CLUSTER_LEVEL_DB_VERSION_1) {
		fprintf(stderr,
			"FAIL: unexpected DB version %u (want %u)\n",
			globalB.version,
			CLUSTER_LEVEL_DB_VERSION_1);
		goto done;
	}

	ranges = cluster_level_supported_ranges();
	highest = &ranges->ranges[0];

	if (globalB.info.info1.active_level.major != highest->major ||
	    globalB.info.info1.active_level.minor != highest->minor_max)
	{
		fprintf(stderr,
			"FAIL: expected level %u.%u in DB, got %u.%u\n",
			highest->major,
			highest->minor_max,
			globalB.info.info1.active_level.major,
			globalB.info.info1.active_level.minor);
		goto done;
	}

	global_level = cluster_level_global_active();
	if (global_level == NULL) {
		fprintf(stderr,
			"FAIL: cluster_level_global_active() returned NULL\n");
		goto done;
	}
	if (global_level->major != globalB.info.info1.active_level.major ||
	    global_level->minor != globalB.info.info1.active_level.minor)
	{
		fprintf(stderr,
			"FAIL: global cached level %u.%u does not match "
			"DB level %u.%u\n",
			global_level->major,
			global_level->minor,
			globalB.info.info1.active_level.major,
			globalB.info.info1.active_level.minor);
		goto done;
	}

	conn_level = ctdbd_conn_get_cluster_level(ctdb_conn);
	if (conn_level == NULL) {
		fprintf(stderr,
			"FAIL: ctdbd_conn_get_cluster_level() returned "
			"NULL\n");
		goto done;
	}
	if (conn_level->major != globalB.info.info1.active_level.major ||
	    conn_level->minor != globalB.info.info1.active_level.minor)
	{
		fprintf(stderr,
			"FAIL: connection cached level %u.%u does not match "
			"DB level %u.%u\n",
			conn_level->major,
			conn_level->minor,
			globalB.info.info1.active_level.major,
			globalB.info.info1.active_level.minor);
		goto done;
	}

	status = cluster_level_db_check(ctdb_conn);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr,
			"FAIL: cluster_level_db_check() failed: %s\n",
			nt_errstr(status));
		goto done;
	}

	printf("OK: CLUSTER_LEVEL_GLOBAL on disk = %u.%u (DB version %u, blob "
	       "size %zu)\n",
	       globalB.info.info1.active_level.major,
	       globalB.info.info1.active_level.minor,
	       globalB.version,
	       data.dsize);

	ret = true;
done:
	TALLOC_FREE(frame);
	return ret;
}

#endif /* CLUSTER_SUPPORT */
