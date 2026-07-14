/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2026

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
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_ctdb.h"
#include "lib/util/util_tdb.h"
#include "librpc/gen_ndr/ndr_cluster_level.h"
#include "ctdbd_conn.h"
#include "cluster_support.h"
#include "cluster_level_db.h"

/*
 * Note msg_ctx is optional, passing NULL means
 * no transactions are possible.
 */
static struct db_context *cluster_level_db_open(
					TALLOC_CTX *mem_ctx,
					struct ctdbd_connection *ctdb_conn,
					struct messaging_context *msg_ctx)
{
	bool allow_transactions = msg_ctx != NULL;
	struct db_context *db = NULL;
	static bool busy;

	SMB_ASSERT(!busy);

	busy = true;
	db= db_open_ctdb_ex(mem_ctx,
			    NULL,  /* ev_ctx */
			    msg_ctx,
			    ctdb_conn,
			    true,  /* persistent */
			    allow_transactions,
			    CLUSTER_LEVEL_TDB_NAME,
			    0,     /* hash_size */
			    TDB_DEFAULT,
			    O_RDWR | O_CREAT,
			    0600,
			    DBWRAP_LOCK_ORDER_1,
			    DBWRAP_FLAG_NONE);
	busy = false;

	return db;
}

struct cluster_level_db_fetch_active_state {
	struct cluster_level_globalB globalB;
	enum ndr_err_code ndr_err;
	size_t consumed;
};

static void cluster_level_db_fetch_active_parser(TDB_DATA key,
						 TDB_DATA data,
						 void *private_data)
{
	struct cluster_level_db_fetch_active_state *state =
		(struct cluster_level_db_fetch_active_state *)private_data;

	state->ndr_err = ndr_pull_struct_blob_noalloc(
		data.dptr,
		data.dsize,
		&state->globalB,
		(ndr_pull_flags_fn_t)ndr_pull_cluster_level_globalB,
		&state->consumed);
}

/*
 * Get the cluster-wide active functional level from the database
 */
static NTSTATUS cluster_level_db_fetch_active(
				struct db_context *db,
				struct cluster_level_active *_level)
{
	const char *key_string = CLUSTER_LEVEL_GLOBAL_KEY;
	TDB_DATA key = string_tdb_data(key_string);
	struct cluster_level_db_fetch_active_state state = {};
	const struct cluster_level_active *level = NULL;
	NTSTATUS status;

	status = dbwrap_parse_record(db,
				     key,
				     cluster_level_db_fetch_active_parser,
				     &state);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		DBG_DEBUG("dbwrap_parse_record(%s) - %s\n",
			  key_string,
			  nt_errstr(status));
		return status;
	}
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("dbwrap_parse_record(%s) - %s\n",
			key_string,
			nt_errstr(status));
		return status;
	}

	if (!NDR_ERR_CODE_IS_SUCCESS(state.ndr_err)) {
		status = ndr_map_error2ntstatus(state.ndr_err);
		DBG_ERR("ndr_pull_cluster_level_globalB version=%"PRIu32" "
			"- %s - %s\n",
			state.globalB.version,
			ndr_errstr(state.ndr_err),
			nt_errstr(status));
		return status;
	}

	switch (state.globalB.version) {
	case CLUSTER_LEVEL_DB_VERSION_1:
		level = &state.globalB.info.info1.active_level;
		break;
	}
	if (level == NULL) {
		status = NT_STATUS_REVISION_MISMATCH;
		DBG_ERR("version=%"PRIu32" %s\n",
			state.globalB.version,
			nt_errstr(status));
		NDR_PRINT_DEBUG(cluster_level_globalB, &state.globalB);
		return status;
	}

	if (DEBUGLVL(DBGLVL_INFO)) {
		NDR_PRINT_DEBUG(cluster_level_globalB, &state.globalB);
	}

	*_level = *level;
	return NT_STATUS_OK;
}

NTSTATUS cluster_level_db_check(struct ctdbd_connection *ctdb_conn)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const struct cluster_level_ranges *supported_ranges =
		cluster_level_supported_ranges();
	struct cluster_level_active active_level = {};
	struct db_context *db = NULL;
	NTSTATUS status;

	/*
	 * We only need temporary read only access, so we pass msg_ctx=NULL
	 */
	db = cluster_level_db_open(frame,
				   ctdb_conn,
				   NULL);  /* msg_ctx */
	if (db == NULL) {
		DBG_ERR("cluster_level_db_open() failed\n");
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	status = cluster_level_db_fetch_active(db, &active_level);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		/*
		 * This is a fresh cluster or a cluster
		 * upgraded from before we introduced
		 * the cluster functional levels.
		 *
		 * As our db context doesn't allow
		 * transactions, it's the callers job to
		 * initialize the database for the first
		 * time.
		 */
		DBG_WARNING("active_level not found yet\n");
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("cluster_level_db_fetch_active() %s\n",
			nt_errstr(status));
		TALLOC_FREE(frame);
		return status;
	}

	status = cluster_level_compatible(supported_ranges,
					  &active_level);
	if (!NT_STATUS_IS_OK(status)) {
		uint32_t i;

		for (i = 0; i < supported_ranges->num_ranges; i++) {
			const struct cluster_level_range *range =
				&supported_ranges->ranges[i];

			DBG_ERR("supported_range: "
				"%"PRIu32".%"PRIu32" -> %"PRIu32".%"PRIu32"\n",
				range->major, range->minor_min,
				range->major, range->minor_max);
		}

		DBG_ERR("active_level: %"PRIu32".%"PRIu32" - %s\n",
			active_level.major, active_level.minor,
			nt_errstr(status));
		TALLOC_FREE(frame);
		return status;
	}

	DBG_DEBUG("active_level: %"PRIu32".%"PRIu32" - %s\n",
		  active_level.major, active_level.minor,
		  nt_errstr(status));

	ctdbd_conn_set_cluster_level(ctdb_conn, &active_level);
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}
