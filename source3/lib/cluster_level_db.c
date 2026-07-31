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
#include "messages.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_ctdb.h"
#include "lib/util/util_tdb.h"
#include "librpc/gen_ndr/ndr_cluster_level.h"
#include "ctdbd_conn.h"
#include "cluster_support.h"
#include "cluster_level_db.h"
#include "ctdb/protocol/protocol.h"

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

/*
 * Store the cluster-wide active functional level.
 */
static NTSTATUS cluster_level_db_store_active(
				struct db_context *db,
				enum cluster_level_db_version version,
				struct timeval now,
				const struct cluster_level_active *level)
{
	const char *key_string = CLUSTER_LEVEL_GLOBAL_KEY;
	TDB_DATA key = string_tdb_data(key_string);
	struct cluster_level_globalB globalB = {
		.version = version,
	};
#define CLUSTER_LEVEL_DB_VERSION_1_REC_SIZE 44
	uint8_t fixed_buf[CLUSTER_LEVEL_DB_VERSION_1_REC_SIZE] = {};
	DATA_BLOB fixed_blob = {
		.data = fixed_buf,
		.length = 0,
	};
	TDB_DATA data = {};
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	if (!cluster_level_is_valid(level)) {
		return NT_STATUS_INVALID_LEVEL;
	}

	switch (globalB.version) {
	case CLUSTER_LEVEL_DB_VERSION_1:
		globalB.info.info1.update_time = now;
		globalB.info.info1.active_level = *level;
		fixed_blob.length = CLUSTER_LEVEL_DB_VERSION_1_REC_SIZE;
		break;
	}
	SMB_ASSERT(fixed_blob.length <= ARRAY_SIZE(fixed_buf));

	if (fixed_blob.length == 0) {
		status = NT_STATUS_REVISION_MISMATCH;
		DBG_ERR("version=%"PRIu32" %s\n",
			globalB.version,
			nt_errstr(status));
		return status;
	}

	ndr_err = ndr_push_struct_into_fixed_blob(
			&fixed_blob, &globalB,
			(ndr_push_flags_fn_t)ndr_push_cluster_level_globalB);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DBG_ERR("ndr_push_cluster_level_globalB version=%"PRIu32" - %s -%s\n",
			globalB.version,
			ndr_errstr(ndr_err),
			nt_errstr(status));
		NDR_PRINT_DEBUG(cluster_level_globalB, &globalB);
		return status;
	}

	if (DEBUGLVL(DBGLVL_INFO)) {
		NDR_PRINT_DEBUG(cluster_level_globalB, &globalB);
	}

	data = (TDB_DATA) {
		.dptr = fixed_blob.data,
		.dsize = fixed_blob.length,
	};

	status = dbwrap_store(db, key, data, TDB_REPLACE);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("dbwrap_store(%s, size=%zu) - %s\n",
			key_string, fixed_blob.length,
			nt_errstr(status));
		return status;
	}

	DBG_DEBUG("dbwrap_store(%s, size=%zu) - %s\n",
		  key_string, fixed_blob.length,
		  nt_errstr(status));
	return NT_STATUS_OK;
}

struct cluster_level_db_node_key {
	char string[
		sizeof(CLUSTER_LEVEL_NODE_KEY_PREFIX)+sizeof("0x12345678")
	];
	TDB_DATA key;
};

static void cluster_level_db_node_key_set(struct cluster_level_db_node_key *key,
					  uint32_t vnn)
{
	int ret;

	ret = snprintf(key->string, sizeof(key->string),
		       CLUSTER_LEVEL_NODE_KEY_FMT,
		       vnn);
	SMB_ASSERT(ret > 0);
	SMB_ASSERT(ret < sizeof(key->string));
	key->key = string_tdb_data(key->string);
}

struct cluster_level_db_fetch_ranges_state {
	TALLOC_CTX *mem_ctx;
	struct cluster_level_nodeB nodeB;
	enum ndr_err_code ndr_err;
};

static void cluster_level_db_fetch_ranges_parser(TDB_DATA key,
						 TDB_DATA data,
						 void *private_data)
{
	struct cluster_level_db_fetch_ranges_state *state =
		(struct cluster_level_db_fetch_ranges_state *)private_data;
	DATA_BLOB blob = {
		.data = data.dptr,
		.length = data.dsize,
	};

	state->ndr_err = ndr_pull_struct_blob(
			&blob, state->mem_ctx, &state->nodeB,
			(ndr_pull_flags_fn_t)ndr_pull_cluster_level_nodeB);
}

/*
 * Fetch the per node supported level ranges.
 */
static NTSTATUS cluster_level_db_fetch_ranges(
				struct db_context *db,
				uint32_t ctdbd_vnn,
				TALLOC_CTX *mem_ctx,
				struct timeval *_update_time,
				struct timeval *_ctdbd_start_time,
				pid_t *_ctdbd_pid,
				struct cluster_level_ranges **_ranges)
{
	struct cluster_level_db_node_key nkey = {};
	struct cluster_level_db_fetch_ranges_state state = {};
	struct timeval update_time;
	struct timeval ctdbd_start_time;
	uint32_t ctdbd_pid;
	struct cluster_level_ranges *ranges = NULL;
	bool valid_level = false;
	NTSTATUS status;

	cluster_level_db_node_key_set(&nkey, ctdbd_vnn);

	/*
	 * Currently only the ranges array is allocated,
	 * so we use cluster_level_ranges as mem_ctx
	 * for ndr_pull_cluster_level_nodeB
	 */
	ranges = talloc_zero(mem_ctx, struct cluster_level_ranges);
	if (ranges == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state.mem_ctx = ranges;

	status = dbwrap_parse_record(db,
				     nkey.key,
				     cluster_level_db_fetch_ranges_parser,
				     &state);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		DBG_DEBUG("dbwrap_parse_record(%s) - %s\n",
			  nkey.string,
			  nt_errstr(status));
		TALLOC_FREE(ranges);
		return status;
	}
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("dbwrap_parse_record(%s) - %s\n",
			nkey.string,
			nt_errstr(status));
		TALLOC_FREE(ranges);
		return status;
	}

	if (!NDR_ERR_CODE_IS_SUCCESS(state.ndr_err)) {
		status = ndr_map_error2ntstatus(state.ndr_err);
		DBG_ERR("ndr_pull_cluster_level_nodeB version=%"PRIu32" "
			"- vnn=%"PRIu32" - %s - %s\n",
			state.nodeB.version,
			ctdbd_vnn,
			ndr_errstr(state.ndr_err),
			nt_errstr(status));
		TALLOC_FREE(ranges);
		return status;
	}

	switch (state.nodeB.version) {
	case CLUSTER_LEVEL_DB_VERSION_1:
		update_time = state.nodeB.info.info1.update_time;
		ctdbd_start_time = state.nodeB.info.info1.ctdbd_start_time;
		ctdbd_pid = state.nodeB.info.info1.ctdbd_pid;
		*ranges = state.nodeB.info.info1.supported_ranges;
		valid_level = true;
		break;
	}

	if (!valid_level) {
		status = NT_STATUS_REVISION_MISMATCH;
		DBG_ERR("version=%"PRIu32" vnn=%"PRIu32" - %s\n",
			state.nodeB.version,
			ctdbd_vnn,
			nt_errstr(status));
		NDR_PRINT_DEBUG(cluster_level_nodeB, &state.nodeB);
		TALLOC_FREE(ranges);
		return status;
	}

	if (DEBUGLVL(DBGLVL_DEBUG)) {
		DBG_DEBUG("version=%"PRIu32" vnn=%"PRIu32"\n",
			state.nodeB.version,
			ctdbd_vnn);
		NDR_PRINT_DEBUG(cluster_level_nodeB, &state.nodeB);
	}

	*_update_time = update_time;
	*_ctdbd_start_time = ctdbd_start_time;
	*_ctdbd_pid = ctdbd_pid;
	*_ranges = ranges;
	return NT_STATUS_OK;
}

/*
 * Store the per node supported level ranges.
 */
static NTSTATUS cluster_level_db_store_ranges(
				struct db_context *db,
				enum cluster_level_db_version version,
				uint32_t ctdbd_vnn,
				struct timeval update_time,
				struct timeval ctdbd_start_time,
				pid_t ctdbd_pid,
				const struct cluster_level_ranges *ranges)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct cluster_level_db_node_key nkey = {};
	struct cluster_level_nodeB nodeB = {
		.version = version,
	};
	DATA_BLOB blob = {};
	TDB_DATA data;
	enum ndr_err_code ndr_err;
	NTSTATUS status;
	bool store = false;

	cluster_level_db_node_key_set(&nkey, ctdbd_vnn);

	switch (nodeB.version) {
	case CLUSTER_LEVEL_DB_VERSION_1:
		nodeB.info.info1.update_time = update_time;
		nodeB.info.info1.ctdbd_pid = ctdbd_pid;
		nodeB.info.info1.ctdbd_start_time = ctdbd_start_time;
		nodeB.info.info1.supported_ranges = *ranges;
		store = true;
		break;
	}

	if (!store) {
		status = NT_STATUS_REVISION_MISMATCH;
		DBG_ERR("version=%"PRIu32" %s\n",
			nodeB.version,
			nt_errstr(status));
		TALLOC_FREE(frame);
		return status;
	}

	ndr_err = ndr_push_struct_blob(&blob, frame, &nodeB,
			(ndr_push_flags_fn_t)ndr_push_cluster_level_nodeB);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DBG_ERR("ndr_push_cluster_level_nodeB version=%"PRIu32" "
			"- %s - %s\n",
			nodeB.version,
			ndr_errstr(ndr_err),
			nt_errstr(status));
		NDR_PRINT_DEBUG(cluster_level_nodeB, &nodeB);
		TALLOC_FREE(frame);
		return status;
	}

	if (DEBUGLVL(DBGLVL_INFO)) {
		NDR_PRINT_DEBUG(cluster_level_nodeB, &nodeB);
	}

	data = (TDB_DATA) {
		.dptr = blob.data,
		.dsize = blob.length,
	};

	status = dbwrap_store(db, nkey.key, data, TDB_REPLACE);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("dbwrap_store(%s, size=%zu) - %s\n",
			nkey.string, blob.length,
			nt_errstr(status));
		TALLOC_FREE(frame);
		return status;
	}

	DBG_DEBUG("dbwrap_store(%s, size=%zu) - %s\n",
		  nkey.string, blob.length,
		  nt_errstr(status));
	TALLOC_FREE(frame);
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

NTSTATUS cluster_level_db_check_or_update(struct ctdbd_connection *ctdb_conn,
					  struct messaging_context *msg_ctx)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const struct cluster_level_ranges *supported_ranges =
		cluster_level_supported_ranges();
	struct cluster_level_active active_level = {};
	bool store_active_level = false;
	bool store_supported_ranges = false;
	enum cluster_level_db_version version = CLUSTER_LEVEL_DB_VERSION_1;
	struct db_context *db = NULL;
	struct timeval now = timeval_current();
	uint32_t ctdb_vnn = UINT32_MAX;
	pid_t ctdb_pid = -1;
	struct timeval ctdb_start_time = {};
	struct timeval old_update_time = {};
	struct timeval old_ctdb_start_time = {};
	pid_t old_ctdb_pid = -1;
	struct cluster_level_ranges *old_ranges = NULL;
	NTSTATUS status;
	int ret;

	SMB_ASSERT(msg_ctx != NULL);

	db = cluster_level_db_open(frame,
				   ctdb_conn,
				   msg_ctx);
	if (db == NULL) {
		DBG_ERR("cluster_level_db_open() failed\n");
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	ret = dbwrap_transaction_start(db);
	if (ret != 0) {
		DBG_ERR("dbwrap_transaction_start() failed\n");
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	ctdb_vnn = ctdbd_vnn(ctdb_conn);
	ctdb_pid = ctdbd_pid(ctdb_conn);
	ctdb_start_time = ctdbd_start_time(ctdb_conn);

	status = cluster_level_db_fetch_active(db, &active_level);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		/*
		 * This is a fresh cluster or a cluster
		 * upgraded from before we introduced
		 * the cluster functional levels.
		 *
		 * We're under a transaction so we are
		 * the first one, so store our highest
		 * supported level.
		 */
		DBG_WARNING("active_level not found yet\n");
		active_level = (struct cluster_level_active) {
			.major = supported_ranges->ranges[0].major,
			.minor = supported_ranges->ranges[0].minor_max,
		};
		store_active_level = true;
	} else if (!NT_STATUS_IS_OK(status)) {
		dbwrap_transaction_cancel(db);
		DBG_ERR("cluster_level_db_fetch_active() %s\n",
			nt_errstr(status));
		TALLOC_FREE(frame);
		return status;
	}

	/*
	 * If needed adjust version based on active_level!
	 */
	version = CLUSTER_LEVEL_DB_VERSION_1;

	if (store_active_level) {
		status = cluster_level_db_store_active(db,
						       version,
						       now,
						       &active_level);
		if (!NT_STATUS_IS_OK(status)) {
			dbwrap_transaction_cancel(db);
			DBG_ERR("cluster_level_db_store_active() %s\n",
				nt_errstr(status));
			TALLOC_FREE(frame);
			return status;
		}
	}

	status = cluster_level_compatible(supported_ranges,
					  &active_level);
	if (!NT_STATUS_IS_OK(status)) {
		uint32_t i;

		dbwrap_transaction_cancel(db);

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

	status = cluster_level_db_fetch_ranges(db,
					       ctdb_vnn,
					       frame,
					       &old_update_time,
					       &old_ctdb_start_time,
					       &old_ctdb_pid,
					       &old_ranges);
	if (NT_STATUS_IS_OK(status)) {
		if (timeval_compare(&old_ctdb_start_time, &ctdb_start_time) != 0) {
			store_supported_ranges = true;
		}
		if (!store_supported_ranges && old_ctdb_pid != ctdb_pid) {
			store_supported_ranges = true;
		}
		if (!store_supported_ranges &&
		    old_ranges->num_ranges != supported_ranges->num_ranges)
		{
			store_supported_ranges = true;
		}
		if (!store_supported_ranges) {
			uint32_t ri;

			for (ri = 0; ri < old_ranges->num_ranges; ri++) {
				const struct cluster_level_range *or =
					&old_ranges->ranges[ri];
				const struct cluster_level_range *sr =
					&supported_ranges->ranges[ri];

				if (or->major != sr->major) {
					store_supported_ranges = true;
					break;
				}
				if (or->minor_min != sr->minor_min) {
					store_supported_ranges = true;
					break;
				}
				if (or->minor_max != sr->minor_max) {
					store_supported_ranges = true;
					break;
				}
			}
		}

		if (store_supported_ranges) {
			DBG_INFO("stored supported ranges outdated\n");
		} else {
			DBG_DEBUG("stored supported ranges up to date\n");
		}
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		/*
		 * This is a fresh cluster or a cluster
		 * upgraded from before we introduced
		 * the cluster functional levels.
		 */
		DBG_INFO("supported_ranges not found yet\n");
		store_supported_ranges = true;
	} else if (!NT_STATUS_IS_OK(status)) {
		dbwrap_transaction_cancel(db);
		DBG_ERR("cluster_level_db_fetch_ranges() %s\n",
			nt_errstr(status));
		TALLOC_FREE(frame);
		return status;
	}

	if (store_supported_ranges) {
		status = cluster_level_db_store_ranges(db,
						       version,
						       ctdb_vnn,
						       now,
						       ctdb_start_time,
						       ctdb_pid,
						       supported_ranges);
		if (!NT_STATUS_IS_OK(status)) {
			dbwrap_transaction_cancel(db);
			DBG_ERR("cluster_level_db_store_ranges() %s\n",
				nt_errstr(status));
			TALLOC_FREE(frame);
			return status;
		}
	} else if (store_active_level) {
		/*
		 * Some other local process already stored the current ranges.
		 * That implies the global level has to there too, if it isn't
		 * somethings terribly wrong.
		 */
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		dbwrap_transaction_cancel(db);
		DBG_ERR("cluster_level_db_store_ranges() "
			"first, but already committed - %s\n",
			nt_errstr(status));
		TALLOC_FREE(frame);
		return status;
	} else {
		/*
		 * Just set a useful error for the debug
		 * message below
		 */
		status = NT_STATUS_ALREADY_COMMITTED;
	}

	/*
	 * If we didn't store anything
	 * dbwrap_transaction_commit() is similar
	 * to dbwrap_transaction_cancel().
	 */
	ret = dbwrap_transaction_commit(db);
	if (ret != 0) {
		DBG_ERR("dbwrap_transaction_commit() failed\n");
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	DBG_DEBUG("supported ranges: store %s\n", nt_errstr(status));

	ctdbd_conn_set_cluster_level(ctdb_conn, &active_level);
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

struct cluster_level_db_nodes_foreach_state {
	struct db_context *db;
	cluster_level_db_nodes_foreach_cb_t cb;
	void *cb_private;
	NTSTATUS error;
};

static int cluster_level_db_nodes_foreach_ctdbd_cb(
				uint32_t total_nodes_count,
				const struct ctdb_node_and_flags *nf,
				void *private_data)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct cluster_level_db_nodes_foreach_state *state =
		(struct cluster_level_db_nodes_foreach_state *)private_data;
	struct cluster_level_ranges *n_ranges = NULL;
	struct cluster_level_ranges zero_ranges = { .num_ranges = 0, };
	struct cluster_level_db_nodes_foreach_node node = {
		.nf = nf,
	};
	NTSTATUS status;

	status = cluster_level_db_fetch_ranges(state->db,
					       nf->pnn,
					       frame,
					       &node.update_time,
					       &node.update_ctdbd.start_time,
					       &node.update_ctdbd.pid,
					       &n_ranges);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		/* no ranges stored yet */
		n_ranges = &zero_ranges;
		node.update_ctdbd.pid = -1;
	} else if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		state->error = status;
		return -1;
	}

	node.supported_ranges = n_ranges;
	status = state->cb(total_nodes_count,
			   &node,
			   state->cb_private);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		state->error = status;
		return -1;
	}
	TALLOC_FREE(frame);
	return 0;
}

NTSTATUS cluster_level_db_nodes_foreach(struct ctdbd_connection *ctdb_conn,
					cluster_level_db_nodes_foreach_cb_t cb,
					void *private_data)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct cluster_level_db_nodes_foreach_state state = {
		.cb = cb,
		.cb_private = private_data,
	};
	int ret;

	/*
	 * We only need temporary read only access,
	 * so we pass msg_ctx=NULL ...
	 */
	state.db = cluster_level_db_open(frame,
					 ctdb_conn,
					 NULL);  /* msg_ctx */
	if (state.db == NULL) {
		DBG_ERR("cluster_level_db_open() failed\n");
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	ret = ctdbd_nodes_foreach(ctdb_conn,
				  cluster_level_db_nodes_foreach_ctdbd_cb,
				  &state);
	if (ret != 0) {
		if (NT_STATUS_IS_OK(state.error)) {
			state.error = NT_STATUS_INTERNAL_ERROR;
		}
		TALLOC_FREE(frame);
		return state.error;
	}

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

struct cluster_level_db_upgrade_to_highest_state {
	struct db_context *db;
	uint32_t error_vnn;
	NTSTATUS error;
};

static int cluster_level_db_upgrade_to_highest_cb(
				uint32_t total_nodes_count,
				const struct ctdb_node_and_flags *nf,
				void *private_data)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct cluster_level_db_upgrade_to_highest_state *state =
		(struct cluster_level_db_upgrade_to_highest_state *)private_data;
	struct timeval n_update_time = {};
	struct timeval n_ctdb_start_time = {};
	pid_t n_ctdb_pid = -1;
	struct cluster_level_ranges *n_ranges = NULL;
	const struct cluster_level_ranges *supported_ranges =
		cluster_level_supported_ranges();
	NTSTATUS status;
	uint32_t i;

	status = cluster_level_db_fetch_ranges(state->db,
					       nf->pnn,
					       frame,
					       &n_update_time,
					       &n_ctdb_start_time,
					       &n_ctdb_pid,
					       &n_ranges);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("node[%"PRIu32"] cluster_level_db_fetch_ranges() %s\n",
			nf->pnn, nt_errstr(status));
		TALLOC_FREE(frame);
		state->error_vnn = nf->pnn;
		state->error = status;
		return -1;
	}

	/*
	 * We expect the same software on all nodes, not
	 * only the highest level in common.
	 */

	if (n_ranges->num_ranges != supported_ranges->num_ranges) {
		DBG_ERR("node[%"PRIu32"] num_ranges[%"PRIu32"] != %"PRIu32".\n",
			nf->pnn,
			n_ranges->num_ranges,
			supported_ranges->num_ranges);
		TALLOC_FREE(frame);
		state->error_vnn = nf->pnn;
		state->error = NT_STATUS_REVISION_MISMATCH;
		return -1;
	}

	for (i = 0; i < n_ranges->num_ranges; i++) {
		const struct cluster_level_range *nr =
			&n_ranges->ranges[i];
		const struct cluster_level_range *sr =
			&supported_ranges->ranges[i];

		if (nr->major != sr->major) {
			DBG_ERR("node[%"PRIu32"] range[%"PRIu32"] "
				"major[%"PRIu32"] != %"PRIu32".\n",
				nf->pnn,
				i,
				nr->major,
				sr->major);
			TALLOC_FREE(frame);
			state->error_vnn = nf->pnn;
			state->error = NT_STATUS_REVISION_MISMATCH;
			return -1;
		}

		if (nr->minor_max != sr->minor_max) {
			DBG_ERR("node[%"PRIu32"] range[%"PRIu32"] "
				"major[%"PRIu32"] "
				"minor_max[%"PRIu32"] != %"PRIu32".\n",
				nf->pnn,
				i,
				nr->major,
				nr->minor_max,
				sr->minor_max);
			TALLOC_FREE(frame);
			state->error_vnn = nf->pnn;
			state->error = NT_STATUS_REVISION_MISMATCH;
			return -1;
		}

		if (nr->minor_min != sr->minor_min) {
			DBG_ERR("node[%"PRIu32"] range[%"PRIu32"] "
				"major[%"PRIu32"] "
				"minor_min[%"PRIu32"] != %"PRIu32".\n",
				nf->pnn,
				i,
				nr->major,
				nr->minor_min,
				sr->minor_min);
			TALLOC_FREE(frame);
			state->error_vnn = nf->pnn;
			state->error = NT_STATUS_REVISION_MISMATCH;
			return -1;
		}
	}

	TALLOC_FREE(frame);
	return 0;
}

NTSTATUS cluster_level_db_upgrade(struct ctdbd_connection *ctdb_conn,
				  struct messaging_context *msg_ctx,
				  struct cluster_level_db_upgrade_req *req)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct cluster_level_db_upgrade_to_highest_state state = {
		.db = NULL,
	};
	const struct cluster_level_ranges *supported_ranges =
		cluster_level_supported_ranges();
	const struct cluster_level_active *conn_level = NULL;
	struct cluster_level_active active_level = {};
	struct cluster_level_active highest_level = {};
	enum cluster_level_db_version version = CLUSTER_LEVEL_DB_VERSION_1;
	struct timeval now = timeval_current();
	NTSTATUS status;
	int ret;

	SMB_ASSERT(msg_ctx != NULL);
	req->out.error_vnn = ctdbd_vnn(ctdb_conn);

	state.db = cluster_level_db_open(frame,
				   ctdb_conn,
				   msg_ctx);
	if (state.db == NULL) {
		DBG_ERR("cluster_level_db_open() failed\n");
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	ret = dbwrap_transaction_start(state.db);
	if (ret != 0) {
		DBG_ERR("dbwrap_transaction_start() failed\n");
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	highest_level = (struct cluster_level_active) {
		.major = supported_ranges->ranges[0].major,
		.minor = supported_ranges->ranges[0].minor_max,
	};

	conn_level = ctdbd_conn_get_cluster_level(ctdb_conn);
	if (conn_level == NULL) {
		dbwrap_transaction_cancel(state.db);
		DBG_ERR("ctdbd_conn_get_cluster_level() failed.\n");
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_CONNECTION;
	}

	status = cluster_level_db_fetch_active(state.db, &active_level);
	if (!NT_STATUS_IS_OK(status)) {
		dbwrap_transaction_cancel(state.db);
		DBG_ERR("cluster_level_db_fetch_active() %s\n",
			nt_errstr(status));
		TALLOC_FREE(frame);
		return status;
	}
	req->out.old_level = active_level;

	if (conn_level->major != active_level.major ||
	    conn_level->minor != active_level.minor)
	{
		dbwrap_transaction_cancel(state.db);
		DBG_ERR("conn_level[%"PRIu32".%"PRIu32"] != "
			"active_level[%"PRIu32".%"PRIu32"].\n",
			conn_level->major, conn_level->minor,
			active_level.major, active_level.minor);
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_CONNECTION;
	}

	if (highest_level.major == active_level.major &&
	    highest_level.minor == active_level.minor)
	{
		dbwrap_transaction_cancel(state.db);
		DBG_ERR("highest_level[%"PRIu32".%"PRIu32"] == "
			"active_level[%"PRIu32".%"PRIu32"].\n",
			highest_level.major, highest_level.minor,
			active_level.major, active_level.minor);
		TALLOC_FREE(frame);
		return NT_STATUS_ALREADY_COMMITTED;
	}

	ret = ctdbd_nodes_foreach(ctdb_conn,
				  cluster_level_db_upgrade_to_highest_cb,
				  &state);
	if (ret != 0) {
		dbwrap_transaction_cancel(state.db);
		if (NT_STATUS_IS_OK(state.error)) {
			state.error_vnn = ctdbd_vnn(ctdb_conn);
			state.error = NT_STATUS_INTERNAL_ERROR;
		}
		DBG_ERR("cluster_level_db_upgrade_to_highest_cb() "
			"vnn=%"PRIu32" %s\n",
			state.error_vnn, nt_errstr(state.error));
		req->out.error_vnn = state.error_vnn;
		TALLOC_FREE(frame);
		return state.error;
	}

	active_level = highest_level;

	/*
	 * If needed adjust version based on active_level!
	 */
	version = CLUSTER_LEVEL_DB_VERSION_1;

	status = cluster_level_db_store_active(state.db,
					       version,
					       now,
					       &active_level);
	if (!NT_STATUS_IS_OK(status)) {
		dbwrap_transaction_cancel(state.db);
		DBG_ERR("cluster_level_db_store_active() %s\n",
			nt_errstr(status));
		TALLOC_FREE(frame);
		return status;
	}

	req->out.new_level = active_level;

	if (req->in.dry_run) {
		dbwrap_transaction_cancel(state.db);
		status = NT_STATUS_NOT_COMMITTED;
		DBG_DEBUG("active_level: %"PRIu32".%"PRIu32" - %s\n",
			  active_level.major, active_level.minor,
			  nt_errstr(status));
		TALLOC_FREE(frame);
		return status;
	}

	ret = dbwrap_transaction_commit(state.db);
	if (ret != 0) {
		DBG_ERR("dbwrap_transaction_commit() failed\n");
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	DBG_DEBUG("active_level: %"PRIu32".%"PRIu32" - %s\n",
		  active_level.major, active_level.minor,
		  nt_errstr(status));

	/*
	 * Announce the change and let every process connected
	 * to ctdb notice it.
	 */
	messaging_send_all(msg_ctx, MSG_CLUSTER_LEVEL_UPGRADED, NULL, 0);

	ctdbd_conn_set_cluster_level(ctdb_conn, &active_level);
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}
