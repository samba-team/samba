/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2012

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
#include "system/filesys.h"
#include "smbd/globals.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "lib/util/util_tdb.h"
#include "librpc/gen_ndr/ndr_smbXsrv.h"
#include "serverid.h"

/*
 * This implements a version scheme for file server internal
 * states. smbXsrv_version_global.tdb stores the possible
 * and current versions of structure formats (struct smbXsrv_*_global)
 * per cluster node.
 *
 * If the supported versions doesn't match a version of any
 * of the other nodes, it refused to start.
 *
 * This should prevent silent corruption of the internal
 * databases and structures, if two incompatible implementations
 * read and write.
 *
 * In future this can be used to implement rolling code upgrades
 * in a cluster, but for now it is simple.
 */

static struct db_context *smbXsrv_version_global_db_ctx = NULL;
static uint32_t smbXsrv_version_global_current_version = UINT32_MAX;

NTSTATUS smbXsrv_version_global_init(const struct server_id *server_id)
{
	const char *global_path = NULL;
	struct db_context *db_ctx = NULL;
	struct db_record *db_rec = NULL;
	TDB_DATA key;
	TDB_DATA val;
	DATA_BLOB blob;
	struct smbXsrv_version_globalB global_blob;
	enum ndr_err_code ndr_err;
	struct smbXsrv_version_global0 *global = NULL;
	uint32_t i;
	uint32_t num_valid = 0;
	struct smbXsrv_version_node0 *valid = NULL;
	struct smbXsrv_version_node0 *local_node = NULL;
	bool exists;
	NTSTATUS status;
	const char *key_string = "smbXsrv_version_global";
	TALLOC_CTX *frame;

	if (smbXsrv_version_global_db_ctx != NULL) {
		return NT_STATUS_OK;
	}

	frame = talloc_stackframe();

	global_path = lock_path("smbXsrv_version_global.tdb");

	db_ctx = db_open(NULL, global_path,
			 0, /* hash_size */
			 TDB_DEFAULT |
			 TDB_CLEAR_IF_FIRST |
			 TDB_INCOMPATIBLE_HASH,
			 O_RDWR | O_CREAT, 0600,
			 DBWRAP_LOCK_ORDER_1);
	if (db_ctx == NULL) {
		status = map_nt_error_from_unix_common(errno);
		DEBUG(0,("smbXsrv_version_global_init: "
			 "failed to open[%s] - %s\n",
			 global_path, nt_errstr(status)));
		TALLOC_FREE(frame);
		return status;
	}

	key = string_term_tdb_data(key_string);

	db_rec = dbwrap_fetch_locked(db_ctx, db_ctx, key);
	if (db_rec == NULL) {
		status = NT_STATUS_INTERNAL_DB_ERROR;
		DEBUG(0,("smbXsrv_version_global_init: "
			 "dbwrap_fetch_locked(%s) - %s\n",
			 key_string, nt_errstr(status)));
		TALLOC_FREE(frame);
		return status;
	}

	val = dbwrap_record_get_value(db_rec);
	if (val.dsize == 0) {
		global = talloc_zero(frame, struct smbXsrv_version_global0);
		if (global == NULL) {
			DEBUG(0,("smbXsrv_version_global_init: "
				 "talloc_zero failed - %s\n", __location__));
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
		ZERO_STRUCT(global_blob);
		global_blob.version = SMBXSRV_VERSION_CURRENT;
		global_blob.info.info0 = global;
	} else {
		blob = data_blob_const(val.dptr, val.dsize);

		ndr_err = ndr_pull_struct_blob(&blob, frame, &global_blob,
			(ndr_pull_flags_fn_t)ndr_pull_smbXsrv_version_globalB);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			status = ndr_map_error2ntstatus(ndr_err);
			DEBUG(0,("smbXsrv_version_global_init: "
				 "ndr_pull_smbXsrv_version_globalB - %s\n",
				 nt_errstr(status)));
			TALLOC_FREE(frame);
			return status;
		}

		switch (global_blob.version) {
		case SMBXSRV_VERSION_0:
			global = global_blob.info.info0;
			if (global == NULL) {
				status = NT_STATUS_INTERNAL_DB_CORRUPTION;
				break;
			}
			status = NT_STATUS_OK;
			break;
		default:
			status = NT_STATUS_REVISION_MISMATCH;
			break;
		}

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("smbXsrv_version_global_init - %s\n",
				 nt_errstr(status)));
			NDR_PRINT_DEBUG(smbXsrv_version_globalB, &global_blob);
			TALLOC_FREE(frame);
			return status;
		}
	}

	valid = talloc_zero_array(global,
				  struct smbXsrv_version_node0,
				  global->num_nodes + 1);
	if (valid == NULL) {
		DEBUG(0,("smbXsrv_version_global_init: "
			 "talloc_zero_array failed - %s\n", __location__));
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	num_valid = 0;
	for (i=0; i < global->num_nodes; i++) {
		struct smbXsrv_version_node0 *n = &global->nodes[i];

		exists = serverid_exists(&n->server_id);
		if (!exists) {
			continue;
		}

		if (n->min_version > n->max_version) {
			status = NT_STATUS_INTERNAL_DB_CORRUPTION;
			DEBUG(0,("smbXsrv_version_global_init - %s\n",
				 nt_errstr(status)));
			NDR_PRINT_DEBUG(smbXsrv_version_globalB, &global_blob);
			TALLOC_FREE(frame);
			return status;
		}

		if (n->min_version > global_blob.version) {
			status = NT_STATUS_INTERNAL_DB_CORRUPTION;
			DEBUG(0,("smbXsrv_version_global_init - %s\n",
				 nt_errstr(status)));
			NDR_PRINT_DEBUG(smbXsrv_version_globalB, &global_blob);
			TALLOC_FREE(frame);
			return status;
		}

		if (n->max_version < global_blob.version) {
			status = NT_STATUS_INTERNAL_DB_CORRUPTION;
			DEBUG(0,("smbXsrv_version_global_init - %s\n",
				 nt_errstr(status)));
			NDR_PRINT_DEBUG(smbXsrv_version_globalB, &global_blob);
			TALLOC_FREE(frame);
			return status;
		}

		valid[num_valid] = *n;
		if (server_id->vnn == n->server_id.vnn) {
			local_node = &valid[num_valid];
		}
		num_valid++;
	}

	if (local_node == NULL) {
		local_node = &valid[num_valid];
		num_valid++;
	}

	local_node->server_id = *server_id;
	local_node->min_version = SMBXSRV_VERSION_0;
	local_node->max_version = SMBXSRV_VERSION_CURRENT;
	local_node->current_version = global_blob.version;

	global->num_nodes = num_valid;
	global->nodes = valid;

	global_blob.seqnum += 1;
	global_blob.info.info0 = global;

	ndr_err = ndr_push_struct_blob(&blob, db_rec, &global_blob,
			(ndr_push_flags_fn_t)ndr_push_smbXsrv_version_globalB);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(0,("smbXsrv_version_global_init: "
			 "ndr_push_smbXsrv_version_globalB - %s\n",
			 nt_errstr(status)));
		TALLOC_FREE(frame);
		return status;
	}

	val = make_tdb_data(blob.data, blob.length);
	status = dbwrap_record_store(db_rec, val, TDB_REPLACE);
	TALLOC_FREE(db_rec);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("smbXsrv_version_global_init: "
			 "dbwrap_record_store - %s\n",
			 nt_errstr(status)));
		TALLOC_FREE(frame);
		return status;
	}

	DEBUG(10,("smbXsrv_version_global_init\n"));
	if (DEBUGLVL(10)) {
		NDR_PRINT_DEBUG(smbXsrv_version_globalB, &global_blob);
	}

	smbXsrv_version_global_db_ctx = db_ctx;
	smbXsrv_version_global_current_version = global_blob.version;

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

uint32_t smbXsrv_version_global_current(void)
{
	return smbXsrv_version_global_current_version;
}
