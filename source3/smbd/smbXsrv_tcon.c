/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2011-2012
   Copyright (C) Michael Adam 2012

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
#include "lib/util/server_id.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_rbt.h"
#include "dbwrap/dbwrap_open.h"
#include "messages.h"
#include "lib/util/util_tdb.h"
#include "librpc/gen_ndr/ndr_smbXsrv.h"
#include "serverid.h"

struct smbXsrv_tcon_table {
	struct {
		struct db_context *db_ctx;
		uint32_t lowest_id;
		uint32_t highest_id;
		uint32_t max_tcons;
		uint32_t num_tcons;
	} local;
	struct {
		struct db_context *db_ctx;
	} global;
};

static struct db_context *smbXsrv_tcon_global_db_ctx = NULL;

NTSTATUS smbXsrv_tcon_global_init(void)
{
	char *global_path = NULL;
	struct db_context *db_ctx = NULL;

	if (smbXsrv_tcon_global_db_ctx != NULL) {
		return NT_STATUS_OK;
	}

	global_path = lock_path(talloc_tos(), "smbXsrv_tcon_global.tdb");
	if (global_path == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	db_ctx = db_open(NULL, global_path,
			 0, /* hash_size */
			 TDB_DEFAULT |
			 TDB_CLEAR_IF_FIRST |
			 TDB_INCOMPATIBLE_HASH,
			 O_RDWR | O_CREAT, 0600,
			 DBWRAP_LOCK_ORDER_1,
			 DBWRAP_FLAG_NONE);
	TALLOC_FREE(global_path);
	if (db_ctx == NULL) {
		NTSTATUS status;

		status = map_nt_error_from_unix_common(errno);

		return status;
	}

	smbXsrv_tcon_global_db_ctx = db_ctx;

	return NT_STATUS_OK;
}

/*
 * NOTE:
 * We need to store the keys in big endian so that dbwrap_rbt's memcmp
 * has the same result as integer comparison between the uint32_t
 * values.
 *
 * TODO: implement string based key
 */

#define SMBXSRV_TCON_GLOBAL_TDB_KEY_SIZE sizeof(uint32_t)

static TDB_DATA smbXsrv_tcon_global_id_to_key(uint32_t id,
					      uint8_t *key_buf)
{
	TDB_DATA key;

	RSIVAL(key_buf, 0, id);

	key = make_tdb_data(key_buf, SMBXSRV_TCON_GLOBAL_TDB_KEY_SIZE);

	return key;
}

#if 0
static NTSTATUS smbXsrv_tcon_global_key_to_id(TDB_DATA key, uint32_t *id)
{
	if (id == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (key.dsize != SMBXSRV_TCON_GLOBAL_TDB_KEY_SIZE) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	*id = RIVAL(key.dptr, 0);

	return NT_STATUS_OK;
}
#endif

#define SMBXSRV_TCON_LOCAL_TDB_KEY_SIZE sizeof(uint32_t)

static TDB_DATA smbXsrv_tcon_local_id_to_key(uint32_t id,
					     uint8_t *key_buf)
{
	TDB_DATA key;

	RSIVAL(key_buf, 0, id);

	key = make_tdb_data(key_buf, SMBXSRV_TCON_LOCAL_TDB_KEY_SIZE);

	return key;
}

static NTSTATUS smbXsrv_tcon_local_key_to_id(TDB_DATA key, uint32_t *id)
{
	if (id == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (key.dsize != SMBXSRV_TCON_LOCAL_TDB_KEY_SIZE) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	*id = RIVAL(key.dptr, 0);

	return NT_STATUS_OK;
}

static struct db_record *smbXsrv_tcon_global_fetch_locked(
			struct db_context *db,
			uint32_t id,
			TALLOC_CTX *mem_ctx)
{
	TDB_DATA key;
	uint8_t key_buf[SMBXSRV_TCON_GLOBAL_TDB_KEY_SIZE];
	struct db_record *rec = NULL;

	key = smbXsrv_tcon_global_id_to_key(id, key_buf);

	rec = dbwrap_fetch_locked(db, mem_ctx, key);

	if (rec == NULL) {
		DBG_DEBUG("Failed to lock global id 0x%08x, key '%s'\n", id,
			  hex_encode_talloc(talloc_tos(), key.dptr, key.dsize));
	}

	return rec;
}

static struct db_record *smbXsrv_tcon_local_fetch_locked(
			struct db_context *db,
			uint32_t id,
			TALLOC_CTX *mem_ctx)
{
	TDB_DATA key;
	uint8_t key_buf[SMBXSRV_TCON_LOCAL_TDB_KEY_SIZE];
	struct db_record *rec = NULL;

	key = smbXsrv_tcon_local_id_to_key(id, key_buf);

	rec = dbwrap_fetch_locked(db, mem_ctx, key);

	if (rec == NULL) {
		DBG_DEBUG("Failed to lock local id 0x%08x, key '%s'\n", id,
			  hex_encode_talloc(talloc_tos(), key.dptr, key.dsize));
	}

	return rec;
}

static NTSTATUS smbXsrv_tcon_table_init(TALLOC_CTX *mem_ctx,
					struct smbXsrv_tcon_table *table,
					uint32_t lowest_id,
					uint32_t highest_id,
					uint32_t max_tcons)
{
	NTSTATUS status;
	uint64_t max_range;

	if (lowest_id > highest_id) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	max_range = highest_id;
	max_range -= lowest_id;
	max_range += 1;

	if (max_tcons > max_range) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	ZERO_STRUCTP(table);
	table->local.db_ctx = db_open_rbt(table);
	if (table->local.db_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	table->local.lowest_id = lowest_id;
	table->local.highest_id = highest_id;
	table->local.max_tcons = max_tcons;

	status = smbXsrv_tcon_global_init();
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	table->global.db_ctx = smbXsrv_tcon_global_db_ctx;

	return NT_STATUS_OK;
}

struct smb1srv_tcon_local_allocate_state {
	const uint32_t lowest_id;
	const uint32_t highest_id;
	uint32_t last_id;
	uint32_t useable_id;
	NTSTATUS status;
};

static int smb1srv_tcon_local_allocate_traverse(struct db_record *rec,
						   void *private_data)
{
	struct smb1srv_tcon_local_allocate_state *state =
		(struct smb1srv_tcon_local_allocate_state *)private_data;
	TDB_DATA key = dbwrap_record_get_key(rec);
	uint32_t id = 0;
	NTSTATUS status;

	status = smbXsrv_tcon_local_key_to_id(key, &id);
	if (!NT_STATUS_IS_OK(status)) {
		state->status = status;
		return -1;
	}

	if (id <= state->last_id) {
		state->status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		return -1;
	}
	state->last_id = id;

	if (id > state->useable_id) {
		state->status = NT_STATUS_OK;
		return -1;
	}

	if (state->useable_id == state->highest_id) {
		state->status = NT_STATUS_INSUFFICIENT_RESOURCES;
		return -1;
	}

	state->useable_id +=1;
	return 0;
}

static NTSTATUS smb1srv_tcon_local_allocate_id(struct db_context *db,
					       uint32_t lowest_id,
					       uint32_t highest_id,
					       TALLOC_CTX *mem_ctx,
					       struct db_record **_rec,
					       uint32_t *_id)
{
	struct smb1srv_tcon_local_allocate_state state = {
		.lowest_id = lowest_id,
		.highest_id = highest_id,
		.last_id = 0,
		.useable_id = lowest_id,
		.status = NT_STATUS_INTERNAL_ERROR,
	};
	uint32_t i;
	uint32_t range;
	NTSTATUS status;
	int count = 0;

	*_rec = NULL;
	*_id = 0;

	if (lowest_id > highest_id) {
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	/*
	 * first we try randomly
	 */
	range = (highest_id - lowest_id) + 1;

	for (i = 0; i < (range / 2); i++) {
		uint32_t id;
		TDB_DATA val;
		struct db_record *rec = NULL;

		id = generate_random() % range;
		id += lowest_id;

		if (id < lowest_id) {
			id = lowest_id;
		}
		if (id > highest_id) {
			id = highest_id;
		}

		rec = smbXsrv_tcon_local_fetch_locked(db, id, mem_ctx);
		if (rec == NULL) {
			return NT_STATUS_INSUFFICIENT_RESOURCES;
		}

		val = dbwrap_record_get_value(rec);
		if (val.dsize != 0) {
			TALLOC_FREE(rec);
			continue;
		}

		*_rec = rec;
		*_id = id;
		return NT_STATUS_OK;
	}

	/*
	 * if the range is almost full,
	 * we traverse the whole table
	 * (this relies on sorted behavior of dbwrap_rbt)
	 */
	status = dbwrap_traverse_read(db, smb1srv_tcon_local_allocate_traverse,
				      &state, &count);
	if (NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_IS_OK(state.status)) {
			return NT_STATUS_INTERNAL_ERROR;
		}

		if (!NT_STATUS_EQUAL(state.status, NT_STATUS_INTERNAL_ERROR)) {
			return state.status;
		}

		if (state.useable_id <= state.highest_id) {
			state.status = NT_STATUS_OK;
		} else {
			return NT_STATUS_INSUFFICIENT_RESOURCES;
		}
	} else if (!NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_DB_CORRUPTION)) {
		/*
		 * Here we really expect NT_STATUS_INTERNAL_DB_CORRUPTION!
		 *
		 * If we get anything else it is an error, because it
		 * means we did not manage to find a free slot in
		 * the db.
		 */
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	if (NT_STATUS_IS_OK(state.status)) {
		uint32_t id;
		TDB_DATA val;
		struct db_record *rec = NULL;

		id = state.useable_id;

		rec = smbXsrv_tcon_local_fetch_locked(db, id, mem_ctx);
		if (rec == NULL) {
			return NT_STATUS_INSUFFICIENT_RESOURCES;
		}

		val = dbwrap_record_get_value(rec);
		if (val.dsize != 0) {
			TALLOC_FREE(rec);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		*_rec = rec;
		*_id = id;
		return NT_STATUS_OK;
	}

	return state.status;
}

struct smbXsrv_tcon_local_fetch_state {
	struct smbXsrv_tcon *tcon;
	NTSTATUS status;
};

static void smbXsrv_tcon_local_fetch_parser(TDB_DATA key, TDB_DATA data,
					    void *private_data)
{
	struct smbXsrv_tcon_local_fetch_state *state =
		(struct smbXsrv_tcon_local_fetch_state *)private_data;
	void *ptr;

	if (data.dsize != sizeof(ptr)) {
		state->status = NT_STATUS_INTERNAL_DB_ERROR;
		return;
	}

	memcpy(&ptr, data.dptr, data.dsize);
	state->tcon = talloc_get_type_abort(ptr, struct smbXsrv_tcon);
	state->status = NT_STATUS_OK;
}

static NTSTATUS smbXsrv_tcon_local_lookup(struct smbXsrv_tcon_table *table,
					  uint32_t tcon_local_id,
					  NTTIME now,
					  struct smbXsrv_tcon **_tcon)
{
	struct smbXsrv_tcon_local_fetch_state state = {
		.tcon = NULL,
		.status = NT_STATUS_INTERNAL_ERROR,
	};
	uint8_t key_buf[SMBXSRV_TCON_LOCAL_TDB_KEY_SIZE];
	TDB_DATA key;
	NTSTATUS status;

	*_tcon = NULL;

	if (tcon_local_id == 0) {
		return NT_STATUS_NETWORK_NAME_DELETED;
	}

	if (table == NULL) {
		/* this might happen before the end of negprot */
		return NT_STATUS_NETWORK_NAME_DELETED;
	}

	if (table->local.db_ctx == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	key = smbXsrv_tcon_local_id_to_key(tcon_local_id, key_buf);

	status = dbwrap_parse_record(table->local.db_ctx, key,
				     smbXsrv_tcon_local_fetch_parser,
				     &state);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		return NT_STATUS_NETWORK_NAME_DELETED;
	} else if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		return state.status;
	}

	if (NT_STATUS_EQUAL(state.tcon->status, NT_STATUS_NETWORK_NAME_DELETED)) {
		return NT_STATUS_NETWORK_NAME_DELETED;
	}

	state.tcon->idle_time = now;

	*_tcon = state.tcon;
	return state.tcon->status;
}

static int smbXsrv_tcon_global_destructor(struct smbXsrv_tcon_global0 *global)
{
	return 0;
}

static void smbXsrv_tcon_global_verify_record(struct db_record *db_rec,
					bool *is_free,
					bool *was_free,
					TALLOC_CTX *mem_ctx,
					struct smbXsrv_tcon_global0 **_g);

static NTSTATUS smbXsrv_tcon_global_allocate(struct db_context *db,
					TALLOC_CTX *mem_ctx,
					struct smbXsrv_tcon_global0 **_global)
{
	uint32_t i;
	struct smbXsrv_tcon_global0 *global = NULL;
	uint32_t last_free = 0;
	const uint32_t min_tries = 3;

	*_global = NULL;

	global = talloc_zero(mem_ctx, struct smbXsrv_tcon_global0);
	if (global == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(global, smbXsrv_tcon_global_destructor);

	/*
	 * Here we just randomly try the whole 32-bit space
	 *
	 * We use just 32-bit, because we want to reuse the
	 * ID for SRVSVC.
	 */
	for (i = 0; i < UINT32_MAX; i++) {
		bool is_free = false;
		bool was_free = false;
		uint32_t id;

		if (i >= min_tries && last_free != 0) {
			id = last_free;
		} else {
			id = generate_random();
		}
		if (id == 0) {
			id++;
		}
		if (id == UINT32_MAX) {
			id--;
		}

		global->db_rec = smbXsrv_tcon_global_fetch_locked(db, id,
								  mem_ctx);
		if (global->db_rec == NULL) {
			talloc_free(global);
			return NT_STATUS_INSUFFICIENT_RESOURCES;
		}

		smbXsrv_tcon_global_verify_record(global->db_rec,
						  &is_free,
						  &was_free,
						  NULL, NULL);

		if (!is_free) {
			TALLOC_FREE(global->db_rec);
			continue;
		}

		if (!was_free && i < min_tries) {
			/*
			 * The session_id is free now,
			 * but was not free before.
			 *
			 * This happens if a smbd crashed
			 * and did not cleanup the record.
			 *
			 * If this is one of our first tries,
			 * then we try to find a real free one.
			 */
			if (last_free == 0) {
				last_free = id;
			}
			TALLOC_FREE(global->db_rec);
			continue;
		}

		global->tcon_global_id = id;

		*_global = global;
		return NT_STATUS_OK;
	}

	/* should not be reached */
	talloc_free(global);
	return NT_STATUS_INTERNAL_ERROR;
}

static void smbXsrv_tcon_global_verify_record(struct db_record *db_rec,
					bool *is_free,
					bool *was_free,
					TALLOC_CTX *mem_ctx,
					struct smbXsrv_tcon_global0 **_g)
{
	TDB_DATA key;
	TDB_DATA val;
	DATA_BLOB blob;
	struct smbXsrv_tcon_globalB global_blob;
	enum ndr_err_code ndr_err;
	struct smbXsrv_tcon_global0 *global = NULL;
	bool exists;
	TALLOC_CTX *frame = talloc_stackframe();

	*is_free = false;

	if (was_free) {
		*was_free = false;
	}
	if (_g) {
		*_g = NULL;
	}

	key = dbwrap_record_get_key(db_rec);

	val = dbwrap_record_get_value(db_rec);
	if (val.dsize == 0) {
		TALLOC_FREE(frame);
		*is_free = true;
		if (was_free) {
			*was_free = true;
		}
		return;
	}

	blob = data_blob_const(val.dptr, val.dsize);

	ndr_err = ndr_pull_struct_blob(&blob, frame, &global_blob,
			(ndr_pull_flags_fn_t)ndr_pull_smbXsrv_tcon_globalB);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(1,("smbXsrv_tcon_global_verify_record: "
			 "key '%s' ndr_pull_struct_blob - %s\n",
			 hex_encode_talloc(frame, key.dptr, key.dsize),
			 nt_errstr(status)));
		TALLOC_FREE(frame);
		return;
	}

	DEBUG(10,("smbXsrv_tcon_global_verify_record\n"));
	if (DEBUGLVL(10)) {
		NDR_PRINT_DEBUG(smbXsrv_tcon_globalB, &global_blob);
	}

	if (global_blob.version != SMBXSRV_VERSION_0) {
		DEBUG(0,("smbXsrv_tcon_global_verify_record: "
			 "key '%s' use unsupported version %u\n",
			 hex_encode_talloc(frame, key.dptr, key.dsize),
			 global_blob.version));
		NDR_PRINT_DEBUG(smbXsrv_tcon_globalB, &global_blob);
		TALLOC_FREE(frame);
		return;
	}

	global = global_blob.info.info0;

	exists = serverid_exists(&global->server_id);
	if (!exists) {
		struct server_id_buf idbuf;
		DEBUG(2,("smbXsrv_tcon_global_verify_record: "
			 "key '%s' server_id %s does not exist.\n",
			 hex_encode_talloc(frame, key.dptr, key.dsize),
			 server_id_str_buf(global->server_id, &idbuf)));
		if (DEBUGLVL(2)) {
			NDR_PRINT_DEBUG(smbXsrv_tcon_globalB, &global_blob);
		}
		TALLOC_FREE(frame);
		dbwrap_record_delete(db_rec);
		*is_free = true;
		return;
	}

	if (_g) {
		*_g = talloc_move(mem_ctx, &global);
	}
	TALLOC_FREE(frame);
}

static NTSTATUS smbXsrv_tcon_global_store(struct smbXsrv_tcon_global0 *global)
{
	struct smbXsrv_tcon_globalB global_blob;
	DATA_BLOB blob = data_blob_null;
	TDB_DATA key;
	TDB_DATA val;
	NTSTATUS status;
	enum ndr_err_code ndr_err;

	/*
	 * TODO: if we use other versions than '0'
	 * we would add glue code here, that would be able to
	 * store the information in the old format.
	 */

	if (global->db_rec == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	key = dbwrap_record_get_key(global->db_rec);
	val = dbwrap_record_get_value(global->db_rec);

	ZERO_STRUCT(global_blob);
	global_blob.version = smbXsrv_version_global_current();
	if (val.dsize >= 8) {
		global_blob.seqnum = IVAL(val.dptr, 4);
	}
	global_blob.seqnum += 1;
	global_blob.info.info0 = global;

	ndr_err = ndr_push_struct_blob(&blob, global->db_rec, &global_blob,
			(ndr_push_flags_fn_t)ndr_push_smbXsrv_tcon_globalB);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(1,("smbXsrv_tcon_global_store: key '%s' ndr_push - %s\n",
			 hex_encode_talloc(global->db_rec, key.dptr, key.dsize),
			 nt_errstr(status)));
		TALLOC_FREE(global->db_rec);
		return status;
	}

	val = make_tdb_data(blob.data, blob.length);
	status = dbwrap_record_store(global->db_rec, val, TDB_REPLACE);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1,("smbXsrv_tcon_global_store: key '%s' store - %s\n",
			 hex_encode_talloc(global->db_rec, key.dptr, key.dsize),
			 nt_errstr(status)));
		TALLOC_FREE(global->db_rec);
		return status;
	}

	if (DEBUGLVL(10)) {
		DEBUG(10,("smbXsrv_tcon_global_store: key '%s' stored\n",
			 hex_encode_talloc(global->db_rec, key.dptr, key.dsize)));
		NDR_PRINT_DEBUG(smbXsrv_tcon_globalB, &global_blob);
	}

	TALLOC_FREE(global->db_rec);

	return NT_STATUS_OK;
}

static int smbXsrv_tcon_destructor(struct smbXsrv_tcon *tcon)
{
	NTSTATUS status;

	status = smbXsrv_tcon_disconnect(tcon, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("smbXsrv_tcon_destructor: "
			  "smbXsrv_tcon_disconnect() failed - %s\n",
			  nt_errstr(status)));
	}

	TALLOC_FREE(tcon->global);

	return 0;
}

static NTSTATUS smbXsrv_tcon_create(struct smbXsrv_tcon_table *table,
				    enum protocol_types protocol,
				    struct server_id server_id,
				    NTTIME now,
				    struct smbXsrv_tcon **_tcon)
{
	struct db_record *local_rec = NULL;
	struct smbXsrv_tcon *tcon = NULL;
	void *ptr = NULL;
	TDB_DATA val;
	struct smbXsrv_tcon_global0 *global = NULL;
	NTSTATUS status;

	if (table->local.num_tcons >= table->local.max_tcons) {
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	tcon = talloc_zero(table, struct smbXsrv_tcon);
	if (tcon == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tcon->table = table;
	tcon->status = NT_STATUS_INTERNAL_ERROR;
	tcon->idle_time = now;

	status = smbXsrv_tcon_global_allocate(table->global.db_ctx,
					      tcon, &global);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(tcon);
		return status;
	}
	tcon->global = global;

	if (protocol >= PROTOCOL_SMB2_02) {
		uint64_t id = global->tcon_global_id;

		global->tcon_wire_id = id;

		tcon->local_id = global->tcon_global_id;

		local_rec = smbXsrv_tcon_local_fetch_locked(table->local.db_ctx,
							tcon->local_id,
							tcon /* TALLOC_CTX */);
		if (local_rec == NULL) {
			TALLOC_FREE(tcon);
			return NT_STATUS_NO_MEMORY;
		}

		val = dbwrap_record_get_value(local_rec);
		if (val.dsize != 0) {
			TALLOC_FREE(tcon);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	} else {

		status = smb1srv_tcon_local_allocate_id(table->local.db_ctx,
							table->local.lowest_id,
							table->local.highest_id,
							tcon,
							&local_rec,
							&tcon->local_id);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(tcon);
			return status;
		}

		global->tcon_wire_id = tcon->local_id;
	}

	global->creation_time = now;

	global->server_id = server_id;

	ptr = tcon;
	val = make_tdb_data((uint8_t const *)&ptr, sizeof(ptr));
	status = dbwrap_record_store(local_rec, val, TDB_REPLACE);
	TALLOC_FREE(local_rec);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(tcon);
		return status;
	}
	table->local.num_tcons += 1;

	talloc_set_destructor(tcon, smbXsrv_tcon_destructor);

	status = smbXsrv_tcon_global_store(global);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("smbXsrv_tcon_create: "
			 "global_id (0x%08x) store failed - %s\n",
			 tcon->global->tcon_global_id,
			 nt_errstr(status)));
		TALLOC_FREE(tcon);
		return status;
	}

	if (DEBUGLVL(10)) {
		struct smbXsrv_tconB tcon_blob = {
			.version = SMBXSRV_VERSION_0,
			.info.info0 = tcon,
		};

		DEBUG(10,("smbXsrv_tcon_create: global_id (0x%08x) stored\n",
			 tcon->global->tcon_global_id));
		NDR_PRINT_DEBUG(smbXsrv_tconB, &tcon_blob);
	}

	*_tcon = tcon;
	return NT_STATUS_OK;
}

NTSTATUS smbXsrv_tcon_update(struct smbXsrv_tcon *tcon)
{
	struct smbXsrv_tcon_table *table = tcon->table;
	NTSTATUS status;

	if (tcon->global->db_rec != NULL) {
		DEBUG(0, ("smbXsrv_tcon_update(0x%08x): "
			  "Called with db_rec != NULL'\n",
			  tcon->global->tcon_global_id));
		return NT_STATUS_INTERNAL_ERROR;
	}

	tcon->global->db_rec = smbXsrv_tcon_global_fetch_locked(
						table->global.db_ctx,
						tcon->global->tcon_global_id,
						tcon->global /* TALLOC_CTX */);
	if (tcon->global->db_rec == NULL) {
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	status = smbXsrv_tcon_global_store(tcon->global);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("smbXsrv_tcon_update: "
			 "global_id (0x%08x) store failed - %s\n",
			 tcon->global->tcon_global_id,
			 nt_errstr(status)));
		return status;
	}

	if (DEBUGLVL(10)) {
		struct smbXsrv_tconB tcon_blob = {
			.version = SMBXSRV_VERSION_0,
			.info.info0 = tcon,
		};

		DEBUG(10,("smbXsrv_tcon_update: global_id (0x%08x) stored\n",
			  tcon->global->tcon_global_id));
		NDR_PRINT_DEBUG(smbXsrv_tconB, &tcon_blob);
	}

	return NT_STATUS_OK;
}

NTSTATUS smbXsrv_tcon_disconnect(struct smbXsrv_tcon *tcon, uint64_t vuid)
{
	struct smbXsrv_tcon_table *table;
	struct db_record *local_rec = NULL;
	struct db_record *global_rec = NULL;
	NTSTATUS status;
	NTSTATUS error = NT_STATUS_OK;

	if (tcon->table == NULL) {
		return NT_STATUS_OK;
	}

	table = tcon->table;
	tcon->table = NULL;

	if (tcon->compat) {
		bool ok;

		ok = chdir_current_service(tcon->compat);
		if (!ok) {
			status = NT_STATUS_INTERNAL_ERROR;
			DEBUG(0, ("smbXsrv_tcon_disconnect(0x%08x, '%s'): "
				  "chdir_current_service() failed: %s\n",
				  tcon->global->tcon_global_id,
				  tcon->global->share_name,
				  nt_errstr(status)));
			tcon->compat = NULL;
			return status;
		}

		close_cnum(tcon->compat, vuid);
		tcon->compat = NULL;
	}

	tcon->status = NT_STATUS_NETWORK_NAME_DELETED;

	global_rec = tcon->global->db_rec;
	tcon->global->db_rec = NULL;
	if (global_rec == NULL) {
		global_rec = smbXsrv_tcon_global_fetch_locked(
						table->global.db_ctx,
						tcon->global->tcon_global_id,
						tcon->global /* TALLOC_CTX */);
		if (global_rec == NULL) {
			error = NT_STATUS_INTERNAL_ERROR;
		}
	}

	if (global_rec != NULL) {
		status = dbwrap_record_delete(global_rec);
		if (!NT_STATUS_IS_OK(status)) {
			TDB_DATA key = dbwrap_record_get_key(global_rec);

			DEBUG(0, ("smbXsrv_tcon_disconnect(0x%08x, '%s'): "
				  "failed to delete global key '%s': %s\n",
				  tcon->global->tcon_global_id,
				  tcon->global->share_name,
				  hex_encode_talloc(global_rec, key.dptr,
						    key.dsize),
				  nt_errstr(status)));
			error = status;
		}
	}
	TALLOC_FREE(global_rec);

	local_rec = tcon->db_rec;
	if (local_rec == NULL) {
		local_rec = smbXsrv_tcon_local_fetch_locked(table->local.db_ctx,
							tcon->local_id,
							tcon /* TALLOC_CTX */);
		if (local_rec == NULL) {
			error = NT_STATUS_INTERNAL_ERROR;
		}
	}

	if (local_rec != NULL) {
		status = dbwrap_record_delete(local_rec);
		if (!NT_STATUS_IS_OK(status)) {
			TDB_DATA key = dbwrap_record_get_key(local_rec);

			DEBUG(0, ("smbXsrv_tcon_disconnect(0x%08x, '%s'): "
				  "failed to delete local key '%s': %s\n",
				  tcon->global->tcon_global_id,
				  tcon->global->share_name,
				  hex_encode_talloc(local_rec, key.dptr,
						    key.dsize),
				  nt_errstr(status)));
			error = status;
		}
		table->local.num_tcons -= 1;
	}
	if (tcon->db_rec == NULL) {
		TALLOC_FREE(local_rec);
	}
	tcon->db_rec = NULL;

	return error;
}

struct smbXsrv_tcon_disconnect_all_state {
	uint64_t vuid;
	NTSTATUS first_status;
	int errors;
};

static int smbXsrv_tcon_disconnect_all_callback(struct db_record *local_rec,
						void *private_data);

static NTSTATUS smbXsrv_tcon_disconnect_all(struct smbXsrv_tcon_table *table,
					    uint64_t vuid)
{
	struct smbXsrv_tcon_disconnect_all_state state;
	NTSTATUS status;
	int count = 0;

	if (table == NULL) {
		return NT_STATUS_OK;
	}

	ZERO_STRUCT(state);
	state.vuid = vuid;

	status = dbwrap_traverse(table->local.db_ctx,
				 smbXsrv_tcon_disconnect_all_callback,
				 &state, &count);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("smbXsrv_tcon_disconnect_all: "
			  "dbwrap_traverse() failed: %s\n",
			  nt_errstr(status)));
		return status;
	}

	if (!NT_STATUS_IS_OK(state.first_status)) {
		DEBUG(0, ("smbXsrv_tcon_disconnect_all: "
			  "count[%d] errors[%d] first[%s]\n",
			  count, state.errors,
			  nt_errstr(state.first_status)));
		return state.first_status;
	}

	return NT_STATUS_OK;
}

static int smbXsrv_tcon_disconnect_all_callback(struct db_record *local_rec,
						void *private_data)
{
	struct smbXsrv_tcon_disconnect_all_state *state =
		(struct smbXsrv_tcon_disconnect_all_state *)private_data;
	TDB_DATA val;
	void *ptr = NULL;
	struct smbXsrv_tcon *tcon = NULL;
	uint64_t vuid;
	NTSTATUS status;

	val = dbwrap_record_get_value(local_rec);
	if (val.dsize != sizeof(ptr)) {
		status = NT_STATUS_INTERNAL_ERROR;
		if (NT_STATUS_IS_OK(state->first_status)) {
			state->first_status = status;
		}
		state->errors++;
		return 0;
	}

	memcpy(&ptr, val.dptr, val.dsize);
	tcon = talloc_get_type_abort(ptr, struct smbXsrv_tcon);

	vuid = state->vuid;
	if (vuid == 0 && tcon->compat) {
		vuid = tcon->compat->vuid;
	}

	tcon->db_rec = local_rec;
	status = smbXsrv_tcon_disconnect(tcon, vuid);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_IS_OK(state->first_status)) {
			state->first_status = status;
		}
		state->errors++;
		return 0;
	}

	return 0;
}

NTSTATUS smb1srv_tcon_table_init(struct smbXsrv_connection *conn)
{
	struct smbXsrv_client *client = conn->client;

	/*
	 * Allow a range from 1..65534 with 65534 values.
	 */
	client->tcon_table = talloc_zero(client, struct smbXsrv_tcon_table);
	if (client->tcon_table == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return smbXsrv_tcon_table_init(client, client->tcon_table,
				       1, UINT16_MAX - 1,
				       UINT16_MAX - 1);
}

NTSTATUS smb1srv_tcon_create(struct smbXsrv_connection *conn,
			     NTTIME now,
			     struct smbXsrv_tcon **_tcon)
{
	struct server_id id = messaging_server_id(conn->client->msg_ctx);

	return smbXsrv_tcon_create(conn->client->tcon_table,
				   conn->protocol,
				   id, now, _tcon);
}

NTSTATUS smb1srv_tcon_lookup(struct smbXsrv_connection *conn,
			     uint16_t tree_id, NTTIME now,
			     struct smbXsrv_tcon **tcon)
{
	uint32_t local_id = tree_id;

	return smbXsrv_tcon_local_lookup(conn->client->tcon_table,
					 local_id, now, tcon);
}

NTSTATUS smb1srv_tcon_disconnect_all(struct smbXsrv_client *client)
{

	/*
	 * We do not pass a vuid here,
	 * which means the vuid is taken from
	 * the tcon->compat->vuid.
	 *
	 * NOTE: that tcon->compat->vuid may point to
	 * a none existing vuid (or the wrong one)
	 * as the tcon can exist without a session
	 * in SMB1.
	 *
	 * This matches the old behavior of
	 * conn_close_all(), but we should think
	 * about how to fix this in future.
	 */
	return smbXsrv_tcon_disconnect_all(client->tcon_table, 0);
}

NTSTATUS smb2srv_tcon_table_init(struct smbXsrv_session *session)
{
	/*
	 * Allow a range from 1..4294967294 with 65534 (same as SMB1) values.
	 */
	session->tcon_table = talloc_zero(session, struct smbXsrv_tcon_table);
	if (session->tcon_table == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return smbXsrv_tcon_table_init(session, session->tcon_table,
				       1, UINT32_MAX - 1,
				       UINT16_MAX - 1);
}

NTSTATUS smb2srv_tcon_create(struct smbXsrv_session *session,
			     NTTIME now,
			     struct smbXsrv_tcon **_tcon)
{
	struct server_id id = messaging_server_id(session->client->msg_ctx);

	return smbXsrv_tcon_create(session->tcon_table,
				   PROTOCOL_SMB2_02,
				   id, now, _tcon);
}

NTSTATUS smb2srv_tcon_lookup(struct smbXsrv_session *session,
			     uint32_t tree_id, NTTIME now,
			     struct smbXsrv_tcon **tcon)
{
	uint32_t local_id = tree_id;

	return smbXsrv_tcon_local_lookup(session->tcon_table,
					 local_id, now, tcon);
}

NTSTATUS smb2srv_tcon_disconnect_all(struct smbXsrv_session *session)
{
	uint64_t vuid = session->global->session_wire_id;

	return smbXsrv_tcon_disconnect_all(session->tcon_table, vuid);
}

struct smbXsrv_tcon_global_traverse_state {
	int (*fn)(struct smbXsrv_tcon_global0 *, void *);
	void *private_data;
};

static int smbXsrv_tcon_global_traverse_fn(struct db_record *rec, void *data)
{
	int ret = -1;
	struct smbXsrv_tcon_global_traverse_state *state =
		(struct smbXsrv_tcon_global_traverse_state*)data;
	TDB_DATA key = dbwrap_record_get_key(rec);
	TDB_DATA val = dbwrap_record_get_value(rec);
	DATA_BLOB blob = data_blob_const(val.dptr, val.dsize);
	struct smbXsrv_tcon_globalB global_blob;
	enum ndr_err_code ndr_err;
	TALLOC_CTX *frame = talloc_stackframe();

	ndr_err = ndr_pull_struct_blob(&blob, frame, &global_blob,
			(ndr_pull_flags_fn_t)ndr_pull_smbXsrv_tcon_globalB);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(1,("Invalid record in smbXsrv_tcon_global.tdb:"
			 "key '%s' ndr_pull_struct_blob - %s\n",
			 hex_encode_talloc(frame, key.dptr, key.dsize),
			 ndr_errstr(ndr_err)));
		goto done;
	}

	if (global_blob.version != SMBXSRV_VERSION_0) {
		DEBUG(1,("Invalid record in smbXsrv_tcon_global.tdb:"
			 "key '%s' unsupported version - %d\n",
			 hex_encode_talloc(frame, key.dptr, key.dsize),
			 (int)global_blob.version));
		goto done;
	}

	if (global_blob.info.info0 == NULL) {
		DEBUG(1,("Invalid record in smbXsrv_tcon_global.tdb:"
			 "key '%s' info0 NULL pointer\n",
			 hex_encode_talloc(frame, key.dptr, key.dsize)));
		goto done;
	}

	global_blob.info.info0->db_rec = rec;
	ret = state->fn(global_blob.info.info0, state->private_data);
done:
	TALLOC_FREE(frame);
	return ret;
}

NTSTATUS smbXsrv_tcon_global_traverse(
			int (*fn)(struct smbXsrv_tcon_global0 *, void *),
			void *private_data)
{
	NTSTATUS status;
	int count = 0;
	struct smbXsrv_tcon_global_traverse_state state = {
		.fn = fn,
		.private_data = private_data,
	};

	become_root();
	status = smbXsrv_tcon_global_init();
	if (!NT_STATUS_IS_OK(status)) {
		unbecome_root();
		DEBUG(0, ("Failed to initialize tcon_global: %s\n",
			  nt_errstr(status)));
		return status;
	}

	status = dbwrap_traverse_read(smbXsrv_tcon_global_db_ctx,
				      smbXsrv_tcon_global_traverse_fn,
				      &state,
				      &count);
	unbecome_root();

	return status;
}
