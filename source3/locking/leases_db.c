/*
   Unix SMB/CIFS implementation.
   Map lease keys to file ids
   Copyright (C) Volker Lendecke 2013

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
#include "locking/leases_db.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "util_tdb.h"
#include "ndr.h"
#include "librpc/gen_ndr/ndr_leases_db.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

/* the leases database handle */
static struct db_context *leases_db;

bool leases_db_init(bool read_only)
{
	char *db_path;

	if (leases_db) {
		return true;
	}

	db_path = lock_path(talloc_tos(), "leases.tdb");
	if (db_path == NULL) {
		return false;
	}

	leases_db = db_open(NULL, db_path, 0,
			    TDB_DEFAULT|
			    TDB_VOLATILE|
			    TDB_CLEAR_IF_FIRST|
			    TDB_SEQNUM|
			    TDB_INCOMPATIBLE_HASH,
			    read_only ? O_RDONLY : O_RDWR|O_CREAT, 0644,
			    DBWRAP_LOCK_ORDER_4, DBWRAP_FLAG_NONE);
	TALLOC_FREE(db_path);
	if (leases_db == NULL) {
		DEBUG(1, ("ERROR: Failed to initialise leases database\n"));
		return false;
	}

	return true;
}

struct leases_db_key_buf {
	uint8_t buf[32];
};

static TDB_DATA leases_db_key(struct leases_db_key_buf *buf,
			      const struct GUID *client_guid,
			      const struct smb2_lease_key *lease_key)
{
	struct leases_db_key db_key = {
		.client_guid = *client_guid,
		.lease_key = *lease_key };
	DATA_BLOB blob = { .data = buf->buf, .length = sizeof(buf->buf) };
	enum ndr_err_code ndr_err;

	if (DEBUGLEVEL >= 10) {
		DBG_DEBUG("\n");
		NDR_PRINT_DEBUG(leases_db_key, &db_key);
	}

	ndr_err = ndr_push_struct_into_fixed_blob(
		&blob, &db_key, (ndr_push_flags_fn_t)ndr_push_leases_db_key);
	SMB_ASSERT(NDR_ERR_CODE_IS_SUCCESS(ndr_err));

	return (TDB_DATA) { .dptr = buf->buf, .dsize = sizeof(buf->buf) };
}

struct leases_db_do_locked_state {
	void (*fn)(struct leases_db_value *value,
		   bool *modified,
		   void *private_data);
	void *private_data;
	NTSTATUS status;
};

static void leases_db_do_locked_fn(
	struct db_record *rec,
	TDB_DATA db_value,
	void *private_data)
{
	struct leases_db_do_locked_state *state = private_data;
	DATA_BLOB blob = { .data = db_value.dptr, .length = db_value.dsize };
	struct leases_db_value *value = NULL;
	enum ndr_err_code ndr_err;
	bool modified = false;

	value = talloc_zero(talloc_tos(), struct leases_db_value);
	if (value == NULL) {
		state->status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	if (blob.length != 0) {
		ndr_err = ndr_pull_struct_blob_all(
			&blob,
			value,
			value,
			(ndr_pull_flags_fn_t)ndr_pull_leases_db_value);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DBG_ERR("ndr_pull_struct_blob_failed: %s\n",
				  ndr_errstr(ndr_err));
			state->status = ndr_map_error2ntstatus(ndr_err);
			goto done;
		}
	}

	state->fn(value, &modified, state->private_data);

	if (!modified) {
		goto done;
	}

	if (value->num_files == 0) {
		state->status = dbwrap_record_delete(rec);
		if (!NT_STATUS_IS_OK(state->status)) {
			DBG_ERR("dbwrap_record_delete returned %s\n",
				  nt_errstr(state->status));
		}
		goto done;
	}

	ndr_err = ndr_push_struct_blob(
		&blob,
		value,
		value,
		(ndr_push_flags_fn_t)ndr_push_leases_db_value);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_ERR("ndr_push_struct_blob_failed: %s\n",
			  ndr_errstr(ndr_err));
		state->status = ndr_map_error2ntstatus(ndr_err);
		goto done;
	}

	if (DEBUGLEVEL >= 10) {
		DBG_DEBUG("\n");
		NDR_PRINT_DEBUG(leases_db_value, value);
	}

	db_value = make_tdb_data(blob.data, blob.length);

	state->status = dbwrap_record_store(rec, db_value, 0);
	if (!NT_STATUS_IS_OK(state->status)) {
		DBG_ERR("dbwrap_record_store returned %s\n",
			  nt_errstr(state->status));
	}

done:
	TALLOC_FREE(value);
}

static NTSTATUS leases_db_do_locked(
	const struct GUID *client_guid,
	const struct smb2_lease_key *lease_key,
	void (*fn)(struct leases_db_value *value,
		   bool *modified,
		   void *private_data),
	void *private_data)
{
	struct leases_db_key_buf keybuf;
	TDB_DATA db_key = leases_db_key(&keybuf, client_guid, lease_key);
	struct leases_db_do_locked_state state = {
		.fn = fn, .private_data = private_data,
	};
	NTSTATUS status;

	if (!leases_db_init(false)) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	status = dbwrap_do_locked(
		leases_db, db_key, leases_db_do_locked_fn, &state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return state.status;
}

struct leases_db_add_state {
	const struct file_id *id;
	uint32_t current_state;
	uint16_t lease_version;
	uint16_t epoch;
	const char *servicepath;
	const char *base_name;
	const char *stream_name;
	NTSTATUS status;
};

static void leases_db_add_fn(
	struct leases_db_value *value, bool *modified, void *private_data)
{
	struct leases_db_add_state *state = private_data;
	struct leases_db_file *tmp = NULL;
	uint32_t i;

	/* id must be unique. */
	for (i = 0; i < value->num_files; i++) {
		if (file_id_equal(state->id, &value->files[i].id)) {
			state->status = NT_STATUS_OBJECT_NAME_COLLISION;
			return;
		}
	}

	if (value->num_files == 0) {
		/* new record */
		value->current_state = state->current_state;
		value->lease_version = state->lease_version;
		value->epoch = state->epoch;
	}

	tmp = talloc_realloc(
		value,
		value->files,
		struct leases_db_file,
		value->num_files + 1);
	if (tmp == NULL) {
		state->status = NT_STATUS_NO_MEMORY;
		return;
	}
	value->files = tmp;

	value->files[value->num_files] = (struct leases_db_file) {
		.id = *state->id,
		.servicepath = state->servicepath,
		.base_name = state->base_name,
		.stream_name = state->stream_name,
	};
	value->num_files += 1;

	*modified = true;
}

NTSTATUS leases_db_add(const struct GUID *client_guid,
		       const struct smb2_lease_key *lease_key,
		       const struct file_id *id,
		       uint32_t current_state,
		       uint16_t lease_version,
		       uint16_t epoch,
		       const char *servicepath,
		       const char *base_name,
		       const char *stream_name)
{
	struct leases_db_add_state state = {
		.id = id,
		.current_state = current_state,
		.lease_version = lease_version,
		.epoch = epoch,
		.servicepath = servicepath,
		.base_name = base_name,
		.stream_name = stream_name,
	};
	NTSTATUS status;

	status = leases_db_do_locked(
		client_guid, lease_key, leases_db_add_fn, &state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("leases_db_do_locked failed: %s\n",
			  nt_errstr(status));
		return status;
	}
	return state.status;
}

struct leases_db_del_state {
	const struct file_id *id;
	NTSTATUS status;
};

static void leases_db_del_fn(
	struct leases_db_value *value, bool *modified, void *private_data)
{
	struct leases_db_del_state *state = private_data;
	uint32_t i;

	for (i = 0; i < value->num_files; i++) {
		if (file_id_equal(state->id, &value->files[i].id)) {
			break;
		}
	}
	if (i == value->num_files) {
		state->status = NT_STATUS_NOT_FOUND;
		return;
	}

	value->files[i] = value->files[value->num_files-1];
	value->num_files -= 1;

	*modified = true;
}

NTSTATUS leases_db_del(const struct GUID *client_guid,
		       const struct smb2_lease_key *lease_key,
		       const struct file_id *id)
{
	struct leases_db_del_state state = { .id = id };
	NTSTATUS status;

	status = leases_db_do_locked(
		client_guid, lease_key, leases_db_del_fn, &state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("leases_db_do_locked failed: %s\n",
			  nt_errstr(status));
		return status;
	}
	return state.status;
}

struct leases_db_fetch_state {
	void (*parser)(uint32_t num_files,
			const struct leases_db_file *files,
			void *private_data);
	void *private_data;
	NTSTATUS status;
};

static void leases_db_parser(TDB_DATA key, TDB_DATA data, void *private_data)
{
	struct leases_db_fetch_state *state =
		(struct leases_db_fetch_state *)private_data;
	DATA_BLOB blob = { .data = data.dptr, .length = data.dsize };
	enum ndr_err_code ndr_err;
	struct leases_db_value *value;

	value = talloc(talloc_tos(), struct leases_db_value);
	if (value == NULL) {
		state->status = NT_STATUS_NO_MEMORY;
		return;
	}

	ndr_err = ndr_pull_struct_blob_all(
		&blob, value, value,
		(ndr_pull_flags_fn_t)ndr_pull_leases_db_value);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(10, ("%s: ndr_pull_struct_blob_failed: %s\n",
			   __func__, ndr_errstr(ndr_err)));
		TALLOC_FREE(value);
		state->status = ndr_map_error2ntstatus(ndr_err);
		return;
	}

	if (DEBUGLEVEL >= 10) {
		DEBUG(10, ("%s:\n", __func__));
		NDR_PRINT_DEBUG(leases_db_value, value);
	}

	state->parser(value->num_files,
			value->files,
			state->private_data);

	TALLOC_FREE(value);
	state->status = NT_STATUS_OK;
}

NTSTATUS leases_db_parse(const struct GUID *client_guid,
			 const struct smb2_lease_key *lease_key,
			 void (*parser)(uint32_t num_files,
					const struct leases_db_file *files,
					void *private_data),
			 void *private_data)
{
	struct leases_db_key_buf keybuf;
	TDB_DATA db_key = leases_db_key(&keybuf, client_guid, lease_key);
	struct leases_db_fetch_state state;
	NTSTATUS status;

	if (!leases_db_init(true)) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	state = (struct leases_db_fetch_state) {
		.parser = parser,
		.private_data = private_data,
		.status = NT_STATUS_OK
	};

	status = dbwrap_parse_record(leases_db, db_key, leases_db_parser,
				     &state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return state.status;
}

struct leases_db_rename_state {
	const struct file_id *id;
	const char *servicename_new;
	const char *filename_new;
	const char *stream_name_new;
	NTSTATUS status;
};

static void leases_db_rename_fn(
	struct leases_db_value *value, bool *modified, void *private_data)
{
	struct leases_db_rename_state *state = private_data;
	struct leases_db_file *file = NULL;
	uint32_t i;

	/* id must exist. */
	for (i = 0; i < value->num_files; i++) {
		if (file_id_equal(state->id, &value->files[i].id)) {
			break;
		}
	}
	if (i == value->num_files) {
		state->status = NT_STATUS_NOT_FOUND;
		return;
	}

	file = &value->files[i];
	file->servicepath = state->servicename_new;
	file->base_name = state->filename_new;
	file->stream_name = state->stream_name_new;

	*modified = true;
}

NTSTATUS leases_db_rename(const struct GUID *client_guid,
		       const struct smb2_lease_key *lease_key,
		       const struct file_id *id,
		       const char *servicename_new,
		       const char *filename_new,
		       const char *stream_name_new)
{
	struct leases_db_rename_state state = {
		.id = id,
		.servicename_new = servicename_new,
		.filename_new = filename_new,
		.stream_name_new = stream_name_new,
	};
	NTSTATUS status;

	status = leases_db_do_locked(
		client_guid, lease_key, leases_db_rename_fn, &state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("leases_db_do_locked failed: %s\n",
			  nt_errstr(status));
		return status;
	}
	return state.status;
}

struct leases_db_set_state {
	uint32_t current_state;
	bool breaking;
	uint32_t breaking_to_requested;
	uint32_t breaking_to_required;
	uint16_t lease_version;
	uint16_t epoch;
};

static void leases_db_set_fn(
	struct leases_db_value *value, bool *modified, void *private_data)
{
	struct leases_db_set_state *state = private_data;

	if (value->num_files == 0) {
		DBG_WARNING("leases_db_set on new entry\n");
		return;
	}
	value->current_state = state->current_state;
	value->breaking = state->breaking;
	value->breaking_to_requested = state->breaking_to_requested;
	value->breaking_to_required = state->breaking_to_required;
	value->lease_version = state->lease_version;
	value->epoch = state->epoch;
	*modified = true;
}

NTSTATUS leases_db_set(const struct GUID *client_guid,
		       const struct smb2_lease_key *lease_key,
		       uint32_t current_state,
		       bool breaking,
		       uint32_t breaking_to_requested,
		       uint32_t	breaking_to_required,
		       uint16_t lease_version,
		       uint16_t epoch)
{
	struct leases_db_set_state state = {
		.current_state = current_state,
		.breaking = breaking,
		.breaking_to_requested = breaking_to_requested,
		.breaking_to_required = breaking_to_required,
		.lease_version = lease_version,
		.epoch = epoch,
	};
	NTSTATUS status;

	status = leases_db_do_locked(
		client_guid, lease_key, leases_db_set_fn, &state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("leases_db_do_locked failed: %s\n",
			  nt_errstr(status));
		return status;
	}
	return NT_STATUS_OK;
}

struct leases_db_get_state {
	const struct file_id *file_id;
	uint32_t *current_state;
	bool *breaking;
	uint32_t *breaking_to_requested;
	uint32_t *breaking_to_required;
	uint16_t *lease_version;
	uint16_t *epoch;
	NTSTATUS status;
};

static void leases_db_get_fn(TDB_DATA key, TDB_DATA data, void *private_data)
{
	struct leases_db_get_state *state = private_data;
	DATA_BLOB blob = { .data = data.dptr, .length = data.dsize };
	enum ndr_err_code ndr_err;
	struct leases_db_value *value;
	uint32_t i;

	value = talloc(talloc_tos(), struct leases_db_value);
	if (value == NULL) {
		state->status = NT_STATUS_NO_MEMORY;
		return;
	}

	ndr_err = ndr_pull_struct_blob_all(
		&blob, value, value,
		(ndr_pull_flags_fn_t)ndr_pull_leases_db_value);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_ERR("ndr_pull_struct_blob_failed: %s\n",
			ndr_errstr(ndr_err));
		TALLOC_FREE(value);
		state->status = ndr_map_error2ntstatus(ndr_err);
		return;
	}

	if (DEBUGLEVEL >= 10) {
		DBG_DEBUG("\n");
		NDR_PRINT_DEBUG(leases_db_value, value);
	}

	/* id must exist. */
	for (i = 0; i < value->num_files; i++) {
		if (file_id_equal(state->file_id, &value->files[i].id)) {
			break;
		}
	}

	if (i == value->num_files) {
		state->status = NT_STATUS_NOT_FOUND;
		TALLOC_FREE(value);
		return;
	}

	if (state->current_state != NULL) {
		*state->current_state = value->current_state;
	};
	if (state->breaking != NULL) {
		*state->breaking = value->breaking;
	};
	if (state->breaking_to_requested != NULL) {
		*state->breaking_to_requested = value->breaking_to_requested;
	};
	if (state->breaking_to_required != NULL) {
		*state->breaking_to_required = value->breaking_to_required;
	};
	if (state->lease_version != NULL) {
		*state->lease_version = value->lease_version;
	};
	if (state->epoch != NULL) {
		*state->epoch = value->epoch;
	};

	TALLOC_FREE(value);
	state->status = NT_STATUS_OK;
}

NTSTATUS leases_db_get(const struct GUID *client_guid,
		       const struct smb2_lease_key *lease_key,
		       const struct file_id *file_id,
		       uint32_t *current_state,
		       bool *breaking,
		       uint32_t *breaking_to_requested,
		       uint32_t	*breaking_to_required,
		       uint16_t *lease_version,
		       uint16_t *epoch)
{
	struct leases_db_get_state state = {
		.file_id = file_id,
		.current_state = current_state,
		.breaking = breaking,
		.breaking_to_requested = breaking_to_requested,
		.breaking_to_required = breaking_to_required,
		.lease_version = lease_version,
		.epoch = epoch,
	};
	struct leases_db_key_buf keybuf;
	TDB_DATA db_key = leases_db_key(&keybuf, client_guid, lease_key);
	NTSTATUS status;

	if (!leases_db_init(true)) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	status = dbwrap_parse_record(
		leases_db, db_key, leases_db_get_fn, &state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return state.status;
}

struct leases_db_get_current_state_state {
	int seqnum;
	uint32_t current_state;
	NTSTATUS status;
};

/*
 * This function is an optimization that
 * relies on the fact that the
 * smb2_lease_state current_state
 * (which is a uint32_t size)
 * from struct leases_db_value is the first
 * entry in the ndr-encoded struct leases_db_value.
 * Read it without having to ndr decode all
 * the values in struct leases_db_value.
 */

static void leases_db_get_current_state_fn(
	TDB_DATA key, TDB_DATA data, void *private_data)
{
	struct leases_db_get_current_state_state *state = private_data;
	struct ndr_pull ndr;
	enum ndr_err_code ndr_err;

	if (data.dsize < sizeof(uint32_t)) {
		state->status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		return;
	}

	state->seqnum = dbwrap_get_seqnum(leases_db);

	ndr = (struct ndr_pull) {
		.data = data.dptr, .data_size = data.dsize,
	};
	ndr_err = ndr_pull_uint32(&ndr, NDR_SCALARS, &state->current_state);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		state->status = ndr_map_error2ntstatus(ndr_err);
	}
}

NTSTATUS leases_db_get_current_state(
	const struct GUID *client_guid,
	const struct smb2_lease_key *lease_key,
	int *database_seqnum,
	uint32_t *current_state)
{
	struct leases_db_get_current_state_state state = { 0 };
	struct leases_db_key_buf keybuf;
	TDB_DATA db_key = { 0 };
	NTSTATUS status;

	if (!leases_db_init(true)) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	state.seqnum = dbwrap_get_seqnum(leases_db);
	if (*database_seqnum == state.seqnum) {
		return NT_STATUS_OK;
	}

	db_key = leases_db_key(&keybuf, client_guid, lease_key);

	status = dbwrap_parse_record(
		leases_db, db_key, leases_db_get_current_state_fn, &state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	*database_seqnum = state.seqnum;
	*current_state = state.current_state;

	return NT_STATUS_OK;
}

NTSTATUS leases_db_copy_file_ids(TALLOC_CTX *mem_ctx,
			uint32_t num_files,
			const struct leases_db_file *files,
			struct file_id **pp_ids)
{
	uint32_t i;
	struct file_id *ids = talloc_array(mem_ctx,
				struct file_id,
				num_files);
	if (ids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < num_files; i++) {
		ids[i] = files[i].id;
	}
	*pp_ids = ids;
	return NT_STATUS_OK;
}
