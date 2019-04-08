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
			    TDB_DEFAULT|TDB_VOLATILE|TDB_CLEAR_IF_FIRST|
			    TDB_INCOMPATIBLE_HASH,
			    read_only ? O_RDONLY : O_RDWR|O_CREAT, 0644,
			    DBWRAP_LOCK_ORDER_2, DBWRAP_FLAG_NONE);
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

static void leases_db_do_locked_fn(struct db_record *rec, void *private_data)
{
	struct leases_db_do_locked_state *state = private_data;
	TDB_DATA db_value = dbwrap_record_get_value(rec);
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
			DBG_DEBUG("ndr_pull_struct_blob_failed: %s\n",
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
			DBG_DEBUG("dbwrap_record_delete returned %s\n",
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
		DBG_DEBUG("ndr_push_struct_blob_failed: %s\n",
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
		DBG_DEBUG("dbwrap_record_store returned %s\n",
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
		       const char *servicepath,
		       const char *base_name,
		       const char *stream_name)
{
	struct leases_db_add_state state = {
		.id = id,
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

NTSTATUS leases_db_del(const struct GUID *client_guid,
		       const struct smb2_lease_key *lease_key,
		       const struct file_id *id)
{
	struct leases_db_key_buf keybuf;
	TDB_DATA db_key = leases_db_key(&keybuf, client_guid, lease_key);
	TDB_DATA db_value;
	struct db_record *rec;
	NTSTATUS status;
	struct leases_db_value *value;
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;
	uint32_t i;

	if (!leases_db_init(false)) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	rec = dbwrap_fetch_locked(leases_db, talloc_tos(), db_key);
	if (rec == NULL) {
		return NT_STATUS_NOT_FOUND;
	}
	db_value = dbwrap_record_get_value(rec);
	if (db_value.dsize == 0) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto out;
	}

	value = talloc(rec, struct leases_db_value);
	if (value == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	blob.data = db_value.dptr;
	blob.length = db_value.dsize;

	ndr_err = ndr_pull_struct_blob_all(
		&blob, value, value,
		(ndr_pull_flags_fn_t)ndr_pull_leases_db_value);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(10, ("%s: ndr_pull_struct_blob_failed: %s\n",
			   __func__, ndr_errstr(ndr_err)));
		status = ndr_map_error2ntstatus(ndr_err);
		goto out;
	}

	/* id must exist. */
	for (i = 0; i < value->num_files; i++) {
		if (file_id_equal(id, &value->files[i].id)) {
			break;
		}
	}

	if (i == value->num_files) {
		status = NT_STATUS_NOT_FOUND;
		goto out;
	}

	value->files[i] = value->files[value->num_files-1];
	value->num_files -= 1;

	if (value->num_files == 0) {
		DEBUG(10, ("%s: deleting record\n", __func__));
		status = dbwrap_record_delete(rec);
	} else {
		DEBUG(10, ("%s: updating record\n", __func__));
		ndr_err = ndr_push_struct_blob(
			&blob, rec, value,
			(ndr_push_flags_fn_t)ndr_push_leases_db_value);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DEBUG(10, ("%s: ndr_push_struct_blob_failed: %s\n",
				   __func__, ndr_errstr(ndr_err)));
			status = ndr_map_error2ntstatus(ndr_err);
			goto out;
		}

		if (DEBUGLEVEL >= 10) {
			DEBUG(10, ("%s:\n", __func__));
			NDR_PRINT_DEBUG(leases_db_value, value);
		}

		db_value = make_tdb_data(blob.data, blob.length);

		status = dbwrap_record_store(rec, db_value, 0);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("%s: dbwrap_record_store returned %s\n",
				   __func__, nt_errstr(status)));
		}
	}

  out:

	TALLOC_FREE(rec);
	return status;
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
