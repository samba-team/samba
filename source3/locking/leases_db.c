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
	if (leases_db) {
		return true;
	}

	leases_db = db_open(NULL, lock_path("leases.tdb"), 0,
			    TDB_DEFAULT|TDB_VOLATILE|TDB_CLEAR_IF_FIRST|
			    TDB_INCOMPATIBLE_HASH,
			    read_only ? O_RDONLY : O_RDWR|O_CREAT, 0644,
			    DBWRAP_LOCK_ORDER_2, DBWRAP_FLAG_NONE);

	if (leases_db == NULL) {
		DEBUG(1, ("ERROR: Failed to initialise leases database\n"));
		return false;
	}

	return true;
}

static bool leases_db_key(TALLOC_CTX *mem_ctx,
			  const struct GUID *client_guid,
			  const struct smb2_lease_key *lease_key,
			  TDB_DATA *key)
{
	struct leases_db_key db_key = {
		.client_guid = *client_guid,
		.lease_key = *lease_key };
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;

	if (DEBUGLEVEL >= 10) {
		DEBUG(10, ("%s:\n", __func__));
		NDR_PRINT_DEBUG(leases_db_key, &db_key);
	}

	ndr_err = ndr_push_struct_blob(
		&blob, mem_ctx, &db_key,
		(ndr_push_flags_fn_t)ndr_push_leases_db_key);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(10, ("%s: ndr_push_struct_blob_failed: %s\n",
			   __func__, ndr_errstr(ndr_err)));
		return false;
	}

	*key = make_tdb_data(blob.data, blob.length);
	return true;
}

NTSTATUS leases_db_add(const struct GUID *client_guid,
		       const struct smb2_lease_key *lease_key,
		       const struct file_id *id,
		       const char *servicepath,
		       const char *base_name,
		       const char *stream_name)
{
	TDB_DATA db_key, db_value;
	DATA_BLOB blob;
	struct db_record *rec;
	NTSTATUS status;
	bool ok;
	struct leases_db_value new_value;
	struct leases_db_file new_file;
	struct leases_db_value *value = NULL;
	enum ndr_err_code ndr_err;

	if (!leases_db_init(false)) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	ok = leases_db_key(talloc_tos(), client_guid, lease_key, &db_key);
	if (!ok) {
		DEBUG(10, ("%s: leases_db_key failed\n", __func__));
		return NT_STATUS_NO_MEMORY;
	}

	rec = dbwrap_fetch_locked(leases_db, talloc_tos(), db_key);
	TALLOC_FREE(db_key.dptr);
	if (rec == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	db_value = dbwrap_record_get_value(rec);
	if (db_value.dsize != 0) {
		uint32_t i;

		DEBUG(10, ("%s: record exists\n", __func__));

		value = talloc(talloc_tos(), struct leases_db_value);
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

		/* id must be unique. */
		for (i = 0; i < value->num_files; i++) {
			if (file_id_equal(id, &value->files[i].id)) {
				status = NT_STATUS_OBJECT_NAME_COLLISION;
				goto out;
			}
		}

		value->files = talloc_realloc(value, value->files,
					struct leases_db_file,
					value->num_files + 1);
		if (value->files == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
		value->files[value->num_files].id = *id;
		value->files[value->num_files].servicepath = servicepath;
		value->files[value->num_files].base_name = base_name;
		value->files[value->num_files].stream_name = stream_name;
		value->num_files += 1;

	} else {
		DEBUG(10, ("%s: new record\n", __func__));

		new_file = (struct leases_db_file) {
			.id = *id,
			.servicepath = servicepath,
			.base_name = base_name,
			.stream_name = stream_name,
		};

		new_value = (struct leases_db_value) {
			.num_files = 1,
			.files = &new_file,
		};
		value = &new_value;
	}

	ndr_err = ndr_push_struct_blob(
		&blob, talloc_tos(), value,
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

  out:

	if (value != &new_value) {
		TALLOC_FREE(value);
	}
	TALLOC_FREE(rec);
	return status;
}

NTSTATUS leases_db_del(const struct GUID *client_guid,
		       const struct smb2_lease_key *lease_key,
		       const struct file_id *id)
{
	TDB_DATA db_key, db_value;
	struct db_record *rec;
	NTSTATUS status;
	struct leases_db_value *value;
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;
	uint32_t i;
	bool ok;

	if (!leases_db_init(false)) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	ok = leases_db_key(talloc_tos(), client_guid, lease_key, &db_key);
	if (!ok) {
		return NT_STATUS_NO_MEMORY;
	}

	rec = dbwrap_fetch_locked(leases_db, talloc_tos(), db_key);
	TALLOC_FREE(db_key.dptr);
	if (rec == NULL) {
		return NT_STATUS_NOT_FOUND;
	}
	db_value = dbwrap_record_get_value(rec);
	if (db_value.dsize == 0) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto out;
	}

	value = talloc(talloc_tos(), struct leases_db_value);
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
			&blob, talloc_tos(), value,
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

	TALLOC_FREE(value);
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
	TDB_DATA db_key;
	struct leases_db_fetch_state state;
	NTSTATUS status;
	bool ok;

	if (!leases_db_init(true)) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	ok = leases_db_key(talloc_tos(), client_guid, lease_key, &db_key);
	if (!ok) {
		return NT_STATUS_NO_MEMORY;
	}

	state = (struct leases_db_fetch_state) {
		.parser = parser,
		.private_data = private_data,
		.status = NT_STATUS_OK
	};

	status = dbwrap_parse_record(leases_db, db_key, leases_db_parser,
				     &state);
	TALLOC_FREE(db_key.dptr);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return state.status;
}

NTSTATUS leases_db_rename(const struct GUID *client_guid,
		       const struct smb2_lease_key *lease_key,
		       const struct file_id *id,
		       const char *servicename_new,
		       const char *filename_new,
		       const char *stream_name_new)
{
	NTSTATUS status;

	status = leases_db_del(client_guid,
				lease_key,
				id);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return leases_db_add(client_guid,
				lease_key,
				id,
				servicename_new,
				filename_new,
				stream_name_new);
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
