/* 
   Unix SMB/CIFS implementation.
   Utility functions for the dbwrap API
   Copyright (C) Volker Lendecke 2007
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

int32_t dbwrap_fetch_int32(struct db_context *db, const char *keystr)
{
	TDB_DATA dbuf;
	int32 ret;

	if (db->fetch(db, NULL, string_term_tdb_data(keystr), &dbuf) != 0) {
		return -1;
	}

	if ((dbuf.dptr == NULL) || (dbuf.dsize != sizeof(int32_t))) {
		TALLOC_FREE(dbuf.dptr);
		return -1;
	}

	ret = IVAL(dbuf.dptr, 0);
	TALLOC_FREE(dbuf.dptr);
	return ret;
}

int dbwrap_store_int32(struct db_context *db, const char *keystr, int32_t v)
{
	struct db_record *rec;
	int32 v_store;
	NTSTATUS status;

	rec = db->fetch_locked(db, NULL, string_term_tdb_data(keystr));
	if (rec == NULL) {
		return -1;
	}

	SIVAL(&v_store, 0, v);

	status = rec->store(rec, make_tdb_data((const uint8 *)&v_store,
					       sizeof(v_store)),
			    TDB_REPLACE);
	TALLOC_FREE(rec);
	return NT_STATUS_IS_OK(status) ? 0 : -1;
}

bool dbwrap_fetch_uint32(struct db_context *db, const char *keystr,
			 uint32_t *val)
{
	TDB_DATA dbuf;

	if (db->fetch(db, NULL, string_term_tdb_data(keystr), &dbuf) != 0) {
		return false;
	}

	if ((dbuf.dptr == NULL) || (dbuf.dsize != sizeof(uint32_t))) {
		TALLOC_FREE(dbuf.dptr);
		return false;
	}

	*val = IVAL(dbuf.dptr, 0);
	TALLOC_FREE(dbuf.dptr);
	return true;
}

bool dbwrap_store_uint32(struct db_context *db, const char *keystr, uint32_t v)
{
	struct db_record *rec;
	uint32 v_store;
	NTSTATUS status;

	rec = db->fetch_locked(db, NULL, string_term_tdb_data(keystr));
	if (rec == NULL) {
		return false;
	}

	SIVAL(&v_store, 0, v);

	status = rec->store(rec, make_tdb_data((const uint8 *)&v_store,
					       sizeof(v_store)),
			    TDB_REPLACE);
	TALLOC_FREE(rec);
	return NT_STATUS_IS_OK(status) ? 0 : -1;
}

/**
 * Atomic unsigned integer change (addition):
 *
 * if value does not exist yet in the db, use *oldval as initial old value.
 * return old value in *oldval.
 * store *oldval + change_val to db.
 */
uint32_t dbwrap_change_uint32_atomic(struct db_context *db, const char *keystr,
				     uint32_t *oldval, uint32_t change_val)
{
	struct db_record *rec;
	uint32 val = -1;
	TDB_DATA data;

	if (!(rec = db->fetch_locked(db, NULL,
				     string_term_tdb_data(keystr)))) {
		return -1;
	}

	if (rec->value.dptr == NULL) {
		val = *oldval;
	} else if (rec->value.dsize == sizeof(val)) {
		val = IVAL(rec->value.dptr, 0);
		*oldval = val;
	} else {
		return -1;
	}

	val += change_val;

	data.dsize = sizeof(val);
	data.dptr = (uint8 *)&val;

	rec->store(rec, data, TDB_REPLACE);

	TALLOC_FREE(rec);

	return 0;
}

/**
 * Atomic integer change (addition):
 *
 * if value does not exist yet in the db, use *oldval as initial old value.
 * return old value in *oldval.
 * store *oldval + change_val to db.
 */
int32 dbwrap_change_int32_atomic(struct db_context *db, const char *keystr,
				 int32 *oldval, int32 change_val)
{
	struct db_record *rec;
	int32 val = -1;
	TDB_DATA data;

	if (!(rec = db->fetch_locked(db, NULL,
				     string_term_tdb_data(keystr)))) {
		return -1;
	}

	if (rec->value.dptr == NULL) {
		val = *oldval;
	} else if (rec->value.dsize == sizeof(val)) {
		val = IVAL(rec->value.dptr, 0);
		*oldval = val;
	} else {
		return -1;
	}

	val += change_val;

	data.dsize = sizeof(val);
	data.dptr = (uint8 *)&val;

	rec->store(rec, data, TDB_REPLACE);

	TALLOC_FREE(rec);

	return 0;
}

NTSTATUS dbwrap_trans_store(struct db_context *db, TDB_DATA key, TDB_DATA dbuf,
			    int flag)
{
	int res;
	struct db_record *rec = NULL;
	NTSTATUS status;

	res = db->transaction_start(db);
	if (res != 0) {
		DEBUG(5, ("transaction_start failed\n"));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	rec = db->fetch_locked(db, talloc_tos(), key);
	if (rec == NULL) {
		DEBUG(5, ("fetch_locked failed\n"));
		status = NT_STATUS_NO_MEMORY;
		goto cancel;
	}

	status = rec->store(rec, dbuf, flag);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5, ("store returned %s\n", nt_errstr(status)));
		goto cancel;
	}

	TALLOC_FREE(rec);

	res = db->transaction_commit(db);
	if (res != 0) {
		DEBUG(5, ("tdb_transaction_commit failed\n"));
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto cancel;
	}

	return NT_STATUS_OK;

 cancel:
	TALLOC_FREE(rec);

	if (db->transaction_cancel(db) != 0) {
		smb_panic("Cancelling transaction failed");
	}
	return status;
}

NTSTATUS dbwrap_trans_delete(struct db_context *db, TDB_DATA key)
{
	int res;
	struct db_record *rec = NULL;
	NTSTATUS status;

	res = db->transaction_start(db);
	if (res != 0) {
		DEBUG(5, ("transaction_start failed\n"));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	rec = db->fetch_locked(db, talloc_tos(), key);
	if (rec == NULL) {
		DEBUG(5, ("fetch_locked failed\n"));
		status = NT_STATUS_NO_MEMORY;
		goto cancel;
	}

	status = rec->delete_rec(rec);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5, ("delete_rec returned %s\n", nt_errstr(status)));
		goto cancel;
	}

	TALLOC_FREE(rec);

	res = db->transaction_commit(db);
	if (res != 0) {
		DEBUG(5, ("tdb_transaction_commit failed\n"));
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto cancel;
	}

	return NT_STATUS_OK;

 cancel:
	TALLOC_FREE(rec);

	if (db->transaction_cancel(db) != 0) {
		smb_panic("Cancelling transaction failed");
	}
	return status;
}

NTSTATUS dbwrap_trans_store_int32(struct db_context *db, const char *keystr,
				  int32_t v)
{
	int32 v_store;

	SIVAL(&v_store, 0, v);

	return dbwrap_trans_store(db, string_term_tdb_data(keystr),
				  make_tdb_data((const uint8 *)&v_store,
						sizeof(v_store)),
				  TDB_REPLACE);
}

NTSTATUS dbwrap_trans_store_uint32(struct db_context *db, const char *keystr,
				   uint32_t v)
{
	uint32 v_store;

	SIVAL(&v_store, 0, v);

	return dbwrap_trans_store(db, string_term_tdb_data(keystr),
				  make_tdb_data((const uint8 *)&v_store,
						sizeof(v_store)),
				  TDB_REPLACE);
}

NTSTATUS dbwrap_trans_store_bystring(struct db_context *db, const char *key,
				     TDB_DATA data, int flags)
{
	return dbwrap_trans_store(db, string_term_tdb_data(key), data, flags);
}

NTSTATUS dbwrap_trans_delete_bystring(struct db_context *db, const char *key)
{
	return dbwrap_trans_delete(db, string_term_tdb_data(key));
}
