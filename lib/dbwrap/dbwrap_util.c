/*
   Unix SMB/CIFS implementation.
   Utility functions for the dbwrap API
   Copyright (C) Volker Lendecke 2007
   Copyright (C) Michael Adam 2009
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2006

   Major code contributions from Aleksey Fedoseev (fedoseev@ru.ibm.com)

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
#include "dbwrap.h"
#include "lib/util/util_tdb.h"

struct dbwrap_fetch_int32_state {
	NTSTATUS status;
	int32_t result;
};

static void dbwrap_fetch_int32_parser(TDB_DATA key, TDB_DATA data,
				      void *private_data)
{
	struct dbwrap_fetch_int32_state *state =
		(struct dbwrap_fetch_int32_state *)private_data;

	if (data.dsize != sizeof(state->result)) {
		state->status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		return;
	}
	state->result = IVAL(data.dptr, 0);
	state->status = NT_STATUS_OK;
}

NTSTATUS dbwrap_fetch_int32(struct db_context *db, TDB_DATA key,
			    int32_t *result)
{
	struct dbwrap_fetch_int32_state state;
	NTSTATUS status;

	if (result == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	state.status = NT_STATUS_INTERNAL_ERROR;

	status = dbwrap_parse_record(db, key, dbwrap_fetch_int32_parser, &state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (NT_STATUS_IS_OK(state.status)) {
		*result = state.result;
	}
	return state.status;
}

NTSTATUS dbwrap_fetch_int32_bystring(struct db_context *db, const char *keystr,
				     int32_t *result)
{
	return dbwrap_fetch_int32(db, string_term_tdb_data(keystr), result);
}

NTSTATUS dbwrap_store_int32_bystring(struct db_context *db, const char *keystr,
				     int32_t v)
{
	uint8_t v_store[sizeof(int32_t)];
	TDB_DATA data = { .dptr = v_store, .dsize = sizeof(v_store) };
	NTSTATUS status;

	SIVAL(v_store, 0, v);

	status = dbwrap_store(db, string_term_tdb_data(keystr), data,
			      TDB_REPLACE);
	return status;
}

struct dbwrap_fetch_uint32_state {
	NTSTATUS status;
	uint32_t result;
};

static void dbwrap_fetch_uint32_parser(TDB_DATA key, TDB_DATA data,
				       void *private_data)
{
	struct dbwrap_fetch_uint32_state *state =
		(struct dbwrap_fetch_uint32_state *)private_data;

	if (data.dsize != sizeof(state->result)) {
		state->status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		return;
	}
	state->result = IVAL(data.dptr, 0);
	state->status = NT_STATUS_OK;
}

NTSTATUS dbwrap_fetch_uint32_bystring(struct db_context *db,
				      const char *keystr, uint32_t *val)
{
	struct dbwrap_fetch_uint32_state state;
	NTSTATUS status;

	if (val == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	state.status = NT_STATUS_INTERNAL_ERROR;

	status = dbwrap_parse_record(db, string_term_tdb_data(keystr),
				     dbwrap_fetch_uint32_parser, &state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (NT_STATUS_IS_OK(state.status)) {
		*val = state.result;
	}
	return state.status;
}

NTSTATUS dbwrap_store_uint32_bystring(struct db_context *db,
				      const char *keystr, uint32_t v)
{
	uint8_t v_store[sizeof(uint32_t)];
	TDB_DATA data = { .dptr = v_store, .dsize = sizeof(v_store) };
	NTSTATUS status;

	SIVAL(v_store, 0, v);

	status = dbwrap_store(db, string_term_tdb_data(keystr), data,
			      TDB_REPLACE);
	return status;
}

/**
 * Atomic unsigned integer change (addition):
 *
 * if value does not exist yet in the db, use *oldval as initial old value.
 * return old value in *oldval.
 * store *oldval + change_val to db.
 */

struct dbwrap_change_uint32_atomic_context {
	const char *keystr;
	uint32_t *oldval;
	uint32_t change_val;
};

static NTSTATUS dbwrap_change_uint32_atomic_action(struct db_context *db,
						   void *private_data)
{
	struct db_record *rec;
	uint32_t val = (uint32_t)-1;
	uint32_t v_store;
	NTSTATUS ret;
	struct dbwrap_change_uint32_atomic_context *state;
	TDB_DATA value;

	state = (struct dbwrap_change_uint32_atomic_context *)private_data;

	rec = dbwrap_fetch_locked(db, talloc_tos(),
				  string_term_tdb_data(state->keystr));
	if (!rec) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	value = dbwrap_record_get_value(rec);

	if (value.dptr == NULL) {
		val = *(state->oldval);
	} else if (value.dsize == sizeof(val)) {
		val = IVAL(value.dptr, 0);
		*(state->oldval) = val;
	} else {
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	val += state->change_val;

	SIVAL(&v_store, 0, val);

	ret = dbwrap_record_store(rec,
				  make_tdb_data((const uint8_t *)&v_store,
						sizeof(v_store)),
				  TDB_REPLACE);

done:
	TALLOC_FREE(rec);
	return ret;
}

NTSTATUS dbwrap_change_uint32_atomic_bystring(struct db_context *db,
					      const char *keystr,
					      uint32_t *oldval,
					      uint32_t change_val)
{
	NTSTATUS ret;
	struct dbwrap_change_uint32_atomic_context state;

	state.keystr = keystr;
	state.oldval = oldval;
	state.change_val = change_val;

	ret = dbwrap_change_uint32_atomic_action(db, &state);

	return ret;
}

NTSTATUS dbwrap_trans_change_uint32_atomic_bystring(struct db_context *db,
						    const char *keystr,
						    uint32_t *oldval,
						    uint32_t change_val)
{
	NTSTATUS ret;
	struct dbwrap_change_uint32_atomic_context state;

	state.keystr = keystr;
	state.oldval = oldval;
	state.change_val = change_val;

	ret = dbwrap_trans_do(db, dbwrap_change_uint32_atomic_action, &state);

	return ret;
}

/**
 * Atomic integer change (addition):
 *
 * if value does not exist yet in the db, use *oldval as initial old value.
 * return old value in *oldval.
 * store *oldval + change_val to db.
 */

struct dbwrap_change_int32_atomic_context {
	TDB_DATA key;
	int32_t *oldval;
	int32_t change_val;
};

static NTSTATUS dbwrap_change_int32_atomic_action(struct db_context *db,
						  void *private_data)
{
	struct db_record *rec;
	int32_t val = -1;
	int32_t v_store;
	NTSTATUS ret;
	struct dbwrap_change_int32_atomic_context *state;
	TDB_DATA value;

	state = (struct dbwrap_change_int32_atomic_context *)private_data;

	rec = dbwrap_fetch_locked(db, talloc_tos(), state->key);
	if (!rec) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	value = dbwrap_record_get_value(rec);

	if (value.dptr == NULL) {
		val = *(state->oldval);
	} else if (value.dsize == sizeof(val)) {
		val = IVAL(value.dptr, 0);
		*(state->oldval) = val;
	} else {
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	val += state->change_val;

	SIVAL(&v_store, 0, val);

	ret = dbwrap_record_store(rec,
				  make_tdb_data((const uint8_t *)&v_store,
						sizeof(v_store)),
				  TDB_REPLACE);

done:
	TALLOC_FREE(rec);
	return ret;
}

NTSTATUS dbwrap_change_int32_atomic(struct db_context *db,
				    TDB_DATA key,
				    int32_t *oldval,
				    int32_t change_val)
{
	NTSTATUS ret;
	struct dbwrap_change_int32_atomic_context state;

	state.key = key;
	state.oldval = oldval;
	state.change_val = change_val;

	ret = dbwrap_change_int32_atomic_action(db, &state);

	return ret;
}

NTSTATUS dbwrap_change_int32_atomic_bystring(struct db_context *db,
					     const char *keystr,
					     int32_t *oldval,
					     int32_t change_val)
{
	return dbwrap_change_int32_atomic(db, string_term_tdb_data(keystr),
					  oldval, change_val);
}

NTSTATUS dbwrap_trans_change_int32_atomic_bystring(struct db_context *db,
						   const char *keystr,
						   int32_t *oldval,
						   int32_t change_val)
{
	NTSTATUS ret;
	struct dbwrap_change_int32_atomic_context state;

	state.key = string_term_tdb_data(keystr);
	state.oldval = oldval;
	state.change_val = change_val;

	ret = dbwrap_trans_do(db, dbwrap_change_int32_atomic_action, &state);

	return ret;
}

struct dbwrap_store_context {
	TDB_DATA *key;
	TDB_DATA *dbuf;
	int flag;
};

static NTSTATUS dbwrap_store_action(struct db_context *db, void *private_data)
{
	NTSTATUS status;
	struct dbwrap_store_context *store_ctx;

	store_ctx = (struct dbwrap_store_context *)private_data;

	status = dbwrap_store(db, *(store_ctx->key), *(store_ctx->dbuf),
			      store_ctx->flag);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5, ("store returned %s\n", nt_errstr(status)));
	}

	return status;
}

NTSTATUS dbwrap_trans_store(struct db_context *db, TDB_DATA key, TDB_DATA dbuf,
			    int flag)
{
	NTSTATUS status;
	struct dbwrap_store_context store_ctx;

	store_ctx.key = &key;
	store_ctx.dbuf = &dbuf;
	store_ctx.flag = flag;

	status = dbwrap_trans_do(db, dbwrap_store_action, &store_ctx);

	return status;
}

static NTSTATUS dbwrap_delete_action(struct db_context * db, void *private_data)
{
	NTSTATUS status;
	TDB_DATA *key = (TDB_DATA *)private_data;

	status = dbwrap_delete(db, *key);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_INFO("dbwrap_record_delete returned %s\n",
			 nt_errstr(status));
	}
	return  status;
}

NTSTATUS dbwrap_trans_delete(struct db_context *db, TDB_DATA key)
{
	NTSTATUS status;

	status = dbwrap_trans_do(db, dbwrap_delete_action, &key);

	return status;
}

NTSTATUS dbwrap_trans_store_int32_bystring(struct db_context *db,
					   const char *keystr,
					   int32_t v)
{
	int32_t v_store;

	SIVAL(&v_store, 0, v);

	return dbwrap_trans_store(db, string_term_tdb_data(keystr),
				  make_tdb_data((const uint8_t *)&v_store,
						sizeof(v_store)),
				  TDB_REPLACE);
}

NTSTATUS dbwrap_trans_store_uint32_bystring(struct db_context *db,
					    const char *keystr,
					    uint32_t v)
{
	uint32_t v_store;

	SIVAL(&v_store, 0, v);

	return dbwrap_trans_store(db, string_term_tdb_data(keystr),
				  make_tdb_data((const uint8_t *)&v_store,
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

/**
 * Wrap db action(s) into a transaction.
 */
NTSTATUS dbwrap_trans_do(struct db_context *db,
			 NTSTATUS (*action)(struct db_context *, void *),
			 void *private_data)
{
	int res;
	NTSTATUS status;

	res = dbwrap_transaction_start(db);
	if (res != 0) {
		DEBUG(5, ("transaction_start failed\n"));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	status = action(db, private_data);
	if (!NT_STATUS_IS_OK(status)) {
		if (dbwrap_transaction_cancel(db) != 0) {
			smb_panic("Cancelling transaction failed");
		}
		return status;
	}

	res = dbwrap_transaction_commit(db);
	if (res == 0) {
		return NT_STATUS_OK;
	}

	DEBUG(2, ("transaction_commit failed\n"));
	return NT_STATUS_INTERNAL_DB_CORRUPTION;
}

struct dbwrap_trans_traverse_action_ctx {
	int (*f)(struct db_record* rec, void* private_data);
	void* private_data;
};


static NTSTATUS dbwrap_trans_traverse_action(struct db_context* db, void* private_data)
{
	struct dbwrap_trans_traverse_action_ctx* ctx =
		(struct dbwrap_trans_traverse_action_ctx*)private_data;

	NTSTATUS status = dbwrap_traverse(db, ctx->f, ctx->private_data, NULL);

	return status;
}

NTSTATUS dbwrap_trans_traverse(struct db_context *db,
			       int (*f)(struct db_record*, void*),
			       void *private_data)
{
	struct dbwrap_trans_traverse_action_ctx ctx = {
		.f = f,
		.private_data = private_data,
	};
	return dbwrap_trans_do(db, dbwrap_trans_traverse_action, &ctx);
}

NTSTATUS dbwrap_purge(struct db_context *db, TDB_DATA key)
{
	NTSTATUS status;

	status = dbwrap_delete(db, key);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		status = NT_STATUS_OK;
	}

	return status;
}

NTSTATUS dbwrap_purge_bystring(struct db_context *db, const char *key)
{
	return dbwrap_purge(db, string_term_tdb_data(key));
}

NTSTATUS dbwrap_delete_bystring(struct db_context *db, const char *key)
{
	return dbwrap_delete(db, string_term_tdb_data(key));
}

NTSTATUS dbwrap_store_bystring(struct db_context *db, const char *key,
			       TDB_DATA data, int flags)
{
	return dbwrap_store(db, string_term_tdb_data(key), data, flags);
}

NTSTATUS dbwrap_fetch_bystring(struct db_context *db, TALLOC_CTX *mem_ctx,
			       const char *key, TDB_DATA *value)
{
	return dbwrap_fetch(db, mem_ctx, string_term_tdb_data(key), value);
}



NTSTATUS dbwrap_delete_bystring_upper(struct db_context *db, const char *key)
{
	char *key_upper;
	NTSTATUS status;

	key_upper = talloc_strdup_upper(talloc_tos(), key);
	if (key_upper == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = dbwrap_delete_bystring(db, key_upper);

	talloc_free(key_upper);
	return status;
}

NTSTATUS dbwrap_store_bystring_upper(struct db_context *db, const char *key,
				     TDB_DATA data, int flags)
{
	char *key_upper;
	NTSTATUS status;

	key_upper = talloc_strdup_upper(talloc_tos(), key);
	if (key_upper == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = dbwrap_store_bystring(db, key_upper, data, flags);

	talloc_free(key_upper);
	return status;
}

NTSTATUS dbwrap_fetch_bystring_upper(struct db_context *db, TALLOC_CTX *mem_ctx,
				     const char *key, TDB_DATA *value)
{
	char *key_upper;
	NTSTATUS status;

	key_upper = talloc_strdup_upper(talloc_tos(), key);
	if (key_upper == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = dbwrap_fetch_bystring(db, mem_ctx, key_upper, value);

	talloc_free(key_upper);
	return status;
}

struct dbwrap_marshall_state {
	uint8_t *buf;
	size_t bufsize;
	size_t dbsize;
};

static int dbwrap_marshall_fn(struct db_record *rec, void *private_data)
{
	struct dbwrap_marshall_state *state = private_data;
	TDB_DATA key, value;
	size_t new_dbsize;

	key = dbwrap_record_get_key(rec);
	value = dbwrap_record_get_value(rec);

	new_dbsize = state->dbsize;
	new_dbsize += 8 + key.dsize;
	new_dbsize += 8 + value.dsize;

	if (new_dbsize <= state->bufsize) {
		uint8_t *p = state->buf + state->dbsize;

		SBVAL(p, 0, key.dsize);
		p += 8;
		memcpy(p, key.dptr, key.dsize);
		p += key.dsize;

		SBVAL(p, 0, value.dsize);
		p += 8;
		memcpy(p, value.dptr, value.dsize);
	}
	state->dbsize = new_dbsize;
	return 0;
}

size_t dbwrap_marshall(struct db_context *db, uint8_t *buf, size_t bufsize)
{
	struct dbwrap_marshall_state state;

	state.bufsize = bufsize;
	state.buf = buf;
	state.dbsize = 0;

	dbwrap_traverse_read(db, dbwrap_marshall_fn, &state, NULL);

	return state.dbsize;
}

static ssize_t dbwrap_unmarshall_get_data(const uint8_t *buf, size_t buflen,
					  size_t ofs, TDB_DATA *pdata)
{
	uint64_t space, len;
	const uint8_t *p;

	if (ofs == buflen) {
		return 0;
	}
	if (ofs > buflen) {
		return -1;
	}

	space = buflen - ofs;
	if (space < 8) {
		return -1;
	}

	p = buf + ofs;
	len = BVAL(p, 0);

	p += 8;
	space -= 8;

	if (len > space) {
		return -1;
	}

	*pdata = (TDB_DATA) { .dptr = discard_const_p(uint8_t, p),
			      .dsize = len };
	return len + 8;
}

NTSTATUS dbwrap_parse_marshall_buf(const uint8_t *buf, size_t buflen,
				   bool (*fn)(TDB_DATA key, TDB_DATA value,
					      void *private_data),
				   void *private_data)
{
	size_t ofs = 0;

	while (true) {
		ssize_t len;
		TDB_DATA key, value;
		bool ok;

		len = dbwrap_unmarshall_get_data(buf, buflen, ofs, &key);
		if (len == 0) {
			break;
		}
		if (len == -1) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		ofs += len;

		len = dbwrap_unmarshall_get_data(buf, buflen, ofs, &value);
		if (len == 0) {
			break;
		}
		if (len == -1) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		ofs += len;

		ok = fn(key, value, private_data);
		if (!ok) {
			break;
		}
	}

	return NT_STATUS_OK;
}

struct dbwrap_unmarshall_state {
	struct db_context *db;
	NTSTATUS ret;
};

static bool dbwrap_unmarshall_fn(TDB_DATA key, TDB_DATA value,
				 void *private_data)
{
	struct dbwrap_unmarshall_state *state = private_data;
	NTSTATUS status;

	status = dbwrap_store(state->db, key, value, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dbwrap_record_store failed: %s\n",
			  nt_errstr(status));
		state->ret = status;
		return false;
	}

	return true;
}

NTSTATUS dbwrap_unmarshall(struct db_context *db, const uint8_t *buf,
			   size_t buflen)
{
	struct dbwrap_unmarshall_state state = { .db = db };
	NTSTATUS status;

	status = dbwrap_parse_marshall_buf(buf, buflen,
					   dbwrap_unmarshall_fn, &state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return state.ret;
}
