/* 
   Unix SMB/CIFS implementation.
   Database interface wrapper around tdb
   Copyright (C) Volker Lendecke 2005
   
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

struct db_tdb_ctx {
	TDB_CONTEXT *tdb;
};

static TDB_DATA blob2tdb(DATA_BLOB blob)
{
	TDB_DATA result;
	result.dptr = blob.data;
	result.dsize = blob.length;
	return result;
}

static DATA_BLOB tdb2blob(TDB_DATA data)
{
	DATA_BLOB result;
	result.data = data.dptr;
	result.length = data.dsize;
	return result;
}

static int db_tdb_store(struct db_record *rec, DATA_BLOB data, int flag);
static int db_tdb_delete(struct db_record *rec);

static int db_tdb_record_destr(void *p)
{
	struct db_record *data = talloc_get_type_abort(p, struct db_record);
	struct db_tdb_ctx *ctx =
		talloc_get_type_abort(data->private_data, struct db_tdb_ctx);
	TDB_DATA key;

	DEBUG(10, ("Unlocking key %s\n",
		   hex_encode(data, data->key.data, data->key.length)));

	key.dptr = data->key.data;
	key.dsize = data->key.length;

	if (tdb_chainunlock(ctx->tdb, key) != 0) {
		DEBUG(0, ("tdb_chainunlock failed\n"));
		return -1;
	}
	return 0;
}

static struct db_record *db_tdb_fetch_locked(struct db_context *db,
				     TALLOC_CTX *mem_ctx, DATA_BLOB key)
{
	struct db_tdb_ctx *ctx = talloc_get_type_abort(db->private_data,
						       struct db_tdb_ctx);
	struct db_record *result;
	TDB_DATA value;

	result = TALLOC_P(mem_ctx, struct db_record);
	if (result == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	result->key = data_blob_talloc(result, key.data, key.length);
	if (result->key.data == NULL) {
		DEBUG(0, ("talloc failed\n"));
		talloc_free(result);
		return NULL;
	}

	result->value.data = NULL;
	result->value.length = 0;
	result->private_data = talloc_reference(result, ctx);
	result->store = db_tdb_store;
	result->delete_rec = db_tdb_delete;

	{
		char *keystr = hex_encode(NULL, key.data, key.length);
		DEBUG(10, ("Locking key %s\n", keystr));
		talloc_free(keystr);
	}

	if (tdb_chainlock(ctx->tdb, blob2tdb(key)) != 0) {
		DEBUG(3, ("tdb_chainlock failed\n"));
		talloc_free(result);
		return NULL;
	}

	talloc_set_destructor(result, db_tdb_record_destr);

	value = tdb_fetch(ctx->tdb, blob2tdb(key));

	if (value.dptr == NULL) {
		return result;
	}

	result->value.length = value.dsize;
	result->value.data = talloc_memdup(result, value.dptr, value.dsize);
	if (result->value.data == NULL) {
		DEBUG(3, ("talloc failed\n"));
		talloc_free(result);
		return NULL;
	}

	SAFE_FREE(value.dptr);

	DEBUG(10, ("Allocated locked data 0x%p\n", result));

	return result;
}

static int db_tdb_store(struct db_record *rec, DATA_BLOB data, int flag)
{
	struct db_tdb_ctx *ctx = talloc_get_type_abort(rec->private_data,
						       struct db_tdb_ctx);

	return tdb_store(ctx->tdb, blob2tdb(rec->key), blob2tdb(data), flag);
}

static int db_tdb_delete(struct db_record *rec)
{
	struct db_tdb_ctx *ctx = talloc_get_type_abort(rec->private_data,
						       struct db_tdb_ctx);

	return tdb_delete(ctx->tdb, blob2tdb(rec->key));
}

struct db_tdb_traverse_ctx {
	struct db_context *db;
	int (*f)(DATA_BLOB key, DATA_BLOB data, void *private_data);
	void *private_data;
};

static int db_tdb_traverse_func(TDB_CONTEXT *tdb, TDB_DATA kbuf, TDB_DATA dbuf,
				void *private_data)
{
	struct db_tdb_traverse_ctx *ctx = private_data;
	return ctx->f(tdb2blob(kbuf), tdb2blob(dbuf), ctx->private_data);
}

static int db_tdb_traverse(struct db_context *db,
			   int (*f)(DATA_BLOB key, DATA_BLOB data,
				    void *private_data),
			   void *private_data)
{
	struct db_tdb_ctx *db_ctx =
		talloc_get_type_abort(db->private_data, struct db_tdb_ctx);
	struct db_tdb_traverse_ctx ctx;

	ctx.db = db;
	ctx.f = f;
	ctx.private_data = private_data;
	return tdb_traverse(db_ctx->tdb, db_tdb_traverse_func, &ctx);
}

static int db_tdb_ctx_destr(void *p)
{
	struct db_tdb_ctx *ctx =
		talloc_get_type_abort(p, struct db_tdb_ctx);

	if (tdb_close(ctx->tdb) != 0) {
		DEBUG(0, ("Failed to close tdb: %s\n", strerror(errno)));
		return -1;
	}

	return 0;
}

struct db_context *db_open(TALLOC_CTX *mem_ctx, const char *name,
			   int hash_size, int tdb_flags,
			   int open_flags, mode_t mode)
{
	struct db_context *result = NULL;
	struct db_tdb_ctx *db_tdb;

	result = TALLOC_P(mem_ctx, struct db_context);
	if (result == NULL) {
		DEBUG(0, ("talloc failed\n"));
		goto fail;
	}

	result->private_data = db_tdb = TALLOC_P(result, struct db_tdb_ctx);
	if (db_tdb == NULL) {
		DEBUG(0, ("talloc failed\n"));
		goto fail;
	}

	db_tdb->tdb = tdb_open_log(name, hash_size, tdb_flags,
				   open_flags, mode);
	if (db_tdb->tdb == NULL) {
		DEBUG(3, ("Could not open tdb: %s\n", strerror(errno)));
		goto fail;
	}

	talloc_set_destructor(db_tdb, db_tdb_ctx_destr);
	result->fetch_locked = db_tdb_fetch_locked;
	result->traverse = db_tdb_traverse;
	return result;

 fail:
	if (result != NULL) {
		talloc_free(result);
	}
	return NULL;
}
