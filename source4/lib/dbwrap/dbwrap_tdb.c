/* 
   Unix SMB/CIFS implementation.

   Database interface wrapper around tdb

   Copyright (C) Volker Lendecke 2005
   Copyright (C) Andrew Tridgell 2007
   
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
#include "lib/tdb/include/tdb.h"
#include "lib/dbwrap/dbwrap.h"
#include "system/filesys.h"
#include "db_wrap.h"

struct db_tdb_ctx {
	struct tdb_wrap *wtdb;
};

static NTSTATUS db_tdb_store(struct db_record *rec, TDB_DATA data, int flag);
static NTSTATUS db_tdb_delete(struct db_record *rec);

static int db_tdb_record_destr(struct db_record* data)
{
	struct db_tdb_ctx *ctx = talloc_get_type(data->private_data, struct db_tdb_ctx);

	if (tdb_chainunlock(ctx->wtdb->tdb, data->key) != 0) {
		DEBUG(0, ("tdb_chainunlock failed\n"));
		return -1;
	}
	return 0;
}

static int db_tdb_fetch(struct db_context *db, TALLOC_CTX *mem_ctx, TDB_DATA key, TDB_DATA *data)
{
	struct db_tdb_ctx *ctx = talloc_get_type(db->private_data, struct db_tdb_ctx);
	TDB_DATA value;

	value = tdb_fetch(ctx->wtdb->tdb, key);
	if (value.dptr == NULL) {
		return -1;
	}

	data->dsize = value.dsize;
	data->dptr  = (uint8_t *)talloc_memdup(mem_ctx, value.dptr, value.dsize);
	free(value.dptr);
	if (data->dptr == NULL) {
		errno = ENOMEM;
		return -1;
	}

	return 0;
}

static struct db_record *db_tdb_fetch_locked(struct db_context *db,
				     TALLOC_CTX *mem_ctx, TDB_DATA key)
{
	struct db_tdb_ctx *ctx = talloc_get_type(db->private_data, struct db_tdb_ctx);
	struct db_record *result;
	TDB_DATA value;

	result = talloc(mem_ctx, struct db_record);
	if (result == NULL) {
		return NULL;
	}

	result->key.dsize = key.dsize;
	result->key.dptr = (uint8_t *)talloc_memdup(result, key.dptr, key.dsize);
	if (result->key.dptr == NULL) {
		talloc_free(result);
		return NULL;
	}

	result->value.dptr = NULL;
	result->value.dsize = 0;
	result->private_data = talloc_reference(result, ctx);
	result->store = db_tdb_store;
	result->delete_rec = db_tdb_delete;

	if (tdb_chainlock(ctx->wtdb->tdb, key) != 0) {
		talloc_free(result);
		return NULL;
	}

	talloc_set_destructor(result, db_tdb_record_destr);

	value = tdb_fetch(ctx->wtdb->tdb, key);

	if (value.dptr == NULL) {
		return result;
	}

	result->value.dsize = value.dsize;
	result->value.dptr = (uint8_t *)talloc_memdup(result, value.dptr,
						    value.dsize);
	free(value.dptr);
	if (result->value.dptr == NULL) {
		talloc_free(result);
		return NULL;
	}

	return result;
}

static NTSTATUS db_tdb_store(struct db_record *rec, TDB_DATA data, int flag)
{
	struct db_tdb_ctx *ctx = talloc_get_type(rec->private_data, struct db_tdb_ctx);

	/*
	 * This has a bug: We need to replace rec->value for correct
	 * operation, but right now brlock and locking don't use the value
	 * anymore after it was stored.
	 */

	return (tdb_store(ctx->wtdb->tdb, rec->key, data, flag) == 0) ?
		NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS db_tdb_delete(struct db_record *rec)
{
	struct db_tdb_ctx *ctx = talloc_get_type(rec->private_data, struct db_tdb_ctx);

	return (tdb_delete(ctx->wtdb->tdb, rec->key) == 0) ?
		NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

struct db_tdb_traverse_ctx {
	struct db_context *db;
	int (*f)(struct db_record *rec, void *private_data);
	void *private_data;
};

static int db_tdb_traverse_func(TDB_CONTEXT *tdb, TDB_DATA kbuf, TDB_DATA dbuf,
				void *private_data)
{
	struct db_tdb_traverse_ctx *ctx =
		(struct db_tdb_traverse_ctx *)private_data;
	struct db_record rec;

	rec.key = kbuf;
	rec.value = dbuf;
	rec.store = db_tdb_store;
	rec.delete_rec = db_tdb_delete;
	rec.private_data = ctx->db->private_data;

	return ctx->f(&rec, ctx->private_data);
}

static int db_tdb_traverse(struct db_context *db,
			   int (*f)(struct db_record *rec, void *private_data),
			   void *private_data)
{
	struct db_tdb_ctx *db_ctx =
		talloc_get_type(db->private_data, struct db_tdb_ctx);
	struct db_tdb_traverse_ctx ctx;

	ctx.db = db;
	ctx.f = f;
	ctx.private_data = private_data;
	return tdb_traverse(db_ctx->wtdb->tdb, db_tdb_traverse_func, &ctx);
}

static NTSTATUS db_tdb_store_deny(struct db_record *rec, TDB_DATA data, int flag)
{
	return NT_STATUS_MEDIA_WRITE_PROTECTED;
}

static NTSTATUS db_tdb_delete_deny(struct db_record *rec)
{
	return NT_STATUS_MEDIA_WRITE_PROTECTED;
}

static int db_tdb_traverse_read_func(TDB_CONTEXT *tdb, TDB_DATA kbuf, TDB_DATA dbuf,
				void *private_data)
{
	struct db_tdb_traverse_ctx *ctx =
		(struct db_tdb_traverse_ctx *)private_data;
	struct db_record rec;

	rec.key = kbuf;
	rec.value = dbuf;
	rec.store = db_tdb_store_deny;
	rec.delete_rec = db_tdb_delete_deny;
	rec.private_data = ctx->db->private_data;

	return ctx->f(&rec, ctx->private_data);
}

static int db_tdb_traverse_read(struct db_context *db,
			   int (*f)(struct db_record *rec, void *private_data),
			   void *private_data)
{
	struct db_tdb_ctx *db_ctx =
		talloc_get_type(db->private_data, struct db_tdb_ctx);
	struct db_tdb_traverse_ctx ctx;

	ctx.db = db;
	ctx.f = f;
	ctx.private_data = private_data;
	return tdb_traverse_read(db_ctx->wtdb->tdb, db_tdb_traverse_read_func, &ctx);
}

static int db_tdb_get_seqnum(struct db_context *db)

{
	struct db_tdb_ctx *db_ctx =
		talloc_get_type(db->private_data, struct db_tdb_ctx);
	return tdb_get_seqnum(db_ctx->wtdb->tdb);
}

/*
  open a temporary database
 */
struct db_context *db_tmp_open_tdb(TALLOC_CTX *mem_ctx, const char *name, int tdb_flags)
{
	struct db_context *result;
	struct db_tdb_ctx *db_tdb;
	char *path;

	result = talloc_zero(mem_ctx, struct db_context);
	if (result == NULL) goto failed;

	db_tdb = talloc(result, struct db_tdb_ctx);
	if (db_tdb == NULL) goto failed;

	result->private_data = db_tdb;

	/* the name passed in should not be a full path, it should be
	   just be the db name */
	path = smbd_tmp_path(result, name);

	db_tdb->wtdb = tdb_wrap_open(db_tdb, path, 0, tdb_flags,
				     O_CREAT|O_RDWR, 0666);
	if (db_tdb->wtdb == NULL) {
		DEBUG(3, ("Could not open tdb '%s': %s\n", path, strerror(errno)));
		goto failed;
	}
	
	talloc_free(path);

	result->fetch_locked  = db_tdb_fetch_locked;
	result->fetch         = db_tdb_fetch;
	result->traverse      = db_tdb_traverse;
	result->traverse_read = db_tdb_traverse_read;
	result->get_seqnum    = db_tdb_get_seqnum;

	return result;

 failed:
	talloc_free(result);
	return NULL;
}
