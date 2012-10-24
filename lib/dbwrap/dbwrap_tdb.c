/*
   Unix SMB/CIFS implementation.
   Database interface wrapper around tdb
   Copyright (C) Volker Lendecke 2005-2007

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
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_private.h"
#include "dbwrap/dbwrap_tdb.h"
#include "lib/tdb_wrap/tdb_wrap.h"
#include "lib/util/util_tdb.h"
#include "system/filesys.h"
#include "ccan/str/str.h"

struct db_tdb_ctx {
	struct tdb_wrap *wtdb;

	struct {
		dev_t dev;
		ino_t ino;
	} id;
};

static NTSTATUS db_tdb_store(struct db_record *rec, TDB_DATA data, int flag);
static NTSTATUS db_tdb_delete(struct db_record *rec);

static void db_tdb_log_key(const char *prefix, TDB_DATA key)
{
	size_t len;
	char *keystr;
	TALLOC_CTX *frame;
	if (DEBUGLEVEL < 10) {
		return;
	}
	frame = talloc_stackframe();
	len = key.dsize;
	if (DEBUGLEVEL == 10) {
		/*
		 * Only fully spam at debuglevel > 10
		 */
		len = MIN(10, key.dsize);
	}
	keystr = hex_encode_talloc(frame, (unsigned char *)(key.dptr),
				   len);
	DEBUG(10, ("%s key %s\n", prefix, keystr));
	TALLOC_FREE(frame);
}

static int db_tdb_record_destr(struct db_record* data)
{
	struct db_tdb_ctx *ctx =
		talloc_get_type_abort(data->private_data, struct db_tdb_ctx);

	db_tdb_log_key("Unlocking", data->key);
	tdb_chainunlock(ctx->wtdb->tdb, data->key);
	return 0;
}

struct tdb_fetch_locked_state {
	TALLOC_CTX *mem_ctx;
	struct db_record *result;
};

static int db_tdb_fetchlock_parse(TDB_DATA key, TDB_DATA data,
				  void *private_data)
{
	struct tdb_fetch_locked_state *state =
		(struct tdb_fetch_locked_state *)private_data;
	struct db_record *result;

	result = (struct db_record *)talloc_size(
		state->mem_ctx,
		sizeof(struct db_record) + key.dsize + data.dsize);

	if (result == NULL) {
		return 0;
	}
	state->result = result;

	result->key.dsize = key.dsize;
	result->key.dptr = ((uint8_t *)result) + sizeof(struct db_record);
	memcpy(result->key.dptr, key.dptr, key.dsize);

	result->value.dsize = data.dsize;

	if (data.dsize > 0) {
		result->value.dptr = result->key.dptr+key.dsize;
		memcpy(result->value.dptr, data.dptr, data.dsize);
	}
	else {
		result->value.dptr = NULL;
	}

	return 0;
}

static struct db_record *db_tdb_fetch_locked_internal(
	struct db_context *db, TALLOC_CTX *mem_ctx, TDB_DATA key)
{
	struct db_tdb_ctx *ctx = talloc_get_type_abort(db->private_data,
						       struct db_tdb_ctx);
	struct tdb_fetch_locked_state state;

	state.mem_ctx = mem_ctx;
	state.result = NULL;

	if ((tdb_parse_record(ctx->wtdb->tdb, key, db_tdb_fetchlock_parse,
			      &state) < 0) &&
	    (tdb_error(ctx->wtdb->tdb) != TDB_ERR_NOEXIST)) {
		tdb_chainunlock(ctx->wtdb->tdb, key);
		return NULL;
	}

	if (state.result == NULL) {
		db_tdb_fetchlock_parse(key, tdb_null, &state);
	}

	if (state.result == NULL) {
		tdb_chainunlock(ctx->wtdb->tdb, key);
		return NULL;
	}

	talloc_set_destructor(state.result, db_tdb_record_destr);

	state.result->private_data = talloc_reference(state.result, ctx);
	state.result->store = db_tdb_store;
	state.result->delete_rec = db_tdb_delete;

	DEBUG(10, ("Allocated locked data 0x%p\n", state.result));

	return state.result;
}

static struct db_record *db_tdb_fetch_locked(
	struct db_context *db, TALLOC_CTX *mem_ctx, TDB_DATA key)
{
	struct db_tdb_ctx *ctx = talloc_get_type_abort(db->private_data,
						       struct db_tdb_ctx);

	db_tdb_log_key("Locking", key);
	if (tdb_chainlock(ctx->wtdb->tdb, key) != 0) {
		DEBUG(3, ("tdb_chainlock failed\n"));
		return NULL;
	}
	return db_tdb_fetch_locked_internal(db, mem_ctx, key);
}

static struct db_record *db_tdb_fetch_locked_timeout(
	struct db_context *db, TALLOC_CTX *mem_ctx, TDB_DATA key,
	unsigned int timeout)
{
	struct db_tdb_ctx *ctx = talloc_get_type_abort(db->private_data,
						       struct db_tdb_ctx);

	db_tdb_log_key("Locking with timeout ", key);
	if (tdb_chainlock_with_timeout(ctx->wtdb->tdb, key, timeout) != 0) {
		DEBUG(3, ("tdb_chainlock_with_timeout failed\n"));
		return NULL;
	}
	return db_tdb_fetch_locked_internal(db, mem_ctx, key);
}

static struct db_record *db_tdb_try_fetch_locked(
	struct db_context *db, TALLOC_CTX *mem_ctx, TDB_DATA key)
{
	struct db_tdb_ctx *ctx = talloc_get_type_abort(db->private_data,
						       struct db_tdb_ctx);

	db_tdb_log_key("Trying to lock", key);
	if (tdb_chainlock_nonblock(ctx->wtdb->tdb, key) != 0) {
		DEBUG(3, ("tdb_chainlock_nonblock failed\n"));
		return NULL;
	}
	return db_tdb_fetch_locked_internal(db, mem_ctx, key);
}


static int db_tdb_exists(struct db_context *db, TDB_DATA key)
{
	struct db_tdb_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_tdb_ctx);
	return tdb_exists(ctx->wtdb->tdb, key);
}

static int db_tdb_wipe(struct db_context *db)
{
	struct db_tdb_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_tdb_ctx);
	return tdb_wipe_all(ctx->wtdb->tdb);
}

static int db_tdb_check(struct db_context *db)
{
	struct db_tdb_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_tdb_ctx);
	return tdb_check(ctx->wtdb->tdb, NULL, NULL);
}

struct db_tdb_parse_state {
	void (*parser)(TDB_DATA key, TDB_DATA data,
		       void *private_data);
	void *private_data;
};

/*
 * tdb_parse_record expects a parser returning int, mixing up tdb and
 * parser errors. Wrap around that by always returning 0 and have
 * dbwrap_parse_record expect a parser returning void.
 */

static int db_tdb_parser(TDB_DATA key, TDB_DATA data, void *private_data)
{
	struct db_tdb_parse_state *state =
		(struct db_tdb_parse_state *)private_data;
	state->parser(key, data, state->private_data);
	return 0;
}

static NTSTATUS db_tdb_parse(struct db_context *db, TDB_DATA key,
			     void (*parser)(TDB_DATA key, TDB_DATA data,
					   void *private_data),
			     void *private_data)
{
	struct db_tdb_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_tdb_ctx);
	struct db_tdb_parse_state state;
	int ret;

	state.parser = parser;
	state.private_data = private_data;

	ret = tdb_parse_record(ctx->wtdb->tdb, key, db_tdb_parser, &state);

	if (ret != 0) {
		return map_nt_error_from_tdb(tdb_error(ctx->wtdb->tdb));
	}
	return NT_STATUS_OK;
}

static NTSTATUS db_tdb_store(struct db_record *rec, TDB_DATA data, int flag)
{
	struct db_tdb_ctx *ctx = talloc_get_type_abort(rec->private_data,
						       struct db_tdb_ctx);

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
	struct db_tdb_ctx *ctx = talloc_get_type_abort(rec->private_data,
						       struct db_tdb_ctx);

	if (tdb_delete(ctx->wtdb->tdb, rec->key) == 0) {
		return NT_STATUS_OK;
	}

	if (tdb_error(ctx->wtdb->tdb) == TDB_ERR_NOEXIST) {
		return NT_STATUS_NOT_FOUND;
	}

	return NT_STATUS_UNSUCCESSFUL;
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
	rec.db = ctx->db;

	return ctx->f(&rec, ctx->private_data);
}

static int db_tdb_traverse(struct db_context *db,
			   int (*f)(struct db_record *rec, void *private_data),
			   void *private_data)
{
	struct db_tdb_ctx *db_ctx =
		talloc_get_type_abort(db->private_data, struct db_tdb_ctx);
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
	rec.db = ctx->db;

	return ctx->f(&rec, ctx->private_data);
}

static int db_tdb_traverse_read(struct db_context *db,
			   int (*f)(struct db_record *rec, void *private_data),
			   void *private_data)
{
	struct db_tdb_ctx *db_ctx =
		talloc_get_type_abort(db->private_data, struct db_tdb_ctx);
	struct db_tdb_traverse_ctx ctx;

	ctx.db = db;
	ctx.f = f;
	ctx.private_data = private_data;
	return tdb_traverse_read(db_ctx->wtdb->tdb, db_tdb_traverse_read_func, &ctx);
}

static int db_tdb_get_seqnum(struct db_context *db)

{
	struct db_tdb_ctx *db_ctx =
		talloc_get_type_abort(db->private_data, struct db_tdb_ctx);
	return tdb_get_seqnum(db_ctx->wtdb->tdb);
}

static int db_tdb_transaction_start(struct db_context *db)
{
	struct db_tdb_ctx *db_ctx =
		talloc_get_type_abort(db->private_data, struct db_tdb_ctx);
	return tdb_transaction_start(db_ctx->wtdb->tdb) ? -1 : 0;
}

static NTSTATUS db_tdb_transaction_start_nonblock(struct db_context *db)
{
	struct db_tdb_ctx *db_ctx =
		talloc_get_type_abort(db->private_data, struct db_tdb_ctx);
	int ret;

	ret = tdb_transaction_start_nonblock(db_ctx->wtdb->tdb);
	if (ret != 0) {
		return map_nt_error_from_tdb(tdb_error(db_ctx->wtdb->tdb));
	}
	return NT_STATUS_OK;
}

static int db_tdb_transaction_commit(struct db_context *db)
{
	struct db_tdb_ctx *db_ctx =
		talloc_get_type_abort(db->private_data, struct db_tdb_ctx);
	return tdb_transaction_commit(db_ctx->wtdb->tdb) ? -1 : 0;
}

static int db_tdb_transaction_cancel(struct db_context *db)
{
	struct db_tdb_ctx *db_ctx =
		talloc_get_type_abort(db->private_data, struct db_tdb_ctx);
	tdb_transaction_cancel(db_ctx->wtdb->tdb);
	return 0;
}

static void db_tdb_id(struct db_context *db, const uint8_t **id, size_t *idlen)
{
	struct db_tdb_ctx *db_ctx =
		talloc_get_type_abort(db->private_data, struct db_tdb_ctx);
	*id = (uint8_t *)&db_ctx->id;
	*idlen = sizeof(db_ctx->id);
}

struct db_context *db_open_tdb(TALLOC_CTX *mem_ctx,
			       struct loadparm_context *lp_ctx,
			       const char *name,
			       int hash_size, int tdb_flags,
			       int open_flags, mode_t mode,
			       enum dbwrap_lock_order lock_order)
{
	struct db_context *result = NULL;
	struct db_tdb_ctx *db_tdb;
	struct stat st;

	/* Extra paranoia. */
	if (name && strends(name, ".ntdb")) {
		DEBUG(0, ("can't try to open %s with tdb!\n", name));
		return NULL;
	}

	result = talloc_zero(mem_ctx, struct db_context);
	if (result == NULL) {
		DEBUG(0, ("talloc failed\n"));
		goto fail;
	}

	result->private_data = db_tdb = talloc(result, struct db_tdb_ctx);
	if (db_tdb == NULL) {
		DEBUG(0, ("talloc failed\n"));
		goto fail;
	}
	result->lock_order = lock_order;

	db_tdb->wtdb = tdb_wrap_open(db_tdb, name, hash_size, tdb_flags,
				     open_flags, mode, lp_ctx);
	if (db_tdb->wtdb == NULL) {
		DEBUG(3, ("Could not open tdb: %s\n", strerror(errno)));
		goto fail;
	}

	ZERO_STRUCT(db_tdb->id);

	if (fstat(tdb_fd(db_tdb->wtdb->tdb), &st) == -1) {
		DEBUG(3, ("fstat failed: %s\n", strerror(errno)));
		goto fail;
	}
	db_tdb->id.dev = st.st_dev;
	db_tdb->id.ino = st.st_ino;

	result->fetch_locked = db_tdb_fetch_locked;
	result->fetch_locked_timeout = db_tdb_fetch_locked_timeout;
	result->try_fetch_locked = db_tdb_try_fetch_locked;
	result->traverse = db_tdb_traverse;
	result->traverse_read = db_tdb_traverse_read;
	result->parse_record = db_tdb_parse;
	result->get_seqnum = db_tdb_get_seqnum;
	result->persistent = ((tdb_flags & TDB_CLEAR_IF_FIRST) == 0);
	result->transaction_start = db_tdb_transaction_start;
	result->transaction_start_nonblock = db_tdb_transaction_start_nonblock;
	result->transaction_commit = db_tdb_transaction_commit;
	result->transaction_cancel = db_tdb_transaction_cancel;
	result->exists = db_tdb_exists;
	result->wipe = db_tdb_wipe;
	result->id = db_tdb_id;
	result->check = db_tdb_check;
	result->stored_callback = NULL;
	result->name = tdb_name(db_tdb->wtdb->tdb);
	result->hash_size = hash_size;
	return result;

 fail:
	if (result != NULL) {
		TALLOC_FREE(result);
	}
	return NULL;
}
