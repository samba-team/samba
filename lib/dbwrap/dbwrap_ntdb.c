/*
   Unix SMB/CIFS implementation.
   Database interface wrapper around ntdb
   Copyright (C) Volker Lendecke 2005-2007
   Copyright (C) Rusty Russell 2012

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
#include "dbwrap/dbwrap_ntdb.h"
#include "system/filesys.h"
#include "lib/util/util_ntdb.h"
#include "ccan/str/str.h"

struct db_ntdb_ctx {
	struct ntdb_context *ntdb;

	struct {
		dev_t dev;
		ino_t ino;
	} id;
};

static int tdb_store_flag_to_ntdb(int tdb_flag)
{
	switch (tdb_flag) {
	/* In fact, any value defaults to TDB_REPLACE in tdb! */
	case 0:
	case TDB_REPLACE:
		return NTDB_REPLACE;
	case TDB_INSERT:
		return NTDB_INSERT;
	case TDB_MODIFY:
		return NTDB_MODIFY;
	default:
		smb_panic("unknown tdb_flag");
	}
}

static NTSTATUS db_ntdb_store(struct db_record *rec, NTDB_DATA data, int flag)
{
	int ntdb_flag = tdb_store_flag_to_ntdb(flag);
	struct db_ntdb_ctx *ctx = talloc_get_type_abort(rec->private_data,
							struct db_ntdb_ctx);

	/*
	 * This has a bug: We need to replace rec->value for correct
	 * operation, but right now brlock and locking don't use the value
	 * anymore after it was stored.
	 */

	if (ntdb_store(ctx->ntdb, rec->key, data, ntdb_flag) == NTDB_SUCCESS) {
		return NT_STATUS_OK;
	}
	return NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS db_ntdb_delete(struct db_record *rec)
{
	enum NTDB_ERROR err;
	struct db_ntdb_ctx *ctx = talloc_get_type_abort(rec->private_data,
						       struct db_ntdb_ctx);

	err = ntdb_delete(ctx->ntdb, rec->key);
	if (err == NTDB_SUCCESS) {
		return NT_STATUS_OK;
	}

	if (err == NTDB_ERR_NOEXIST) {
		return NT_STATUS_NOT_FOUND;
	}

	return NT_STATUS_UNSUCCESSFUL;
}

static void db_ntdb_log_key(const char *prefix, NTDB_DATA key)
{
	size_t len;
	char *keystr;

	if (DEBUGLEVEL < 10) {
		return;
	}
	len = key.dsize;
	if (DEBUGLEVEL == 10) {
		/*
		 * Only fully spam at debuglevel > 10
		 */
		len = MIN(10, key.dsize);
	}
	keystr = hex_encode_talloc(talloc_tos(), (unsigned char *)(key.dptr),
				   len);
	DEBUG(10, ("%s key %s\n", prefix, keystr));
	TALLOC_FREE(keystr);
}

static int db_ntdb_record_destr(struct db_record* data)
{
	struct db_ntdb_ctx *ctx =
		talloc_get_type_abort(data->private_data, struct db_ntdb_ctx);

	db_ntdb_log_key("Unlocking", data->key);
	ntdb_chainunlock(ctx->ntdb, data->key);
	return 0;
}

struct ntdb_fetch_locked_state {
	TALLOC_CTX *mem_ctx;
	struct db_record *result;
};

static enum NTDB_ERROR db_ntdb_fetchlock_parse(NTDB_DATA key, NTDB_DATA data,
					       struct ntdb_fetch_locked_state *state)
{
	struct db_record *result;

	result = (struct db_record *)talloc_size(
		state->mem_ctx,
		sizeof(struct db_record) + key.dsize + data.dsize);

	if (result == NULL) {
		return NTDB_ERR_OOM;
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

	return NTDB_SUCCESS;
}

static struct db_record *db_ntdb_fetch_locked_internal(
	struct db_context *db, TALLOC_CTX *mem_ctx, NTDB_DATA key)
{
	struct db_ntdb_ctx *ctx = talloc_get_type_abort(db->private_data,
							struct db_ntdb_ctx);
	struct ntdb_fetch_locked_state state;
	enum NTDB_ERROR err;
	NTDB_DATA null = { NULL, 0 };

	state.mem_ctx = mem_ctx;
	state.result = NULL;

	err = ntdb_parse_record(ctx->ntdb, key, db_ntdb_fetchlock_parse,
				&state);
	if (err != NTDB_SUCCESS && err != NTDB_ERR_NOEXIST) {
		ntdb_chainunlock(ctx->ntdb, key);
		return NULL;
	}

	if (state.result == NULL) {
		db_ntdb_fetchlock_parse(key, null, &state);
	}

	if (state.result == NULL) {
		ntdb_chainunlock(ctx->ntdb, key);
		return NULL;
	}

	talloc_set_destructor(state.result, db_ntdb_record_destr);

	state.result->private_data = talloc_reference(state.result, ctx);
	state.result->store = db_ntdb_store;
	state.result->delete_rec = db_ntdb_delete;

	DEBUG(10, ("Allocated locked data 0x%p\n", state.result));

	return state.result;
}

static struct db_record *db_ntdb_fetch_locked(
	struct db_context *db, TALLOC_CTX *mem_ctx, NTDB_DATA key)
{
	struct db_ntdb_ctx *ctx = talloc_get_type_abort(db->private_data,
						       struct db_ntdb_ctx);

	db_ntdb_log_key("Locking", key);
	if (ntdb_chainlock(ctx->ntdb, key) != 0) {
		DEBUG(3, ("ntdb_chainlock failed\n"));
		return NULL;
	}
	return db_ntdb_fetch_locked_internal(db, mem_ctx, key);
}

/* Proxy which sets waitflag to false so we never block. */
static int lock_nonblock(int fd, int rw, off_t off, off_t len, bool waitflag,
			 void *_orig)
{
	struct ntdb_attribute_flock *orig = _orig;

	return orig->lock(fd, rw, off, len, false, orig->data);
}

static enum NTDB_ERROR enable_nonblock(struct ntdb_context *ntdb,
				       union ntdb_attribute *orig)
{
	union ntdb_attribute locking;
	enum NTDB_ERROR ecode;

	orig->base.attr = NTDB_ATTRIBUTE_FLOCK;
	ecode = ntdb_get_attribute(ntdb, orig);
	if (ecode != NTDB_SUCCESS) {
		return ecode;
	}

	/* Replace locking function with our own. */
	locking = *orig;
	locking.flock.data = orig;
	locking.flock.lock = lock_nonblock;

	return ntdb_set_attribute(ntdb, &locking);
}

static void disable_nonblock(struct ntdb_context *ntdb)
{
	ntdb_unset_attribute(ntdb, NTDB_ATTRIBUTE_FLOCK);
}

static enum NTDB_ERROR ntdb_chainlock_nonblock(struct ntdb_context *ntdb,
					       NTDB_DATA key)
{
	union ntdb_attribute orig;
	enum NTDB_ERROR ecode;

	ecode = enable_nonblock(ntdb, &orig);
	if (!ecode) {
		ecode = ntdb_chainlock(ntdb, key);
		disable_nonblock(ntdb);
	}
	return ecode;
}

static struct db_record *db_ntdb_try_fetch_locked(
	struct db_context *db, TALLOC_CTX *mem_ctx, TDB_DATA key)
{
	struct db_ntdb_ctx *ctx = talloc_get_type_abort(db->private_data,
						       struct db_ntdb_ctx);

	db_ntdb_log_key("Trying to lock", key);
	if (ntdb_chainlock_nonblock(ctx->ntdb, key) != 0) {
		DEBUG(3, ("ntdb_chainlock_nonblock failed\n"));
		return NULL;
	}
	return db_ntdb_fetch_locked_internal(db, mem_ctx, key);
}

static int db_ntdb_exists(struct db_context *db, TDB_DATA key)
{
	struct db_ntdb_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_ntdb_ctx);
	return ntdb_exists(ctx->ntdb, key);
}

static int db_ntdb_wipe(struct db_context *db)
{
	struct db_ntdb_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_ntdb_ctx);
	if (ntdb_wipe_all(ctx->ntdb) != NTDB_SUCCESS) {
		return -1;
	}
	return 0;
}

static int db_ntdb_check(struct db_context *db)
{
	struct db_ntdb_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_ntdb_ctx);
	if (ntdb_check(ctx->ntdb, NULL, NULL) != NTDB_SUCCESS) {
		return -1;
	}
	return 0;
}

struct db_ntdb_parse_state {
	void (*parser)(TDB_DATA key, TDB_DATA data,
		       void *private_data);
	void *private_data;
};

/*
 * ntdb_parse_record expects a parser returning enum NTDB_ERROR,
 * mixing up ntdb and parser errors. Wrap around that by always
 * returning NTDB_SUCCESS and have dbwrap_parse_record expect a parser
 * returning void.
 */

static enum NTDB_ERROR db_ntdb_parser(NTDB_DATA key, NTDB_DATA data,
				      struct db_ntdb_parse_state *state)
{
	state->parser(key, data, state->private_data);
	return TDB_SUCCESS;
}

static NTSTATUS db_ntdb_parse(struct db_context *db, TDB_DATA key,
			      void (*parser)(TDB_DATA key, TDB_DATA data,
					     void *private_data),
			      void *private_data)
{
	struct db_ntdb_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_ntdb_ctx);
	struct db_ntdb_parse_state state;
	enum NTDB_ERROR err;

	state.parser = parser;
	state.private_data = private_data;

	err = ntdb_parse_record(ctx->ntdb, key, db_ntdb_parser, &state);
	return map_nt_error_from_ntdb(err);
}

struct db_ntdb_traverse_ctx {
	struct db_context *db;
	int (*f)(struct db_record *rec, void *private_data);
	void *private_data;
};

static int db_ntdb_traverse_func(struct ntdb_context *ntdb,
				 NTDB_DATA kbuf, NTDB_DATA dbuf,
				 struct db_ntdb_traverse_ctx *ctx)
{
	struct db_record rec;

	rec.key = kbuf;
	rec.value = dbuf;
	rec.store = db_ntdb_store;
	rec.delete_rec = db_ntdb_delete;
	rec.private_data = ctx->db->private_data;
	rec.db = ctx->db;

	return ctx->f(&rec, ctx->private_data);
}

static int db_ntdb_traverse(struct db_context *db,
			    int (*f)(struct db_record *rec, void *private_data),
			    void *private_data)
{
	struct db_ntdb_ctx *db_ctx =
		talloc_get_type_abort(db->private_data, struct db_ntdb_ctx);
	struct db_ntdb_traverse_ctx ctx;
	int64_t ret;

	ctx.db = db;
	ctx.f = f;
	ctx.private_data = private_data;
	ret = ntdb_traverse(db_ctx->ntdb, db_ntdb_traverse_func, &ctx);

	if (ret < 0) {
		return -1;
	}

	/* Make sure we don't truncate! */
	if ((int)ret != ret) {
		ret = INT_MAX;
	}
	return ret;
}

static NTSTATUS db_ntdb_store_deny(struct db_record *rec, NTDB_DATA data, int flag)
{
	return NT_STATUS_MEDIA_WRITE_PROTECTED;
}

static NTSTATUS db_ntdb_delete_deny(struct db_record *rec)
{
	return NT_STATUS_MEDIA_WRITE_PROTECTED;
}

static int db_ntdb_traverse_read_func(struct ntdb_context *ntdb,
				      NTDB_DATA kbuf, NTDB_DATA dbuf,
				      struct db_ntdb_traverse_ctx *ctx)
{
	struct db_record rec;

	rec.key = kbuf;
	rec.value = dbuf;
	rec.store = db_ntdb_store_deny;
	rec.delete_rec = db_ntdb_delete_deny;
	rec.private_data = ctx->db->private_data;
	rec.db = ctx->db;

	return ctx->f(&rec, ctx->private_data);
}

static int db_ntdb_traverse_read(struct db_context *db,
				 int (*f)(struct db_record *rec,
					  void *private_data),
				 void *private_data)
{
	struct db_ntdb_ctx *db_ctx =
		talloc_get_type_abort(db->private_data, struct db_ntdb_ctx);
	struct db_ntdb_traverse_ctx ctx;
	int64_t ret;

	ctx.db = db;
	ctx.f = f;
	ctx.private_data = private_data;

	/* This is a bit of paranoia to check that f() isn't altering
	 * database. */
	if (ntdb_get_flags(db_ctx->ntdb) & NTDB_RDONLY) {
		ret = ntdb_traverse(db_ctx->ntdb, db_ntdb_traverse_read_func,
				    &ctx);
	} else {
		ntdb_add_flag(db_ctx->ntdb, NTDB_RDONLY);
		ret = ntdb_traverse(db_ctx->ntdb, db_ntdb_traverse_read_func,
				    &ctx);
		ntdb_remove_flag(db_ctx->ntdb, NTDB_RDONLY);
	}

	if (ret < 0) {
		return -1;
	}

	/* Make sure we don't truncate! */
	if ((int)ret != ret) {
		ret = INT_MAX;
	}
	return ret;
}

static int db_ntdb_get_seqnum(struct db_context *db)

{
	struct db_ntdb_ctx *db_ctx =
		talloc_get_type_abort(db->private_data, struct db_ntdb_ctx);
	return ntdb_get_seqnum(db_ctx->ntdb);
}

static int db_ntdb_transaction_start(struct db_context *db)
{
	struct db_ntdb_ctx *db_ctx =
		talloc_get_type_abort(db->private_data, struct db_ntdb_ctx);
	return ntdb_transaction_start(db_ctx->ntdb) == NTDB_SUCCESS ? 0 : -1;
}

static NTSTATUS db_ntdb_transaction_start_nonblock(struct db_context *db)
{
	union ntdb_attribute orig;
	enum NTDB_ERROR ecode;
	struct db_ntdb_ctx *db_ctx =
		talloc_get_type_abort(db->private_data, struct db_ntdb_ctx);

	ecode = enable_nonblock(db_ctx->ntdb, &orig);
	if (!ecode) {
		ecode = ntdb_transaction_start(db_ctx->ntdb);
		disable_nonblock(db_ctx->ntdb);
	}
	return map_nt_error_from_ntdb(ecode);
}

static int db_ntdb_transaction_commit(struct db_context *db)
{
	struct db_ntdb_ctx *db_ctx =
		talloc_get_type_abort(db->private_data, struct db_ntdb_ctx);
	return ntdb_transaction_commit(db_ctx->ntdb) == NTDB_SUCCESS ? 0 : -1;
}

static int db_ntdb_transaction_cancel(struct db_context *db)
{
	struct db_ntdb_ctx *db_ctx =
		talloc_get_type_abort(db->private_data, struct db_ntdb_ctx);
	ntdb_transaction_cancel(db_ctx->ntdb);
	return 0;
}

static void db_ntdb_id(struct db_context *db, const uint8_t **id, size_t *idlen)
{
	struct db_ntdb_ctx *db_ctx =
		talloc_get_type_abort(db->private_data, struct db_ntdb_ctx);
	*id = (uint8_t *)&db_ctx->id;
	*idlen = sizeof(db_ctx->id);
}

/* Don't ask this to open a .tdb file: dbwrap_local_open will catch that. */
struct db_context *db_open_ntdb(TALLOC_CTX *mem_ctx,
				struct loadparm_context *lp_ctx,
				const char *ntdbname,
				int hash_size, int ntdb_flags,
				int open_flags, mode_t mode,
				enum dbwrap_lock_order lock_order,
				uint64_t dbwrap_flags)
{
	struct db_context *result = NULL;
	struct db_ntdb_ctx *db_ntdb;
	struct stat st;
	union ntdb_attribute hattr;

	if ((ntdb_flags & NTDB_INTERNAL) && !ntdbname) {
		ntdbname = "unnamed";
	}

	/* Extra paranoia. */
	if (strends(ntdbname, ".tdb")) {
		DEBUG(0, ("can't try to open %s with ntdb!", ntdbname));
		return NULL;
	}

	/* We only use this if hsize is non-zero. */
	hattr.base.attr = NTDB_ATTRIBUTE_HASHSIZE;
	hattr.base.next = NULL;
	hattr.hashsize.size = hash_size;

	result = talloc_zero(mem_ctx, struct db_context);
	if (result == NULL) {
		DEBUG(0, ("talloc failed\n"));
		goto fail;
	}

	result->private_data = db_ntdb = talloc(result, struct db_ntdb_ctx);
	if (db_ntdb == NULL) {
		DEBUG(0, ("talloc failed\n"));
		goto fail;
	}
	result->lock_order = lock_order;

	db_ntdb->ntdb = ntdb_new(db_ntdb, ntdbname, ntdb_flags,
				 open_flags, mode,
				 hash_size ? &hattr : NULL, lp_ctx);
	if (db_ntdb->ntdb == NULL) {
		DEBUG(3, ("Could not open ntdb %s: %s\n",
			  ntdbname, strerror(errno)));
		goto fail;
	}

	ZERO_STRUCT(db_ntdb->id);

	if (fstat(ntdb_fd(db_ntdb->ntdb), &st) == -1) {
		DEBUG(3, ("fstat failed: %s\n", strerror(errno)));
		goto fail;
	}
	db_ntdb->id.dev = st.st_dev;
	db_ntdb->id.ino = st.st_ino;

	result->fetch_locked = db_ntdb_fetch_locked;
	result->try_fetch_locked = db_ntdb_try_fetch_locked;
	result->traverse = db_ntdb_traverse;
	result->traverse_read = db_ntdb_traverse_read;
	result->parse_record = db_ntdb_parse;
	result->get_seqnum = db_ntdb_get_seqnum;
	result->persistent = ((ntdb_flags & NTDB_CLEAR_IF_FIRST) == 0);
	result->transaction_start = db_ntdb_transaction_start;
	result->transaction_start_nonblock = db_ntdb_transaction_start_nonblock;
	result->transaction_commit = db_ntdb_transaction_commit;
	result->transaction_cancel = db_ntdb_transaction_cancel;
	result->exists = db_ntdb_exists;
	result->wipe = db_ntdb_wipe;
	result->id = db_ntdb_id;
	result->check = db_ntdb_check;
	result->stored_callback = NULL;
	result->name = ntdb_name(db_ntdb->ntdb);
	result->hash_size = hash_size;
	return result;

 fail:
	if (result != NULL) {
		TALLOC_FREE(result);
	}
	return NULL;
}
