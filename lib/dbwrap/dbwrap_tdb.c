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

#include "replace.h"
#include "system/dir.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_private.h"
#include "dbwrap/dbwrap_tdb.h"
#include "lib/tdb_wrap/tdb_wrap.h"
#include "lib/util/util_tdb.h"
#include "lib/util/debug.h"
#include "lib/util/samba_util.h"
#include "system/filesys.h"
#include "lib/param/param.h"
#include "libcli/util/error.h"

struct db_tdb_ctx {
	struct tdb_wrap *wtdb;

	/* Persistent tdb for DBWRAP_FLAG_PER_REC_PERSISTENT*/
	struct tdb_wrap *ptdb;

	struct {
		dev_t dev;
		ino_t ino;
	} id;
};

struct dbwrap_tdb_header {
        uint32_t version;
        uint32_t flags;
        uint32_t reserved[2];
};

#define DBWRAP_TDB_HEADER_VERSION	1
#define DBWRAP_TDB_FLAG_PERSISTENT	(1 << 0)


static NTSTATUS db_tdb_storev(struct db_record *rec,
			      const TDB_DATA *dbufs, int num_dbufs, int flag);
static NTSTATUS db_tdb_delete(struct db_record *rec);

static int db_tdb_record_destr(struct db_record* data)
{
	struct db_tdb_ctx *ctx =
		talloc_get_type_abort(data->private_data, struct db_tdb_ctx);

	dbwrap_log_key("Unlocking", data->key);
	tdb_chainunlock(ctx->wtdb->tdb, data->key);
	return 0;
}

struct tdb_fetch_locked_state {
	TALLOC_CTX *mem_ctx;
	struct db_context *db;
	struct db_record *result;
};

static int db_tdb_fetchlock_parse(TDB_DATA key, TDB_DATA data,
				  void *private_data)
{
	struct tdb_fetch_locked_state *state =
		(struct tdb_fetch_locked_state *)private_data;
	struct db_record *result;
	struct db_record_flags flags = {};

	if ((state->db->flags & DBWRAP_FLAG_PER_REC_PERSISTENT) &&
	    (data.dsize > 0))
	{
		struct dbwrap_tdb_header header;

		SMB_ASSERT(data.dsize >= sizeof(header));
		memcpy(&header, data.dptr, sizeof(header));
		SMB_ASSERT(header.version == DBWRAP_TDB_HEADER_VERSION);

		data.dsize -= sizeof(header);
		data.dptr += sizeof(header);

		if (header.flags & DBWRAP_TDB_FLAG_PERSISTENT) {
			flags.persistent = true;
		}
	}

	result = (struct db_record *)talloc_size(
		state->mem_ctx,
		sizeof(struct db_record) + key.dsize + data.dsize);

	if (result == NULL) {
		return 0;
	}
	state->result = result;

	result->flags = flags;
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
	result->value_valid = true;

	return 0;
}

static struct db_record *db_tdb_fetch_locked_internal(
	struct db_context *db,
	struct db_tdb_ctx *ctx,
	TALLOC_CTX *mem_ctx,
	TDB_DATA key)
{
	struct tdb_fetch_locked_state state;
	int ret;

	state = (struct tdb_fetch_locked_state) {
		.mem_ctx = mem_ctx,
		.db = db,
	};

	ret = tdb_parse_record(ctx->wtdb->tdb,
			       key,
			       db_tdb_fetchlock_parse,
			       &state);
	if ((ret < 0) && (tdb_error(ctx->wtdb->tdb) != TDB_ERR_NOEXIST)) {
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

	state.result->private_data = ctx;
	state.result->storev = db_tdb_storev;
	state.result->delete_rec = db_tdb_delete;

	DBG_DEBUG("Allocated locked data %p\n", state.result);

	return state.result;
}

static struct db_record *db_tdb_fetch_locked(
	struct db_context *db, TALLOC_CTX *mem_ctx, TDB_DATA key)
{
	struct db_tdb_ctx *ctx = talloc_get_type_abort(db->private_data,
						       struct db_tdb_ctx);

	dbwrap_log_key("Locking", key);
	if (tdb_chainlock(ctx->wtdb->tdb, key) != 0) {
		DEBUG(3, ("tdb_chainlock failed\n"));
		return NULL;
	}
	return db_tdb_fetch_locked_internal(db, ctx, mem_ctx, key);
}

static NTSTATUS db_tdb_do_locked(struct db_context *db, TDB_DATA key,
				 void (*fn)(struct db_record *rec,
					    TDB_DATA value,
					    void *private_data),
				 void *private_data)
{
	struct db_tdb_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_tdb_ctx);
	uint8_t *buf = NULL;
	struct db_record rec;
	TDB_DATA value;
	int ret;

	ret = tdb_chainlock(ctx->wtdb->tdb, key);
	if (ret == -1) {
		enum TDB_ERROR err = tdb_error(ctx->wtdb->tdb);
		DBG_DEBUG("tdb_chainlock failed: %s\n",
			  tdb_errorstr(ctx->wtdb->tdb));
		return map_nt_error_from_tdb(err);
	}

	ret = tdb_fetch_talloc(ctx->wtdb->tdb, key, ctx, &buf);

	if ((ret != 0) && (ret != ENOENT)) {
		DBG_DEBUG("tdb_fetch_talloc failed: %s\n",
			  strerror(errno));
		tdb_chainunlock(ctx->wtdb->tdb, key);
		return map_nt_error_from_unix_common(ret);
	}

	rec = (struct db_record) {
		.db = db, .key = key,
		.value_valid = false,
		.storev = db_tdb_storev, .delete_rec = db_tdb_delete,
		.private_data = ctx
	};

        value = (TDB_DATA) {
                .dptr = buf,
                .dsize = talloc_get_size(buf)
        };

	if ((db->flags & DBWRAP_FLAG_PER_REC_PERSISTENT) &&
	    (value.dsize > 0))
	{
                struct dbwrap_tdb_header header;

		SMB_ASSERT(value.dsize >= sizeof(header));
                memcpy(&header, value.dptr, sizeof(header));
                value.dsize -= sizeof(struct dbwrap_tdb_header);
                value.dptr += sizeof(struct dbwrap_tdb_header);

                SMB_ASSERT(header.version == DBWRAP_TDB_HEADER_VERSION);
                if (header.flags & DBWRAP_TDB_FLAG_PERSISTENT) {
                        rec.flags.persistent = true;
                }
        }

        fn(&rec, value, private_data);

	tdb_chainunlock(ctx->wtdb->tdb, key);

	talloc_free(buf);

	return NT_STATUS_OK;
}

static int db_tdb_exists(struct db_context *db, TDB_DATA key)
{
	struct db_tdb_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_tdb_ctx);
	return tdb_exists(ctx->wtdb->tdb, key);
}

static int db_tdb_wipe(struct db_context *db, struct dbwrap_wipe_flags flags)
{
	struct db_tdb_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_tdb_ctx);
	int ret;

	if (flags.wipe_persistent_backup_db) {
		if (!(db->flags & DBWRAP_FLAG_PER_REC_PERSISTENT)) {
			return 0;
		}

		ret = tdb_wipe_all(ctx->ptdb->tdb);
		if (ret != 0) {
			return -1;
		}
	}

	if (flags.wipe_default) {
		ret = tdb_wipe_all(ctx->wtdb->tdb);
		if (ret != 0) {
			return -1;
		}
	}

	return 0;
}

static int db_tdb_check(struct db_context *db)
{
	struct db_tdb_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_tdb_ctx);
	return tdb_check(ctx->wtdb->tdb, NULL, NULL);
}

struct db_tdb_parse_state {
	struct db_context *db;
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

	if (state->db->flags & DBWRAP_FLAG_PER_REC_PERSISTENT) {
		if (data.dsize < sizeof(struct dbwrap_tdb_header)) {
			dbwrap_log_key("bad key", key);
			return -1;
		}
		data.dsize -= sizeof(struct dbwrap_tdb_header);
		data.dptr += sizeof(struct dbwrap_tdb_header);
	}

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

	state = (struct db_tdb_parse_state) {
		.db = db,
		.parser = parser,
		.private_data = private_data,
	};

	ret = tdb_parse_record(ctx->wtdb->tdb, key, db_tdb_parser, &state);

	if (ret != 0) {
		return map_nt_error_from_tdb(tdb_error(ctx->wtdb->tdb));
	}
	return NT_STATUS_OK;
}

static NTSTATUS db_tdb_storev(struct db_record *rec,
			      const TDB_DATA *orig_dbufs,
			      int orig_num_dbufs,
			      int flag)
{
	struct db_tdb_ctx *ctx = talloc_get_type_abort(rec->private_data,
						       struct db_tdb_ctx);
	struct tdb_context *tdb = ctx->wtdb->tdb;
	bool db_persistent = (rec->db->flags & DBWRAP_FLAG_PER_REC_PERSISTENT);
	int num_dbufs = db_persistent ? orig_num_dbufs + 1 : orig_num_dbufs;
	TDB_DATA _dbufs[num_dbufs];
	const TDB_DATA *dbufs = db_persistent ? _dbufs : orig_dbufs;
	struct dbwrap_tdb_header h;
	bool do_persistent_store = false;
	bool do_persistent_delete = false;
	bool in_txn = false;
	int tdb_flag;
	NTSTATUS status;
	int ret;

	/*
	 * This has a bug: We need to replace rec->value for correct
	 * operation, but right now brlock and locking don't use the value
	 * anymore after it was stored.
	 */

	if (db_persistent) {
		h = (struct dbwrap_tdb_header) {
			.version = DBWRAP_TDB_HEADER_VERSION,
			.flags = flag & DBWRAP_STORE_PERSISTENT ?
				DBWRAP_TDB_FLAG_PERSISTENT : 0,
		};

		_dbufs[0].dsize = sizeof(h);
		_dbufs[0].dptr = (unsigned char *)&h;
		memcpy(&_dbufs[1],
		       orig_dbufs,
		       orig_num_dbufs * sizeof(TDB_DATA));
	}

	/* Make sure not to confuse tdb with any other flag */
	tdb_flag = flag & DBWRAP_TDB_FLAGS;

	ret = tdb_storev(ctx->wtdb->tdb,
			 rec->key,
			 dbufs,
			 num_dbufs,
			 tdb_flag);
	if (ret != 0) {
		enum TDB_ERROR err = tdb_error(tdb);
		status = map_nt_error_from_tdb(err);
		return status;
	}

	if (flag & DBWRAP_STORE_PERSISTENT) {
		do_persistent_store = true;
	} else if (rec->flags.persistent) {
		do_persistent_delete = true;
	}

	if (!do_persistent_store && !do_persistent_delete) {
		return NT_STATUS_OK;
	}
	if (!db_persistent) {
		DBG_ERR("Invalid persistency request\n");
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	ret = tdb_transaction_start(ctx->ptdb->tdb);
	if (ret != 0) {
		enum TDB_ERROR err = tdb_error(tdb);
		status = map_nt_error_from_tdb(err);
		goto fail;
	}
	in_txn = true;

	if (do_persistent_store) {
		ret = tdb_storev(ctx->ptdb->tdb,
				 rec->key,
				 dbufs,
				 num_dbufs,
				 tdb_flag);
		if (ret != 0) {
			enum TDB_ERROR err = tdb_error(tdb);
			status = map_nt_error_from_tdb(err);
			goto fail;
		}
	} else {
		ret = tdb_delete(ctx->ptdb->tdb, rec->key);
		if (ret != 0) {
			enum TDB_ERROR err = tdb_error(tdb);
			status = map_nt_error_from_tdb(err);
			goto fail;
		}
	}

	ret = tdb_transaction_commit(ctx->ptdb->tdb);
	in_txn = false;
	if (ret != 0) {
		enum TDB_ERROR err = tdb_error(tdb);
		status = map_nt_error_from_tdb(err);
		goto fail;
	}

	status = NT_STATUS_OK;

fail:
	if (in_txn) {
		ret = tdb_transaction_cancel(ctx->ptdb->tdb);
		SMB_ASSERT(ret == 0);
	}
	return status;
}

static NTSTATUS db_tdb_delete_persistent(struct db_record *rec)
{
	struct db_tdb_ctx *ctx = talloc_get_type_abort(rec->private_data,
						       struct db_tdb_ctx);
	bool in_txn = false;
	int ret;

	ret = tdb_transaction_start(ctx->ptdb->tdb);
	if (ret != 0) {
		goto fail;
	}
	in_txn = true;

	ret = tdb_delete(ctx->ptdb->tdb, rec->key);
	if (ret != 0) {
		goto fail;
	}

	ret = tdb_transaction_commit(ctx->ptdb->tdb);
	in_txn = false;
	if (ret != 0) {
		goto fail;
	}

	return NT_STATUS_OK;

fail:
	if (in_txn) {
		ret = tdb_transaction_cancel(ctx->ptdb->tdb);
		SMB_ASSERT(ret == 0);
	}
	if (tdb_error(ctx->ptdb->tdb) == TDB_ERR_NOEXIST) {
		return NT_STATUS_NOT_FOUND;
	}
	return NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS db_tdb_delete(struct db_record *rec)
{
	struct db_tdb_ctx *ctx = talloc_get_type_abort(rec->private_data,
						       struct db_tdb_ctx);
	NTSTATUS status;

	if (rec->flags.persistent) {
		status = db_tdb_delete_persistent(rec);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

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
	bool found_marker;
};

static int db_tdb_traverse_func(TDB_CONTEXT *tdb, TDB_DATA kbuf, TDB_DATA dbuf,
				void *private_data)
{
	struct db_tdb_traverse_ctx *ctx =
		(struct db_tdb_traverse_ctx *)private_data;
	struct db_record rec = {};

	if (ctx->db->flags & DBWRAP_FLAG_PER_REC_PERSISTENT) {
		struct dbwrap_tdb_header h;
		int cmp = 1;

		if (kbuf.dsize ==
		    sizeof(DBWRAP_PERSISTENT_MIGRATION_MARKER_KEY))
		{
			cmp = memcmp(
				kbuf.dptr,
				DBWRAP_PERSISTENT_MIGRATION_MARKER_KEY,
				sizeof(DBWRAP_PERSISTENT_MIGRATION_MARKER_KEY));
		}
		if (cmp == 0) {
			ctx->found_marker = true;
			return 0;
		}

		if (dbuf.dsize < sizeof(struct dbwrap_tdb_header)) {
			dbwrap_log_key("Small record", kbuf);
			return 0;
		}

		memcpy(&h, dbuf.dptr, sizeof(h));
		SMB_ASSERT(h.version == DBWRAP_TDB_HEADER_VERSION);

		if (h.flags & DBWRAP_TDB_FLAG_PERSISTENT) {
			rec.flags.persistent = true;
		}

		dbuf.dptr += sizeof(struct dbwrap_tdb_header);
		dbuf.dsize -= sizeof(struct dbwrap_tdb_header);
	}

	rec.key = kbuf;
	rec.value = dbuf;
	rec.value_valid = true;
	rec.storev = db_tdb_storev;
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
	int nrecs;

	ctx = (struct db_tdb_traverse_ctx) {
		.db = db,
		.f = f,
		.private_data = private_data,
	};

	nrecs = tdb_traverse(db_ctx->wtdb->tdb, db_tdb_traverse_func, &ctx);
	if (ctx.found_marker) {
		nrecs--;
	}
	return nrecs;
}

static NTSTATUS db_tdb_storev_deny(struct db_record *rec,
				   const TDB_DATA *dbufs, int num_dbufs,
				   int flag)
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
	struct db_record rec = {};

	if (ctx->db->flags & DBWRAP_FLAG_PER_REC_PERSISTENT) {
		struct dbwrap_tdb_header h;
		int cmp = 1;

		if (kbuf.dsize ==
		    sizeof(DBWRAP_PERSISTENT_MIGRATION_MARKER_KEY))
		{
			cmp = memcmp(
				kbuf.dptr,
				DBWRAP_PERSISTENT_MIGRATION_MARKER_KEY,
				sizeof(DBWRAP_PERSISTENT_MIGRATION_MARKER_KEY));
		}
		if (cmp == 0) {
			ctx->found_marker = true;
			return 0;
		}

		if (dbuf.dsize < sizeof(struct dbwrap_tdb_header)) {
			dbwrap_log_key("Small record", kbuf);
			return 0;
		}

		memcpy(&h, dbuf.dptr, sizeof(h));
		SMB_ASSERT(h.version == DBWRAP_TDB_HEADER_VERSION);

		if (h.flags & DBWRAP_TDB_FLAG_PERSISTENT) {
			rec.flags.persistent = true;
		}

		dbuf.dptr += sizeof(struct dbwrap_tdb_header);
		dbuf.dsize -= sizeof(struct dbwrap_tdb_header);
	}

	rec.key = kbuf;
	rec.value = dbuf;
	rec.value_valid = true;
	rec.storev = db_tdb_storev_deny;
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
	int nrecs;

	ctx = (struct db_tdb_traverse_ctx) {
		.db = db,
		.f = f,
		.private_data = private_data,
	};

	nrecs = tdb_traverse_read(db_ctx->wtdb->tdb,
				  db_tdb_traverse_read_func,
				  &ctx);
	if (ctx.found_marker) {
		nrecs--;
	}
	return nrecs;
}

static int db_tdb_traverse_per_rec_persistent_read(
	struct db_context *db,
	int (*f)(struct db_record *rec,
		 void *private_data),
	void *private_data)
{
	struct db_tdb_ctx *db_ctx = talloc_get_type_abort(
		db->private_data, struct db_tdb_ctx);
	struct db_tdb_traverse_ctx ctx;
	int nrecs;

	if (!(db->flags & DBWRAP_FLAG_PER_REC_PERSISTENT)) {
		return 0;
	}

	ctx = (struct db_tdb_traverse_ctx) {
		.db = db,
		.f = f,
		.private_data = private_data,
	};

	nrecs = tdb_traverse_read(db_ctx->ptdb->tdb,
				  db_tdb_traverse_read_func,
				  &ctx);
	if (ctx.found_marker) {
		nrecs--;
	}
	return nrecs;
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

static size_t db_tdb_id(struct db_context *db, uint8_t *id, size_t idlen)
{
	struct db_tdb_ctx *db_ctx =
		talloc_get_type_abort(db->private_data, struct db_tdb_ctx);

	if (idlen >= sizeof(db_ctx->id)) {
		memcpy(id, &db_ctx->id, sizeof(db_ctx->id));
	}

	return sizeof(db_ctx->id);
}

struct migrate_persistent_state {
	struct db_tdb_ctx *db_tdb;
};

static int migrate_persistent_traverse_fn(struct tdb_context *tdb,
					  TDB_DATA key,
					  TDB_DATA data,
					  void *private_data)
{
	struct migrate_persistent_state *state =
		(struct migrate_persistent_state *)private_data;
	int ret;

	ret = tdb_store(state->db_tdb->wtdb->tdb, key, data, 0);
	if (ret != 0) {
		return -1;
	}

	return 0;
}

static int db_tdb_migrate_persistent_recs(struct db_context *db)
{
	struct db_tdb_ctx *db_tdb = talloc_get_type_abort(db->private_data,
							  struct db_tdb_ctx);
	struct migrate_persistent_state migration_state;
	struct db_record *marker_rec = NULL;
	TDB_DATA marker_key;
	TDB_DATA marker_val;
	char *curtime = NULL;
	NTSTATUS status;
	int ret;

	/*
	 * First let's check if the volatile db was cleared by
	 * clear-if-first. That would imply a smbd restart so we have to trigger
	 * migration of records from the persistent db back to the volatile db.
	 */
	marker_key = string_term_tdb_data(
		DBWRAP_PERSISTENT_MIGRATION_MARKER_KEY);

	marker_rec = dbwrap_fetch_locked(db, db, marker_key);
	if (marker_rec == NULL) {
		DBG_ERR("db_tdb_fetch_locked() failed\n");
		ret = -1;
		goto out;
	}

	marker_val = dbwrap_record_get_value(marker_rec);
	if (marker_val.dptr != NULL) {
		DBG_DEBUG("Migration marker: %s\n", marker_val.dptr);
		ret = 0;
		goto out;
	}

	migration_state = (struct migrate_persistent_state) {
		.db_tdb = db_tdb,
	};

	ret = tdb_traverse_read(db_tdb->ptdb->tdb,
				migrate_persistent_traverse_fn,
				&migration_state);
	if (ret == -1) {
		DBG_ERR("tdb_traverse_read failed\n");
		goto out;
	}

	curtime = current_timestring(marker_rec, false);
	if (curtime == NULL) {
		ret = -1;
		goto out;
	}

	status = dbwrap_record_store(marker_rec,
				     string_term_tdb_data(curtime),
				     DBWRAP_INSERT);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to write migration marker: %s\n",
			nt_errstr(status));
		goto out;
	}

	ret = 0;

out:
	TALLOC_FREE(marker_rec);
	return ret;
}

static bool db_open_tdb_per_rec_persistent(struct db_context *db,
					   const char *name,
					   int hash_size,
					   int tdb_flags,
					   int open_flags,
					   mode_t mode,
					   uint64_t dbwrap_flags)
{
	struct db_tdb_ctx *db_tdb = talloc_get_type_abort(
		db->private_data, struct db_tdb_ctx);
	char *tdb_dirname = NULL;
	char *tdb_basename = NULL;
	char *dot = NULL;
	char *persistent_path = NULL;
	int ptdb_flags;
	int ret;

	if (!(dbwrap_flags & DBWRAP_FLAG_PER_REC_PERSISTENT)) {
		return true;
	}

	if (!(tdb_flags & TDB_CLEAR_IF_FIRST)) {
		DBG_WARNING("DBWRAP_FLAG_PER_REC_PERSISTENT only allowed with "
			    "TDB_CLEAR_IF_FIRST\n");
		return false;
	}

	tdb_dirname = talloc_strdup(db, name);
	if (tdb_dirname == NULL) {
		return false;
	}
	tdb_basename = talloc_strdup(db, name);
	if (tdb_basename == NULL) {
		return false;
	}
	dot = strrchr(tdb_basename, '.');
	if (dot != NULL) {
		*dot = '\0';
	}

	persistent_path = talloc_asprintf(db,
					  "%s/%s_persistent.tdb",
					  dirname(tdb_dirname),
					  basename(tdb_basename));
	TALLOC_FREE(tdb_dirname);
	TALLOC_FREE(tdb_basename);
	if (persistent_path == NULL) {
		return false;
	}

	ptdb_flags = tdb_flags & ~(TDB_CLEAR_IF_FIRST | TDB_MUTEX_LOCKING);

	db_tdb->ptdb = tdb_wrap_open(db_tdb,
				     persistent_path,
				     hash_size,
				     ptdb_flags,
				     open_flags,
				     mode);
	TALLOC_FREE(persistent_path);
	if (db_tdb->ptdb == NULL) {
		DBG_ERR("Could not open persistent tdb for %s: %s\n",
			db->name, strerror(errno));
		return false;
	}

	db->traverse_per_rec_persistent_read =
		db_tdb_traverse_per_rec_persistent_read;

	if ((open_flags & O_ACCMODE) != O_RDWR) {
		return true;
	}

	ret = db_tdb_migrate_persistent_recs(db);
	if (ret != 0) {
		DBG_ERR("Record migration in db %s failed\n", db->name);
		return false;
	}
	return true;
}

struct db_context *db_open_tdb(TALLOC_CTX *mem_ctx,
			       const char *name,
			       int hash_size, int tdb_flags,
			       int open_flags, mode_t mode,
			       enum dbwrap_lock_order lock_order,
			       uint64_t dbwrap_flags)
{
	struct db_context *result = NULL;
	struct db_tdb_ctx *db_tdb;
	struct stat st;
	bool ok;

	result = talloc_zero(mem_ctx, struct db_context);
	if (result == NULL) {
		DEBUG(0, ("talloc failed\n"));
		goto fail;
	}

	result->private_data = db_tdb = talloc_zero(result, struct db_tdb_ctx);
	if (db_tdb == NULL) {
		DEBUG(0, ("talloc failed\n"));
		goto fail;
	}
	result->lock_order = lock_order;

	db_tdb->wtdb = tdb_wrap_open(db_tdb, name, hash_size, tdb_flags,
				     open_flags, mode);
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
	result->do_locked = db_tdb_do_locked;
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
	result->name = tdb_name(db_tdb->wtdb->tdb);
	result->flags = dbwrap_flags;

	ok = db_open_tdb_per_rec_persistent(result,
					    name,
					    hash_size,
					    tdb_flags,
					    open_flags,
					    mode,
					    dbwrap_flags);
	if (!ok) {
		goto fail;
	}

	return result;

 fail:
	TALLOC_FREE(result);
	return NULL;
}
