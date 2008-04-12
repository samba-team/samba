/*
   Unix SMB/CIFS implementation.

   Database interface wrapper around tdb/ctdb

   Copyright (C) Volker Lendecke 2005-2007
   Copyright (C) Stefan Metzmacher 2008

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
#include "librpc/gen_ndr/ndr_messaging.h"

struct db_tdb2_ctx {
	struct db_context *db;
	const char *name;
	struct tdb_wrap *mtdb;
	const char *mtdb_path;
	bool master_transaction;
	struct {
		int hash_size;
		int tdb_flags;
		int open_flags;
		mode_t mode;
	} open;
	struct tdb_wrap *ltdb;
	const char *ltdb_path;
	bool local_transaction;
	int transaction;
	bool out_of_sync;
	uint32_t lseqnum;
	uint32_t mseqnum;
#define DB_TDB2_MASTER_SEQNUM_KEYSTR "DB_TDB2_MASTER_SEQNUM_KEYSTR"
	TDB_DATA mseqkey;
	uint32_t max_buffer_size;
	uint32_t current_buffer_size;
	struct dbwrap_tdb2_changes changes;
};


static NTSTATUS db_tdb2_store(struct db_record *rec, TDB_DATA data, int flag);
static NTSTATUS db_tdb2_delete(struct db_record *rec);

static void db_tdb2_queue_change(struct db_tdb2_ctx *db_ctx, const TDB_DATA key);
static void db_tdb2_send_notify(struct db_tdb2_ctx *db_ctx);

static struct db_context *db_open_tdb2_ex(TALLOC_CTX *mem_ctx,
					  const char *name,
					  int hash_size, int tdb_flags,
					  int open_flags, mode_t mode,
					  const struct dbwrap_tdb2_changes *chgs);

static int db_tdb2_sync_from_master(struct db_tdb2_ctx *db_ctx,
				    const struct dbwrap_tdb2_changes *changes);

static int db_tdb2_open_master(struct db_tdb2_ctx *db_ctx, bool transaction,
			       const struct dbwrap_tdb2_changes *changes);
static int db_tdb2_commit_local(struct db_tdb2_ctx *db_ctx, uint32_t mseqnum);
static int db_tdb2_close_master(struct db_tdb2_ctx *db_ctx);
static int db_tdb2_transaction_cancel(struct db_context *db);

static void db_tdb2_receive_changes(struct messaging_context *msg,
				    void *private_data,
				    uint32_t msg_type,
				    struct server_id server_id,
				    DATA_BLOB *data);

static struct messaging_context *global_tdb2_msg_ctx;
static bool global_tdb2_msg_ctx_initialized;

void db_tdb2_setup_messaging(struct messaging_context *msg_ctx, bool server)
{
	global_tdb2_msg_ctx = msg_ctx;

	global_tdb2_msg_ctx_initialized = true;

	if (!server) {
		return;
	}

	if (!lp_parm_bool(-1, "dbwrap", "use_tdb2", false)) {
		return;
	}

	messaging_register(msg_ctx, NULL, MSG_DBWRAP_TDB2_CHANGES,
			   db_tdb2_receive_changes);
}

static struct messaging_context *db_tdb2_get_global_messaging_context(void)
{
	struct messaging_context *msg_ctx;

	if (global_tdb2_msg_ctx_initialized) {
		return global_tdb2_msg_ctx;
	}

	msg_ctx = messaging_init(NULL, procid_self(),
				 event_context_init(NULL));

	db_tdb2_setup_messaging(msg_ctx, false);

	return global_tdb2_msg_ctx;
}

struct tdb_fetch_locked_state {
	TALLOC_CTX *mem_ctx;
	struct db_record *result;
};

static int db_tdb2_fetchlock_parse(TDB_DATA key, TDB_DATA data,
				  void *private_data)
{
	struct tdb_fetch_locked_state *state =
		(struct tdb_fetch_locked_state *)private_data;

	state->result = (struct db_record *)talloc_size(
		state->mem_ctx,
		sizeof(struct db_record) + key.dsize + data.dsize);

	if (state->result == NULL) {
		return 0;
	}

	state->result->key.dsize = key.dsize;
	state->result->key.dptr = ((uint8 *)state->result)
		+ sizeof(struct db_record);
	memcpy(state->result->key.dptr, key.dptr, key.dsize);

	state->result->value.dsize = data.dsize;

	if (data.dsize > 0) {
		state->result->value.dptr = state->result->key.dptr+key.dsize;
		memcpy(state->result->value.dptr, data.dptr, data.dsize);
	}
	else {
		state->result->value.dptr = NULL;
	}

	return 0;
}

static struct db_record *db_tdb2_fetch_locked(struct db_context *db,
					      TALLOC_CTX *mem_ctx, TDB_DATA key)
{
	struct db_tdb2_ctx *ctx = talloc_get_type_abort(db->private_data,
							struct db_tdb2_ctx);
	struct tdb_fetch_locked_state state;

	/* Do not accidently allocate/deallocate w/o need when debug level is lower than needed */
	if(DEBUGLEVEL >= 10) {
		char *keystr = hex_encode(NULL, (unsigned char*)key.dptr, key.dsize);
		DEBUG(10, (DEBUGLEVEL > 10
			   ? "Locking key %s\n" : "Locking key %.20s\n",
			   keystr));
		TALLOC_FREE(keystr);
	}

	/*
	 * we only support modifications within a
	 * started transaction.
	 */
	if (ctx->transaction == 0) {
		DEBUG(0, ("db_tdb2_fetch_locked[%s]: no transaction started\n",
			  ctx->name));
		smb_panic("no transaction");
		return NULL;
	}

	state.mem_ctx = mem_ctx;
	state.result = NULL;

	tdb_parse_record(ctx->mtdb->tdb, key, db_tdb2_fetchlock_parse, &state);

	if (state.result == NULL) {
		db_tdb2_fetchlock_parse(key, tdb_null, &state);
	}

	if (state.result == NULL) {
		return NULL;
	}

	state.result->private_data = talloc_reference(state.result, ctx);
	state.result->store = db_tdb2_store;
	state.result->delete_rec = db_tdb2_delete;

	DEBUG(10, ("Allocated locked data 0x%p\n", state.result));

	return state.result;
}

struct tdb_fetch_state {
	TALLOC_CTX *mem_ctx;
	int result;
	TDB_DATA data;
};

static int db_tdb2_fetch_parse(TDB_DATA key, TDB_DATA data,
			       void *private_data)
{
	struct tdb_fetch_state *state =
		(struct tdb_fetch_state *)private_data;

	state->data.dptr = (uint8 *)talloc_memdup(state->mem_ctx, data.dptr,
						  data.dsize);
	if (state->data.dptr == NULL) {
		state->result = -1;
		return 0;
	}

	state->data.dsize = data.dsize;
	return 0;
}

static void db_tdb2_resync_before_read(struct db_tdb2_ctx *db_ctx, TDB_DATA *kbuf)
{
	if (db_ctx->mtdb) {
		return;
	}

	if (!db_ctx->out_of_sync) {
		return;
	}

	/*
	 * this function operates on the local copy,
	 * so hide the DB_TDB2_MASTER_SEQNUM_KEYSTR from the caller.
	 */
	if (kbuf && (db_ctx->mseqkey.dsize == kbuf->dsize) &&
	    (memcmp(db_ctx->mseqkey.dptr, kbuf->dptr, kbuf->dsize) == 0)) {
		return;
	}

	DEBUG(0,("resync_before_read[%s/%s]\n",
		 db_ctx->mtdb_path, db_ctx->ltdb_path));

	db_tdb2_open_master(db_ctx, false, NULL);
	db_tdb2_close_master(db_ctx);
}

static int db_tdb2_fetch(struct db_context *db, TALLOC_CTX *mem_ctx,
			 TDB_DATA key, TDB_DATA *pdata)
{
	struct db_tdb2_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_tdb2_ctx);

	struct tdb_fetch_state state;

	db_tdb2_resync_before_read(ctx, &key);

	if (ctx->out_of_sync) {
		DEBUG(0,("out of sync[%s] failing fetch\n",
			 ctx->ltdb_path));
		errno = EIO;
		return -1;
	}

	state.mem_ctx = mem_ctx;
	state.result = 0;
	state.data = tdb_null;

	tdb_parse_record(ctx->ltdb->tdb, key, db_tdb2_fetch_parse, &state);

	if (state.result == -1) {
		return -1;
	}

	*pdata = state.data;
	return 0;
}

static NTSTATUS db_tdb2_store(struct db_record *rec, TDB_DATA data, int flag)
{
	struct db_tdb2_ctx *ctx = talloc_get_type_abort(rec->private_data,
						       struct db_tdb2_ctx);
	int ret;

	/*
	 * This has a bug: We need to replace rec->value for correct
	 * operation, but right now brlock and locking don't use the value
	 * anymore after it was stored.
	 */

	/* first store it to the master copy */
	ret = tdb_store(ctx->mtdb->tdb, rec->key, data, flag);
	if (ret != 0) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* then store it to the local copy */
	ret = tdb_store(ctx->ltdb->tdb, rec->key, data, flag);
	if (ret != 0) {
		/* try to restore the old value in the master copy */
		if (rec->value.dptr) {
			tdb_store(ctx->mtdb->tdb, rec->key,
				  rec->value, TDB_REPLACE);
		} else {
			tdb_delete(ctx->mtdb->tdb, rec->key);
		}
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	db_tdb2_queue_change(ctx, rec->key);

	return NT_STATUS_OK;
}

static NTSTATUS db_tdb2_delete(struct db_record *rec)
{
	struct db_tdb2_ctx *ctx = talloc_get_type_abort(rec->private_data,
						       struct db_tdb2_ctx);
	int ret;

	ret = tdb_delete(ctx->mtdb->tdb, rec->key);
	if (ret != 0) {
		if (tdb_error(ctx->mtdb->tdb) == TDB_ERR_NOEXIST) {
			return NT_STATUS_NOT_FOUND;
		}

		return NT_STATUS_UNSUCCESSFUL;
	}

	ret = tdb_delete(ctx->ltdb->tdb, rec->key);
	if (ret != 0) {
		/* try to restore the value in the master copy */
		tdb_store(ctx->mtdb->tdb, rec->key,
			  rec->value, TDB_REPLACE);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	db_tdb2_queue_change(ctx, rec->key);

	return NT_STATUS_OK;
}

struct db_tdb2_traverse_ctx {
	struct db_tdb2_ctx *db_ctx;
	int (*f)(struct db_record *rec, void *private_data);
	void *private_data;
};

static int db_tdb2_traverse_func(TDB_CONTEXT *tdb, TDB_DATA kbuf, TDB_DATA dbuf,
				void *private_data)
{
	struct db_tdb2_traverse_ctx *ctx =
		(struct db_tdb2_traverse_ctx *)private_data;
	struct db_record rec;

	/* this function operates on the master copy */

	rec.key = kbuf;
	rec.value = dbuf;
	rec.store = db_tdb2_store;
	rec.delete_rec = db_tdb2_delete;
	rec.private_data = ctx->db_ctx;

	return ctx->f(&rec, ctx->private_data);
}

static int db_tdb2_traverse(struct db_context *db,
			   int (*f)(struct db_record *rec, void *private_data),
			   void *private_data)
{
	struct db_tdb2_ctx *db_ctx =
		talloc_get_type_abort(db->private_data, struct db_tdb2_ctx);
	struct db_tdb2_traverse_ctx ctx;

	/*
	 * we only support modifications within a
	 * started transaction.
	 */
	if (db_ctx->transaction == 0) {
		DEBUG(0, ("db_tdb2_traverse[%s]: no transaction started\n",
			  db_ctx->name));
		smb_panic("no transaction");
		return -1;
	}

	/* here we traverse the master copy */
	ctx.db_ctx = db_ctx;
	ctx.f = f;
	ctx.private_data = private_data;
	return tdb_traverse(db_ctx->mtdb->tdb, db_tdb2_traverse_func, &ctx);
}

static NTSTATUS db_tdb2_store_deny(struct db_record *rec, TDB_DATA data, int flag)
{
	return NT_STATUS_MEDIA_WRITE_PROTECTED;
}

static NTSTATUS db_tdb2_delete_deny(struct db_record *rec)
{
	return NT_STATUS_MEDIA_WRITE_PROTECTED;
}

static int db_tdb2_traverse_read_func(TDB_CONTEXT *tdb, TDB_DATA kbuf, TDB_DATA dbuf,
				void *private_data)
{
	struct db_tdb2_traverse_ctx *ctx =
		(struct db_tdb2_traverse_ctx *)private_data;
	struct db_record rec;

	/*
	 * this function operates on the local copy,
	 * so hide the DB_TDB2_MASTER_SEQNUM_KEYSTR from the caller.
	 */
	if ((ctx->db_ctx->mseqkey.dsize == kbuf.dsize) &&
	    (memcmp(ctx->db_ctx->mseqkey.dptr, kbuf.dptr, kbuf.dsize) == 0)) {
		return 0;
	}

	rec.key = kbuf;
	rec.value = dbuf;
	rec.store = db_tdb2_store_deny;
	rec.delete_rec = db_tdb2_delete_deny;
	rec.private_data = ctx->db_ctx;

	return ctx->f(&rec, ctx->private_data);
}

static int db_tdb2_traverse_read(struct db_context *db,
			   int (*f)(struct db_record *rec, void *private_data),
			   void *private_data)
{
	struct db_tdb2_ctx *db_ctx =
		talloc_get_type_abort(db->private_data, struct db_tdb2_ctx);
	struct db_tdb2_traverse_ctx ctx;
	int ret;

	db_tdb2_resync_before_read(db_ctx, NULL);

	if (db_ctx->out_of_sync) {
		DEBUG(0,("out of sync[%s] failing traverse_read\n",
			 db_ctx->ltdb_path));
		errno = EIO;
		return -1;
	}

	/* here we traverse the local copy */
	ctx.db_ctx = db_ctx;
	ctx.f = f;
	ctx.private_data = private_data;
	ret = tdb_traverse_read(db_ctx->ltdb->tdb, db_tdb2_traverse_read_func, &ctx);
	if (ret > 0) {
		/* we have filtered one entry */
		ret--;
	}

	return ret;
}

static int db_tdb2_get_seqnum(struct db_context *db)

{
	struct db_tdb2_ctx *db_ctx =
		talloc_get_type_abort(db->private_data, struct db_tdb2_ctx);
	uint32_t nlseq;
	uint32_t nmseq;
	bool ok;

	nlseq = tdb_get_seqnum(db_ctx->ltdb->tdb);

	if (nlseq == db_ctx->lseqnum) {
		return db_ctx->mseqnum;
	}

	ok = tdb_fetch_uint32_byblob(db_ctx->ltdb->tdb,
				     db_ctx->mseqkey,
				     &nmseq);
	if (!ok) {
		/* TODO: what should we do here? */
		return db_ctx->mseqnum;
	}

	db_ctx->lseqnum = nlseq;
	db_ctx->mseqnum = nmseq;

	return db_ctx->mseqnum;
}

static int db_tdb2_transaction_start(struct db_context *db)
{
	struct db_tdb2_ctx *db_ctx =
		talloc_get_type_abort(db->private_data, struct db_tdb2_ctx);
	int ret;

	if (db_ctx->transaction) {
		db_ctx->transaction++;
		return 0;
	}

	/* we need to open the master tdb in order to */
	ret = db_tdb2_open_master(db_ctx, true, NULL);
	if (ret != 0) {
		return ret;
	}

	ret = tdb_transaction_start(db_ctx->ltdb->tdb);
	if (ret != 0) {
		db_tdb2_close_master(db_ctx);
		return ret;
	}

	db_ctx->local_transaction = true;
	db_ctx->transaction = 1;

	return 0;
}

static void db_tdb2_queue_change(struct db_tdb2_ctx *db_ctx, const TDB_DATA key)
{
	size_t size_needed = 4 + key.dsize;
	size_t size_new = db_ctx->current_buffer_size + size_needed;
	uint32_t i;
	DATA_BLOB *keys;

	db_ctx->changes.num_changes++;

	if (db_ctx->changes.num_changes > 1 &&
	    db_ctx->changes.keys == NULL) {
		/*
		 * this means we already overflowed
		 */
		return;
	}

	if (db_ctx->changes.num_changes == 1) {
		db_ctx->changes.old_seqnum = db_ctx->mseqnum;
	}

	for (i=0; i < db_ctx->changes.num_keys; i++) {
		int ret;

		if (key.dsize != db_ctx->changes.keys[i].length) {
			continue;
		}
		ret = memcmp(key.dptr, db_ctx->changes.keys[i].data, key.dsize);
		if (ret != 0) {
			continue;
		}

		/*
		 * the key is already in the list
		 * so we're done
		 */
		return;
	}

	if (db_ctx->max_buffer_size < size_new) {
		goto overflow;
	}

	keys = TALLOC_REALLOC_ARRAY(db_ctx, db_ctx->changes.keys,
				    DATA_BLOB,
				    db_ctx->changes.num_keys + 1);
	if (!keys) {
		goto overflow;
	}
	db_ctx->changes.keys = keys;

	keys[db_ctx->changes.num_keys].data = (uint8_t *)talloc_memdup(keys,
								key.dptr,
								key.dsize);
	if (!keys[db_ctx->changes.num_keys].data) {
		goto overflow;
	}
	keys[db_ctx->changes.num_keys].length = key.dsize;
	db_ctx->changes.num_keys++;
	db_ctx->current_buffer_size = size_new;

	return;

overflow:
	/*
	 * on overflow discard the buffer and let
	 * the others reload the whole tdb
	 */
	db_ctx->current_buffer_size = 0;
	db_ctx->changes.num_keys = 0;
	TALLOC_FREE(db_ctx->changes.keys);
	return;
}

static void db_tdb2_send_notify(struct db_tdb2_ctx *db_ctx)
{
	enum ndr_err_code ndr_err;
	bool ok;
	DATA_BLOB blob;
	struct messaging_context *msg_ctx;
	int num_msgs = 0;
	struct server_id self = procid_self();

	msg_ctx = db_tdb2_get_global_messaging_context();

	db_ctx->changes.name = db_ctx->name;

	DEBUG(10,("%s[%s] size[%u/%u] changes[%u] keys[%u] seqnum[%u=>%u]\n",
		 __FUNCTION__,
		 db_ctx->changes.name,
		 db_ctx->current_buffer_size,
		 db_ctx->max_buffer_size,
		 db_ctx->changes.num_changes,
		 db_ctx->changes.num_keys,
		 db_ctx->changes.old_seqnum,
		 db_ctx->changes.new_seqnum));

	if (db_ctx->changes.num_changes == 0) {
		DEBUG(10,("db_tdb2_send_notify[%s]: no changes\n",
			db_ctx->changes.name));
		goto done;
	}

	if (!msg_ctx) {
		DEBUG(1,("db_tdb2_send_notify[%s]: skipped (no msg ctx)\n",
			db_ctx->changes.name));
		goto done;
	}

	ndr_err = ndr_push_struct_blob(
		&blob, talloc_tos(), &db_ctx->changes,
		(ndr_push_flags_fn_t)ndr_push_dbwrap_tdb2_changes);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0,("db_tdb2_send_notify[%s]: failed to push changes: %s\n",
			db_ctx->changes.name,
			nt_errstr(ndr_map_error2ntstatus(ndr_err))));
		goto done;
	}

	ok = message_send_all(msg_ctx, MSG_DBWRAP_TDB2_CHANGES,
			      blob.data, blob.length, &num_msgs);
	if (!ok) {
		DEBUG(0,("db_tdb2_send_notify[%s]: failed to send changes\n",
			db_ctx->changes.name));
		goto done;
	}

	DEBUG(10,("db_tdb2_send_notify[%s]: pid %s send %u messages\n",
		db_ctx->name, procid_str_static(&self), num_msgs));

done:
	TALLOC_FREE(db_ctx->changes.keys);
	ZERO_STRUCT(db_ctx->changes);

	return;
}

static void db_tdb2_receive_changes(struct messaging_context *msg,
				    void *private_data,
				    uint32_t msg_type,
				    struct server_id server_id,
				    DATA_BLOB *data)
{
	enum ndr_err_code ndr_err;
	struct dbwrap_tdb2_changes changes;
	struct db_context *db;
	struct server_id self;

	if (procid_is_me(&server_id)) {
		DEBUG(0,("db_tdb2_receive_changes: ignore selfpacket\n"));
		return;
	}

	self = procid_self();

	DEBUG(10,("db_tdb2_receive_changes: from %s to %s\n",
		procid_str(debug_ctx(), &server_id),
		procid_str(debug_ctx(), &self)));

	ndr_err = ndr_pull_struct_blob_all(
		data, talloc_tos(), &changes,
		(ndr_pull_flags_fn_t)ndr_pull_dbwrap_tdb2_changes);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0,("db_tdb2_receive_changes: failed to pull changes: %s\n",
			nt_errstr(ndr_map_error2ntstatus(ndr_err))));
		goto done;
	}

	if(DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(dbwrap_tdb2_changes, &changes);
	}

	/* open the db, this will sync it */
	db = db_open_tdb2_ex(talloc_tos(), changes.name, 0,
			     0, O_RDWR, 0600, &changes);
	TALLOC_FREE(db);
done:
	return;
}

static int db_tdb2_transaction_commit(struct db_context *db)
{
	struct db_tdb2_ctx *db_ctx =
		talloc_get_type_abort(db->private_data, struct db_tdb2_ctx);
	int ret;
	uint32_t mseqnum;

	if (db_ctx->transaction == 0) {
		return -1;
	} else if (db_ctx->transaction > 1) {
		db_ctx->transaction--;
		return 0;
	}

	mseqnum = tdb_get_seqnum(db_ctx->mtdb->tdb);
	db_ctx->changes.new_seqnum = mseqnum;

	/* first commit to the master copy */
	ret = tdb_transaction_commit(db_ctx->mtdb->tdb);
	db_ctx->master_transaction = false;
	if (ret != 0) {
		int saved_errno = errno;
		db_tdb2_transaction_cancel(db);
		errno = saved_errno;
		return ret;
	}

	/*
	 * Note: as we've already commited the changes to the master copy
	 * 	 so we ignore errors in the following functions
	 */
	ret = db_tdb2_commit_local(db_ctx, mseqnum);
	if (ret == 0) {
		db_ctx->out_of_sync = false;
	} else {
		db_ctx->out_of_sync = true;
	}

	db_ctx->transaction = 0;

	db_tdb2_close_master(db_ctx);

	db_tdb2_send_notify(db_ctx);

	return 0;
}

static int db_tdb2_transaction_cancel(struct db_context *db)
{
	struct db_tdb2_ctx *db_ctx =
		talloc_get_type_abort(db->private_data, struct db_tdb2_ctx);
	int saved_errno;
	int ret;

	if (db_ctx->transaction == 0) {
		return -1;
	}
	if (db_ctx->transaction > 1) {
		db_ctx->transaction--;
		return 0;
	}

	/* cancel the transaction and close the master copy */
	ret = db_tdb2_close_master(db_ctx);
	saved_errno = errno;

	/* now cancel on the local copy and ignore any error */
	tdb_transaction_cancel(db_ctx->ltdb->tdb);
	db_ctx->local_transaction = false;

	db_ctx->transaction = 0;

	errno = saved_errno;
	return ret;
}

static int db_tdb2_open_master(struct db_tdb2_ctx *db_ctx, bool transaction,
			       const struct dbwrap_tdb2_changes *changes)
{
	int ret;

	db_ctx->mtdb = tdb_wrap_open(db_ctx,
				     db_ctx->mtdb_path,
				     db_ctx->open.hash_size,
				     db_ctx->open.tdb_flags|TDB_NOMMAP|TDB_SEQNUM,
				     db_ctx->open.open_flags,
				     db_ctx->open.mode);
	if (db_ctx->mtdb == NULL) {
		DEBUG(0, ("Could not open master tdb[%s]: %s\n",
			  db_ctx->mtdb_path,
			  strerror(errno)));
		return -1;
	}
	DEBUG(10,("open_master[%s]\n", db_ctx->mtdb_path));

	if (!db_ctx->ltdb) {
		struct stat st;

		if (fstat(tdb_fd(db_ctx->mtdb->tdb), &st) == 0) {
			db_ctx->open.mode = st.st_mode;
		}

		/* make sure the local one uses the same hash size as the master one */
		db_ctx->open.hash_size = tdb_hash_size(db_ctx->mtdb->tdb);

		db_ctx->ltdb = tdb_wrap_open(db_ctx,
					     db_ctx->ltdb_path,
					     db_ctx->open.hash_size,
					     db_ctx->open.tdb_flags|TDB_SEQNUM,
					     db_ctx->open.open_flags|O_CREAT,
					     db_ctx->open.mode);
		if (db_ctx->ltdb == NULL) {
			DEBUG(0, ("Could not open local tdb[%s]: %s\n",
				  db_ctx->ltdb_path,
				  strerror(errno)));
			TALLOC_FREE(db_ctx->mtdb);
			return -1;
		}
		DEBUG(10,("open_local[%s]\n", db_ctx->ltdb_path));
	}

	if (transaction) {
		ret = tdb_transaction_start(db_ctx->mtdb->tdb);
		if (ret != 0) {
			DEBUG(0,("open failed to start transaction[%s]\n",
				 db_ctx->mtdb_path));
			db_tdb2_close_master(db_ctx);
			return ret;
		}
		db_ctx->master_transaction = true;
	}

	ret = db_tdb2_sync_from_master(db_ctx, changes);
	if (ret != 0) {
		DEBUG(0,("open failed to sync from master[%s]\n",
			 db_ctx->ltdb_path));
		db_tdb2_close_master(db_ctx);
		return ret;
	}

	return 0;
}

static int db_tdb2_commit_local(struct db_tdb2_ctx *db_ctx, uint32_t mseqnum)
{
	bool ok;
	int ret;

	/* first fetch the master seqnum */
	db_ctx->mseqnum = mseqnum;

	/* now we try to store the master seqnum in the local tdb */
	ok = tdb_store_uint32_byblob(db_ctx->ltdb->tdb,
				     db_ctx->mseqkey,
				     db_ctx->mseqnum);
	if (!ok) {
		tdb_transaction_cancel(db_ctx->ltdb->tdb);
		db_ctx->local_transaction = false;
		DEBUG(0,("local failed[%s] store mseq[%u]\n",
			 db_ctx->ltdb_path, db_ctx->mseqnum));
		return -1;
	}

	/* now commit all changes to the local tdb */
	ret = tdb_transaction_commit(db_ctx->ltdb->tdb);
	db_ctx->local_transaction = false;
	if (ret != 0) {
		DEBUG(0,("local failed[%s] commit mseq[%u]\n",
			 db_ctx->ltdb_path, db_ctx->mseqnum));
		return ret;
	}

	/*
	 * and update the cached local seqnum this is needed to
	 * let us cache the master seqnum.
	 */
	db_ctx->lseqnum = tdb_get_seqnum(db_ctx->ltdb->tdb);
	DEBUG(10,("local updated[%s] mseq[%u]\n",
		  db_ctx->ltdb_path, db_ctx->mseqnum));

	return 0;
}

static int db_tdb2_close_master(struct db_tdb2_ctx *db_ctx)
{
	if (db_ctx->master_transaction) {
		tdb_transaction_cancel(db_ctx->mtdb->tdb);
	}
	db_ctx->master_transaction = false;
	/* now we can close the master handle */
	TALLOC_FREE(db_ctx->mtdb);

	DEBUG(10,("close_master[%s] ok\n", db_ctx->mtdb_path));
	return 0;
}

static int db_tdb2_traverse_sync_all_func(TDB_CONTEXT *tdb,
					  TDB_DATA kbuf, TDB_DATA dbuf,
					  void *private_data)
{
	struct db_tdb2_traverse_ctx *ctx =
		(struct db_tdb2_traverse_ctx *)private_data;
	uint32_t *seqnum = (uint32_t *)ctx->private_data;
	int ret;

	DEBUG(10,("sync_entry[%s]\n", ctx->db_ctx->mtdb_path));

	/* Do not accidently allocate/deallocate w/o need when debug level is lower than needed */
	if(DEBUGLEVEL >= 10) {
		char *keystr = hex_encode(NULL, (unsigned char*)kbuf.dptr, kbuf.dsize);
		DEBUG(10, (DEBUGLEVEL > 10
			   ? "Locking key %s\n" : "Locking key %.20s\n",
			   keystr));
		TALLOC_FREE(keystr);
	}

	ret = tdb_store(ctx->db_ctx->ltdb->tdb, kbuf, dbuf, TDB_INSERT);
	if (ret != 0) {
		DEBUG(0,("sync_entry[%s] %d: %s\n",
			ctx->db_ctx->ltdb_path, ret,
			tdb_errorstr(ctx->db_ctx->ltdb->tdb)));
		return ret;
	}

	*seqnum = tdb_get_seqnum(ctx->db_ctx->mtdb->tdb);

	return 0;
}

static int db_tdb2_sync_all(struct db_tdb2_ctx *db_ctx, uint32_t *seqnum)
{
	struct db_tdb2_traverse_ctx ctx;
	int ret;

	ret = tdb_wipe_all(db_ctx->ltdb->tdb);
	if (ret != 0) {
		DEBUG(0,("tdb_wipe_all[%s] failed %d: %s\n",
			 db_ctx->ltdb_path, ret,
			 tdb_errorstr(db_ctx->ltdb->tdb)));
		return ret;
	}

	ctx.db_ctx = db_ctx;
	ctx.f = NULL;
	ctx.private_data = seqnum;
	ret = tdb_traverse_read(db_ctx->mtdb->tdb,
				db_tdb2_traverse_sync_all_func,
				&ctx);
	DEBUG(10,("db_tdb2_sync_all[%s] count[%d]\n",
		  db_ctx->mtdb_path, ret));
	if (ret < 0) {
		return ret;
	}

	return 0;
}

static int db_tdb2_sync_changes(struct db_tdb2_ctx *db_ctx,
				const struct dbwrap_tdb2_changes *changes,
				uint32_t *seqnum)
{
	uint32_t cseqnum;
	uint32_t mseqnum;
	uint32_t i;
	int ret;
	bool need_full_sync = false;

	DEBUG(10,("db_tdb2_sync_changes[%s] changes[%u]\n",
		  changes->name, changes->num_changes));
	if(DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(dbwrap_tdb2_changes, discard_const(changes));
	}

	/* for the master tdb for reading */
	ret = tdb_lockall_read(db_ctx->mtdb->tdb);
	if (ret != 0) {
		DEBUG(0,("tdb_lockall_read[%s] %d\n", db_ctx->mtdb_path, ret));
		return ret;
	}

	/* first fetch seqnum we know about */
	cseqnum = db_tdb2_get_seqnum(db_ctx->db);

	/* then fetch the master seqnum */
	mseqnum = tdb_get_seqnum(db_ctx->mtdb->tdb);

	if (cseqnum == mseqnum) {
		DEBUG(10,("db_tdb2_sync_changes[%s] uptodate[%u]\n",
			  db_ctx->mtdb_path, mseqnum));
		/* we hit a race before and now noticed we're uptodate */
		goto done;
	}

	/* now see if the changes describe what we need */
	if (changes->old_seqnum != cseqnum) {
		need_full_sync = true;
	}

	if (changes->new_seqnum != mseqnum) {
		need_full_sync = true;
	}

	/* this was the overflow case */
	if (changes->num_keys == 0) {
		need_full_sync = true;
	}

	if (need_full_sync) {
		tdb_unlockall_read(db_ctx->mtdb->tdb);
		DEBUG(0,("fallback to full sync[%s] seq[%u=>%u] keys[%u]\n",
			db_ctx->ltdb_path, cseqnum, mseqnum,
			changes->num_keys));
		return db_tdb2_sync_all(db_ctx, &mseqnum);
	}

	for (i=0; i < changes->num_keys; i++) {
		const char *op = NULL;
		bool del = false;
		TDB_DATA key;
		TDB_DATA val;

		key.dsize = changes->keys[i].length;
		key.dptr = changes->keys[i].data;

		val = tdb_fetch(db_ctx->mtdb->tdb, key);
		ret = tdb_error(db_ctx->mtdb->tdb);
		if (ret == TDB_ERR_NOEXIST) {
			del = true;
		} else if (ret != 0) {
			DEBUG(0,("sync_changes[%s] failure %d\n",
				 db_ctx->mtdb_path, ret));
			goto failed;
		}

		if (del) {
			op = "delete";
			ret = tdb_delete(db_ctx->ltdb->tdb, key);
			DEBUG(10,("sync_changes[%s] delete key[%u] %d\n",
				  db_ctx->mtdb_path, i, ret));
		} else {
			op = "store";
			ret = tdb_store(db_ctx->ltdb->tdb, key,
					val, TDB_REPLACE);
			DEBUG(10,("sync_changes[%s] store key[%u] %d\n",
				  db_ctx->mtdb_path, i, ret));
		}
		SAFE_FREE(val.dptr);
		if (ret != 0) {
			DEBUG(0,("sync_changes[%s] %s key[%u] failed %d\n",
				 db_ctx->mtdb_path, op, i, ret));
			goto failed;
		}
	}

done:
	tdb_unlockall_read(db_ctx->mtdb->tdb);

	*seqnum = mseqnum;
	return 0;
failed:
	tdb_unlockall_read(db_ctx->mtdb->tdb);
	return ret;
}

static int db_tdb2_sync_from_master(struct db_tdb2_ctx *db_ctx,
				    const struct dbwrap_tdb2_changes *changes)
{
	int ret;
	uint32_t cseqnum;
	uint32_t mseqnum;
	bool force = false;

	/* first fetch seqnum we know about */
	cseqnum = db_tdb2_get_seqnum(db_ctx->db);

	/* then fetch the master seqnum */
	mseqnum = tdb_get_seqnum(db_ctx->mtdb->tdb);

	if (db_ctx->lseqnum == 0) {
		force = true;
	}

	if (!force && cseqnum == mseqnum) {
		DEBUG(10,("uptodate[%s] mseq[%u]\n",
			  db_ctx->ltdb_path, mseqnum));
		/* the local copy is uptodate, close the master db */
		return 0;
	}
	DEBUG(10,("not uptodate[%s] seq[%u=>%u]\n",
		  db_ctx->ltdb_path, cseqnum, mseqnum));

	ret = tdb_transaction_start(db_ctx->ltdb->tdb);
	if (ret != 0) {
		DEBUG(0,("failed to start transaction[%s] %d: %s\n",
			 db_ctx->ltdb_path, ret,
			 tdb_errorstr(db_ctx->ltdb->tdb)));
		db_ctx->out_of_sync = true;
		return ret;
	}
	db_ctx->local_transaction = true;

	if (changes && !force) {
		ret = db_tdb2_sync_changes(db_ctx, changes, &mseqnum);
		if (ret != 0) {
			db_ctx->out_of_sync = true;
			tdb_transaction_cancel(db_ctx->ltdb->tdb);
			db_ctx->local_transaction = false;
			return ret;
		}
	} else {
		ret = db_tdb2_sync_all(db_ctx, &mseqnum);
		if (ret != 0) {
			db_ctx->out_of_sync = true;
			tdb_transaction_cancel(db_ctx->ltdb->tdb);
			db_ctx->local_transaction = false;
			return ret;
		}
	}

	ret = db_tdb2_commit_local(db_ctx, mseqnum);
	if (ret != 0) {
		db_ctx->out_of_sync = true;
		return ret;
	}

	db_ctx->out_of_sync = false;

	return 0;
}

static int db_tdb2_ctx_destructor(struct db_tdb2_ctx *db_tdb2)
{
	db_tdb2_close_master(db_tdb2);
	if (db_tdb2->local_transaction) {
		tdb_transaction_cancel(db_tdb2->ltdb->tdb);
	}
	db_tdb2->local_transaction = false;
	TALLOC_FREE(db_tdb2->ltdb);
	return 0;
}

static struct db_context *db_open_tdb2_ex(TALLOC_CTX *mem_ctx,
					  const char *name,
					  int hash_size, int tdb_flags,
					  int open_flags, mode_t mode,
					  const struct dbwrap_tdb2_changes *chgs)
{
	struct db_context *result = NULL;
	struct db_tdb2_ctx *db_tdb2;
	int ret;
	const char *md;
	const char *ld;
	const char *bn;

	bn = strrchr_m(name, '/');
	if (bn) {
		bn++;
		DEBUG(3,("db_open_tdb2: use basename[%s] of abspath[%s]:\n",
			bn, name));
	} else {
		bn = name;
	}

	md = lp_parm_const_string(-1, "dbwrap_tdb2", "master directory", NULL);
	if (!md) {
		DEBUG(0,("'dbwrap_tdb2:master directory' empty\n"));
		goto fail;
	}

	ld = lp_parm_const_string(-1, "dbwrap_tdb2", "local directory", NULL);
	if (!ld) {
		DEBUG(0,("'dbwrap_tdb2:local directory' empty\n"));
		goto fail;
	}

	result = TALLOC_ZERO_P(mem_ctx, struct db_context);
	if (result == NULL) {
		DEBUG(0, ("talloc failed\n"));
		goto fail;
	}

	result->private_data = db_tdb2 = TALLOC_ZERO_P(result, struct db_tdb2_ctx);
	if (db_tdb2 == NULL) {
		DEBUG(0, ("talloc failed\n"));
		goto fail;
	}

	db_tdb2->db = result;

	db_tdb2->open.hash_size	= hash_size;
	db_tdb2->open.tdb_flags	= tdb_flags;
	db_tdb2->open.open_flags= open_flags;
	db_tdb2->open.mode	= mode;

	db_tdb2->max_buffer_size = lp_parm_ulong(-1, "dbwrap_tdb2",
						 "notify buffer size", 512);

	db_tdb2->name = talloc_strdup(db_tdb2, bn);
	if (db_tdb2->name == NULL) {
		DEBUG(0, ("talloc_strdup failed\n"));
		goto fail;
	}

	db_tdb2->mtdb_path = talloc_asprintf(db_tdb2, "%s/%s",
					     md, bn);
	if (db_tdb2->mtdb_path == NULL) {
		DEBUG(0, ("talloc_asprintf failed\n"));
		goto fail;
	}

	db_tdb2->ltdb_path = talloc_asprintf(db_tdb2, "%s/%s.tdb2",
					     ld, bn);
	if (db_tdb2->ltdb_path == NULL) {
		DEBUG(0, ("talloc_asprintf failed\n"));
		goto fail;
	}

	db_tdb2->mseqkey = string_term_tdb_data(DB_TDB2_MASTER_SEQNUM_KEYSTR);

	/*
	 * this implicit opens the local one if as it's not yet open
	 * it syncs the local copy.
	 */
	ret = db_tdb2_open_master(db_tdb2, false, chgs);
	if (ret != 0) {
		goto fail;
	}

	ret = db_tdb2_close_master(db_tdb2);
	if (ret != 0) {
		goto fail;
	}

	DEBUG(10,("db_open_tdb2[%s] opened with mseq[%u]\n",
		  db_tdb2->name, db_tdb2->mseqnum));

	result->fetch_locked = db_tdb2_fetch_locked;
	result->fetch = db_tdb2_fetch;
	result->traverse = db_tdb2_traverse;
	result->traverse_read = db_tdb2_traverse_read;
	result->get_seqnum = db_tdb2_get_seqnum;
	result->persistent = ((tdb_flags & TDB_CLEAR_IF_FIRST) == 0);
	result->transaction_start = db_tdb2_transaction_start;
	result->transaction_commit = db_tdb2_transaction_commit;
	result->transaction_cancel = db_tdb2_transaction_cancel;

	talloc_set_destructor(db_tdb2, db_tdb2_ctx_destructor);

	return result;

 fail:
	if (result != NULL) {
		TALLOC_FREE(result);
	}
	return NULL;
}

struct db_context *db_open_tdb2(TALLOC_CTX *mem_ctx,
				const char *name,
				int hash_size, int tdb_flags,
				int open_flags, mode_t mode)
{
	return db_open_tdb2_ex(mem_ctx, name, hash_size,
			       tdb_flags, open_flags, mode, NULL);
}
