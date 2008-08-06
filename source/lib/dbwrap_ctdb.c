/* 
   Unix SMB/CIFS implementation.
   Database interface wrapper around ctdbd
   Copyright (C) Volker Lendecke 2007
   
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
#ifdef CLUSTER_SUPPORT
#include "ctdb.h"
#include "ctdb_private.h"
#include "ctdbd_conn.h"

struct db_ctdb_ctx {
	struct tdb_wrap *wtdb;
	uint32 db_id;
};

struct db_ctdb_rec {
	struct db_ctdb_ctx *ctdb_ctx;
	struct ctdb_ltdb_header header;
};

static NTSTATUS db_ctdb_store(struct db_record *rec, TDB_DATA data, int flag)
{
	struct db_ctdb_rec *crec = talloc_get_type_abort(
		rec->private_data, struct db_ctdb_rec);
	TDB_DATA cdata;
	int ret;

	cdata.dsize = sizeof(crec->header) + data.dsize;

	if (!(cdata.dptr = SMB_MALLOC_ARRAY(uint8, cdata.dsize))) {
		return NT_STATUS_NO_MEMORY;
	}

	memcpy(cdata.dptr, &crec->header, sizeof(crec->header));
	memcpy(cdata.dptr + sizeof(crec->header), data.dptr, data.dsize);

	ret = tdb_store(crec->ctdb_ctx->wtdb->tdb, rec->key, cdata, TDB_REPLACE);

	SAFE_FREE(cdata.dptr);

	return (ret == 0) ? NT_STATUS_OK : NT_STATUS_INTERNAL_DB_CORRUPTION;
}


/* for persistent databases the store is a bit different. We have to
   ask the ctdb daemon to push the record to all nodes after the
   store */
static NTSTATUS db_ctdb_store_persistent(struct db_record *rec, TDB_DATA data, int flag)
{
	struct db_ctdb_rec *crec = talloc_get_type_abort(
		rec->private_data, struct db_ctdb_rec);
	TDB_DATA cdata;
	int ret;
	NTSTATUS status;

	cdata.dsize = sizeof(crec->header) + data.dsize;

	if (!(cdata.dptr = SMB_MALLOC_ARRAY(uint8, cdata.dsize))) {
		return NT_STATUS_NO_MEMORY;
	}

	crec->header.rsn++;

	memcpy(cdata.dptr, &crec->header, sizeof(crec->header));
	memcpy(cdata.dptr + sizeof(crec->header), data.dptr, data.dsize);

	ret = tdb_store(crec->ctdb_ctx->wtdb->tdb, rec->key, cdata, TDB_REPLACE);
	status = (ret == 0) ? NT_STATUS_OK : NT_STATUS_INTERNAL_DB_CORRUPTION;
	
	/* now tell ctdbd to update this record on all other nodes */
	if (NT_STATUS_IS_OK(status)) {
		status = ctdbd_persistent_store(messaging_ctdbd_connection(), crec->ctdb_ctx->db_id, rec->key, cdata);
	}

	SAFE_FREE(cdata.dptr);

	return status;
}

static NTSTATUS db_ctdb_delete(struct db_record *rec)
{
	struct db_ctdb_rec *crec = talloc_get_type_abort(
		rec->private_data, struct db_ctdb_rec);
	TDB_DATA data;
	int ret;

	/*
	 * We have to store the header with empty data. TODO: Fix the
	 * tdb-level cleanup
	 */

	data.dptr = (uint8 *)&crec->header;
	data.dsize = sizeof(crec->header);

	ret = tdb_store(crec->ctdb_ctx->wtdb->tdb, rec->key, data, TDB_REPLACE);

	return (ret == 0) ? NT_STATUS_OK : NT_STATUS_INTERNAL_DB_CORRUPTION;
}

static int db_ctdb_record_destr(struct db_record* data)
{
	struct db_ctdb_rec *crec = talloc_get_type_abort(
		data->private_data, struct db_ctdb_rec);

	DEBUG(10, (DEBUGLEVEL > 10
		   ? "Unlocking db %u key %s\n"
		   : "Unlocking db %u key %.20s\n",
		   (int)crec->ctdb_ctx->db_id,
		   hex_encode(data, (unsigned char *)data->key.dptr,
			      data->key.dsize)));

	if (tdb_chainunlock(crec->ctdb_ctx->wtdb->tdb, data->key) != 0) {
		DEBUG(0, ("tdb_chainunlock failed\n"));
		return -1;
	}

	return 0;
}

static struct db_record *db_ctdb_fetch_locked(struct db_context *db,
					      TALLOC_CTX *mem_ctx,
					      TDB_DATA key)
{
	struct db_ctdb_ctx *ctx = talloc_get_type_abort(db->private_data,
							struct db_ctdb_ctx);
	struct db_record *result;
	struct db_ctdb_rec *crec;
	NTSTATUS status;
	TDB_DATA ctdb_data;
	int migrate_attempts = 0;

	if (!(result = talloc(mem_ctx, struct db_record))) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	if (!(crec = TALLOC_ZERO_P(result, struct db_ctdb_rec))) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(result);
		return NULL;
	}

	result->private_data = (void *)crec;
	crec->ctdb_ctx = ctx;

	result->key.dsize = key.dsize;
	result->key.dptr = (uint8 *)talloc_memdup(result, key.dptr, key.dsize);
	if (result->key.dptr == NULL) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(result);
		return NULL;
	}

	/*
	 * Do a blocking lock on the record
	 */
again:

	if (DEBUGLEVEL >= 10) {
		char *keystr = hex_encode(result, key.dptr, key.dsize);
		DEBUG(10, (DEBUGLEVEL > 10
			   ? "Locking db %u key %s\n"
			   : "Locking db %u key %.20s\n",
			   (int)crec->ctdb_ctx->db_id, keystr));
		TALLOC_FREE(keystr);
	}
	
	if (tdb_chainlock(ctx->wtdb->tdb, key) != 0) {
		DEBUG(3, ("tdb_chainlock failed\n"));
		TALLOC_FREE(result);
		return NULL;
	}

	if (db->persistent) {
		result->store = db_ctdb_store_persistent;
	} else {
		result->store = db_ctdb_store;
	}
	result->delete_rec = db_ctdb_delete;
	talloc_set_destructor(result, db_ctdb_record_destr);

	ctdb_data = tdb_fetch(ctx->wtdb->tdb, key);

	/*
	 * See if we have a valid record and we are the dmaster. If so, we can
	 * take the shortcut and just return it.
	 */

	if ((ctdb_data.dptr == NULL) ||
	    (ctdb_data.dsize < sizeof(struct ctdb_ltdb_header)) ||
	    ((struct ctdb_ltdb_header *)ctdb_data.dptr)->dmaster != get_my_vnn()
#if 0
	    || (random() % 2 != 0)
#endif
) {
		SAFE_FREE(ctdb_data.dptr);
		tdb_chainunlock(ctx->wtdb->tdb, key);
		talloc_set_destructor(result, NULL);

		migrate_attempts += 1;

		DEBUG(10, ("ctdb_data.dptr = %p, dmaster = %u (%u)\n",
			   ctdb_data.dptr, ctdb_data.dptr ?
			   ((struct ctdb_ltdb_header *)ctdb_data.dptr)->dmaster : -1,
			   get_my_vnn()));

		status = ctdbd_migrate(messaging_ctdbd_connection(),ctx->db_id, key);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(5, ("ctdb_migrate failed: %s\n",
				  nt_errstr(status)));
			TALLOC_FREE(result);
			return NULL;
		}
		/* now its migrated, try again */
		goto again;
	}

	if (migrate_attempts > 10) {
		DEBUG(0, ("db_ctdb_fetch_locked needed %d attempts\n",
			  migrate_attempts));
	}

	memcpy(&crec->header, ctdb_data.dptr, sizeof(crec->header));

	result->value.dsize = ctdb_data.dsize - sizeof(crec->header);
	result->value.dptr = NULL;

	if ((result->value.dsize != 0)
	    && !(result->value.dptr = (uint8 *)talloc_memdup(
			 result, ctdb_data.dptr + sizeof(crec->header),
			 result->value.dsize))) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(result);
	}

	SAFE_FREE(ctdb_data.dptr);

	return result;
}

/*
  fetch (unlocked, no migration) operation on ctdb
 */
static int db_ctdb_fetch(struct db_context *db, TALLOC_CTX *mem_ctx,
			 TDB_DATA key, TDB_DATA *data)
{
	struct db_ctdb_ctx *ctx = talloc_get_type_abort(db->private_data,
							struct db_ctdb_ctx);
	NTSTATUS status;
	TDB_DATA ctdb_data;

	/* try a direct fetch */
	ctdb_data = tdb_fetch(ctx->wtdb->tdb, key);

	/*
	 * See if we have a valid record and we are the dmaster. If so, we can
	 * take the shortcut and just return it.
	 * we bypass the dmaster check for persistent databases
	 */
	if ((ctdb_data.dptr != NULL) &&
	    (ctdb_data.dsize >= sizeof(struct ctdb_ltdb_header)) &&
	    (db->persistent ||
	     ((struct ctdb_ltdb_header *)ctdb_data.dptr)->dmaster == get_my_vnn())) {
		/* we are the dmaster - avoid the ctdb protocol op */

		data->dsize = ctdb_data.dsize - sizeof(struct ctdb_ltdb_header);
		if (data->dsize == 0) {
			SAFE_FREE(ctdb_data.dptr);
			data->dptr = NULL;
			return 0;
		}

		data->dptr = (uint8 *)talloc_memdup(
			mem_ctx, ctdb_data.dptr+sizeof(struct ctdb_ltdb_header),
			data->dsize);

		SAFE_FREE(ctdb_data.dptr);

		if (data->dptr == NULL) {
			return -1;
		}
		return 0;
	}

	SAFE_FREE(ctdb_data.dptr);

	/* we weren't able to get it locally - ask ctdb to fetch it for us */
	status = ctdbd_fetch(messaging_ctdbd_connection(),ctx->db_id, key, mem_ctx, data);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5, ("ctdbd_fetch failed: %s\n", nt_errstr(status)));
		return -1;
	}

	return 0;
}

struct traverse_state {
	struct db_context *db;
	int (*fn)(struct db_record *rec, void *private_data);
	void *private_data;
};

static void traverse_callback(TDB_DATA key, TDB_DATA data, void *private_data)
{
	struct traverse_state *state = (struct traverse_state *)private_data;
	struct db_record *rec;
	TALLOC_CTX *tmp_ctx = talloc_new(state->db);
	/* we have to give them a locked record to prevent races */
	rec = db_ctdb_fetch_locked(state->db, tmp_ctx, key);
	if (rec && rec->value.dsize > 0) {
		state->fn(rec, state->private_data);
	}
	talloc_free(tmp_ctx);
}

static int traverse_persistent_callback(TDB_CONTEXT *tdb, TDB_DATA kbuf, TDB_DATA dbuf,
					void *private_data)
{
	struct traverse_state *state = (struct traverse_state *)private_data;
	struct db_record *rec;
	TALLOC_CTX *tmp_ctx = talloc_new(state->db);
	int ret = 0;
	/* we have to give them a locked record to prevent races */
	rec = db_ctdb_fetch_locked(state->db, tmp_ctx, kbuf);
	if (rec && rec->value.dsize > 0) {
		ret = state->fn(rec, state->private_data);
	}
	talloc_free(tmp_ctx);
	return ret;
}

static int db_ctdb_traverse(struct db_context *db,
			    int (*fn)(struct db_record *rec,
				      void *private_data),
			    void *private_data)
{
        struct db_ctdb_ctx *ctx = talloc_get_type_abort(db->private_data,
                                                        struct db_ctdb_ctx);
	struct traverse_state state;

	state.db = db;
	state.fn = fn;
	state.private_data = private_data;

	if (db->persistent) {
		/* for persistent databases we don't need to do a ctdb traverse,
		   we can do a faster local traverse */
		return tdb_traverse(ctx->wtdb->tdb, traverse_persistent_callback, &state);
	}


	ctdbd_traverse(ctx->db_id, traverse_callback, &state);
	return 0;
}

static NTSTATUS db_ctdb_store_deny(struct db_record *rec, TDB_DATA data, int flag)
{
	return NT_STATUS_MEDIA_WRITE_PROTECTED;
}

static NTSTATUS db_ctdb_delete_deny(struct db_record *rec)
{
	return NT_STATUS_MEDIA_WRITE_PROTECTED;
}

static void traverse_read_callback(TDB_DATA key, TDB_DATA data, void *private_data)
{
	struct traverse_state *state = (struct traverse_state *)private_data;
	struct db_record rec;
	rec.key = key;
	rec.value = data;
	rec.store = db_ctdb_store_deny;
	rec.delete_rec = db_ctdb_delete_deny;
	rec.private_data = state->db;
	state->fn(&rec, state->private_data);
}

static int traverse_persistent_callback_read(TDB_CONTEXT *tdb, TDB_DATA kbuf, TDB_DATA dbuf,
					void *private_data)
{
	struct traverse_state *state = (struct traverse_state *)private_data;
	struct db_record rec;
	rec.key = kbuf;
	rec.value = dbuf;
	rec.store = db_ctdb_store_deny;
	rec.delete_rec = db_ctdb_delete_deny;
	rec.private_data = state->db;

	if (rec.value.dsize <= sizeof(struct ctdb_ltdb_header)) {
		/* a deleted record */
		return 0;
	}
	rec.value.dsize -= sizeof(struct ctdb_ltdb_header);
	rec.value.dptr += sizeof(struct ctdb_ltdb_header);

	return state->fn(&rec, state->private_data);
}

static int db_ctdb_traverse_read(struct db_context *db,
				 int (*fn)(struct db_record *rec,
					   void *private_data),
				 void *private_data)
{
        struct db_ctdb_ctx *ctx = talloc_get_type_abort(db->private_data,
                                                        struct db_ctdb_ctx);
	struct traverse_state state;

	state.db = db;
	state.fn = fn;
	state.private_data = private_data;

	if (db->persistent) {
		/* for persistent databases we don't need to do a ctdb traverse,
		   we can do a faster local traverse */
		return tdb_traverse_read(ctx->wtdb->tdb, traverse_persistent_callback_read, &state);
	}

	ctdbd_traverse(ctx->db_id, traverse_read_callback, &state);
	return 0;
}

static int db_ctdb_get_seqnum(struct db_context *db)
{
        struct db_ctdb_ctx *ctx = talloc_get_type_abort(db->private_data,
                                                        struct db_ctdb_ctx);
	return tdb_get_seqnum(ctx->wtdb->tdb);
}

static int db_ctdb_trans_dummy(struct db_context *db)
{
	/*
	 * Not implemented yet, just return ok
	 */
	return 0;
}

struct db_context *db_open_ctdb(TALLOC_CTX *mem_ctx,
				const char *name,
				int hash_size, int tdb_flags,
				int open_flags, mode_t mode)
{
	struct db_context *result;
	struct db_ctdb_ctx *db_ctdb;
	char *db_path;

	if (!lp_clustering()) {
		DEBUG(10, ("Clustering disabled -- no ctdb\n"));
		return NULL;
	}

	if (!(result = TALLOC_ZERO_P(mem_ctx, struct db_context))) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(result);
		return NULL;
	}

	if (!(db_ctdb = TALLOC_P(result, struct db_ctdb_ctx))) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(result);
		return NULL;
	}

	if (!NT_STATUS_IS_OK(ctdbd_db_attach(messaging_ctdbd_connection(),name, &db_ctdb->db_id, tdb_flags))) {
		DEBUG(0, ("ctdbd_db_attach failed for %s\n", name));
		TALLOC_FREE(result);
		return NULL;
	}

	db_path = ctdbd_dbpath(messaging_ctdbd_connection(), db_ctdb, db_ctdb->db_id);

	result->persistent = ((tdb_flags & TDB_CLEAR_IF_FIRST) == 0);

	/* only pass through specific flags */
	tdb_flags &= TDB_SEQNUM;

	/* honor permissions if user has specified O_CREAT */
	if (open_flags & O_CREAT) {
		chmod(db_path, mode);
	}

	db_ctdb->wtdb = tdb_wrap_open(db_ctdb, db_path, hash_size, tdb_flags, O_RDWR, 0);
	if (db_ctdb->wtdb == NULL) {
		DEBUG(0, ("Could not open tdb %s: %s\n", db_path, strerror(errno)));
		TALLOC_FREE(result);
		return NULL;
	}
	talloc_free(db_path);

	result->private_data = (void *)db_ctdb;
	result->fetch_locked = db_ctdb_fetch_locked;
	result->fetch = db_ctdb_fetch;
	result->traverse = db_ctdb_traverse;
	result->traverse_read = db_ctdb_traverse_read;
	result->get_seqnum = db_ctdb_get_seqnum;
	result->transaction_start = db_ctdb_trans_dummy;
	result->transaction_commit = db_ctdb_trans_dummy;
	result->transaction_cancel = db_ctdb_trans_dummy;

	DEBUG(3,("db_open_ctdb: opened database '%s' with dbid 0x%x\n",
		 name, db_ctdb->db_id));

	return result;
}
#endif
