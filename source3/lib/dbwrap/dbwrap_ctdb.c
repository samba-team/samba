/*
   Unix SMB/CIFS implementation.
   Database interface wrapper around ctdbd
   Copyright (C) Volker Lendecke 2007-2009
   Copyright (C) Michael Adam 2009

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
#include "lib/tdb_wrap/tdb_wrap.h"
#include "util_tdb.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_ctdb.h"
#include "dbwrap/dbwrap_rbt.h"
#include "lib/param/param.h"

#include "ctdb/include/ctdb_protocol.h"
#include "ctdb/protocol/protocol.h"
#include "ctdb/protocol/protocol_api.h"
#include "ctdbd_conn.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_private.h"
#include "dbwrap/dbwrap_ctdb.h"
#include "g_lock.h"
#include "messages.h"
#include "messages_ctdb.h"
#include "lib/cluster_support.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/util/server_id.h"
#include "source3/lib/global_contexts.h"
#include "source3/include/serverid.h"

struct db_ctdb_transaction_handle {
	struct db_ctdb_ctx *ctx;
	/*
	 * we store the writes done under a transaction:
	 */
	struct ctdb_marshall_buffer *m_write;
	uint32_t nesting;
	bool nested_cancel;
	char *lock_name;
};

struct db_ctdb_ctx {
	struct db_context *db;
	struct tdb_wrap *wtdb;
	uint32_t db_id;
	struct db_ctdb_transaction_handle *transaction;
	struct g_lock_ctx *lock_ctx;

	/*
	 * Persistent db used with DBWRAP_FLAG_PER_REC_PERSISTENT
	 */
	struct db_context *pdb;

	/* thresholds for warning messages */
	int warn_unlock_msecs;
	int warn_migrate_msecs;
	int warn_migrate_attempts;
	int warn_locktime_msecs;
};

struct db_ctdb_rec {
	struct db_ctdb_ctx *ctdb_ctx;
	struct ctdb_ltdb_header header;
	struct timeval lock_time;
};

struct ctdb_async_ctx {
	bool initialized;
	struct ctdbd_connection *async_conn;
};

static struct ctdb_async_ctx ctdb_async_ctx;

static int ctdb_async_ctx_init_internal(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					bool reinit)
{
	int ret;

	if (reinit) {
		TALLOC_FREE(ctdb_async_ctx.async_conn);
		ctdb_async_ctx.initialized = false;
	}

	if (ctdb_async_ctx.initialized) {
		return 0;
	}

	become_root();
	ret = ctdbd_init_async_connection(
		mem_ctx,
		lp_ctdbd_socket(),
		lp_ctdb_timeout(),
		&ctdb_async_ctx.async_conn);
	unbecome_root();

	if (ret != 0) {
		DBG_ERR("ctdbd_init_async_connection(%s, timeout=%d) "
			"failed: ret=%d %s\n",
			lp_ctdbd_socket(),
			lp_ctdb_timeout(),
			ret, strerror(ret));
		return ret;
	}

	SMB_ASSERT(ctdb_async_ctx.async_conn != NULL);

	ctdb_async_ctx.initialized = true;
	return 0;
}

static int ctdb_async_ctx_init(TALLOC_CTX *mem_ctx, struct tevent_context *ev)
{
	return ctdb_async_ctx_init_internal(mem_ctx, ev, false);
}

int ctdb_async_ctx_reinit(TALLOC_CTX *mem_ctx, struct tevent_context *ev)
{
	return ctdb_async_ctx_init_internal(mem_ctx, ev, true);
}

static NTSTATUS tdb_error_to_ntstatus(struct tdb_context *tdb)
{
	enum TDB_ERROR tret = tdb_error(tdb);

	return map_nt_error_from_tdb(tret);
}

struct db_ctdb_ltdb_parse_state {
	void (*parser)(TDB_DATA key, struct ctdb_ltdb_header *header,
		       TDB_DATA data, void *private_data);
	void *private_data;
};

static int db_ctdb_ltdb_parser(TDB_DATA key, TDB_DATA data,
			       void *private_data)
{
	struct db_ctdb_ltdb_parse_state *state =
		(struct db_ctdb_ltdb_parse_state *)private_data;

	if (data.dsize < sizeof(struct ctdb_ltdb_header)) {
		return -1;
	}

	state->parser(
		key, (struct ctdb_ltdb_header *)data.dptr,
		make_tdb_data(data.dptr + sizeof(struct ctdb_ltdb_header),
			      data.dsize - sizeof(struct ctdb_ltdb_header)),
		state->private_data);
	return 0;
}

static NTSTATUS db_ctdb_ltdb_parse(
	struct db_ctdb_ctx *db, TDB_DATA key,
	void (*parser)(TDB_DATA key, struct ctdb_ltdb_header *header,
		       TDB_DATA data, void *private_data),
	void *private_data)
{
	struct db_ctdb_ltdb_parse_state state;
	int ret;

	state.parser = parser;
	state.private_data = private_data;

	ret = tdb_parse_record(db->wtdb->tdb, key, db_ctdb_ltdb_parser,
			       &state);
	if (ret == -1) {
		return NT_STATUS_NOT_FOUND;
	}
	return NT_STATUS_OK;
}

/*
 * Store a record together with the ctdb record header
 * in the local copy of the database.
 */
static NTSTATUS db_ctdb_ltdb_store(struct db_ctdb_ctx *db,
				   TDB_DATA key,
				   struct ctdb_ltdb_header *header,
				   const TDB_DATA *dbufs, int num_dbufs)
{
	TDB_DATA recs[num_dbufs+1];
	int ret;

	recs[0] = (TDB_DATA) { .dptr = (uint8_t *)header,
			       .dsize = sizeof(struct ctdb_ltdb_header) };
	memcpy(&recs[1], dbufs, sizeof(TDB_DATA) * num_dbufs);

	ret = tdb_storev(db->wtdb->tdb, key, recs, num_dbufs + 1, TDB_REPLACE);

	return (ret == 0) ? NT_STATUS_OK
			  : tdb_error_to_ntstatus(db->wtdb->tdb);

}

static NTSTATUS db_ctdb_push_record(struct db_record *rec,
				    const TDB_DATA *dbufs,
				    int num_dbufs)
{
	struct ctdbd_connection *conn = messaging_ctdb_connection();
	struct db_ctdb_rec *crec = talloc_get_type_abort(
		rec->private_data, struct db_ctdb_rec);
	TDB_DATA data = {};
	TDB_DATA ctrl_data;
	struct ctdb_push_record_data prd = {
		.db_id = crec->ctdb_ctx->db_id,
		.hdr = crec->header,
		.key = rec->key,
	};
	int32_t ctrl_ret;
	NTSTATUS status;
	size_t np = 0;
	int ret;

	ret = ctdbd_generation(conn, &prd.generation);
	if (ret != 0) {
		DBG_ERR("ctdbd_generation() failed: %s\n",
			strerror(ret));
		return NT_STATUS_CLUSTER_NODE_DOWN;
	}

	status = dbwrap_merge_dbufs(&data, rec, dbufs, num_dbufs);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	prd.value = data;

	ctrl_data.dsize = ctdb_push_record_data_len(&prd);
	ctrl_data.dptr = talloc_zero_array(crec, uint8_t, ctrl_data.dsize);
	if (ctrl_data.dptr == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	ctdb_push_record_data_push(&prd, ctrl_data.dptr, &np);

	ret = ctdbd_control_broadcast(messaging_ctdb_connection(),
				      CTDB_CONTROL_PUSH_RECORD,
				      crec->ctdb_ctx->db_id,
				      CTDB_CTRL_FLAG_NOREPLY,
				      ctrl_data,
				      NULL,
				      NULL,
				      &ctrl_ret);
	TALLOC_FREE(ctrl_data.dptr);

	if (ret != 0 || ctrl_ret != 0) {
		DBG_ERR("Error sending PUSH_RECORD control: %s, "
			"ctrl_ret = %" PRIi32 "\n",
			strerror(ret), ctrl_ret);
		if (ret != 0) {
			return map_nt_error_from_unix(ret);
		}
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}

/*
  form a ctdb_rec_data record from a key/data pair
 */
static struct ctdb_rec_data_old *db_ctdb_marshall_record(TALLOC_CTX *mem_ctx, uint32_t reqid,
						  TDB_DATA key,
						  struct ctdb_ltdb_header *header,
						  TDB_DATA data)
{
	size_t length;
	struct ctdb_rec_data_old *d;

	length = offsetof(struct ctdb_rec_data_old, data) + key.dsize +
		data.dsize + sizeof(*header);
	d = (struct ctdb_rec_data_old *)talloc_size(mem_ctx, length);
	if (d == NULL) {
		return NULL;
	}
	d->length = length;
	d->reqid = reqid;
	d->keylen = key.dsize;
	memcpy(&d->data[0], key.dptr, key.dsize);

	d->datalen = data.dsize + sizeof(*header);
	memcpy(&d->data[key.dsize], header, sizeof(*header));
	memcpy(&d->data[key.dsize+sizeof(*header)], data.dptr, data.dsize);
	return d;
}


/* helper function for marshalling multiple records */
static struct ctdb_marshall_buffer *db_ctdb_marshall_add(TALLOC_CTX *mem_ctx,
					       struct ctdb_marshall_buffer *m,
					       uint32_t db_id,
					       uint32_t reqid,
					       TDB_DATA key,
					       struct ctdb_ltdb_header *header,
					       TDB_DATA data)
{
	struct ctdb_rec_data_old *r;
	size_t m_size, r_size;
	struct ctdb_marshall_buffer *m2 = NULL;

	r = db_ctdb_marshall_record(talloc_tos(), reqid, key, header, data);
	if (r == NULL) {
		talloc_free(m);
		return NULL;
	}

	if (m == NULL) {
		m = (struct ctdb_marshall_buffer *)talloc_zero_size(
			mem_ctx, offsetof(struct ctdb_marshall_buffer, data));
		if (m == NULL) {
			goto done;
		}
		m->db_id = db_id;
	}

	m_size = talloc_get_size(m);
	r_size = talloc_get_size(r);

	m2 = (struct ctdb_marshall_buffer *)talloc_realloc_size(
		mem_ctx, m,  m_size + r_size);
	if (m2 == NULL) {
		talloc_free(m);
		goto done;
	}

	memcpy(m_size + (uint8_t *)m2, r, r_size);

	m2->count++;

done:
	talloc_free(r);
	return m2;
}

/* we've finished marshalling, return a data blob with the marshalled records */
static TDB_DATA db_ctdb_marshall_finish(struct ctdb_marshall_buffer *m)
{
	TDB_DATA data;
	data.dptr = (uint8_t *)m;
	data.dsize = talloc_get_size(m);
	return data;
}

/*
   loop over a marshalling buffer

     - pass r==NULL to start
     - loop the number of times indicated by m->count
*/
static struct ctdb_rec_data_old *db_ctdb_marshall_loop_next_key(
	struct ctdb_marshall_buffer *m, struct ctdb_rec_data_old *r, TDB_DATA *key)
{
	if (r == NULL) {
		r = (struct ctdb_rec_data_old *)&m->data[0];
	} else {
		r = (struct ctdb_rec_data_old *)(r->length + (uint8_t *)r);
	}

	key->dptr   = &r->data[0];
	key->dsize  = r->keylen;
	return r;
}

static bool db_ctdb_marshall_buf_parse(
	struct ctdb_rec_data_old *r, uint32_t *reqid,
	struct ctdb_ltdb_header **header, TDB_DATA *data)
{
	if (r->datalen < sizeof(struct ctdb_ltdb_header)) {
		return false;
	}

	*reqid = r->reqid;

	data->dptr  = &r->data[r->keylen] + sizeof(struct ctdb_ltdb_header);
	data->dsize = r->datalen - sizeof(struct ctdb_ltdb_header);

	*header = (struct ctdb_ltdb_header *)&r->data[r->keylen];

	return true;
}

/**
 * CTDB transaction destructor
 */
static int db_ctdb_transaction_destructor(struct db_ctdb_transaction_handle *h)
{
	NTSTATUS status;

	status = g_lock_unlock(h->ctx->lock_ctx,
			       string_term_tdb_data(h->lock_name));
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("g_lock_unlock failed for %s: %s\n", h->lock_name,
			  nt_errstr(status)));
		return -1;
	}
	return 0;
}

/**
 * CTDB dbwrap API: transaction_start function
 * starts a transaction on a persistent database
 */
static int db_ctdb_transaction_start(struct db_context *db)
{
	struct db_ctdb_transaction_handle *h;
	NTSTATUS status;
	struct db_ctdb_ctx *ctx = talloc_get_type_abort(db->private_data,
							struct db_ctdb_ctx);

	if (!db->persistent) {
		DEBUG(0,("transactions not supported on non-persistent database 0x%08x\n", 
			 ctx->db_id));
		return -1;
	}

	if (ctx->transaction) {
		ctx->transaction->nesting++;
		DEBUG(5, (__location__ " transaction start on db 0x%08x: nesting %d -> %d\n",
			  ctx->db_id, ctx->transaction->nesting - 1, ctx->transaction->nesting));
		return 0;
	}

	h = talloc_zero(db, struct db_ctdb_transaction_handle);
	if (h == NULL) {
		DEBUG(0,(__location__ " oom for transaction handle\n"));
		return -1;
	}

	h->ctx = ctx;

	h->lock_name = talloc_asprintf(h, "transaction_db_0x%08x",
				       (unsigned int)ctx->db_id);
	if (h->lock_name == NULL) {
		DEBUG(0, ("talloc_asprintf failed\n"));
		TALLOC_FREE(h);
		return -1;
	}

	/*
	 * Wait a day, i.e. forever...
	 */
	status = g_lock_lock(ctx->lock_ctx,
			     string_term_tdb_data(h->lock_name),
			     G_LOCK_WRITE,
			     tevent_timeval_set(86400, 0),
			     NULL,
			     NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("g_lock_lock failed: %s\n", nt_errstr(status)));
		TALLOC_FREE(h);
		return -1;
	}

	talloc_set_destructor(h, db_ctdb_transaction_destructor);

	ctx->transaction = h;

	DEBUG(5,(__location__ " transaction started on db 0x%08x\n", ctx->db_id));

	return 0;
}

static bool parse_newest_in_marshall_buffer(
	struct ctdb_marshall_buffer *buf, TDB_DATA key,
	void (*parser)(TDB_DATA key, struct ctdb_ltdb_header *header,
		       TDB_DATA data, void *private_data),
	void *private_data)
{
	struct ctdb_rec_data_old *rec = NULL;
	struct ctdb_ltdb_header *h = NULL;
	TDB_DATA data;
	uint32_t i;

	if (buf == NULL) {
		return false;
	}

	/*
	 * Walk the list of records written during this
	 * transaction. If we want to read one we have already
	 * written, return the last written sample. Thus we do not do
	 * a "break;" for the first hit, this record might have been
	 * overwritten later.
	 */

	for (i=0; i<buf->count; i++) {
		TDB_DATA tkey;
		uint32_t reqid;

		rec = db_ctdb_marshall_loop_next_key(buf, rec, &tkey);
		if (rec == NULL) {
			return false;
		}

		if (!tdb_data_equal(key, tkey)) {
			continue;
		}

		if (!db_ctdb_marshall_buf_parse(rec, &reqid, &h, &data)) {
			return false;
		}
	}

	if (h == NULL) {
		return false;
	}

	parser(key, h, data, private_data);

	return true;
}

struct pull_newest_from_marshall_buffer_state {
	struct ctdb_ltdb_header *pheader;
	TALLOC_CTX *mem_ctx;
	TDB_DATA *pdata;
};

static void pull_newest_from_marshall_buffer_parser(
	TDB_DATA key, struct ctdb_ltdb_header *header,
	TDB_DATA data, void *private_data)
{
	struct pull_newest_from_marshall_buffer_state *state =
		(struct pull_newest_from_marshall_buffer_state *)private_data;

	if (state->pheader != NULL) {
		memcpy(state->pheader, header, sizeof(*state->pheader));
	}
	if (state->pdata != NULL) {
		state->pdata->dsize = data.dsize;
		state->pdata->dptr = (uint8_t *)talloc_memdup(
			state->mem_ctx, data.dptr, data.dsize);
	}
}

static bool pull_newest_from_marshall_buffer(struct ctdb_marshall_buffer *buf,
					     TDB_DATA key,
					     struct ctdb_ltdb_header *pheader,
					     TALLOC_CTX *mem_ctx,
					     TDB_DATA *pdata)
{
	struct pull_newest_from_marshall_buffer_state state;

	state.pheader = pheader;
	state.mem_ctx = mem_ctx;
	state.pdata = pdata;

	if (!parse_newest_in_marshall_buffer(
		    buf, key, pull_newest_from_marshall_buffer_parser,
		    &state)) {
		return false;
	}
	if ((pdata != NULL) && (pdata->dsize != 0) && (pdata->dptr == NULL)) {
		/* ENOMEM */
		return false;
	}
	return true;
}

static NTSTATUS db_ctdb_storev_transaction(struct db_record *rec,
					   const TDB_DATA *dbufs, int num_dbufs,
					   int flag);
static NTSTATUS db_ctdb_delete_transaction(struct db_record *rec);

static struct db_record *db_ctdb_fetch_locked_transaction(struct db_ctdb_ctx *ctx,
							  TALLOC_CTX *mem_ctx,
							  TDB_DATA key)
{
	struct db_record *result;
	TDB_DATA ctdb_data;

	if (!(result = talloc(mem_ctx, struct db_record))) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	result->db = ctx->db;
	result->private_data = ctx->transaction;

	result->key.dsize = key.dsize;
	result->key.dptr = (uint8_t *)talloc_memdup(result, key.dptr,
						    key.dsize);
	if (result->key.dptr == NULL) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(result);
		return NULL;
	}

	result->storev = db_ctdb_storev_transaction;
	result->delete_rec = db_ctdb_delete_transaction;

	if (ctx->transaction == NULL) {
		DEBUG(0, ("no transaction available\n"));
		TALLOC_FREE(result);
		return NULL;
	}
	if (pull_newest_from_marshall_buffer(ctx->transaction->m_write, key,
					     NULL, result, &result->value)) {
		result->value_valid = true;
		return result;
	}

	ctdb_data = tdb_fetch(ctx->wtdb->tdb, key);
	if (ctdb_data.dptr == NULL) {
		/* create the record */
		result->value = tdb_null;
		result->value_valid = true;
		return result;
	}

	result->value.dsize = ctdb_data.dsize - sizeof(struct ctdb_ltdb_header);
	result->value.dptr = NULL;

	if ((result->value.dsize != 0)
	    && !(result->value.dptr = (uint8_t *)talloc_memdup(
			 result, ctdb_data.dptr + sizeof(struct ctdb_ltdb_header),
			 result->value.dsize))) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(result);
		return NULL;
	}
	result->value_valid = true;

	SAFE_FREE(ctdb_data.dptr);

	return result;
}

static int db_ctdb_record_destructor(struct db_record **recp)
{
	struct db_record *rec = talloc_get_type_abort(*recp, struct db_record);
	struct db_ctdb_transaction_handle *h = talloc_get_type_abort(
		rec->private_data, struct db_ctdb_transaction_handle);
	int ret = h->ctx->db->transaction_commit(h->ctx->db);
	if (ret != 0) {
		DEBUG(0,(__location__ " transaction_commit failed\n"));
	}
	return 0;
}

/*
  auto-create a transaction for persistent databases
 */
static struct db_record *db_ctdb_fetch_locked_persistent(struct db_ctdb_ctx *ctx,
							 TALLOC_CTX *mem_ctx,
							 TDB_DATA key)
{
	int res;
	struct db_record *rec, **recp;

	res = db_ctdb_transaction_start(ctx->db);
	if (res == -1) {
		return NULL;
	}

	rec = db_ctdb_fetch_locked_transaction(ctx, mem_ctx, key);
	if (rec == NULL) {
		ctx->db->transaction_cancel(ctx->db);
		return NULL;
	}

	/* destroy this transaction when we release the lock */
	recp = talloc(rec, struct db_record *);
	if (recp == NULL) {
		ctx->db->transaction_cancel(ctx->db);
		talloc_free(rec);
		return NULL;
	}
	*recp = rec;
	talloc_set_destructor(recp, db_ctdb_record_destructor);
	return rec;
}


/*
  stores a record inside a transaction
 */
static NTSTATUS db_ctdb_transaction_store(struct db_ctdb_transaction_handle *h,
					  TDB_DATA key, TDB_DATA data)
{
	TALLOC_CTX *tmp_ctx = talloc_new(h);
	TDB_DATA rec;
	struct ctdb_ltdb_header header;

	ZERO_STRUCT(header);

	/* we need the header so we can update the RSN */

	if (!pull_newest_from_marshall_buffer(h->m_write, key, &header,
					      NULL, NULL)) {

		rec = tdb_fetch(h->ctx->wtdb->tdb, key);

		if (rec.dptr != NULL) {
			memcpy(&header, rec.dptr,
			       sizeof(struct ctdb_ltdb_header));
			rec.dsize -= sizeof(struct ctdb_ltdb_header);

			/*
			 * a special case, we are writing the same
			 * data that is there now
			 */
			if (data.dsize == rec.dsize &&
			    memcmp(data.dptr,
				   rec.dptr + sizeof(struct ctdb_ltdb_header),
				   data.dsize) == 0) {
				SAFE_FREE(rec.dptr);
				talloc_free(tmp_ctx);
				return NT_STATUS_OK;
			}
		}
		SAFE_FREE(rec.dptr);
	}

	header.dmaster = get_my_vnn();
	header.rsn++;

	h->m_write = db_ctdb_marshall_add(h, h->m_write, h->ctx->db_id, 0, key, &header, data);
	if (h->m_write == NULL) {
		DEBUG(0,(__location__ " Failed to add to marshalling record\n"));
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}


/* 
   a record store inside a transaction
 */
static NTSTATUS db_ctdb_storev_transaction(
	struct db_record *rec, const TDB_DATA *dbufs, int num_dbufs, int flag)
{
	struct db_ctdb_transaction_handle *h = talloc_get_type_abort(
		rec->private_data, struct db_ctdb_transaction_handle);
	NTSTATUS status;
	TDB_DATA data = {0};

	status = dbwrap_merge_dbufs(&data, rec, dbufs, num_dbufs);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = db_ctdb_transaction_store(h, rec->key, data);

	TALLOC_FREE(data.dptr);

	return status;
}

/*
   a record delete inside a transaction
 */
static NTSTATUS db_ctdb_delete_transaction(struct db_record *rec)
{
	struct db_ctdb_transaction_handle *h = talloc_get_type_abort(
		rec->private_data, struct db_ctdb_transaction_handle);
	NTSTATUS status;

	status =  db_ctdb_transaction_store(h, rec->key, tdb_null);
	return status;
}

static void db_ctdb_fetch_db_seqnum_parser(
	TDB_DATA key, struct ctdb_ltdb_header *header,
	TDB_DATA data, void *private_data)
{
	uint64_t *seqnum = (uint64_t *)private_data;

	if (data.dsize != sizeof(uint64_t)) {
		*seqnum = 0;
		return;
	}
	memcpy(seqnum, data.dptr, sizeof(*seqnum));
}

/**
 * Fetch the db sequence number of a persistent db directly from the db.
 */
static NTSTATUS db_ctdb_fetch_db_seqnum_from_db(struct db_ctdb_ctx *db,
						uint64_t *seqnum)
{
	NTSTATUS status;
	TDB_DATA key;

	if (seqnum == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	key = string_term_tdb_data(CTDB_DB_SEQNUM_KEY);

	status = db_ctdb_ltdb_parse(
		db, key, db_ctdb_fetch_db_seqnum_parser, seqnum);

	if (NT_STATUS_IS_OK(status)) {
		return NT_STATUS_OK;
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		*seqnum = 0;
		return NT_STATUS_OK;
	}
	return status;
}

/**
 * Store the database sequence number inside a transaction.
 */
static NTSTATUS db_ctdb_store_db_seqnum(struct db_ctdb_transaction_handle *h,
					uint64_t seqnum)
{
	NTSTATUS status;
	TDB_DATA key = string_term_tdb_data(CTDB_DB_SEQNUM_KEY);
	TDB_DATA data = { .dptr=(uint8_t *)&seqnum, .dsize=sizeof(seqnum) };

	status = db_ctdb_transaction_store(h, key, data);

	return status;
}

/*
  commit a transaction
 */
static int db_ctdb_transaction_commit(struct db_context *db)
{
	struct db_ctdb_ctx *ctx = talloc_get_type_abort(db->private_data,
							struct db_ctdb_ctx);
	NTSTATUS rets;
	int32_t status;
	struct db_ctdb_transaction_handle *h = ctx->transaction;
	uint64_t old_seqnum, new_seqnum;
	useconds_t sleep_time = 10000; /* Start with 10ms */
	int ret;

	if (h == NULL) {
		DEBUG(0,(__location__ " transaction commit with no open transaction on db 0x%08x\n", ctx->db_id));
		return -1;
	}

	if (h->nested_cancel) {
		db->transaction_cancel(db);
		DEBUG(5,(__location__ " Failed transaction commit after nested cancel\n"));
		return -1;
	}

	if (h->nesting != 0) {
		h->nesting--;
		DEBUG(5, (__location__ " transaction commit on db 0x%08x: nesting %d -> %d\n",
			  ctx->db_id, ctx->transaction->nesting + 1, ctx->transaction->nesting));
		return 0;
	}

	if (h->m_write == NULL) {
		/*
		 * No changes were made, so don't change the seqnum,
		 * don't push to other node, just exit with success.
		 */
		ret = 0;
		goto done;
	}

	DEBUG(5,(__location__ " transaction commit on db 0x%08x\n", ctx->db_id));

	/*
	 * As the last db action before committing, bump the database sequence
	 * number. Note that this undoes all changes to the seqnum records
	 * performed under the transaction. This record is not meant to be
	 * modified by user interaction. It is for internal use only...
	 */
	rets = db_ctdb_fetch_db_seqnum_from_db(ctx, &old_seqnum);
	if (!NT_STATUS_IS_OK(rets)) {
		DEBUG(1, (__location__ " failed to fetch the db sequence number "
			  "in transaction commit on db 0x%08x\n", ctx->db_id));
		ret = -1;
		goto done;
	}

	new_seqnum = old_seqnum + 1;

	rets = db_ctdb_store_db_seqnum(h, new_seqnum);
	if (!NT_STATUS_IS_OK(rets)) {
		DEBUG(1, (__location__ "failed to store the db sequence number "
			  " in transaction commit on db 0x%08x\n", ctx->db_id));
		ret = -1;
		goto done;
	}

again:
	/* tell ctdbd to commit to the other nodes */
	ret = ctdbd_control_local(messaging_ctdb_connection(),
				  CTDB_CONTROL_TRANS3_COMMIT,
				  h->ctx->db_id, 0,
				  db_ctdb_marshall_finish(h->m_write),
				  NULL, NULL, &status);
	if ((ret != 0) || status != 0) {
		/*
		 * The TRANS3_COMMIT control should only possibly fail when a
		 * recovery has been running concurrently. In any case, the db
		 * will be the same on all nodes, either the new copy or the
		 * old copy.  This can be detected by comparing the old and new
		 * local sequence numbers.
		 */
		rets = db_ctdb_fetch_db_seqnum_from_db(ctx, &new_seqnum);
		if (!NT_STATUS_IS_OK(rets)) {
			DEBUG(1, (__location__ " failed to refetch db sequence "
				  "number after failed TRANS3_COMMIT\n"));
			ret = -1;
			goto done;
		}

		if (new_seqnum == old_seqnum) {
			/*
			 * Recovery prevented all our changes: retry. Do an
			 * exponential backoff, starting with 10 ms up to one
			 * second.
			 */
			usleep(sleep_time);
			if (sleep_time < 1000000) {
				sleep_time *= 2;
			}
			goto again;
		}
		if (new_seqnum != (old_seqnum + 1)) {
			DEBUG(0, (__location__ " ERROR: new_seqnum[%lu] != "
				  "old_seqnum[%lu] + (0 or 1) after failed "
				  "TRANS3_COMMIT - this should not happen!\n",
				  (unsigned long)new_seqnum,
				  (unsigned long)old_seqnum));
			ret = -1;
			goto done;
		}
		/*
		 * Recovery propagated our changes to all nodes, completing
		 * our commit for us - succeed.
		 */
	}

	ret = 0;

done:
	h->ctx->transaction = NULL;
	talloc_free(h);
	return ret;
}


/*
  cancel a transaction
 */
static int db_ctdb_transaction_cancel(struct db_context *db)
{
	struct db_ctdb_ctx *ctx = talloc_get_type_abort(db->private_data,
							struct db_ctdb_ctx);
	struct db_ctdb_transaction_handle *h = ctx->transaction;

	if (h == NULL) {
		DEBUG(0,(__location__ " transaction cancel with no open transaction on db 0x%08x\n", ctx->db_id));
		return -1;
	}

	if (h->nesting != 0) {
		h->nesting--;
		h->nested_cancel = true;
		DEBUG(5, (__location__ " transaction cancel on db 0x%08x: nesting %d -> %d\n",
			  ctx->db_id, ctx->transaction->nesting + 1, ctx->transaction->nesting));
		return 0;
	}

	DEBUG(5,(__location__ " Cancel transaction on db 0x%08x\n", ctx->db_id));

	ctx->transaction = NULL;
	talloc_free(h);
	return 0;
}

static bool db_ctdb_can_use_local_copy(TDB_DATA ctdb_data,
				       uint32_t my_vnn,
				       bool read_only,
				       bool *persistent_in_progress);

static int db_ctdb_migrate_locked(struct db_ctdb_rec *crec,
				  TDB_DATA key,
				  TDB_DATA *_data)
{
	struct db_ctdb_ctx *ctx = crec->ctdb_ctx;
	struct timeval migrate_start;
	struct timeval chainlock_start;
	struct timeval ctdb_start_time;
	double chainlock_time = 0;
	double ctdb_time = 0;
	int migrate_attempts;
	double duration;
	int duration_msecs;
	bool persistent_in_progress;
	useconds_t sleep_time = 10000; /* Start with 10ms */
	TDB_DATA data;
	int ret;

	migrate_attempts = 0;
	GetTimeOfDay(&migrate_start);

again:
	if (DEBUGLEVEL >= 10) {
		char *keystr = hex_encode_talloc(talloc_tos(),
						 key.dptr,
						 key.dsize);
		DBG_DEBUG(DEBUGLEVEL > 10
			   ? "Locking db %u key %s\n"
			   : "Locking db %u key %.20s\n",
			   (int)ctx->db_id, keystr);
		TALLOC_FREE(keystr);
	}

	GetTimeOfDay(&chainlock_start);

	ret = tdb_chainlock(ctx->wtdb->tdb, key);
	if (ret != 0) {
		DBG_ERR("tdb_chainlock failed\n");
		return -1;
	}

	chainlock_time += timeval_elapsed(&chainlock_start);

	data = tdb_fetch(ctx->wtdb->tdb, key);

	if (!db_ctdb_can_use_local_copy(data,
					get_my_vnn(),
					false,
					&persistent_in_progress))
	{
		tdb_chainunlock(ctx->wtdb->tdb, key);
		if (persistent_in_progress) {
			/*
			 * Someone else is in the middle of doing a store with
			 * DBWRAP_STORE_PERSISTENT, give him enough time to grab
			 * the record and finish.
			 */
			usleep(sleep_time);
			if (sleep_time < 1000000) {
				sleep_time *= 2;
			}
		}

		migrate_attempts++;
		GetTimeOfDay(&ctdb_start_time);

		DBG_DEBUG("data.dptr = %p, dmaster = %"PRIu32" "
			  "(%"PRIu32") %"PRIu32"\n",
			  data.dptr, data.dptr ?
			  ((struct ctdb_ltdb_header *)data.dptr)->dmaster :
			   UINT32_MAX,
			   get_my_vnn(),
			  data.dptr ?
			  ((struct ctdb_ltdb_header *)data.dptr)->flags : 0);

		SAFE_FREE(data.dptr);

		ret = ctdbd_migrate(messaging_ctdb_connection(),
				    ctx->db_id,
				    key);
		ctdb_time += timeval_elapsed(&ctdb_start_time);
		if (ret != 0) {
			DBG_ERR("ctdbd_migrate failed: %s\n", strerror(ret));
			return -1;
		}

		goto again;
	}

	duration = timeval_elapsed(&migrate_start);
	duration_msecs = duration * 1000;

	if ((migrate_attempts > ctx->warn_migrate_attempts) ||
	    (duration_msecs > ctx->warn_migrate_msecs))
	{
		int chain = 0;

		if (tdb_get_flags(ctx->wtdb->tdb) & TDB_INCOMPATIBLE_HASH) {
			chain = tdb_jenkins_hash(&key) %
				tdb_hash_size(ctx->wtdb->tdb);
		}

		DBG_ERR("db %s key %s, chain %d "
			"needed %d attempts, %d milliseconds, "
			"chainlock: %f ms, CTDB %f ms\n",
			tdb_name(ctx->wtdb->tdb),
			hex_encode_talloc(talloc_tos(),
					  (unsigned char *)key.dptr,
					  key.dsize),
			chain,
			migrate_attempts,
			duration_msecs,
			chainlock_time * 1000.0,
			ctdb_time * 1000.0);
	}

	memcpy(&crec->header, data.dptr, sizeof(crec->header));
	memmove(data.dptr,
		data.dptr + sizeof(struct ctdb_ltdb_header),
		data.dsize - sizeof(struct ctdb_ltdb_header));
	data.dsize -= sizeof(struct ctdb_ltdb_header);

	*_data = data;
	return 0;
}

static void prepare_local_header_for_push_record(struct ctdb_ltdb_header *h)
{
	/*
	 * The combination of db_ctdb_ltdb_store() and db_ctdb_push_record()
	 * causes the record to be written to all active nodes in the cluster.
	 * This needs to be done carefully, otherwise it will interact badly
	 * with vacuuming.  The behaviour needs to simulate what happens during
	 * CTDB recovery, since this is the only other time the same record in a
	 * volatile database may be written to all nodes.
	 *
	 * MIGRATED_WITH_DATA: All records need to be written with this flag.
	 * For other nodes, this is handled by the ctdbd push record
	 * implementation.  For this (dmaster) node this flag needs to be
	 * explicitly set.
	 *
	 * dmaster has rsn++: The current dmaster needs to have the highest
	 * RSN so CTDB vacuuming recognises copies elsewhere as out-of-date,
	 * causing them to be deleted.  This would normally be done when
	 * ctdb_ltdb_store() calls ctdb_ltdb_store_server().  However, the
	 * record is stored directly here, so the RSN increment needs to be
	 * done here.
	 */
	h->rsn++;
	h->flags |= CTDB_REC_FLAG_MIGRATED_WITH_DATA;
}

static NTSTATUS db_ctdb_storev(struct db_record *rec,
			       const TDB_DATA *orig_dbufs,
			       int orig_num_dbufs,
			       int flag)
{
	struct db_ctdb_rec *crec = talloc_get_type_abort(
		rec->private_data, struct db_ctdb_rec);
	struct server_id id = messaging_server_id(global_messaging_context());
	int num_dbufs = orig_num_dbufs;
	TDB_DATA data;
	TDB_DATA _dbufs[num_dbufs + 1];
	const TDB_DATA *dbufs = orig_dbufs;
	uint8_t idbuf[SERVER_ID_BUF_LENGTH];
	struct ctdb_ltdb_header header = crec->header;
	struct db_context *pdb = crec->ctdb_ctx->pdb;
	struct db_ctdb_ctx *pdb_ctdb_ctx = NULL;
	struct db_record *prec = NULL;
	bool do_persistent_store = false;
	bool do_persistent_delete = false;
	NTSTATUS status;
	int ret;

	if (flag & DBWRAP_STORE_PERSISTENT) {
		do_persistent_store = true;
	} else if (rec->flags.persistent) {
		do_persistent_delete = true;
	}

	if (do_persistent_store || do_persistent_delete) {
		/*
		 * As we drop the chainlock at some point below and reacquire it
		 * at the end (see below for the reasons for that), we have to
		 * add this user-space lock to make the whole operation atomic
		 * again.
		 */
		server_id_put(idbuf, id);
		_dbufs[0] = (TDB_DATA) {
			.dptr = idbuf,
			.dsize = SERVER_ID_BUF_LENGTH,
		};
		memcpy(&_dbufs[1], orig_dbufs, orig_num_dbufs * sizeof(TDB_DATA));
		dbufs = _dbufs;
		num_dbufs++;
		header.flags |= CTDB_REC_FLAG_PERSISTENT_IN_PROGRESS;
	}

	if (do_persistent_store) {
		prepare_local_header_for_push_record(&header);
		header.flags |= CTDB_REC_FLAG_PERSISTENT;
		crec->header.flags |= CTDB_REC_FLAG_PERSISTENT;
	}

	status = db_ctdb_ltdb_store(crec->ctdb_ctx,
				    rec->key,
				    &header,
				    dbufs,
				    num_dbufs);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("db_ctdb_ltdb_store failed: %s\n", nt_errstr(status));
		return status;
	}

	if (do_persistent_delete) {
		ret = tdb_chainunlock(crec->ctdb_ctx->wtdb->tdb, rec->key);
		if (ret != 0) {
			DBG_ERR("tdb_chainunlock failed\n");
			return NT_STATUS_INTERNAL_DB_ERROR;
		}

		pdb_ctdb_ctx = talloc_get_type_abort(
			pdb->private_data, struct db_ctdb_ctx);

		prec = db_ctdb_fetch_locked_persistent(pdb_ctdb_ctx,
						       talloc_tos(),
						       rec->key);
		if (prec == NULL) {
			DBG_ERR("db_ctdb_fetch_locked_persistent failed\n");
			return NT_STATUS_INTERNAL_ERROR;
		}

		status = db_ctdb_delete_transaction(prec);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("db_ctdb_fetch_locked_persistent failed\n");
			return NT_STATUS_INTERNAL_ERROR;
		}

		/* This commits the transaction */
		TALLOC_FREE(prec);

		ret = db_ctdb_migrate_locked(crec, rec->key, &data);
		if (ret != 0) {
			DBG_ERR("db_ctdb_migrate failed\n");
			return NT_STATUS_INTERNAL_ERROR;
		}
		SAFE_FREE(data.dptr);

		crec->header.flags &= ~CTDB_REC_FLAG_PERSISTENT_IN_PROGRESS;
                crec->header.flags &= ~CTDB_REC_FLAG_PERSISTENT;

		status = db_ctdb_ltdb_store(crec->ctdb_ctx,
					    rec->key,
					    &crec->header,
					    orig_dbufs,
					    orig_num_dbufs);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("db_ctdb_ltdb_store failed: %s\n", nt_errstr(status));
			return status;
		}
		rec->flags.persistent = false;
		return NT_STATUS_OK;
	}

	if (!do_persistent_store) {
		return NT_STATUS_OK;
	}

	/* Make sure not to confuse tdb with unknown flags */
	flag &= DBWRAP_TDB_FLAGS;

	/*
	 * First push out the record to the volatile dbs on all nodes. If this
	 * returns success, this just means the push out succeeded, not that the
	 * records are already on stable storage on the nodes.
	 *
	 * That's where the subsequent transaction on the persistent db comes
	 * into play: it's a kind of barrier and the transaction succeeding
	 * means all previous operations, either a successful push-record, or a
	 * recovery, succeeded. Either a successful push-record, or a recovery
	 * happening between the initial local store and the final transaction
	 * store, will have successfully pushed out the record to all nodes.
	 */
	status = db_ctdb_push_record(rec, orig_dbufs, orig_num_dbufs);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	 * We have to drop the chainlock, otherwise we could deadlock with ctdb
	 * recovery while doing txn below, but this has consequences, see
	 * below...
	 */
	ret = tdb_chainunlock(crec->ctdb_ctx->wtdb->tdb, rec->key);
	if (ret != 0) {
		DBG_ERR("tdb_chainunlock failed\n");
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	pdb_ctdb_ctx = talloc_get_type_abort(
		pdb->private_data, struct db_ctdb_ctx);

	prec = db_ctdb_fetch_locked_persistent(pdb_ctdb_ctx,
					       talloc_tos(),
					       rec->key);
	if (prec == NULL) {
		DBG_ERR("db_ctdb_fetch_locked_persistent failed\n");
		return NT_STATUS_INTERNAL_ERROR;
	}

	status = db_ctdb_storev_transaction(prec,
					    orig_dbufs,
					    orig_num_dbufs,
					    flag);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("db_ctdb_storev_transaction failed\n");
		return status;
	}

	/* This will commit the transaction */
	TALLOC_FREE(prec);


	/*
	 * We have to go through the whole migrate/lock/check loop again as
	 * we've dropped the chainlock above and the record could have been
	 * migrated away.
	 */
	ret = db_ctdb_migrate_locked(crec, rec->key, &data);
	if (ret != 0) {
		DBG_ERR("db_ctdb_migrate failed\n");
		return NT_STATUS_INTERNAL_ERROR;
	}
	SAFE_FREE(data.dptr);

	crec->header.flags &= ~CTDB_REC_FLAG_PERSISTENT_IN_PROGRESS;

	status = db_ctdb_ltdb_store(crec->ctdb_ctx,
				    rec->key,
				    &crec->header,
				    orig_dbufs,
				    orig_num_dbufs);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("db_ctdb_ltdb_store failed: %s\n", nt_errstr(status));
		return status;
	}
	rec->flags.persistent = true;
	return status;
}



static NTSTATUS db_ctdb_send_schedule_for_deletion(struct db_record *rec)
{
	NTSTATUS status = NT_STATUS_OK;
	int ret;
	struct ctdb_control_schedule_for_deletion *dd;
	TDB_DATA indata;
	int32_t cstatus;
	struct db_ctdb_rec *crec = talloc_get_type_abort(
		rec->private_data, struct db_ctdb_rec);
	struct db_ctdb_ctx *ctx = crec->ctdb_ctx;

	indata.dsize = offsetof(struct ctdb_control_schedule_for_deletion, key) + rec->key.dsize;
	indata.dptr = talloc_zero_array(crec, uint8_t, indata.dsize);
	if (indata.dptr == NULL) {
		DEBUG(0, (__location__ " talloc failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	dd = (struct ctdb_control_schedule_for_deletion *)(void *)indata.dptr;
	dd->db_id = ctx->db_id;
	dd->hdr = crec->header;
	dd->keylen = rec->key.dsize;
	memcpy(dd->key, rec->key.dptr, rec->key.dsize);

	ret = ctdbd_control_local(messaging_ctdb_connection(),
				  CTDB_CONTROL_SCHEDULE_FOR_DELETION,
				  crec->ctdb_ctx->db_id,
				  CTDB_CTRL_FLAG_NOREPLY, /* flags */
				  indata,
				  NULL, /* mem_ctx */
				  NULL, /* outdata */
				  &cstatus);
	talloc_free(indata.dptr);

	if ((ret != 0) || cstatus != 0) {
		DEBUG(1, (__location__ " Error sending local control "
			  "SCHEDULE_FOR_DELETION: %s, cstatus = %"PRIi32"\n",
			  strerror(ret), cstatus));
		if (ret != 0) {
			status = map_nt_error_from_unix(ret);
		} else {
			status = NT_STATUS_UNSUCCESSFUL;
		}
	}

	return status;
}

static NTSTATUS db_ctdb_delete(struct db_record *rec)
{
	NTSTATUS status;

	/*
	 * We have to store the header with empty data. TODO: Fix the
	 * tdb-level cleanup
	 */

	status = db_ctdb_storev(rec, &tdb_null, 1, 0);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = db_ctdb_send_schedule_for_deletion(rec);
	return status;
}

static int db_ctdb_record_destr(struct db_record* data)
{
	struct db_ctdb_rec *crec = talloc_get_type_abort(
		data->private_data, struct db_ctdb_rec);
	int threshold;
	int ret;
	struct timeval before;
	double timediff;

	DEBUG(10, (DEBUGLEVEL > 10
		   ? "Unlocking db %u key %s\n"
		   : "Unlocking db %u key %.20s\n",
		   (int)crec->ctdb_ctx->db_id,
		   hex_encode_talloc(data, (unsigned char *)data->key.dptr,
			      data->key.dsize)));

	before = timeval_current();

	ret = tdb_chainunlock(crec->ctdb_ctx->wtdb->tdb, data->key);

	timediff = timeval_elapsed(&before);
	timediff *= 1000;	/* get us milliseconds */

	if (timediff > crec->ctdb_ctx->warn_unlock_msecs) {
		char *key;
		key = hex_encode_talloc(talloc_tos(),
					(unsigned char *)data->key.dptr,
					data->key.dsize);
		DEBUG(0, ("tdb_chainunlock on db %s, key %s took %f milliseconds\n",
			  tdb_name(crec->ctdb_ctx->wtdb->tdb), key,
			  timediff));
		TALLOC_FREE(key);
	}

	if (ret != 0) {
		DEBUG(0, ("tdb_chainunlock failed\n"));
		return -1;
	}

	threshold = crec->ctdb_ctx->warn_locktime_msecs;
	if (threshold != 0) {
		timediff = timeval_elapsed(&crec->lock_time) * 1000;
		if (timediff > threshold) {
			const char *key;

			key = hex_encode_talloc(data,
						(unsigned char *)data->key.dptr,
						data->key.dsize);
			DEBUG(0, ("Held tdb lock on db %s, key %s "
				  "%f milliseconds\n",
				  tdb_name(crec->ctdb_ctx->wtdb->tdb),
				  key, timediff));
		}
	}

	return 0;
}

/**
 * Check whether we have a valid local copy of the given record,
 * either for reading or for writing.
 */
static bool db_ctdb_can_use_local_hdr(const struct ctdb_ltdb_header *hdr,
				      TDB_DATA data,
				      uint32_t my_vnn,
				      bool read_only,
				      bool *persistent_in_progress)
{
	*persistent_in_progress = false;

	if (hdr->dmaster != my_vnn) {
		/* If we're not dmaster, it must be r/o copy. */
		return read_only && (hdr->flags & CTDB_REC_RO_HAVE_READONLY);
	}

	if (hdr->flags & CTDB_REC_FLAG_PERSISTENT_IN_PROGRESS) {
		struct server_id my_id = messaging_server_id(
			global_messaging_context());
		struct server_id id;

		SMB_ASSERT(data.dsize >= SERVER_ID_BUF_LENGTH);

		server_id_get(&id, data.dptr);
		if (server_id_equal(&id, &my_id)) {
			/*
			 * Out own in-progress record, use it
			 */
			return true;
		}
		if (serverid_exists(&id)) {
			/*
			 * Someone else is using it, let the caller know.
			 */
			*persistent_in_progress = true;
			return false;
		}
		/*
		 * This has a stale persistent_in_progress header,
		 * remove the header and use the record.
		 */

		memmove(data.dptr,
			data.dptr + SERVER_ID_BUF_LENGTH,
			data.dsize - SERVER_ID_BUF_LENGTH);
		data.dsize -= SERVER_ID_BUF_LENGTH;
		return true;
	}

	/*
	 * If we want write access, no one may have r/o copies.
	 */
	return read_only || !(hdr->flags & CTDB_REC_RO_HAVE_DELEGATIONS);
}

static bool db_ctdb_can_use_local_copy(TDB_DATA ctdb_data, uint32_t my_vnn,
				       bool read_only,
				       bool *persistent_in_progress)
{
	TDB_DATA data;

	*persistent_in_progress = false;

	if (ctdb_data.dptr == NULL) {
		return false;
	}

	if (ctdb_data.dsize < sizeof(struct ctdb_ltdb_header)) {
		return false;
	}

	data = (TDB_DATA) {
		.dptr = ctdb_data.dptr + sizeof(struct ctdb_ltdb_header),
		.dsize = ctdb_data.dsize - sizeof(struct ctdb_ltdb_header)
	};

	return db_ctdb_can_use_local_hdr(
		(struct ctdb_ltdb_header *)ctdb_data.dptr,
		data,
		my_vnn,
		read_only,
		persistent_in_progress);
}

static struct db_record *fetch_locked_internal(struct db_ctdb_ctx *ctx,
					       TALLOC_CTX *mem_ctx,
					       TDB_DATA key)
{
	struct db_record *result;
	struct db_ctdb_rec *crec;
	TDB_DATA ctdb_data;
	int ret;

	if (!(result = talloc(mem_ctx, struct db_record))) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	if (!(crec = talloc_zero(result, struct db_ctdb_rec))) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(result);
		return NULL;
	}

	result->flags = (struct db_record_flags) {};
	result->db = ctx->db;
	result->private_data = (void *)crec;
	result->storev = db_ctdb_storev;
	result->delete_rec = db_ctdb_delete;
	crec->ctdb_ctx = ctx;

	/*
	 * Do a blocking lock on the record
	 */
	ret = db_ctdb_migrate_locked(crec, key, &ctdb_data);
	if (ret != 0) {
		DBG_ERR("db_ctdb_migrate_locked failed\n");
		TALLOC_FREE(result);
		return NULL;
	}

	GetTimeOfDay(&crec->lock_time);
	talloc_set_destructor(result, db_ctdb_record_destr);

	result->key.dsize = key.dsize;
	result->key.dptr = (uint8_t *)talloc_memdup(result, key.dptr,
						    key.dsize);
	if (result->key.dptr == NULL) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(result);
		return NULL;
	}

	result->value.dsize = ctdb_data.dsize;
	result->value.dptr = NULL;

	if (result->value.dsize != 0) {
		result->value.dptr = talloc_memdup(
			result, ctdb_data.dptr,
			result->value.dsize);
		if (result->value.dptr == NULL) {
			DBG_ERR("talloc failed\n");
			TALLOC_FREE(result);
			return NULL;
		}
	}

	if (crec->header.flags & CTDB_REC_FLAG_PERSISTENT) {
		result->flags.persistent = true;
	}

	result->value_valid = true;

	SAFE_FREE(ctdb_data.dptr);

	return result;
}

static struct db_record *db_ctdb_fetch_locked(struct db_context *db,
					      TALLOC_CTX *mem_ctx,
					      TDB_DATA key)
{
	struct db_ctdb_ctx *ctx = talloc_get_type_abort(db->private_data,
							struct db_ctdb_ctx);

	if (ctx->transaction != NULL) {
		return db_ctdb_fetch_locked_transaction(ctx, mem_ctx, key);
	}

	if (db->persistent) {
		return db_ctdb_fetch_locked_persistent(ctx, mem_ctx, key);
	}

	return fetch_locked_internal(ctx, mem_ctx, key);
}

struct db_ctdb_parse_record_state {
	struct tevent_context *ev;
	struct db_context *db;
	TDB_DATA key;
	void (*parser)(TDB_DATA key, TDB_DATA data, void *private_data);
	void *private_data;
	uint32_t my_vnn;
	bool local;
	bool ask_for_readonly_copy;
	bool done;
	bool empty_record;
	enum dbwrap_req_state *req_state;
	bool persistent_in_progress;
	useconds_t sleep_time;
};

static void db_ctdb_parse_record_parser(
	TDB_DATA key, struct ctdb_ltdb_header *header,
	TDB_DATA data, void *private_data)
{
	struct db_ctdb_parse_record_state *state =
		(struct db_ctdb_parse_record_state *)private_data;
	state->parser(key, data, state->private_data);
}

static void db_ctdb_parse_record_parser_nonpersistent(
	TDB_DATA key, struct ctdb_ltdb_header *header,
	TDB_DATA data, void *private_data)
{
	struct db_ctdb_parse_record_state *state =
		(struct db_ctdb_parse_record_state *)private_data;

	if (!db_ctdb_can_use_local_hdr(header,
				       data,
				       state->my_vnn,
				       true,
				       &state->persistent_in_progress))
	{
		if (state->persistent_in_progress) {
			return;
		}
		if (state->local) {
			/*
			 * We found something in the db, so it seems that this record,
			 * while not usable locally right now, is popular. Ask for a
			 * R/O copy.
			 */
			state->ask_for_readonly_copy = true;
		}
		return;
	}

	/*
	 * A record consisting only of the ctdb header can be
	 * a validly created empty record or a tombstone
	 * record of a deleted record (not vacuumed yet). Mark
	 * it accordingly.
	 */
	state->empty_record = (data.dsize == 0);
	if (!state->empty_record) {
		state->parser(key, data, state->private_data);
	}
	state->done = true;
}

static NTSTATUS db_ctdb_try_parse_local_record(struct db_ctdb_ctx *ctx,
					       TDB_DATA key,
					       struct db_ctdb_parse_record_state *state)
{
	NTSTATUS status;

	if (ctx->transaction != NULL) {
		struct db_ctdb_transaction_handle *h = ctx->transaction;
		bool found;

		/*
		 * Transactions only happen for persistent db's.
		 */

		found = parse_newest_in_marshall_buffer(
			h->m_write, key, db_ctdb_parse_record_parser, state);

		if (found) {
			return NT_STATUS_OK;
		}
	}

	if (ctx->db->persistent) {
		/*
		 * Persistent db, but not found in the transaction buffer
		 */
		return db_ctdb_ltdb_parse(
			ctx, key, db_ctdb_parse_record_parser, state);
	}

	state->done = false;
	state->ask_for_readonly_copy = false;

	status = db_ctdb_ltdb_parse(
		ctx, key, db_ctdb_parse_record_parser_nonpersistent, state);
	if (NT_STATUS_IS_OK(status) && state->done) {
		if (state->empty_record) {
			/*
			 * We know authoritatively, that this is an empty
			 * record. Since ctdb does not distinguish between empty
			 * and deleted records, this can be a record stored as
			 * empty or a not-yet-vacuumed tombstone record of a
			 * deleted record. Now Samba right now can live without
			 * empty records, so we can safely report this record
			 * as non-existing.
			 *
			 * See bugs 10008 and 12005.
			 */
			return NT_STATUS_NOT_FOUND;
		}
		return NT_STATUS_OK;
	}

	return NT_STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS db_ctdb_parse_record(struct db_context *db, TDB_DATA key,
				     void (*parser)(TDB_DATA key,
						    TDB_DATA data,
						    void *private_data),
				     void *private_data)
{
	struct db_ctdb_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_ctdb_ctx);
	struct db_ctdb_parse_record_state state;
	useconds_t sleep_time = 10000; /* Start with 10ms */
	NTSTATUS status;
	int ret;

again_local:
	state = (struct db_ctdb_parse_record_state) {
		.parser = parser,
		.private_data = private_data,
		.my_vnn = get_my_vnn(),
		.local = true,
	};

	status = db_ctdb_try_parse_local_record(ctx, key, &state);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		return status;
	}
	if (state.persistent_in_progress) {
		/*
		 * Someone else is in the middle of doing a store with
		 * DBWRAP_STORE_PERSISTENT, give him enough time to grab
		 * the record and finish.
		 */
		usleep(sleep_time);
		if (sleep_time < 1000000) {
			sleep_time *= 2;
		}
		goto again_local;
	}

	state.local = false;
	if (db->flags & DBWRAP_FLAG_PER_REC_PERSISTENT) {
		/*
		 * TODO: check compatibility of using push-record with read-only
		 * copies. For now disable read-only records.
		 */
		state.ask_for_readonly_copy = false;
	}

	sleep_time = 10000; /* Start with 10ms */

again_ctdb:
	ret = ctdbd_parse(messaging_ctdb_connection(),
			  ctx->db_id,
			  key,
			  state.ask_for_readonly_copy,
			  db_ctdb_parse_record_parser_nonpersistent,
			  &state);
	if (ret != 0) {
		if (ret == ENOENT) {
			/*
			 * This maps to
			 * NT_STATUS_OBJECT_NAME_NOT_FOUND. Our upper
			 * layers expect NT_STATUS_NOT_FOUND for "no
			 * record around". We need to convert dbwrap
			 * to 0/errno away from NTSTATUS ... :-)
			 */
			return NT_STATUS_NOT_FOUND;
		}
		return map_nt_error_from_unix(ret);
	}
	if (state.persistent_in_progress) {
		/*
		 * Someone else is in the middle of doing a store with
		 * DBWRAP_STORE_PERSISTENT, give him enough time to grab
		 * the record and finish.
		 */
		usleep(sleep_time);
		if (sleep_time < 1000000) {
			sleep_time *= 2;
		}
		goto again_ctdb;
	}
	return NT_STATUS_OK;
}

static void db_ctdb_parse_record_done(struct tevent_req *subreq);

static struct tevent_req *db_ctdb_parse_record_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct db_context *db,
	TDB_DATA key,
	void (*parser)(TDB_DATA key,
		       TDB_DATA data,
		       void *private_data),
	void *private_data,
	enum dbwrap_req_state *req_state)
{
	struct db_ctdb_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_ctdb_ctx);
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct db_ctdb_parse_record_state *state = NULL;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct db_ctdb_parse_record_state);
	if (req == NULL) {
		*req_state = DBWRAP_REQ_ERROR;
		return NULL;

	}

	*state = (struct db_ctdb_parse_record_state) {
		.ev = ev,
		.db = db,
		.key = key,
		.parser = parser,
		.private_data = private_data,
		.req_state = req_state,
		.my_vnn = get_my_vnn(),
		.empty_record = false,
		.sleep_time = 10000, /* start with 10 ms */
	};

again_local:
	status = db_ctdb_try_parse_local_record(ctx, key, state);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		if (tevent_req_nterror(req, status)) {
			*req_state = DBWRAP_REQ_ERROR;
			return tevent_req_post(req, ev);
		}
		*req_state = DBWRAP_REQ_DONE;
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}
	if (state->persistent_in_progress) {
		/*
		 * Someone else is in the middle of doing a store with
		 * DBWRAP_STORE_PERSISTENT, give him enough time to grab
		 * the record and finish.
		 */
		usleep(state->sleep_time);
		if (state->sleep_time < 1000000) {
			state->sleep_time *= 2;
		}
		goto again_local;
	}

	if (db->flags & DBWRAP_FLAG_PER_REC_PERSISTENT) {
		/*
		 * TODO: check compatibility of using push-record with read-only
		 * copies. For now disable read-only records.
		 */
		state->ask_for_readonly_copy = false;
	}

	state->sleep_time = 10000; /* start with 10 ms */

	subreq = ctdbd_parse_send(state,
				  ev,
				  ctdb_async_ctx.async_conn,
				  ctx->db_id,
				  key,
				  state->ask_for_readonly_copy,
				  db_ctdb_parse_record_parser_nonpersistent,
				  private_data,
				  req_state);
	if (tevent_req_nomem(subreq, req)) {
		*req_state = DBWRAP_REQ_ERROR;
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, db_ctdb_parse_record_done, req);

	return req;
}

static void db_ctdb_parse_record_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct db_ctdb_parse_record_state *state = tevent_req_data(
		req, struct db_ctdb_parse_record_state);
	struct db_ctdb_ctx *ctx = talloc_get_type_abort(
		state->db->private_data, struct db_ctdb_ctx);
	int ret;

	ret = ctdbd_parse_recv(subreq);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		if (ret == ENOENT) {
			/*
			 * This maps to NT_STATUS_OBJECT_NAME_NOT_FOUND. Our
			 * upper layers expect NT_STATUS_NOT_FOUND for "no
			 * record around". We need to convert dbwrap to 0/errno
			 * away from NTSTATUS ... :-)
			 */
			tevent_req_nterror(req, NT_STATUS_NOT_FOUND);
			return;
		}
		tevent_req_nterror(req, map_nt_error_from_unix(ret));
		return;
	}

	if (state->persistent_in_progress) {
		/*
		 * Someone else is in the middle of doing a store with
		 * DBWRAP_STORE_PERSISTENT, give him enough time to grab
		 * the record and finish.
		 */
		usleep(state->sleep_time);
		if (state->sleep_time < 1000000) {
			state->sleep_time *= 2;
		}
		subreq = ctdbd_parse_send(state,
					  state->ev,
					  ctdb_async_ctx.async_conn,
					  ctx->db_id,
					  state->key,
					  state->ask_for_readonly_copy,
					  db_ctdb_parse_record_parser_nonpersistent,
					  state->private_data,
					  state->req_state);
		if (tevent_req_nomem(subreq, req)) {
			*(state->req_state) = DBWRAP_REQ_ERROR;
			return;
		}
		tevent_req_set_callback(subreq, db_ctdb_parse_record_done, req);
		return;
	}

	tevent_req_done(req);
	return;
}

static NTSTATUS db_ctdb_parse_record_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

struct traverse_state {
	struct db_context *db;
	int (*fn)(struct db_record *rec, void *private_data);
	void *private_data;
	int count;
	bool filter;
};

static void traverse_callback(TDB_DATA key, TDB_DATA data, void *private_data)
{
	struct traverse_state *state = (struct traverse_state *)private_data;
	struct db_record *rec = NULL;
	TALLOC_CTX *tmp_ctx = NULL;

	if ((state->db->flags & DBWRAP_FLAG_PER_REC_PERSISTENT) &&
	    state->filter &&
	    (key.dsize == sizeof(DBWRAP_PERSISTENT_MIGRATION_MARKER_KEY)))
	{
		int cmp;
		cmp = memcmp(key.dptr,
			     DBWRAP_PERSISTENT_MIGRATION_MARKER_KEY,
			     sizeof(DBWRAP_PERSISTENT_MIGRATION_MARKER_KEY));
		if (cmp == 0) {
			return;
		}
	}

	if (data.dsize < sizeof(struct ctdb_ltdb_header)) {
		dbwrap_log_key("Small record for key\n", key);
		return;
	}

	tmp_ctx = talloc_new(state->db);
	if (tmp_ctx == NULL) {
		DBG_ERR("talloc_new failed\n");
		return;
	}

	/* we have to give them a locked record to prevent races */
	rec = db_ctdb_fetch_locked(state->db, tmp_ctx, key);
	if (rec != NULL && rec->value.dsize > 0) {
		state->fn(rec, state->private_data);
		state->count++;
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

	/*
	 * Skip the __db_sequence_number__ key:
	 * This is used for persistent transactions internally.
	 */
	if (kbuf.dsize == strlen(CTDB_DB_SEQNUM_KEY) + 1 &&
	    strcmp((const char*)kbuf.dptr, CTDB_DB_SEQNUM_KEY) == 0)
	{
		goto done;
	}

	/* we have to give them a locked record to prevent races */
	rec = db_ctdb_fetch_locked(state->db, tmp_ctx, kbuf);
	if (rec && rec->value.dsize > 0) {
		ret = state->fn(rec, state->private_data);
	}

done:
	talloc_free(tmp_ctx);
	return ret;
}

/* wrapper to use traverse_persistent_callback with dbwrap */
static int traverse_persistent_callback_dbwrap(struct db_record *rec, void* data)
{
	return traverse_persistent_callback(NULL, rec->key, rec->value, data);
}

static int db_ctdbd_traverse(uint32_t db_id,
			     void (*fn)(TDB_DATA key, TDB_DATA data,
					void *private_data),
			     void *private_data)
{
	struct ctdbd_connection *conn;
	int ret;

	become_root();
	ret = ctdbd_init_connection(talloc_tos(), lp_ctdbd_socket(),
				    lp_ctdb_timeout(), &conn);
	unbecome_root();
	if (ret != 0) {
		DBG_WARNING("ctdbd_init_connection failed: %s\n",
			    strerror(ret));
		return ret;
	}

	ret = ctdbd_traverse(conn, db_id, fn, private_data);
	TALLOC_FREE(conn);

	if (ret != 0) {
		DBG_WARNING("ctdbd_traverse failed: %s\n",
			    strerror(ret));
		return ret;
	}

	return 0;
}

static int db_ctdb_traverse_internal(struct db_context *db,
				     int (*fn)(struct db_record *rec,
					       void *private_data),
				     bool filter,
				     void *private_data)
{
	int ret;
        struct db_ctdb_ctx *ctx = talloc_get_type_abort(db->private_data,
                                                        struct db_ctdb_ctx);
	struct traverse_state state;

	state = (struct traverse_state) {
		.db = db,
		.fn = fn,
		.filter = filter,
		.private_data = private_data,
	};

	if (db->persistent) {
		struct tdb_context *ltdb = ctx->wtdb->tdb;

		/* for persistent databases we don't need to do a ctdb traverse,
		   we can do a faster local traverse */
		ret = tdb_traverse(ltdb, traverse_persistent_callback, &state);
		if (ret < 0) {
			return ret;
		}
		if (ctx->transaction && ctx->transaction->m_write) {
			/*
			 * we now have to handle keys not yet
			 * present at transaction start
			 */
			struct db_context *newkeys = db_open_rbt(talloc_tos());
			struct ctdb_marshall_buffer *mbuf = ctx->transaction->m_write;
			struct ctdb_rec_data_old *rec=NULL;
			uint32_t i;
			int count = 0;
			NTSTATUS status;

			if (newkeys == NULL) {
				return -1;
			}

			for (i=0; i<mbuf->count; i++) {
				TDB_DATA key;
				rec = db_ctdb_marshall_loop_next_key(
					mbuf, rec, &key);
				SMB_ASSERT(rec != NULL);

				if (!tdb_exists(ltdb, key)) {
					dbwrap_store(newkeys, key, tdb_null, 0);
				}
			}
			status = dbwrap_traverse(newkeys,
						 traverse_persistent_callback_dbwrap,
						 &state,
						 &count);
			talloc_free(newkeys);
			if (!NT_STATUS_IS_OK(status)) {
				return -1;
			}
			ret += count;
		}
		return ret;
	}

	ret = db_ctdbd_traverse(ctx->db_id, traverse_callback, &state);
	if (ret != 0) {
		return -1;
	}
	return state.count;
}

static int db_ctdb_traverse(struct db_context *db,
			    int (*fn)(struct db_record *rec,
				      void *private_data),
			    void *private_data)
{
	return db_ctdb_traverse_internal(db, fn, true, private_data);
}

static NTSTATUS db_ctdb_storev_deny(struct db_record *rec,
				    const TDB_DATA *dbufs, int num_dbufs, int flag)
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
	struct ctdb_ltdb_header h = {};
	struct db_record rec = {};

	if ((state->db->flags & DBWRAP_FLAG_PER_REC_PERSISTENT) &&
	    (key.dsize == sizeof(DBWRAP_PERSISTENT_MIGRATION_MARKER_KEY)))
	{
		int cmp;
		cmp = memcmp(key.dptr,
			     DBWRAP_PERSISTENT_MIGRATION_MARKER_KEY,
			     sizeof(DBWRAP_PERSISTENT_MIGRATION_MARKER_KEY));
		if (cmp == 0) {
			return;
		}
	}

	if (data.dsize < sizeof(h)) {
		DBG_ERR("Small record for key [%s]\n",
			hex_encode_talloc(
				talloc_tos(),
				(unsigned char *)key.dptr,
				key.dsize));
		return;
	}

	if (state->db->flags & DBWRAP_FLAG_PER_REC_PERSISTENT) {
		memcpy(&h, data.dptr, sizeof(h));
	}
	data.dsize -= sizeof(h);
	data.dptr += sizeof(h);

	rec.db = state->db;
	rec.key = key;
	rec.value = data;
	rec.storev = db_ctdb_storev_deny;
	rec.delete_rec = db_ctdb_delete_deny;
	rec.private_data = NULL;
	if (h.flags & CTDB_REC_FLAG_PERSISTENT) {
		rec.flags.persistent = true;
	}
	rec.value_valid = true;
	state->fn(&rec, state->private_data);
	state->count++;
}

static int traverse_persistent_callback_read(TDB_CONTEXT *tdb, TDB_DATA kbuf, TDB_DATA dbuf,
					void *private_data)
{
	struct traverse_state *state = (struct traverse_state *)private_data;
	struct db_record rec;

	/*
	 * Skip the __db_sequence_number__ key:
	 * This is used for persistent transactions internally.
	 */
	if (kbuf.dsize == strlen(CTDB_DB_SEQNUM_KEY) + 1 &&
	    strcmp((const char*)kbuf.dptr, CTDB_DB_SEQNUM_KEY) == 0)
	{
		return 0;
	}

	ZERO_STRUCT(rec);
	rec.db = state->db;
	rec.key = kbuf;
	rec.value = dbuf;
	rec.value_valid = true;
	rec.storev = db_ctdb_storev_deny;
	rec.delete_rec = db_ctdb_delete_deny;
	rec.private_data = NULL;

	if (rec.value.dsize <= sizeof(struct ctdb_ltdb_header)) {
		/* a deleted record */
		return 0;
	}
	rec.value.dsize -= sizeof(struct ctdb_ltdb_header);
	rec.value.dptr += sizeof(struct ctdb_ltdb_header);

	state->count++;
	return state->fn(&rec, state->private_data);
}

static int db_ctdb_traverse_read(struct db_context *db,
				 int (*fn)(struct db_record *rec,
					   void *private_data),
				 void *private_data)
{
	int ret;
        struct db_ctdb_ctx *ctx = talloc_get_type_abort(db->private_data,
                                                        struct db_ctdb_ctx);
	struct traverse_state state;

	state = (struct traverse_state) {
		.db = db,
		.fn = fn,
		.private_data = private_data,
	};

	if (db->persistent) {
		/* for persistent databases we don't need to do a ctdb traverse,
		   we can do a faster local traverse */
		int nrecs;

		nrecs = tdb_traverse_read(ctx->wtdb->tdb,
					  traverse_persistent_callback_read,
					  &state);
		if (nrecs == -1) {
			return -1;
		}
		return state.count;
	}

	ret = db_ctdbd_traverse(ctx->db_id, traverse_read_callback, &state);
	if (ret != 0) {
		return -1;
	}
	return state.count;
}

static int traverse_perrec_persistent_read_cb(TDB_CONTEXT *tdb,
					      TDB_DATA kbuf,
					      TDB_DATA dbuf,
					      void *private_data)
{
	struct traverse_state *state = (struct traverse_state *)private_data;
	struct db_record rec;

	/*
	 * Skip the __db_sequence_number__ key:
	 * This is used for persistent transactions internally.
	 */
	if (kbuf.dsize == strlen(CTDB_DB_SEQNUM_KEY) + 1 &&
	    strcmp((const char*)kbuf.dptr, CTDB_DB_SEQNUM_KEY) == 0)
	{
		return 0;
	}

	ZERO_STRUCT(rec);
	rec.db = state->db;
	rec.key = kbuf;
	rec.value = dbuf;
	rec.value_valid = true;
	rec.storev = db_ctdb_storev_deny;
	rec.delete_rec = db_ctdb_delete_deny;
	rec.private_data = NULL;

	if (rec.value.dsize <= sizeof(struct ctdb_ltdb_header)) {
		/* A deleted record */
		return 0;
	}
	rec.value.dsize -= sizeof(struct ctdb_ltdb_header);
	rec.value.dptr += sizeof(struct ctdb_ltdb_header);

	state->count++;
	return state->fn(&rec, state->private_data);
}

static int db_ctdb_traverse_per_rec_persistent_read(
	struct db_context *db,
	int (*fn)(struct db_record *rec,
		  void *private_data),
	void *private_data)
{
	struct db_ctdb_ctx *ctx = talloc_get_type_abort(db->private_data,
							struct db_ctdb_ctx);
	struct db_ctdb_ctx *pctx = talloc_get_type_abort(ctx->pdb->private_data,
							struct db_ctdb_ctx);
	struct traverse_state state;
	int nrecs;

	if (!(db->flags & DBWRAP_FLAG_PER_REC_PERSISTENT)) {
		return 0;
	}

	state.db = db;
	state.fn = fn;
	state.private_data = private_data;
	state.count = 0;

	nrecs = tdb_traverse_read(pctx->wtdb->tdb,
				  traverse_perrec_persistent_read_cb,
				  &state);
	if (nrecs == -1) {
		return -1;
	}
	return state.count;
}

static int db_ctdb_get_seqnum(struct db_context *db)
{
        struct db_ctdb_ctx *ctx = talloc_get_type_abort(db->private_data,
                                                        struct db_ctdb_ctx);
	return tdb_get_seqnum(ctx->wtdb->tdb);
}

static size_t db_ctdb_id(struct db_context *db, uint8_t *id, size_t idlen)
{
	struct db_ctdb_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_ctdb_ctx);

	if (idlen >= sizeof(ctx->db_id)) {
		memcpy(id, &ctx->db_id, sizeof(ctx->db_id));
	}

	return sizeof(ctx->db_id);
}

static int wipe_delete_fn(struct db_record *rec, void *private_data)
{
	NTSTATUS status;

	/*
	 * Avoid deleting the persistent backup record
	 */
	rec->flags.persistent = false;

	status = rec->delete_rec(rec);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}
	return 0;
}

static NTSTATUS wipe_trans_fn(struct db_context *db, void *private_data)
{
	int ret;

	ret = db_ctdb_traverse(db, wipe_delete_fn, NULL);
	if (ret == -1) {
		return NT_STATUS_INTERNAL_DB_ERROR;
	}
	return NT_STATUS_OK;
}

static int db_ctdb_wipe(struct db_context *db,
			struct dbwrap_wipe_flags flags)
{
	struct db_ctdb_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_ctdb_ctx);
	NTSTATUS status;
	int ret;

	if (flags.wipe_persistent_backup_db) {
		if (!(db->flags & DBWRAP_FLAG_PER_REC_PERSISTENT)) {
			return 0;
		}

		status = dbwrap_trans_do(ctx->pdb, wipe_trans_fn, NULL);
		if (!NT_STATUS_IS_OK(status)) {
			return -1;
		}
	}

	if (flags.wipe_default) {
		if (db->persistent) {
			status = dbwrap_trans_do(db, wipe_trans_fn, NULL);
			if (!NT_STATUS_IS_OK(status)) {
				return -1;
			}
			return 0;
		}

		ret = db_ctdb_traverse_internal(db, wipe_delete_fn, false, NULL);
		if (ret == -1) {
			return -1;
		}
	}
	return 0;
}

struct migrate_persistent_state {
	struct db_ctdb_ctx *db_ctdb_ctx;
};

static int migrate_persistent_traverse_fn(struct tdb_context *ctdb,
					  TDB_DATA key,
					  TDB_DATA data,
					  void *private_data)
{
	struct migrate_persistent_state *state =
		(struct migrate_persistent_state *)private_data;
	struct db_record *rec = NULL;
	struct db_ctdb_rec *crec = NULL;
	struct ctdb_ltdb_header header;
	TDB_DATA d;
	int cmp;
	NTSTATUS status;
	int ret;

	if (key.dsize == strlen(CTDB_DB_SEQNUM_KEY) + 1) {
		cmp = strncmp(CTDB_DB_SEQNUM_KEY,
			      (char *)key.dptr,
			      key.dsize);
		if (cmp == 0) {
			return 0;
		}
	}

	if (data.dsize <= sizeof(struct ctdb_ltdb_header)) {
		/* A deleted record */
		return 0;
	}

	rec = fetch_locked_internal(state->db_ctdb_ctx, state->db_ctdb_ctx, key);
	if (rec == NULL) {
		DBG_ERR("db_tdb_fetch_locked() failed\n");
		ret = -1;
		goto out;
	}
	crec = talloc_get_type_abort(rec->private_data, struct db_ctdb_rec);

	d = (TDB_DATA) {
		.dptr = data.dptr + sizeof(struct ctdb_ltdb_header),
		.dsize = data.dsize - sizeof(struct ctdb_ltdb_header)
	};

	crec->header.flags |= CTDB_REC_FLAG_PERSISTENT;
	header = crec->header;
	prepare_local_header_for_push_record(&header);

	status = db_ctdb_ltdb_store(state->db_ctdb_ctx,
				    key,
				    &header,
				    &d,
				    1);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("db_ctdb_ltdb_store failed: %s\n", nt_errstr(status));
		ret = -1;
		goto out;
	}

	status = db_ctdb_push_record(rec, &d, 1);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("db_ctdb_push_record failed: %s\n", nt_errstr(status));
		ret = -1;
		goto out;
	}

	ret = 0;
out:
	TALLOC_FREE(rec);
	return ret;
}

static int db_ctdb_migrate_persistent_recs(struct db_context *db,
					   struct messaging_context *msg)
{
	struct db_ctdb_ctx *db_ctdb_ctx = talloc_get_type_abort(
		db->private_data, struct db_ctdb_ctx);
	struct db_ctdb_ctx *pdb_ctdb_ctx = talloc_get_type_abort(
		db_ctdb_ctx->pdb->private_data, struct db_ctdb_ctx);
	struct server_id id = messaging_server_id(msg);
	uint8_t idbuf[SERVER_ID_BUF_LENGTH];
	struct migrate_persistent_state migration_state;
	struct db_record *marker_rec = NULL;
	struct db_ctdb_rec *crec = NULL;
	struct ctdb_ltdb_header header;
	TDB_DATA marker_key;
	TDB_DATA marker_val;
	char *curtime = NULL;
	NTSTATUS status;
	int ret;

	/*
	 * First let's check if the volatile db was cleared by
	 * clear-if-first. That would imply an smbd or cluster restart, so we
	 * have to trigger migration of records from the persistent db back to
	 * the volatile db.
	 */
	marker_key = string_term_tdb_data(
		DBWRAP_PERSISTENT_MIGRATION_MARKER_KEY);

	marker_rec = fetch_locked_internal(db_ctdb_ctx,
					   db_ctdb_ctx,
					   marker_key);
	if (marker_rec == NULL) {
		DBG_ERR("db_tdb_fetch_locked() failed\n");
		ret = -1;
		goto out;
	}

	marker_val = dbwrap_record_get_value(marker_rec);
	if (marker_val.dptr != NULL) {
		DBG_DEBUG("db [%s] already migrated at %s\n",
			  db->name, marker_val.dptr);
		TALLOC_FREE(marker_rec);

		ret = 0;
		goto out;
	}

	server_id_put(idbuf, id);
	marker_val = (TDB_DATA) {
		.dptr = idbuf,
		.dsize = SERVER_ID_BUF_LENGTH,
	};
	crec = talloc_get_type_abort(marker_rec->private_data,
				     struct db_ctdb_rec);
	crec->header.flags |= CTDB_REC_FLAG_PERSISTENT_IN_PROGRESS;

	status = db_ctdb_ltdb_store(db_ctdb_ctx,
				    marker_key,
				    &crec->header,
				    &marker_val,
				    1);
	if (!NT_STATUS_IS_OK(status)) {
		ret = -1;
		goto out;
	}

	TALLOC_FREE(marker_rec);

	migration_state = (struct migrate_persistent_state) {
		.db_ctdb_ctx = db_ctdb_ctx,
	};

	ret = tdb_traverse_read(pdb_ctdb_ctx->wtdb->tdb,
				migrate_persistent_traverse_fn,
				&migration_state);
	if (ret == -1) {
		DBG_ERR("tdb_traverse_read failed\n");
		goto out;
	}

	DBG_INFO("Migrated %d records of db [%s]\n", ret, db->name);

	marker_rec = fetch_locked_internal(db_ctdb_ctx,
					   db_ctdb_ctx,
					   marker_key);
	if (marker_rec == NULL) {
		DBG_ERR("db_tdb_fetch_locked() failed\n");
		ret = -1;
		goto out;
	}

	curtime = current_timestring(marker_rec, false);
	if (curtime == NULL) {
		ret = -1;
		goto out;
	}
	marker_val = string_term_tdb_data(curtime);

	crec = talloc_get_type_abort(marker_rec->private_data,
				     struct db_ctdb_rec);

	header = crec->header;
	prepare_local_header_for_push_record(&header);
	header.flags &= ~CTDB_REC_FLAG_PERSISTENT_IN_PROGRESS;

	status = db_ctdb_ltdb_store(db_ctdb_ctx,
				    marker_key,
				    &header,
				    &marker_val,
				    1);
	if (!NT_STATUS_IS_OK(status)) {
		ret = -1;
		goto out;
	}

	status = db_ctdb_push_record(marker_rec, &marker_val, 1);
	if (!NT_STATUS_IS_OK(status)) {
		ret = -1;
		goto out;
	}

	ret = 0;

out:
	TALLOC_FREE(marker_rec);
	return ret;
}

static NTSTATUS db_ctdb_open_per_rec_persistent_db(
	struct db_context *db,
	struct messaging_context *msg_ctx,
	int hash_size,
	int tdb_flags,
	int open_flags,
	mode_t mode,
	enum dbwrap_lock_order lock_order,
	uint64_t dbwrap_flags)
{
	struct db_ctdb_ctx *db_ctx = talloc_get_type_abort(
		db->private_data, struct db_ctdb_ctx);
	char *tmpname = NULL;
	char *dot = NULL;
	char *persistent_name = NULL;
	int ptdb_flags;
	int ret;

	if (!(dbwrap_flags & DBWRAP_FLAG_PER_REC_PERSISTENT)) {
		return NT_STATUS_OK;
	}

	if (db->persistent) {
		DBG_WARNING("DBWRAP_FLAG_PER_REC_PERSISTENT only allowed with "
			    "TDB_CLEAR_IF_FIRST\n");
		return NT_STATUS_INTERNAL_ERROR;
	}

	ptdb_flags = tdb_flags & ~(TDB_CLEAR_IF_FIRST | TDB_MUTEX_LOCKING);
	dbwrap_flags &= ~DBWRAP_FLAG_PER_REC_PERSISTENT;

	tmpname = talloc_strdup(db_ctx, db->name);
	if (tmpname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	dot = strrchr(tmpname, '.');
	if (dot != NULL) {
		*dot = '\0';
	}
	persistent_name = talloc_asprintf(db,
					  "%s_persistent.tdb",
					  tmpname);
	TALLOC_FREE(tmpname);
	if (persistent_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	db_ctx->pdb = db_open_ctdb(db_ctx,
				   msg_ctx,
				   persistent_name,
				   hash_size,
				   ptdb_flags,
				   open_flags,
				   mode,
				   lock_order,
				   dbwrap_flags);
	TALLOC_FREE(persistent_name);
	if (db_ctx->pdb == NULL) {
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	db->traverse_per_rec_persistent_read =
		db_ctdb_traverse_per_rec_persistent_read;

	if ((open_flags & O_ACCMODE) != O_RDWR) {
		return NT_STATUS_OK;
	}

	ret = db_ctdb_migrate_persistent_recs(db, msg_ctx);
	if (ret != 0) {
		DBG_ERR("Record migration in db %s failed\n", db->name);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	return NT_STATUS_OK;
}

struct db_context *db_open_ctdb(TALLOC_CTX *mem_ctx,
				struct messaging_context *msg_ctx,
				const char *name,
				int hash_size, int tdb_flags,
				int open_flags, mode_t mode,
				enum dbwrap_lock_order lock_order,
				uint64_t dbwrap_flags)
{
	struct db_context *result;
	struct db_ctdb_ctx *db_ctdb;
	char *db_path;
	struct loadparm_context *lp_ctx;
	TDB_DATA data;
	TDB_DATA outdata = {0};
	bool persistent = (tdb_flags & TDB_CLEAR_IF_FIRST) == 0;
	int32_t cstatus;
	NTSTATUS status;
	int ret;

	if (!lp_clustering()) {
		DEBUG(10, ("Clustering disabled -- no ctdb\n"));
		return NULL;
	}

	if (!(result = talloc_zero(mem_ctx, struct db_context))) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(result);
		return NULL;
	}

	if (!(db_ctdb = talloc(result, struct db_ctdb_ctx))) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(result);
		return NULL;
	}

	result->name = talloc_strdup(result, name);
	if (result->name == NULL) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(result);
		return NULL;
	}

	db_ctdb->transaction = NULL;
	db_ctdb->db = result;

	ret = ctdbd_db_attach(messaging_ctdb_connection(), name,
			      &db_ctdb->db_id, persistent);
	if (ret != 0) {
		DEBUG(0, ("ctdbd_db_attach failed for %s: %s\n", name,
			  strerror(ret)));
		TALLOC_FREE(result);
		return NULL;
	}

	if (tdb_flags & TDB_SEQNUM) {
		data.dptr = (uint8_t *)&db_ctdb->db_id;
		data.dsize = sizeof(db_ctdb->db_id);

		ret = ctdbd_control_local(messaging_ctdb_connection(),
					  CTDB_CONTROL_ENABLE_SEQNUM,
					  0, 0, data,
					  NULL, NULL, &cstatus);
		if ((ret != 0) || cstatus != 0) {
			DBG_ERR("ctdb_control for enable seqnum "
				"failed: %s\n", strerror(ret));
			TALLOC_FREE(result);
			return NULL;
		}
	}

	db_path = ctdbd_dbpath(messaging_ctdb_connection(), db_ctdb,
			       db_ctdb->db_id);
	if (db_path == NULL) {
		DBG_ERR("ctdbd_dbpath failed\n");
		TALLOC_FREE(result);
		return NULL;
	}

	result->persistent = persistent;
	result->lock_order = lock_order;

	data.dptr = (uint8_t *)&db_ctdb->db_id;
	data.dsize = sizeof(db_ctdb->db_id);

	ret = ctdbd_control_local(messaging_ctdb_connection(),
				  CTDB_CONTROL_DB_OPEN_FLAGS,
				  0, 0, data, NULL, &outdata, &cstatus);
	if (ret != 0) {
		DBG_ERR(" ctdb control for db_open_flags "
			 "failed: %s\n", strerror(ret));
		TALLOC_FREE(result);
		return NULL;
	}

	if (cstatus != 0 || outdata.dsize != sizeof(int)) {
		DBG_ERR("ctdb_control for db_open_flags failed\n");
		TALLOC_FREE(outdata.dptr);
		TALLOC_FREE(result);
		return NULL;
	}

	tdb_flags = *(int *)outdata.dptr;
	TALLOC_FREE(outdata.dptr);

	if (!result->persistent) {
		ret = ctdb_async_ctx_init(NULL, messaging_tevent_context(msg_ctx));
		if (ret != 0) {
			DBG_ERR("ctdb_async_ctx_init failed: %s\n", strerror(ret));
			TALLOC_FREE(result);
			return NULL;
		}
	}

	if (dbwrap_flags & DBWRAP_FLAG_PER_REC_PERSISTENT) {
		/*
		 * TODO: check compatibility of using push-record with read-only
		 * copies. For now disable read-only records.
		 */
		dbwrap_flags &= ~DBWRAP_FLAG_OPTIMIZE_READONLY_ACCESS;
	}

	if (!result->persistent &&
	    (dbwrap_flags & DBWRAP_FLAG_OPTIMIZE_READONLY_ACCESS))
	{
		TDB_DATA indata;

		indata = make_tdb_data((uint8_t *)&db_ctdb->db_id,
				       sizeof(db_ctdb->db_id));

		ret = ctdbd_control_local(
			messaging_ctdb_connection(),
			CTDB_CONTROL_SET_DB_READONLY, 0, 0,
			indata, NULL, NULL, &cstatus);
		if ((ret != 0) || (cstatus != 0)) {
			DEBUG(1, ("CTDB_CONTROL_SET_DB_READONLY failed: "
				  "%s, %"PRIi32"\n", strerror(ret), cstatus));
			TALLOC_FREE(result);
			return NULL;
		}
	}

	lp_ctx = loadparm_init_s3(db_path, loadparm_s3_helpers());

	if (hash_size == 0) {
		hash_size = lpcfg_tdb_hash_size(lp_ctx, db_path);
	}

	db_ctdb->wtdb = tdb_wrap_open(db_ctdb, db_path, hash_size,
				      lpcfg_tdb_flags(lp_ctx, tdb_flags),
				      O_RDWR, 0);
	talloc_unlink(db_path, lp_ctx);
	if (db_ctdb->wtdb == NULL) {
		DEBUG(0, ("Could not open tdb %s: %s\n", db_path, strerror(errno)));
		TALLOC_FREE(result);
		return NULL;
	}
	talloc_free(db_path);

	/* honor permissions if user has specified O_CREAT */
	if (open_flags & O_CREAT) {
		int fd;
		fd = tdb_fd(db_ctdb->wtdb->tdb);
		ret = fchmod(fd, mode);
		if (ret == -1) {
			DBG_WARNING("fchmod failed: %s\n",
				    strerror(errno));
			TALLOC_FREE(result);
			return NULL;
		}
	}

	if (result->persistent) {
		db_ctdb->lock_ctx = g_lock_ctx_init(db_ctdb, msg_ctx);
		if (db_ctdb->lock_ctx == NULL) {
			DEBUG(0, ("g_lock_ctx_init failed\n"));
			TALLOC_FREE(result);
			return NULL;
		}
	}

	db_ctdb->warn_unlock_msecs = lp_parm_int(-1, "ctdb",
						 "unlock_warn_threshold", 5);
	db_ctdb->warn_migrate_attempts = lp_parm_int(-1, "ctdb",
						     "migrate_attempts", 10);
	db_ctdb->warn_migrate_msecs = lp_parm_int(-1, "ctdb",
						  "migrate_duration", 5000);
	db_ctdb->warn_locktime_msecs = lp_ctdb_locktime_warn_threshold();

	result->private_data = (void *)db_ctdb;
	result->fetch_locked = db_ctdb_fetch_locked;
	result->parse_record = db_ctdb_parse_record;
	result->parse_record_send = db_ctdb_parse_record_send;
	result->parse_record_recv = db_ctdb_parse_record_recv;
	result->traverse = db_ctdb_traverse;
	result->traverse_read = db_ctdb_traverse_read;
	result->get_seqnum = db_ctdb_get_seqnum;
	result->transaction_start = db_ctdb_transaction_start;
	result->transaction_commit = db_ctdb_transaction_commit;
	result->transaction_cancel = db_ctdb_transaction_cancel;
	result->wipe = db_ctdb_wipe;
	result->id = db_ctdb_id;
	result->flags = dbwrap_flags;

	DEBUG(3,("db_open_ctdb: opened database '%s' with dbid 0x%x\n",
		 name, db_ctdb->db_id));

	status = db_ctdb_open_per_rec_persistent_db(result,
						    msg_ctx,
						    hash_size,
						    tdb_flags,
						    open_flags,
						    mode,
						    lock_order,
						    dbwrap_flags);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	return result;

fail:
	TALLOC_FREE(result);
	return NULL;
}
