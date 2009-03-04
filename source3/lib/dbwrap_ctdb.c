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

struct db_ctdb_transaction_handle {
	struct db_ctdb_ctx *ctx;
	bool in_replay;
	/* we store the reads and writes done under a transaction one
	   list stores both reads and writes, the other just writes
	*/
	struct ctdb_marshall_buffer *m_all;
	struct ctdb_marshall_buffer *m_write;
	uint32_t nesting;
	bool nested_cancel;
};

struct db_ctdb_ctx {
	struct db_context *db;
	struct tdb_wrap *wtdb;
	uint32 db_id;
	struct db_ctdb_transaction_handle *transaction;
};

struct db_ctdb_rec {
	struct db_ctdb_ctx *ctdb_ctx;
	struct ctdb_ltdb_header header;
};

static struct db_record *fetch_locked_internal(struct db_ctdb_ctx *ctx,
					       TALLOC_CTX *mem_ctx,
					       TDB_DATA key,
					       bool persistent);

static NTSTATUS tdb_error_to_ntstatus(struct tdb_context *tdb)
{
	NTSTATUS status;
	enum TDB_ERROR tret = tdb_error(tdb);

	switch (tret) {
	case TDB_ERR_EXISTS:
		status = NT_STATUS_OBJECT_NAME_COLLISION;
		break;
	case TDB_ERR_NOEXIST:
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		break;
	default:
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		break;
	}

	return status;
}



/*
  form a ctdb_rec_data record from a key/data pair

  note that header may be NULL. If not NULL then it is included in the data portion
  of the record
 */
static struct ctdb_rec_data *db_ctdb_marshall_record(TALLOC_CTX *mem_ctx, uint32_t reqid,	
						  TDB_DATA key, 
						  struct ctdb_ltdb_header *header,
						  TDB_DATA data)
{
	size_t length;
	struct ctdb_rec_data *d;

	length = offsetof(struct ctdb_rec_data, data) + key.dsize + 
		data.dsize + (header?sizeof(*header):0);
	d = (struct ctdb_rec_data *)talloc_size(mem_ctx, length);
	if (d == NULL) {
		return NULL;
	}
	d->length = length;
	d->reqid = reqid;
	d->keylen = key.dsize;
	memcpy(&d->data[0], key.dptr, key.dsize);
	if (header) {
		d->datalen = data.dsize + sizeof(*header);
		memcpy(&d->data[key.dsize], header, sizeof(*header));
		memcpy(&d->data[key.dsize+sizeof(*header)], data.dptr, data.dsize);
	} else {
		d->datalen = data.dsize;
		memcpy(&d->data[key.dsize], data.dptr, data.dsize);
	}
	return d;
}


/* helper function for marshalling multiple records */
static struct ctdb_marshall_buffer *db_ctdb_marshall_add(TALLOC_CTX *mem_ctx, 
					       struct ctdb_marshall_buffer *m,
					       uint64_t db_id,
					       uint32_t reqid,
					       TDB_DATA key,
					       struct ctdb_ltdb_header *header,
					       TDB_DATA data)
{
	struct ctdb_rec_data *r;
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
static struct ctdb_rec_data *db_ctdb_marshall_loop_next(struct ctdb_marshall_buffer *m, struct ctdb_rec_data *r,
						     uint32_t *reqid,
						     struct ctdb_ltdb_header *header,
						     TDB_DATA *key, TDB_DATA *data)
{
	if (r == NULL) {
		r = (struct ctdb_rec_data *)&m->data[0];
	} else {
		r = (struct ctdb_rec_data *)(r->length + (uint8_t *)r);
	}

	if (reqid != NULL) {
		*reqid = r->reqid;
	}

	if (key != NULL) {
		key->dptr   = &r->data[0];
		key->dsize  = r->keylen;
	}
	if (data != NULL) {
		data->dptr  = &r->data[r->keylen];
		data->dsize = r->datalen;
		if (header != NULL) {
			data->dptr += sizeof(*header);
			data->dsize -= sizeof(*header);
		}
	}

	if (header != NULL) {
		if (r->datalen < sizeof(*header)) {
			return NULL;
		}
		*header = *(struct ctdb_ltdb_header *)&r->data[r->keylen];
	}

	return r;
}



/* start a transaction on a database */
static int db_ctdb_transaction_destructor(struct db_ctdb_transaction_handle *h)
{
	tdb_transaction_cancel(h->ctx->wtdb->tdb);
	return 0;
}

/* start a transaction on a database */
static int db_ctdb_transaction_fetch_start(struct db_ctdb_transaction_handle *h)
{
	struct db_record *rh;
	TDB_DATA key;
	TALLOC_CTX *tmp_ctx;
	const char *keyname = CTDB_TRANSACTION_LOCK_KEY;
	int ret;
	struct db_ctdb_ctx *ctx = h->ctx;
	TDB_DATA data;

	key.dptr = (uint8_t *)discard_const(keyname);
	key.dsize = strlen(keyname);

again:
	tmp_ctx = talloc_new(h);

	rh = fetch_locked_internal(ctx, tmp_ctx, key, true);
	if (rh == NULL) {
		DEBUG(0,(__location__ " Failed to fetch_lock database\n"));		
		talloc_free(tmp_ctx);
		return -1;
	}
	talloc_free(rh);

	ret = tdb_transaction_start(ctx->wtdb->tdb);
	if (ret != 0) {
		DEBUG(0,(__location__ " Failed to start tdb transaction\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	data = tdb_fetch(ctx->wtdb->tdb, key);
	if ((data.dptr == NULL) ||
	    (data.dsize < sizeof(struct ctdb_ltdb_header)) ||
	    ((struct ctdb_ltdb_header *)data.dptr)->dmaster != get_my_vnn()) {
		SAFE_FREE(data.dptr);
		tdb_transaction_cancel(ctx->wtdb->tdb);
		talloc_free(tmp_ctx);
		goto again;
	}

	SAFE_FREE(data.dptr);
	talloc_free(tmp_ctx);

	return 0;
}


/* start a transaction on a database */
static int db_ctdb_transaction_start(struct db_context *db)
{
	struct db_ctdb_transaction_handle *h;
	int ret;
	struct db_ctdb_ctx *ctx = talloc_get_type_abort(db->private_data,
							struct db_ctdb_ctx);

	if (!db->persistent) {
		DEBUG(0,("transactions not supported on non-persistent database 0x%08x\n", 
			 ctx->db_id));
		return -1;
	}

	if (ctx->transaction) {
		ctx->transaction->nesting++;
		return 0;
	}

	h = talloc_zero(db, struct db_ctdb_transaction_handle);
	if (h == NULL) {
		DEBUG(0,(__location__ " oom for transaction handle\n"));		
		return -1;
	}

	h->ctx = ctx;

	ret = db_ctdb_transaction_fetch_start(h);
	if (ret != 0) {
		talloc_free(h);
		return -1;
	}

	talloc_set_destructor(h, db_ctdb_transaction_destructor);

	ctx->transaction = h;

	DEBUG(5,(__location__ " Started transaction on db 0x%08x\n", ctx->db_id));

	return 0;
}



/*
  fetch a record inside a transaction
 */
static int db_ctdb_transaction_fetch(struct db_ctdb_ctx *db, 
				     TALLOC_CTX *mem_ctx, 
				     TDB_DATA key, TDB_DATA *data)
{
	struct db_ctdb_transaction_handle *h = db->transaction;

	*data = tdb_fetch(h->ctx->wtdb->tdb, key);

	if (data->dptr != NULL) {
		uint8_t *oldptr = (uint8_t *)data->dptr;
		data->dsize -= sizeof(struct ctdb_ltdb_header);
		if (data->dsize == 0) {
			data->dptr = NULL;
		} else {
			data->dptr = (uint8 *)
				talloc_memdup(
					mem_ctx, data->dptr+sizeof(struct ctdb_ltdb_header),
					data->dsize);
		}
		SAFE_FREE(oldptr);
		if (data->dptr == NULL && data->dsize != 0) {
			return -1;
		}
	}

	if (!h->in_replay) {
		h->m_all = db_ctdb_marshall_add(h, h->m_all, h->ctx->db_id, 1, key, NULL, *data);
		if (h->m_all == NULL) {
			DEBUG(0,(__location__ " Failed to add to marshalling record\n"));
			data->dsize = 0;
			talloc_free(data->dptr);
			return -1;
		}
	}

	return 0;
}


static NTSTATUS db_ctdb_store_transaction(struct db_record *rec, TDB_DATA data, int flag);
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

	result->private_data = ctx->transaction;

	result->key.dsize = key.dsize;
	result->key.dptr = (uint8 *)talloc_memdup(result, key.dptr, key.dsize);
	if (result->key.dptr == NULL) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(result);
		return NULL;
	}

	result->store = db_ctdb_store_transaction;
	result->delete_rec = db_ctdb_delete_transaction;

	ctdb_data = tdb_fetch(ctx->wtdb->tdb, key);
	if (ctdb_data.dptr == NULL) {
		/* create the record */
		result->value = tdb_null;
		return result;
	}

	result->value.dsize = ctdb_data.dsize - sizeof(struct ctdb_ltdb_header);
	result->value.dptr = NULL;

	if ((result->value.dsize != 0)
	    && !(result->value.dptr = (uint8 *)talloc_memdup(
			 result, ctdb_data.dptr + sizeof(struct ctdb_ltdb_header),
			 result->value.dsize))) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(result);
	}

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
static int db_ctdb_transaction_store(struct db_ctdb_transaction_handle *h, 
				     TDB_DATA key, TDB_DATA data)
{
	TALLOC_CTX *tmp_ctx = talloc_new(h);
	int ret;
	TDB_DATA rec;
	struct ctdb_ltdb_header header;

	/* we need the header so we can update the RSN */
	rec = tdb_fetch(h->ctx->wtdb->tdb, key);
	if (rec.dptr == NULL) {
		/* the record doesn't exist - create one with us as dmaster.
		   This is only safe because we are in a transaction and this
		   is a persistent database */
		ZERO_STRUCT(header);
		header.dmaster = get_my_vnn();
	} else {
		memcpy(&header, rec.dptr, sizeof(struct ctdb_ltdb_header));
		rec.dsize -= sizeof(struct ctdb_ltdb_header);
		/* a special case, we are writing the same data that is there now */
		if (data.dsize == rec.dsize &&
		    memcmp(data.dptr, rec.dptr + sizeof(struct ctdb_ltdb_header), data.dsize) == 0) {
			SAFE_FREE(rec.dptr);
			talloc_free(tmp_ctx);
			return 0;
		}
		SAFE_FREE(rec.dptr);
	}

	header.rsn++;

	if (!h->in_replay) {
		h->m_all = db_ctdb_marshall_add(h, h->m_all, h->ctx->db_id, 0, key, NULL, data);
		if (h->m_all == NULL) {
			DEBUG(0,(__location__ " Failed to add to marshalling record\n"));
			talloc_free(tmp_ctx);
			return -1;
		}
	}

	h->m_write = db_ctdb_marshall_add(h, h->m_write, h->ctx->db_id, 0, key, &header, data);
	if (h->m_write == NULL) {
		DEBUG(0,(__location__ " Failed to add to marshalling record\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	rec.dsize = data.dsize + sizeof(struct ctdb_ltdb_header);
	rec.dptr = (uint8_t *)talloc_size(tmp_ctx, rec.dsize);
	if (rec.dptr == NULL) {
		DEBUG(0,(__location__ " Failed to alloc record\n"));
		talloc_free(tmp_ctx);
		return -1;
	}
	memcpy(rec.dptr, &header, sizeof(struct ctdb_ltdb_header));
	memcpy(sizeof(struct ctdb_ltdb_header) + (uint8_t *)rec.dptr, data.dptr, data.dsize);

	ret = tdb_store(h->ctx->wtdb->tdb, key, rec, TDB_REPLACE);

	talloc_free(tmp_ctx);

	return ret;
}


/* 
   a record store inside a transaction
 */
static NTSTATUS db_ctdb_store_transaction(struct db_record *rec, TDB_DATA data, int flag)
{
	struct db_ctdb_transaction_handle *h = talloc_get_type_abort(
		rec->private_data, struct db_ctdb_transaction_handle);
	int ret;

	ret = db_ctdb_transaction_store(h, rec->key, data);
	if (ret != 0) {
		return tdb_error_to_ntstatus(h->ctx->wtdb->tdb);
	}
	return NT_STATUS_OK;
}

/* 
   a record delete inside a transaction
 */
static NTSTATUS db_ctdb_delete_transaction(struct db_record *rec)
{
	struct db_ctdb_transaction_handle *h = talloc_get_type_abort(
		rec->private_data, struct db_ctdb_transaction_handle);
	int ret;

	ret = db_ctdb_transaction_store(h, rec->key, tdb_null);
	if (ret != 0) {
		return tdb_error_to_ntstatus(h->ctx->wtdb->tdb);
	}
	return NT_STATUS_OK;
}


/*
  replay a transaction
 */
static int ctdb_replay_transaction(struct db_ctdb_transaction_handle *h)
{
	int ret, i;
	struct ctdb_rec_data *rec = NULL;

	h->in_replay = true;
	talloc_free(h->m_write);
	h->m_write = NULL;

	ret = db_ctdb_transaction_fetch_start(h);
	if (ret != 0) {
		return ret;
	}

	for (i=0;i<h->m_all->count;i++) {
		TDB_DATA key, data;

		rec = db_ctdb_marshall_loop_next(h->m_all, rec, NULL, NULL, &key, &data);
		if (rec == NULL) {
			DEBUG(0, (__location__ " Out of records in ctdb_replay_transaction?\n"));
			goto failed;
		}

		if (rec->reqid == 0) {
			/* its a store */
			if (db_ctdb_transaction_store(h, key, data) != 0) {
				goto failed;
			}
		} else {
			TDB_DATA data2;
			TALLOC_CTX *tmp_ctx = talloc_new(h);

			if (db_ctdb_transaction_fetch(h->ctx, tmp_ctx, key, &data2) != 0) {
				talloc_free(tmp_ctx);
				goto failed;
			}
			if (data2.dsize != data.dsize ||
			    memcmp(data2.dptr, data.dptr, data.dsize) != 0) {
				/* the record has changed on us - we have to give up */
				talloc_free(tmp_ctx);
				goto failed;
			}
			talloc_free(tmp_ctx);
		}
	}

	return 0;

failed:
	tdb_transaction_cancel(h->ctx->wtdb->tdb);
	return -1;
}


/*
  commit a transaction
 */
static int db_ctdb_transaction_commit(struct db_context *db)
{
	struct db_ctdb_ctx *ctx = talloc_get_type_abort(db->private_data,
							struct db_ctdb_ctx);
	NTSTATUS rets;
	int ret;
	int status;
	int retries = 0;
	struct db_ctdb_transaction_handle *h = ctx->transaction;
	enum ctdb_controls failure_control = CTDB_CONTROL_TRANS2_ERROR;

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
		return 0;
	}

	DEBUG(5,(__location__ " Commit transaction on db 0x%08x\n", ctx->db_id));

	talloc_set_destructor(h, NULL);

	/* our commit strategy is quite complex.

	   - we first try to commit the changes to all other nodes

	   - if that works, then we commit locally and we are done

	   - if a commit on another node fails, then we need to cancel
	     the transaction, then restart the transaction (thus
	     opening a window of time for a pending recovery to
	     complete), then replay the transaction, checking all the
	     reads and writes (checking that reads give the same data,
	     and writes succeed). Then we retry the transaction to the
	     other nodes
	*/

again:
	if (h->m_write == NULL) {
		/* no changes were made, potentially after a retry */
		tdb_transaction_cancel(h->ctx->wtdb->tdb);
		talloc_free(h);
		ctx->transaction = NULL;
		return 0;
	}

	/* tell ctdbd to commit to the other nodes */
	rets = ctdbd_control_local(messaging_ctdbd_connection(), 
				   retries==0?CTDB_CONTROL_TRANS2_COMMIT:CTDB_CONTROL_TRANS2_COMMIT_RETRY, 
				   h->ctx->db_id, 0,
				   db_ctdb_marshall_finish(h->m_write), NULL, NULL, &status);
	if (!NT_STATUS_IS_OK(rets) || status != 0) {
		tdb_transaction_cancel(h->ctx->wtdb->tdb);
		sleep(1);

		if (!NT_STATUS_IS_OK(rets)) {
			failure_control = CTDB_CONTROL_TRANS2_ERROR;			
		} else {
			/* work out what error code we will give if we 
			   have to fail the operation */
			switch ((enum ctdb_trans2_commit_error)status) {
			case CTDB_TRANS2_COMMIT_SUCCESS:
			case CTDB_TRANS2_COMMIT_SOMEFAIL:
			case CTDB_TRANS2_COMMIT_TIMEOUT:
				failure_control = CTDB_CONTROL_TRANS2_ERROR;
				break;
			case CTDB_TRANS2_COMMIT_ALLFAIL:
				failure_control = CTDB_CONTROL_TRANS2_FINISHED;
				break;
			}
		}

		if (++retries == 5) {
			DEBUG(0,(__location__ " Giving up transaction on db 0x%08x after %d retries failure_control=%u\n", 
				 h->ctx->db_id, retries, (unsigned)failure_control));
			ctdbd_control_local(messaging_ctdbd_connection(), failure_control,
					    h->ctx->db_id, CTDB_CTRL_FLAG_NOREPLY, 
					    tdb_null, NULL, NULL, NULL);
			h->ctx->transaction = NULL;
			talloc_free(h);
			ctx->transaction = NULL;
			return -1;			
		}

		if (ctdb_replay_transaction(h) != 0) {
			DEBUG(0,(__location__ " Failed to replay transaction failure_control=%u\n",
				 (unsigned)failure_control));
			ctdbd_control_local(messaging_ctdbd_connection(), failure_control,
					    h->ctx->db_id, CTDB_CTRL_FLAG_NOREPLY, 
					    tdb_null, NULL, NULL, NULL);
			h->ctx->transaction = NULL;
			talloc_free(h);
			ctx->transaction = NULL;
			return -1;
		}
		goto again;
	} else {
		failure_control = CTDB_CONTROL_TRANS2_ERROR;
	}

	/* do the real commit locally */
	ret = tdb_transaction_commit(h->ctx->wtdb->tdb);
	if (ret != 0) {
		DEBUG(0,(__location__ " Failed to commit transaction failure_control=%u\n",
			 (unsigned)failure_control));
		ctdbd_control_local(messaging_ctdbd_connection(), failure_control, h->ctx->db_id, 
				    CTDB_CTRL_FLAG_NOREPLY, tdb_null, NULL, NULL, NULL);
		h->ctx->transaction = NULL;
		talloc_free(h);
		return ret;
	}

	/* tell ctdbd that we are finished with our local commit */
	ctdbd_control_local(messaging_ctdbd_connection(), CTDB_CONTROL_TRANS2_FINISHED, 
			    h->ctx->db_id, CTDB_CTRL_FLAG_NOREPLY, 
			    tdb_null, NULL, NULL, NULL);
	h->ctx->transaction = NULL;
	talloc_free(h);
	return 0;
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
		return 0;
	}

	DEBUG(5,(__location__ " Cancel transaction on db 0x%08x\n", ctx->db_id));

	ctx->transaction = NULL;
	talloc_free(h);
	return 0;
}


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

	return (ret == 0) ? NT_STATUS_OK
			  : tdb_error_to_ntstatus(crec->ctdb_ctx->wtdb->tdb);
}



static NTSTATUS db_ctdb_delete(struct db_record *rec)
{
	TDB_DATA data;

	/*
	 * We have to store the header with empty data. TODO: Fix the
	 * tdb-level cleanup
	 */

	ZERO_STRUCT(data);

	return db_ctdb_store(rec, data, 0);

}

static int db_ctdb_record_destr(struct db_record* data)
{
	struct db_ctdb_rec *crec = talloc_get_type_abort(
		data->private_data, struct db_ctdb_rec);

	DEBUG(10, (DEBUGLEVEL > 10
		   ? "Unlocking db %u key %s\n"
		   : "Unlocking db %u key %.20s\n",
		   (int)crec->ctdb_ctx->db_id,
		   hex_encode_talloc(data, (unsigned char *)data->key.dptr,
			      data->key.dsize)));

	if (tdb_chainunlock(crec->ctdb_ctx->wtdb->tdb, data->key) != 0) {
		DEBUG(0, ("tdb_chainunlock failed\n"));
		return -1;
	}

	return 0;
}

static struct db_record *fetch_locked_internal(struct db_ctdb_ctx *ctx,
					       TALLOC_CTX *mem_ctx,
					       TDB_DATA key,
					       bool persistent)
{
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
		char *keystr = hex_encode_talloc(result, key.dptr, key.dsize);
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

	result->store = db_ctdb_store;
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

	return fetch_locked_internal(ctx, mem_ctx, key, db->persistent);
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

	if (ctx->transaction) {
		return db_ctdb_transaction_fetch(ctx, mem_ctx, key, data);
	}

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

static int db_ctdb_get_flags(struct db_context *db)
{
        struct db_ctdb_ctx *ctx = talloc_get_type_abort(db->private_data,
                                                        struct db_ctdb_ctx);
	return tdb_get_flags(ctx->wtdb->tdb);
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

	db_ctdb->transaction = NULL;
	db_ctdb->db = result;

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
	result->get_flags = db_ctdb_get_flags;
	result->transaction_start = db_ctdb_transaction_start;
	result->transaction_commit = db_ctdb_transaction_commit;
	result->transaction_cancel = db_ctdb_transaction_cancel;

	DEBUG(3,("db_open_ctdb: opened database '%s' with dbid 0x%x\n",
		 name, db_ctdb->db_id));

	return result;
}
#endif
