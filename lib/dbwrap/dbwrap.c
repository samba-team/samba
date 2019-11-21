/*
   Unix SMB/CIFS implementation.
   Database interface wrapper
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2006

   Major code contributions from Aleksey Fedoseev (fedoseev@ru.ibm.com)

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
#include "lib/util/debug.h"
#include "lib/util/fault.h"
#include "lib/util/talloc_stack.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_private.h"
#include "lib/util/util_tdb.h"
#include "lib/util/tevent_ntstatus.h"

/*
 * Fall back using fetch if no genuine exists operation is provided
 */

static int dbwrap_fallback_exists(struct db_context *db, TDB_DATA key)
{
	NTSTATUS status = dbwrap_parse_record(db, key, NULL, NULL);
	return NT_STATUS_IS_OK(status) ? 1 : 0;
}

static int delete_record(struct db_record *rec, void *data)
{
	NTSTATUS status = dbwrap_record_delete(rec);
	return NT_STATUS_IS_OK(status) ? 0 : -1;
}

/*
 * Fallback wipe implementation using traverse and delete if no genuine
 * wipe operation is provided
 */
static int dbwrap_fallback_wipe(struct db_context *db)
{
	NTSTATUS status = dbwrap_trans_traverse(db, delete_record, NULL);
	return NT_STATUS_IS_OK(status) ? 0 : -1;
}

static int do_nothing(struct db_record *rec, void *unused)
{
	return 0;
}

/*
 * Fallback check operation: just traverse.
 */
static int dbwrap_fallback_check(struct db_context *db)
{
	NTSTATUS status = dbwrap_traverse_read(db, do_nothing, NULL, NULL);
	return NT_STATUS_IS_OK(status) ? 0 : -1;
}

/*
 * Wrapper functions for the backend methods
 */

TDB_DATA dbwrap_record_get_key(const struct db_record *rec)
{
	return rec->key;
}

TDB_DATA dbwrap_record_get_value(const struct db_record *rec)
{
	SMB_ASSERT(rec->value_valid);
	return rec->value;
}

NTSTATUS dbwrap_record_storev(struct db_record *rec,
			      const TDB_DATA *dbufs, int num_dbufs, int flags)
{
	NTSTATUS status;

	/*
	 * Invalidate before rec->storev() is called, give
	 * rec->storev() the chance to re-validate rec->value.
	 */
	rec->value_valid = false;

	status = rec->storev(rec, dbufs, num_dbufs, flags);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return NT_STATUS_OK;
}

NTSTATUS dbwrap_record_store(struct db_record *rec, TDB_DATA data, int flags)
{
	return dbwrap_record_storev(rec, &data, 1, flags);
}

NTSTATUS dbwrap_record_delete(struct db_record *rec)
{
	NTSTATUS status;

	/*
	 * Invalidate before rec->delete_rec() is called, give
	 * rec->delete_rec() the chance to re-validate rec->value.
	 */
	rec->value_valid = false;

	status = rec->delete_rec(rec);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return NT_STATUS_OK;
}

const char *locked_dbs[DBWRAP_LOCK_ORDER_MAX];

static void debug_lock_order(int level)
{
	int i;
	DEBUG(level, ("lock order: "));
	for (i=0; i<DBWRAP_LOCK_ORDER_MAX; i++) {
		DEBUGADD(level,
			 (" %d:%s",
			  i + 1,
			  locked_dbs[i] ? locked_dbs[i] : "<none>"));
	}
	DEBUGADD(level, ("\n"));
}

void dbwrap_lock_order_lock(const char *db_name,
			    enum dbwrap_lock_order lock_order)
{
	int idx;

	DBG_INFO("check lock order %d for %s\n",
		 (int)lock_order,
		 db_name);

	if (!DBWRAP_LOCK_ORDER_VALID(lock_order)) {
		DBG_ERR("Invalid lock order %d of %s\n",
			lock_order,
			db_name);
		smb_panic("lock order violation");
	}

	for (idx=lock_order-1; idx<DBWRAP_LOCK_ORDER_MAX; idx++) {
		if (locked_dbs[idx] != NULL) {
			DBG_ERR("Lock order violation: Trying %s at %d while "
				"%s at %d is locked\n",
				db_name,
				(int)lock_order,
				locked_dbs[idx],
				idx + 1);
			debug_lock_order(0);
			smb_panic("lock order violation");
		}
	}

	locked_dbs[lock_order-1] = db_name;

	debug_lock_order(10);
}

void dbwrap_lock_order_unlock(const char *db_name,
			      enum dbwrap_lock_order lock_order)
{
	DBG_INFO("release lock order %d for %s\n",
		 (int)lock_order,
		 db_name);

	if (!DBWRAP_LOCK_ORDER_VALID(lock_order)) {
		DBG_ERR("Invalid lock order %d of %s\n",
			lock_order,
			db_name);
		smb_panic("lock order violation");
	}

	if (locked_dbs[lock_order-1] == NULL) {
		DBG_ERR("db %s at order %d unlocked\n",
			db_name,
			(int)lock_order);
		smb_panic("lock order violation");
	}

	if (locked_dbs[lock_order-1] != db_name) {
		DBG_ERR("locked db at lock order %d is %s, expected %s\n",
			(int)lock_order,
			locked_dbs[lock_order-1],
			db_name);
		smb_panic("lock order violation");
	}

	locked_dbs[lock_order-1] = NULL;
}

struct dbwrap_lock_order_state {
	struct db_context *db;
};

static int dbwrap_lock_order_state_destructor(
	struct dbwrap_lock_order_state *s)
{
	struct db_context *db = s->db;
	dbwrap_lock_order_unlock(db->name, db->lock_order);
	return 0;
}

static struct dbwrap_lock_order_state *dbwrap_check_lock_order(
	struct db_context *db, TALLOC_CTX *mem_ctx)
{
	struct dbwrap_lock_order_state *state;

	state = talloc(mem_ctx, struct dbwrap_lock_order_state);
	if (state == NULL) {
		DBG_WARNING("talloc failed\n");
		return NULL;
	}
	state->db = db;

	dbwrap_lock_order_lock(db->name, db->lock_order);
	talloc_set_destructor(state, dbwrap_lock_order_state_destructor);

	return state;
}

static struct db_record *dbwrap_fetch_locked_internal(
	struct db_context *db, TALLOC_CTX *mem_ctx, TDB_DATA key,
	struct db_record *(*db_fn)(struct db_context *db, TALLOC_CTX *mem_ctx,
				   TDB_DATA key))
{
	struct db_record *rec;
	struct dbwrap_lock_order_state *lock_order = NULL;

	if (db->lock_order != DBWRAP_LOCK_ORDER_NONE) {
		lock_order = dbwrap_check_lock_order(db, mem_ctx);
		if (lock_order == NULL) {
			return NULL;
		}
	}
	rec = db_fn(db, mem_ctx, key);
	if (rec == NULL) {
		TALLOC_FREE(lock_order);
		return NULL;
	}
	(void)talloc_steal(rec, lock_order);
	rec->db = db;
	return rec;
}

struct db_record *dbwrap_fetch_locked(struct db_context *db,
				      TALLOC_CTX *mem_ctx,
				      TDB_DATA key)
{
	return dbwrap_fetch_locked_internal(db, mem_ctx, key,
					    db->fetch_locked);
}

struct db_record *dbwrap_try_fetch_locked(struct db_context *db,
				      TALLOC_CTX *mem_ctx,
				      TDB_DATA key)
{
	return dbwrap_fetch_locked_internal(
		db, mem_ctx, key,
		db->try_fetch_locked
		? db->try_fetch_locked : db->fetch_locked);
}

struct db_context *dbwrap_record_get_db(struct db_record *rec)
{
	return rec->db;
}

struct dbwrap_fetch_state {
	TALLOC_CTX *mem_ctx;
	TDB_DATA data;
};

static void dbwrap_fetch_parser(TDB_DATA key, TDB_DATA data,
				void *private_data)
{
	struct dbwrap_fetch_state *state =
		(struct dbwrap_fetch_state *)private_data;

	state->data.dsize = data.dsize;
	state->data.dptr = (uint8_t *)talloc_memdup(state->mem_ctx, data.dptr,
						    data.dsize);
}

NTSTATUS dbwrap_fetch(struct db_context *db, TALLOC_CTX *mem_ctx,
		      TDB_DATA key, TDB_DATA *value)
{
	struct dbwrap_fetch_state state;
	NTSTATUS status;

	if (value == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	state.mem_ctx = mem_ctx;

	status = dbwrap_parse_record(db, key, dbwrap_fetch_parser, &state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if ((state.data.dsize != 0) && (state.data.dptr == NULL)) {
		return NT_STATUS_NO_MEMORY;
	}
	*value = state.data;
	return NT_STATUS_OK;
}

bool dbwrap_exists(struct db_context *db, TDB_DATA key)
{
	int result;
	if (db->exists != NULL) {
		result = db->exists(db, key);
	} else {
		result = dbwrap_fallback_exists(db,key);
	}
	return (result == 1);
}

struct dbwrap_store_state {
	TDB_DATA data;
	int flags;
	NTSTATUS status;
};

static void dbwrap_store_fn(
	struct db_record *rec,
	TDB_DATA value,
	void *private_data)
{
	struct dbwrap_store_state *state = private_data;
	state->status = dbwrap_record_store(rec, state->data, state->flags);
}

NTSTATUS dbwrap_store(struct db_context *db, TDB_DATA key,
		      TDB_DATA data, int flags)
{
	struct dbwrap_store_state state = { .data = data, .flags = flags };
	NTSTATUS status;

	status = dbwrap_do_locked(db, key, dbwrap_store_fn, &state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return state.status;
}

struct dbwrap_delete_state {
	NTSTATUS status;
};

static void dbwrap_delete_fn(
	struct db_record *rec,
	TDB_DATA value,
	void *private_data)
{
	struct dbwrap_delete_state *state = private_data;
	state->status = dbwrap_record_delete(rec);
}

NTSTATUS dbwrap_delete(struct db_context *db, TDB_DATA key)
{
	struct dbwrap_delete_state state = { .status = NT_STATUS_NOT_FOUND };
	NTSTATUS status;

	status = dbwrap_do_locked(db, key, dbwrap_delete_fn, &state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return state.status;
}

NTSTATUS dbwrap_traverse(struct db_context *db,
			 int (*f)(struct db_record*, void*),
			 void *private_data,
			 int *count)
{
	int ret = db->traverse(db, f, private_data);

	if (ret < 0) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	if (count != NULL) {
		*count = ret;
	}

	return NT_STATUS_OK;
}

NTSTATUS dbwrap_traverse_read(struct db_context *db,
			      int (*f)(struct db_record*, void*),
			      void *private_data,
			      int *count)
{
	int ret = db->traverse_read(db, f, private_data);

	if (ret < 0) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	if (count != NULL) {
		*count = ret;
	}

	return NT_STATUS_OK;
}

static void dbwrap_null_parser(TDB_DATA key, TDB_DATA val, void* data)
{
	return;
}

NTSTATUS dbwrap_parse_record(struct db_context *db, TDB_DATA key,
			     void (*parser)(TDB_DATA key, TDB_DATA data,
					    void *private_data),
			     void *private_data)
{
	if (parser == NULL) {
		parser = dbwrap_null_parser;
	}
	return db->parse_record(db, key, parser, private_data);
}

struct dbwrap_parse_record_state {
	struct db_context *db;
	TDB_DATA key;
	uint8_t _keybuf[64];
};

static void dbwrap_parse_record_done(struct tevent_req *subreq);

struct tevent_req *dbwrap_parse_record_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct db_context *db,
	TDB_DATA key,
	void (*parser)(TDB_DATA key, TDB_DATA data, void *private_data),
	void *private_data,
	enum dbwrap_req_state *req_state)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct dbwrap_parse_record_state *state = NULL;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state, struct dbwrap_parse_record_state);
	if (req == NULL) {
		*req_state = DBWRAP_REQ_ERROR;
		return NULL;
	}

	*state = (struct dbwrap_parse_record_state) {
		.db = db,
	};

	if (parser == NULL) {
		parser = dbwrap_null_parser;
	}

	*req_state = DBWRAP_REQ_INIT;

	if (db->parse_record_send == NULL) {
		/*
		 * Backend doesn't implement async version, call sync one
		 */
		status = db->parse_record(db, key, parser, private_data);
		if (tevent_req_nterror(req, status)) {
			*req_state = DBWRAP_REQ_DONE;
			return tevent_req_post(req, ev);
		}

		*req_state = DBWRAP_REQ_DONE;
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	/*
	 * Copy the key into our state ensuring the key data buffer is always
	 * available to all the dbwrap backends over the entire lifetime of the
	 * async request. Otherwise the caller might have free'd the key buffer.
	 */
	if (key.dsize > sizeof(state->_keybuf)) {
		state->key.dptr = talloc_memdup(state, key.dptr, key.dsize);
		if (tevent_req_nomem(state->key.dptr, req)) {
			return tevent_req_post(req, ev);
		}
	} else {
		memcpy(state->_keybuf, key.dptr, key.dsize);
		state->key.dptr = state->_keybuf;
	}
	state->key.dsize = key.dsize;

	subreq = db->parse_record_send(state,
				       ev,
				       db,
				       state->key,
				       parser,
				       private_data,
				       req_state);
	if (tevent_req_nomem(subreq, req)) {
		*req_state = DBWRAP_REQ_ERROR;
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq,
				dbwrap_parse_record_done,
				req);
	return req;
}

static void dbwrap_parse_record_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct dbwrap_parse_record_state *state = tevent_req_data(
		req, struct dbwrap_parse_record_state);
	NTSTATUS status;

	status = state->db->parse_record_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	tevent_req_done(req);
}

NTSTATUS dbwrap_parse_record_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS dbwrap_do_locked(struct db_context *db, TDB_DATA key,
			  void (*fn)(struct db_record *rec,
				     TDB_DATA value,
				     void *private_data),
			  void *private_data)
{
	struct db_record *rec;

	if (db->do_locked != NULL) {
		NTSTATUS status;

		if (db->lock_order != DBWRAP_LOCK_ORDER_NONE) {
			dbwrap_lock_order_lock(db->name, db->lock_order);
		}

		status = db->do_locked(db, key, fn, private_data);

		if (db->lock_order != DBWRAP_LOCK_ORDER_NONE) {
			dbwrap_lock_order_unlock(db->name, db->lock_order);
		}

		return status;
	}

	rec = dbwrap_fetch_locked(db, db, key);
	if (rec == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * Invalidate rec->value, nobody shall assume it's set from
	 * within dbwrap_do_locked().
	 */
	rec->value_valid = false;

	fn(rec, rec->value, private_data);

	TALLOC_FREE(rec);

	return NT_STATUS_OK;
}

int dbwrap_wipe(struct db_context *db)
{
	if (db->wipe == NULL) {
		return dbwrap_fallback_wipe(db);
	}
	return db->wipe(db);
}

int dbwrap_check(struct db_context *db)
{
	if (db->check == NULL) {
		return dbwrap_fallback_check(db);
	}
	return db->check(db);
}

int dbwrap_get_seqnum(struct db_context *db)
{
	return db->get_seqnum(db);
}

int dbwrap_transaction_start(struct db_context *db)
{
	if (!db->persistent) {
		/*
		 * dbwrap_ctdb has two different data models for persistent
		 * and non-persistent databases. Transactions are supported
		 * only for the persistent databases. This check is here to
		 * prevent breakages of the cluster case, autobuild at this
		 * point only tests non-clustered Samba. Before removing this
		 * check, please make sure that this facility has also been
		 * added to dbwrap_ctdb.
		 *
		 * Thanks, vl
		 */
		DEBUG(1, ("transactions not supported on non-persistent "
			  "database %s\n", db->name));
		return -1;
	}
	return db->transaction_start(db);
}

NTSTATUS dbwrap_transaction_start_nonblock(struct db_context *db)
{
	if (db->transaction_start_nonblock) {
		return db->transaction_start_nonblock(db);
	} else {
		return dbwrap_transaction_start(db) == 0 ? NT_STATUS_OK
			: NT_STATUS_UNSUCCESSFUL;
	}
}

int dbwrap_transaction_commit(struct db_context *db)
{
	return db->transaction_commit(db);
}

int dbwrap_transaction_cancel(struct db_context *db)
{
	return db->transaction_cancel(db);
}

size_t dbwrap_db_id(struct db_context *db, uint8_t *id, size_t idlen)
{
	return db->id(db, id, idlen);
}

bool dbwrap_is_persistent(struct db_context *db)
{
	return db->persistent;
}

const char *dbwrap_name(struct db_context *db)
{
	return db->name;
}

static ssize_t tdb_data_buf(const TDB_DATA *dbufs, int num_dbufs,
			    uint8_t *buf, size_t buflen)
{
	size_t needed = 0;
	uint8_t *p = buf;
	int i;

	for (i=0; i<num_dbufs; i++) {
		size_t thislen = dbufs[i].dsize;

		needed += thislen;
		if (needed < thislen) {
			/* wrap */
			return -1;
		}

		if (p != NULL && (thislen != 0) && (needed <= buflen)) {
			memcpy(p, dbufs[i].dptr, thislen);
			p += thislen;
		}
	}

	return needed;
}


TDB_DATA dbwrap_merge_dbufs(TALLOC_CTX *mem_ctx,
			    const TDB_DATA *dbufs, int num_dbufs)
{
	ssize_t len = tdb_data_buf(dbufs, num_dbufs, NULL, 0);
	uint8_t *buf;

	if (len == -1) {
		return (TDB_DATA) {0};
	}

	buf = talloc_array(mem_ctx, uint8_t, len);
	if (buf == NULL) {
		return (TDB_DATA) {0};
	}

	tdb_data_buf(dbufs, num_dbufs, buf, len);

	return (TDB_DATA) { .dptr = buf, .dsize = len };
}
