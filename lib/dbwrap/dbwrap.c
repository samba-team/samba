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

#include "includes.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_private.h"
#include "lib/util/util_tdb.h"

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
	return rec->value;
}

NTSTATUS dbwrap_record_store(struct db_record *rec, TDB_DATA data, int flags)
{
	NTSTATUS status;
	struct db_context *db;

	status = rec->store(rec, data, flags);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	db = rec->db;
	if (db->stored_callback != NULL) {
		db->stored_callback(db, rec,
				    db->stored_callback_private_data);
	}
	return NT_STATUS_OK;
}

void dbwrap_set_stored_callback(
	struct db_context *db,
	void (*cb)(struct db_context *db, struct db_record *rec,
		   void *private_data),
	void *private_data)
{
	db->stored_callback = cb;
	db->stored_callback_private_data = private_data;
}

NTSTATUS dbwrap_record_delete(struct db_record *rec)
{
	NTSTATUS status;
	struct db_context *db;

	status = rec->delete_rec(rec);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	db = rec->db;
	if (db->stored_callback != NULL) {
		db->stored_callback(db, rec,
				    db->stored_callback_private_data);
	}
	return NT_STATUS_OK;
}

struct dbwrap_lock_order_state {
	struct db_context **locked_dbs;
	struct db_context *db;
};

static void debug_lock_order(int level, struct db_context *dbs[])
{
	int i;
	DEBUG(level, ("lock order: "));
	for (i=0; i<DBWRAP_LOCK_ORDER_MAX; i++) {
		DEBUGADD(level, (" %d:%s", i + 1, dbs[i] ? dbs[i]->name : "<none>"));
	}
	DEBUGADD(level, ("\n"));
}

static int dbwrap_lock_order_state_destructor(
	struct dbwrap_lock_order_state *s)
{
	int idx = s->db->lock_order - 1;

	DEBUG(5, ("release lock order %d for %s\n",
		  (int)s->db->lock_order, s->db->name));

	if (s->locked_dbs[idx] != s->db) {
		DEBUG(0, ("locked db at lock order %d is %s, expected %s\n",
			  idx + 1, s->locked_dbs[idx]->name, s->db->name));
		debug_lock_order(0, s->locked_dbs);
		smb_panic("inconsistent lock_order\n");
	}

	s->locked_dbs[idx] = NULL;

	debug_lock_order(10, s->locked_dbs);

	return 0;
}


static struct dbwrap_lock_order_state *dbwrap_check_lock_order(
	struct db_context *db, TALLOC_CTX *mem_ctx)
{
	int idx;
	static struct db_context *locked_dbs[DBWRAP_LOCK_ORDER_MAX];
	struct dbwrap_lock_order_state *state = NULL;

	if (!DBWRAP_LOCK_ORDER_VALID(db->lock_order)) {
		DEBUG(0,("Invalid lock order %d of %s\n",
			 (int)db->lock_order, db->name));
		smb_panic("invalid lock_order\n");
		return NULL;
	}

	DEBUG(5, ("check lock order %d for %s\n",
		  (int)db->lock_order, db->name));


	for (idx=db->lock_order - 1; idx < DBWRAP_LOCK_ORDER_MAX; idx++) {
		if (locked_dbs[idx] != NULL) {
			DEBUG(0, ("Lock order violation: Trying %s at %d while %s at %d is locked\n",
				  db->name, (int)db->lock_order, locked_dbs[idx]->name, idx + 1));
			debug_lock_order(0, locked_dbs);
			smb_panic("invalid lock_order");
			return NULL;
		}
	}

	state = talloc(mem_ctx, struct dbwrap_lock_order_state);
	if (state == NULL) {
		DEBUG(1, ("talloc failed\n"));
		return NULL;
	}
	state->db = db;
	state->locked_dbs = locked_dbs;
	talloc_set_destructor(state, dbwrap_lock_order_state_destructor);

	locked_dbs[db->lock_order - 1] = db;

	debug_lock_order(10, locked_dbs);

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

NTSTATUS dbwrap_store(struct db_context *db, TDB_DATA key,
		      TDB_DATA data, int flags)
{
	struct db_record *rec;
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();

	rec = dbwrap_fetch_locked(db, frame, key);
	if (rec == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	status = dbwrap_record_store(rec, data, flags);
	TALLOC_FREE(frame);
	return status;
}

NTSTATUS dbwrap_delete(struct db_context *db, TDB_DATA key)
{
	struct db_record *rec;
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();

	rec = dbwrap_fetch_locked(db, frame, key);
	if (rec == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	status = dbwrap_record_delete(rec);
	TALLOC_FREE(frame);
	return status;
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

int dbwrap_wipe(struct db_context *db)
{
	if (db->wipe == NULL) {
		return dbwrap_fallback_wipe(db);
	}
	return db->wipe(db);
}

int dbwrap_hash_size(struct db_context *db)
{
	return db->hash_size;
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

void dbwrap_db_id(struct db_context *db, const uint8_t **id, size_t *idlen)
{
	db->id(db, id, idlen);
}

bool dbwrap_is_persistent(struct db_context *db)
{
	return db->persistent;
}

const char *dbwrap_name(struct db_context *db)
{
	return db->name;
}
