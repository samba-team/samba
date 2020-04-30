/*
   ldb database library using mdb back end

   Copyright (C) Jakub Hrozek 2014
   Copyright (C) Catalyst.Net Ltd 2017

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include "ldb_mdb.h"
#include "../ldb_key_value/ldb_kv.h"
#include "include/dlinklist.h"

#define MDB_URL_PREFIX		"mdb://"
#define MDB_URL_PREFIX_SIZE	(sizeof(MDB_URL_PREFIX)-1)

#define LDB_MDB_MAX_KEY_LENGTH 511

#define GIGABYTE (1024*1024*1024)

int ldb_mdb_err_map(int lmdb_err)
{
	switch (lmdb_err) {
	case MDB_SUCCESS:
		return LDB_SUCCESS;
	case EIO:
		return LDB_ERR_OPERATIONS_ERROR;
#ifdef EBADE
	case EBADE:
#endif
	case MDB_INCOMPATIBLE:
	case MDB_CORRUPTED:
	case MDB_INVALID:
		return LDB_ERR_UNAVAILABLE;
	case MDB_BAD_TXN:
	case MDB_BAD_VALSIZE:
#ifdef MDB_BAD_DBI
	case MDB_BAD_DBI:
#endif
	case MDB_PANIC:
	case EINVAL:
		return LDB_ERR_PROTOCOL_ERROR;
	case MDB_MAP_FULL:
	case MDB_DBS_FULL:
	case MDB_READERS_FULL:
	case MDB_TLS_FULL:
	case MDB_TXN_FULL:
	case EAGAIN:
		return LDB_ERR_BUSY;
	case MDB_KEYEXIST:
		return LDB_ERR_ENTRY_ALREADY_EXISTS;
	case MDB_NOTFOUND:
	case ENOENT:
		return LDB_ERR_NO_SUCH_OBJECT;
	case EACCES:
		return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	default:
		break;
	}
	return LDB_ERR_OTHER;
}

#define ldb_mdb_error(ldb, ecode) lmdb_error_at(ldb, ecode, __FILE__, __LINE__)
static int lmdb_error_at(struct ldb_context *ldb,
			 int ecode,
			 const char *file,
			 int line)
{
	int ldb_err = ldb_mdb_err_map(ecode);
	char *reason = mdb_strerror(ecode);
	ldb_asprintf_errstring(ldb,
			       "(%d) - %s at %s:%d",
			       ecode,
			       reason,
			       file,
			       line);
	return ldb_err;
}

static bool lmdb_transaction_active(struct ldb_kv_private *ldb_kv)
{
	return ldb_kv->lmdb_private->txlist != NULL;
}

static MDB_txn *lmdb_trans_get_tx(struct lmdb_trans *ltx)
{
	if (ltx == NULL) {
		return NULL;
	}

	return ltx->tx;
}

static void trans_push(struct lmdb_private *lmdb, struct lmdb_trans *ltx)
{
	if (lmdb->txlist) {
		talloc_steal(lmdb->txlist, ltx);
	}

	DLIST_ADD(lmdb->txlist, ltx);
}

static void trans_finished(struct lmdb_private *lmdb, struct lmdb_trans *ltx)
{
	DLIST_REMOVE(lmdb->txlist, ltx);
	talloc_free(ltx);
}


static struct lmdb_trans *lmdb_private_trans_head(struct lmdb_private *lmdb)
{
	struct lmdb_trans *ltx;

	ltx = lmdb->txlist;
	return ltx;
}


static MDB_txn *get_current_txn(struct lmdb_private *lmdb)
{
	MDB_txn *txn = NULL;

	txn = lmdb_trans_get_tx(lmdb_private_trans_head(lmdb));
	if (txn != NULL) {
		return txn;
	}
	if (lmdb->read_txn != NULL) {
		return lmdb->read_txn;
	}
	lmdb->error = MDB_BAD_TXN;
	ldb_set_errstring(lmdb->ldb, __location__":No active transaction\n");
	return NULL;
}

static int lmdb_store(struct ldb_kv_private *ldb_kv,
		      struct ldb_val key,
		      struct ldb_val data,
		      int flags)
{
	struct lmdb_private *lmdb = ldb_kv->lmdb_private;
	MDB_val mdb_key;
	MDB_val mdb_data;
	int mdb_flags;
	MDB_txn *txn = NULL;
	MDB_dbi dbi = 0;

	if (ldb_kv->read_only) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	txn = lmdb_trans_get_tx(lmdb_private_trans_head(lmdb));
	if (txn == NULL) {
		ldb_debug(lmdb->ldb, LDB_DEBUG_FATAL, "No transaction");
		lmdb->error = MDB_PANIC;
		return ldb_mdb_error(lmdb->ldb, lmdb->error);
	}

	lmdb->error = mdb_dbi_open(txn, NULL, 0, &dbi);
	if (lmdb->error != MDB_SUCCESS) {
		return ldb_mdb_error(lmdb->ldb, lmdb->error);
	}

	mdb_key.mv_size = key.length;
	mdb_key.mv_data = key.data;

	mdb_data.mv_size = data.length;
	mdb_data.mv_data = data.data;

	if (flags == TDB_INSERT) {
		mdb_flags = MDB_NOOVERWRITE;
	} else if (flags == TDB_MODIFY) {
		/*
		 * Modifying a record, ensure that it exists.
		 * This mimics the TDB semantics
		 */
		MDB_val value;
		lmdb->error = mdb_get(txn, dbi, &mdb_key, &value);
		if (lmdb->error != MDB_SUCCESS) {
			return ldb_mdb_error(lmdb->ldb, lmdb->error);
		}
		mdb_flags = 0;
	} else {
		mdb_flags = 0;
	}

	lmdb->error = mdb_put(txn, dbi, &mdb_key, &mdb_data, mdb_flags);
	if (lmdb->error != MDB_SUCCESS) {
		return ldb_mdb_error(lmdb->ldb, lmdb->error);
	}

	return ldb_mdb_err_map(lmdb->error);
}

static int lmdb_delete(struct ldb_kv_private *ldb_kv, struct ldb_val key)
{
	struct lmdb_private *lmdb = ldb_kv->lmdb_private;
	MDB_val mdb_key;
	MDB_txn *txn = NULL;
	MDB_dbi dbi = 0;

	if (ldb_kv->read_only) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	txn = lmdb_trans_get_tx(lmdb_private_trans_head(lmdb));
	if (txn == NULL) {
		ldb_debug(lmdb->ldb, LDB_DEBUG_FATAL, "No transaction");
		lmdb->error = MDB_PANIC;
		return ldb_mdb_error(lmdb->ldb, lmdb->error);
	}

	lmdb->error = mdb_dbi_open(txn, NULL, 0, &dbi);
	if (lmdb->error != MDB_SUCCESS) {
		return ldb_mdb_error(lmdb->ldb, lmdb->error);
	}

	mdb_key.mv_size = key.length;
	mdb_key.mv_data = key.data;

	lmdb->error = mdb_del(txn, dbi, &mdb_key, NULL);
	if (lmdb->error != MDB_SUCCESS) {
		return ldb_mdb_error(lmdb->ldb, lmdb->error);
	}
	return ldb_mdb_err_map(lmdb->error);
}

static int lmdb_traverse_fn(struct ldb_kv_private *ldb_kv,
			    ldb_kv_traverse_fn fn,
			    void *ctx)
{
	struct lmdb_private *lmdb = ldb_kv->lmdb_private;
	MDB_val mdb_key;
	MDB_val mdb_data;
	MDB_txn *txn = NULL;
	MDB_dbi dbi = 0;
	MDB_cursor *cursor = NULL;
	int ret;

	txn = get_current_txn(lmdb);
	if (txn == NULL) {
		ldb_debug(lmdb->ldb, LDB_DEBUG_FATAL, "No transaction");
		lmdb->error = MDB_PANIC;
		return ldb_mdb_error(lmdb->ldb, lmdb->error);
	}

	lmdb->error = mdb_dbi_open(txn, NULL, 0, &dbi);
	if (lmdb->error != MDB_SUCCESS) {
		return ldb_mdb_error(lmdb->ldb, lmdb->error);
	}

	lmdb->error = mdb_cursor_open(txn, dbi, &cursor);
	if (lmdb->error != MDB_SUCCESS) {
		goto done;
	}

	while ((lmdb->error = mdb_cursor_get(
			cursor, &mdb_key,
			&mdb_data, MDB_NEXT)) == MDB_SUCCESS) {

		struct ldb_val key = {
			.length = mdb_key.mv_size,
			.data = mdb_key.mv_data,
		};
		struct ldb_val data = {
			.length = mdb_data.mv_size,
			.data = mdb_data.mv_data,
		};

		ret = fn(ldb_kv, key, data, ctx);
		if (ret != 0) {
			/*
			 * NOTE: This DOES NOT set lmdb->error!
			 *
			 * This means that the caller will get success.
			 * This matches TDB traverse behaviour, where callbacks
			 * may terminate the traverse, but do not change the
			 * return code from success.
			 *
			 * Callers SHOULD store their own error codes.
			 */
			goto done;
		}
	}
	if (lmdb->error == MDB_NOTFOUND) {
		lmdb->error = MDB_SUCCESS;
	}
done:
	if (cursor != NULL) {
		mdb_cursor_close(cursor);
	}

	if (lmdb->error != MDB_SUCCESS) {
		return ldb_mdb_error(lmdb->ldb, lmdb->error);
	}
	return ldb_mdb_err_map(lmdb->error);
}

static int lmdb_update_in_iterate(struct ldb_kv_private *ldb_kv,
				  struct ldb_val key,
				  struct ldb_val key2,
				  struct ldb_val data,
				  void *state)
{
	struct lmdb_private *lmdb = ldb_kv->lmdb_private;
	struct ldb_val copy;
	int ret = LDB_SUCCESS;

	/*
	 * Need to take a copy of the data as the delete operation alters the
	 * data, as it is in private lmdb memory.
	 */
	copy.length = data.length;
	copy.data = talloc_memdup(ldb_kv, data.data, data.length);
	if (copy.data == NULL) {
		lmdb->error = MDB_PANIC;
		return ldb_oom(lmdb->ldb);
	}

	lmdb->error = lmdb_delete(ldb_kv, key);
	if (lmdb->error != MDB_SUCCESS) {
		ldb_debug(
			lmdb->ldb,
			LDB_DEBUG_ERROR,
			"Failed to delete %*.*s "
			"for rekey as %*.*s: %s",
			(int)key.length, (int)key.length,
			(const char *)key.data,
			(int)key2.length, (int)key2.length,
			(const char *)key.data,
			mdb_strerror(lmdb->error));
		ret = ldb_mdb_error(lmdb->ldb, lmdb->error);
		goto done;
	}

	lmdb->error = lmdb_store(ldb_kv, key2, copy, 0);
	if (lmdb->error != MDB_SUCCESS) {
		ldb_debug(
			lmdb->ldb,
			LDB_DEBUG_ERROR,
			"Failed to rekey %*.*s as %*.*s: %s",
			(int)key.length, (int)key.length,
			(const char *)key.data,
			(int)key2.length, (int)key2.length,
			(const char *)key.data,
			mdb_strerror(lmdb->error));
		ret = ldb_mdb_error(lmdb->ldb, lmdb->error);
		goto done;
	}

done:
	if (copy.data != NULL) {
		TALLOC_FREE(copy.data);
		copy.length = 0;
	}

	/*
	 * Explicity invalidate the data, as the delete has done this
	 */
	data.length = 0;
	data.data = NULL;

	return ret;
}

/* Handles only a single record */
static int lmdb_parse_record(struct ldb_kv_private *ldb_kv,
			     struct ldb_val key,
			     int (*parser)(struct ldb_val key,
					   struct ldb_val data,
					   void *private_data),
			     void *ctx)
{
	struct lmdb_private *lmdb = ldb_kv->lmdb_private;
	MDB_val mdb_key;
	MDB_val mdb_data;
	MDB_txn *txn = NULL;
	MDB_dbi dbi;
	struct ldb_val data;

	txn = get_current_txn(lmdb);
	if (txn == NULL) {
		ldb_debug(lmdb->ldb, LDB_DEBUG_FATAL, "No transaction active");
		lmdb->error = MDB_PANIC;
		return ldb_mdb_error(lmdb->ldb, lmdb->error);
	}

	lmdb->error = mdb_dbi_open(txn, NULL, 0, &dbi);
	if (lmdb->error != MDB_SUCCESS) {
		return ldb_mdb_error(lmdb->ldb, lmdb->error);
	}

	mdb_key.mv_size = key.length;
	mdb_key.mv_data = key.data;

	lmdb->error = mdb_get(txn, dbi, &mdb_key, &mdb_data);
	if (lmdb->error != MDB_SUCCESS) {
		/* TODO closing a handle should not even be necessary */
		mdb_dbi_close(lmdb->env, dbi);
		if (lmdb->error == MDB_NOTFOUND) {
			return LDB_ERR_NO_SUCH_OBJECT;
		}
		return ldb_mdb_error(lmdb->ldb, lmdb->error);
	}
	data.data = mdb_data.mv_data;
	data.length = mdb_data.mv_size;

	/* TODO closing a handle should not even be necessary */
	mdb_dbi_close(lmdb->env, dbi);

	return parser(key, data, ctx);
}

/*
 * Exactly the same as iterate, except we have a start key and an end key
 * (which are both included in the results if present).
 *
 * If start > end, return MDB_PANIC.
 */
static int lmdb_iterate_range(struct ldb_kv_private *ldb_kv,
			      struct ldb_val start_key,
			      struct ldb_val end_key,
			      ldb_kv_traverse_fn fn,
			      void *ctx)
{
	struct lmdb_private *lmdb = ldb_kv->lmdb_private;
	MDB_val mdb_key;
	MDB_val mdb_data;
	MDB_txn *txn = NULL;
	MDB_dbi dbi = 0;
	MDB_cursor *cursor = NULL;
	int ret;

	MDB_val mdb_s_key;
	MDB_val mdb_e_key;

	txn = get_current_txn(lmdb);
	if (txn == NULL) {
		ldb_debug(lmdb->ldb, LDB_DEBUG_FATAL, "No transaction");
		lmdb->error = MDB_PANIC;
		return ldb_mdb_error(lmdb->ldb, lmdb->error);
	}

	lmdb->error = mdb_dbi_open(txn, NULL, 0, &dbi);
	if (lmdb->error != MDB_SUCCESS) {
		return ldb_mdb_error(lmdb->ldb, lmdb->error);
	}

	mdb_s_key.mv_size = start_key.length;
	mdb_s_key.mv_data = start_key.data;

	mdb_e_key.mv_size = end_key.length;
	mdb_e_key.mv_data = end_key.data;

	if (mdb_cmp(txn, dbi, &mdb_s_key, &mdb_e_key) > 0) {
		lmdb->error = MDB_PANIC;
		return ldb_mdb_error(lmdb->ldb, lmdb->error);
	}

	lmdb->error = mdb_cursor_open(txn, dbi, &cursor);
	if (lmdb->error != MDB_SUCCESS) {
		goto done;
	}

	lmdb->error = mdb_cursor_get(cursor, &mdb_s_key, &mdb_data, MDB_SET_RANGE);

	if (lmdb->error != MDB_SUCCESS) {
		if (lmdb->error == MDB_NOTFOUND) {
			lmdb->error = MDB_SUCCESS;
		}
		goto done;
	} else {
		struct ldb_val key = {
			.length = mdb_s_key.mv_size,
			.data = mdb_s_key.mv_data,
		};
		struct ldb_val data = {
			.length = mdb_data.mv_size,
			.data = mdb_data.mv_data,
		};

		if (mdb_cmp(txn, dbi, &mdb_s_key, &mdb_e_key) > 0) {
			goto done;
		}

		ret = fn(ldb_kv, key, data, ctx);
		if (ret != 0) {
			/*
			 * NOTE: This DOES NOT set lmdb->error!
			 *
			 * This means that the caller will get success.
			 * This matches TDB traverse behaviour, where callbacks
			 * may terminate the traverse, but do not change the
			 * return code from success.
			 *
			 * Callers SHOULD store their own error codes.
			 */
			goto done;
		}
	}

	while ((lmdb->error = mdb_cursor_get(
			cursor, &mdb_key,
			&mdb_data, MDB_NEXT)) == MDB_SUCCESS) {

		struct ldb_val key = {
			.length = mdb_key.mv_size,
			.data = mdb_key.mv_data,
		};
		struct ldb_val data = {
			.length = mdb_data.mv_size,
			.data = mdb_data.mv_data,
		};

		if (mdb_cmp(txn, dbi, &mdb_key, &mdb_e_key) > 0) {
			goto done;
		}

		ret = fn(ldb_kv, key, data, ctx);
		if (ret != 0) {
			/*
			 * NOTE: This DOES NOT set lmdb->error!
			 *
			 * This means that the caller will get success.
			 * This matches TDB traverse behaviour, where callbacks
			 * may terminate the traverse, but do not change the
			 * return code from success.
			 *
			 * Callers SHOULD store their own error codes.
			 */
			goto done;
		}
	}
	if (lmdb->error == MDB_NOTFOUND) {
		lmdb->error = MDB_SUCCESS;
	}
done:
	if (cursor != NULL) {
		mdb_cursor_close(cursor);
	}

	if (lmdb->error != MDB_SUCCESS) {
		return ldb_mdb_error(lmdb->ldb, lmdb->error);
	}
	return ldb_mdb_err_map(lmdb->error);
}

static int lmdb_lock_read(struct ldb_module *module)
{
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);
	struct lmdb_private *lmdb = ldb_kv->lmdb_private;
	pid_t pid = getpid();

	if (pid != lmdb->pid) {
		ldb_asprintf_errstring(
			lmdb->ldb,
			__location__": Reusing ldb opened by pid %d in "
			"process %d\n",
			lmdb->pid,
			pid);
		lmdb->error = MDB_BAD_TXN;
		return LDB_ERR_PROTOCOL_ERROR;
	}

	lmdb->error = MDB_SUCCESS;
	if (lmdb_transaction_active(ldb_kv) == false &&
	    ldb_kv->read_lock_count == 0) {
		lmdb->error = mdb_txn_begin(lmdb->env,
					    NULL,
					    MDB_RDONLY,
					    &lmdb->read_txn);
	}
	if (lmdb->error != MDB_SUCCESS) {
		return ldb_mdb_error(lmdb->ldb, lmdb->error);
	}

	ldb_kv->read_lock_count++;
	return ldb_mdb_err_map(lmdb->error);
}

static int lmdb_unlock_read(struct ldb_module *module)
{
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);

	if (lmdb_transaction_active(ldb_kv) == false &&
	    ldb_kv->read_lock_count == 1) {
		struct lmdb_private *lmdb = ldb_kv->lmdb_private;
		mdb_txn_commit(lmdb->read_txn);
		lmdb->read_txn = NULL;
		ldb_kv->read_lock_count--;
		return LDB_SUCCESS;
	}
	ldb_kv->read_lock_count--;
	return LDB_SUCCESS;
}

static int lmdb_transaction_start(struct ldb_kv_private *ldb_kv)
{
	struct lmdb_private *lmdb = ldb_kv->lmdb_private;
	struct lmdb_trans *ltx;
	struct lmdb_trans *ltx_head;
	MDB_txn *tx_parent;
	pid_t pid = getpid();

	/* Do not take out the transaction lock on a read-only DB */
	if (ldb_kv->read_only) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	ltx = talloc_zero(lmdb, struct lmdb_trans);
	if (ltx == NULL) {
		return ldb_oom(lmdb->ldb);
	}

	if (pid != lmdb->pid) {
		ldb_asprintf_errstring(
			lmdb->ldb,
			__location__": Reusing ldb opened by pid %d in "
			"process %d\n",
			lmdb->pid,
			pid);
		lmdb->error = MDB_BAD_TXN;
		return LDB_ERR_PROTOCOL_ERROR;
	}

	/*
	 * Clear out any stale readers
	 */
	{
		int stale = 0;
		mdb_reader_check(lmdb->env, &stale);
		if (stale > 0) {
			ldb_debug(
				lmdb->ldb,
				LDB_DEBUG_ERROR,
				"LMDB Stale readers, deleted (%d)",
				stale);
		}
	}



	ltx_head = lmdb_private_trans_head(lmdb);

	tx_parent = lmdb_trans_get_tx(ltx_head);

	lmdb->error = mdb_txn_begin(lmdb->env, tx_parent, 0, &ltx->tx);
	if (lmdb->error != MDB_SUCCESS) {
		return ldb_mdb_error(lmdb->ldb, lmdb->error);
	}

	trans_push(lmdb, ltx);

	return ldb_mdb_err_map(lmdb->error);
}

static int lmdb_transaction_cancel(struct ldb_kv_private *ldb_kv)
{
	struct lmdb_trans *ltx;
	struct lmdb_private *lmdb = ldb_kv->lmdb_private;

	ltx = lmdb_private_trans_head(lmdb);
	if (ltx == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	mdb_txn_abort(ltx->tx);
	trans_finished(lmdb, ltx);
	return LDB_SUCCESS;
}

static int lmdb_transaction_prepare_commit(struct ldb_kv_private *ldb_kv)
{
	/* No need to prepare a commit */
	return LDB_SUCCESS;
}

static int lmdb_transaction_commit(struct ldb_kv_private *ldb_kv)
{
	struct lmdb_trans *ltx;
	struct lmdb_private *lmdb = ldb_kv->lmdb_private;

	ltx = lmdb_private_trans_head(lmdb);
	if (ltx == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	lmdb->error = mdb_txn_commit(ltx->tx);
	trans_finished(lmdb, ltx);

	return lmdb->error;
}

static int lmdb_error(struct ldb_kv_private *ldb_kv)
{
	return ldb_mdb_err_map(ldb_kv->lmdb_private->error);
}

static const char *lmdb_errorstr(struct ldb_kv_private *ldb_kv)
{
	return mdb_strerror(ldb_kv->lmdb_private->error);
}

static const char *lmdb_name(struct ldb_kv_private *ldb_kv)
{
	return "lmdb";
}

static bool lmdb_changed(struct ldb_kv_private *ldb_kv)
{
	/*
	 * lmdb does no provide a quick way to determine if the database
	 * has changed.  This function always returns true.
	 *
	 * Note that tdb uses a sequence number that allows this function
	 * to be implemented efficiently.
	 */
	return true;
}

/*
 * Get the number of records in the database.
 *
 * The mdb_env_stat call returns an accurate count, so we return the actual
 * number of records in the database rather than an estimate.
 */
static size_t lmdb_get_size(struct ldb_kv_private *ldb_kv)
{

	struct MDB_stat stats = {0};
	struct lmdb_private *lmdb = ldb_kv->lmdb_private;
	int ret = 0;

	ret = mdb_env_stat(lmdb->env, &stats);
	if (ret != 0) {
		return 0;
	}
	return stats.ms_entries;
}

/*
 * Start a sub transaction
 * As lmdb supports nested transactions we can start a new transaction
 */
static int lmdb_nested_transaction_start(struct ldb_kv_private *ldb_kv)
{
	int ret = lmdb_transaction_start(ldb_kv);
	return ret;
}

/*
 * Commit a sub transaction
 * As lmdb supports nested transactions we can commit the nested transaction
 */
static int lmdb_nested_transaction_commit(struct ldb_kv_private *ldb_kv)
{
	int ret = lmdb_transaction_commit(ldb_kv);
	return ret;
}

/*
 * Cancel a sub transaction
 * As lmdb supports nested transactions we can cancel the nested transaction
 */
static int lmdb_nested_transaction_cancel(struct ldb_kv_private *ldb_kv)
{
	int ret = lmdb_transaction_cancel(ldb_kv);
	return ret;
}

static struct kv_db_ops lmdb_key_value_ops = {
	.options            = LDB_KV_OPTION_STABLE_READ_LOCK,

	.store              = lmdb_store,
	.delete             = lmdb_delete,
	.iterate            = lmdb_traverse_fn,
	.update_in_iterate  = lmdb_update_in_iterate,
	.fetch_and_parse    = lmdb_parse_record,
	.iterate_range      = lmdb_iterate_range,
	.lock_read          = lmdb_lock_read,
	.unlock_read        = lmdb_unlock_read,
	.begin_write        = lmdb_transaction_start,
	.prepare_write      = lmdb_transaction_prepare_commit,
	.finish_write       = lmdb_transaction_commit,
	.abort_write        = lmdb_transaction_cancel,
	.error              = lmdb_error,
	.errorstr           = lmdb_errorstr,
	.name               = lmdb_name,
	.has_changed        = lmdb_changed,
	.transaction_active = lmdb_transaction_active,
	.get_size           = lmdb_get_size,
	.begin_nested_write = lmdb_nested_transaction_start,
	.finish_nested_write = lmdb_nested_transaction_commit,
	.abort_nested_write = lmdb_nested_transaction_cancel,
};

static const char *lmdb_get_path(const char *url)
{
	const char *path;

	/* parse the url */
	if (strchr(url, ':')) {
		if (strncmp(url, MDB_URL_PREFIX, MDB_URL_PREFIX_SIZE) != 0) {
			return NULL;
		}
		path = url + MDB_URL_PREFIX_SIZE;
	} else {
		path = url;
	}

	return path;
}

static int lmdb_pvt_destructor(struct lmdb_private *lmdb)
{
	struct lmdb_trans *ltx = NULL;

	/* Check if this is a forked child */
	if (getpid() != lmdb->pid) {
		int fd = 0;
		/*
		 * We cannot call mdb_env_close or commit any transactions,
		 * otherwise they might appear finished in the parent.
		 *
		 */

		if (mdb_env_get_fd(lmdb->env, &fd) == 0) {
			close(fd);
		}

		/* Remove the pointer, so that no access should occur */
		lmdb->env = NULL;

		return 0;
	}

	/*
	 * Close the read transaction if it's open
	 */
	if (lmdb->read_txn != NULL) {
		mdb_txn_abort(lmdb->read_txn);
	}

	if (lmdb->env == NULL) {
		return 0;
	}

	/*
	 * Abort any currently active transactions
	 */
	ltx = lmdb_private_trans_head(lmdb);
	while (ltx != NULL) {
		mdb_txn_abort(ltx->tx);
		trans_finished(lmdb, ltx);
		ltx = lmdb_private_trans_head(lmdb);
	}
	lmdb->env = NULL;

	return 0;
}

struct mdb_env_wrap {
	struct mdb_env_wrap *next, *prev;
	dev_t device;
	ino_t inode;
	MDB_env *env;
	pid_t pid;
};

static struct mdb_env_wrap *mdb_list;

/* destroy the last connection to an mdb */
static int mdb_env_wrap_destructor(struct mdb_env_wrap *w)
{
	mdb_env_close(w->env);
	DLIST_REMOVE(mdb_list, w);
	return 0;
}

static int lmdb_open_env(TALLOC_CTX *mem_ctx,
			 MDB_env **env,
			 struct ldb_context *ldb,
			 const char *path,
			 const size_t env_map_size,
			 unsigned int flags)
{
	int ret;
	unsigned int mdb_flags = MDB_NOSUBDIR|MDB_NOTLS;
	/*
	 * MDB_NOSUBDIR implies there is a separate file called path and a
	 * separate lockfile called path-lock
	 */

	struct mdb_env_wrap *w;
	struct stat st;
	pid_t pid = getpid();
	int fd = 0;
	unsigned v;

	if (stat(path, &st) == 0) {
		for (w=mdb_list;w;w=w->next) {
			if (st.st_dev == w->device &&
			    st.st_ino == w->inode &&
			    pid == w->pid) {
				/*
				 * We must have only one MDB_env per process
				 */
				if (!talloc_reference(mem_ctx, w)) {
					return ldb_oom(ldb);
				}
				*env = w->env;
				return LDB_SUCCESS;
			}
		}
	}

	w = talloc(mem_ctx, struct mdb_env_wrap);
	if (w == NULL) {
		return ldb_oom(ldb);
	}

	ret = mdb_env_create(env);
	if (ret != 0) {
		ldb_asprintf_errstring(
			ldb,
			"Could not create MDB environment %s: %s\n",
			path,
			mdb_strerror(ret));
		return ldb_mdb_err_map(ret);
	}

	if (env_map_size > 0) {
		ret = mdb_env_set_mapsize(*env, env_map_size);
		if (ret != 0) {
			ldb_asprintf_errstring(
				ldb,
				"Could not set MDB mmap() size to %llu "
				"on %s: %s\n",
				(unsigned long long)(env_map_size),
				path,
				mdb_strerror(ret));
			TALLOC_FREE(w);
			return ldb_mdb_err_map(ret);
		}
	}

	mdb_env_set_maxreaders(*env, 100000);
	/*
	 * As we ensure that there is only one MDB_env open per database per
	 * process. We can not use the MDB_RDONLY flag, as another ldb may be
	 * opened in read write mode
	 */
	if (flags & LDB_FLG_NOSYNC) {
		mdb_flags |= MDB_NOSYNC;
	}
	ret = mdb_env_open(*env, path, mdb_flags, 0644);
	if (ret != 0) {
		ldb_asprintf_errstring(ldb,
				"Could not open DB %s: %s\n",
				path, mdb_strerror(ret));
		TALLOC_FREE(w);
		return ldb_mdb_err_map(ret);
	}

	{
		MDB_envinfo stat = {0};
		ret = mdb_env_info (*env, &stat);
		if (ret != 0) {
			ldb_asprintf_errstring(
				ldb,
				"Could not get MDB environment stats %s: %s\n",
				path,
				mdb_strerror(ret));
		return ldb_mdb_err_map(ret);
		}
	}

	ret = mdb_env_get_fd(*env, &fd);
	if (ret != 0) {
		ldb_asprintf_errstring(ldb,
				       "Could not obtain DB FD %s: %s\n",
				       path, mdb_strerror(ret));
		TALLOC_FREE(w);
		return ldb_mdb_err_map(ret);
	}

	/* Just as for TDB: on exec, don't inherit the fd */
	v = fcntl(fd, F_GETFD, 0);
	if (v == -1) {
		TALLOC_FREE(w);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = fcntl(fd, F_SETFD, v | FD_CLOEXEC);
	if (ret == -1) {
		TALLOC_FREE(w);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (fstat(fd, &st) != 0) {
		ldb_asprintf_errstring(
			ldb,
			"Could not stat %s:\n",
			path);
		TALLOC_FREE(w);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	w->env = *env;
	w->device = st.st_dev;
	w->inode  = st.st_ino;
	w->pid = pid;

	talloc_set_destructor(w, mdb_env_wrap_destructor);

	DLIST_ADD(mdb_list, w);

	return LDB_SUCCESS;

}

static int lmdb_pvt_open(struct lmdb_private *lmdb,
			 struct ldb_context *ldb,
			 const char *path,
			 const size_t env_map_size,
			 unsigned int flags)
{
	int ret;
	int lmdb_max_key_length;

	if (flags & LDB_FLG_DONT_CREATE_DB) {
		struct stat st;
		if (stat(path, &st) != 0) {
			return LDB_ERR_UNAVAILABLE;
		}
	}

	ret = lmdb_open_env(lmdb, &lmdb->env, ldb, path, env_map_size, flags);
	if (ret != 0) {
		return ret;
	}

	/* Close when lmdb is released */
	talloc_set_destructor(lmdb, lmdb_pvt_destructor);

	/* Store the original pid during the LMDB open */
	lmdb->pid = getpid();

	lmdb_max_key_length = mdb_env_get_maxkeysize(lmdb->env);

	/* This will never happen, but if it does make sure to freak out */
	if (lmdb_max_key_length < LDB_MDB_MAX_KEY_LENGTH) {
		return ldb_operr(ldb);
	}

	return LDB_SUCCESS;
}

int lmdb_connect(struct ldb_context *ldb,
		 const char *url,
		 unsigned int flags,
		 const char *options[],
		 struct ldb_module **_module)
{
	const char *path = NULL;
	struct lmdb_private *lmdb = NULL;
	struct ldb_kv_private *ldb_kv = NULL;
	int ret;
	size_t env_map_size = 0;

	/*
	 * We hold locks, so we must use a private event context
	 * on each returned handle
	 */
	ldb_set_require_private_event_context(ldb);

	path = lmdb_get_path(url);
	if (path == NULL) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "Invalid mdb URL '%s'", url);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ldb_kv = talloc_zero(ldb, struct ldb_kv_private);
	if (!ldb_kv) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	lmdb = talloc_zero(ldb_kv, struct lmdb_private);
	if (lmdb == NULL) {
		TALLOC_FREE(ldb_kv);
		return ldb_oom(ldb);
	}
	lmdb->ldb = ldb;
	ldb_kv->kv_ops = &lmdb_key_value_ops;

	{
		const char *size = ldb_options_find(
			ldb, ldb->options, "lmdb_env_size");
		if (size != NULL) {
			env_map_size = strtoull(size, NULL, 0);
		}
	}

	ret = lmdb_pvt_open(lmdb, ldb, path, env_map_size, flags);
	if (ret != LDB_SUCCESS) {
		TALLOC_FREE(ldb_kv);
		return ret;
	}

	ldb_kv->lmdb_private = lmdb;
	if (flags & LDB_FLG_RDONLY) {
		ldb_kv->read_only = true;
	}

	/*
	 * This maximum length becomes encoded in the index values so
	 * must never change even if LMDB starts to allow longer keys.
	 * The override option is max_key_len_for_self_test, and is
	 * used for testing only.
	 */
	ldb_kv->max_key_length = LDB_MDB_MAX_KEY_LENGTH;

	return ldb_kv_init_store(
	    ldb_kv, "ldb_mdb backend", ldb, options, _module);
}
