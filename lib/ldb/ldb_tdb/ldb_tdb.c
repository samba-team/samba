/*
   ldb database library

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Stefan Metzmacher 2004
   Copyright (C) Simo Sorce 2006-2008
   Copyright (C) Matthias Dieter Wallnöfer 2009-2010

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

/*
 *  Name: ldb_tdb
 *
 *  Component: ldb tdb backend
 *
 *  Description: core functions for tdb backend
 *
 *  Author: Andrew Tridgell
 *  Author: Stefan Metzmacher
 *
 *  Modifications:
 *
 *  - description: make the module use asynchronous calls
 *    date: Feb 2006
 *    Author: Simo Sorce
 *
 *  - description: make it possible to use event contexts
 *    date: Jan 2008
 *    Author: Simo Sorce
 *
 *  - description: fix up memory leaks and small bugs
 *    date: Oct 2009
 *    Author: Matthias Dieter Wallnöfer
 */

#include "ldb_tdb.h"
#include "ldb_private.h"
#include "../ldb_key_value/ldb_kv.h"
#include <tdb.h>

/*
  lock the database for read - use by ltdb_search and ltdb_sequence_number
*/
static int ltdb_lock_read(struct ldb_module *module)
{
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);
	int tdb_ret = 0;
	int ret;
	pid_t pid = getpid();

	if (ldb_kv->pid != pid) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       __location__
				       ": Reusing ldb opend by pid %d in "
				       "process %d\n",
				       ldb_kv->pid,
				       pid);
		return LDB_ERR_PROTOCOL_ERROR;
	}

	if (tdb_transaction_active(ldb_kv->tdb) == false &&
	    ldb_kv->read_lock_count == 0) {
		tdb_ret = tdb_lockall_read(ldb_kv->tdb);
	}
	if (tdb_ret == 0) {
		ldb_kv->read_lock_count++;
		return LDB_SUCCESS;
	}
	ret = ltdb_err_map(tdb_error(ldb_kv->tdb));
	if (ret == LDB_SUCCESS) {
		ret = LDB_ERR_OPERATIONS_ERROR;
	}
	ldb_debug_set(ldb_module_get_ctx(module),
		      LDB_DEBUG_FATAL,
		      "Failure during ltdb_lock_read(): %s -> %s",
		      tdb_errorstr(ldb_kv->tdb),
		      ldb_strerror(ret));
	return ret;
}

/*
  unlock the database after a ltdb_lock_read()
*/
static int ltdb_unlock_read(struct ldb_module *module)
{
	void *data = ldb_module_get_private(module);
	struct ldb_kv_private *ldb_kv =
	    talloc_get_type(data, struct ldb_kv_private);
	pid_t pid = getpid();

	if (ldb_kv->pid != pid) {
		ldb_asprintf_errstring(ldb_module_get_ctx(module),
				       __location__
				       ": Reusing ldb opend by pid %d in "
				       "process %d\n",
				       ldb_kv->pid,
				       pid);
		return LDB_ERR_PROTOCOL_ERROR;
	}
	if (!tdb_transaction_active(ldb_kv->tdb) &&
	    ldb_kv->read_lock_count == 1) {
		tdb_unlockall_read(ldb_kv->tdb);
		ldb_kv->read_lock_count--;
		return 0;
	}
	ldb_kv->read_lock_count--;
	return 0;
}

static int ltdb_store(struct ldb_kv_private *ldb_kv,
		      struct ldb_val ldb_key,
		      struct ldb_val ldb_data,
		      int flags)
{
	TDB_DATA key = {
		.dptr = ldb_key.data,
		.dsize = ldb_key.length
	};
	TDB_DATA data = {
		.dptr = ldb_data.data,
		.dsize = ldb_data.length
	};
	bool transaction_active = tdb_transaction_active(ldb_kv->tdb);
	if (transaction_active == false){
		return LDB_ERR_PROTOCOL_ERROR;
	}
	return tdb_store(ldb_kv->tdb, key, data, flags);
}

static int ltdb_error(struct ldb_kv_private *ldb_kv)
{
	return ltdb_err_map(tdb_error(ldb_kv->tdb));
}

static const char *ltdb_errorstr(struct ldb_kv_private *ldb_kv)
{
	return tdb_errorstr(ldb_kv->tdb);
}

static int ltdb_delete(struct ldb_kv_private *ldb_kv, struct ldb_val ldb_key)
{
	TDB_DATA tdb_key = {
		.dptr = ldb_key.data,
		.dsize = ldb_key.length
	};
	bool transaction_active = tdb_transaction_active(ldb_kv->tdb);
	if (transaction_active == false){
		return LDB_ERR_PROTOCOL_ERROR;
	}
	return tdb_delete(ldb_kv->tdb, tdb_key);
}

static int ltdb_transaction_start(struct ldb_kv_private *ldb_kv)
{
	pid_t pid = getpid();

	if (ldb_kv->pid != pid) {
		ldb_asprintf_errstring(ldb_module_get_ctx(ldb_kv->module),
				       __location__
				       ": Reusing ldb opend by pid %d in "
				       "process %d\n",
				       ldb_kv->pid,
				       pid);
		return LDB_ERR_PROTOCOL_ERROR;
	}

	return tdb_transaction_start(ldb_kv->tdb);
}

static int ltdb_transaction_cancel(struct ldb_kv_private *ldb_kv)
{
	pid_t pid = getpid();

	if (ldb_kv->pid != pid) {
		ldb_asprintf_errstring(ldb_module_get_ctx(ldb_kv->module),
				       __location__
				       ": Reusing ldb opend by pid %d in "
				       "process %d\n",
				       ldb_kv->pid,
				       pid);
		return LDB_ERR_PROTOCOL_ERROR;
	}

	return tdb_transaction_cancel(ldb_kv->tdb);
}

static int ltdb_transaction_prepare_commit(struct ldb_kv_private *ldb_kv)
{
	pid_t pid = getpid();

	if (ldb_kv->pid != pid) {
		ldb_asprintf_errstring(ldb_module_get_ctx(ldb_kv->module),
				       __location__
				       ": Reusing ldb opend by pid %d in "
				       "process %d\n",
				       ldb_kv->pid,
				       pid);
		return LDB_ERR_PROTOCOL_ERROR;
	}

	return tdb_transaction_prepare_commit(ldb_kv->tdb);
}

static int ltdb_transaction_commit(struct ldb_kv_private *ldb_kv)
{
	pid_t pid = getpid();

	if (ldb_kv->pid != pid) {
		ldb_asprintf_errstring(ldb_module_get_ctx(ldb_kv->module),
				       __location__
				       ": Reusing ldb opend by pid %d in "
				       "process %d\n",
				       ldb_kv->pid,
				       pid);
		return LDB_ERR_PROTOCOL_ERROR;
	}

	return tdb_transaction_commit(ldb_kv->tdb);
}
struct kv_ctx {
	ldb_kv_traverse_fn kv_traverse_fn;
	void *ctx;
	struct ldb_kv_private *ldb_kv;
	int (*parser)(struct ldb_val key,
		      struct ldb_val data,
		      void *private_data);
	int parser_ret;
};

static int ltdb_traverse_fn_wrapper(struct tdb_context *tdb,
				    TDB_DATA tdb_key,
				    TDB_DATA tdb_data,
				    void *ctx)
{
	struct kv_ctx *kv_ctx = ctx;
	struct ldb_val key = {
		.length = tdb_key.dsize,
		.data = tdb_key.dptr,
	};
	struct ldb_val data = {
		.length = tdb_data.dsize,
		.data = tdb_data.dptr,
	};
	return kv_ctx->kv_traverse_fn(kv_ctx->ldb_kv, key, data, kv_ctx->ctx);
}

static int ltdb_traverse_fn(struct ldb_kv_private *ldb_kv,
			    ldb_kv_traverse_fn fn,
			    void *ctx)
{
	struct kv_ctx kv_ctx = {
	    .kv_traverse_fn = fn, .ctx = ctx, .ldb_kv = ldb_kv};
	if (tdb_transaction_active(ldb_kv->tdb)) {
		return tdb_traverse(
		    ldb_kv->tdb, ltdb_traverse_fn_wrapper, &kv_ctx);
	} else {
		return tdb_traverse_read(
		    ldb_kv->tdb, ltdb_traverse_fn_wrapper, &kv_ctx);
	}
}

static int ltdb_update_in_iterate(struct ldb_kv_private *ldb_kv,
				  struct ldb_val ldb_key,
				  struct ldb_val ldb_key2,
				  struct ldb_val ldb_data,
				  void *state)
{
	int tdb_ret;
	struct ldb_context *ldb;
	struct ldb_kv_reindex_context *ctx =
	    (struct ldb_kv_reindex_context *)state;
	struct ldb_module *module = ldb_kv->module;
	TDB_DATA key = {
		.dptr = ldb_key.data,
		.dsize = ldb_key.length
	};
	TDB_DATA key2 = {
		.dptr = ldb_key2.data,
		.dsize = ldb_key2.length
	};
	TDB_DATA data = {
		.dptr = ldb_data.data,
		.dsize = ldb_data.length
	};

	ldb = ldb_module_get_ctx(module);

	tdb_ret = tdb_delete(ldb_kv->tdb, key);
	if (tdb_ret != 0) {
		ldb_debug(ldb,
			  LDB_DEBUG_ERROR,
			  "Failed to delete %*.*s "
			  "for rekey as %*.*s: %s",
			  (int)key.dsize,
			  (int)key.dsize,
			  (const char *)key.dptr,
			  (int)key2.dsize,
			  (int)key2.dsize,
			  (const char *)key.dptr,
			  tdb_errorstr(ldb_kv->tdb));
		ctx->error = ltdb_err_map(tdb_error(ldb_kv->tdb));
		return -1;
	}
	tdb_ret = tdb_store(ldb_kv->tdb, key2, data, 0);
	if (tdb_ret != 0) {
		ldb_debug(ldb,
			  LDB_DEBUG_ERROR,
			  "Failed to rekey %*.*s as %*.*s: %s",
			  (int)key.dsize,
			  (int)key.dsize,
			  (const char *)key.dptr,
			  (int)key2.dsize,
			  (int)key2.dsize,
			  (const char *)key.dptr,
			  tdb_errorstr(ldb_kv->tdb));
		ctx->error = ltdb_err_map(tdb_error(ldb_kv->tdb));
		return -1;
	}
	return tdb_ret;
}

static int ltdb_parse_record_wrapper(TDB_DATA tdb_key,
				     TDB_DATA tdb_data,
				     void *ctx)
{
	struct kv_ctx *kv_ctx = ctx;
	struct ldb_val key = {
		.length = tdb_key.dsize,
		.data = tdb_key.dptr,
	};
	struct ldb_val data = {
		.length = tdb_data.dsize,
		.data = tdb_data.dptr,
	};

	kv_ctx->parser_ret = kv_ctx->parser(key, data, kv_ctx->ctx);
	return kv_ctx->parser_ret;
}

static int ltdb_parse_record(struct ldb_kv_private *ldb_kv,
			     struct ldb_val ldb_key,
			     int (*parser)(struct ldb_val key,
					   struct ldb_val data,
					   void *private_data),
			     void *ctx)
{
	struct kv_ctx kv_ctx = {.parser = parser, .ctx = ctx, .ldb_kv = ldb_kv};
	TDB_DATA key = {
		.dptr = ldb_key.data,
		.dsize = ldb_key.length
	};
	int ret;

	if (tdb_transaction_active(ldb_kv->tdb) == false &&
	    ldb_kv->read_lock_count == 0) {
		return LDB_ERR_PROTOCOL_ERROR;
	}

	ret = tdb_parse_record(
	    ldb_kv->tdb, key, ltdb_parse_record_wrapper, &kv_ctx);
	if (kv_ctx.parser_ret != LDB_SUCCESS) {
		return kv_ctx.parser_ret;
	} else if (ret == 0) {
		return LDB_SUCCESS;
	}
	return ltdb_err_map(tdb_error(ldb_kv->tdb));
}

static int ltdb_iterate_range(struct ldb_kv_private *ldb_kv,
			      struct ldb_val start_key,
			      struct ldb_val end_key,
			      ldb_kv_traverse_fn fn,
			      void *ctx)
{
	/*
	 * We do not implement this operation because we do not know how to
	 * iterate from one key to the next (in a sorted fashion).
	 *
	 * We could mimic it potentially, but it would violate boundaries of
	 * knowledge (data type representation).
	 */
	return LDB_ERR_OPERATIONS_ERROR;
}

static const char *ltdb_name(struct ldb_kv_private *ldb_kv)
{
	return tdb_name(ldb_kv->tdb);
}

static bool ltdb_changed(struct ldb_kv_private *ldb_kv)
{
	int seq = tdb_get_seqnum(ldb_kv->tdb);
	bool has_changed = (seq != ldb_kv->tdb_seqnum);

	ldb_kv->tdb_seqnum = seq;

	return has_changed;
}

static bool ltdb_transaction_active(struct ldb_kv_private *ldb_kv)
{
	return tdb_transaction_active(ldb_kv->tdb);
}

/*
 * Get an estimate of the number of records in a tdb database.
 *
 * This implementation will overestimate the number of records in a sparsely
 * populated database. The size estimate is only used for allocating
 * an in memory tdb to cache index records during a reindex, overestimating
 * the contents is acceptable, and preferable to underestimating
 */
#define RECORD_SIZE 500
static size_t ltdb_get_size(struct ldb_kv_private *ldb_kv)
{
	size_t map_size = tdb_map_size(ldb_kv->tdb);
	size_t size = map_size / RECORD_SIZE;

	return size;
}

/*
 * Start a sub transaction
 * As TDB does not currently support nested transactions, we do nothing and
 * return LDB_SUCCESS
 */
static int ltdb_nested_transaction_start(struct ldb_kv_private *ldb_kv)
{
	return LDB_SUCCESS;
}

/*
 * Commit a sub transaction
 * As TDB does not currently support nested transactions, we do nothing and
 * return LDB_SUCCESS
 */
static int ltdb_nested_transaction_commit(struct ldb_kv_private *ldb_kv)
{
	return LDB_SUCCESS;
}

/*
 * Cancel a sub transaction
 * As TDB does not currently support nested transactions, we do nothing and
 * return LDB_SUCCESS
 */
static int ltdb_nested_transaction_cancel(struct ldb_kv_private *ldb_kv)
{
	return LDB_SUCCESS;
}

static const struct kv_db_ops key_value_ops = {
	/* No support for any additional features */
	.options = 0,

	.store = ltdb_store,
	.delete = ltdb_delete,
	.iterate = ltdb_traverse_fn,
	.update_in_iterate = ltdb_update_in_iterate,
	.fetch_and_parse = ltdb_parse_record,
	.iterate_range = ltdb_iterate_range,
	.lock_read = ltdb_lock_read,
	.unlock_read = ltdb_unlock_read,
	.begin_write = ltdb_transaction_start,
	.prepare_write = ltdb_transaction_prepare_commit,
	.finish_write = ltdb_transaction_commit,
	.abort_write = ltdb_transaction_cancel,
	.error = ltdb_error,
	.errorstr = ltdb_errorstr,
	.name = ltdb_name,
	.has_changed = ltdb_changed,
	.transaction_active = ltdb_transaction_active,
	.get_size = ltdb_get_size,
	.begin_nested_write = ltdb_nested_transaction_start,
	.finish_nested_write = ltdb_nested_transaction_commit,
	.abort_nested_write = ltdb_nested_transaction_cancel,
};

/*
  connect to the database
*/
int ltdb_connect(struct ldb_context *ldb, const char *url,
		 unsigned int flags, const char *options[],
		 struct ldb_module **_module)
{
	const char *path;
	int tdb_flags, open_flags;
	struct ldb_kv_private *ldb_kv;

	/*
	 * We hold locks, so we must use a private event context
	 * on each returned handle
	 */
	ldb_set_require_private_event_context(ldb);

	/* parse the url */
	if (strchr(url, ':')) {
		if (strncmp(url, "tdb://", 6) != 0) {
			ldb_debug(ldb, LDB_DEBUG_ERROR,
				  "Invalid tdb URL '%s'", url);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		path = url+6;
	} else {
		path = url;
	}

	tdb_flags = TDB_DEFAULT | TDB_SEQNUM | TDB_DISALLOW_NESTING;

	/* check for the 'nosync' option */
	if (flags & LDB_FLG_NOSYNC) {
		tdb_flags |= TDB_NOSYNC;
	}

	/* and nommap option */
	if (flags & LDB_FLG_NOMMAP) {
		tdb_flags |= TDB_NOMMAP;
	}

	ldb_kv = talloc_zero(ldb, struct ldb_kv_private);
	if (!ldb_kv) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (flags & LDB_FLG_RDONLY) {
		/*
		 * This is weird, but because we can only have one tdb
		 * in this process, and the other one could be
		 * read-write, we can't use the tdb readonly.  Plus a
		 * read only tdb prohibits the all-record lock.
		 */
		open_flags = O_RDWR;

		ldb_kv->read_only = true;

	} else if (flags & LDB_FLG_DONT_CREATE_DB) {
		/*
		 * This is used by ldbsearch to prevent creation of the database
		 * if the name is wrong
		 */
		open_flags = O_RDWR;
	} else {
		/*
		 * This is the normal case
		 */
		open_flags = O_CREAT | O_RDWR;
	}

	ldb_kv->kv_ops = &key_value_ops;

	errno = 0;
	/* note that we use quite a large default hash size */
	ldb_kv->tdb = ltdb_wrap_open(ldb_kv,
				     path,
				     10000,
				     tdb_flags,
				     open_flags,
				     ldb_get_create_perms(ldb),
				     ldb);
	if (!ldb_kv->tdb) {
		ldb_asprintf_errstring(ldb,
				       "Unable to open tdb '%s': %s", path, strerror(errno));
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "Unable to open tdb '%s': %s", path, strerror(errno));
		talloc_free(ldb_kv);
		if (errno == EACCES || errno == EPERM) {
			return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
		}
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return ldb_kv_init_store(
	    ldb_kv, "ldb_tdb backend", ldb, options, _module);
}
