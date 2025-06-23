/*
   Unix SMB/CIFS implementation.
   Watch dbwrap record changes
   Copyright (C) Volker Lendecke 2012

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
#include "lib/util/server_id.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap_watch.h"
#include "dbwrap_open.h"
#include "lib/util/util_tdb.h"
#include "lib/util/tevent_ntstatus.h"
#include "serverid.h"
#include "server_id_watch.h"
#include "lib/dbwrap/dbwrap_private.h"

struct dbwrap_watcher {
	/*
	 * Process watching this record
	 */
	struct server_id pid;
	/*
	 * Individual instance inside the waiter, incremented each
	 * time a watcher is created
	 */
	uint64_t instance;
};

#define DBWRAP_WATCHER_BUF_LENGTH (SERVER_ID_BUF_LENGTH + sizeof(uint64_t))
#define DBWRAP_MAX_WATCHERS (INT32_MAX/DBWRAP_WATCHER_BUF_LENGTH)

/*
 * Watched records contain a header of:
 *
 * [uint32] num_records
 * 0 [DBWRAP_WATCHER_BUF_LENGTH]              \
 * 1 [DBWRAP_WATCHER_BUF_LENGTH]              |
 * ..                                         |- Array of watchers
 * (num_records-1)[DBWRAP_WATCHER_BUF_LENGTH] /
 *
 * [Remainder of record....]
 *
 * If this header is absent then this is a
 * fresh record of length zero (no watchers).
 */

static bool dbwrap_watch_rec_parse(
	TDB_DATA data,
	uint8_t **pwatchers,
	size_t *pnum_watchers,
	TDB_DATA *pdata)
{
	size_t num_watchers;

	if (data.dsize == 0) {
		/* Fresh record */
		if (pwatchers != NULL) {
			*pwatchers = NULL;
		}
		if (pnum_watchers != NULL) {
			*pnum_watchers = 0;
		}
		if (pdata != NULL) {
			*pdata = (TDB_DATA) { .dptr = NULL };
		}
		return true;
	}

	if (data.dsize < sizeof(uint32_t)) {
		/* Invalid record */
		return false;
	}

	num_watchers = IVAL(data.dptr, 0);

	data.dptr += sizeof(uint32_t);
	data.dsize -= sizeof(uint32_t);

	if (num_watchers > data.dsize/DBWRAP_WATCHER_BUF_LENGTH) {
		/* Invalid record */
		return false;
	}

	if (pwatchers != NULL) {
		*pwatchers = data.dptr;
	}
	if (pnum_watchers != NULL) {
		*pnum_watchers = num_watchers;
	}
	if (pdata != NULL) {
		size_t watchers_len = num_watchers * DBWRAP_WATCHER_BUF_LENGTH;
		*pdata = (TDB_DATA) {
			.dptr = data.dptr + watchers_len,
			.dsize = data.dsize - watchers_len
		};
	}

	return true;
}

static void dbwrap_watcher_get(struct dbwrap_watcher *w,
			       const uint8_t buf[DBWRAP_WATCHER_BUF_LENGTH])
{
	server_id_get(&w->pid, buf);
	w->instance = BVAL(buf, SERVER_ID_BUF_LENGTH);
}

static void dbwrap_watcher_put(uint8_t buf[DBWRAP_WATCHER_BUF_LENGTH],
			       const struct dbwrap_watcher *w)
{
	server_id_put(buf, w->pid);
	SBVAL(buf, SERVER_ID_BUF_LENGTH, w->instance);
}

static void dbwrap_watch_log_invalid_record(
	struct db_context *db, TDB_DATA key, TDB_DATA value)
{
	DBG_ERR("Found invalid record in %s\n", dbwrap_name(db));
	dump_data(1, key.dptr, key.dsize);
	dump_data(1, value.dptr, value.dsize);
}

struct db_watched_ctx {
	struct db_context *backend;
	struct messaging_context *msg;
};

struct db_watched_record {
	struct db_record *rec;
	struct server_id self;
	struct {
		struct db_record *rec;
		TDB_DATA initial_value;
		bool initial_valid;
	} backend;
	bool force_fini_store;
	struct dbwrap_watcher added;
	bool removed_first;
	struct {
		/*
		 * The is the number of watcher records
		 * parsed from backend.initial_value
		 */
		size_t count;
		/*
		 * This is the pointer to
		 * the optentially first watcher record
		 * parsed from backend.initial_value
		 *
		 * The pointer actually points to memory
		 * in backend.initial_value.
		 *
		 * Note it might be NULL, if count is 0.
		 */
		uint8_t *first;
		/*
		 * This remembers if we already
		 * notified the watchers.
		 *
		 * As we only need to do that once during:
		 *   do_locked
		 * or:
		 *   between rec = fetch_locked
		 *   and
		 *   TALLOC_FREE(rec)
		 */
		bool alerted;
	} watchers;
	struct {
		struct dbwrap_watcher watcher;
	} wakeup;
};

static struct db_watched_record *db_record_get_watched_record(struct db_record *rec)
{
	/*
	 * we can't use wrec = talloc_get_type_abort() here!
	 * because wrec is likely a stack variable in
	 * dbwrap_watched_do_locked_fn()
	 *
	 * In order to have a least some protection
	 * we verify the cross reference pointers
	 * between rec and wrec
	 */
	struct db_watched_record *wrec =
		(struct db_watched_record *)rec->private_data;
	SMB_ASSERT(wrec->rec == rec);
	return wrec;
}

static NTSTATUS dbwrap_watched_record_storev(
	struct db_watched_record *wrec,
	const TDB_DATA *dbufs, int num_dbufs, int flags);
static NTSTATUS dbwrap_watched_storev(struct db_record *rec,
				      const TDB_DATA *dbufs, int num_dbufs,
				      int flags);
static NTSTATUS dbwrap_watched_delete(struct db_record *rec);
static void dbwrap_watched_trigger_wakeup(struct messaging_context *msg_ctx,
					  struct dbwrap_watcher *watcher);
static int db_watched_record_destructor(struct db_watched_record *wrec);

static void db_watched_record_init(struct db_context *db,
				   struct messaging_context *msg_ctx,
				   struct db_record *rec,
				   struct db_watched_record *wrec,
				   struct db_record *backend_rec,
				   TDB_DATA backend_value)
{
	bool ok;

	*rec = (struct db_record) {
		.db = db,
		.key = dbwrap_record_get_key(backend_rec),
		.storev = dbwrap_watched_storev,
		.delete_rec = dbwrap_watched_delete,
		.private_data = wrec,
	};

	*wrec = (struct db_watched_record) {
		.rec = rec,
		.self = messaging_server_id(msg_ctx),
		.backend = {
			.rec = backend_rec,
			.initial_value = backend_value,
			.initial_valid = true,
		},
	};

	ok = dbwrap_watch_rec_parse(backend_value,
				    &wrec->watchers.first,
				    &wrec->watchers.count,
				    &rec->value);
	if (!ok) {
		dbwrap_watch_log_invalid_record(rec->db, rec->key, backend_value);
		/* wipe invalid data */
		rec->value = (TDB_DATA) { .dptr = NULL, .dsize = 0 };
	}
}

static struct db_record *dbwrap_watched_fetch_locked(
	struct db_context *db, TALLOC_CTX *mem_ctx, TDB_DATA key)
{
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_watched_ctx);
	struct db_record *rec = NULL;
	struct db_watched_record *wrec = NULL;
	struct db_record *backend_rec = NULL;
	TDB_DATA backend_value = { .dptr = NULL, };

	rec = talloc_zero(mem_ctx, struct db_record);
	if (rec == NULL) {
		return NULL;
	}
	wrec = talloc_zero(rec, struct db_watched_record);
	if (wrec == NULL) {
		TALLOC_FREE(rec);
		return NULL;
	}

	backend_rec = dbwrap_fetch_locked(ctx->backend, wrec, key);
	if (backend_rec == NULL) {
		TALLOC_FREE(rec);
		return NULL;
	}
	backend_value = dbwrap_record_get_value(backend_rec);

	db_watched_record_init(db, ctx->msg,
			       rec, wrec,
			       backend_rec, backend_value);
	rec->value_valid = true;
	talloc_set_destructor(wrec, db_watched_record_destructor);

	return rec;
}

struct db_watched_record_fini_state {
	struct db_watched_record *wrec;
	TALLOC_CTX *frame;
	TDB_DATA dbufs[2];
	int num_dbufs;
	bool ok;
};

static void db_watched_record_fini_fetcher(TDB_DATA key,
					   TDB_DATA backend_value,
					   void *private_data)
{
	struct db_watched_record_fini_state *state =
		(struct db_watched_record_fini_state *)private_data;
	struct db_watched_record *wrec = state->wrec;
	struct db_record *rec = wrec->rec;
	TDB_DATA value = {};
	bool ok;
	size_t copy_size;

	/*
	 * We're within dbwrap_parse_record()
	 * and backend_value directly points into
	 * the mmap'ed tdb, so we need to copy the
	 * parts we require.
	 */

	ok = dbwrap_watch_rec_parse(backend_value, NULL, NULL, &value);
	if (!ok) {
		struct db_context *db = dbwrap_record_get_db(rec);

		dbwrap_watch_log_invalid_record(db, key, backend_value);

		/* wipe invalid data */
		value = (TDB_DATA) { .dptr = NULL, .dsize = 0 };
	}

	copy_size = MIN(rec->value.dsize, value.dsize);
	if (copy_size != 0) {
		/*
		 * First reuse the buffer we already had
		 * as much as we can.
		 */
		memcpy(rec->value.dptr, value.dptr, copy_size);
		state->dbufs[state->num_dbufs++] = rec->value;
		value.dsize -= copy_size;
		value.dptr += copy_size;
	}

	if (value.dsize != 0) {
		uint8_t *p = NULL;

		/*
		 * There's still new data left
		 * allocate it on callers stackframe
		 */
		p = talloc_memdup(state->frame, value.dptr, value.dsize);
		if (p == NULL) {
			DBG_WARNING("failed to allocate %zu bytes\n",
				    value.dsize);
			return;
		}

		state->dbufs[state->num_dbufs++] = (TDB_DATA) {
			.dptr = p, .dsize = value.dsize,
		};
	}

	state->ok = true;
}

static void db_watched_record_fini(struct db_watched_record *wrec)
{
	struct db_watched_record_fini_state state = { .wrec = wrec, };
	struct db_context *backend = dbwrap_record_get_db(wrec->backend.rec);
	struct db_record *rec = wrec->rec;
	TDB_DATA key = dbwrap_record_get_key(wrec->backend.rec);
	NTSTATUS status;

	if (!wrec->force_fini_store) {
		return;
	}

	if (wrec->backend.initial_valid) {
		if (rec->value.dsize != 0) {
			state.dbufs[state.num_dbufs++] = rec->value;
		}
	} else {
		/*
		 * We need to fetch the current
		 * value from the backend again,
		 * which may need to allocate memory
		 * on the provided stackframe.
		 */

		state.frame = talloc_stackframe();

		status = dbwrap_parse_record(backend, key,
				db_watched_record_fini_fetcher, &state);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("dbwrap_parse_record failed: %s\n",
				    nt_errstr(status));
			TALLOC_FREE(state.frame);
			return;
		}
		if (!state.ok) {
			TALLOC_FREE(state.frame);
			return;
		}
	}

	/*
	 * We don't want to wake up others just because
	 * we added ourself as new watcher. But if we
	 * removed outself from the first position
	 * we need to alert the next one.
	 */
	if (!wrec->removed_first) {
		dbwrap_watched_watch_skip_alerting(rec);
	}

	status = dbwrap_watched_record_storev(wrec, state.dbufs, state.num_dbufs, 0);
	TALLOC_FREE(state.frame);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("dbwrap_watched_record_storev failed: %s\n",
			    nt_errstr(status));
		return;
	}

	return;
}

static int db_watched_record_destructor(struct db_watched_record *wrec)
{
	struct db_record *rec = wrec->rec;
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		rec->db->private_data, struct db_watched_ctx);

	db_watched_record_fini(wrec);
	TALLOC_FREE(wrec->backend.rec);
	dbwrap_watched_trigger_wakeup(ctx->msg, &wrec->wakeup.watcher);
	return 0;
}

struct dbwrap_watched_do_locked_state {
	struct db_context *db;
	struct messaging_context *msg_ctx;
	struct db_watched_record *wrec;
	struct db_record *rec;
	void (*fn)(struct db_record *rec,
		   TDB_DATA value,
		   void *private_data);
	void *private_data;
};

static void dbwrap_watched_do_locked_fn(
	struct db_record *backend_rec,
	TDB_DATA backend_value,
	void *private_data)
{
	struct dbwrap_watched_do_locked_state *state =
		(struct dbwrap_watched_do_locked_state *)private_data;

	db_watched_record_init(state->db, state->msg_ctx,
			       state->rec, state->wrec,
			       backend_rec, backend_value);

	state->fn(state->rec, state->rec->value, state->private_data);

	db_watched_record_fini(state->wrec);
}

static NTSTATUS dbwrap_watched_do_locked(struct db_context *db, TDB_DATA key,
					 void (*fn)(struct db_record *rec,
						    TDB_DATA value,
						    void *private_data),
					 void *private_data)
{
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_watched_ctx);
	struct db_watched_record wrec;
	struct db_record rec;
	struct dbwrap_watched_do_locked_state state = {
		.db = db, .msg_ctx = ctx->msg,
		.rec = &rec, .wrec = &wrec,
		.fn = fn, .private_data = private_data,
	};
	NTSTATUS status;

	status = dbwrap_do_locked(
		ctx->backend, key, dbwrap_watched_do_locked_fn, &state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dbwrap_do_locked returned %s\n", nt_errstr(status));
		return status;
	}

	DBG_DEBUG("dbwrap_watched_do_locked_fn returned\n");

	dbwrap_watched_trigger_wakeup(state.msg_ctx, &wrec.wakeup.watcher);

	return NT_STATUS_OK;
}

static void dbwrap_watched_record_prepare_wakeup(
	struct db_watched_record *wrec)
{
	/*
	 * Wakeup only needs to happen once (if at all)
	 */
	if (wrec->watchers.alerted) {
		/* already done */
		return;
	}
	wrec->watchers.alerted = true;

	if (wrec->watchers.count == 0) {
		DBG_DEBUG("No watchers\n");
		return;
	}

	while (wrec->watchers.count != 0) {
		struct server_id_buf tmp;
		bool exists;

		dbwrap_watcher_get(&wrec->wakeup.watcher, wrec->watchers.first);
		exists = serverid_exists(&wrec->wakeup.watcher.pid);
		if (!exists) {
			DBG_DEBUG("Discard non-existing waiter %s:%"PRIu64"\n",
				  server_id_str_buf(wrec->wakeup.watcher.pid, &tmp),
				  wrec->wakeup.watcher.instance);
			wrec->watchers.first += DBWRAP_WATCHER_BUF_LENGTH;
			wrec->watchers.count -= 1;
			continue;
		}

		/*
		 * We will only wakeup the first waiter, via
		 * dbwrap_watched_trigger_wakeup(), but keep
		 * all (including the first one) in the list that
		 * will be flushed back to the backend record
		 * again. Waiters are removing their entries
		 * via dbwrap_watched_watch_remove_instance()
		 * when they no longer want to monitor the record.
		 */
		DBG_DEBUG("Will alert first waiter %s:%"PRIu64"\n",
			  server_id_str_buf(wrec->wakeup.watcher.pid, &tmp),
			  wrec->wakeup.watcher.instance);
		break;
	}
}

static void dbwrap_watched_trigger_wakeup(struct messaging_context *msg_ctx,
					  struct dbwrap_watcher *watcher)
{
	struct server_id_buf tmp;
	uint8_t instance_buf[8];
	NTSTATUS status;

	if (watcher->instance == 0) {
		DBG_DEBUG("No one to wakeup\n");
		return;
	}

	DBG_DEBUG("Alerting %s:%"PRIu64"\n",
		  server_id_str_buf(watcher->pid, &tmp),
		  watcher->instance);

	SBVAL(instance_buf, 0, watcher->instance);

	status = messaging_send_buf(
		msg_ctx,
		watcher->pid,
		MSG_DBWRAP_MODIFIED,
		instance_buf,
		sizeof(instance_buf));
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("messaging_send_buf to %s failed: %s - ignoring...\n",
			    server_id_str_buf(watcher->pid, &tmp),
			    nt_errstr(status));
	}
}

static NTSTATUS dbwrap_watched_record_storev(
	struct db_watched_record *wrec,
	const TDB_DATA *dbufs, int num_dbufs, int flags)
{
	uint8_t num_watchers_buf[4] = { 0 };
	uint8_t add_buf[DBWRAP_WATCHER_BUF_LENGTH];
	size_t num_store_watchers;
	TDB_DATA my_dbufs[num_dbufs+3];
	int num_my_dbufs = 0;
	NTSTATUS status;
	size_t add_count = 0;

	dbwrap_watched_record_prepare_wakeup(wrec);

	wrec->backend.initial_valid = false;
	wrec->force_fini_store = false;

	if (wrec->added.pid.pid != 0) {
		dbwrap_watcher_put(add_buf, &wrec->added);
		add_count = 1;
	}

	num_store_watchers = wrec->watchers.count + add_count;
	if (num_store_watchers == 0 && num_dbufs == 0) {
		status = dbwrap_record_delete(wrec->backend.rec);
		return status;
	}
	if (num_store_watchers >= DBWRAP_MAX_WATCHERS) {
		DBG_WARNING("Can't handle %zu watchers\n",
			    num_store_watchers);
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	SIVAL(num_watchers_buf, 0, num_store_watchers);

	my_dbufs[num_my_dbufs++] = (TDB_DATA) {
		.dptr = num_watchers_buf, .dsize = sizeof(num_watchers_buf),
	};
	if (wrec->watchers.count != 0) {
		my_dbufs[num_my_dbufs++] = (TDB_DATA) {
			.dptr = wrec->watchers.first, .dsize = wrec->watchers.count * DBWRAP_WATCHER_BUF_LENGTH,
		};
	}
	if (add_count != 0) {
		my_dbufs[num_my_dbufs++] = (TDB_DATA) {
			.dptr = add_buf,
			.dsize = sizeof(add_buf),
		};
	}
	if (num_dbufs != 0) {
		memcpy(my_dbufs+num_my_dbufs, dbufs, num_dbufs * sizeof(*dbufs));
		num_my_dbufs += num_dbufs;
	}

	SMB_ASSERT(num_my_dbufs <= ARRAY_SIZE(my_dbufs));

	status = dbwrap_record_storev(
		wrec->backend.rec, my_dbufs, num_my_dbufs, flags);
	return status;
}

static NTSTATUS dbwrap_watched_storev(struct db_record *rec,
				      const TDB_DATA *dbufs, int num_dbufs,
				      int flags)
{
	struct db_watched_record *wrec = db_record_get_watched_record(rec);

	return dbwrap_watched_record_storev(wrec, dbufs, num_dbufs, flags);
}

static NTSTATUS dbwrap_watched_delete(struct db_record *rec)
{
	struct db_watched_record *wrec = db_record_get_watched_record(rec);

	/*
	 * dbwrap_watched_record_storev() will figure out
	 * if the record should be deleted or if there are still
	 * watchers to be stored.
	 */
	return dbwrap_watched_record_storev(wrec, NULL, 0, 0);
}

struct dbwrap_watched_traverse_state {
	struct db_context *db;
	int (*fn)(struct db_record *rec, void *private_data);
	void *private_data;
};

static int dbwrap_watched_traverse_fn(struct db_record *rec,
				      void *private_data)
{
	struct dbwrap_watched_traverse_state *state = private_data;
	struct db_record prec = *rec;
	bool ok;

	ok = dbwrap_watch_rec_parse(rec->value, NULL, NULL, &prec.value);
	if (!ok) {
		return 0;
	}
	if (prec.value.dsize == 0) {
		return 0;
	}
	prec.value_valid = true;
	prec.db = state->db;

	return state->fn(&prec, state->private_data);
}

static int dbwrap_watched_traverse(struct db_context *db,
				   int (*fn)(struct db_record *rec,
					     void *private_data),
				   void *private_data)
{
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_watched_ctx);
	struct dbwrap_watched_traverse_state state = {
		.db = db, .fn = fn, .private_data = private_data };
	NTSTATUS status;
	int ret;

	status = dbwrap_traverse(
		ctx->backend, dbwrap_watched_traverse_fn, &state, &ret);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}
	return ret;
}

static int dbwrap_watched_traverse_read(struct db_context *db,
					int (*fn)(struct db_record *rec,
						  void *private_data),
					void *private_data)
{
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_watched_ctx);
	struct dbwrap_watched_traverse_state state = {
		.db = db, .fn = fn, .private_data = private_data };
	NTSTATUS status;
	int ret;

	status = dbwrap_traverse_read(
		ctx->backend, dbwrap_watched_traverse_fn, &state, &ret);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}
	return ret;
}

static int dbwrap_watched_get_seqnum(struct db_context *db)
{
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_watched_ctx);
	return dbwrap_get_seqnum(ctx->backend);
}

static int dbwrap_watched_transaction_start(struct db_context *db)
{
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_watched_ctx);
	return dbwrap_transaction_start(ctx->backend);
}

static int dbwrap_watched_transaction_commit(struct db_context *db)
{
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_watched_ctx);
	return dbwrap_transaction_commit(ctx->backend);
}

static int dbwrap_watched_transaction_cancel(struct db_context *db)
{
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_watched_ctx);
	return dbwrap_transaction_cancel(ctx->backend);
}

struct dbwrap_watched_parse_record_state {
	struct db_context *db;
	void (*parser)(TDB_DATA key, TDB_DATA data, void *private_data);
	void *private_data;
	bool ok;
};

static void dbwrap_watched_parse_record_parser(TDB_DATA key, TDB_DATA data,
					       void *private_data)
{
	struct dbwrap_watched_parse_record_state *state = private_data;
	TDB_DATA userdata;

	state->ok = dbwrap_watch_rec_parse(data, NULL, NULL, &userdata);
	if (!state->ok) {
		dbwrap_watch_log_invalid_record(state->db, key, data);
		return;
	}

	state->parser(key, userdata, state->private_data);
}

static NTSTATUS dbwrap_watched_parse_record(
	struct db_context *db, TDB_DATA key,
	void (*parser)(TDB_DATA key, TDB_DATA data, void *private_data),
	void *private_data)
{
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_watched_ctx);
	struct dbwrap_watched_parse_record_state state = {
		.db = db,
		.parser = parser,
		.private_data = private_data,
	};
	NTSTATUS status;

	status = dbwrap_parse_record(
		ctx->backend, key, dbwrap_watched_parse_record_parser, &state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!state.ok) {
		return NT_STATUS_NOT_FOUND;
	}
	return NT_STATUS_OK;
}

static void dbwrap_watched_parse_record_done(struct tevent_req *subreq);

static struct tevent_req *dbwrap_watched_parse_record_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct db_context *db,
	TDB_DATA key,
	void (*parser)(TDB_DATA key, TDB_DATA data, void *private_data),
	void *private_data,
	enum dbwrap_req_state *req_state)
{
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_watched_ctx);
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct dbwrap_watched_parse_record_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct dbwrap_watched_parse_record_state);
	if (req == NULL) {
		*req_state = DBWRAP_REQ_ERROR;
		return NULL;
	}

	*state = (struct dbwrap_watched_parse_record_state) {
		.parser = parser,
		.private_data = private_data,
		.ok = true,
	};

	subreq = dbwrap_parse_record_send(state,
					  ev,
					  ctx->backend,
					  key,
					  dbwrap_watched_parse_record_parser,
					  state,
					  req_state);
	if (tevent_req_nomem(subreq, req)) {
		*req_state = DBWRAP_REQ_ERROR;
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, dbwrap_watched_parse_record_done, req);
	return req;
}

static void dbwrap_watched_parse_record_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct dbwrap_watched_parse_record_state *state = tevent_req_data(
		req, struct dbwrap_watched_parse_record_state);
	NTSTATUS status;

	status = dbwrap_parse_record_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (!state->ok) {
		tevent_req_nterror(req, NT_STATUS_NOT_FOUND);
		return;
	}

	tevent_req_done(req);
	return;
}

static NTSTATUS dbwrap_watched_parse_record_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

static int dbwrap_watched_exists(struct db_context *db, TDB_DATA key)
{
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_watched_ctx);

	return dbwrap_exists(ctx->backend, key);
}

static size_t dbwrap_watched_id(struct db_context *db, uint8_t *id,
				size_t idlen)
{
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_watched_ctx);

	return dbwrap_db_id(ctx->backend, id, idlen);
}

struct db_context *db_open_watched(TALLOC_CTX *mem_ctx,
				   struct db_context **backend,
				   struct messaging_context *msg)
{
	struct db_context *db;
	struct db_watched_ctx *ctx;

	db = talloc_zero(mem_ctx, struct db_context);
	if (db == NULL) {
		return NULL;
	}
	ctx = talloc_zero(db, struct db_watched_ctx);
	if (ctx == NULL) {
		TALLOC_FREE(db);
		return NULL;
	}
	db->private_data = ctx;

	ctx->msg = msg;

	ctx->backend = talloc_move(ctx, backend);
	db->lock_order = ctx->backend->lock_order;
	ctx->backend->lock_order = DBWRAP_LOCK_ORDER_NONE;

	db->fetch_locked = dbwrap_watched_fetch_locked;
	db->do_locked = dbwrap_watched_do_locked;
	db->traverse = dbwrap_watched_traverse;
	db->traverse_read = dbwrap_watched_traverse_read;
	db->get_seqnum = dbwrap_watched_get_seqnum;
	db->transaction_start = dbwrap_watched_transaction_start;
	db->transaction_commit = dbwrap_watched_transaction_commit;
	db->transaction_cancel = dbwrap_watched_transaction_cancel;
	db->parse_record = dbwrap_watched_parse_record;
	db->parse_record_send = dbwrap_watched_parse_record_send;
	db->parse_record_recv = dbwrap_watched_parse_record_recv;
	db->exists = dbwrap_watched_exists;
	db->id = dbwrap_watched_id;
	db->name = dbwrap_name(ctx->backend);

	return db;
}

uint64_t dbwrap_watched_watch_add_instance(struct db_record *rec)
{
	struct db_watched_record *wrec = db_record_get_watched_record(rec);
	static uint64_t global_instance = 1;

	SMB_ASSERT(wrec->added.instance == 0);

	wrec->added = (struct dbwrap_watcher) {
		.pid = wrec->self,
		.instance = global_instance++,
	};

	wrec->force_fini_store = true;

	return wrec->added.instance;
}

void dbwrap_watched_watch_remove_instance(struct db_record *rec, uint64_t instance)
{
	struct db_watched_record *wrec = db_record_get_watched_record(rec);
	struct dbwrap_watcher clear_watcher = {
		.pid = wrec->self,
		.instance = instance,
	};
	size_t i;
	struct server_id_buf buf;

	if (instance == 0) {
		return;
	}

	if (wrec->added.instance == instance) {
		SMB_ASSERT(server_id_equal(&wrec->added.pid, &wrec->self));
		DBG_DEBUG("Watcher %s:%"PRIu64" reverted from adding\n",
			  server_id_str_buf(clear_watcher.pid, &buf),
			  clear_watcher.instance);
		ZERO_STRUCT(wrec->added);
	}

	for (i=0; i < wrec->watchers.count; i++) {
		struct dbwrap_watcher watcher;
		size_t off = i*DBWRAP_WATCHER_BUF_LENGTH;
		size_t next_off;
		size_t full_len;
		size_t move_len;

		dbwrap_watcher_get(&watcher, wrec->watchers.first + off);

		if (clear_watcher.instance != watcher.instance) {
			continue;
		}
		if (!server_id_equal(&clear_watcher.pid, &watcher.pid)) {
			continue;
		}

		wrec->force_fini_store = true;

		if (i == 0) {
			DBG_DEBUG("Watcher %s:%"PRIu64" removed from first position of %zu\n",
				  server_id_str_buf(clear_watcher.pid, &buf),
				  clear_watcher.instance,
				  wrec->watchers.count);
			wrec->watchers.first += DBWRAP_WATCHER_BUF_LENGTH;
			wrec->watchers.count -= 1;
			wrec->removed_first = true;
			return;
		}
		if (i == (wrec->watchers.count-1)) {
			DBG_DEBUG("Watcher %s:%"PRIu64" removed from last position of %zu\n",
				  server_id_str_buf(clear_watcher.pid, &buf),
				  clear_watcher.instance,
				  wrec->watchers.count);
			wrec->watchers.count -= 1;
			return;
		}

		DBG_DEBUG("Watcher %s:%"PRIu64" cleared at position %zu from %zu\n",
			  server_id_str_buf(clear_watcher.pid, &buf),
			  clear_watcher.instance, i+1,
			  wrec->watchers.count);

		next_off = off + DBWRAP_WATCHER_BUF_LENGTH;
		full_len = wrec->watchers.count * DBWRAP_WATCHER_BUF_LENGTH;
		move_len = full_len - next_off;
		memmove(wrec->watchers.first + off,
			wrec->watchers.first + next_off,
			move_len);
		wrec->watchers.count -= 1;
		return;
	}

	DBG_DEBUG("Watcher %s:%"PRIu64" not found in %zu watchers\n",
		  server_id_str_buf(clear_watcher.pid, &buf),
		  clear_watcher.instance,
		  wrec->watchers.count);
	return;
}

void dbwrap_watched_watch_skip_alerting(struct db_record *rec)
{
	struct db_watched_record *wrec = db_record_get_watched_record(rec);

	wrec->wakeup.watcher = (struct dbwrap_watcher) { .instance = 0, };
	wrec->watchers.alerted = true;
}

void dbwrap_watched_watch_reset_alerting(struct db_record *rec)
{
	struct db_watched_record *wrec = db_record_get_watched_record(rec);

	wrec->wakeup.watcher = (struct dbwrap_watcher) { .instance = 0, };
	wrec->watchers.alerted = false;
}

void dbwrap_watched_watch_force_alerting(struct db_record *rec)
{
	struct db_watched_record *wrec = db_record_get_watched_record(rec);

	dbwrap_watched_record_prepare_wakeup(wrec);
}

struct dbwrap_watched_watch_state {
	struct db_context *db;
	TDB_DATA key;
	struct dbwrap_watcher watcher;
	struct server_id blocker;
	bool blockerdead;
};

static bool dbwrap_watched_msg_filter(struct messaging_rec *rec,
				      void *private_data);
static void dbwrap_watched_watch_done(struct tevent_req *subreq);
static void dbwrap_watched_watch_blocker_died(struct tevent_req *subreq);
static int dbwrap_watched_watch_state_destructor(
	struct dbwrap_watched_watch_state *state);

struct tevent_req *dbwrap_watched_watch_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct db_record *rec,
					     uint64_t resumed_instance,
					     struct server_id blocker)
{
	struct db_context *db = dbwrap_record_get_db(rec);
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_watched_ctx);
	struct db_watched_record *wrec = db_record_get_watched_record(rec);
	struct tevent_req *req, *subreq;
	struct dbwrap_watched_watch_state *state;
	uint64_t instance;

	req = tevent_req_create(mem_ctx, &state,
				struct dbwrap_watched_watch_state);
	if (req == NULL) {
		return NULL;
	}
	state->db = db;
	state->blocker = blocker;

	if (ctx->msg == NULL) {
		tevent_req_nterror(req, NT_STATUS_NOT_SUPPORTED);
		return tevent_req_post(req, ev);
	}

	if (resumed_instance == 0 && wrec->added.instance == 0) {
		/*
		 * Adding a new instance
		 */
		instance = dbwrap_watched_watch_add_instance(rec);
	} else if (resumed_instance != 0 && wrec->added.instance == 0) {
		/*
		 * Resuming an existing instance that was
		 * already present before do_locked started
		 */
		instance = resumed_instance;
	} else if (resumed_instance == wrec->added.instance) {
		/*
		 * The caller used dbwrap_watched_watch_add_instance()
		 * already during this do_locked() invocation.
		 */
		instance = resumed_instance;
	} else {
		tevent_req_nterror(req, NT_STATUS_REQUEST_NOT_ACCEPTED);
		return tevent_req_post(req, ev);
	}

	state->watcher = (struct dbwrap_watcher) {
		.pid = messaging_server_id(ctx->msg),
		.instance = instance,
	};

	state->key = tdb_data_talloc_copy(state, rec->key);
	if (tevent_req_nomem(state->key.dptr, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = messaging_filtered_read_send(
		state, ev, ctx->msg, dbwrap_watched_msg_filter, state);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, dbwrap_watched_watch_done, req);

	talloc_set_destructor(state, dbwrap_watched_watch_state_destructor);

	if (blocker.pid != 0) {
		subreq = server_id_watch_send(state, ev, blocker);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(
			subreq, dbwrap_watched_watch_blocker_died, req);
	}

	return req;
}

static void dbwrap_watched_watch_blocker_died(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct dbwrap_watched_watch_state *state = tevent_req_data(
		req, struct dbwrap_watched_watch_state);
	int ret;

	ret = server_id_watch_recv(subreq, NULL);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		tevent_req_nterror(req, map_nt_error_from_unix(ret));
		return;
	}
	state->blockerdead = true;
	tevent_req_done(req);
}

static void dbwrap_watched_watch_state_destructor_fn(
	struct db_record *rec,
	TDB_DATA value,
	void *private_data)
{
	struct dbwrap_watched_watch_state *state = talloc_get_type_abort(
		private_data, struct dbwrap_watched_watch_state);

	/*
	 * Here we just remove ourself from the in memory
	 * watchers array and let db_watched_record_fini()
	 * call dbwrap_watched_record_storev() to do the magic
	 * of writing back the modified in memory copy.
	 */
	dbwrap_watched_watch_remove_instance(rec, state->watcher.instance);
	return;
}

static int dbwrap_watched_watch_state_destructor(
	struct dbwrap_watched_watch_state *state)
{
	NTSTATUS status;

	status = dbwrap_do_locked(
		state->db,
		state->key,
		dbwrap_watched_watch_state_destructor_fn,
		state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("dbwrap_do_locked failed: %s\n",
			    nt_errstr(status));
	}
	return 0;
}

static bool dbwrap_watched_msg_filter(struct messaging_rec *rec,
				      void *private_data)
{
	struct dbwrap_watched_watch_state *state = talloc_get_type_abort(
		private_data, struct dbwrap_watched_watch_state);
	uint64_t instance;

	if (rec->msg_type != MSG_DBWRAP_MODIFIED) {
		return false;
	}
	if (rec->num_fds != 0) {
		return false;
	}

	if (rec->buf.length != sizeof(instance)) {
		DBG_DEBUG("Got size %zu, expected %zu\n",
			  rec->buf.length,
			  sizeof(instance));
		return false;
	}

	instance = BVAL(rec->buf.data, 0);

	if (instance != state->watcher.instance) {
		DBG_DEBUG("Got instance %"PRIu64", expected %"PRIu64"\n",
			  instance,
			  state->watcher.instance);
		return false;
	}

	return true;
}

static void dbwrap_watched_watch_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct dbwrap_watched_watch_state *state = tevent_req_data(
		req, struct dbwrap_watched_watch_state);
	struct messaging_rec *rec;
	int ret;

	ret = messaging_filtered_read_recv(subreq, state, &rec);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		tevent_req_nterror(req, map_nt_error_from_unix(ret));
		return;
	}
	tevent_req_done(req);
}

NTSTATUS dbwrap_watched_watch_recv(struct tevent_req *req,
				   uint64_t *pkeep_instance,
				   bool *blockerdead,
				   struct server_id *blocker)
{
	struct dbwrap_watched_watch_state *state = tevent_req_data(
		req, struct dbwrap_watched_watch_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}
	if (pkeep_instance != NULL) {
		*pkeep_instance = state->watcher.instance;
		/*
		 * No need to remove ourselves anymore,
		 * the caller will take care of removing itself.
		 */
		talloc_set_destructor(state, NULL);
	}
	if (blockerdead != NULL) {
		*blockerdead = state->blockerdead;
	}
	if (blocker != NULL) {
		*blocker = state->blocker;
	}
	tevent_req_received(req);
	return NT_STATUS_OK;
}

