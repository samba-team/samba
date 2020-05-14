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

struct db_watched_subrec {
	struct db_record *subrec;
	struct dbwrap_watcher added;
};

static NTSTATUS dbwrap_watched_subrec_storev(
	struct db_record *rec, struct db_watched_subrec *subrec,
	const TDB_DATA *dbufs, int num_dbufs, int flags);
static NTSTATUS dbwrap_watched_subrec_delete(
	struct db_record *rec, struct db_watched_subrec *subrec);
static NTSTATUS dbwrap_watched_storev(struct db_record *rec,
				      const TDB_DATA *dbufs, int num_dbufs,
				      int flags);
static NTSTATUS dbwrap_watched_delete(struct db_record *rec);
static void dbwrap_watched_subrec_wakeup(
	struct db_record *rec, struct db_watched_subrec *subrec);
static int db_watched_subrec_destructor(struct db_watched_subrec *s);

static struct db_record *dbwrap_watched_fetch_locked(
	struct db_context *db, TALLOC_CTX *mem_ctx, TDB_DATA key)
{
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_watched_ctx);
	struct db_record *rec;
	struct db_watched_subrec *subrec;
	TDB_DATA subrec_value;
	bool ok;

	rec = talloc_zero(mem_ctx, struct db_record);
	if (rec == NULL) {
		return NULL;
	}
	subrec = talloc_zero(rec, struct db_watched_subrec);
	if (subrec == NULL) {
		TALLOC_FREE(rec);
		return NULL;
	}
	talloc_set_destructor(subrec, db_watched_subrec_destructor);
	rec->private_data = subrec;

	subrec->subrec = dbwrap_fetch_locked(ctx->backend, subrec, key);
	if (subrec->subrec == NULL) {
		TALLOC_FREE(rec);
		return NULL;
	}

	rec->db = db;
	rec->key = dbwrap_record_get_key(subrec->subrec);
	rec->storev = dbwrap_watched_storev;
	rec->delete_rec = dbwrap_watched_delete;

	subrec_value = dbwrap_record_get_value(subrec->subrec);

	ok = dbwrap_watch_rec_parse(subrec_value, NULL, NULL, &rec->value);
	if (!ok) {
		dbwrap_watch_log_invalid_record(db, rec->key, subrec_value);
		/* wipe invalid data */
		rec->value = (TDB_DATA) { .dptr = NULL, .dsize = 0 };
	}
	rec->value_valid = true;

	return rec;
}

struct dbwrap_watched_add_watcher_state {
	struct dbwrap_watcher w;
	NTSTATUS status;
};

static void dbwrap_watched_add_watcher(
	struct db_record *rec,
	TDB_DATA value,
	void *private_data)
{
	struct dbwrap_watched_add_watcher_state *state = private_data;
	size_t num_watchers = 0;
	bool ok;

	uint8_t num_watchers_buf[4];
	uint8_t add_buf[DBWRAP_WATCHER_BUF_LENGTH];

	TDB_DATA dbufs[4] = {
		{
			.dptr = num_watchers_buf,
			.dsize = sizeof(num_watchers_buf),
		},
		{ 0 },		/* filled in with existing watchers */
		{
			.dptr = add_buf,
			.dsize = sizeof(add_buf),
		},
		{ 0 },		/* filled in with existing data */
	};

	dbwrap_watcher_put(add_buf, &state->w);

	ok = dbwrap_watch_rec_parse(
		value, &dbufs[1].dptr, &num_watchers, &dbufs[3]);
	if (!ok) {
		struct db_context *db = dbwrap_record_get_db(rec);
		TDB_DATA key = dbwrap_record_get_key(rec);

		dbwrap_watch_log_invalid_record(db, key, value);

		/* wipe invalid data */
		num_watchers = 0;
		dbufs[3] = (TDB_DATA) { .dptr = NULL, .dsize = 0 };
	}

	dbufs[1].dsize = num_watchers * DBWRAP_WATCHER_BUF_LENGTH;

	if (num_watchers >= UINT32_MAX) {
		DBG_DEBUG("Can't handle %zu watchers\n",
			  num_watchers+1);
		state->status = NT_STATUS_INSUFFICIENT_RESOURCES;
		return;
	}

	num_watchers += 1;
	SIVAL(num_watchers_buf, 0, num_watchers);

	state->status = dbwrap_record_storev(rec, dbufs, ARRAY_SIZE(dbufs), 0);
}

static int db_watched_subrec_destructor(struct db_watched_subrec *s)
{
	struct dbwrap_watched_add_watcher_state state = { .w = s->added };
	struct db_context *backend = dbwrap_record_get_db(s->subrec);
	NTSTATUS status;

	if (s->added.pid.pid == 0) {
		return 0;
	}

	status = dbwrap_do_locked(
		backend, s->subrec->key, dbwrap_watched_add_watcher, &state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("dbwrap_do_locked failed: %s\n",
			    nt_errstr(status));
		return 0;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		DBG_WARNING("dbwrap_watched_add_watcher failed: %s\n",
			    nt_errstr(state.status));
		return 0;
	}
	return 0;
}

struct dbwrap_watched_subrec_wakeup_state {
	struct messaging_context *msg_ctx;
};
static void dbwrap_watched_subrec_wakeup_fn(
	struct db_record *rec,
	TDB_DATA value,
	void *private_data);

struct dbwrap_watched_do_locked_state {
	struct db_context *db;
	void (*fn)(struct db_record *rec,
		   TDB_DATA value,
		   void *private_data);
	void *private_data;

	struct db_watched_subrec subrec;

	/*
	 * This contains the initial value we got
	 * passed to dbwrap_watched_do_locked_fn()
	 *
	 * It's only used in order to pass it
	 * to dbwrap_watched_subrec_wakeup_fn()
	 * in dbwrap_watched_do_locked_{storev,delete}()
	 *
	 * It gets cleared after the first call to
	 * dbwrap_watched_subrec_wakeup_fn() as we
	 * only need to wakeup once per dbwrap_do_locked().
	 */
	TDB_DATA wakeup_value;

	NTSTATUS status;
};

static NTSTATUS dbwrap_watched_do_locked_storev(
	struct db_record *rec, const TDB_DATA *dbufs, int num_dbufs,
	int flags)
{
	struct dbwrap_watched_do_locked_state *state = rec->private_data;
	struct db_watched_subrec *subrec = &state->subrec;
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		state->db->private_data, struct db_watched_ctx);
	struct dbwrap_watched_subrec_wakeup_state wakeup_state = {
		.msg_ctx = ctx->msg,
	};
	NTSTATUS status;

	/*
	 * Wakeup only needs to happen once.
	 * so we clear state->wakeup_value after the first run
	 */
	dbwrap_watched_subrec_wakeup_fn(rec, state->wakeup_value, &wakeup_state);
	state->wakeup_value = (TDB_DATA) { .dsize = 0, };

	status = dbwrap_watched_subrec_storev(rec, subrec, dbufs, num_dbufs,
					      flags);
	return status;
}

static NTSTATUS dbwrap_watched_do_locked_delete(struct db_record *rec)
{
	struct dbwrap_watched_do_locked_state *state = rec->private_data;
	struct db_watched_subrec *subrec = &state->subrec;
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		state->db->private_data, struct db_watched_ctx);
	struct dbwrap_watched_subrec_wakeup_state wakeup_state = {
		.msg_ctx = ctx->msg,
	};
	NTSTATUS status;

	/*
	 * Wakeup only needs to happen once.
	 * so we clear state->wakeup_value after the first run
	 */
	dbwrap_watched_subrec_wakeup_fn(rec, state->wakeup_value, &wakeup_state);
	state->wakeup_value = (TDB_DATA) { .dsize = 0, };

	status = dbwrap_watched_subrec_delete(rec, subrec);
	return status;
}

static void dbwrap_watched_do_locked_fn(
	struct db_record *subrec,
	TDB_DATA subrec_value,
	void *private_data)
{
	struct dbwrap_watched_do_locked_state *state =
		(struct dbwrap_watched_do_locked_state *)private_data;
	TDB_DATA value = {0};
	struct db_record rec = {
		.db = state->db,
		.key = dbwrap_record_get_key(subrec),
		.value_valid = true,
		.storev = dbwrap_watched_do_locked_storev,
		.delete_rec = dbwrap_watched_do_locked_delete,
		.private_data = state
	};
	bool ok;

	state->subrec = (struct db_watched_subrec) {
		.subrec = subrec
	};
	state->wakeup_value = subrec_value;

	ok = dbwrap_watch_rec_parse(subrec_value, NULL, NULL, &value);
	if (!ok) {
		dbwrap_watch_log_invalid_record(rec.db, rec.key, subrec_value);
		/* wipe invalid data */
		value = (TDB_DATA) { .dptr = NULL, .dsize = 0 };
	}

	state->fn(&rec, value, state->private_data);

	db_watched_subrec_destructor(&state->subrec);
}

static NTSTATUS dbwrap_watched_do_locked(struct db_context *db, TDB_DATA key,
					 void (*fn)(struct db_record *rec,
						    TDB_DATA value,
						    void *private_data),
					 void *private_data)
{
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_watched_ctx);
	struct dbwrap_watched_do_locked_state state = {
		.db = db, .fn = fn, .private_data = private_data
	};
	NTSTATUS status;

	status = dbwrap_do_locked(
		ctx->backend, key, dbwrap_watched_do_locked_fn, &state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dbwrap_do_locked returned %s\n", nt_errstr(status));
		return status;
	}

	DBG_DEBUG("dbwrap_watched_do_locked_fn returned %s\n",
		  nt_errstr(state.status));

	return state.status;
}

static void dbwrap_watched_subrec_wakeup_fn(
	struct db_record *rec,
	TDB_DATA value,
	void *private_data)
{
	struct dbwrap_watched_subrec_wakeup_state *state = private_data;
	uint8_t *watchers;
	size_t num_watchers = 0;
	size_t i;
	bool ok;

	ok = dbwrap_watch_rec_parse(value, &watchers, &num_watchers, NULL);
	if (!ok) {
		struct db_context *db = dbwrap_record_get_db(rec);
		TDB_DATA key = dbwrap_record_get_key(rec);
		dbwrap_watch_log_invalid_record(db, key, value);
		return;
	}

	if (num_watchers == 0) {
		DBG_DEBUG("No watchers\n");
		return;
	}

	for (i=0; i<num_watchers; i++) {
		struct dbwrap_watcher watcher;
		struct server_id_buf tmp;
		uint8_t instance_buf[8];
		NTSTATUS status;

		dbwrap_watcher_get(
			&watcher, watchers + i*DBWRAP_WATCHER_BUF_LENGTH);

		DBG_DEBUG("Alerting %s:%"PRIu64"\n",
			  server_id_str_buf(watcher.pid, &tmp),
			  watcher.instance);

		SBVAL(instance_buf, 0, watcher.instance);

		status = messaging_send_buf(
			state->msg_ctx,
			watcher.pid,
			MSG_DBWRAP_MODIFIED,
			instance_buf,
			sizeof(instance_buf));
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("messaging_send_buf to %s failed: %s\n",
				  server_id_str_buf(watcher.pid, &tmp),
				  nt_errstr(status));
		}
	}
}

static void dbwrap_watched_subrec_wakeup(
	struct db_record *rec, struct db_watched_subrec *subrec)
{
	struct db_context *backend = dbwrap_record_get_db(subrec->subrec);
	struct db_context *db = dbwrap_record_get_db(rec);
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_watched_ctx);
	struct dbwrap_watched_subrec_wakeup_state state = {
		.msg_ctx = ctx->msg,
	};
	NTSTATUS status;

	if (rec->storev == dbwrap_watched_do_locked_storev) {
		/*
		 * This is handled in the caller,
		 * as we need to avoid recursion
		 * into dbwrap_do_locked().
		 */
		return;
	}

	status = dbwrap_do_locked(
		backend,
		subrec->subrec->key,
		dbwrap_watched_subrec_wakeup_fn,
		&state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dbwrap_record_modify failed: %s\n",
			  nt_errstr(status));
	}
}

static NTSTATUS dbwrap_watched_subrec_storev(
	struct db_record *rec, struct db_watched_subrec *subrec,
	const TDB_DATA *dbufs, int num_dbufs, int flags)
{
	uint8_t num_watchers_buf[4] = { 0 };
	TDB_DATA my_dbufs[num_dbufs+1];
	NTSTATUS status;

	dbwrap_watched_subrec_wakeup(rec, subrec);

	/*
	 * Watchers only informed once, set num_watchers to 0
	 */
	my_dbufs[0] = (TDB_DATA) {
		.dptr = num_watchers_buf, .dsize = sizeof(num_watchers_buf),
	};
	if (num_dbufs != 0) {
		memcpy(my_dbufs+1, dbufs, num_dbufs * sizeof(*dbufs));
	}

	status = dbwrap_record_storev(
		subrec->subrec, my_dbufs, ARRAY_SIZE(my_dbufs), flags);
	return status;
}

static NTSTATUS dbwrap_watched_storev(struct db_record *rec,
				      const TDB_DATA *dbufs, int num_dbufs,
				      int flags)
{
	struct db_watched_subrec *subrec = talloc_get_type_abort(
		rec->private_data, struct db_watched_subrec);
	NTSTATUS status;

	status = dbwrap_watched_subrec_storev(rec, subrec, dbufs, num_dbufs,
					      flags);
	return status;
}

static NTSTATUS dbwrap_watched_subrec_delete(
	struct db_record *rec, struct db_watched_subrec *subrec)
{
	NTSTATUS status;

	dbwrap_watched_subrec_wakeup(rec, subrec);

	/*
	 * Watchers were informed, we can throw away the record now
	 */
	status = dbwrap_record_delete(subrec->subrec);
	return status;
}

static NTSTATUS dbwrap_watched_delete(struct db_record *rec)
{
	struct db_watched_subrec *subrec = talloc_get_type_abort(
		rec->private_data, struct db_watched_subrec);
	NTSTATUS status;

	status = dbwrap_watched_subrec_delete(rec, subrec);
	return status;
}

struct dbwrap_watched_traverse_state {
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
	prec.value_valid = true;

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
		.fn = fn, .private_data = private_data };
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
		.fn = fn, .private_data = private_data };
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

static void dbwrap_watched_wakeup_fn(
	struct db_record *rec,
	TDB_DATA value,
	void *private_data)
{
	uint8_t num_watchers_buf[4] = { 0 };
	TDB_DATA dbufs[2] = {
		{
			.dptr = num_watchers_buf,
			.dsize = sizeof(num_watchers_buf),
		},
		{ 0 },		/* filled in with existing data */
	};
	NTSTATUS status;
	bool ok;

	dbwrap_watched_subrec_wakeup_fn(rec, value, private_data);

	/*
	 * Watchers are informed only once: Store the existing data
	 * without any watchers
	 */

	ok = dbwrap_watch_rec_parse(value, NULL, NULL, &dbufs[1]);
	if (!ok) {
		DBG_DEBUG("dbwrap_watch_rec_parse failed\n");
		return;
	}

	status = dbwrap_record_storev(rec, dbufs, ARRAY_SIZE(dbufs), 0);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dbwrap_record_storev() failed: %s\n",
			  nt_errstr(status));
	}
}

void dbwrap_watched_wakeup(struct db_record *rec)
{
	struct db_context *db = dbwrap_record_get_db(rec);
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_watched_ctx);
	struct dbwrap_watched_subrec_wakeup_state state = {
		.msg_ctx = ctx->msg,
	};
	NTSTATUS status;

	status = dbwrap_do_locked(
		ctx->backend, rec->key, dbwrap_watched_wakeup_fn, &state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dbwrap_do_locked failed: %s\n",
			  nt_errstr(status));
	}
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
					     struct server_id blocker)
{
	struct db_context *db = dbwrap_record_get_db(rec);
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_watched_ctx);
	struct db_watched_subrec *subrec = NULL;
	struct tevent_req *req, *subreq;
	struct dbwrap_watched_watch_state *state;

	static uint64_t instance = 1;

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

	/*
	 * Figure out whether we're called as part of do_locked. If
	 * so, we can't use talloc_get_type_abort, the
	 * db_watched_subrec is stack-allocated in that case.
	 */

	if (rec->storev == dbwrap_watched_storev) {
		subrec = talloc_get_type_abort(rec->private_data,
					       struct db_watched_subrec);
	}
	if (rec->storev == dbwrap_watched_do_locked_storev) {
		struct dbwrap_watched_do_locked_state *do_locked_state;
		do_locked_state = rec->private_data;
		subrec = &do_locked_state->subrec;
	}
	if (subrec == NULL) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}
	if (subrec->added.pid.pid != 0) {
		tevent_req_nterror(req, NT_STATUS_REQUEST_NOT_ACCEPTED);
		return tevent_req_post(req, ev);
	}

	state->watcher = (struct dbwrap_watcher) {
		.pid = messaging_server_id(ctx->msg),
		.instance = instance++,
	};
	subrec->added = state->watcher;

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
	uint8_t *watchers;
	size_t num_watchers = 0;
	size_t i;
	bool ok;
	NTSTATUS status;

	uint8_t num_watchers_buf[4];

	TDB_DATA dbufs[4] = {
		{
			.dptr = num_watchers_buf,
			.dsize = sizeof(num_watchers_buf),
		},
		{ 0 },		/* watchers "before" state->w */
		{ 0 },		/* watchers "behind" state->w */
		{ 0 },		/* filled in with data */
	};

	ok = dbwrap_watch_rec_parse(
		value, &watchers, &num_watchers, &dbufs[3]);
	if (!ok) {
		status = dbwrap_record_delete(rec);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("dbwrap_record_delete failed: %s\n",
				  nt_errstr(status));
		}
		return;
	}

	for (i=0; i<num_watchers; i++) {
		struct dbwrap_watcher watcher;

		dbwrap_watcher_get(
			&watcher, watchers + i*DBWRAP_WATCHER_BUF_LENGTH);

		if ((state->watcher.instance == watcher.instance) &&
		    server_id_equal(&state->watcher.pid, &watcher.pid)) {
			break;
		}
	}

	if (i == num_watchers) {
		struct server_id_buf buf;
		DBG_DEBUG("Watcher %s:%"PRIu64" not found\n",
			  server_id_str_buf(state->watcher.pid, &buf),
			  state->watcher.instance);
		return;
	}

	if (i > 0) {
		dbufs[1] = (TDB_DATA) {
			.dptr = watchers,
			.dsize = i * DBWRAP_WATCHER_BUF_LENGTH,
		};
	}

	if (i < (num_watchers - 1)) {
		size_t behind = (num_watchers - 1 - i);

		dbufs[2] = (TDB_DATA) {
			.dptr = watchers + (i+1) * DBWRAP_WATCHER_BUF_LENGTH,
			.dsize = behind * DBWRAP_WATCHER_BUF_LENGTH,
		};
	}

	num_watchers -= 1;

	if ((num_watchers == 0) && (dbufs[3].dsize == 0)) {
		status = dbwrap_record_delete(rec);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("dbwrap_record_delete() failed: %s\n",
				  nt_errstr(status));
		}
		return;
	}

	SIVAL(num_watchers_buf, 0, num_watchers);

	status = dbwrap_record_storev(rec, dbufs, ARRAY_SIZE(dbufs), 0);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dbwrap_record_storev() failed: %s\n",
			  nt_errstr(status));
	}
}

static int dbwrap_watched_watch_state_destructor(
	struct dbwrap_watched_watch_state *state)
{
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		state->db->private_data, struct db_watched_ctx);
	NTSTATUS status;

	status = dbwrap_do_locked(
		ctx->backend,
		state->key,
		dbwrap_watched_watch_state_destructor_fn,
		state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dbwrap_do_locked failed: %s\n",
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

	ret = messaging_filtered_read_recv(subreq, talloc_tos(), &rec);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		tevent_req_nterror(req, map_nt_error_from_unix(ret));
		return;
	}
	/*
	 * No need to remove ourselves anymore, we've been removed by
	 * dbwrap_watched_subrec_wakeup().
	 */
	talloc_set_destructor(state, NULL);
	tevent_req_done(req);
}

NTSTATUS dbwrap_watched_watch_recv(struct tevent_req *req,
				   bool *blockerdead,
				   struct server_id *blocker)
{
	struct dbwrap_watched_watch_state *state = tevent_req_data(
		req, struct dbwrap_watched_watch_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	if (blockerdead != NULL) {
		*blockerdead = state->blockerdead;
	}
	if (blocker != NULL) {
		*blocker = state->blocker;
	}
	return NT_STATUS_OK;
}

