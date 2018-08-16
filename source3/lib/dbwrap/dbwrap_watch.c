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

static ssize_t dbwrap_record_watchers_key(struct db_context *db,
					  struct db_record *rec,
					  uint8_t *wkey, size_t wkey_len)
{
	size_t db_id_len = dbwrap_db_id(db, NULL, 0);
	uint8_t db_id[db_id_len];
	size_t needed;
	TDB_DATA key;

	dbwrap_db_id(db, db_id, db_id_len);

	key = dbwrap_record_get_key(rec);

	needed = sizeof(uint32_t) + db_id_len;
	if (needed < sizeof(uint32_t)) {
		return -1;
	}

	needed += key.dsize;
	if (needed < key.dsize) {
		return -1;
	}

	if (wkey_len >= needed) {
		SIVAL(wkey, 0, db_id_len);
		memcpy(wkey + sizeof(uint32_t), db_id, db_id_len);
		memcpy(wkey + sizeof(uint32_t) + db_id_len,
		       key.dptr, key.dsize);
	}

	return needed;
}

static bool dbwrap_record_watchers_key_parse(
	TDB_DATA wkey, uint8_t **p_db_id, size_t *p_db_id_len, TDB_DATA *key)
{
	size_t db_id_len;

	if (wkey.dsize < sizeof(uint32_t)) {
		DBG_WARNING("Invalid watchers key, dsize=%zu\n", wkey.dsize);
		return false;
	}
	db_id_len = IVAL(wkey.dptr, 0);
	if (db_id_len > (wkey.dsize - sizeof(uint32_t))) {
		DBG_WARNING("Invalid watchers key, wkey.dsize=%zu, "
			    "db_id_len=%zu\n", wkey.dsize, db_id_len);
		return false;
	}
	if (p_db_id != NULL) {
		*p_db_id = wkey.dptr + sizeof(uint32_t);
	}
	if (p_db_id_len != NULL) {
		*p_db_id_len = db_id_len;
	}
	if (key != NULL) {
		key->dptr = wkey.dptr + sizeof(uint32_t) + db_id_len;
		key->dsize = wkey.dsize - sizeof(uint32_t) - db_id_len;
	}
	return true;
}

/*
 * Watched records contain a header of:
 *
 * [uint32] num_records | deleted bit
 * 0 [SERVER_ID_BUF_LENGTH]                   \
 * 1 [SERVER_ID_BUF_LENGTH]                   |
 * ..                                         |- Array of watchers
 * (num_records-1)[SERVER_ID_BUF_LENGTH]      /
 *
 * [Remainder of record....]
 *
 * If this header is absent then this is a
 * fresh record of length zero (no watchers).
 *
 * Note that a record can be deleted with
 * watchers present. If so the deleted bit
 * is set and the watcher server_id's are
 * woken to allow them to remove themselves
 * from the watcher array. The record is left
 * present marked with the deleted bit until all
 * watchers are removed, then the record itself
 * is deleted.
 */

#define NUM_WATCHERS_DELETED_BIT (1UL<<31)
#define NUM_WATCHERS_MASK (NUM_WATCHERS_DELETED_BIT-1)

struct dbwrap_watch_rec {
	uint8_t *watchers;
	size_t num_watchers;
	bool deleted;
	TDB_DATA data;
};

static bool dbwrap_watch_rec_parse(TDB_DATA data,
				   struct dbwrap_watch_rec *wrec)
{
	size_t num_watchers;
	bool deleted;
	TDB_DATA userdata = { 0 };

	if (data.dsize < sizeof(uint32_t)) {
		/* Fresh or invalid record */
		return false;
	}

	num_watchers = IVAL(data.dptr, 0);

	deleted = num_watchers & NUM_WATCHERS_DELETED_BIT;
	num_watchers &= NUM_WATCHERS_MASK;

	data.dptr += sizeof(uint32_t);
	data.dsize -= sizeof(uint32_t);

	if (num_watchers > data.dsize/SERVER_ID_BUF_LENGTH) {
		/* Invalid record */
		return false;
	}

	if (!deleted) {
		size_t watchers_len = num_watchers * SERVER_ID_BUF_LENGTH;
		userdata = (TDB_DATA) {
			.dptr = data.dptr + watchers_len,
			.dsize = data.dsize - watchers_len
		};
	}

	*wrec = (struct dbwrap_watch_rec) {
		.watchers = data.dptr, .num_watchers = num_watchers,
		.deleted = deleted, .data = userdata
	};

	return true;
}

static void dbwrap_watch_rec_get_watcher(
	struct dbwrap_watch_rec *wrec, size_t i, struct server_id *watcher)
{
	if (i >= wrec->num_watchers) {
		abort();
	}
	server_id_get(watcher, wrec->watchers + i * SERVER_ID_BUF_LENGTH);
}

static void dbwrap_watch_rec_del_watcher(struct dbwrap_watch_rec *wrec,
					 size_t i)
{
	if (i >= wrec->num_watchers) {
		abort();
	}
	wrec->num_watchers -= 1;
	if (i < wrec->num_watchers) {
		uint8_t *wptr = wrec->watchers + i*SERVER_ID_BUF_LENGTH;
		memcpy(wptr,
		       wrec->watchers+wrec->num_watchers*SERVER_ID_BUF_LENGTH,
		       SERVER_ID_BUF_LENGTH);
	}
}

struct db_watched_ctx {
	struct db_context *backend;
	struct messaging_context *msg;
};

struct db_watched_subrec {
	struct db_record *subrec;
	struct dbwrap_watch_rec wrec;
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
static void dbwrap_watched_wakeup(struct db_record *rec,
				  struct dbwrap_watch_rec *wrec);
static NTSTATUS dbwrap_watched_save(struct db_record *rec,
				    struct dbwrap_watch_rec *wrec,
				    struct server_id *addwatch,
				    const TDB_DATA *databufs,
				    size_t num_databufs,
				    int flags);

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

	ok = dbwrap_watch_rec_parse(subrec_value, &subrec->wrec);
	if (ok) {
		rec->value = subrec->wrec.data;
	}

	return rec;
}

struct dbwrap_watched_do_locked_state {
	TALLOC_CTX *mem_ctx;
	struct db_context *db;
	void (*fn)(struct db_record *rec, void *private_data);
	void *private_data;

	struct db_watched_subrec subrec;

	NTSTATUS status;
};

static NTSTATUS dbwrap_watched_do_locked_storev(
	struct db_record *rec, const TDB_DATA *dbufs, int num_dbufs,
	int flags)
{
	struct dbwrap_watched_do_locked_state *state = rec->private_data;
	struct db_watched_subrec *subrec = &state->subrec;
	NTSTATUS status;

	status = dbwrap_watched_subrec_storev(rec, subrec, dbufs, num_dbufs,
					      flags);
	return status;
}

static NTSTATUS dbwrap_watched_do_locked_delete(struct db_record *rec)
{
	struct dbwrap_watched_do_locked_state *state = rec->private_data;
	struct db_watched_subrec *subrec = &state->subrec;
	NTSTATUS status;

	status = dbwrap_watched_subrec_delete(rec, subrec);
	return status;
}

static void dbwrap_watched_do_locked_fn(struct db_record *subrec,
					void *private_data)
{
	struct dbwrap_watched_do_locked_state *state =
		(struct dbwrap_watched_do_locked_state *)private_data;
	TDB_DATA subrec_value = dbwrap_record_get_value(subrec);
	struct db_record rec;
	bool ok;

	rec = (struct db_record) {
		.db = state->db, .key = dbwrap_record_get_key(subrec),
		.storev = dbwrap_watched_do_locked_storev,
		.delete_rec = dbwrap_watched_do_locked_delete,
		.private_data = state
	};

	state->subrec = (struct db_watched_subrec) {
		.subrec = subrec
	};

	ok = dbwrap_watch_rec_parse(subrec_value, &state->subrec.wrec);
	if (ok) {
		rec.value = state->subrec.wrec.data;
	}

	state->fn(&rec, state->private_data);
}

static NTSTATUS dbwrap_watched_do_locked(struct db_context *db, TDB_DATA key,
					 void (*fn)(struct db_record *rec,
						    void *private_data),
					 void *private_data)
{
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_watched_ctx);
	struct dbwrap_watched_do_locked_state state = {
		.mem_ctx = talloc_stackframe(),
		.db = db, .fn = fn, .private_data = private_data
	};
	NTSTATUS status;

	status = dbwrap_do_locked(
		ctx->backend, key, dbwrap_watched_do_locked_fn, &state);
	TALLOC_FREE(state.mem_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dbwrap_do_locked returned %s\n", nt_errstr(status));
		return status;
	}

	DBG_DEBUG("dbwrap_watched_do_locked_fn returned %s\n",
		  nt_errstr(state.status));

	return state.status;
}

static void dbwrap_watched_wakeup(struct db_record *rec,
				  struct dbwrap_watch_rec *wrec)
{
	struct db_context *db = rec->db;
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_watched_ctx);
	size_t i;
	size_t db_id_len = dbwrap_db_id(db, NULL, 0);
	uint8_t db_id[db_id_len];
	uint8_t len_buf[4];
	struct iovec iov[3];

	SIVAL(len_buf, 0, db_id_len);

	iov[0] = (struct iovec) { .iov_base = len_buf, .iov_len = 4 };
	iov[1] = (struct iovec) { .iov_base = db_id, .iov_len = db_id_len };
	iov[2] = (struct iovec) { .iov_base = rec->key.dptr,
				  .iov_len = rec->key.dsize };

	dbwrap_db_id(db, db_id, db_id_len);

	i = 0;

	while (i < wrec->num_watchers) {
		struct server_id watcher;
		NTSTATUS status;
		struct server_id_buf tmp;

		dbwrap_watch_rec_get_watcher(wrec, i, &watcher);

		DBG_DEBUG("Alerting %s\n", server_id_str_buf(watcher, &tmp));

		status = messaging_send_iov(ctx->msg, watcher,
					    MSG_DBWRAP_MODIFIED,
					    iov, ARRAY_SIZE(iov), NULL, 0);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("messaging_send_iov to %s failed: %s\n",
				  server_id_str_buf(watcher, &tmp),
				  nt_errstr(status));
		}
		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			dbwrap_watch_rec_del_watcher(wrec, i);
			continue;
		}

		i += 1;
	}
}

static NTSTATUS dbwrap_watched_save(struct db_record *rec,
				    struct dbwrap_watch_rec *wrec,
				    struct server_id *addwatch,
				    const TDB_DATA *databufs,
				    size_t num_databufs,
				    int flags)
{
	uint32_t num_watchers_buf;
	uint8_t sizebuf[4];
	uint8_t addbuf[SERVER_ID_BUF_LENGTH];
	NTSTATUS status;
	struct TDB_DATA dbufs[num_databufs+3];

	dbufs[0] = (TDB_DATA) {
		.dptr = sizebuf, .dsize = sizeof(sizebuf)
	};

	dbufs[1] = (TDB_DATA) {
		.dptr = wrec->watchers,
		.dsize = wrec->num_watchers * SERVER_ID_BUF_LENGTH
	};

	if (addwatch != NULL) {
		server_id_put(addbuf, *addwatch);

		dbufs[2] = (TDB_DATA) {
			.dptr = addbuf, .dsize = SERVER_ID_BUF_LENGTH
		};
		wrec->num_watchers += 1;
	} else {
		dbufs[2] = (TDB_DATA) { 0 };
	}

	if (num_databufs != 0) {
		memcpy(&dbufs[3], databufs, sizeof(TDB_DATA) * num_databufs);
	}

	num_watchers_buf = wrec->num_watchers;
	if (wrec->deleted) {
		num_watchers_buf |= NUM_WATCHERS_DELETED_BIT;
	}

	SIVAL(sizebuf, 0, num_watchers_buf);

	status = dbwrap_record_storev(rec, dbufs, ARRAY_SIZE(dbufs), flags);
	return status;
}

static NTSTATUS dbwrap_watched_subrec_storev(
	struct db_record *rec, struct db_watched_subrec *subrec,
	const TDB_DATA *dbufs, int num_dbufs, int flags)
{
	NTSTATUS status;

	dbwrap_watched_wakeup(rec, &subrec->wrec);

	subrec->wrec.deleted = false;

	status = dbwrap_watched_save(subrec->subrec, &subrec->wrec, NULL,
				     dbufs, num_dbufs, flags);
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

	dbwrap_watched_wakeup(rec, &subrec->wrec);

	if (subrec->wrec.num_watchers == 0) {
		return dbwrap_record_delete(subrec->subrec);
	}

	subrec->wrec.deleted = true;

	status = dbwrap_watched_save(subrec->subrec, &subrec->wrec,
				     NULL, NULL, 0, 0);
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
	struct dbwrap_watch_rec wrec;
	bool ok;

	ok = dbwrap_watch_rec_parse(rec->value, &wrec);
	if (!ok || wrec.deleted) {
		return 0;
	}

	prec.value = wrec.data;

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
	void (*parser)(TDB_DATA key, TDB_DATA data, void *private_data);
	void *private_data;
	bool deleted;
};

static void dbwrap_watched_parse_record_parser(TDB_DATA key, TDB_DATA data,
					       void *private_data)
{
	struct dbwrap_watched_parse_record_state *state = private_data;
	struct dbwrap_watch_rec wrec;
	bool ok;

	ok = dbwrap_watch_rec_parse(data, &wrec);
	if ((!ok) || (wrec.deleted)) {
		state->deleted = true;
		return;
	}

	state->parser(key, wrec.data, state->private_data);
}

static NTSTATUS dbwrap_watched_parse_record(
	struct db_context *db, TDB_DATA key,
	void (*parser)(TDB_DATA key, TDB_DATA data, void *private_data),
	void *private_data)
{
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_watched_ctx);
	struct dbwrap_watched_parse_record_state state = {
		.parser = parser,
		.private_data = private_data,
		.deleted = false
	};
	NTSTATUS status;

	status = dbwrap_parse_record(
		ctx->backend, key, dbwrap_watched_parse_record_parser, &state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (state.deleted) {
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
		.deleted = false,
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

	if (state->deleted) {
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

struct dbwrap_watched_watch_state {
	struct db_context *db;
	struct server_id me;
	TDB_DATA w_key;
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
	ssize_t needed;
	NTSTATUS status;

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

	state->me = messaging_server_id(ctx->msg);

	needed = dbwrap_record_watchers_key(db, rec, NULL, 0);
	if (needed == -1) {
		tevent_req_nterror(req, NT_STATUS_INSUFFICIENT_RESOURCES);
		return tevent_req_post(req, ev);
	}
	state->w_key.dsize = needed;

	state->w_key.dptr = talloc_array(state, uint8_t, state->w_key.dsize);
	if (tevent_req_nomem(state->w_key.dptr, req)) {
		return tevent_req_post(req, ev);
	}
	dbwrap_record_watchers_key(db, rec, state->w_key.dptr,
				   state->w_key.dsize);

	subreq = messaging_filtered_read_send(
		state, ev, ctx->msg, dbwrap_watched_msg_filter, state);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, dbwrap_watched_watch_done, req);

	status = dbwrap_watched_save(subrec->subrec, &subrec->wrec, &state->me,
				     &subrec->wrec.data, 1, 0);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	talloc_set_destructor(state, dbwrap_watched_watch_state_destructor);

	if (blocker.pid != 0) {
		subreq = server_id_watch_send(state, ev, ctx->msg, blocker);
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

static bool dbwrap_watched_remove_waiter(struct dbwrap_watch_rec *wrec,
					 struct server_id id)
{
	size_t i;

	for (i=0; i<wrec->num_watchers; i++) {
		struct server_id watcher;
		dbwrap_watch_rec_get_watcher(wrec, i, &watcher);
		if (server_id_equal(&id, &watcher)) {
			break;
		}
	}

	if (i == wrec->num_watchers) {
		struct server_id_buf buf;
		DBG_WARNING("Did not find %s in state->watchers\n",
			    server_id_str_buf(id, &buf));
		return false;
	}

	dbwrap_watch_rec_del_watcher(wrec, i);
	return true;
}

static int dbwrap_watched_watch_state_destructor(
	struct dbwrap_watched_watch_state *state)
{
	struct db_record *rec;
	struct db_watched_subrec *subrec;
	TDB_DATA key;
	bool ok;

	ok = dbwrap_record_watchers_key_parse(state->w_key, NULL, NULL, &key);
	if (!ok) {
		DBG_WARNING("dbwrap_record_watchers_key_parse failed\n");
		return 0;
	}

	rec = dbwrap_fetch_locked(state->db, state, key);
	if (rec == NULL) {
		DBG_WARNING("dbwrap_fetch_locked failed\n");
		return 0;
	}

	subrec = talloc_get_type_abort(
		rec->private_data, struct db_watched_subrec);

	ok = dbwrap_watched_remove_waiter(&subrec->wrec, state->me);
	if (ok) {
		NTSTATUS status;
		status = dbwrap_watched_save(subrec->subrec, &subrec->wrec,
					     NULL, &subrec->wrec.data, 1, 0);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("dbwrap_watched_save failed: %s\n",
				    nt_errstr(status));
		}
	}

	TALLOC_FREE(rec);
	return 0;
}

static bool dbwrap_watched_msg_filter(struct messaging_rec *rec,
				      void *private_data)
{
	struct dbwrap_watched_watch_state *state = talloc_get_type_abort(
		private_data, struct dbwrap_watched_watch_state);
	int cmp;

	if (rec->msg_type != MSG_DBWRAP_MODIFIED) {
		return false;
	}
	if (rec->num_fds != 0) {
		return false;
	}
	if (rec->buf.length != state->w_key.dsize) {
		return false;
	}

	cmp = memcmp(rec->buf.data, state->w_key.dptr, rec->buf.length);

	return (cmp == 0);
}

static void dbwrap_watched_watch_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct messaging_rec *rec;
	int ret;

	ret = messaging_filtered_read_recv(subreq, talloc_tos(), &rec);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		tevent_req_nterror(req, map_nt_error_from_unix(ret));
		return;
	}
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

