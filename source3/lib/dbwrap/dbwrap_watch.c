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
		DEBUG(1, ("Invalid watchers key\n"));
		return false;
	}
	db_id_len = IVAL(wkey.dptr, 0);
	if (db_id_len > (wkey.dsize - sizeof(uint32_t))) {
		DEBUG(1, ("Invalid watchers key, wkey.dsize=%d, "
			  "db_id_len=%d\n", (int)wkey.dsize, (int)db_id_len));
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

static ssize_t dbwrap_watched_parse(TDB_DATA data, struct server_id *ids,
				    size_t num_ids, bool *pdeleted,
				    TDB_DATA *pdata)
{
	size_t i, num_watchers;
	bool deleted;

	if (data.dsize < sizeof(uint32_t)) {
		/* Fresh or invalid record */
		return -1;
	}

	num_watchers = IVAL(data.dptr, 0);

	deleted = num_watchers & NUM_WATCHERS_DELETED_BIT;
	num_watchers &= NUM_WATCHERS_MASK;

	data.dptr += sizeof(uint32_t);
	data.dsize -= sizeof(uint32_t);

	if (num_watchers > data.dsize/SERVER_ID_BUF_LENGTH) {
		/* Invalid record */
		return -1;
	}

	if (num_watchers > num_ids) {
		/*
		 * Not enough space to store the watchers server_id's.
		 * Just move past all of them to allow the remaining part
		 * of the record to be returned.
		 */
		data.dptr += num_watchers * SERVER_ID_BUF_LENGTH;
		data.dsize -= num_watchers * SERVER_ID_BUF_LENGTH;
		goto done;
	}

	/*
	 * Note, even if marked deleted we still must
	 * return the id's array to allow awoken
	 * watchers to remove themselves.
	 */

	for (i=0; i<num_watchers; i++) {
		server_id_get(&ids[i], data.dptr);
		data.dptr += SERVER_ID_BUF_LENGTH;
		data.dsize -= SERVER_ID_BUF_LENGTH;
	}

done:
	if (deleted) {
		data = (TDB_DATA) {0};
	}
	if (pdata != NULL) {
		*pdata = data;
	}
	if (pdeleted != NULL) {
		*pdeleted = deleted;
	}

	return num_watchers;
}

static ssize_t dbwrap_watched_unparse(const struct server_id *watchers,
				      size_t num_watchers, bool deleted,
				      TDB_DATA data,
				      uint8_t *buf, size_t buflen)
{
	size_t i, len, ofs;
	uint32_t num_watchers_buf;

	if (num_watchers > UINT32_MAX/SERVER_ID_BUF_LENGTH) {
		return -1;
	}

	len = num_watchers * SERVER_ID_BUF_LENGTH;

	len += sizeof(uint32_t);
	if (len < sizeof(uint32_t)) {
		return -1;
	}

	len += data.dsize;
	if (len < data.dsize) {
		return -1;
	}

	if (len > buflen) {
		return len;
	}

	num_watchers_buf = num_watchers;
	if (deleted) {
		num_watchers_buf |= NUM_WATCHERS_DELETED_BIT;
	}

	ofs = 0;
	SIVAL(buf, ofs, num_watchers_buf);
	ofs += 4;

	for (i=0; i<num_watchers; i++) {
		server_id_put(buf+ofs, watchers[i]);
		ofs += SERVER_ID_BUF_LENGTH;
	}

	if ((data.dptr != NULL) && (data.dsize != 0)) {
		memcpy(buf + ofs, data.dptr, data.dsize);
	}

	return len;
}

struct db_watched_ctx {
	struct db_context *backend;
	struct messaging_context *msg;
};

struct db_watched_subrec {
	struct db_record *subrec;
	struct server_id *watchers;
	bool deleted;
};

static NTSTATUS dbwrap_watched_store(struct db_record *rec, TDB_DATA data,
				     int flag);
static NTSTATUS dbwrap_watched_delete(struct db_record *rec);

static struct db_record *dbwrap_watched_fetch_locked(
	struct db_context *db, TALLOC_CTX *mem_ctx, TDB_DATA key)
{
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_watched_ctx);
	struct db_record *rec;
	struct db_watched_subrec *subrec;
	TDB_DATA subrec_value;
	ssize_t num_watchers;

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
	rec->store = dbwrap_watched_store;
	rec->delete_rec = dbwrap_watched_delete;

	subrec_value = dbwrap_record_get_value(subrec->subrec);

	num_watchers = dbwrap_watched_parse(subrec_value, NULL, 0, NULL, NULL);
	if (num_watchers == -1) {
		/* Fresh or invalid record */
		rec->value = (TDB_DATA) { 0 };
		return rec;
	}

	subrec->watchers = talloc_array(subrec, struct server_id,
					num_watchers);
	if (subrec->watchers == NULL) {
		TALLOC_FREE(rec);
		return NULL;
	}

	dbwrap_watched_parse(subrec_value, subrec->watchers, num_watchers,
			     &subrec->deleted, &rec->value);

	return rec;
}

static void dbwrap_watched_wakeup(struct db_record *rec,
				  struct db_watched_subrec *subrec)
{
	struct db_context *db = dbwrap_record_get_db(rec);
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_watched_ctx);
	size_t i, num_watchers;
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

	num_watchers = talloc_array_length(subrec->watchers);

	i = 0;

	while (i < num_watchers) {
		NTSTATUS status;
		struct server_id_buf tmp;

		DBG_DEBUG("Alerting %s\n",
			  server_id_str_buf(subrec->watchers[i], &tmp));

		status = messaging_send_iov(ctx->msg, subrec->watchers[i],
					    MSG_DBWRAP_MODIFIED,
					    iov, ARRAY_SIZE(iov), NULL, 0);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("messaging_send_iov to %s failed: %s\n",
				  server_id_str_buf(subrec->watchers[i], &tmp),
				  nt_errstr(status));
		}
		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			subrec->watchers[i] = subrec->watchers[num_watchers-1];
			num_watchers -= 1;

			subrec->watchers = talloc_realloc(
				subrec, subrec->watchers, struct server_id,
				num_watchers);
			continue;
		}

		i += 1;
	}
}

static NTSTATUS dbwrap_watched_save(struct db_watched_subrec *subrec,
				    TDB_DATA data, int flag)
{
	size_t num_watchers;
	ssize_t len;
	uint8_t *buf;
	NTSTATUS status;

	num_watchers = talloc_array_length(subrec->watchers);

	len = dbwrap_watched_unparse(subrec->watchers, num_watchers,
				     subrec->deleted, data, NULL, 0);
	if (len == -1) {
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	buf = talloc_array(subrec, uint8_t, len);
	if (buf == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	dbwrap_watched_unparse(subrec->watchers, num_watchers,
			       subrec->deleted, data, buf, len);

	status = dbwrap_record_store(
		subrec->subrec, (TDB_DATA) { .dptr = buf, .dsize = len },
		flag);

	TALLOC_FREE(buf);

	return status;
}

static NTSTATUS dbwrap_watched_store(struct db_record *rec, TDB_DATA data,
				     int flag)
{
	struct db_watched_subrec *subrec = talloc_get_type_abort(
		rec->private_data, struct db_watched_subrec);

	dbwrap_watched_wakeup(rec, subrec);

	subrec->deleted = false;

	return dbwrap_watched_save(subrec, data, flag);

}

static NTSTATUS dbwrap_watched_delete(struct db_record *rec)
{
	struct db_watched_subrec *subrec = talloc_get_type_abort(
		rec->private_data, struct db_watched_subrec);
	size_t num_watchers;

	dbwrap_watched_wakeup(rec, subrec);

	num_watchers = talloc_array_length(subrec->watchers);
	if (num_watchers == 0) {
		return dbwrap_record_delete(subrec->subrec);
	}

	subrec->deleted = true;

	return dbwrap_watched_save(subrec, (TDB_DATA) {0}, 0);
}

struct dbwrap_watched_traverse_state {
	int (*fn)(struct db_record *rec, void *private_data);
	void *private_data;
};

static int dbwrap_watched_traverse_fn(struct db_record *rec,
				      void *private_data)
{
	struct dbwrap_watched_traverse_state *state = private_data;
	ssize_t num_watchers;
	struct db_record prec = *rec;
	bool deleted;

	num_watchers = dbwrap_watched_parse(rec->value, NULL, 0, &deleted,
					    &prec.value);

	if ((num_watchers == -1) || deleted) {
		return 0;
	}

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
	ssize_t num_watchers;
	TDB_DATA userdata;

	num_watchers = dbwrap_watched_parse(data, NULL, 0, &state->deleted,
					    &userdata);
	if ((num_watchers == -1) || state->deleted) {
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
				   struct db_context *backend,
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

	db->lock_order = backend->lock_order;
	backend->lock_order = DBWRAP_LOCK_ORDER_NONE;
	ctx->backend = talloc_move(ctx, &backend);

	db->fetch_locked = dbwrap_watched_fetch_locked;
	db->traverse = dbwrap_watched_traverse;
	db->traverse_read = dbwrap_watched_traverse_read;
	db->get_seqnum = dbwrap_watched_get_seqnum;
	db->transaction_start = dbwrap_watched_transaction_start;
	db->transaction_commit = dbwrap_watched_transaction_commit;
	db->transaction_cancel = dbwrap_watched_transaction_cancel;
	db->parse_record = dbwrap_watched_parse_record;
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
	struct db_watched_subrec *subrec = talloc_get_type_abort(
		rec->private_data, struct db_watched_subrec);
	struct db_context *db = dbwrap_record_get_db(rec);
	struct db_watched_ctx *ctx = talloc_get_type_abort(
		db->private_data, struct db_watched_ctx);

	struct tevent_req *req, *subreq;
	struct dbwrap_watched_watch_state *state;
	ssize_t needed;
	size_t num_watchers;
	struct server_id *tmp;
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

	num_watchers = talloc_array_length(subrec->watchers);

	tmp = talloc_realloc(subrec, subrec->watchers, struct server_id,
			     num_watchers + 1);
	if (tevent_req_nomem(tmp, req)) {
		return tevent_req_post(req, ev);
	}
	subrec->watchers = tmp;
	subrec->watchers[num_watchers] = state->me;

	status = dbwrap_watched_save(subrec, rec->value, 0);
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

static bool dbwrap_watched_remove_waiter(struct db_watched_subrec *subrec,
					 struct server_id id)
{
	size_t i, num_watchers;

	num_watchers = talloc_array_length(subrec->watchers);

	for (i=0; i<num_watchers; i++) {
		if (server_id_equal(&id, &subrec->watchers[i])) {
			break;
		}
	}

	if (i == num_watchers) {
		DBG_WARNING("Did not find id in state->watchers\n");
		return false;
	}

	subrec->watchers[i] = subrec->watchers[num_watchers-1];
	subrec->watchers = talloc_realloc(subrec, subrec->watchers,
					  struct server_id, num_watchers-1);

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

	ok = dbwrap_watched_remove_waiter(subrec, state->me);
	if (ok) {
		NTSTATUS status;
		status = dbwrap_watched_save(subrec, rec->value, 0);
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
				   TALLOC_CTX *mem_ctx,
				   struct db_record **prec,
				   bool *blockerdead,
				   struct server_id *blocker)
{
	struct dbwrap_watched_watch_state *state = tevent_req_data(
		req, struct dbwrap_watched_watch_state);
	struct db_watched_subrec *subrec;
	NTSTATUS status;
	TDB_DATA key;
	struct db_record *rec;
	bool ok;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	if (blockerdead != NULL) {
		*blockerdead = state->blockerdead;
	}
	if (blocker != NULL) {
		*blocker = state->blocker;
	}
	if (prec == NULL) {
		return NT_STATUS_OK;
	}

	ok = dbwrap_record_watchers_key_parse(state->w_key, NULL, NULL, &key);
	if (!ok) {
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	rec = dbwrap_fetch_locked(state->db, mem_ctx, key);
	if (rec == NULL) {
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	talloc_set_destructor(state, NULL);

	subrec = talloc_get_type_abort(
		rec->private_data, struct db_watched_subrec);

	ok = dbwrap_watched_remove_waiter(subrec, state->me);
	if (ok) {
		status = dbwrap_watched_save(subrec, rec->value, 0);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("dbwrap_watched_save failed: %s\n",
				    nt_errstr(status));
		}
	}

	*prec = rec;
	return NT_STATUS_OK;
}
