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

static struct db_context *dbwrap_record_watchers_db(void)
{
	static struct db_context *watchers_db;

	if (watchers_db == NULL) {
		watchers_db = db_open(
			NULL, lock_path("dbwrap_watchers.tdb"),	0,
			TDB_CLEAR_IF_FIRST | TDB_INCOMPATIBLE_HASH,
			O_RDWR|O_CREAT, 0600, DBWRAP_LOCK_ORDER_3,
			DBWRAP_FLAG_NONE);
	}
	return watchers_db;
}

static TDB_DATA dbwrap_record_watchers_key(TALLOC_CTX *mem_ctx,
					   struct db_context *db,
					   struct db_record *rec,
					   TDB_DATA *rec_key)
{
	const uint8_t *db_id;
	size_t db_id_len;
	TDB_DATA key, wkey;

	dbwrap_db_id(db, &db_id, &db_id_len);
	key = dbwrap_record_get_key(rec);

	wkey.dsize = sizeof(uint32_t) + db_id_len + key.dsize;
	wkey.dptr = talloc_array(mem_ctx, uint8_t, wkey.dsize);
	if (wkey.dptr == NULL) {
		return make_tdb_data(NULL, 0);
	}
	SIVAL(wkey.dptr, 0, db_id_len);
	memcpy(wkey.dptr + sizeof(uint32_t), db_id, db_id_len);
	memcpy(wkey.dptr + sizeof(uint32_t) + db_id_len, key.dptr, key.dsize);

	if (rec_key != NULL) {
		rec_key->dptr = wkey.dptr + sizeof(uint32_t) + db_id_len;
		rec_key->dsize = key.dsize;
	}

	return wkey;
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
	*p_db_id = wkey.dptr + sizeof(uint32_t);
	*p_db_id_len = db_id_len;
	key->dptr = wkey.dptr + sizeof(uint32_t) + db_id_len;
	key->dsize = wkey.dsize - sizeof(uint32_t) - db_id_len;
	return true;
}

static NTSTATUS dbwrap_record_add_watcher(TDB_DATA w_key, struct server_id id)
{
	struct TALLOC_CTX *frame = talloc_stackframe();
	struct db_context *db;
	struct db_record *rec;
	TDB_DATA value;
	struct server_id *ids;
	size_t num_ids;
	NTSTATUS status;

	db = dbwrap_record_watchers_db();
	if (db == NULL) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}
	rec = dbwrap_fetch_locked(db, talloc_tos(), w_key);
	if (rec == NULL) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}
	value = dbwrap_record_get_value(rec);

	if ((value.dsize % sizeof(struct server_id)) != 0) {
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto fail;
	}

	ids = (struct server_id *)value.dptr;
	num_ids = value.dsize / sizeof(struct server_id);

	ids = talloc_array(talloc_tos(), struct server_id,
			   num_ids + 1);
	if (ids == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}
	memcpy(ids, value.dptr, value.dsize);
	ids[num_ids] = id;
	num_ids += 1;

	status = dbwrap_record_store(
		rec, make_tdb_data((uint8_t *)ids, talloc_get_size(ids)), 0);
fail:
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS dbwrap_record_del_watcher(TDB_DATA w_key, struct server_id id)
{
	struct TALLOC_CTX *frame = talloc_stackframe();
	struct db_context *db;
	struct db_record *rec;
	struct server_id *ids;
	size_t i, num_ids;
	TDB_DATA value;
	NTSTATUS status;

	db = dbwrap_record_watchers_db();
	if (db == NULL) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}
	rec = dbwrap_fetch_locked(db, talloc_tos(), w_key);
	if (rec == NULL) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}
	value = dbwrap_record_get_value(rec);

	if ((value.dsize % sizeof(struct server_id)) != 0) {
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto fail;
	}

	ids = (struct server_id *)value.dptr;
	num_ids = value.dsize / sizeof(struct server_id);

	for (i=0; i<num_ids; i++) {
		if (serverid_equal(&id, &ids[i])) {
			ids[i] = ids[num_ids-1];
			value.dsize -= sizeof(struct server_id);
			break;
		}
	}
	if (value.dsize == 0) {
		status = dbwrap_record_delete(rec);
		goto done;
	}
	status = dbwrap_record_store(rec, value, 0);
fail:
done:
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS dbwrap_record_get_watchers(struct db_context *db,
					   struct db_record *rec,
					   TALLOC_CTX *mem_ctx,
					   struct server_id **p_ids,
					   size_t *p_num_ids)
{
	struct db_context *w_db;
	TDB_DATA key = { 0, };
	TDB_DATA value = { 0, };
	struct server_id *ids;
	NTSTATUS status;

	key = dbwrap_record_watchers_key(talloc_tos(), db, rec, NULL);
	if (key.dptr == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}
	w_db = dbwrap_record_watchers_db();
	if (w_db == NULL) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto fail;
	}
	status = dbwrap_fetch(w_db, mem_ctx, key, &value);
	TALLOC_FREE(key.dptr);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	if ((value.dsize % sizeof(struct server_id)) != 0) {
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto fail;
	}
	ids = (struct server_id *)value.dptr;
	*p_ids = talloc_move(mem_ctx, &ids);
	*p_num_ids = value.dsize / sizeof(struct server_id);
	return NT_STATUS_OK;
fail:
	TALLOC_FREE(key.dptr);
	TALLOC_FREE(value.dptr);
	return status;
}

struct dbwrap_record_watch_state {
	struct tevent_context *ev;
	struct db_context *db;
	struct tevent_req *req;
	struct messaging_context *msg;
	TDB_DATA key;
	TDB_DATA w_key;
};

static bool dbwrap_record_watch_filter(struct messaging_rec *rec,
				       void *private_data);
static void dbwrap_record_watch_done(struct tevent_req *subreq);
static int dbwrap_record_watch_state_destructor(
	struct dbwrap_record_watch_state *state);

struct tevent_req *dbwrap_record_watch_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct db_record *rec,
					    struct messaging_context *msg)
{
	struct tevent_req *req, *subreq;
	struct dbwrap_record_watch_state *state;
	struct db_context *watchers_db;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct dbwrap_record_watch_state);
	if (req == NULL) {
		return NULL;
	}
	state->db = dbwrap_record_get_db(rec);
	state->ev = ev;
	state->req = req;
	state->msg = msg;

	watchers_db = dbwrap_record_watchers_db();
	if (watchers_db == NULL) {
		tevent_req_nterror(req, map_nt_error_from_unix(errno));
		return tevent_req_post(req, ev);
	}

	state->w_key = dbwrap_record_watchers_key(state, state->db, rec,
						  &state->key);
	if (tevent_req_nomem(state->w_key.dptr, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = messaging_filtered_read_send(
		state, ev, state->msg, dbwrap_record_watch_filter, state);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, dbwrap_record_watch_done, req);

	status = dbwrap_record_add_watcher(
		state->w_key, messaging_server_id(state->msg));
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}
	talloc_set_destructor(state, dbwrap_record_watch_state_destructor);

	return req;
}

static bool dbwrap_record_watch_filter(struct messaging_rec *rec,
				       void *private_data)
{
	struct dbwrap_record_watch_state *state = talloc_get_type_abort(
		private_data, struct dbwrap_record_watch_state);

	if (rec->msg_type != MSG_DBWRAP_MODIFIED) {
		return false;
	}
	if (rec->num_fds != 0) {
		return false;
	}
	if (rec->buf.length != state->w_key.dsize) {
		return false;
	}
	return memcmp(rec->buf.data, state->w_key.dptr,	rec->buf.length) == 0;
}

static int dbwrap_record_watch_state_destructor(
	struct dbwrap_record_watch_state *s)
{
	if (s->msg != NULL) {
		dbwrap_record_del_watcher(
			s->w_key, messaging_server_id(s->msg));
	}
	return 0;
}

static void dbwrap_watch_record_stored(struct db_context *db,
				       struct db_record *rec,
				       void *private_data)
{
	struct messaging_context *msg = talloc_get_type_abort(
		private_data, struct messaging_context);
	struct server_id *ids = NULL;
	size_t num_ids = 0;
	TDB_DATA w_key = { 0, };
	NTSTATUS status;
	uint32_t i;

	status = dbwrap_record_get_watchers(db, rec, talloc_tos(),
					    &ids, &num_ids);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		goto done;
	}
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("dbwrap_record_get_watchers failed: %s\n",
			  nt_errstr(status)));
		goto done;
	}
	w_key = dbwrap_record_watchers_key(talloc_tos(), db, rec, NULL);
	if (w_key.dptr == NULL) {
		DEBUG(1, ("dbwrap_record_watchers_key failed\n"));
		goto done;
	}

	for (i=0; i<num_ids; i++) {
		status = messaging_send_buf(msg, ids[i], MSG_DBWRAP_MODIFIED,
					    w_key.dptr, w_key.dsize);
		if (!NT_STATUS_IS_OK(status)) {
			char *str = procid_str_static(&ids[i]);
			DEBUG(1, ("messaging_send to %s failed: %s\n",
				  str, nt_errstr(status)));
			TALLOC_FREE(str);
		}
	}
done:
	TALLOC_FREE(w_key.dptr);
	TALLOC_FREE(ids);
	return;
}

void dbwrap_watch_db(struct db_context *db, struct messaging_context *msg)
{
	dbwrap_set_stored_callback(db, dbwrap_watch_record_stored, msg);
}

static void dbwrap_record_watch_done(struct tevent_req *subreq)
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

NTSTATUS dbwrap_record_watch_recv(struct tevent_req *req,
				  TALLOC_CTX *mem_ctx,
				  struct db_record **prec)
{
	struct dbwrap_record_watch_state *state = tevent_req_data(
		req, struct dbwrap_record_watch_state);
	NTSTATUS status;
	struct db_record *rec;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	if (prec == NULL) {
		return NT_STATUS_OK;
	}
	rec = dbwrap_fetch_locked(state->db, mem_ctx, state->key);
	if (rec == NULL) {
		return NT_STATUS_INTERNAL_DB_ERROR;
	}
	*prec = rec;
	return NT_STATUS_OK;
}

struct dbwrap_watchers_traverse_read_state {
	int (*fn)(const uint8_t *db_id, size_t db_id_len, const TDB_DATA key,
		  const struct server_id *watchers, size_t num_watchers,
		  void *private_data);
	void *private_data;
};

static int dbwrap_watchers_traverse_read_callback(
	struct db_record *rec, void *private_data)
{
	struct dbwrap_watchers_traverse_read_state *state =
		(struct dbwrap_watchers_traverse_read_state *)private_data;
	uint8_t *db_id;
	size_t db_id_len;
	TDB_DATA w_key, key, w_data;
	int res;

	w_key = dbwrap_record_get_key(rec);
	w_data = dbwrap_record_get_value(rec);

	if (!dbwrap_record_watchers_key_parse(w_key, &db_id, &db_id_len,
					      &key)) {
		return 0;
	}
	if ((w_data.dsize % sizeof(struct server_id)) != 0) {
		return 0;
	}
	res = state->fn(db_id, db_id_len, key,
			(struct server_id *)w_data.dptr,
			w_data.dsize / sizeof(struct server_id),
			state->private_data);
	return res;
}

void dbwrap_watchers_traverse_read(
	int (*fn)(const uint8_t *db_id, size_t db_id_len, const TDB_DATA key,
		  const struct server_id *watchers, size_t num_watchers,
		  void *private_data),
	void *private_data)
{
	struct dbwrap_watchers_traverse_read_state state;
	struct db_context *db;

	db = dbwrap_record_watchers_db();
	if (db == NULL) {
		return;
	}
	state.fn = fn;
	state.private_data = private_data;
	dbwrap_traverse_read(db, dbwrap_watchers_traverse_read_callback,
			     &state, NULL);
}

static int dbwrap_wakeall_cb(const uint8_t *db_id, size_t db_id_len,
			     const TDB_DATA key,
			     const struct server_id *watchers,
			     size_t num_watchers,
			     void *private_data)
{
	struct messaging_context *msg = talloc_get_type_abort(
		private_data, struct messaging_context);
	uint32_t i;
	DATA_BLOB blob;

	blob.data = key.dptr;
	blob.length = key.dsize;

	for (i=0; i<num_watchers; i++) {
		messaging_send(msg, watchers[i], MSG_DBWRAP_MODIFIED, &blob);
	}
	return 0;
}

void dbwrap_watchers_wakeall(struct messaging_context *msg)
{
	dbwrap_watchers_traverse_read(dbwrap_wakeall_cb, msg);
}
