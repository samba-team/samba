/*
   Unix SMB/CIFS implementation.
   global locks based on dbwrap and messaging
   Copyright (C) 2009 by Volker Lendecke

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
#include "dbwrap/dbwrap_open.h"
#include "dbwrap/dbwrap_watch.h"
#include "g_lock.h"
#include "util_tdb.h"
#include "../lib/util/tevent_ntstatus.h"
#include "messages.h"
#include "serverid.h"

struct g_lock_ctx {
	struct db_context *db;
	struct messaging_context *msg;
};

/*
 * The "g_lock.tdb" file contains records, indexed by the 0-terminated
 * lockname. The record contains an array of "struct g_lock_rec"
 * structures.
 */

#define G_LOCK_REC_LENGTH (SERVER_ID_BUF_LENGTH+1)

static void g_lock_rec_put(uint8_t buf[G_LOCK_REC_LENGTH],
			   const struct g_lock_rec rec)
{
	SCVAL(buf, 0, rec.lock_type);
	server_id_put(buf+1, rec.pid);
}

static void g_lock_rec_get(struct g_lock_rec *rec,
			   const uint8_t buf[G_LOCK_REC_LENGTH])
{
	rec->lock_type = CVAL(buf, 0);
	server_id_get(&rec->pid, buf+1);
}

struct g_lock {
	uint8_t *recsbuf;
	size_t num_recs;
	uint8_t *data;
	size_t datalen;
};

static bool g_lock_parse(uint8_t *buf, size_t buflen, struct g_lock *lck)
{
	size_t found_recs, data_ofs;

	if (buflen < sizeof(uint32_t)) {
		*lck = (struct g_lock) {0};
		return true;
	}

	found_recs = IVAL(buf, 0);

	buf += sizeof(uint32_t);
	buflen -= sizeof(uint32_t);
	if (found_recs > buflen/G_LOCK_REC_LENGTH) {
		return false;
	}

	data_ofs = found_recs * G_LOCK_REC_LENGTH;

	*lck = (struct g_lock) {
		.recsbuf = buf, .num_recs = found_recs,
		.data = buf+data_ofs, .datalen = buflen-data_ofs
	};

	return true;
}

static void g_lock_get_rec(const struct g_lock *lck,
			   size_t i,
			   struct g_lock_rec *rec)
{
	if (i >= lck->num_recs) {
		abort();
	}
	g_lock_rec_get(rec, lck->recsbuf + i*G_LOCK_REC_LENGTH);
}

static void g_lock_rec_del(struct g_lock *lck, size_t i)
{
	if (i >= lck->num_recs) {
		abort();
	}
	lck->num_recs -= 1;
	if (i < lck->num_recs) {
		uint8_t *recptr = lck->recsbuf + i*G_LOCK_REC_LENGTH;
		memcpy(recptr, lck->recsbuf + lck->num_recs*G_LOCK_REC_LENGTH,
		       G_LOCK_REC_LENGTH);
	}
}

static NTSTATUS g_lock_store(struct db_record *rec, struct g_lock *lck,
			     struct g_lock_rec *add)
{
	uint8_t sizebuf[4];
	uint8_t addbuf[G_LOCK_REC_LENGTH];

	struct TDB_DATA dbufs[] = {
		{ .dptr = sizebuf, .dsize = sizeof(sizebuf) },
		{ .dptr = lck->recsbuf,
		  .dsize = lck->num_recs * G_LOCK_REC_LENGTH },
		{ 0 },
		{ .dptr = lck->data, .dsize = lck->datalen }
	};

	if (add != NULL) {
		g_lock_rec_put(addbuf, *add);

		dbufs[2] = (TDB_DATA) {
			.dptr = addbuf, .dsize = G_LOCK_REC_LENGTH
		};

		lck->num_recs += 1;
	}

	SIVAL(sizebuf, 0, lck->num_recs);

	return dbwrap_record_storev(rec, dbufs, ARRAY_SIZE(dbufs), 0);
}

struct g_lock_ctx *g_lock_ctx_init(TALLOC_CTX *mem_ctx,
				   struct messaging_context *msg)
{
	struct g_lock_ctx *result;
	struct db_context *backend;
	char *db_path;

	result = talloc(mem_ctx, struct g_lock_ctx);
	if (result == NULL) {
		return NULL;
	}
	result->msg = msg;

	db_path = lock_path(talloc_tos(), "g_lock.tdb");
	if (db_path == NULL) {
		TALLOC_FREE(result);
		return NULL;
	}

	backend = db_open(result, db_path, 0,
			  TDB_CLEAR_IF_FIRST|TDB_INCOMPATIBLE_HASH,
			  O_RDWR|O_CREAT, 0600,
			  DBWRAP_LOCK_ORDER_3,
			  DBWRAP_FLAG_NONE);
	TALLOC_FREE(db_path);
	if (backend == NULL) {
		DBG_WARNING("Could not open g_lock.tdb\n");
		TALLOC_FREE(result);
		return NULL;
	}

	result->db = db_open_watched(result, &backend, msg);
	if (result->db == NULL) {
		DBG_WARNING("db_open_watched failed\n");
		TALLOC_FREE(result);
		return NULL;
	}
	return result;
}

static bool g_lock_conflicts(enum g_lock_type l1, enum g_lock_type l2)
{
	/*
	 * Only tested write locks so far. Very likely this routine
	 * needs to be fixed for read locks....
	 */
	if ((l1 == G_LOCK_READ) && (l2 == G_LOCK_READ)) {
		return false;
	}
	return true;
}

static NTSTATUS g_lock_trylock(struct db_record *rec, struct server_id self,
			       enum g_lock_type type,
			       struct server_id *blocker)
{
	TDB_DATA data;
	size_t i;
	struct g_lock lck;
	struct g_lock_rec mylock = {0};
	NTSTATUS status;
	bool modified = false;
	bool ok;

	data = dbwrap_record_get_value(rec);

	ok = g_lock_parse(data.dptr, data.dsize, &lck);
	if (!ok) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	if ((type == G_LOCK_READ) && (lck.num_recs > 0)) {
		struct g_lock_rec check_rec;

		/*
		 * Read locks can stay around forever if the process
		 * dies. Do a heuristic check for process existence:
		 * Check one random process for existence. Hopefully
		 * this will keep runaway read locks under control.
		 */
		i = generate_random() % lck.num_recs;

		g_lock_get_rec(&lck, i, &check_rec);

		if ((check_rec.lock_type == G_LOCK_READ) &&
		    !serverid_exists(&check_rec.pid)) {
			g_lock_rec_del(&lck, i);
			modified = true;
		}
	}

	/*
	 * For the lock upgrade/downgrade case, remove ourselves from
	 * the list. We re-add ourselves later after we checked the
	 * other entries for conflict.
	 */

	for (i=0; i<lck.num_recs; i++) {
		struct g_lock_rec lock;

		g_lock_get_rec(&lck, i, &lock);

		if (serverid_equal(&self, &lock.pid)) {
			if (lock.lock_type == type) {
				status = NT_STATUS_WAS_LOCKED;
				goto done;
			}

			mylock = lock;
			g_lock_rec_del(&lck, i);
			modified = true;
			break;
		}
	}

	/*
	 * Check for conflicts with everybody else. Not a for-loop
	 * because we remove stale entries in the meantime,
	 * decrementing lck.num_recs.
	 */

	i = 0;

	while (i < lck.num_recs) {
		struct g_lock_rec lock;

		g_lock_get_rec(&lck, i, &lock);

		if (g_lock_conflicts(type, lock.lock_type)) {
			struct server_id pid = lock.pid;

			/*
			 * As the serverid_exists might recurse into
			 * the g_lock code, we use
			 * SERVERID_UNIQUE_ID_NOT_TO_VERIFY to avoid the loop
			 */
			pid.unique_id = SERVERID_UNIQUE_ID_NOT_TO_VERIFY;

			if (serverid_exists(&pid)) {
				status = NT_STATUS_LOCK_NOT_GRANTED;
				*blocker = lock.pid;
				goto done;
			}

			/*
			 * Delete stale conflicting entry
			 */
			g_lock_rec_del(&lck, i);
			modified = true;
			continue;
		}
		i++;
	}

	modified = true;

	mylock = (struct g_lock_rec) {
		.pid = self,
		.lock_type = type
	};

	status = NT_STATUS_OK;
done:
	if (modified) {
		NTSTATUS store_status;

		/*
		 * (Re-)add ourselves if needed via non-NULL
		 * g_lock_store argument
		 */

		store_status = g_lock_store(
			rec,
			&lck,
			mylock.pid.pid != 0 ? &mylock : NULL);

		if (!NT_STATUS_IS_OK(store_status)) {
			DBG_WARNING("g_lock_record_store failed: %s\n",
				    nt_errstr(store_status));
			status = store_status;
		}
	}
	return status;
}

struct g_lock_lock_state {
	struct tevent_context *ev;
	struct g_lock_ctx *ctx;
	TDB_DATA key;
	enum g_lock_type type;
};

static void g_lock_lock_retry(struct tevent_req *subreq);

struct g_lock_lock_fn_state {
	struct g_lock_lock_state *state;
	struct server_id self;

	struct tevent_req *watch_req;
	NTSTATUS status;
};

static void g_lock_lock_fn(struct db_record *rec, void *private_data)
{
	struct g_lock_lock_fn_state *state = private_data;
	struct server_id blocker;

	state->status = g_lock_trylock(rec, state->self, state->state->type,
				       &blocker);
	if (!NT_STATUS_EQUAL(state->status, NT_STATUS_LOCK_NOT_GRANTED)) {
		return;
	}

	state->watch_req = dbwrap_watched_watch_send(
		state->state, state->state->ev, rec, blocker);
}

struct tevent_req *g_lock_lock_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct g_lock_ctx *ctx,
				    TDB_DATA key,
				    enum g_lock_type type)
{
	struct tevent_req *req;
	struct g_lock_lock_state *state;
	struct g_lock_lock_fn_state fn_state;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state, struct g_lock_lock_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->ctx = ctx;
	state->key = key;
	state->type = type;

	fn_state = (struct g_lock_lock_fn_state) {
		.state = state, .self = messaging_server_id(ctx->msg)
	};

	status = dbwrap_do_locked(ctx->db, key, g_lock_lock_fn, &fn_state);
	if (tevent_req_nterror(req, status)) {
		DBG_DEBUG("dbwrap_do_locked failed: %s\n",
			  nt_errstr(status));
		return tevent_req_post(req, ev);
	}

	if (NT_STATUS_IS_OK(fn_state.status)) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}
	if (!NT_STATUS_EQUAL(fn_state.status, NT_STATUS_LOCK_NOT_GRANTED)) {
		tevent_req_nterror(req, fn_state.status);
		return tevent_req_post(req, ev);
	}

	if (tevent_req_nomem(fn_state.watch_req, req)) {
		return tevent_req_post(req, ev);
	}

	if (!tevent_req_set_endtime(
		    fn_state.watch_req, state->ev,
		    timeval_current_ofs(5 + sys_random() % 5, 0))) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(fn_state.watch_req, g_lock_lock_retry, req);
	return req;
}

static void g_lock_lock_retry(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct g_lock_lock_state *state = tevent_req_data(
		req, struct g_lock_lock_state);
	struct g_lock_lock_fn_state fn_state;
	NTSTATUS status;

	status = dbwrap_watched_watch_recv(subreq, NULL, NULL);
	DBG_DEBUG("watch_recv returned %s\n", nt_errstr(status));
	TALLOC_FREE(subreq);

	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		tevent_req_nterror(req, status);
		return;
	}

	fn_state = (struct g_lock_lock_fn_state) {
		.state = state, .self = messaging_server_id(state->ctx->msg)
	};

	status = dbwrap_do_locked(state->ctx->db, state->key,
				  g_lock_lock_fn, &fn_state);
	if (tevent_req_nterror(req, status)) {
		DBG_DEBUG("dbwrap_do_locked failed: %s\n",
			  nt_errstr(status));
		return;
	}

	if (NT_STATUS_IS_OK(fn_state.status)) {
		tevent_req_done(req);
		return;
	}
	if (!NT_STATUS_EQUAL(fn_state.status, NT_STATUS_LOCK_NOT_GRANTED)) {
		tevent_req_nterror(req, fn_state.status);
		return;
	}

	if (tevent_req_nomem(fn_state.watch_req, req)) {
		return;
	}

	if (!tevent_req_set_endtime(
		    fn_state.watch_req, state->ev,
		    timeval_current_ofs(5 + sys_random() % 5, 0))) {
		return;
	}
	tevent_req_set_callback(fn_state.watch_req, g_lock_lock_retry, req);
}

NTSTATUS g_lock_lock_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS g_lock_lock(struct g_lock_ctx *ctx, TDB_DATA key,
		     enum g_lock_type type, struct timeval timeout)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	struct timeval end;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = g_lock_lock_send(frame, ev, ctx, key, type);
	if (req == NULL) {
		goto fail;
	}
	end = timeval_current_ofs(timeout.tv_sec, timeout.tv_usec);
	if (!tevent_req_set_endtime(req, ev, end)) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = g_lock_lock_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

struct g_lock_unlock_state {
	TDB_DATA key;
	struct server_id self;
	NTSTATUS status;
};

static void g_lock_unlock_fn(struct db_record *rec,
			     void *private_data)
{
	struct g_lock_unlock_state *state = private_data;
	TDB_DATA value;
	struct g_lock lck;
	size_t i;
	bool ok;

	value = dbwrap_record_get_value(rec);

	ok = g_lock_parse(value.dptr, value.dsize, &lck);
	if (!ok) {
		DBG_DEBUG("g_lock_parse for %s failed\n",
			  hex_encode_talloc(talloc_tos(),
					    state->key.dptr,
					    state->key.dsize));
		state->status = NT_STATUS_FILE_INVALID;
		return;
	}
	for (i=0; i<lck.num_recs; i++) {
		struct g_lock_rec lockrec;
		g_lock_get_rec(&lck, i, &lockrec);
		if (serverid_equal(&state->self, &lockrec.pid)) {
			break;
		}
	}
	if (i == lck.num_recs) {
		DBG_DEBUG("Lock not found, num_rec=%zu\n", lck.num_recs);
		state->status = NT_STATUS_NOT_FOUND;
		return;
	}

	g_lock_rec_del(&lck, i);

	if ((lck.num_recs == 0) && (lck.datalen == 0)) {
		state->status = dbwrap_record_delete(rec);
		return;
	}
	state->status = g_lock_store(rec, &lck, NULL);
}

NTSTATUS g_lock_unlock(struct g_lock_ctx *ctx, TDB_DATA key)
{
	struct g_lock_unlock_state state = {
		.self = messaging_server_id(ctx->msg), .key = key
	};
	NTSTATUS status;

	status = dbwrap_do_locked(ctx->db, key, g_lock_unlock_fn, &state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("dbwrap_do_locked failed: %s\n",
			    nt_errstr(status));
		return status;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		DBG_WARNING("g_lock_unlock_fn failed: %s\n",
			    nt_errstr(state.status));
		return state.status;
	}

	return NT_STATUS_OK;
}

struct g_lock_write_data_state {
	TDB_DATA key;
	struct server_id self;
	const uint8_t *data;
	size_t datalen;
	NTSTATUS status;
};

static void g_lock_write_data_fn(struct db_record *rec,
				 void *private_data)
{
	struct g_lock_write_data_state *state = private_data;
	TDB_DATA value;
	struct g_lock lck;
	size_t i;
	bool ok;

	value = dbwrap_record_get_value(rec);

	ok = g_lock_parse(value.dptr, value.dsize, &lck);
	if (!ok) {
		DBG_DEBUG("g_lock_parse for %s failed\n",
			  hex_encode_talloc(talloc_tos(),
					    state->key.dptr,
					    state->key.dsize));
		state->status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		return;
	}
	for (i=0; i<lck.num_recs; i++) {
		struct g_lock_rec lockrec;
		g_lock_get_rec(&lck, i, &lockrec);
		if ((lockrec.lock_type == G_LOCK_WRITE) &&
		    serverid_equal(&state->self, &lockrec.pid)) {
			break;
		}
	}
	if (i == lck.num_recs) {
		DBG_DEBUG("Not locked by us\n");
		state->status = NT_STATUS_NOT_LOCKED;
		return;
	}

	lck.data = discard_const_p(uint8_t, state->data);
	lck.datalen = state->datalen;
	state->status = g_lock_store(rec, &lck, NULL);
}

NTSTATUS g_lock_write_data(struct g_lock_ctx *ctx, TDB_DATA key,
			   const uint8_t *buf, size_t buflen)
{
	struct g_lock_write_data_state state = {
		.key = key, .self = messaging_server_id(ctx->msg),
		.data = buf, .datalen = buflen
	};
	NTSTATUS status;

	status = dbwrap_do_locked(ctx->db, key,
				  g_lock_write_data_fn, &state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("dbwrap_do_locked failed: %s\n",
			    nt_errstr(status));
		return status;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		DBG_WARNING("g_lock_write_data_fn failed: %s\n",
			    nt_errstr(state.status));
		return state.status;
	}

	return NT_STATUS_OK;
}

struct g_lock_locks_state {
	int (*fn)(TDB_DATA key, void *private_data);
	void *private_data;
};

static int g_lock_locks_fn(struct db_record *rec, void *priv)
{
	TDB_DATA key;
	struct g_lock_locks_state *state = (struct g_lock_locks_state *)priv;

	key = dbwrap_record_get_key(rec);
	return state->fn(key, state->private_data);
}

int g_lock_locks(struct g_lock_ctx *ctx,
		 int (*fn)(TDB_DATA key, void *private_data),
		 void *private_data)
{
	struct g_lock_locks_state state;
	NTSTATUS status;
	int count;

	state.fn = fn;
	state.private_data = private_data;

	status = dbwrap_traverse_read(ctx->db, g_lock_locks_fn, &state, &count);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}
	return count;
}

struct g_lock_dump_state {
	TALLOC_CTX *mem_ctx;
	TDB_DATA key;
	void (*fn)(const struct g_lock_rec *locks,
		   size_t num_locks,
		   const uint8_t *data,
		   size_t datalen,
		   void *private_data);
	void *private_data;
	NTSTATUS status;
};

static void g_lock_dump_fn(TDB_DATA key, TDB_DATA data,
			   void *private_data)
{
	struct g_lock_dump_state *state = private_data;
	struct g_lock_rec *recs;
	struct g_lock lck;
	size_t i;
	bool ok;

	ok = g_lock_parse(data.dptr, data.dsize, &lck);
	if (!ok) {
		DBG_DEBUG("g_lock_parse failed for %s\n",
			  hex_encode_talloc(talloc_tos(),
					    state->key.dptr,
					    state->key.dsize));
		state->status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		return;
	}

	recs = talloc_array(state->mem_ctx, struct g_lock_rec, lck.num_recs);
	if (recs == NULL) {
		DBG_DEBUG("talloc failed\n");
		state->status = NT_STATUS_NO_MEMORY;
		return;
	}

	for (i=0; i<lck.num_recs; i++) {
		g_lock_get_rec(&lck, i, &recs[i]);
	}

	state->fn(recs, lck.num_recs, lck.data, lck.datalen,
		  state->private_data);

	TALLOC_FREE(recs);

	state->status = NT_STATUS_OK;
}

NTSTATUS g_lock_dump(struct g_lock_ctx *ctx, TDB_DATA key,
		     void (*fn)(const struct g_lock_rec *locks,
				size_t num_locks,
				const uint8_t *data,
				size_t datalen,
				void *private_data),
		     void *private_data)
{
	struct g_lock_dump_state state = {
		.mem_ctx = ctx, .key = key,
		.fn = fn, .private_data = private_data
	};
	NTSTATUS status;

	status = dbwrap_parse_record(ctx->db, key, g_lock_dump_fn, &state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dbwrap_parse_record returned %s\n",
			  nt_errstr(status));
		return status;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		DBG_DEBUG("g_lock_dump_fn returned %s\n",
			  nt_errstr(state.status));
		return state.status;
	}
	return NT_STATUS_OK;
}

static bool g_lock_init_all(TALLOC_CTX *mem_ctx,
			    struct tevent_context **pev,
			    struct messaging_context **pmsg,
			    struct g_lock_ctx **pg_ctx)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct g_lock_ctx *g_ctx = NULL;

	ev = samba_tevent_context_init(mem_ctx);
	if (ev == NULL) {
		d_fprintf(stderr, "ERROR: could not init event context\n");
		goto fail;
	}
	msg = messaging_init(mem_ctx, ev);
	if (msg == NULL) {
		d_fprintf(stderr, "ERROR: could not init messaging context\n");
		goto fail;
	}
	g_ctx = g_lock_ctx_init(mem_ctx, msg);
	if (g_ctx == NULL) {
		d_fprintf(stderr, "ERROR: could not init g_lock context\n");
		goto fail;
	}

	*pev = ev;
	*pmsg = msg;
	*pg_ctx = g_ctx;
	return true;
fail:
	TALLOC_FREE(g_ctx);
	TALLOC_FREE(msg);
	TALLOC_FREE(ev);
	return false;
}

NTSTATUS g_lock_do(TDB_DATA key, enum g_lock_type lock_type,
		   struct timeval timeout,
		   void (*fn)(void *private_data), void *private_data)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct g_lock_ctx *g_ctx = NULL;
	NTSTATUS status;

	if (!g_lock_init_all(talloc_tos(), &ev, &msg, &g_ctx)) {
		status = NT_STATUS_ACCESS_DENIED;
		goto done;
	}

	status = g_lock_lock(g_ctx, key, lock_type, timeout);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}
	fn(private_data);
	g_lock_unlock(g_ctx, key);

done:
	TALLOC_FREE(g_ctx);
	TALLOC_FREE(msg);
	TALLOC_FREE(ev);
	return status;
}
