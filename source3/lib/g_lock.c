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

static ssize_t g_lock_put(uint8_t *buf, size_t buflen,
			  const struct g_lock_rec *locks,
			  size_t num_locks,
			  const uint8_t *data, size_t datalen)
{
	size_t i, len, ofs;

	if (num_locks > UINT32_MAX/G_LOCK_REC_LENGTH) {
		return -1;
	}

	len = num_locks * G_LOCK_REC_LENGTH;

	len += sizeof(uint32_t);
	if (len < sizeof(uint32_t)) {
		return -1;
	}

	len += datalen;
	if (len < datalen) {
		return -1;
	}

	if (len > buflen) {
		return len;
	}

	ofs = 0;
	SIVAL(buf, ofs, num_locks);
	ofs += sizeof(uint32_t);

	for (i=0; i<num_locks; i++) {
		g_lock_rec_put(buf+ofs, locks[i]);
		ofs += G_LOCK_REC_LENGTH;
	}

	if ((data != NULL) && (datalen != 0)) {
		memcpy(buf+ofs, data, datalen);
	}

	return len;
}

static ssize_t g_lock_get(TDB_DATA recval,
			  struct g_lock_rec *locks, size_t num_locks,
			  uint8_t **data, size_t *datalen)
{
	size_t found_locks;

	if (recval.dsize < sizeof(uint32_t)) {
		/* Fresh or invalid record */
		found_locks = 0;
		goto done;
	}

	found_locks = IVAL(recval.dptr, 0);
	recval.dptr += sizeof(uint32_t);
	recval.dsize -= sizeof(uint32_t);

	if (found_locks > recval.dsize/G_LOCK_REC_LENGTH) {
		/* Invalid record */
		return 0;
	}

	if (found_locks <= num_locks) {
		size_t i;

		for (i=0; i<found_locks; i++) {
			g_lock_rec_get(&locks[i], recval.dptr);
			recval.dptr += G_LOCK_REC_LENGTH;
			recval.dsize -= G_LOCK_REC_LENGTH;
		}
	} else {
		/*
		 * Not enough space passed in by the caller, don't
		 * parse the locks.
		 */
		recval.dptr += found_locks * G_LOCK_REC_LENGTH;
		recval.dsize -= found_locks * G_LOCK_REC_LENGTH;
	}

done:
	if (data != NULL) {
		*data = recval.dptr;
	}
	if (datalen != NULL) {
		*datalen = recval.dsize;
	}
	return found_locks;
}

static NTSTATUS g_lock_get_talloc(TALLOC_CTX *mem_ctx, TDB_DATA recval,
				  struct g_lock_rec **plocks,
				  size_t *pnum_locks,
				  uint8_t **data, size_t *datalen)
{
	struct g_lock_rec *locks;
	ssize_t num_locks;

	num_locks = g_lock_get(recval, NULL, 0, NULL, NULL);
	if (num_locks == -1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	locks = talloc_array(mem_ctx, struct g_lock_rec, num_locks);
	if (locks == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	g_lock_get(recval, locks, num_locks, data, datalen);

	*plocks = locks;
	*pnum_locks = num_locks;

	return NT_STATUS_OK;
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

	db_path = lock_path("g_lock.tdb");
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
		DEBUG(1, ("g_lock_init: Could not open g_lock.tdb\n"));
		TALLOC_FREE(result);
		return NULL;
	}

	result->db = db_open_watched(result, backend, msg);
	if (result->db == NULL) {
		DBG_WARNING("g_lock_init: db_open_watched failed\n");
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

static NTSTATUS g_lock_record_store(struct db_record *rec,
				    const struct g_lock_rec *locks,
				    size_t num_locks,
				    const uint8_t *data, size_t datalen)
{
	ssize_t len;
	uint8_t *buf;
	NTSTATUS status;

	len = g_lock_put(NULL, 0, locks, num_locks, data, datalen);
	if (len == -1) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	buf = talloc_array(rec, uint8_t, len);
	if (buf == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	g_lock_put(buf, len, locks, num_locks, data, datalen);

	status = dbwrap_record_store(
		rec, (TDB_DATA) { .dptr = buf, .dsize = len }, 0);

	TALLOC_FREE(buf);

	return status;
}

static NTSTATUS g_lock_trylock(struct db_record *rec, struct server_id self,
			       enum g_lock_type type,
			       struct server_id *blocker)
{
	TDB_DATA data, userdata;
	size_t i, num_locks, my_lock;
	struct g_lock_rec *locks, *tmp;
	NTSTATUS status;
	bool modified = false;

	data = dbwrap_record_get_value(rec);

	status = g_lock_get_talloc(talloc_tos(), data, &locks, &num_locks,
				   &userdata.dptr, &userdata.dsize);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	my_lock = num_locks;	/* doesn't exist yet */

	if ((type == G_LOCK_READ) && (num_locks > 0)) {
		/*
		 * Read locks can stay around forever if the process
		 * dies. Do a heuristic check for process existence:
		 * Check one random process for existence. Hopefully
		 * this will keep runaway read locks under control.
		 */
		i = generate_random() % num_locks;

		if (!serverid_exists(&locks[i].pid)) {
			locks[i] = locks[num_locks-1];
			num_locks -=1;
			modified = true;
		}
	}

	for (i=0; i<num_locks; i++) {
		struct g_lock_rec *lock = &locks[i];

		if (serverid_equal(&self, &lock->pid)) {
			if (lock->lock_type == type) {
				status = NT_STATUS_WAS_LOCKED;
				goto done;
			}
			my_lock = i;
			break;
		}
	}

	for (i=0; i<num_locks; i++) {

		if (i == my_lock) {
			continue;
		}

		if (g_lock_conflicts(type, locks[i].lock_type)) {
			struct server_id pid = locks[i].pid;

			/*
			 * As the serverid_exists might recurse into
			 * the g_lock code, we use
			 * SERVERID_UNIQUE_ID_NOT_TO_VERIFY to avoid the loop
			 */
			pid.unique_id = SERVERID_UNIQUE_ID_NOT_TO_VERIFY;

			if (serverid_exists(&pid)) {
				status = NT_STATUS_LOCK_NOT_GRANTED;
				*blocker = locks[i].pid;
				goto done;
			}

			/*
			 * Delete stale conflicting entry
			 */
			locks[i] = locks[num_locks-1];
			num_locks -= 1;
			modified = true;
		}
	}

	if (my_lock >= num_locks) {
		tmp = talloc_realloc(talloc_tos(), locks, struct g_lock_rec,
				     num_locks+1);
		if (tmp == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
		locks = tmp;
		my_lock = num_locks;
		num_locks += 1;
	}

	locks[my_lock] = (struct g_lock_rec){ .pid = self, .lock_type = type };
	modified = true;

	status = NT_STATUS_OK;
done:
	if (modified) {
		NTSTATUS store_status;
		store_status = g_lock_record_store(
			rec, locks, num_locks, userdata.dptr, userdata.dsize);
		if (!NT_STATUS_IS_OK(store_status)) {
			DBG_WARNING("g_lock_record_store failed: %s\n",
				    nt_errstr(store_status));
			status = store_status;
		}
	}
	TALLOC_FREE(locks);
	return status;
}

struct g_lock_lock_state {
	struct tevent_context *ev;
	struct g_lock_ctx *ctx;
	const char *name;
	enum g_lock_type type;
};

static void g_lock_lock_retry(struct tevent_req *subreq);

struct tevent_req *g_lock_lock_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct g_lock_ctx *ctx,
				    const char *name,
				    enum g_lock_type type)
{
	struct tevent_req *req, *subreq;
	struct g_lock_lock_state *state;
	struct db_record *rec;
	struct server_id self, blocker;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state, struct g_lock_lock_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->ctx = ctx;
	state->name = name;
	state->type = type;

	rec = dbwrap_fetch_locked(ctx->db, talloc_tos(),
				  string_term_tdb_data(state->name));
	if (rec == NULL) {
		DEBUG(10, ("fetch_locked(\"%s\") failed\n", name));
		tevent_req_nterror(req, NT_STATUS_LOCK_NOT_GRANTED);
		return tevent_req_post(req, ev);
	}

	self = messaging_server_id(state->ctx->msg);

	status = g_lock_trylock(rec, self, state->type, &blocker);
	if (NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(rec);
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}
	if (!NT_STATUS_EQUAL(status, NT_STATUS_LOCK_NOT_GRANTED)) {
		TALLOC_FREE(rec);
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}
	subreq = dbwrap_watched_watch_send(state, state->ev, rec, blocker);
	TALLOC_FREE(rec);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	if (!tevent_req_set_endtime(
		    subreq, state->ev,
		    timeval_current_ofs(5 + sys_random() % 5, 0))) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, g_lock_lock_retry, req);
	return req;
}

static void g_lock_lock_retry(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct g_lock_lock_state *state = tevent_req_data(
		req, struct g_lock_lock_state);
	struct server_id self = messaging_server_id(state->ctx->msg);
	struct server_id blocker;
	struct db_record *rec;
	NTSTATUS status;

	status = dbwrap_watched_watch_recv(subreq, talloc_tos(), &rec, NULL,
					   NULL);
	TALLOC_FREE(subreq);

	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		rec = dbwrap_fetch_locked(
			state->ctx->db, talloc_tos(),
			string_term_tdb_data(state->name));
		if (rec == NULL) {
			status = map_nt_error_from_unix(errno);
		} else {
			status = NT_STATUS_OK;
		}
	}

	if (tevent_req_nterror(req, status)) {
		return;
	}
	status = g_lock_trylock(rec, self, state->type, &blocker);
	if (NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(rec);
		tevent_req_done(req);
		return;
	}
	if (!NT_STATUS_EQUAL(status, NT_STATUS_LOCK_NOT_GRANTED)) {
		TALLOC_FREE(rec);
		tevent_req_nterror(req, status);
		return;
	}
	subreq = dbwrap_watched_watch_send(state, state->ev, rec, blocker);
	TALLOC_FREE(rec);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	if (!tevent_req_set_endtime(
		    subreq, state->ev,
		    timeval_current_ofs(5 + sys_random() % 5, 0))) {
		tevent_req_oom(req);
		return;
	}
	tevent_req_set_callback(subreq, g_lock_lock_retry, req);
	return;

}

NTSTATUS g_lock_lock_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS g_lock_lock(struct g_lock_ctx *ctx, const char *name,
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
	req = g_lock_lock_send(frame, ev, ctx, name, type);
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

NTSTATUS g_lock_unlock(struct g_lock_ctx *ctx, const char *name)
{
	struct server_id self = messaging_server_id(ctx->msg);
	struct db_record *rec = NULL;
	struct g_lock_rec *locks = NULL;
	size_t i, num_locks;
	NTSTATUS status;
	TDB_DATA value, userdata;

	rec = dbwrap_fetch_locked(ctx->db, talloc_tos(),
				  string_term_tdb_data(name));
	if (rec == NULL) {
		DEBUG(10, ("fetch_locked(\"%s\") failed\n", name));
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}

	value = dbwrap_record_get_value(rec);

	status = g_lock_get_talloc(talloc_tos(), value, &locks, &num_locks,
				   &userdata.dptr, &userdata.dsize);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("g_lock_get for %s failed: %s\n", name,
			  nt_errstr(status));
		status = NT_STATUS_FILE_INVALID;
		goto done;
	}
	for (i=0; i<num_locks; i++) {
		if (serverid_equal(&self, &locks[i].pid)) {
			break;
		}
	}
	if (i == num_locks) {
		DBG_DEBUG("Lock not found, num_locks=%zu\n", num_locks);
		status = NT_STATUS_NOT_FOUND;
		goto done;
	}

	locks[i] = locks[num_locks-1];
	num_locks -= 1;

	if ((num_locks == 0) && (userdata.dsize == 0)) {
		status = dbwrap_record_delete(rec);
	} else {
		status = g_lock_record_store(
			rec, locks, num_locks, userdata.dptr, userdata.dsize);
	}
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("Could not store record: %s\n", nt_errstr(status));
		goto done;
	}

	status = NT_STATUS_OK;
done:
	TALLOC_FREE(rec);
	TALLOC_FREE(locks);
	return status;
}

NTSTATUS g_lock_write_data(struct g_lock_ctx *ctx, const char *name,
			   const uint8_t *buf, size_t buflen)
{
	struct server_id self = messaging_server_id(ctx->msg);
	struct db_record *rec = NULL;
	struct g_lock_rec *locks = NULL;
	size_t i, num_locks;
	NTSTATUS status;
	TDB_DATA value;

	rec = dbwrap_fetch_locked(ctx->db, talloc_tos(),
				  string_term_tdb_data(name));
	if (rec == NULL) {
		DEBUG(10, ("fetch_locked(\"%s\") failed\n", name));
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}

	value = dbwrap_record_get_value(rec);

	status = g_lock_get_talloc(talloc_tos(), value, &locks, &num_locks,
				   NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("g_lock_get for %s failed: %s\n", name,
			  nt_errstr(status));
		status = NT_STATUS_FILE_INVALID;
		goto done;
	}

	for (i=0; i<num_locks; i++) {
		if (server_id_equal(&self, &locks[i].pid) &&
		    (locks[i].lock_type == G_LOCK_WRITE)) {
			break;
		}
	}
	if (i == num_locks) {
		DBG_DEBUG("Not locked by us\n");
		status = NT_STATUS_NOT_LOCKED;
		goto done;
	}

	status = g_lock_record_store(rec, locks, num_locks, buf, buflen);

done:
	TALLOC_FREE(locks);
	TALLOC_FREE(rec);
	return status;
}

struct g_lock_locks_state {
	int (*fn)(const char *name, void *private_data);
	void *private_data;
};

static int g_lock_locks_fn(struct db_record *rec, void *priv)
{
	TDB_DATA key;
	struct g_lock_locks_state *state = (struct g_lock_locks_state *)priv;

	key = dbwrap_record_get_key(rec);
	if ((key.dsize == 0) || (key.dptr[key.dsize-1] != 0)) {
		DEBUG(1, ("invalid key in g_lock.tdb, ignoring\n"));
		return 0;
	}
	return state->fn((char *)key.dptr, state->private_data);
}

int g_lock_locks(struct g_lock_ctx *ctx,
		 int (*fn)(const char *name, void *private_data),
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

NTSTATUS g_lock_dump(struct g_lock_ctx *ctx, const char *name,
		     void (*fn)(const struct g_lock_rec *locks,
				size_t num_locks,
				const uint8_t *data,
				size_t datalen,
				void *private_data),
		     void *private_data)
{
	TDB_DATA data;
	size_t num_locks;
	struct g_lock_rec *locks = NULL;
	uint8_t *userdata;
	size_t userdatalen;
	NTSTATUS status;

	status = dbwrap_fetch_bystring(ctx->db, talloc_tos(), name, &data);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if ((data.dsize == 0) || (data.dptr == NULL)) {
		return NT_STATUS_OK;
	}

	status = g_lock_get_talloc(talloc_tos(), data, &locks, &num_locks,
				   &userdata, &userdatalen);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("g_lock_get for %s failed: %s\n", name,
			  nt_errstr(status));
		TALLOC_FREE(data.dptr);
		return NT_STATUS_INTERNAL_ERROR;
	}

	fn(locks, num_locks, userdata, userdatalen, private_data);

	TALLOC_FREE(locks);
	TALLOC_FREE(data.dptr);
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

NTSTATUS g_lock_do(const char *name, enum g_lock_type lock_type,
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

	status = g_lock_lock(g_ctx, name, lock_type, timeout);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}
	fn(private_data);
	g_lock_unlock(g_ctx, name);

done:
	TALLOC_FREE(g_ctx);
	TALLOC_FREE(msg);
	TALLOC_FREE(ev);
	return status;
}
