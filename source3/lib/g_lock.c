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
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "dbwrap/dbwrap_watch.h"
#include "g_lock.h"
#include "util_tdb.h"
#include "ctdbd_conn.h"
#include "../lib/util/select.h"
#include "../lib/util/tevent_ntstatus.h"
#include "system/select.h"
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

struct g_lock_rec {
	enum g_lock_type lock_type;
	struct server_id pid;
};

struct g_lock_ctx *g_lock_ctx_init(TALLOC_CTX *mem_ctx,
				   struct messaging_context *msg)
{
	struct g_lock_ctx *result;

	result = talloc(mem_ctx, struct g_lock_ctx);
	if (result == NULL) {
		return NULL;
	}
	result->msg = msg;

	result->db = db_open(result, lock_path("g_lock.tdb"), 0,
			     TDB_CLEAR_IF_FIRST|TDB_INCOMPATIBLE_HASH,
			     O_RDWR|O_CREAT, 0600,
			     DBWRAP_LOCK_ORDER_2,
			     DBWRAP_FLAG_NONE);
	if (result->db == NULL) {
		DEBUG(1, ("g_lock_init: Could not open g_lock.tdb\n"));
		TALLOC_FREE(result);
		return NULL;
	}
	dbwrap_watch_db(result->db, msg);
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

static bool g_lock_parse(TALLOC_CTX *mem_ctx, TDB_DATA data,
			 unsigned *pnum_locks, struct g_lock_rec **plocks)
{
	unsigned num_locks;
	struct g_lock_rec *locks;

	if ((data.dsize % sizeof(struct g_lock_rec)) != 0) {
		DEBUG(1, ("invalid lock record length %d\n", (int)data.dsize));
		return false;
	}
	num_locks = data.dsize / sizeof(struct g_lock_rec);
	locks = talloc_memdup(mem_ctx, data.dptr, data.dsize);
	if (locks == NULL) {
		DEBUG(1, ("talloc_memdup failed\n"));
		return false;
	}
	*plocks = locks;
	*pnum_locks = num_locks;
	return true;
}

static NTSTATUS g_lock_trylock(struct db_record *rec, struct server_id self,
			       enum g_lock_type type)
{
	TDB_DATA data;
	unsigned i, num_locks;
	struct g_lock_rec *locks, *tmp;
	NTSTATUS status;
	bool modified = false;

	data = dbwrap_record_get_value(rec);

	if (!g_lock_parse(talloc_tos(), data, &num_locks, &locks)) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	for (i=0; i<num_locks; i++) {
		if (serverid_equal(&self, &locks[i].pid)) {
			status = NT_STATUS_INTERNAL_ERROR;
			goto done;
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

	tmp = talloc_realloc(talloc_tos(), locks, struct g_lock_rec,
			     num_locks+1);
	if (tmp == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	locks = tmp;

	ZERO_STRUCT(locks[num_locks]);
	locks[num_locks].pid = self;
	locks[num_locks].lock_type = type;
	num_locks += 1;
	modified = true;

	status = NT_STATUS_OK;
done:
	if (modified) {
		NTSTATUS store_status;

		data = make_tdb_data((uint8_t *)locks, num_locks * sizeof(*locks));
		store_status = dbwrap_record_store(rec, data, 0);
		if (!NT_STATUS_IS_OK(store_status)) {
			DEBUG(1, ("rec->store failed: %s\n",
				  nt_errstr(store_status)));
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
	struct server_id self;
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

	status = g_lock_trylock(rec, self, state->type);
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
	subreq = dbwrap_record_watch_send(state, state->ev, rec,
					  state->ctx->msg);
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
	struct db_record *rec;
	NTSTATUS status;

	status = dbwrap_record_watch_recv(subreq, talloc_tos(), &rec);
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
	status = g_lock_trylock(rec, self, state->type);
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
	subreq = dbwrap_record_watch_send(state, state->ev, rec,
					  state->ctx->msg);
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
	unsigned i, num_locks;
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

	if (!g_lock_parse(talloc_tos(), value, &num_locks, &locks)) {
		DEBUG(10, ("g_lock_parse for %s failed\n", name));
		status = NT_STATUS_FILE_INVALID;
		goto done;
	}
	for (i=0; i<num_locks; i++) {
		if (serverid_equal(&self, &locks[i].pid)) {
			break;
		}
	}
	if (i == num_locks) {
		DEBUG(10, ("g_lock_force_unlock: Lock not found\n"));
		status = NT_STATUS_NOT_FOUND;
		goto done;
	}

	locks[i] = locks[num_locks-1];
	num_locks -= 1;

	if (num_locks == 0) {
		status = dbwrap_record_delete(rec);
	} else {
		TDB_DATA data;
		data = make_tdb_data((uint8_t *)locks,
				     sizeof(struct g_lock_rec) * num_locks);
		status = dbwrap_record_store(rec, data, 0);
	}
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("g_lock_force_unlock: Could not store record: %s\n",
			  nt_errstr(status)));
		goto done;
	}

	status = NT_STATUS_OK;
done:
	TALLOC_FREE(rec);
	TALLOC_FREE(locks);
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
	} else {
		return count;
	}
}

NTSTATUS g_lock_dump(struct g_lock_ctx *ctx, const char *name,
		     int (*fn)(struct server_id pid,
			       enum g_lock_type lock_type,
			       void *private_data),
		     void *private_data)
{
	TDB_DATA data;
	unsigned i, num_locks;
	struct g_lock_rec *locks = NULL;
	bool ret;
	NTSTATUS status;

	status = dbwrap_fetch_bystring(ctx->db, talloc_tos(), name, &data);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if ((data.dsize == 0) || (data.dptr == NULL)) {
		return NT_STATUS_OK;
	}

	ret = g_lock_parse(talloc_tos(), data, &num_locks, &locks);

	TALLOC_FREE(data.dptr);

	if (!ret) {
		DEBUG(10, ("g_lock_parse for %s failed\n", name));
		return NT_STATUS_INTERNAL_ERROR;
	}

	for (i=0; i<num_locks; i++) {
		if (fn(locks[i].pid, locks[i].lock_type, private_data) != 0) {
			break;
		}
	}
	TALLOC_FREE(locks);
	return NT_STATUS_OK;
}

struct g_lock_get_state {
	bool found;
	struct server_id *pid;
};

static int g_lock_get_fn(struct server_id pid, enum g_lock_type lock_type,
			 void *priv)
{
	struct g_lock_get_state *state = (struct g_lock_get_state *)priv;
	state->found = true;
	*state->pid = pid;
	return 1;
}

NTSTATUS g_lock_get(struct g_lock_ctx *ctx, const char *name,
		    struct server_id *pid)
{
	struct g_lock_get_state state;
	NTSTATUS status;

	state.found = false;
	state.pid = pid;

	status = g_lock_dump(ctx, name, g_lock_get_fn, &state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!state.found) {
		return NT_STATUS_NOT_FOUND;
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
