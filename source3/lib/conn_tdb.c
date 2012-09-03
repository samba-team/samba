/* 
   Unix SMB/CIFS implementation.
   Low-level connections.tdb access functions
   Copyright (C) Volker Lendecke 2007

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
#include "smbd/globals.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "dbwrap/dbwrap_rbt.h"
#include "messages.h"
#include "lib/conn_tdb.h"
#include "util_tdb.h"

static struct db_context *connections_db_ctx(bool rw)
{
	static struct db_context *db_ctx;
	int open_flags;

	if (db_ctx != NULL) {
		return db_ctx;
	}

	open_flags = rw ? (O_RDWR|O_CREAT) : O_RDONLY;

	db_ctx = db_open(NULL, lock_path("connections.tdb"), 0,
			 TDB_CLEAR_IF_FIRST|TDB_INCOMPATIBLE_HASH|TDB_DEFAULT,
			 open_flags, 0644, DBWRAP_LOCK_ORDER_1);
	return db_ctx;
}

static struct db_record *connections_fetch_record(TALLOC_CTX *mem_ctx,
						  TDB_DATA key)
{
	struct db_context *ctx = connections_db_ctx(True);

	if (ctx == NULL) {
		return NULL;
	}

	return dbwrap_fetch_locked(ctx, mem_ctx, key);
}

struct db_record *connections_fetch_entry_ext(TALLOC_CTX *mem_ctx,
					      struct server_id id,
					      int cnum,
					      const char *name)
{
	struct connections_key ckey;
	TDB_DATA key;

	ZERO_STRUCT(ckey);
	ckey.pid = id;
	ckey.cnum = cnum;
	strlcpy(ckey.name, name, sizeof(ckey.name));

	key.dsize = sizeof(ckey);
	key.dptr = (uint8 *)&ckey;

	return connections_fetch_record(mem_ctx, key);
}

struct db_record *connections_fetch_entry(TALLOC_CTX *mem_ctx,
					  connection_struct *conn,
					  const char *name)
{
	struct server_id id = messaging_server_id(conn->sconn->msg_ctx);
	return connections_fetch_entry_ext(mem_ctx, id, conn->cnum, name);
}

struct connections_forall_state {
	struct db_context *session_by_pid;
	int (*fn)(const struct connections_key *key,
		  const struct connections_data *data,
		  void *private_data);
	void *private_data;
	int count;
};

struct connections_forall_session {
	uid_t uid;
	gid_t gid;
	char machine[FSTRING_LEN];
	char addr[FSTRING_LEN];
};

static int collect_sessions_fn(struct smbXsrv_session_global0 *global,
			       void *connections_forall_state)
{
	NTSTATUS status;
	struct connections_forall_state *state =
		(struct connections_forall_state*)connections_forall_state;

	uint32_t id = global->session_global_id;
	struct connections_forall_session sess;

	sess.uid = global->auth_session_info->unix_token->uid;
	sess.gid = global->auth_session_info->unix_token->gid;
	strncpy(sess.machine, global->channels[0].remote_name, sizeof(sess.machine));
	strncpy(sess.addr, global->channels[0].remote_address, sizeof(sess.addr));

	status = dbwrap_store(state->session_by_pid,
			      make_tdb_data((void*)&id, sizeof(id)),
			      make_tdb_data((void*)&sess, sizeof(sess)),
			      TDB_INSERT);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to store record: %s\n", nt_errstr(status)));
	}
	return 0;
}

static int traverse_tcon_fn(struct smbXsrv_tcon_global0 *global,
			    void *connections_forall_state)
{
	NTSTATUS status;
	struct connections_forall_state *state =
		(struct connections_forall_state*)connections_forall_state;

	struct connections_key key;
	struct connections_data data;

	uint32_t sess_id = global->session_global_id;
	struct connections_forall_session sess = {
		.uid = -1,
		.gid = -1,
	};

	TDB_DATA val = tdb_null;

	status = dbwrap_fetch(state->session_by_pid, state,
			      make_tdb_data((void*)&sess_id, sizeof(sess_id)),
			      &val);
	if (NT_STATUS_IS_OK(status)) {
		memcpy((uint8_t *)&sess, val.dptr, val.dsize);
	}

	ZERO_STRUCT(key);
	ZERO_STRUCT(data);

	key.pid = data.pid = global->server_id;
	key.cnum = data.cnum = global->tcon_global_id;
	strncpy(key.name, global->share_name, sizeof(key.name));
	strncpy(data.servicename, global->share_name, sizeof(data.servicename));
	data.uid = sess.uid;
	data.gid = sess.gid;
	strncpy(data.addr, sess.addr, sizeof(data.addr));
	strncpy(data.machine, sess.machine, sizeof(data.machine));
	data.start = nt_time_to_unix(global->creation_time);

	state->count++;

	return state->fn(&key, &data, state->private_data);
}

int connections_forall_read(int (*fn)(const struct connections_key *key,
				      const struct connections_data *data,
				      void *private_data),
			    void *private_data)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct connections_forall_state *state =
		talloc_zero(talloc_tos(), struct connections_forall_state);
	NTSTATUS status;
	int ret = -1;

	state->session_by_pid = db_open_rbt(state);
	state->fn = fn;
	state->private_data = private_data;
	status = smbXsrv_session_global_traverse(collect_sessions_fn, state);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to traverse sessions: %s\n",
			  nt_errstr(status)));
		goto done;
	}

	status = smbXsrv_tcon_global_traverse(traverse_tcon_fn, state);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to traverse tree connects: %s\n",
			  nt_errstr(status)));
		goto done;
	}
	ret = state->count;
done:
	talloc_free(frame);
	return ret;
}

bool connections_init(bool rw)
{
	return (connections_db_ctx(rw) != NULL);
}
