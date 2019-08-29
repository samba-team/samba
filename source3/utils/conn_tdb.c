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
#include "conn_tdb.h"
#include "util_tdb.h"

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
	fstring machine;
	fstring addr;
	uint16_t cipher;
	uint16_t dialect;
	uint8_t signing_flags;
};

static int collect_sessions_fn(struct smbXsrv_session_global0 *global,
			       void *connections_forall_state)
{
	NTSTATUS status;
	struct connections_forall_state *state =
		(struct connections_forall_state*)connections_forall_state;

	uint32_t id = global->session_global_id;
	struct connections_forall_session sess;

	if (global->auth_session_info == NULL) {
		sess.uid = -1;
		sess.gid = -1;
	} else {
		sess.uid = global->auth_session_info->unix_token->uid;
		sess.gid = global->auth_session_info->unix_token->gid;
	}
	fstrcpy(sess.machine, global->channels[0].remote_name);
	fstrcpy(sess.addr, global->channels[0].remote_address);
	sess.cipher = global->channels[0].encryption_cipher;
	sess.dialect = global->connection_dialect;
	sess.signing_flags = global->signing_flags;

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

	/*
	 * Note: that share_name is defined as array without a pointer.
	 * that's why it's always a valid pointer here.
	 */
	if (strlen(global->share_name) == 0) {
		/*
		 * when a smbXsrv_tcon is created it's created
		 * with empty share_name first in order to allocate
		 * an id, before filling in the details.
		 */
		return 0;
	}

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
	fstrcpy(key.name, global->share_name);
	fstrcpy(data.servicename, global->share_name);
	data.uid = sess.uid;
	data.gid = sess.gid;
	fstrcpy(data.addr, sess.addr);
	fstrcpy(data.machine, sess.machine);
	data.start = nt_time_to_unix(global->creation_time);
	data.encryption_flags = global->encryption_flags;
	data.cipher = sess.cipher;
	data.dialect = sess.dialect;
	data.signing_flags = global->signing_flags;

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
