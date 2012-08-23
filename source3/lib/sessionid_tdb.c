/*
   Unix SMB/CIFS implementation.
   Low-level sessionid.tdb access functions
   Copyright (C) Volker Lendecke 2010

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
#include "session.h"
#include "util_tdb.h"
#include "smbd/globals.h"

static struct db_context *session_db_ctx(void)
{
	static struct db_context *session_db_ctx_ptr;

	if (session_db_ctx_ptr != NULL) {
		return session_db_ctx_ptr;
	}

	session_db_ctx_ptr = db_open(NULL, lock_path("sessionid.tdb"), 0,
				     TDB_CLEAR_IF_FIRST|TDB_DEFAULT|TDB_INCOMPATIBLE_HASH,
				     O_RDWR | O_CREAT, 0644,
				     DBWRAP_LOCK_ORDER_1);
	return session_db_ctx_ptr;
}

bool sessionid_init(void)
{
	if (session_db_ctx() == NULL) {
		DEBUG(1,("session_init: failed to open sessionid tdb\n"));
		return False;
	}

	return True;
}

struct db_record *sessionid_fetch_record(TALLOC_CTX *mem_ctx, const char *key)
{
	struct db_context *db;

	db = session_db_ctx();
	if (db == NULL) {
		return NULL;
	}
	return dbwrap_fetch_locked(db, mem_ctx, string_term_tdb_data(key));
}

struct sessionid_traverse_state {
	int (*fn)(struct db_record *rec, const char *key,
		  struct sessionid *session, void *private_data);
	void *private_data;
};

static int sessionid_traverse_fn(struct db_record *rec, void *private_data)
{
	TDB_DATA key;
	TDB_DATA value;
	struct sessionid_traverse_state *state =
		(struct sessionid_traverse_state *)private_data;
	struct sessionid session;

	key = dbwrap_record_get_key(rec);
	value = dbwrap_record_get_value(rec);
	if ((key.dptr[key.dsize-1] != '\0')
	    || (value.dsize != sizeof(struct sessionid))) {
		DEBUG(1, ("Found invalid record in sessionid.tdb\n"));
		return 0;
	}

	memcpy(&session, value.dptr, sizeof(session));

	return state->fn(rec, (char *)key.dptr, &session,
			 state->private_data);
}

NTSTATUS sessionid_traverse(int (*fn)(struct db_record *rec, const char *key,
				      struct sessionid *session,
				      void *private_data),
			    void *private_data)
{
	struct db_context *db;
	struct sessionid_traverse_state state;
	NTSTATUS status;

	db = session_db_ctx();
	if (db == NULL) {
		return NT_STATUS_UNSUCCESSFUL;
	}
	state.fn = fn;
	state.private_data = private_data;
	status = dbwrap_traverse(db, sessionid_traverse_fn, &state, NULL);
	return status;
}

struct sessionid_traverse_read_state {
	int (*fn)(const char *key, struct sessionid *session,
		  void *private_data);
	void *private_data;
};

static int sessionid_traverse_read_fn(struct smbXsrv_session_global0 *global,
				      void *private_data)
{
	struct sessionid_traverse_read_state *state =
		(struct sessionid_traverse_read_state *)private_data;
	struct auth_session_info *session_info = global->auth_session_info;
	struct sessionid session = {
		.uid = session_info->unix_token->uid,
		.gid = session_info->unix_token->gid,
		.id_num = global->session_global_id,
		.connect_start = nt_time_to_unix(global->creation_time),
		.pid = global->channels[0].server_id,
	};

	strncpy(session.username,
		session_info->unix_info->unix_name,
		sizeof(fstring)-1);
	strncpy(session.remote_machine,
		global->channels[0].remote_name,
		sizeof(fstring)-1);
	strncpy(session.hostname,
		global->channels[0].remote_address,
		sizeof(fstring)-1);
	strncpy(session.netbios_name,
		global->channels[0].remote_name,
		sizeof(fstring)-1);
	snprintf(session.id_str, sizeof(fstring)-1,
		 "smb/%u", global->session_global_id);
	strncpy(session.ip_addr_str,
		global->channels[0].remote_address,
		sizeof(fstring)-1);

	return state->fn(NULL, &session, state->private_data);
}

NTSTATUS sessionid_traverse_read(int (*fn)(const char *key,
					  struct sessionid *session,
					  void *private_data),
				 void *private_data)
{
	struct sessionid_traverse_read_state state;
	NTSTATUS status;

	state.fn = fn;
	state.private_data = private_data;
	status = smbXsrv_session_global_traverse(sessionid_traverse_read_fn,
						 &state);

	return status;
}
