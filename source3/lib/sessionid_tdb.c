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
		.uid = -1,
		.gid = -1,
		.id_num = global->session_global_id,
		.connect_start = nt_time_to_unix(global->creation_time),
		.pid = global->channels[0].server_id,
	};

	if (session_info != NULL) {
		session.uid = session_info->unix_token->uid;
		session.gid = session_info->unix_token->gid;
		strncpy(session.username,
			session_info->unix_info->unix_name,
			sizeof(fstring)-1);
	}

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
