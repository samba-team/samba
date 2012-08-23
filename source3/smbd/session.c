/* 
   Unix SMB/CIFS implementation.
   session handling for utmp and PAM

   Copyright (C) tridge@samba.org       2001
   Copyright (C) abartlet@samba.org     2001
   Copyright (C) Gerald (Jerry) Carter  2006   
   
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

/* a "session" is claimed when we do a SessionSetupX operation
   and is yielded when the corresponding vuid is destroyed.

   sessions are used to populate utmp and PAM session structures
*/

#include "includes.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "dbwrap/dbwrap.h"
#include "session.h"
#include "auth.h"
#include "../lib/tsocket/tsocket.h"
#include "../libcli/security/security.h"
#include "messages.h"

/********************************************************************
 called when a session is created
********************************************************************/

bool session_claim(struct smbXsrv_session *session)
{
	struct user_struct *vuser = session->compat;
	struct smbd_server_connection *sconn = session->connection->sconn;
	struct server_id pid = messaging_server_id(sconn->msg_ctx);
	TDB_DATA data;
	struct sessionid sessionid;
	fstring keystr;
	struct db_record *rec;
	NTSTATUS status;
	char *raddr;

	vuser->session_keystr = NULL;

	/* don't register sessions for the guest user - its just too
	   expensive to go through pam session code for browsing etc */
	if (security_session_user_level(vuser->session_info, NULL) < SECURITY_USER) {
		return True;
	}

	if (!sessionid_init()) {
		return False;
	}

	ZERO_STRUCT(sessionid);

	sessionid.id_num = session->global->session_global_id;

	data.dptr = NULL;
	data.dsize = 0;

	snprintf(keystr, sizeof(keystr), "ID/%u", sessionid.id_num);
	snprintf(sessionid.id_str, sizeof(sessionid.id_str),
		 "smb/%u", sessionid.id_num);

	rec = sessionid_fetch_record(NULL, keystr);
	if (rec == NULL) {
		DEBUG(1, ("Could not lock \"%s\"\n", keystr));
		return False;
	}

	raddr = tsocket_address_inet_addr_string(session->connection->remote_address,
						 talloc_tos());
	if (raddr == NULL) {
		return false;
	}

	/* Make clear that we require the optional unix_token in the source3 code */
	SMB_ASSERT(vuser->session_info->unix_token);

	fstrcpy(sessionid.username, vuser->session_info->unix_info->unix_name);
	fstrcpy(sessionid.hostname, sconn->remote_hostname);
	sessionid.pid = pid;
	sessionid.uid = vuser->session_info->unix_token->uid;
	sessionid.gid = vuser->session_info->unix_token->gid;
	fstrcpy(sessionid.remote_machine, get_remote_machine_name());
	fstrcpy(sessionid.ip_addr_str, raddr);
	sessionid.connect_start = time(NULL);

	if (!smb_pam_claim_session(sessionid.username, sessionid.id_str,
				   sessionid.hostname)) {
		DEBUG(1,("pam_session rejected the session for %s [%s]\n",
				sessionid.username, sessionid.id_str));

		TALLOC_FREE(rec);
		return False;
	}

	data.dptr = (uint8 *)&sessionid;
	data.dsize = sizeof(sessionid);

	status = dbwrap_record_store(rec, data, TDB_REPLACE);

	TALLOC_FREE(rec);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1,("session_claim: unable to create session id "
			 "record: %s\n", nt_errstr(status)));
		return False;
	}

	if (lp_utmp()) {
		sys_utmp_claim(sessionid.username, sessionid.hostname,
			       sessionid.id_str, sessionid.id_num);
	}

	vuser->session_keystr = talloc_strdup(vuser, keystr);
	if (!vuser->session_keystr) {
		DEBUG(0, ("session_claim:  talloc_strdup() failed for session_keystr\n"));
		return False;
	}
	return True;
}

/********************************************************************
 called when a session is destroyed
********************************************************************/

void session_yield(struct smbXsrv_session *session)
{
	struct user_struct *vuser = session->compat;
	struct sessionid sessionid;
	struct db_record *rec;
	TDB_DATA value;

	if (!vuser->session_keystr) {
		return;
	}

	rec = sessionid_fetch_record(NULL, vuser->session_keystr);
	if (rec == NULL) {
		return;
	}

	value = dbwrap_record_get_value(rec);

	if (value.dsize != sizeof(sessionid))
		return;

	memcpy(&sessionid, value.dptr, sizeof(sessionid));

	if (lp_utmp()) {
		sys_utmp_yield(sessionid.username, sessionid.hostname, 
			       sessionid.id_str, sessionid.id_num);
	}

	smb_pam_close_session(sessionid.username, sessionid.id_str,
			      sessionid.hostname);

	dbwrap_record_delete(rec);

	TALLOC_FREE(rec);
}

/********************************************************************
********************************************************************/

struct session_list {
	TALLOC_CTX *mem_ctx;
	int count;
	struct sessionid *sessions;
};

static int gather_sessioninfo(const char *key, struct sessionid *session,
			      void *private_data)
{
	struct session_list *sesslist = (struct session_list *)private_data;

	sesslist->sessions = talloc_realloc(
		sesslist->mem_ctx, sesslist->sessions, struct sessionid,
		sesslist->count+1);

	if (!sesslist->sessions) {
		sesslist->count = 0;
		return -1;
	}

	memcpy(&sesslist->sessions[sesslist->count], session,
	       sizeof(struct sessionid));

	sesslist->count++;

	DEBUG(7, ("gather_sessioninfo session from %s@%s\n",
		  session->username, session->remote_machine));

	return 0;
}

/********************************************************************
********************************************************************/

int list_sessions(TALLOC_CTX *mem_ctx, struct sessionid **session_list)
{
	struct session_list sesslist;
	NTSTATUS status;

	sesslist.mem_ctx = mem_ctx;
	sesslist.count = 0;
	sesslist.sessions = NULL;

	status = sessionid_traverse_read(gather_sessioninfo, (void *) &sesslist);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("Session traverse failed\n"));
		SAFE_FREE(sesslist.sessions);
		*session_list = NULL;
		return 0;
	}

	*session_list = sesslist.sessions;
	return sesslist.count;
}
