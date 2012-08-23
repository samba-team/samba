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
	struct auth_session_info *session_info =
		session->global->auth_session_info;
	const char *username;
	const char *hostname;
	unsigned int id_num;
	fstring id_str;

	/* don't register sessions for the guest user - its just too
	   expensive to go through pam session code for browsing etc */
	if (security_session_user_level(session_info, NULL) < SECURITY_USER) {
		return true;
	}

	id_num = session->global->session_global_id;

	snprintf(id_str, sizeof(id_str), "smb/%u", id_num);

	/* Make clear that we require the optional unix_token in the source3 code */
	SMB_ASSERT(session_info->unix_token);

	username = session_info->unix_info->unix_name;
	hostname = session->global->channels[0].remote_name;

	if (!smb_pam_claim_session(username, id_str, hostname)) {
		DEBUG(1,("pam_session rejected the session for %s [%s]\n",
				username, id_str));
		return false;
	}

	if (lp_utmp()) {
		sys_utmp_claim(username, hostname, id_str, id_num);
	}

	return true;
}

/********************************************************************
 called when a session is destroyed
********************************************************************/

void session_yield(struct smbXsrv_session *session)
{
	struct auth_session_info *session_info =
		session->global->auth_session_info;
	const char *username;
	const char *hostname;
	unsigned int id_num;
	fstring id_str = "";

	id_num = session->global->session_global_id;

	snprintf(id_str, sizeof(id_str), "smb/%u", id_num);

	/* Make clear that we require the optional unix_token in the source3 code */
	SMB_ASSERT(session_info->unix_token);

	username = session_info->unix_info->unix_name;
	hostname = session->global->channels[0].remote_name;

	if (lp_utmp()) {
		sys_utmp_yield(username, hostname, id_str, id_num);
	}

	smb_pam_close_session(username, id_str, hostname);
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
