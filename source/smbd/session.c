/* 
   Unix SMB/Netbios implementation.
   Version 2.0
   session handling for utmp and PAM
   Copyright (C) tridge@samba.org 2001
   Copyright (C) abartlet@pcug.org.au 2001
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/* a "session" is claimed when we do a SessionSetupX operation
   and is yielded when the corresponding vuid is destroyed.

   sessions are used to populate utmp and PAM session structures
*/

#include "includes.h"

#if defined(WITH_PAM) || defined(WITH_UTMP)

static TDB_CONTEXT *tdb;
struct sessionid {
	fstring username;
	fstring hostname;
	fstring id_str;
	uint32  id_num;
	uint32  pid;
};

/* called when a session is created */
BOOL session_claim(uint16 vuid)
{
	user_struct *vuser = get_valid_user_struct(vuid);
	int i;
	TDB_DATA data;
	struct sessionid sessionid;
	pstring dbuf;
	int dlen;
	uint32 pid = (uint32)sys_getpid();
	TDB_DATA key;		
	fstring keystr;
	char * hostname;

	vuser->session_id = 0;

	/* don't register sessions for the guest user - its just too
	   expensive to go through pam session code for browsing etc */
	if (strequal(vuser->user.unix_name,lp_guestaccount(-1))) {
		return True;
	}

	if (!tdb) {
		tdb = tdb_open_log(lock_path("sessionid.tdb"), 0, TDB_CLEAR_IF_FIRST|TDB_DEFAULT, 
			       O_RDWR | O_CREAT, 0644);
		if (!tdb) {
			DEBUG(1,("session_claim: failed to open sessionid tdb\n"));
			return False;
		}
	}

	ZERO_STRUCT(sessionid);

	data.dptr = NULL;
	data.dsize = 0;

	for (i=1;i<MAX_SESSION_ID;i++) {
		slprintf(keystr, sizeof(keystr)-1, "ID/%d", i);
		key.dptr = keystr;
		key.dsize = strlen(keystr)+1;

		if (tdb_store(tdb, key, data, TDB_INSERT) == 0) break;
	}

	if (i == MAX_SESSION_ID) {
		DEBUG(1,("session_claim: out of session IDs (max is %d)\n", 
			 MAX_SESSION_ID));
		return False;
	}

        /* Don't resolve the hostname in smbd as we can pause for a long
           time while waiting for DNS timeouts to occur.  The correct
           place to do this is in the code that displays the session
           information. */

        hostname = client_addr();

	fstrcpy(sessionid.username, vuser->user.unix_name);
	fstrcpy(sessionid.hostname, hostname);
	slprintf(sessionid.id_str, sizeof(sessionid.id_str)-1, SESSION_TEMPLATE, i);
	sessionid.id_num = i;
	sessionid.pid = pid;

	if (!smb_pam_claim_session(sessionid.username, sessionid.id_str, sessionid.hostname)) {
		DEBUG(1,("pam_session rejected the session for %s [%s]\n",
				sessionid.username, sessionid.id_str));
		tdb_delete(tdb, key);
		return False;
	}

	dlen = tdb_pack(dbuf, sizeof(dbuf), "fffdd",
			sessionid.username, sessionid.hostname, sessionid.id_str,
			sessionid.id_num, sessionid.pid);

	data.dptr = dbuf;
	data.dsize = dlen;
	if (tdb_store(tdb, key, data, TDB_MODIFY) != 0) {
		DEBUG(1,("session_claim: unable to create session id record\n"));
		return False;
	}

#if WITH_UTMP	
	if (lp_utmp()) {
		sys_utmp_claim(sessionid.username, sessionid.hostname, 
			       sessionid.id_str, sessionid.id_num);
	}
#endif

	vuser->session_id = i;
	return True;
}

/* called when a session is destroyed */
void session_yield(uint16 vuid)
{
	user_struct *vuser = get_valid_user_struct(vuid);
	TDB_DATA data;
	struct sessionid sessionid;
	TDB_DATA key;		
	fstring keystr;

	if (!tdb) return;

	if (vuser->session_id == 0) {
		return;
	}

	slprintf(keystr, sizeof(keystr)-1, "ID/%d", vuser->session_id);

	key.dptr = keystr;
	key.dsize = strlen(keystr)+1;

	data = tdb_fetch(tdb, key);
	if (data.dptr == NULL) {
		return;
	}

	tdb_unpack(data.dptr, data.dsize, "fffdd",
		   &sessionid.username, &sessionid.hostname, &sessionid.id_str,
		   &sessionid.id_num, &sessionid.pid);

	safe_free(data.dptr);
	data.dptr = NULL;

#if WITH_UTMP	
	if (lp_utmp()) {
		sys_utmp_yield(sessionid.username, sessionid.hostname, 
			       sessionid.id_str, sessionid.id_num);
	}
#endif

	smb_pam_close_session(sessionid.username, sessionid.id_str, sessionid.hostname);

	tdb_delete(tdb, key);
}

#else
 /* null functions - no session support needed */
 BOOL session_claim(uint16 vuid) { return True; }
 void session_yield(uint16 vuid) {} 
#endif
