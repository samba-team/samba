/* 
   Unix SMB/CIFS implementation.
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

extern fstring remote_machine;

static TDB_CONTEXT *tdb;
/* called when a session is created */
BOOL session_claim(user_struct *vuser)
{
	int i;
	TDB_DATA data;
	struct sessionid sessionid;
	uint32 pid = (uint32)sys_getpid();
	TDB_DATA key;		
	fstring keystr;
	char * hostname;

	vuser->session_id = 0;

	/* don't register sessions for the guest user - its just too
	   expensive to go through pam session code for browsing etc */
	if (vuser->guest) {
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

	/* If 'hostname lookup' == yes, then do the DNS lookup.  This is
           needed becouse utmp and PAM both expect DNS names */

	if (lp_hostname_lookups()) {
		hostname = client_name();
	} else {
		hostname = client_addr();
	}

	fstrcpy(sessionid.username, vuser->user.unix_name);
	fstrcpy(sessionid.hostname, hostname);
	slprintf(sessionid.id_str, sizeof(sessionid.id_str)-1, SESSION_TEMPLATE, i);
	sessionid.id_num = i;
	sessionid.pid = pid;
	sessionid.uid = vuser->uid;
	sessionid.gid = vuser->gid;
	fstrcpy(sessionid.remote_machine, remote_machine);
	fstrcpy(sessionid.ip_addr, client_addr());

	if (!smb_pam_claim_session(sessionid.username, sessionid.id_str, sessionid.hostname)) {
		DEBUG(1,("pam_session rejected the session for %s [%s]\n",
				sessionid.username, sessionid.id_str));
		tdb_delete(tdb, key);
		return False;
	}

	data.dptr = (char *)&sessionid;
	data.dsize = sizeof(sessionid);
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
void session_yield(user_struct *vuser)
{
	TDB_DATA dbuf;
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

	dbuf = tdb_fetch(tdb, key);

	if (dbuf.dsize != sizeof(sessionid))
		return;

	memcpy(&sessionid, dbuf.dptr, sizeof(sessionid));

	SAFE_FREE(dbuf.dptr);

#if WITH_UTMP	
	if (lp_utmp()) {
		sys_utmp_yield(sessionid.username, sessionid.hostname, 
			       sessionid.id_str, sessionid.id_num);
	}
#endif

	smb_pam_close_session(sessionid.username, sessionid.id_str, sessionid.hostname);

	tdb_delete(tdb, key);
}

BOOL session_traverse(int (*fn)(TDB_CONTEXT *, TDB_DATA, TDB_DATA, void *), void *state)
{
  if (!tdb) {
    DEBUG(3, ("No tdb opened\n"));
    return False;
  }

  tdb_traverse(tdb, fn, state);
  return True;
}



