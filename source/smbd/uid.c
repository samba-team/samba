/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   uid/user handling
   Copyright (C) Andrew Tridgell 1992-1998
   
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

#include "includes.h"

extern int DEBUGLEVEL;

extern uid_t initial_uid;
extern gid_t initial_gid;

/* what user is current? */
extern struct current_user current_user;

extern pstring OriginalDir;

/****************************************************************************
become the guest user
****************************************************************************/
BOOL become_guest(void)
{
  BOOL ret;
  static const struct passwd *pass=NULL;

  if (initial_uid != 0) 
    return(True);

  if (!pass)
    pass = Get_Pwnam(lp_guestaccount(-1),True);
  if (!pass) return(False);

#ifdef AIX
  /* MWW: From AIX FAQ patch to WU-ftpd: call initgroups before setting IDs */
  initgroups(pass->pw_name, (gid_t)pass->pw_gid);
#endif

  ret = become_id(pass->pw_uid,pass->pw_gid);

  if (!ret) {
    DEBUG(1,("Failed to become guest. Invalid guest account?\n"));
  }

  current_user.conn = NULL;
  current_user.vuid = UID_FIELD_INVALID;

  return(ret);
}


/****************************************************************************
  become the user of a connection number
****************************************************************************/
BOOL become_user(connection_struct *conn, uint16 vuid)
{
	user_struct *vuser = get_valid_user_struct(vuid);
	int snum;
	gid_t gid;
	uid_t uid;

	/*
	 * We need a separate check in security=share mode due to vuid
	 * always being UID_FIELD_INVALID. If we don't do this then
	 * in share mode security we are *always* changing uid's between
	 * SMB's - this hurts performance - Badly.
	 */

	if((lp_security() == SEC_SHARE) && (current_user.conn == conn) &&
	   (current_user.uid == conn->uid)) {
		DEBUG(4,("Skipping become_user - already user\n"));
		return(True);
	} else if ((current_user.conn == conn) && 
		   (vuser != NULL) && (current_user.vuid == vuid) && 
		   (current_user.uid == vuser->uid)) {
		DEBUG(4,("Skipping become_user - already user\n"));
		return(True);
	}

	unbecome_user();

	if (!conn) {
		DEBUG(2,("Connection not open\n"));
		return(False);
	}

	snum = SNUM(conn);

	if((vuser != NULL) && !check_vuser_ok(&conn->uid_cache, vuser, snum))
		return False;

	if (conn->force_user || 
	    lp_security() == SEC_SHARE ||
	    !(vuser) || (vuser->guest)) {
		uid = conn->uid;
		gid = conn->gid;
		current_user.groups = conn->groups;
		current_user.ngroups = conn->ngroups;
	} else {
		if (!vuser) {
			DEBUG(2,("Invalid vuid used %d\n",vuid));
			return(False);
		}
		uid = vuser->uid;
		if(!*lp_force_group(snum)) {
			gid = vuser->gid;
		} else {
			gid = conn->gid;
		}
		current_user.ngroups = vuser->n_groups;
		current_user.groups  = vuser->groups;
	}
	
	if (initial_uid == 0)  {
		if (!become_gid(gid)) return(False);

#ifdef HAVE_SETGROUPS      
		if (!(conn && conn->ipc)) {
			/* groups stuff added by ih/wreu */
			if (current_user.ngroups > 0)
				if (setgroups(current_user.ngroups,
					      current_user.groups)<0) {
					DEBUG(0,("setgroups call failed!\n"));
				}
		}
#endif

		if (!conn->admin_user && !become_uid(uid))
			return(False);
	}
	
	current_user.conn = conn;
	current_user.vuid = vuid;

	DEBUG(5,("become_user uid=(%d,%d) gid=(%d,%d)\n",
		 (int)getuid(),(int)geteuid(),(int)getgid(),(int)getegid()));
  
	return(True);
}

/****************************************************************************
  unbecome the user of a connection number
****************************************************************************/
BOOL unbecome_user(void )
{
  if (!current_user.conn)
    return(False);

  return unbecome_to_initial_uid();
}

