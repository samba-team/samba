#define OLD_NTDOMAIN 1

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

/* what user is current? */
extern struct current_user current_user;

/****************************************************************************
 Become the guest user.
****************************************************************************/

BOOL become_guest(void)
{
	static struct passwd *pass=NULL;
	
	if (!pass)
		pass = Get_Pwnam(lp_guestaccount(-1),True);
	if (!pass) return(False);
	
#ifdef AIX
	/* MWW: From AIX FAQ patch to WU-ftpd: call initgroups before 
	   setting IDs */
	initgroups(pass->pw_name, (gid_t)pass->pw_gid);
#endif
	
	set_sec_ctx(pass->pw_uid, pass->pw_gid, 0, NULL);
	
	current_user.conn = NULL;
	current_user.vuid = UID_FIELD_INVALID;
	
	return True;
}

/*******************************************************************
 Check if a username is OK.
********************************************************************/

static BOOL check_user_ok(connection_struct *conn, user_struct *vuser,int snum)
{
  int i;
  for (i=0;i<conn->uid_cache.entries;i++)
    if (conn->uid_cache.list[i] == vuser->uid) return(True);

  if (!user_ok(vuser->user.unix_name,snum)) return(False);

  i = conn->uid_cache.entries % UID_CACHE_SIZE;
  conn->uid_cache.list[i] = vuser->uid;

  if (conn->uid_cache.entries < UID_CACHE_SIZE)
    conn->uid_cache.entries++;

  return(True);
}

/****************************************************************************
 Become the user of a connection number.
****************************************************************************/

BOOL become_user(connection_struct *conn, uint16 vuid)
{
	user_struct *vuser = get_valid_user_struct(vuid);
	int snum;
	gid_t gid;
	uid_t uid;
	char group_c;

	if (!conn) {
		DEBUG(2,("Connection not open\n"));
		return(False);
	}

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
		   (vuser != 0) && (current_user.vuid == vuid) && 
		   (current_user.uid == vuser->uid)) {
		DEBUG(4,("Skipping become_user - already user\n"));
		return(True);
	}

	snum = SNUM(conn);

	if((vuser != NULL) && !check_user_ok(conn, vuser, snum))
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
		gid = vuser->gid;
		current_user.ngroups = vuser->n_groups;
		current_user.groups  = vuser->groups;
	}

	/*
	 * See if we should force group for this service.
	 * If so this overrides any group set in the force
	 * user code.
	 */

	if((group_c = *lp_force_group(snum))) {
		if(group_c == '+') {

			/*
			 * Only force group if the user is a member of
			 * the service group. Check the group memberships for
			 * this user (we already have this) to
			 * see if we should force the group.
			 */

			int i;
			for (i = 0; i < current_user.ngroups; i++) {
				if (current_user.groups[i] == conn->gid) {
					gid = conn->gid;
					break;
				}
			}
		} else {
			gid = conn->gid;
		}
	}
	
	set_sec_ctx(uid, gid, current_user.ngroups, current_user.groups);

	current_user.conn = conn;
	current_user.vuid = vuid;

	DEBUG(5,("become_user uid=(%d,%d) gid=(%d,%d)\n",
		 (int)getuid(),(int)geteuid(),(int)getgid(),(int)getegid()));
  
	return(True);
}

/****************************************************************************
 Unbecome the user of a connection number.
****************************************************************************/

BOOL unbecome_user(void )
{
	set_root_sec_ctx();

	DEBUG(5,("unbecome_user now uid=(%d,%d) gid=(%d,%d)\n",
		(int)getuid(),(int)geteuid(),(int)getgid(),(int)getegid()));

	current_user.conn = NULL;
	current_user.vuid = UID_FIELD_INVALID;

	return(True);
}

/****************************************************************************
 Become the user of an authenticated connected named pipe.
 When this is called we are currently running as the connection
 user.
****************************************************************************/

BOOL become_authenticated_pipe_user(pipes_struct *p)
{
	BOOL res = push_sec_ctx();

	if (!res) {
		return False;
	}

	set_sec_ctx(p->uid, p->gid, 0, NULL);  /* fix group stuff */

	return True;
}

/****************************************************************************
 Unbecome the user of an authenticated connected named pipe.
 When this is called we are running as the authenticated pipe
 user and need to go back to being the connection user.
****************************************************************************/

BOOL unbecome_authenticated_pipe_user(pipes_struct *p)
{
	return pop_sec_ctx();
}

/* Temporarily become a root user.  Must match with unbecome_root(). */

void become_root(void)
{
	push_sec_ctx();
	set_root_sec_ctx();
}

/* Unbecome the root user */

void unbecome_root(void)
{
	pop_sec_ctx();
}

#undef OLD_NTDOMAIN
