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

extern struct current_user current_user;

/****************************************************************************
 Become the user of a connection number.
****************************************************************************/
BOOL become_user(connection_struct *conn, uint16 vuid)
{
	extern vuser_key *user_key;
	static vuser_key key;
	key.pid = sys_getpid();
	key.vuid = vuid;

	user_key = &key;

	return become_userk(conn, &key);
}
/****************************************************************************
 Become the user of a connection number.
****************************************************************************/
BOOL become_userk(connection_struct *conn, const vuser_key *key)
{
	user_struct *vuser = NULL;
	int snum;
	gid_t gid = -1;
	uid_t uid = -1;
	char group_c;
	int ngroups = 0;
	gid_t *groups = NULL;
	BOOL ret;

	if (!conn)
	{
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
	   (current_user.uid == conn->uid))
	{
		DEBUG(4,("Skipping become_user - already user\n"));

		return(True);
	}

	vuser = get_valid_user_struct(key);

	if ((current_user.conn == conn) && 
		   (vuser != NULL) &&
		   (current_user.key.vuid == key->vuid) && 
		   (current_user.key.pid == key->pid) && 
		   (current_user.uid == vuser->uid))
	{
		DEBUG(4,("Skipping become_user - already user\n"));
		vuid_free_user_struct(vuser);
		return(True);
	}

	unbecome_user();

	snum = SNUM(conn);

	if((vuser != NULL) && !check_vuser_ok(&conn->uid_cache, vuser, snum))
	{
		vuid_free_user_struct(vuser);
		return False;
	}

	if (conn->force_user || 
	    lp_security() == SEC_SHARE ||
	    !(vuser) || (vuser->guest)) {
		uid = conn->uid;
		gid = conn->gid;
		groups = conn->groups;
		ngroups = conn->ngroups;
	} else {
		if (!vuser) {
			DEBUG(2,("Invalid vuid used %d\n",key->vuid));
			return(False);
		}
		uid = vuser->uid;
		gid = vuser->gid;
		ngroups = vuser->n_groups;
		groups  = vuser->groups;
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
	
	/* fortunately, become_unix_sec_ctx() now copies the groups */
	ret = become_unix_sec_ctx(key, conn, uid, gid, ngroups, groups);

	/* free the groups *after* setting them! */
	vuid_free_user_struct(vuser);

	return ret;
}

/****************************************************************************
  unbecome the user of a connection number
****************************************************************************/
BOOL unbecome_user(void )
{
	extern vuser_key *user_key;
	user_key = NULL;

  if (!current_user.conn)
    return(False);

  return unbecome_to_initial_uid();
}

