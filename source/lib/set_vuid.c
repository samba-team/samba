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
static struct uid_cache vcache;

/* what user is current? */
extern struct current_user current_user;

extern pstring OriginalDir;

void init_vuid(void)
{
	vcache.entries = 0;
}

/****************************************************************************
  become the user of a connection number
****************************************************************************/
BOOL become_vuser(uint16 vuid)
{
	user_struct *vuser = get_valid_user_struct(vuid);
	gid_t gid;
	uid_t uid;

	unbecome_vuser();

	if((vuser != NULL) && !check_vuser_ok(&vcache, vuser, -1))
		return False;

	if ( vuser != NULL &&
	     current_user.vuid == vuid && 
	     current_user.uid  == vuser->uid)
	{
		DEBUG(4,("Skipping become_vuser - already user\n"));
		return(True);
	}
	uid = vuser->uid;
	gid = vuser->gid;
	current_user.ngroups = vuser->n_groups;
	current_user.groups  = vuser->groups;
	
	if (initial_uid == 0)
	{
		if (!become_gid(gid)) return(False);

#ifdef HAVE_SETGROUPS      
		/* groups stuff added by ih/wreu */
		if (current_user.ngroups > 0)
		{
			if (setgroups(current_user.ngroups,
				      current_user.groups)<0) {
				DEBUG(0,("setgroups call failed!\n"));
			}
		}
#endif

		if (!become_uid(uid)) return(False);
	}
	
	current_user.conn = NULL;
	current_user.vuid = vuid;

	DEBUG(5,("become_vuser uid=(%d,%d) gid=(%d,%d)\n",
		 (int)getuid(),(int)geteuid(),(int)getgid(),(int)getegid()));
  
	return(True);
}

/****************************************************************************
  unbecome a user 
****************************************************************************/
BOOL unbecome_vuser(void)
{
  return unbecome_to_initial_uid();
}

