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

static struct uid_cache vcache;

void init_vuid(void)
{
	init_uid();
	vcache.entries = 0;
}

/****************************************************************************
  become the user of a connection number
****************************************************************************/
BOOL become_vuser(const vuser_key *k)
{
	user_struct *vuser;
	BOOL ret;

	unbecome_vuser();
	vuser = get_valid_user_struct(k);

	if (vuser == NULL)
	{
		return False;
	}

#if 0
	if (!check_vuser_ok(&vcache, vuser, -1))
	{
		DEBUG(2,("become_vuser: check_vuser rejected access\n"));
		vuid_free_user_struct(vuser);
		return False;
	}
#endif

	ret = become_unix_sec_ctx(k, NULL, vuser->uid, vuser->gid,
	                           vuser->n_groups, vuser->groups);
	vuid_free_user_struct(vuser);
	return ret;
}

/****************************************************************************
  unbecome a user 
****************************************************************************/
BOOL unbecome_vuser(void)
{
	return unbecome_to_initial_uid();
}

