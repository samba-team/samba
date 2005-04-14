/*
   Unix SMB/CIFS implementation.
   Samba utility functions, used in smbd only
   Copyright (C) Andrew Tridgell 2002

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

/* 
   This function requires sys_getgrouplist - which is only
   available in smbd due to it's use of become_root() in a 
   legacy systems hack.
*/

/*
  return a full list of groups for a user

  returns the number of groups the user is a member of. The return will include the
  users primary group.

  remember to free the resulting gid_t array

  NOTE! uses become_root() to gain correct priviages on systems
  that lack a native getgroups() call (uses initgroups and getgroups)
*/
BOOL getgroups_user(const char *user, gid_t primary_gid, gid_t **ret_groups, int *ngroups)
{
	int ngrp, max_grp;
	gid_t *temp_groups;
	gid_t *groups;
	int i;

	max_grp = groups_max();
	temp_groups = SMB_MALLOC_ARRAY(gid_t, max_grp);
	if (! temp_groups) {
		return False;
	}

	if (sys_getgrouplist(user, primary_gid, temp_groups, &max_grp) == -1) {
		
		gid_t *groups_tmp;
		
		groups_tmp = SMB_REALLOC_ARRAY(temp_groups, gid_t, max_grp);
		
		if (!groups_tmp) {
			SAFE_FREE(temp_groups);
			return False;
		}
		temp_groups = groups_tmp;
		
		if (sys_getgrouplist(user, primary_gid, temp_groups, &max_grp) == -1) {
			DEBUG(0, ("get_user_groups: failed to get the unix group list\n"));
			SAFE_FREE(temp_groups);
			return False;
		}
	}
	
	ngrp = 0;
	groups = NULL;

	/* Add in primary group first */
	add_gid_to_array_unique(primary_gid, &groups, &ngrp);

	for (i=0; i<max_grp; i++)
		add_gid_to_array_unique(temp_groups[i], &groups, &ngrp);

	*ngroups = ngrp;
	*ret_groups = groups;
	SAFE_FREE(temp_groups);
	return True;
}

