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
int getgroups_user(const char *user, gid_t **groups)
{
	struct passwd *pwd;
	int ngrp, max_grp;

	pwd = getpwnam_alloc(user);
	if (!pwd) return -1;

	max_grp = groups_max();
	(*groups) = (gid_t *)malloc(sizeof(gid_t) * max_grp);
	if (! *groups) {
		passwd_free(&pwd);
		errno = ENOMEM;
		return -1;
	}

	ngrp = sys_getgrouplist(user, pwd->pw_gid, *groups, &max_grp);
	if (ngrp <= 0) {
		passwd_free(&pwd);
		free(*groups);
		return ngrp;
	}

	passwd_free(&pwd);
	return ngrp;
}
