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
BOOL getgroups_user(const char *user, gid_t **groups, int *ngroups)
{
	struct passwd *pwd;
	int ngrp, max_grp;
	gid_t *temp_groups;
	int i;

	pwd = getpwnam_alloc(user);
	if (!pwd) return False;

	max_grp = groups_max();
	temp_groups = (gid_t *)malloc(sizeof(gid_t) * max_grp);
	if (! groups) {
		passwd_free(&pwd);
		errno = ENOMEM;
		return False;
	}

	ngrp = sys_getgrouplist(user, pwd->pw_gid, temp_groups, &max_grp);
	if (ngrp <= 0) {
		passwd_free(&pwd);
		SAFE_FREE(temp_groups);
		return False;
	}

	/* Add in primary group first */
	add_gid_to_array_unique(pwd->pw_gid, groups, ngroups);

	passwd_free(&pwd);

	for (i=0; i<max_grp; i++)
		add_gid_to_array_unique(temp_groups[i], groups, ngroups);

	SAFE_FREE(temp_groups);
	return True;
}

/*******************************************************************
 Map a username from a dos name to a unix name by looking in the username
 map. Note that this modifies the name in place.
 This is the main function that should be called *once* on
 any incoming or new username - in order to canonicalize the name.
 This is being done to de-couple the case conversions from the user mapping
 function. Previously, the map_username was being called
 every time Get_Pwnam was called.
 Returns True if username was changed, false otherwise.
********************************************************************/

BOOL map_username(fstring user)
{
	static BOOL initialised=False;
	static fstring last_from,last_to;
	XFILE *f;
	char *mapfile = lp_username_map();
	char *s;
	pstring buf;
	BOOL mapped_user = False;

	char *unix_name;
	BOOL res, is_user;

	if (!*user)
		return False;

	become_root();
	res = nt_to_unix_name(NULL, user, &unix_name, &is_user);
	unbecome_root();

	if (res) {
		if (is_user) {
			fstrcpy(user, unix_name);
			SAFE_FREE(unix_name);
			return True;
		}
		SAFE_FREE(unix_name);
	}

	if (!*mapfile)
		return False;

	if (!initialised) {
		*last_from = *last_to = 0;
		initialised = True;
	}

	if (strequal(user,last_to))
		return False;

	if (strequal(user,last_from)) {
		DEBUG(3,("Mapped user %s to %s\n",user,last_to));
		fstrcpy(user,last_to);
		return True;
	}
  
	f = x_fopen(mapfile,O_RDONLY, 0);
	if (!f) {
		DEBUG(0,("can't open username map %s. Error %s\n",mapfile, strerror(errno) ));
		return False;
	}

	DEBUG(4,("Scanning username map %s\n",mapfile));

	while((s=fgets_slash(buf,sizeof(buf),f))!=NULL) {
		char *unixname = s;
		char *dosname = strchr_m(unixname,'=');
		char **dosuserlist;
		BOOL return_if_mapped = False;

		if (!dosname)
			continue;

		*dosname++ = 0;

		while (isspace((int)*unixname))
			unixname++;

		if ('!' == *unixname) {
			return_if_mapped = True;
			unixname++;
			while (*unixname && isspace((int)*unixname))
				unixname++;
		}
    
		if (!*unixname || strchr_m("#;",*unixname))
			continue;

		{
			int l = strlen(unixname);
			while (l && isspace((int)unixname[l-1])) {
				unixname[l-1] = 0;
				l--;
			}
		}

		dosuserlist = str_list_make(dosname, NULL);
		if (!dosuserlist) {
			DEBUG(0,("Unable to build user list\n"));
			return False;
		}

		if (strchr_m(dosname,'*') || user_in_list(user, (const char **)dosuserlist, NULL, 0)) {
			DEBUG(3,("Mapped user %s to %s\n",user,unixname));
			mapped_user = True;
			fstrcpy(last_from,user);
			sscanf(unixname,"%s",user);
			fstrcpy(last_to,user);
			if(return_if_mapped) {
				str_list_free (&dosuserlist);
				x_fclose(f);
				return True;
			}
		}
    
		str_list_free (&dosuserlist);
	}

	x_fclose(f);

	/*
	 * Setup the last_from and last_to as an optimization so 
	 * that we don't scan the file again for the same user.
	 */
	fstrcpy(last_from,user);
	fstrcpy(last_to,user);

	return mapped_user;
}
