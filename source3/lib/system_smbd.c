/* 
   Unix SMB/CIFS implementation.
   system call wrapper interface.
   Copyright (C) Andrew Tridgell 2002
   Copyright (C) Andrew Barteltt 2002

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

/* 
   This file may assume linkage with smbd - for things like become_root()
   etc. 
*/

#include "includes.h"

#ifndef HAVE_GETGROUPLIST
/*
  This is a *much* faster way of getting the list of groups for a user
  without changing the current supplemenrary group list. The old
  method used getgrent() which could take 20 minutes on a really big
  network with hundeds of thousands of groups and users. The new method
  takes a couple of seconds.

  NOTE!! this function only works if it is called as root!
  */
static int getgrouplist_internals(const char *user, gid_t gid, gid_t *groups, int *grpcnt)
{
	gid_t *gids_saved;
	int ret, ngrp_saved, num_gids;

	if (non_root_mode()) {
		*grpcnt = 0;
		return 0;
	}

	/* work out how many groups we need to save */
	ngrp_saved = getgroups(0, NULL);
	if (ngrp_saved == -1) {
		/* this shouldn't happen */
		return -1;
	}
	
	gids_saved = (gid_t *)malloc(sizeof(gid_t) * (ngrp_saved+1));
	if (!gids_saved) {
		errno = ENOMEM;
		return -1;
	}

	ngrp_saved = getgroups(ngrp_saved, gids_saved);
	if (ngrp_saved == -1) {
		SAFE_FREE(gids_saved);
		/* very strange! */
		return -1;
	}

	if (initgroups(user, gid) != 0) {
		DEBUG(0, ("getgrouplist_internals: initgroups() failed!\n"));
		SAFE_FREE(gids_saved);
		return -1;
	}

	/* this must be done to cope with systems that put the current egid in the
	   return from getgroups() */
	save_re_gid();
	set_effective_gid(gid);
	setgid(gid);

	num_gids = getgroups(0, NULL);
	if (num_gids + 1 > *grpcnt) {
		*grpcnt = num_gids + 1;
		ret = -1;
	} else {
		ret = getgroups(*grpcnt - 1, &groups[1]);
		if (ret >= 0) {
			groups[0] = gid;
			*grpcnt = ret + 1;
		}
	}

	restore_re_gid();

	if (sys_setgroups(ngrp_saved, gids_saved) != 0) {
		/* yikes! */
		DEBUG(0,("ERROR: getgrouplist: failed to reset group list!\n"));
		smb_panic("getgrouplist: failed to reset group list!\n");
		free(gids_saved);
		return -1;
	}
	
	/* this will remove any duplicates gids in the list and 
	   update the group counter */
	   
	remove_duplicate_gids( grpcnt, groups );

	free(gids_saved);
	return ret;
}
#endif

int sys_getgrouplist(const char *user, gid_t gid, gid_t *groups, int *grpcnt)
{
	char *p;
	int retval;

	DEBUG(10,("sys_getgrouplist: user [%s]\n", user));
	
	/* see if we should disable winbindd lookups for local users */
	if ( (p = strchr(user, *lp_winbind_separator())) == NULL ) {
		if ( !winbind_off() )
			DEBUG(0,("sys_getgroup_list: Insufficient environment space for %s\n",
				WINBINDD_DONT_ENV));
		else
			DEBUG(10,("sys_getgrouplist(): disabled winbindd for group lookup [user == %s]\n",
				user));
	}

#ifdef HAVE_GETGROUPLIST
	retval = getgrouplist(user, gid, groups, grpcnt);
#else
	become_root();
	retval = getgrouplist_internals(user, gid, groups, grpcnt);
	unbecome_root();
#endif

	/* allow winbindd lookups */
	winbind_on();
	
	return retval;
}
