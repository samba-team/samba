/*
   Unix SMB/Netbios implementation.
   Version 3.0
   Samba utility functions
   Copyright (C) Simo Sorce 2001

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

/****************************************************************
 Returns a single linked list of group entries.
 Use grent_free() to free it after use.
****************************************************************/
struct sys_grent * getgrent_list(void)
{
	struct sys_grent *glist;
	struct sys_grent *gent;
	struct group *grp;
	
	gent = (struct sys_grent *) malloc(sizeof(struct sys_grent));
	if (gent == NULL) {
		DEBUG (0, ("Out of memory in getgrent_list!\n"));
		return NULL;
	}
	glist = gent;
	
	setgrent();
	grp = getgrent();
	while (grp != NULL)
	{
		int i,num;
		
		bzero (gent, sizeof(struct sys_grent));
		if (grp->gr_name) gent->gr_name = strdup(grp->gr_name);
		if (grp->gr_passwd) gent->gr_passwd = strdup(grp->gr_passwd);
		gent->gr_gid = grp->gr_gid;
		
		/* number of strings in gr_mem */
		for (num = 0; grp->gr_mem[num];	num++);
		
		/* alloc space for gr_mem string pointers */
		gent->gr_mem = (char **) malloc(num+1 * sizeof(char *));
		if (gent->gr_mem == NULL) {
			DEBUG(0, ("Out of memory in getgrent_list!\n"));
			endgrent();
			grent_free(glist);
			return NULL;
		}
		for (i=0; i < num; i++)
			gent->gr_mem[i] = strdup(grp->gr_mem[i]);
		gent->gr_mem[num] = NULL;
		
		grp = getgrent();
		if (grp)
		{
			gent->next = (struct sys_grent *) malloc(sizeof(struct sys_grent));
			if (gent->next == NULL) {
				DEBUG(0, ("Out of memory in getgrent_list!\n"));
				endgrent();
				grent_free(glist);
				return NULL;
			}
			gent = gent->next;
		}
	}
	
	endgrent();
	return glist;
}

/****************************************************************
 Free the single linked list of group entries made by
 getgrent_list()
****************************************************************/
void grent_free (struct sys_grent *glist)
{
	while (glist)
	{
		char **ary;
		struct sys_grent *temp;
		
		if (glist->gr_name) free(glist->gr_name);
		if (glist->gr_passwd) free(glist->gr_passwd);
		if (glist->gr_mem)
		{
			ary = glist->gr_mem;
			while (*ary)
			{
				free(*ary);
				ary++;
			}
			free(glist->gr_mem);
		}
		temp = glist->next;
		free(glist);
		glist = temp;
	}
}

/****************************************************************
 Returns a single linked list of passwd entries.
 Use pwent_free() to free it after use.
****************************************************************/
struct sys_pwent * getpwent_list(void)
{
	struct sys_pwent *plist;
	struct sys_pwent *pent;
	struct passwd *pwd;
	
	pent = (struct sys_pwent *) malloc(sizeof(struct sys_pwent));
	if (pent == NULL) {
		DEBUG (0, ("Out of memory in getpwent_list!\n"));
		return NULL;
	}
	plist = pent;
	
	setpwent();
	pwd = getpwent();
	while (pwd != NULL)
	{
		bzero (pent, sizeof(struct sys_pwent));
		if (pwd->pw_name) pent->pw_name = strdup(pwd->pw_name);
		if (pwd->pw_passwd) pent->pw_passwd = strdup(pwd->pw_passwd);
		pent->pw_uid = pwd->pw_uid;
		pent->pw_gid = pwd->pw_gid;
		if (pwd->pw_gecos) pent->pw_name = strdup(pwd->pw_gecos);
		if (pwd->pw_dir) pent->pw_name = strdup(pwd->pw_dir);
		if (pwd->pw_shell) pent->pw_name = strdup(pwd->pw_shell);

		
		pwd = getpwent();
		if (pwd)
		{
			pent->next = (struct sys_pwent *) malloc(sizeof(struct sys_pwent));
			if (pent->next == NULL) {
				DEBUG(0, ("Out of memory in getgrent_list!\n"));
				endpwent();
				pwent_free(plist);
				return NULL;
			}
			pent = pent->next;
		}
	}
	
	endpwent();
	return plist;

}

/****************************************************************
 Free the single linked list of passwd entries made by
 getpwent_list()
****************************************************************/
void pwent_free (struct sys_pwent *plist)
{
	while (plist)
	{
		struct sys_pwent *temp;
		
		if (plist->pw_name) free(plist->pw_name);
		if (plist->pw_passwd) free(plist->pw_passwd);
		if (plist->pw_gecos) free(plist->pw_gecos);
		if (plist->pw_dir) free(plist->pw_dir);
		if (plist->pw_shell) free(plist->pw_shell);

		temp = plist->next;
		free(plist);
		plist = temp;
	}
}

