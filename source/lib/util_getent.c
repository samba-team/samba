/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Simo Sorce 2001
   Copyright (C) Jeremy Allison 2001

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
	memset(gent, '\0', sizeof(struct sys_grent));
	glist = gent;
	
	setgrent();
	grp = getgrent();
	if (grp == NULL) {
		endgrent();
		SAFE_FREE(glist);
		return NULL;
	}

	while (grp != NULL) {
		int i,num;
		
		if (grp->gr_name) {
			if ((gent->gr_name = strdup(grp->gr_name)) == NULL)
				goto err;
		}
		if (grp->gr_passwd) {
			if ((gent->gr_passwd = strdup(grp->gr_passwd)) == NULL)
				goto err;
		}
		gent->gr_gid = grp->gr_gid;
		
		/* number of strings in gr_mem */
		for (num = 0; grp->gr_mem[num];	num++)
			;
		
		/* alloc space for gr_mem string pointers */
		if ((gent->gr_mem = (char **) malloc((num+1) * sizeof(char *))) == NULL)
			goto err;

		memset(gent->gr_mem, '\0', (num+1) * sizeof(char *));

		for (i=0; i < num; i++) {
			if ((gent->gr_mem[i] = strdup(grp->gr_mem[i])) == NULL)
				goto err;
		}
		gent->gr_mem[num] = NULL;
		
		grp = getgrent();
		if (grp) {
			gent->next = (struct sys_grent *) malloc(sizeof(struct sys_grent));
			if (gent->next == NULL)
				goto err;
			gent = gent->next;
			memset(gent, '\0', sizeof(struct sys_grent));
		}
	}
	
	endgrent();
	return glist;

  err:

	endgrent();
	DEBUG(0, ("Out of memory in getgrent_list!\n"));
	grent_free(glist);
	return NULL;
}

/****************************************************************
 Free the single linked list of group entries made by
 getgrent_list()
****************************************************************/

void grent_free (struct sys_grent *glist)
{
	while (glist) {
		struct sys_grent *prev;
		
		SAFE_FREE(glist->gr_name);
		SAFE_FREE(glist->gr_passwd);
		if (glist->gr_mem) {
			int i;
			for (i = 0; glist->gr_mem[i]; i++)
				SAFE_FREE(glist->gr_mem[i]);
			SAFE_FREE(glist->gr_mem);
		}
		prev = glist;
		glist = glist->next;
		SAFE_FREE(prev);
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
	while (pwd != NULL) {
		memset(pent, '\0', sizeof(struct sys_pwent));
		if (pwd->pw_name) {
			if ((pent->pw_name = strdup(pwd->pw_name)) == NULL)
				goto err;
		}
		if (pwd->pw_passwd) {
			if ((pent->pw_passwd = strdup(pwd->pw_passwd)) == NULL)
				goto err;
		}
		pent->pw_uid = pwd->pw_uid;
		pent->pw_gid = pwd->pw_gid;
		if (pwd->pw_gecos) {
			if ((pent->pw_gecos = strdup(pwd->pw_gecos)) == NULL)
				goto err;
		}
		if (pwd->pw_dir) {
			if ((pent->pw_dir = strdup(pwd->pw_dir)) == NULL)
				goto err;
		}
		if (pwd->pw_shell) {
			if ((pent->pw_shell = strdup(pwd->pw_shell)) == NULL)
				goto err;
		}

		pwd = getpwent();
		if (pwd) {
			pent->next = (struct sys_pwent *) malloc(sizeof(struct sys_pwent));
			if (pent->next == NULL)
				goto err;
			pent = pent->next;
		}
	}
	
	endpwent();
	return plist;

  err:

	endpwent();
	DEBUG(0, ("Out of memory in getpwent_list!\n"));
	pwent_free(plist);
	return NULL;
}

/****************************************************************
 Free the single linked list of passwd entries made by
 getpwent_list()
****************************************************************/

void pwent_free (struct sys_pwent *plist)
{
	while (plist) {
		struct sys_pwent *prev;
		
		SAFE_FREE(plist->pw_name);
		SAFE_FREE(plist->pw_passwd);
		SAFE_FREE(plist->pw_gecos);
		SAFE_FREE(plist->pw_dir);
		SAFE_FREE(plist->pw_shell);

		prev = plist;
		plist = plist->next;
		SAFE_FREE(prev);
	}
}

/****************************************************************
 Add the individual group users onto the list.
****************************************************************/

static struct sys_userlist *add_members_to_userlist(struct sys_userlist *list_head, const struct group *grp)
{
	size_t num_users, i;

	/* Count the number of users. */
	for (num_users = 0; grp->gr_mem[num_users]; num_users++)
		;

	for (i = 0; i < num_users; i++) {
		struct sys_userlist *entry = (struct sys_userlist *)malloc(sizeof(*entry));
		if (entry == NULL) {
			free_userlist(list_head);
			return NULL;
		}
		entry->unix_name = (char *)strdup(grp->gr_mem[i]);
		if (entry->unix_name == NULL) {
			SAFE_FREE(entry);
			free_userlist(list_head);
			return NULL;
		}
		DLIST_ADD(list_head, entry);
	}
	return list_head;
}

/****************************************************************
 Get the list of UNIX users in a group.
 We have to enumerate the /etc/group file as some UNIX getgrnam()
 calls won't do that for us (notably Tru64 UNIX).
****************************************************************/

struct sys_userlist *get_users_in_group(const char *gname)
{
	struct sys_userlist *list_head = NULL;
	struct group *gptr;
	fstring domain;
	fstring groupname;
	DOM_SID sid;
	enum SID_NAME_USE name_type;

	/* No point using winbind if we can't split it in the
	   first place */
	if (split_domain_and_name(gname, domain, groupname)) {

		/*
		 * If we're doing this via winbindd, don't do the
		 * entire group list enumeration as we know this is
		 * pointless (and slow).
		 */
		
		if (winbind_lookup_name(domain, groupname, &sid, &name_type) 
		    && name_type == SID_NAME_DOM_GRP) {
			if ((gptr = (struct group *)getgrnam(gname)) == NULL)
				return NULL;
			return add_members_to_userlist(list_head, gptr);
		}
	}
	
#if !defined(BROKEN_GETGRNAM)
	if ((gptr = (struct group *)getgrnam(gname)) == NULL)
		return NULL;
	return add_members_to_userlist(list_head, gptr);
#else
	/* BROKEN_GETGRNAM - True64 */
	setgrent();
	while((gptr = getgrent()) != NULL) {
		if (strequal(gname, gptr->gr_name)) {
			list_head = add_members_to_userlist(list_head, gptr);
			if (list_head == NULL)
				return NULL;
		}
	}
	endgrent();
	return list_head;
#endif
}

/****************************************************************
 Free list allocated above.
****************************************************************/

void free_userlist(struct sys_userlist *list_head)
{
	while (list_head) {
		struct sys_userlist *old_head = list_head;
		DLIST_REMOVE(list_head, list_head);
		SAFE_FREE(old_head->unix_name);
		SAFE_FREE(old_head);
	}
}

/****************************************************************
****************************************************************/

static int int_compare( int *a, int *b ) 
{
	if ( *a == *b )
		return 0;
	else if ( *a < *b )
		return -1;
	else 
		return 1;
}

void remove_duplicate_gids( int *num_groups, gid_t *groups )
{
	int i;
	int count = *num_groups;

	if ( *num_groups <= 0 || !groups )
		return;

	
	DEBUG(8,("remove_duplicate_gids: Enter %d gids\n", *num_groups));

	qsort( groups, *num_groups, sizeof(gid_t), QSORT_CAST int_compare );

	for ( i=1; i<count; ) {
		if ( groups[i-1] == groups[i] ) {
			memmove( &groups[i-1], &groups[i], (count - i + 1)*sizeof(gid_t) );

			/* decrement the total number of groups and do not increment 
			   the loop counter */
			count--;
			continue;
		}
		i++;
	}

	*num_groups = count;

	DEBUG(8,("remove_duplicate_gids: Exit %d gids\n", *num_groups));

	return;
}
