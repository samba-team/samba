/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Username handling
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 1997-2001.
   
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

/* internal functions */
static struct passwd *uname_string_combinations(char *s, struct passwd * (*fn) (const char *), int N);
static struct passwd *uname_string_combinations2(char *s, int offset, struct passwd * (*fn) (const char *), int N);

/*****************************************************************
 Check if a user or group name is local (this is a *local* name for
 *local* people, there's nothing for you here...).
*****************************************************************/

BOOL name_is_local(const char *name)
{
	return !strchr_m(name, *lp_winbind_separator());
}

/****************************************************************************
 Get a users home directory.
****************************************************************************/

char *get_user_home_dir(const char *user)
{
	static struct passwd *pass;

	pass = Get_Pwnam(user);

	if (!pass)
		return(NULL);
	return(pass->pw_dir);      
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

BOOL map_username(char *user)
{
	static BOOL initialised=False;
	static fstring last_from,last_to;
	XFILE *f;
	char *mapfile = lp_username_map();
	char *s;
	pstring buf;
	BOOL mapped_user = False;

	if (!*user)
		return False;

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

		while (isspace(*unixname))
			unixname++;

		if ('!' == *unixname) {
			return_if_mapped = True;
			unixname++;
			while (*unixname && isspace(*unixname))
				unixname++;
		}
    
		if (!*unixname || strchr_m("#;",*unixname))
			continue;

		{
			int l = strlen(unixname);
			while (l && isspace(unixname[l-1])) {
				unixname[l-1] = 0;
				l--;
			}
		}

		dosuserlist = lp_list_make(dosname);
		if (!dosuserlist) {
			DEBUG(0,("Unable to build user list\n"));
			return False;
		}

		if (strchr_m(dosname,'*') || user_in_list(user, dosuserlist)) {
			DEBUG(3,("Mapped user %s to %s\n",user,unixname));
			mapped_user = True;
			fstrcpy(last_from,user);
			sscanf(unixname,"%s",user);
			fstrcpy(last_to,user);
			if(return_if_mapped) {
				lp_list_free (&dosuserlist);
				x_fclose(f);
				return True;
			}
		}
    
		lp_list_free (&dosuserlist);
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

/****************************************************************************
 Get_Pwnam wrapper
****************************************************************************/

static struct passwd *_Get_Pwnam(const char *s)
{
	struct passwd *ret;

	ret = sys_getpwnam(s);
	if (ret) {
#ifdef HAVE_GETPWANAM
		struct passwd_adjunct *pwret;
		pwret = getpwanam(s);
		if (pwret && pwret->pwa_passwd)
			pstrcpy(ret->pw_passwd,pwret->pwa_passwd);
#endif
	}

	return(ret);
}


/****************************************************************************
 * A wrapper for getpwnam().  The following variations are tried:
 *   - as transmitted
 *   - in all lower case if this differs from transmitted
 *   - in all upper case if this differs from transmitted
 *   - using lp_usernamelevel() for permutations.
****************************************************************************/

struct passwd *Get_Pwnam_internals(const char *user, char *user2)
{
	struct passwd *ret = NULL;

	if (!user2 || !(*user2))
		return(NULL);

	if (!user || !(*user))
		return(NULL);

	/* Try in all lower case first as this is the most 
	   common case on UNIX systems */
	strlower(user2);
	DEBUG(5,("Trying _Get_Pwnam(), username as lowercase is %s\n",user2));
	ret = _Get_Pwnam(user2);
	if(ret)
		goto done;

	/* Try as given, if username wasn't originally lowercase */
	if(strcmp(user,user2) != 0) {
		DEBUG(5,("Trying _Get_Pwnam(), username as given is %s\n",user));
		ret = _Get_Pwnam(user);
		if(ret)
			goto done;
	}	

	/* Try as uppercase, if username wasn't originally uppercase */
	strupper(user2);
	if(strcmp(user,user2) != 0) {
		DEBUG(5,("Trying _Get_Pwnam(), username as uppercase is %s\n",user2));
		ret = _Get_Pwnam(user2);
		if(ret)
			goto done;
	}

	/* Try all combinations up to usernamelevel */
	strlower(user2);
	DEBUG(5,("Checking combinations of %d uppercase letters in %s\n",lp_usernamelevel(),user2));
	ret = uname_string_combinations(user2, _Get_Pwnam, lp_usernamelevel());

done:
	DEBUG(5,("Get_Pwnam %s find a valid username!\n",ret ? "did":"didn't"));
	return ret;
}

/****************************************************************************
 Get_Pwnam wrapper for modification.
  NOTE: This can potentially modify 'user'! 
****************************************************************************/

struct passwd *Get_Pwnam_Modify(char *user)
{
	fstring user2;
	struct passwd *ret;

	fstrcpy(user2, user);

	ret = Get_Pwnam_internals(user, user2);
	
	/* If caller wants the modified username, ensure they get it  */
	fstrcpy(user,user2);

	/* We can safely assume ret is NULL if none of the above succeed */
	return(ret);  
}

/****************************************************************************
 Get_Pwnam wrapper without modification.
  NOTE: This with NOT modify 'user'! 
****************************************************************************/

struct passwd *Get_Pwnam(const char *user)
{
	fstring user2;
	struct passwd *ret;

	fstrcpy(user2, user);

	ret = Get_Pwnam_internals(user, user2);
	
	/* We can safely assume ret is NULL if none of the above succeed */
	return(ret);  
}

/****************************************************************************
 Check if a user is in a netgroup user list.
****************************************************************************/

static BOOL user_in_netgroup_list(const char *user, const char *ngname)
{
#ifdef HAVE_NETGROUP
	static char *mydomain = NULL;
	if (mydomain == NULL)
		yp_get_default_domain(&mydomain);

	if(mydomain == NULL) {
		DEBUG(5,("Unable to get default yp domain\n"));
		return False;
	}

	DEBUG(5,("looking for user %s of domain %s in netgroup %s\n",
		user, mydomain, ngname));
	DEBUG(5,("innetgr is %s\n", innetgr(ngname, NULL, user, mydomain)
		? "TRUE" : "FALSE"));

	if (innetgr(ngname, NULL, user, mydomain))
		return (True);
#endif /* HAVE_NETGROUP */
	return False;
}

/****************************************************************************
 Check if a user is in a winbind group.
****************************************************************************/
  
static BOOL user_in_winbind_group_list(const char *user, const char *gname, BOOL *winbind_answered)
{
	int num_groups;
	int i;
 	gid_t *groups = NULL;
 	gid_t gid;
 	BOOL ret = False;
 
 	*winbind_answered = False;
 
 	/*
 	 * Get the gid's that this user belongs to.
 	 */
 
 	if ((num_groups = winbind_getgroups(user, 0, NULL)) == -1)
 		return False;
 
 	if (num_groups == 0) {
 		*winbind_answered = True;
 		return False;
 	}
 
 	if ((groups = (gid_t *)malloc(sizeof(gid_t) * num_groups )) == NULL) {
 		DEBUG(0,("user_in_winbind_group_list: malloc fail.\n"));
 		goto err;
 	}
 
 	if ((num_groups = winbind_getgroups(user, num_groups, groups)) == -1) {
 		DEBUG(0,("user_in_winbind_group_list: second winbind_getgroups call \
failed with error %s\n", strerror(errno) ));
 		goto err;
	}
 
 	/*
 	 * Now we have the gid list for this user - convert the gname
 	 * to a gid_t via either winbind or the local UNIX lookup and do the comparison.
 	 */
 
	if ((gid = nametogid(gname)) == (gid_t)-1) {
 		DEBUG(0,("user_in_winbind_group_list: winbind_lookup_name for group %s failed.\n",
 			gname ));
 		goto err;
 	}
 
 	for (i = 0; i < num_groups; i++) {
 		if (gid == groups[i]) {
 			ret = True;
 			break;
 		}
 	}
 
 	*winbind_answered = True;
 	SAFE_FREE(groups);
 	return ret;
 
   err:
 
 	*winbind_answered = False;
 	SAFE_FREE(groups);
 	return False;
}	      
 
/****************************************************************************
 Check if a user is in a UNIX group.
****************************************************************************/

static BOOL user_in_unix_group_list(const char *user,const char *gname)
{
	struct group *gptr;
	char **member;  
	struct passwd *pass = Get_Pwnam(user);

	DEBUG(10,("user_in_unix_group_list: checking user %s in group %s\n", user, gname));

 	/*
 	 * We need to check the users primary group as this
 	 * group is implicit and often not listed in the group database.
 	 */
 
 	if (pass) {
 		if (strequal(gname,gidtoname(pass->pw_gid))) {
 			DEBUG(10,("user_in_unix_group_list: group %s is primary group.\n", gname ));
 			return True;
 		}
 	}
 
 	if ((gptr = (struct group *)getgrnam(gname)) == NULL) {
 		DEBUG(10,("user_in_unix_group_list: no such group %s\n", gname ));
 		return False;
 	}
 
 	member = gptr->gr_mem;
  	while (member && *member) {
 		DEBUG(10,("user_in_unix_group_list: checking user %s against member %s\n", user, *member ));
  		if (strequal(*member,user)) {
  			return(True);
  		}
		member++;
	}

	return False;
}	      

/****************************************************************************
 Check if a user is in a group list. Ask winbind first, then use UNIX.
****************************************************************************/

BOOL user_in_group_list(const char *user, const char *gname)
{
	BOOL winbind_answered = False;
	BOOL ret;

	ret = user_in_winbind_group_list(user, gname, &winbind_answered);
	if (!winbind_answered)
		ret = user_in_unix_group_list(user, gname);

	if (ret)
		DEBUG(10,("user_in_group_list: user |%s| is in group |%s|\n", user, gname));
	return ret;
}

/****************************************************************************
 Check if a user is in a user list - can check combinations of UNIX
 and netgroup lists.
****************************************************************************/

BOOL user_in_list(const char *user,char **list)
{
	if (!list || !*list)
		return False;

	DEBUG(10,("user_in_list: checking user %s in list\n", user));

	while (*list) {

		DEBUG(10,("user_in_list: checking user |%s| in group |%s|\n", user, *list));

		/*
		 * Check raw username.
		 */
		if (strequal(user, *list))
			return(True);

		/*
		 * Now check to see if any combination
		 * of UNIX and netgroups has been specified.
		 */

		if(**list == '@') {
			/*
			 * Old behaviour. Check netgroup list
			 * followed by UNIX list.
			 */
			if(user_in_netgroup_list(user, *list +1))
				return True;
			if(user_in_group_list(user, *list +1))
				return True;
		} else if (**list == '+') {

			if((*(*list +1)) == '&') {
				/*
				 * Search UNIX list followed by netgroup.
				 */
				if(user_in_group_list(user, *list +2))
					return True;
				if(user_in_netgroup_list(user, *list +2))
					return True;

			} else {

				/*
				 * Just search UNIX list.
				 */

				if(user_in_group_list(user, *list +1))
					return True;
			}

		} else if (**list == '&') {

			if(*(*list +1) == '+') {
				/*
				 * Search netgroup list followed by UNIX list.
				 */
				if(user_in_netgroup_list(user, *list +2))
					return True;
				if(user_in_group_list(user, *list +2))
					return True;
			} else {
				/*
				 * Just search netgroup list.
				 */
				if(user_in_netgroup_list(user, *list +1))
					return True;
			}
		} else if (!name_is_local(*list)) {
			/*
			 * If user name did not match and token is not
			 * a unix group and the token has a winbind separator in the
			 * name then see if it is a Windows group.
			 */

			DOM_SID g_sid;
			enum SID_NAME_USE name_type;
			BOOL winbind_answered = False;
			BOOL ret;

			/* Check to see if name is a Windows group */
			if (winbind_lookup_name(*list, &g_sid, &name_type) && name_type == SID_NAME_DOM_GRP) {

				/* Check if user name is in the Windows group */
				ret = user_in_winbind_group_list(user, *list, &winbind_answered);

				if (winbind_answered && ret == True) {
					DEBUG(10,("user_in_list: user |%s| is in group |%s|\n", user, *list));
					return ret;
				}
			}
		}
    
		list++;
	}
	return(False);
}

/* The functions below have been taken from password.c and slightly modified */
/****************************************************************************
 Apply a function to upper/lower case combinations
 of a string and return true if one of them returns true.
 Try all combinations with N uppercase letters.
 offset is the first char to try and change (start with 0)
 it assumes the string starts lowercased
****************************************************************************/

static struct passwd *uname_string_combinations2(char *s,int offset,struct passwd *(*fn)(const char *),int N)
{
	ssize_t len = (ssize_t)strlen(s);
	int i;
	struct passwd *ret;

	if (N <= 0 || offset >= len)
		return(fn(s));

	for (i=offset;i<(len-(N-1));i++) {
		char c = s[i];
		if (!islower(c))
			continue;
		s[i] = toupper(c);
		ret = uname_string_combinations2(s,i+1,fn,N-1);
		if(ret)
			return(ret);
		s[i] = c;
	}
	return(NULL);
}

/****************************************************************************
 Apply a function to upper/lower case combinations
 of a string and return true if one of them returns true.
 Try all combinations with up to N uppercase letters.
 offset is the first char to try and change (start with 0)
 it assumes the string starts lowercased
****************************************************************************/

static struct passwd * uname_string_combinations(char *s,struct passwd * (*fn)(const char *),int N)
{
	int n;
	struct passwd *ret;

	for (n=1;n<=N;n++) {
		ret = uname_string_combinations2(s,0,fn,n);
		if(ret)
			return(ret);
	}  
	return(NULL);
}

/****************************************************************************
 These wrappers allow appliance mode to work. In appliance mode the username
 takes the form DOMAIN/user.
****************************************************************************/

struct passwd *smb_getpwnam(char *user, BOOL allow_change)
{
	struct passwd *pw;
	char *p;
	char *sep;
	extern pstring global_myname;

	if (allow_change)
		pw = Get_Pwnam_Modify(user);
	else
		pw = Get_Pwnam(user);

	if (pw)
		return pw;

	/*
	 * If it is a domain qualified name and it isn't in our password
	 * database but the domain portion matches our local machine name then
	 * lookup just the username portion locally.
	 */

	sep = lp_winbind_separator();
	p = strchr_m(user,*sep);
	if (p && strncasecmp(global_myname, user, strlen(global_myname))==0) {
		if (allow_change)
			pw = Get_Pwnam_Modify(p+1);
		else
			pw = Get_Pwnam(p+1);
	}
	return NULL;
}
