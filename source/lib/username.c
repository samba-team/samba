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
static struct passwd *uname_string_combinations(char *s, struct passwd * (*fn) (char *), int N);
static struct passwd *uname_string_combinations2(char *s, int offset, struct passwd * (*fn) (char *), int N);

/*****************************************************************
 Check if a user or group name is local (this is a *local* name for
 *local* people, there's nothing for you here...).
*****************************************************************/

BOOL name_is_local(const char *name)
{
	return !strchr(name, *lp_winbind_separator());
}

/****************************************************************************
 Get a users home directory.
****************************************************************************/

char *get_user_home_dir(char *user)
{
	static struct passwd *pass;

	pass = Get_Pwnam(user, False);
	if (!pass)
		return(NULL);
	/* Return home directory from struct passwd. */
	return(pass->pw_dir);      
}

/****************************************************************************
 Get a users home service directory.
****************************************************************************/

char *get_user_service_home_dir(char *user)
{
	static struct passwd *pass;
	int snum;

	/* Ensure the user exists. */

	pass = Get_Pwnam(user, False);
	if (!pass)
		return(NULL);

	/* If a path is specified in [homes] then use it instead of the
	   user's home directory from struct passwd. */

	if ((snum = lp_servicenumber(HOMES_NAME)) != -1) {
		static pstring home_dir;

		pstrcpy(home_dir, lp_pathname(snum));
		standard_sub_home(snum, user, home_dir, sizeof(home_dir));

		if (home_dir[0])
			return home_dir;
	}

	/* Return home directory from struct passwd. */

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
	FILE *f;
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
  
	f = sys_fopen(mapfile,"r");
	if (!f) {
		DEBUG(0,("can't open username map %s. Error %s\n",mapfile, strerror(errno) ));
		return False;
	}

	DEBUG(4,("Scanning username map %s\n",mapfile));

	while((s=fgets_slash(buf,sizeof(buf),f))!=NULL) {
		char *unixname = s;
		char *dosname = strchr(unixname,'=');
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
    
		if (!*unixname || strchr("#;",*unixname))
			continue;

		{
			int l = strlen(unixname);
			while (l && isspace((int)unixname[l-1])) {
				unixname[l-1] = 0;
				l--;
			}
		}

		if (strchr(dosname,'*') || user_in_list(user,dosname)) {
			DEBUG(3,("Mapped user %s to %s\n",user,unixname));
			mapped_user = True;
			fstrcpy(last_from,user);
			sscanf(unixname,"%s",user);
			fstrcpy(last_to,user);
			if(return_if_mapped) { 
				fclose(f);
				return True;
			}
		}
	}

	fclose(f);

	/*
	 * Setup the last_from and last_to as an optimization so 
	 * that we don't scan the file again for the same user.
	 */
	fstrcpy(last_from,user);
	fstrcpy(last_to,user);

	return mapped_user;
}

/****************************************************************************
 Get_Pwnam wrapper.
****************************************************************************/

static struct passwd *_Get_Pwnam(char *s)
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
 A wrapper for getpwnam().  The following variations are tried...
    - in all lower case
    - as transmitted IF a different case
    - in all upper case IF that is different from the transmitted username
    - using the lp_usernamelevel() for permutations
 Note that this can change user! The user name is in Unix code page.
****************************************************************************/

struct passwd *Get_Pwnam(char *user,BOOL allow_change)
{
	fstring 	user2, orig_username;
  	int 		usernamelevel = lp_usernamelevel();
	struct 		passwd *ret;  

	if (!user || !(*user))
		return(NULL);

	/* make a few copies to work with */
	fstrcpy(orig_username, user);
	if (!allow_change) {
		/* allow_change was False, so make a copy and temporarily
		   assign the char* user to the temp copy */
		fstrcpy(user2,user);
		user = &user2[0];
	}

	/* try in all lower case first as this is the most
	   common case on UNIX systems */
	unix_to_dos(user);
	strlower(user);
	dos_to_unix(user);

	ret = _Get_Pwnam(user);
	if (ret)
		return(ret);
	
	/* try as transmitted, but only if the original username
	   gives us a different case */
	if (strcmp(user, orig_username) != 0) {
		ret = _Get_Pwnam(orig_username);
		if (ret) {
			if (allow_change)
				fstrcpy(user, orig_username);

			return(ret);
		}
	}

	/* finally, try in all caps if that is a new case */
	unix_to_dos(user);
	strupper(user);
	dos_to_unix(user);

	if (strcmp(user, orig_username) != 0) {
		ret = _Get_Pwnam(user);
		if (ret)
			return(ret);
	}

	/* Try all combinations up to usernamelevel. */
	unix_to_dos(user);
	strlower(user);
	dos_to_unix(user);

	ret = uname_string_combinations(user, _Get_Pwnam, usernamelevel);

	if (ret)
		return(ret);

	return(NULL);
}

/****************************************************************************
 Check if a user is in a netgroup user list.
****************************************************************************/

static BOOL user_in_netgroup_list(char *user,char *ngname)
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
		? "True" : "False"));

	if (innetgr(ngname, NULL, user, mydomain))
		return (True);
#endif /* HAVE_NETGROUP */
	return False;
}

/****************************************************************************
 Check if a user is in a winbind group.
****************************************************************************/
  
static BOOL user_in_winbind_group_list(char *user,char *gname, BOOL *winbind_answered)
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
			DEBUG(10,("user_in_winbind_group_list: user |%s| is in group |%s|\n",
				user, gname ));
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
 Names are in UNIX character set format.
****************************************************************************/

static BOOL user_in_unix_group_list(char *user,const char *gname)
{
	struct passwd *pass = Get_Pwnam(user,False);
	struct sys_userlist *user_list;
	struct sys_userlist *member;

	DEBUG(10,("user_in_unix_group_list: checking user %s in group %s\n", user, gname));

 	/*
 	 * We need to check the users primary group as this
 	 * group is implicit and often not listed in the group database.
 	 */
 
 	if (pass) {
 		if (strequal_unix(gname, gidtoname(pass->pw_gid))) {
 			DEBUG(10,("user_in_unix_group_list: group %s is primary group.\n", gname ));
 			return True;
 		}
 	}
 
	user_list = get_users_in_group(gname);
 	if (user_list == NULL) {
 		DEBUG(10,("user_in_unix_group_list: no such group %s\n", gname ));
 		return False;
 	}

	for (member = user_list; member; member = member->next) {
 		DEBUG(10,("user_in_unix_group_list: checking user %s against member %s\n",
			user, member->unix_name ));
  		if (strequal_unix(member->unix_name,user)) {
			free_userlist(user_list);
			DEBUG(10,("user_in_unix_group_list: user |%s| is in group |%s|\n", user, gname));
  			return(True);
  		}
	}

	free_userlist(user_list);
	return False;
}	      

/****************************************************************************
 Check if a user is in a group list. Ask winbind first, then use UNIX.
 Names are in UNIX character set format.
****************************************************************************/

BOOL user_in_group_list(char *user,char *gname)
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
 Names are in UNIX character set format.
****************************************************************************/

BOOL user_in_list(char *user,char *list)
{
	pstring tok;
	const char *p=list;

	DEBUG(10,("user_in_list: checking user %s in list %s\n", user, list));

	while (next_token(&p,tok,LIST_SEP, sizeof(tok))) {

		DEBUG(10,("user_in_list: checking user |%s| against |%s|\n", user, tok));

		/*
		 * Check raw username.
		 */
		if (strequal_unix(user,tok)) {
			DEBUG(10,("user_in_list: user |%s| matches |%s|\n", user, tok));
			return(True);
		}

		/*
		 * Now check to see if any combination
		 * of UNIX and netgroups has been specified.
		 */

		if(*tok == '@') {
			/*
			 * Old behaviour. Check netgroup list
			 * followed by UNIX list.
			 */
			if(user_in_netgroup_list(user,&tok[1]))
				return True;
			if(user_in_group_list(user,&tok[1]))
				return True;
		} else if (*tok == '+') {

			if(tok[1] == '&') {
				/*
				 * Search UNIX list followed by netgroup.
				 */
				if(user_in_group_list(user,&tok[2]))
					return True;
				if(user_in_netgroup_list(user,&tok[2]))
					return True;

			} else {

				/*
				 * Just search UNIX list.
				 */

				if(user_in_group_list(user,&tok[1]))
					return True;
			}

		} else if (*tok == '&') {

			if(tok[1] == '+') {
				/*
				 * Search netgroup list followed by UNIX list.
				 */
				if(user_in_netgroup_list(user,&tok[2]))
					return True;
				if(user_in_group_list(user,&tok[2]))
					return True;
			} else {
				/*
				 * Just search netgroup list.
				 */
				if(user_in_netgroup_list(user,&tok[1]))
					return True;
			}
		} else if (!name_is_local(tok)) {
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
			if (winbind_lookup_name(NULL, tok, &g_sid, &name_type) && name_type == SID_NAME_DOM_GRP) {
 
				/* Check if user name is in the Windows group */
				ret = user_in_winbind_group_list(user, tok, &winbind_answered);
 
				if (winbind_answered && ret == True) {
					DEBUG(10,("user_in_list: user |%s| is in group |%s|\n", user, tok));
					return ret;
				}
			}
		}
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

static struct passwd *uname_string_combinations2(char *s,int offset,struct passwd *(*fn)(char *),int N)
{
	ssize_t len = (ssize_t)strlen(s);
	int i;
	struct passwd *ret;

	if (N <= 0 || offset >= len)
		return(fn(s));

	for (i=offset;i<(len-(N-1));i++) {
		char c = s[i];
		if (!islower((int)c))
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

static struct passwd * uname_string_combinations(char *s,struct passwd * (*fn)(char *),int N)
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
these wrappers allow appliance mode to work. In appliance mode the username
takes the form DOMAIN/user
****************************************************************************/
struct passwd *smb_getpwnam(char *user, BOOL allow_change)
{
	struct passwd *pw;
	char *p;
	char *sep;
	extern pstring global_myname;

	pw = Get_Pwnam(user, allow_change);
	if (pw)
		return pw;

	/*
	 * If it is a domain qualified name and it isn't in our password
	 * database but the domain portion matches our local machine name then
	 * lookup just the username portion locally.
	 */

	sep = lp_winbind_separator();
	p = strchr(user,*sep);
	if (p && strncasecmp(global_myname, user, strlen(global_myname))==0)
		return Get_Pwnam(p+1, allow_change);

	return NULL;
}
