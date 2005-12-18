/* 
   Unix SMB/CIFS implementation.
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

static BOOL name_is_local(const char *name)
{
	return !(strchr_m(name, *lp_winbind_separator()));
}

/****************************************************************************
 Get a users home directory.
****************************************************************************/

char *get_user_home_dir(const char *user)
{
	static struct passwd *pass;

	/* Ensure the user exists. */

	pass = Get_Pwnam(user);

	if (!pass)
		return(NULL);
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

BOOL map_username(fstring user)
{
	static BOOL initialised=False;
	static fstring last_from,last_to;
	XFILE *f;
	char *mapfile = lp_username_map();
	char *s;
	pstring buf;
	BOOL mapped_user = False;
	char *cmd = lp_username_map_script();
	
	if (!*user)
		return False;
		
	if (strequal(user,last_to))
		return False;

	if (strequal(user,last_from)) {
		DEBUG(3,("Mapped user %s to %s\n",user,last_to));
		fstrcpy(user,last_to);
		return True;
	}
	
	/* first try the username map script */
	
	if ( *cmd ) {
		char **qlines;
		pstring command;
		int numlines, ret, fd;

		pstr_sprintf( command, "%s \"%s\"", cmd, user );

		DEBUG(10,("Running [%s]\n", command));
		ret = smbrun(command, &fd);
		DEBUGADD(10,("returned [%d]\n", ret));

		if ( ret != 0 ) {
			if (fd != -1)
				close(fd);
			return False;
		}

		numlines = 0;
		qlines = fd_lines_load(fd, &numlines);
		DEBUGADD(10,("Lines returned = [%d]\n", numlines));
		close(fd);

		/* should be either no lines or a single line with the mapped username */

		if (numlines) {
			DEBUG(3,("Mapped user %s to %s\n", user, qlines[0] ));
			fstrcpy( user, qlines[0] );
		}

		file_lines_free(qlines);
		
		return numlines != 0;
	}

	/* ok.  let's try the mapfile */
	
	if (!*mapfile)
		return False;

	if (!initialised) {
		*last_from = *last_to = 0;
		initialised = True;
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

		if (strchr_m(dosname,'*') ||
		    user_in_list(user, (const char **)dosuserlist)) {
			DEBUG(3,("Mapped user %s to %s\n",user,unixname));
			mapped_user = True;
			fstrcpy( last_from,user );
			fstrcpy( user, unixname );
			fstrcpy( last_to,user );
			if ( return_if_mapped ) {
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

/****************************************************************************
 * A wrapper for sys_getpwnam().  The following variations are tried:
 *   - as transmitted
 *   - in all lower case if this differs from transmitted
 *   - in all upper case if this differs from transmitted
 *   - using lp_usernamelevel() for permutations.
****************************************************************************/

static struct passwd *Get_Pwnam_ret = NULL;

static struct passwd *Get_Pwnam_internals(const char *user, char *user2)
{
	struct passwd *ret = NULL;

	if (!user2 || !(*user2))
		return(NULL);

	if (!user || !(*user))
		return(NULL);

	/* Try in all lower case first as this is the most 
	   common case on UNIX systems */
	strlower_m(user2);
	DEBUG(5,("Trying _Get_Pwnam(), username as lowercase is %s\n",user2));
	ret = getpwnam_alloc(user2);
	if(ret)
		goto done;

	/* Try as given, if username wasn't originally lowercase */
	if(strcmp(user, user2) != 0) {
		DEBUG(5,("Trying _Get_Pwnam(), username as given is %s\n",
			 user));
		ret = getpwnam_alloc(user);
		if(ret)
			goto done;
	}

	/* Try as uppercase, if username wasn't originally uppercase */
	strupper_m(user2);
	if(strcmp(user, user2) != 0) {
		DEBUG(5,("Trying _Get_Pwnam(), username as uppercase is %s\n",
			 user2));
		ret = getpwnam_alloc(user2);
		if(ret)
			goto done;
	}

	/* Try all combinations up to usernamelevel */
	strlower_m(user2);
	DEBUG(5,("Checking combinations of %d uppercase letters in %s\n",
		 lp_usernamelevel(), user2));
	ret = uname_string_combinations(user2, getpwnam_alloc,
					lp_usernamelevel());

done:
	DEBUG(5,("Get_Pwnam_internals %s find user [%s]!\n",ret ?
		 "did":"didn't", user));

	return ret;
}

/****************************************************************************
 Get_Pwnam wrapper without modification.
  NOTE: This with NOT modify 'user'! 
  This will return an allocated structure
****************************************************************************/

struct passwd *Get_Pwnam_alloc(const char *user)
{
	fstring user2;
	struct passwd *ret;

	if ( *user == '\0' ) {
		DEBUG(10,("Get_Pwnam: empty username!\n"));
		return NULL;
	}

	fstrcpy(user2, user);

	DEBUG(5,("Finding user %s\n", user));

	ret = Get_Pwnam_internals(user, user2);
	
	return ret;  
}

/****************************************************************************
 Get_Pwnam wrapper without modification.
  NOTE: This with NOT modify 'user'! 
****************************************************************************/

struct passwd *Get_Pwnam(const char *user)
{
	struct passwd *ret;

	ret = Get_Pwnam_alloc(user);
	
	/* This call used to just return the 'passwd' static buffer.
	   This could then have accidental reuse implications, so 
	   we now malloc a copy, and free it in the next use.

	   This should cause the (ab)user to segfault if it 
	   uses an old struct. 
	   
	   This is better than useing the wrong data in security
	   critical operations.

	   The real fix is to make the callers free the returned 
	   malloc'ed data.
	*/

	if (Get_Pwnam_ret) {
		passwd_free(&Get_Pwnam_ret);
	}
	
	Get_Pwnam_ret = ret;

	return ret;  
}

/****************************************************************************
 Check if a user is in a netgroup user list. If at first we don't succeed,
 try lower case.
****************************************************************************/

BOOL user_in_netgroup(const char *user, const char *ngname)
{
#ifdef HAVE_NETGROUP
	static char *mydomain = NULL;
	fstring lowercase_user;

	if (mydomain == NULL)
		yp_get_default_domain(&mydomain);

	if(mydomain == NULL) {
		DEBUG(5,("Unable to get default yp domain\n"));
		return False;
	}

	DEBUG(5,("looking for user %s of domain %s in netgroup %s\n",
		user, mydomain, ngname));

	if (innetgr(ngname, NULL, user, mydomain)) {
		DEBUG(5,("user_in_netgroup: Found\n"));
		return (True);
	} else {

		/*
		 * Ok, innetgr is case sensitive. Try once more with lowercase
		 * just in case. Attempt to fix #703. JRA.
		 */

		fstrcpy(lowercase_user, user);
		strlower_m(lowercase_user);
	
		DEBUG(5,("looking for user %s of domain %s in netgroup %s\n",
			lowercase_user, mydomain, ngname));

		if (innetgr(ngname, NULL, lowercase_user, mydomain)) {
			DEBUG(5,("user_in_netgroup: Found\n"));
			return (True);
		}
	}
#endif /* HAVE_NETGROUP */
	return False;
}

/****************************************************************************
 Check if a user is in a winbind group.
****************************************************************************/
  
static BOOL user_in_winbind_group(const char *user, const char *gname,
				  BOOL *winbind_answered)
{
	int i;
 	gid_t gid, gid_low, gid_high;
 	BOOL ret = False;
	static gid_t *groups = NULL;
	static int num_groups = 0;
	static fstring last_user = "";
 
 	*winbind_answered = False;
 
	if ((gid = nametogid(gname)) == (gid_t)-1) {
 		DEBUG(0,("user_in_winbind_group: nametogid for group %s "
			 "failed.\n", gname ));
 		goto err;
 	}

	if (!lp_idmap_gid(&gid_low, &gid_high)) {
		DEBUG(4, ("winbind gid range not configured, therefore %s "
			  "cannot be a winbind group\n", gname));
 		goto err;
	}

	if (gid < gid_low || gid > gid_high) {
		DEBUG(4, ("group %s is not a winbind group\n", gname));
 		goto err;
	}
 
	/* try to user the last user we looked up */
	/* otherwise fall back to lookups */
	
	if ( !strequal( last_user, user ) || !groups )
 	{
		/* clear any cached information */
		
 	 	SAFE_FREE(groups);
		fstrcpy( last_user, "" );

	 	/*
 		 * Get the gid's that this user belongs to.
 		 */
 
	 	if ((num_groups = winbind_getgroups(user, &groups)) == -1)
 			return False;
			
		if ( num_groups == -1 )
			return False;
 
	 	if ( num_groups == 0 ) {
 			*winbind_answered = True;
 			return False;
 		}
 		
		/* save the last username */
		
		fstrcpy( last_user, user );
		
	}
	else 
		DEBUG(10,("user_in_winbind_group: using cached user "
			  "groups for [%s]\n", user));
 
 	if ( DEBUGLEVEL >= 10 ) {
		DEBUG(10,("user_in_winbind_group: using groups -- "));
	 	for ( i=0; i<num_groups; i++ )
			DEBUGADD(10,("%lu ", (unsigned long)groups[i]));
		DEBUGADD(10,("\n"));	
	}
 
	/*
	 * Now we have the gid list for this user - convert the gname to a
	 * gid_t via either winbind or the local UNIX lookup and do the
	 * comparison.
	 */
 
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

BOOL user_in_unix_group(const char *user,const char *gname)
{
	struct passwd *pass = Get_Pwnam(user);
	struct sys_userlist *user_list;
	struct sys_userlist *member;

	DEBUG(10,("user_in_unix_group: checking user %s in group %s\n",
		  user, gname));

 	/*
 	 * We need to check the users primary group as this
 	 * group is implicit and often not listed in the group database.
 	 */
 
 	if (pass) {
 		if (strequal(gname,gidtoname(pass->pw_gid))) {
 			DEBUG(10,("user_in_unix_group: group %s is "
				  "primary group.\n", gname ));
 			return True;
 		}
 	}
 
	user_list = get_users_in_group(gname);
 	if (user_list == NULL) {
 		DEBUG(10,("user_in_unix_group: no such group %s\n",
			  gname ));
 		return False;
 	}

	for (member = user_list; member; member = member->next) {
 		DEBUG(10,("user_in_unix_group: checking user %s against "
			  "member %s\n", user, member->unix_name ));
  		if (strequal(member->unix_name,user)) {
			free_userlist(user_list);
  			return(True);
  		}
	}

	free_userlist(user_list);
	return False;
}	      

/****************************************************************************
 Check if a user is in a group list. Ask winbind first, then use UNIX.
****************************************************************************/

BOOL user_in_group(const char *user, const char *gname)
{
	BOOL winbind_answered = False;
	BOOL ret;

	ret = user_in_winbind_group(user, gname, &winbind_answered);
	if (!winbind_answered)
		ret = user_in_unix_group(user, gname);

	if (ret)
		DEBUG(10,("user_in_group: user |%s| is in group |%s|\n",
			  user, gname));
	return ret;
}

/****************************************************************************
 Check if a user is in a user list - can check combinations of UNIX
 and netgroup lists.
****************************************************************************/

BOOL user_in_list(const char *user,const char **list)
{
	if (!list || !*list)
		return False;

	DEBUG(10,("user_in_list: checking user %s in list\n", user));

	while (*list) {

		DEBUG(10,("user_in_list: checking user |%s| against |%s|\n",
			  user, *list));

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
			if(user_in_netgroup(user, *list +1))
				return True;
			if(user_in_group(user, *list +1))
				return True;
		} else if (**list == '+') {

			if((*(*list +1)) == '&') {
				/*
				 * Search UNIX list followed by netgroup.
				 */
				if(user_in_group(user, *list +2))
					return True;
				if(user_in_netgroup(user, *list +2))
					return True;

			} else {

				/*
				 * Just search UNIX list.
				 */

				if(user_in_group(user, *list +1))
					return True;
			}

		} else if (**list == '&') {

			if(*(*list +1) == '+') {
				/*
				 * Search netgroup list followed by UNIX list.
				 */
				if(user_in_netgroup(user, *list +2))
					return True;
				if(user_in_group(user, *list +2))
					return True;
			} else {
				/*
				 * Just search netgroup list.
				 */
				if(user_in_netgroup(user, *list +1))
					return True;
			}
		} else if (!name_is_local(*list)) {
			/*
			 * If user name did not match and token is not a unix
			 * group and the token has a winbind separator in the
			 * name then see if it is a Windows group.
			 */

			DOM_SID g_sid;
			enum SID_NAME_USE name_type;
			BOOL winbind_answered = False;
			BOOL ret;
			fstring groupname, domain;
			
			/* Parse a string of the form DOMAIN/user into a
			 * domain and a user */

			char *p = strchr(*list,*lp_winbind_separator());
			
			DEBUG(10,("user_in_list: checking if user |%s| is in "
				  "winbind group |%s|\n", user, *list));

			if (p) {
				fstrcpy(groupname, p+1);
				fstrcpy(domain, *list);
				domain[PTR_DIFF(p, *list)] = 0;

				/* Check to see if name is a Windows group;
				   Win2k native mode DCs will return domain
				   local groups; while NT4 or mixed mode 2k
				   DCs will not */
			
				if ( winbind_lookup_name(domain, groupname,
							 &g_sid, &name_type) 
				     && ( name_type==SID_NAME_DOM_GRP || 
					  (strequal(lp_workgroup(), domain) &&
					   name_type==SID_NAME_ALIAS) ) )
				{
					
					/* Check if user name is in the
					 * Windows group */
					ret = user_in_winbind_group(
						user, *list,
						&winbind_answered);
					
					if (winbind_answered && ret == True) {
						DEBUG(10,("user_in_list: user "
							  "|%s| is in winbind "
							  "group |%s|\n",
							  user, *list));
						return ret;
					}
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

