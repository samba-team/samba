/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Username handling
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

/* internal functions */
static struct passwd *uname_string_combinations(char *s, struct passwd * (*fn) (char *), int N);
static struct passwd *uname_string_combinations2(char *s, int offset, struct passwd * (*fn) (char *), int N);

/*******************************************************************
turn a uid into a user name
********************************************************************/
char *uidtoname(uid_t uid)
{
  static char name[40];
  struct passwd *pass=NULL;
    pass = getpwuid(uid);
  if (pass) return(pass->pw_name);
  slprintf(name, sizeof(name) - 1, "%d",(int)uid);
  return(name);
}

/****************************************************************************
Setup the groups a user belongs to.
****************************************************************************/
int get_unixgroups(const char *user, uid_t uid, gid_t gid, int *p_ngroups,
		   gid_t ** p_groups)
{
	int i, ngroups;
	gid_t grp = 0;
	gid_t *groups = NULL;

	if (-1 == initgroups(user, gid))
	{
		DEBUG(0, ("Unable to initgroups!\n"));
		if (getuid() == 0)
		{
			if (gid < 0 || gid > 16000 || uid < 0 || uid > 16000)
			{
				DEBUG(0,
				      ("This is probably a problem with the account %s\n",
				       user));
			}
		}
		return -1;
	}

	ngroups = sys_getgroups(0, &grp);
	if (ngroups <= 0)
	{
		ngroups = 32;
	}

	if ((groups = (gid_t *) malloc(sizeof(gid_t) * ngroups)) == NULL)
	{
		DEBUG(0, ("get_unixgroups malloc fail !\n"));
		return -1;
	}

	ngroups = sys_getgroups(ngroups, groups);

	(*p_ngroups) = ngroups;
	(*p_groups) = groups;

	DEBUG(3, ("%s is in %d groups: ", user, ngroups));
	for (i = 0; i < ngroups; i++)
	{
		DEBUG(3, ("%s%d", (i ? ", " : ""), (int)groups[i]));
	}
	DEBUG(3, ("\n"));

	return 0;
}

/****************************************************************************
get all unix groups.  copying group members is hideous on memory, so it's
NOT done here.  however, names of unix groups _are_ string-allocated so
free_unix_grps() must be called.
****************************************************************************/
BOOL get_unix_grps(int *p_ngroups, struct group **p_groups)
{
	struct group *grp;

	DEBUG(10, ("get_unix_grps\n"));

	if (p_ngroups == NULL || p_groups == NULL)
	{
		return False;
	}

	(*p_ngroups) = 0;
	(*p_groups) = NULL;

	setgrent();

	while ((grp = getgrent()) != NULL)
	{
		struct group *copy_grp;


		(*p_groups) =
			(struct group *)Realloc((*p_groups),
						(size_t) ((*p_ngroups) +
							  1) *
						sizeof(struct group));
		if ((*p_groups) == NULL)
		{
			(*p_ngroups) = 0;
			endgrent();

			return False;
		}

		copy_grp = &(*p_groups)[*p_ngroups];
		memcpy(copy_grp, grp, sizeof(*grp));
		copy_grp->gr_name = strdup(copy_grp->gr_name);
		copy_grp->gr_mem = NULL;

		(*p_ngroups)++;
	}

	endgrent();

	DEBUG(10, ("get_unix_grps: %d groups\n", (*p_ngroups)));
	return True;
}

/****************************************************************************
free memory associated with unix groups.
****************************************************************************/
void free_unix_grps(int ngroups, struct group *p_groups)
{
	int i;

	if (p_groups == NULL)
	{
		return;
	}

	for (i = 0; i < ngroups; i++)
	{
		if (p_groups[i].gr_name != NULL)
		{
			free(p_groups[i].gr_name);
		}
	}

	free(p_groups);
}

/*******************************************************************
turn a gid into a group name
********************************************************************/

char *gidtoname(gid_t gid)
{
	static char name[40];
	struct group *grp = getgrgid(gid);
	if (grp)
		return (grp->gr_name);
	slprintf(name, sizeof(name) - 1, "%d", (int)gid);
	return (name);
}

/*******************************************************************
turn a user name into a uid
********************************************************************/
BOOL nametouid(const char *name, uid_t * uid)
{
	const struct passwd *pass = Get_Pwnam(name, False);
	if (pass)
	{
		*uid = pass->pw_uid;
		return True;
	}
	else if (isdigit(name[0]))
	{
		*uid = (uid_t) get_number(name);
		return True;
	}
	else
	{
		return False;
	}
}

/*******************************************************************
turn a group name into a gid
********************************************************************/

BOOL nametogid(const char *name, gid_t * gid)
{
	struct group *grp = getgrnam(name);
	if (grp)
	{
		*gid = grp->gr_gid;
		return True;
	}
	else if (isdigit(name[0]))
	{
		*gid = (gid_t) get_number(name);
		return True;
	}
	else
	{
		return False;
	}
}

/****************************************************************************
get a users home directory.
****************************************************************************/
char *get_user_home_dir(char *user)
{
	const struct passwd *pass;
	static pstring home_dir;

	pass = Get_Pwnam(user, False);

	if (pass == NULL || pass->pw_dir == NULL) return(NULL);

	pstrcpy(home_dir, pass->pw_dir);
	DEBUG(10,("get_smbhome_dir: returning %s for user %s\n", home_dir, user));
	return home_dir;
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
    DEBUG(0,("can't open username map %s\n",mapfile));
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

    while (isspace(*unixname))
      unixname++;
    if ('!' == *unixname) {
      return_if_mapped = True;
      unixname++;
      while (*unixname && isspace(*unixname))
        unixname++;
    }
    
    if (!*unixname || strchr("#;",*unixname))
      continue;

    {
      int l = strlen(unixname);
      while (l && isspace(unixname[l-1])) {
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
 Get_Pwnam wrapper
****************************************************************************/
static struct passwd *_Get_Pwnam(char *s)
{
	struct passwd *ret;

	ret = sys_getpwnam(s);
#ifdef HAVE_GETPWANAM
	if (ret)
	{
		struct passwd_adjunct *pwret;
		pwret = getpwanam(s);
		if (pwret != NULL && pwret->pwa_passwd != NULL)
		{
			pstrcpy(ret->pw_passwd, pwret->pwa_passwd);
		}
	}
#endif

	return ret;
}


/****************************************************************************
 A wrapper for getpwnam() that tries with all lower and all upper case 
if the initial name fails. Also tried with first letter capitalised
Note that this can change user!  Function returns const to emphasise
the fact that most of the members of the struct passwd * returned are
dynamically allocated.
****************************************************************************/
const struct passwd *Get_Pwnam(char *user,BOOL allow_change)
{
  fstring user2;
  int last_char;
  int usernamelevel = lp_usernamelevel();

  struct passwd *ret;  

  if (!user || !(*user))
    return(NULL);

  StrnCpy(user2,user,sizeof(user2)-1);

  if (!allow_change) {
    user = &user2[0];
  }

  ret = _Get_Pwnam(user);
  if (ret)
    return(ret);

  strlower(user);
  ret = _Get_Pwnam(user);
  if (ret)
    return(ret);

  strupper(user);
  ret = _Get_Pwnam(user);
  if (ret)
    return(ret);

  /* Try with first letter capitalised. */
  if (strlen(user) > 1)
    strlower(user+1);  
  ret = _Get_Pwnam(user);
  if (ret)
    return(ret);

  /* try with last letter capitalised */
  strlower(user);
  last_char = strlen(user)-1;
  user[last_char] = toupper(user[last_char]);
  ret = _Get_Pwnam(user);
  if (ret)
    return(ret);

  /* Try all combinations up to usernamelevel. */
  strlower(user);
  ret = uname_string_combinations(user, _Get_Pwnam, usernamelevel);
  if (ret)
    return(ret);

  if (allow_change)
    fstrcpy(user,user2);

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
  } else {
    DEBUG(5,("looking for user %s of domain %s in netgroup %s\n",
          user, mydomain, ngname));
    DEBUG(5,("innetgr is %s\n",
          innetgr(ngname, NULL, user, mydomain)
          ? "TRUE" : "FALSE"));

    if (innetgr(ngname, NULL, user, mydomain))
      return (True);
  }
#endif /* HAVE_NETGROUP */
  return False;
}

/****************************************************************************
 Check if a user is in a UNIX user list.
****************************************************************************/
static BOOL user_in_group_list(char *user,char *gname)
{
#ifdef HAVE_GETGRENT
  struct group *gptr;
  char **member;  
  const struct passwd *pass = Get_Pwnam(user,False);

	if (pass) { 
    gptr = getgrgid(pass->pw_gid);
    if (gptr && strequal(gptr->gr_name,gname))
      return(True); 
  } 

	while ((gptr = (struct group *)getgrent())) {
		if (!strequal(gptr->gr_name,gname))
			continue;
    member = gptr->gr_mem;
		while (member && *member) {
			if (strequal(*member,user)) {
				endgrent();
        return(True);
			}
      member++;
    }
  }

	endgrent();
#endif /* HAVE_GETGRNAM */
  return False;
}	      

/****************************************************************************
check if a username is valid
****************************************************************************/
BOOL user_ok(char *user,int snum)
{
	pstring valid, invalid;
	BOOL ret;

	StrnCpy(valid, lp_valid_users(snum), sizeof(pstring));
	StrnCpy(invalid, lp_invalid_users(snum), sizeof(pstring));

	pstring_sub(valid,"%S",lp_servicename(snum));
	pstring_sub(invalid,"%S",lp_servicename(snum));
	
	ret = !user_in_list(user,invalid);
	
	if (ret && valid && *valid) {
		ret = user_in_list(user,valid);
	}

	if (ret && lp_onlyuser(snum)) {
		char *user_list = lp_username(snum);
		pstring_sub(user_list,"%S",lp_servicename(snum));
		ret = user_in_list(user,user_list);
	}

	return(ret);
}

/****************************************************************************
check if a user is in a user list - can check combinations of UNIX
and netgroup lists.
****************************************************************************/
BOOL user_in_list(char *user,char *list)
{
  pstring tok;
  char *p=list;

  while (next_token(&p,tok,LIST_SEP, sizeof(tok))) {
    /*
     * Check raw username.
     */
    if (strequal(user,tok))
      return(True);

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

#ifdef PASSWORD_LENGTH
  len = MIN(len,PASSWORD_LENGTH);
#endif

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
struct passwd *smb_getpwnam(char *user, char *domain, BOOL allow_change)
{
	struct passwd *pw;
	fstring userdom;

	pw = Get_Pwnam(user, allow_change);
	if (pw || !domain || !*domain) return pw;

	slprintf(userdom, sizeof(userdom), "%s/%s", domain, user);

	DEBUG(4,("smb_getpwnam trying userdom %s\n", userdom));

	return Get_Pwnam(userdom, allow_change);
}

int smb_initgroups(char *user, char *domain, gid_t group)
{
	fstring userdom;
	int ret;

	ret = initgroups(user, group);
	if (ret==0 || !domain || !*domain) return ret;

	slprintf(userdom, sizeof(userdom), "%s/%s", domain, user);

	DEBUG(4,("smb_initgroups trying userdom %s\n", userdom));

	return initgroups(userdom, group);
}
