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
extern DOM_SID global_machine_sid;

/* internal functions */
static struct passwd *uname_string_combinations(char *s, struct passwd * (*fn) (char *), int N);
static struct passwd *uname_string_combinations2(char *s, int offset, struct passwd * (*fn) (char *), int N);

/****************************************************************************
get a users home directory.
****************************************************************************/
char *get_home_dir(char *user)
{
  static struct passwd *pass;

  pass = Get_Pwnam(user, False);

  if (!pass) return(NULL);
  return(pass->pw_dir);      
}


/*******************************************************************
map a username from a dos name to a unix name by looking in the username
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
  
  f = fopen(mapfile,"r");
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
   * Username wasn't mapped. Setup the last_from and last_to
   * as an optimization so that we don't scan the file again
   * for the same user.
   */
  fstrcpy(last_from,user);
  fstrcpy(last_to,user);

  return False;
}

/****************************************************************************
Get_Pwnam wrapper
****************************************************************************/
static struct passwd *_Get_Pwnam(char *s)
{
  struct passwd *ret;

  ret = getpwnam(s);
  if (ret)
    {
#ifdef GETPWANAM
      struct passwd_adjunct *pwret;
      pwret = getpwanam(s);
      if (pwret)
	{
	  free(ret->pw_passwd);
	  ret->pw_passwd = pwret->pwa_passwd;
	}
#endif

    }

  return(ret);
}


/****************************************************************************
a wrapper for getpwnam() that tries with all lower and all upper case 
if the initial name fails. Also tried with first letter capitalised
Note that this can change user!
****************************************************************************/
struct passwd *Get_Pwnam(char *user,BOOL allow_change)
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
  if (ret) return(ret);

  strlower(user);
  ret = _Get_Pwnam(user);
  if (ret)  return(ret);

  strupper(user);
  ret = _Get_Pwnam(user);
  if (ret) return(ret);

  /* try with first letter capitalised */
  if (strlen(user) > 1)
    strlower(user+1);  
  ret = _Get_Pwnam(user);
  if (ret) return(ret);

  /* try with last letter capitalised */
  strlower(user);
  last_char = strlen(user)-1;
  user[last_char] = toupper(user[last_char]);
  DEBUG(3, ("Trying username %s\n", user));
  ret = _Get_Pwnam(user);
  if (ret) return(ret);

  /* try all combinations up to usernamelevel */
  strlower(user);
  ret = uname_string_combinations(user, _Get_Pwnam, usernamelevel);
  if (ret) return(ret);

  if (allow_change)
    fstrcpy(user,user2);

  return(NULL);
}

/****************************************************************************
check if a user is in a user list
****************************************************************************/
BOOL user_in_list(char *user,char *list)
{
  pstring tok;
  char *p=list;

  while (next_token(&p,tok,LIST_SEP))
    {
      if (strequal(user,tok))
	return(True);

#ifdef NETGROUP
      if (*tok == '@')
	{
	  static char *mydomain = NULL;
	  if (mydomain == 0)
	    yp_get_default_domain(&mydomain);

	  if(mydomain == 0)
	    {
              DEBUG(5,("Unable to get default yp domain\n"));
            }
          else
	    {
	  
  	      DEBUG(5,("looking for user %s of domain %s in netgroup %s\n",
		   user, mydomain, &tok[1]));
	      DEBUG(5,("innetgr is %s\n",
		   innetgr(&tok[1], (char *) 0, user, mydomain)
		   ? "TRUE" : "FALSE"));
	  
  	      if (innetgr(&tok[1], (char *)0, user, mydomain))
	        return (True);
            }
	}
#endif


#if HAVE_GETGRNAM 
      if (*tok == '@')
	{
          struct group *gptr;
          char **member;  
	  struct passwd *pass = Get_Pwnam(user,False);

	  if (pass) { 
	    gptr = getgrgid(pass->pw_gid);
	    if (gptr && strequal(gptr->gr_name,&tok[1]))
	      return(True); 
	  } 

	  gptr = (struct group *)getgrnam(&tok[1]);

	  if (gptr)
	    {
	      member = gptr->gr_mem;
	      while (member && *member)
		{
		  if (strequal(*member,user))
		    return(True);
		  member++;
		}
	    }
	}	      
#endif
    }
  return(False);
}

/* The functions below have been taken from password.c and slightly modified */
/****************************************************************************
apply a function to upper/lower case combinations
of a string and return true if one of them returns true.
try all combinations with N uppercase letters.
offset is the first char to try and change (start with 0)
it assumes the string starts lowercased
****************************************************************************/
static struct passwd *uname_string_combinations2(char *s,int offset,struct passwd *(*fn)(char *),int N)
{
  int len = strlen(s);
  int i;
  struct passwd *ret;

#ifdef PASSWORD_LENGTH
  len = MIN(len,PASSWORD_LENGTH);
#endif

  if (N <= 0 || offset >= len)
    return(fn(s));


  for (i=offset;i<(len-(N-1));i++)

    {
      char c = s[i];
      if (!islower(c)) continue;
      s[i] = toupper(c);
      ret = uname_string_combinations2(s,i+1,fn,N-1);
      if(ret) return(ret);
      s[i] = c;
    }
  return(NULL);
}

/****************************************************************************
apply a function to upper/lower case combinations
of a string and return true if one of them returns true.
try all combinations with up to N uppercase letters.
offset is the first char to try and change (start with 0)
it assumes the string starts lowercased
****************************************************************************/
static struct passwd * uname_string_combinations(char *s,struct passwd * (*fn)(char *),int N)
{
  int n;
  struct passwd *ret;

  for (n=1;n<=N;n++)
  {
    ret = uname_string_combinations2(s,0,fn,n);
    if(ret) return(ret);
  }
  return(NULL);
}

#if 0 
/* JRATEST - under construction. */
/**************************************************************************
 Groupname map functionality. The code loads a groupname map file and
 (currently) loads it into a linked list. This is slow and memory
 hungry, but can be changed into a more efficient storage format
 if the demands on it become excessive.
***************************************************************************/

typedef struct groupname_map {
   ubi_slNode next;

   char *windows_name;
   DOM_SID windows_sid;
   char *unix_name;
   gid_t unix_gid;
} groupname_map_entry;

static ubi_slList groupname_map_list;

/**************************************************************************
 Delete all the entries in the groupname map list.
***************************************************************************/

static void delete_groupname_map_list(void)
{
  groupname_map_entry *gmep;

  while((gmep = (groupname_map_entry *)ubi_slRemHead( groupname_map_list )) != NULL) {
    if(gmep->windows_name)
      free(gmep->windows_name);
    if(gmep->unix_name)
      free(gmep->unix_name);
    free((char *)gmep);
  }
}

/**************************************************************************
 Load a groupname map file. Sets last accessed timestamp.
***************************************************************************/

void load_groupname_map(void)
{
  static time_t groupmap_file_last_modified = (time_t)0;
  static BOOL initialized = False;
  char *groupname_map_file = lp_groupname_map();
  struct stat st;
  FILE *fp;
  char *s;
  pstring buf;

  if(!initialized) {
    ubi_slInsert( &groupname_map_list );
    initialized = True;
  }

  if (!*groupname_map_file)
    return;

  if(stat(groupname_map_file, &st) != 0) {
    DEBUG(0, ("load_groupname_map: Unable to stat file %s. Error was %s\n",
               groupname_map_file, strerror(errno) ));
    return;
  }

  /*
   * Check if file has changed.
   */
  if( st.st_mtime <= groupmap_file_last_modified)
    return;

  groupmap_file_last_modified = st.st_mtime;

  /*
   * Load the file.
   */

  fp = fopen(groupname_map_file,"r");
  if (!fp) {
    DEBUG(0,("load_groupname_map: can't open groupname map %s. Error was %s\n",
          mapfile, strerror(errno)));
    return;
  }

  /*
   * Throw away any previous list.
   */
  delete_groupname_map_list();

  DEBUG(4,("load_groupname_map: Scanning groupname map %s\n",groupname_map_file));

  while((s=fgets_slash(buf,sizeof(buf),fp))!=NULL) {
    pstring unixname;
    pstring windows_name;
    struct group *gptr;
    DOM_SID tmp_sid;

    DEBUG(10,("load_groupname_map: Read line |%s|\n", s);

    if (!*s || strchr("#;",*s))
      continue;

    if(!next_token(&s,unixname, "\t\n\r="))
      continue;

    if(!next_token(&s,windows_name, "\t\n\r="))
      continue;

    trim_string(unixname, " ", " ");
    trim_string(windows_name, " ", " ");

    if (!*dosname)
      continue;

    if(!*unixname)
      continue;

    /*
     * Attempt to get the unix gid_t for this name.
     */

    DEBUG(5,("load_groupname_map: Attempting to find unix group %s.\n",
          unixname ));

    if((gptr = (struct group *)getgrnam(unixname)) == NULL) {
      DEBUG(0,("load_groupname_map: getgrnam for group %s failed.\
Error was %s.\n", unixname, strerror(errno) ));
      continue;
    }

    /*
     * Now map to an NT SID.
     */

    if(!lookup_wellknown_sid_from_name(windows_name, &tmp_sid)) {
      /*
       * It's not a well known name, convert the UNIX gid_t
       * to a rid within this domain SID.
       */
      tmp_sid = global_machine_sid;
      tmp_sid.sub_auths[tmp_sid.num_auths++] = 
                    pdb_gid_to_group_rid((gid_t)gptr->gr_gid);
    }

    /*
     * Create the list entry and add it onto the list.
     */

  }

  fclose(fp);
}
#endif /* JRATEST */
