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
********************************************************************/
void map_username(char *user)
{
  static BOOL initialised=False;
  static fstring last_from,last_to;
  FILE *f;
  char *s;
  char *mapfile = lp_username_map();

  if (!*user) return;

  if (!*mapfile) {
    return;
  }

  if (!initialised) {
    *last_from = *last_to = 0;
    initialised = True;
  }

  if (strequal(user,last_to))
    return;

  if (strequal(user,last_from)) {
    DEBUG(3,("Mapped user %s to %s\n",user,last_to));
    fstrcpy(user,last_to);
    return;
  }
  
  f = fopen(mapfile,"r");
  if (!f) {
    DEBUG(0,("can't open username map %s\n",mapfile));
    return;
  }

  DEBUG(4,("Scanning username map %s\n",mapfile));

  for (; (s=fgets_slash(NULL,80,f)); free(s)) {
    char *unixname = s;
    char *dosname = strchr(unixname,'=');
    BOOL return_if_mapped = False;

    if (!dosname) continue;
    *dosname++ = 0;

    while (isspace(*unixname)) unixname++;
    if ('!' == *unixname) {
      return_if_mapped = True;
      unixname++;
      while (*unixname && isspace(*unixname)) unixname++;
    }
    
    if (!*unixname || strchr("#;",*unixname)) continue;

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
        free(s);
        fclose(f);
        return;
      }
    }
  }

  fclose(f);
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
