/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Username handling
   Copyright (C) Andrew Tridgell 1992-1995
   
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


/****************************************************************************
get a users home directory. tries as-is then lower case
****************************************************************************/
char *get_home_dir(char *user)
{
  static struct passwd *pass;

  pass = Get_Pwnam(user,False);

  if (!pass) return(NULL);
  return(pass->pw_dir);      
}


/*******************************************************************
map a username from a dos name to a unix name by looking in the username
map
********************************************************************/
void map_username(char *user)
{
  static int depth=0;
  static BOOL initialised=False;
  static fstring last_from,last_to;
  FILE *f;
  char *s;
  char *mapfile = lp_username_map();
  if (!*mapfile || depth) return;

  if (!*user) return;

  if (!initialised) {
    *last_from = *last_to = 0;
    initialised = True;
  }

  if (strequal(user,last_to)) return;

  if (strequal(user,last_from)) {
    DEBUG(3,("Mapped user %s to %s\n",user,last_to));
    strcpy(user,last_to);
    return;
  }
  
  f = fopen(mapfile,"r");
  if (!f) {
    DEBUG(0,("can't open username map %s\n",mapfile));
    return;
  }

  DEBUG(4,("Scanning username map %s\n",mapfile));

  depth++;

  for (; (s=fgets_slash(NULL,80,f)); free(s)) {
    char *unixname = s;
    char *dosname = strchr(unixname,'=');

    if (!dosname) continue;
    *dosname++ = 0;

    while (isspace(*unixname)) unixname++;
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
      StrnCpy(last_from,user,sizeof(last_from)-1);
      sscanf(unixname,"%s",user);
      StrnCpy(last_to,user,sizeof(last_to)-1);
    }
  }

  fclose(f);

  depth--;
}

/****************************************************************************
internals of Get_Pwnam wrapper
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
Note that this changes user!
****************************************************************************/
struct passwd *Get_Pwnam(char *user,BOOL allow_change)
{
  fstring user2;

  struct passwd *ret;  

  if (!user || !(*user))
    return(NULL);

  StrnCpy(user2,user,sizeof(user2)-1);

  if (!allow_change) {
    user = &user2[0];
  }

  map_username(user);

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

  if (allow_change)
    strcpy(user,user2);

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
	  
	  DEBUG(5,("looking for user %s of domain %s in netgroup %s\n",
		   user, mydomain, &tok[1]));
	  DEBUG(5,("innetgr is %s\n",
		   innetgr(&tok[1], (char *) 0, user, mydomain)
		   ? "TRUE" : "FALSE"));
	  
	  if (innetgr(&tok[1], (char *)0, user, mydomain))
	    return (True);
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


