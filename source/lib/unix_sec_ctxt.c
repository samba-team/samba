/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   uid/user handling
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

static uid_t initial_uid;
static gid_t initial_gid;

/* what context is current */
struct unix_sec_ctxt curr_ctxt;

/****************************************************************************
initialise the security context routines
****************************************************************************/
void init_sec_ctxt(void)
{
	initial_uid = curr_ctxt.uid = geteuid();
	initial_gid = curr_ctxt.gid = getegid();

	if (initial_gid != 0 && initial_uid == 0) {
#ifdef HAVE_SETRESUID
		setresgid(0,0,0);
#else
		setgid(0);
		setegid(0);
#endif
	}

	initial_uid = geteuid();
	initial_gid = getegid();
}


/****************************************************************************
  become the specified uid 
****************************************************************************/
static BOOL become_uid(uid_t uid)
{
	if (initial_uid != 0)
	{
		return(True);
	}
	
	if (uid == (uid_t)-1 || ((sizeof(uid_t) == 2) && (uid == (uid_t)65535)))
	{
		static int done;
		if (!done) {
			DEBUG(1,("WARNING: using uid %d is a security risk\n",(int)uid));
			done=1;
		}
	}

#ifdef HAVE_TRAPDOOR_UID
#ifdef HAVE_SETUIDX
	/* AIX3 has setuidx which is NOT a trapoor function (tridge) */
	if (setuidx(ID_EFFECTIVE, uid) != 0) {
		if (seteuid(uid) != 0) {
			DEBUG(1,("Can't set uid %d (setuidx)\n", (int)uid));
			return False;
		}
	}
#endif
#endif

#ifdef HAVE_SETRESUID
    if (setresuid(-1,uid,-1) != 0)
#else
    if ((seteuid(uid) != 0) && 
	(setuid(uid) != 0))
#endif
      {
	DEBUG(0,("Couldn't set uid %d currently set to (%d,%d)\n",
		 (int)uid,(int)getuid(), (int)geteuid()));
	if (uid > (uid_t)32000) {
		DEBUG(0,("Looks like your OS doesn't like high uid values - try using a different account\n"));
	}
	return(False);
      }

    if (((uid == (uid_t)-1) || ((sizeof(uid_t) == 2) && (uid == 65535))) && (geteuid() != uid))
	{
	    DEBUG(0,("Invalid uid -1. perhaps you have a account with uid 65535?\n"));
	    return(False);
    }

    curr_ctxt.uid = uid;

    return(True);
}


/****************************************************************************
  become the specified gid
****************************************************************************/
static BOOL become_gid(gid_t gid)
{
  if (initial_uid != 0)
    return(True);

  if (gid == (gid_t)-1 || ((sizeof(gid_t) == 2) && (gid == (gid_t)65535))) {
    DEBUG(1,("WARNING: using gid %d is a security risk\n",(int)gid));    
  }
  
#ifdef HAVE_SETRESUID
  if (setresgid(-1,gid,-1) != 0)
#else
  if (setgid(gid) != 0)
#endif
      {
	DEBUG(0,("Couldn't set gid %d currently set to (%d,%d)\n",
		 (int)gid,(int)getgid(),(int)getegid()));
	if (gid > 32000) {
		DEBUG(0,("Looks like your OS doesn't like high gid values - try using a different account\n"));
	}
	return(False);
      }

  curr_ctxt.gid = gid;

  return(True);
}


/****************************************************************************
  become the user of a connection number
****************************************************************************/
BOOL become_unix_sec_ctxt(struct unix_sec_ctxt const *ctxt)
{
	if (curr_ctxt.uid == ctxt->uid)
	{
		DEBUG(4,("Skipping become_unix_sec_ctxt - already user\n"));
		return(True);
	}

	unbecome_unix_sec_ctxt();

	curr_ctxt.ngroups = ctxt->ngroups;
	curr_ctxt.groups  = ctxt->groups;
	curr_ctxt.name    = ctxt->name;

	if (initial_uid == 0)
	{
		if (!become_uid(ctxt->uid)) return(False);
#ifdef HAVE_SETGROUPS      
		if (curr_ctxt.ngroups > 0)
		{
			if (setgroups(curr_ctxt.ngroups,
					      curr_ctxt.groups) < 0)
			{
				DEBUG(0,("setgroups call failed!\n"));
			}
		}
#endif
		if (!become_gid(ctxt->gid)) return(False);

	}
	
	DEBUG(5,("become_unix_sec_ctxt uid=(%d,%d) gid=(%d,%d)\n",
		 (int)getuid(),(int)geteuid(),(int)getgid(),(int)getegid()));
  
	return(True);
}

/****************************************************************************
  unbecome the user of a connection number
****************************************************************************/
BOOL unbecome_unix_sec_ctxt(void)
{
  if (initial_uid == 0)
    {
#ifdef HAVE_SETRESUID
      setresuid(-1,getuid(),-1);
      setresgid(-1,getgid(),-1);
#else
      if (seteuid(initial_uid) != 0) 
	setuid(initial_uid);
      setgid(initial_gid);
#endif
    }

#ifdef NO_EID
  if (initial_uid == 0)
    DEBUG(2,("Running with no EID\n"));
  initial_uid = getuid();
  initial_gid = getgid();
#else
  if (geteuid() != initial_uid) {
	  DEBUG(0,("Warning: You appear to have a trapdoor uid system\n"));
	  initial_uid = geteuid();
  }
  if (getegid() != initial_gid) {
	  DEBUG(0,("Warning: You appear to have a trapdoor gid system\n"));
	  initial_gid = getegid();
  }
#endif

  curr_ctxt.uid = initial_uid;
  curr_ctxt.gid = initial_gid;
  curr_ctxt.name = NULL;

  curr_ctxt.ngroups = 0;
  curr_ctxt.groups  = NULL;

  DEBUG(5,("unbecome_unix_sec_ctxt now uid=(%d,%d) gid=(%d,%d)\n",
	(int)getuid(),(int)geteuid(),(int)getgid(),(int)getegid()));

  return(True);
}

static struct unix_sec_ctxt curr_ctxt_saved;
static int become_root_depth;

/****************************************************************************
This is used when we need to do a privileged operation (such as mucking
with share mode files) and temporarily need root access to do it. This
call should always be paired with an unbecome_root() call immediately
after the operation

Set save_dir if you also need to save/restore the CWD 
****************************************************************************/
void become_unix_root_sec_ctxt(void) 
{
	if (become_root_depth) {
		DEBUG(0,("ERROR: become root depth is non zero\n"));
	}

	curr_ctxt_saved = curr_ctxt;
	become_root_depth = 1;

	become_uid(0);
	become_gid(0);
}

/****************************************************************************
When the privileged operation is over call this

Set save_dir if you also need to save/restore the CWD 
****************************************************************************/
void unbecome_unix_root_sec_ctxt(void)
{
	if (become_root_depth != 1)
	{
		DEBUG(0,("ERROR: unbecome root depth is %d\n",
			 become_root_depth));
	}

	/* we might have done a become_user() while running as root,
	   if we have then become root again in order to become 
	   non root! */
	if (curr_ctxt.uid != 0)
	{
		become_uid(0);
	}

	/* restore our gid first */
	if (!become_gid(curr_ctxt_saved.gid))
	{
		DEBUG(0,("ERROR: Failed to restore gid\n"));
		exit(-1);
	}

#ifdef HAVE_SETGROUPS      
	if (curr_ctxt_saved.ngroups > 0)
	{
		if (setgroups(curr_ctxt_saved.ngroups,
				      curr_ctxt_saved.groups) < 0)
		{
			DEBUG(0,("setgroups call failed!\n"));
		}
	}
#endif
	/* now restore our uid */
	if (!become_uid(curr_ctxt_saved.uid))
	{
		DEBUG(0,("ERROR: Failed to restore uid\n"));
		exit(-1);
	}

	curr_ctxt = curr_ctxt_saved;

	become_root_depth = 0;
}

