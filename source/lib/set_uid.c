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

/* what user is current? */
extern struct current_user current_user;

pstring OriginalDir;

/****************************************************************************
get the current security context vuid key
****************************************************************************/
const vuser_key *get_sec_ctx(void)
{
	if (current_user.key.vuid != UID_FIELD_INVALID)
	{
		return &current_user.key;
	}
	return NULL;
}

/****************************************************************************
initialise the uid routines
****************************************************************************/
void init_uid(void)
{
	current_user.uid = geteuid();
	current_user.gid = getegid();

	if (current_user.uid != 0 && current_user.gid == 0)
	{
		gain_root_group_privilege();
	}

	current_user.conn = NULL;
	current_user.key.vuid = UID_FIELD_INVALID;

	current_user.ngroups = 0;
	current_user.groups = NULL;

	dos_ChDir(OriginalDir);
}


/****************************************************************************
  become the specified uid 
****************************************************************************/
BOOL become_uid(uid_t uid)
{

	if (uid == (uid_t) - 1
	    || ((sizeof(uid_t) == 2) && (uid == (uid_t) 65535)))
	{
		static int done;
		if (!done)
		{
			DEBUG(1,
			      ("WARNING: using uid %d is a security risk\n",
			       (int)uid));
			done = 1;
		}
	}


	set_effective_uid(uid);

	current_user.uid = uid;

#ifdef WITH_PROFILE
	profile_p->uid_changes++;
#endif

	return (True);
}


/****************************************************************************
  become the specified gid
****************************************************************************/
BOOL become_gid(gid_t gid)
{
	if (gid == (gid_t) - 1
	    || ((sizeof(gid_t) == 2) && (gid == (gid_t) 65535)))
	{
		DEBUG(1, ("WARNING: using gid %d is a security risk\n",
			  (int)gid));
	}

	set_effective_gid(gid);

	current_user.gid = gid;

	return (True);
}

/****************************************************************************
  unbecome a user 
****************************************************************************/
BOOL unbecome_to_initial_uid(void)
{
	if (!current_user.conn)
		return (False);

	dos_ChDir(OriginalDir);

	set_effective_uid(0);
	set_effective_gid(0);

	if (geteuid() != 0)
	{
		DEBUG(0,
		      ("Warning: You appear to have a trapdoor uid system\n"));
	}
	if (getegid() != 0)
	{
		DEBUG(0,
		      ("Warning: You appear to have a trapdoor gid system\n"));
	}

	current_user.uid = 0;
	current_user.gid = 0;

	if (dos_ChDir(OriginalDir) != 0)
		DEBUG(0, ("chdir(%s) failed in unbecome_user\n",
			  OriginalDir));

	DEBUG(5, ("unbecome_user now uid=(%d,%d) gid=(%d,%d)\n",
		  (int)getuid(), (int)geteuid(), (int)getgid(),
		  (int)getegid()));

	current_user.conn = NULL;
	current_user.key.vuid = UID_FIELD_INVALID;

	return (True);
}

/****************************************************************************
  become the specified uid and gid
****************************************************************************/
BOOL become_id(uid_t uid, gid_t gid)
{
	return (become_gid(gid) && become_uid(uid));
}

/****************************************************************************
  become the user of a connection number
****************************************************************************/
BOOL become_unix_sec_ctx(const vuser_key * k, connection_struct * conn,
			 uid_t new_uid, gid_t new_gid,
			 int n_groups, gid_t * groups)
{
	gid_t gid;
	uid_t uid;

	if (current_user.uid == new_uid &&
	    current_user.key.pid == k->pid &&
	    current_user.key.vuid == k->vuid)
	{
		DEBUG(4, ("Skipping become_unix_sec_ctx - already user\n"));
		return (True);
	}

	unbecome_to_initial_uid();

	uid = new_uid;
	gid = new_gid;
	current_user.ngroups = n_groups;
	current_user.groups = groups;

	if (!become_gid(gid))
		return (False);

#ifdef HAVE_SETGROUPS
	if (!(conn != NULL && conn->ipc))
	{
		/* groups stuff added by ih/wreu */
		if (current_user.ngroups > 0)
		{
			if (setgroups(current_user.ngroups,
				      current_user.groups) < 0)
			{
				DEBUG(0, ("setgroups call failed!\n"));
			}
		}
	}
	{
		int i;
		DEBUG(3, ("Setting %d in %d groups: ", (int)new_uid, n_groups));
		for (i = 0; i < n_groups; i++)
		{
			DEBUG(3, ("%s%d", (i ? ", " : ""), (int)groups[i]));
		}
		DEBUG(3, ("\n"));
	}
#endif

	if (conn == NULL)
	{
		if (!become_uid(uid))
			return False;
	}
	else
	{
		if (!conn->admin_user && !become_uid(uid))
			return False;
	}

	current_user.conn = conn;
	current_user.key = *k;

	DEBUG(5,
	      ("become_unix_sec_ctx uid=(%d,%d) gid=(%d,%d) vuser=(%d,%x)\n",
	       (int)getuid(), (int)geteuid(), (int)getgid(), (int)getegid(),
	       current_user.key.pid, current_user.key.vuid));

	return (True);
}

/****************************************************************************
become the guest user
****************************************************************************/
BOOL become_guest(void)
{
	BOOL ret;
	const struct passwd *pass = NULL;

	if (!pass)
		pass = Get_Pwnam(lp_guestaccount(-1), True);
	if (!pass)
		return (False);

#ifdef AIX
	/* MWW: From AIX FAQ patch to WU-ftpd: call initgroups before setting IDs */
	initgroups(pass->pw_name, (gid_t) pass->pw_gid);
#endif

	ret = become_id(pass->pw_uid, pass->pw_gid);

	if (!ret)
	{
		DEBUG(1,
		      ("Failed to become guest. Invalid guest account?\n"));
	}

	current_user.conn = NULL;
	current_user.key.vuid = UID_FIELD_INVALID;

	return (ret);
}

static struct current_user current_user_saved;
static int become_root_depth = 0;
static pstring become_root_dir;

/****************************************************************************
This is used when we need to do a privilaged operation (such as mucking
with share mode files) and temporarily need root access to do it. This
call should always be paired with an unbecome_root() call immediately
after the operation

Set save_dir if you also need to save/restore the CWD 
****************************************************************************/
void become_root(BOOL save_dir)
{
	if (become_root_depth < 0)
	{
		DEBUG(0, ("ERROR: become root depth is negative!\n"));
	}
	if (save_dir)
		dos_GetWd(become_root_dir);

	current_user_saved = current_user;
	become_root_depth++;

	become_uid(0);
	become_gid(0);
}

/****************************************************************************
When the privilaged operation is over call this

Set save_dir if you also need to save/restore the CWD 
****************************************************************************/
void unbecome_root(BOOL restore_dir)
{
	if (become_root_depth <= 0)
	{
		DEBUG(0, ("ERROR: unbecome root depth is %d\n",
			  become_root_depth));
		SMB_ASSERT(False);
	}

	become_root_depth--;

	if (become_root_depth > 0)
	{
		DEBUG(10, ("not yet root: unbecome root depth is %d\n",
			   become_root_depth));
		return;
	}
	/* we might have done a become_user() while running as root,
	   if we have then become root again in order to become 
	   non root! */
	if (current_user.uid != 0)
	{
		become_uid(0);
	}

	/* restore our gid first */
	if (!become_gid(current_user_saved.gid))
	{
		DEBUG(0, ("ERROR: Failed to restore gid\n"));
		exit_server("Failed to restore gid");
	}

#ifdef HAVE_SETGROUPS
	if (current_user_saved.ngroups > 0)
	{
		if (setgroups(current_user_saved.ngroups,
			      current_user_saved.groups) < 0)
			DEBUG(0, ("ERROR: setgroups call failed!\n"));
	}
#endif

	/* now restore our uid */
	if (!become_uid(current_user_saved.uid))
	{
		DEBUG(0, ("ERROR: Failed to restore uid\n"));
		exit_server("Failed to restore uid");
	}

	if (restore_dir)
		dos_ChDir(become_root_dir);

	current_user = current_user_saved;
}
