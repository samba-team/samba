/*
 * Unix SMB/Netbios implementation. Version 1.9. SMB parameters and setup
 * Copyright (C) Andrew Tridgell 1992-1998 Modified by Jeremy Allison 1995.
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675
 * Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

#ifdef USE_SMBUNIX_DB

extern int DEBUGLEVEL;
extern DOM_SID global_member_sid;

/***************************************************************
 Start to enumerate the smbpasswd list. Returns a void pointer
 to ensure no modification outside this module.
****************************************************************/

static void *startsmbunixgrpent(BOOL update)
{
	return startsmbfilepwent(False);
}

/***************************************************************
 End enumeration of the smbpasswd list.
****************************************************************/

static void endsmbunixgrpent(void *vp)
{
	endsmbfilepwent(vp);
}

/*************************************************************************
 Return the current position in the smbpasswd list as an SMB_BIG_UINT.
 This must be treated as an opaque token.
*************************************************************************/

static SMB_BIG_UINT getsmbunixgrppos(void *vp)
{
	return getsmbfilepwpos(vp);
}

/*************************************************************************
 Set the current position in the smbpasswd list from an SMB_BIG_UINT.
 This must be treated as an opaque token.
*************************************************************************/

static BOOL setsmbunixgrppos(void *vp, SMB_BIG_UINT tok)
{
	return setsmbfilepwpos(vp, tok);
}

/*************************************************************************
 Routine to return the next smbpassgroup entry
 *************************************************************************/
static struct smb_passwd *getsmbunixgrpent(void *vp,
		uint32 **grp_rids, int *num_grps,
		uint32 **als_rids, int *num_alss)
{
	/* Static buffers we will return. */
	struct smb_passwd *pw_buf;
	struct passwd *pw;
	int i;
	int unixgrps;
	gid_t *grps;

	if (vp == NULL)
	{
		DEBUG(0,("getsmbunixgrpent: Bad password file pointer.\n"));
		return NULL;
	}

	pw_buf = getsmbfilepwent(vp);
	
	if (grp_rids != NULL)
	{
		(*grp_rids) = NULL;
		(*num_grps) = 0;
	}

	if (als_rids != NULL)
	{
		(*als_rids) = NULL;
		(*num_alss) = 0;
	}
	
	if (als_rids == NULL && grp_rids == NULL)
	{
		return pw_buf;
	}

	/*
	 * find all unix groups
	 */

	pw = Get_Pwnam(pw_buf->smb_name, False);

	if (pw == NULL)
	{
		return NULL;
	}

	if (get_unixgroups(pw_buf->smb_name, pw->pw_uid, pw->pw_gid, &unixgrps, &grps))
	{
		return NULL;
	}

	/*
	 * check each unix group for a mapping as an nt alias or an nt group
	 */

	for (i = 0; i < unixgrps; i++)
	{
		DOM_SID sid;
		char *unix_grpname;
		uint32 status;
		uint32 rid;

		/*
		 * find the unix name for each user's group.
		 * assume the unix group is an nt name (alias? group? user?)
		 * (user or not our own domain will be an error).
		 */

		unix_grpname = gidtoname(grps[i]);
		if (map_unix_alias_name(unix_grpname, &sid, NULL, NULL))
		{
			/*
			 * ok, the unix groupname is mapped to an alias.
			 * check that it is in our domain.
			 */

			sid_split_rid(&sid, &rid);
			if (!sid_equal(&sid, &global_member_sid))
			{
				pstring sid_str;
				sid_to_string(sid_str, &sid);
				DEBUG(0,("user %s is in a UNIX group %s that maps to an NT Domain Alias RID (0x%x) in another domain (%s)\n",
				          pw_buf->smb_name, unix_grpname, rid, sid_str));
				continue;
			}

			if (add_num_to_list(als_rids, num_alss, rid) == NULL)
			{
				return NULL;
			}
		}
		else if (map_unix_group_name(unix_grpname, &sid, NULL, NULL))
		{
			/*
			 * ok, the unix groupname is mapped to a domain group.
			 * check that it is in our domain.
			 */

			sid_split_rid(&sid, &rid);
			if (!sid_equal(&sid, &global_member_sid))
			{
				pstring sid_str;
				sid_to_string(sid_str, &sid);
				DEBUG(0,("user %s is in a UNIX group %s that maps to an NT Domain Group RID (0x%x) in another domain (%s)\n",
				          pw_buf->smb_name, unix_grpname, rid, sid_str));
				continue;
			}

			if (add_num_to_list(grp_rids, num_grps, rid) == NULL)
			{
				return NULL;
			}
		}
		else if (lp_server_role() == ROLE_DOMAIN_MEMBER)
		{
			/*
			 * server is a member of a domain or stand-alone.
			 * name is not explicitly mapped
			 * so we are responsible for it.
			 * as a LOCAL group.
			 */

			rid = pwdb_gid_to_alias_rid(grps[i]);
			if (add_num_to_list(als_rids, num_alss, rid) == NULL)
			{
				return NULL;
			}
		}
		else if (lp_server_role() != ROLE_DOMAIN_NONE)
		{
			/*
			 * server is a PDC or BDC.
			 * name is explicitly mapped
			 * so we are responsible for it.
			 * as a DOMAIN group.
			 */

			rid = pwdb_gid_to_group_rid(grps[i]);
			if (add_num_to_list(grp_rids, num_grps, rid) == NULL)
			{
				return NULL;
			}
		}
	}

	return pw_buf;
}

static struct passgrp_ops file_ops =
{
	startsmbunixgrpent,
	endsmbunixgrpent,
	getsmbunixgrppos,
	setsmbunixgrppos,
	iterate_getsmbgrpnam,          /* In passgrp.c */
	iterate_getsmbgrpuid,          /* In passgrp.c */
	iterate_getsmbgrprid,          /* In passgrp.c */
	getsmbunixgrpent,
};

struct passgrp_ops *unix_initialise_password_grp(void)
{    
  return &file_ops;
}

#else
 /* Do *NOT* make this function static. It breaks the compile on gcc. JRA */
 void smbpass_dummy_function(void) { } /* stop some compilers complaining */
#endif /* USE_SMBPASS_DB */
