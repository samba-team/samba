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
#include "sids.h"

#ifdef USE_SMBUNIX_DB

extern int DEBUGLEVEL;

/***************************************************************
 Start to enumerate the smbpasswd list. Returns a void pointer
 to ensure no modification outside this module.
****************************************************************/

static void *startsmbunixgrpent(BOOL update)
{
	return startsmbpwent(False);
}

/***************************************************************
 End enumeration of the smbpasswd list.
****************************************************************/

static void endsmbunixgrpent(void *vp)
{
	endsmbpwent(vp);
}

/*************************************************************************
 Return the current position in the smbpasswd list as an SMB_BIG_UINT.
 This must be treated as an opaque token.
*************************************************************************/

static SMB_BIG_UINT getsmbunixgrppos(void *vp)
{
	return getsmbpwpos(vp);
}

/*************************************************************************
 Set the current position in the smbpasswd list from an SMB_BIG_UINT.
 This must be treated as an opaque token.
*************************************************************************/

static BOOL setsmbunixgrppos(void *vp, SMB_BIG_UINT tok)
{
	return setsmbpwpos(vp, tok);
}

/*************************************************************************
 Routine to return the next smbpassgroup entry
 *************************************************************************/
static struct smb_passwd *getsmbunixgrpent(void *vp,
		uint32 **grp_rids, int *num_grps,
		uint32 **als_rids, int *num_alss)
{
	/* Static buffers we will return. */
	struct sam_passwd *pw_buf;
	fstring unix_name;
	int i;
	int unixgrps;
	gid_t *grps;
	BOOL failed = False;

	if (vp == NULL)
	{
		DEBUG(0,("getsmbunixgrpent: Bad password file pointer.\n"));
		return NULL;
	}

	pw_buf = getsam21pwent(vp);
	
	if (pw_buf == NULL)
	{
		return NULL;
	}

	fstrcpy(unix_name, pw_buf->unix_name);

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
		/* they didn't want to know the members. */
		return pwdb_sam_to_smb(pw_buf);
	}

	/*
	 * find all unix groups
	 */

	if (get_unixgroups(unix_name, pw_buf->unix_uid, pw_buf->unix_gid, &unixgrps, &grps))
	{
		return NULL;
	}

	/*
	 * check each unix group for a mapping as an nt alias or an nt group
	 */

	for (i = 0; i < unixgrps && !failed; i++)
	{
		uint32 rid;

		/*
		 * find the unix name for each user's group.
		 * assume the unix group is an nt name (alias? group? user?)
		 * (user or not our own domain will be an error).
		 *
		 * oh, oh, can anyone spot what's missing heeere?
		 * you guessed it: built-in aliases.  those are in
		 * Domain S-1-5-20, and NT Domain Users can only
		 * have lists of RIDs as groups.
		 *
		 * doesn't stop you making NT Domain Users a member
		 * of a BUILTIN Alias (e.g "Administrators" or "Power Users")
		 * it's just that there's no way to tell that from this
		 * API call: wrong domain, sorry.
		 *
		 */

		DOM_NAME_MAP gmep;

		if (!lookupsmbgrpgid(grps[i], &gmep))
		{
			continue;
		}

		sid_split_rid(&gmep.sid, &rid);
		if (!sid_equal(&global_sam_sid, &gmep.sid))
		{
			continue;
		}

		switch (gmep.type)
		{
			case SID_NAME_ALIAS:
			{
				if (als_rids != NULL && add_num_to_list(als_rids, num_alss, rid) == NULL)
				{
					failed = True;
				}
				break;
			}
			case SID_NAME_DOM_GRP:
			case SID_NAME_WKN_GRP:
			{
				if (grp_rids != NULL && add_num_to_list(grp_rids, num_grps, rid) == NULL)
				{
					failed = True;
				}
				break;
			}
			default:
			{
				break;
			}
		}
	}

	if (failed)
	{
		if (grp_rids != NULL && (*grp_rids) != NULL)
		{
			free(*grp_rids);
			(*num_grps) = 0;
		}

		if (als_rids != NULL && (*als_rids) != NULL)
		{
			free(*als_rids);
			(*num_alss) = 0;
		}

		return NULL;
	}

	return pwdb_sam_to_smb(pw_buf);
}

static struct passgrp_ops smbunixgrp_ops =
{
	startsmbunixgrpent,
	endsmbunixgrpent,
	getsmbunixgrppos,
	setsmbunixgrppos,
	iterate_getsmbgrpntnam,          /* In passgrp.c */
	iterate_getsmbgrpuid,          /* In passgrp.c */
	iterate_getsmbgrprid,          /* In passgrp.c */
	getsmbunixgrpent
};

struct passgrp_ops *unix_initialise_password_grp(void)
{    
  return &smbunixgrp_ops;
}

#else
 /* Do *NOT* make this function static. It breaks the compile on gcc. JRA */
 void smbpassgroupunix_dummy_function(void) { } /* stop some compilers complaining */
#endif /* USE_SMBPASS_DB */
