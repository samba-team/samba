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


extern DOM_SID global_sam_sid;
extern fstring global_sam_name;

/***************************************************************
 Start to enumerate the alspasswd list. Returns a void pointer
 to ensure no modification outside this module.
****************************************************************/

static void *startalsunixpwent(BOOL update)
{
	setgrent();
	return (void*)(-1);
}

/***************************************************************
 End enumeration of the alspasswd list.
****************************************************************/

static void endalsunixpwent(void *vp)
{
	endgrent();
}

/*************************************************************************
 Return the current position in the alspasswd list as an SMB_BIG_UINT.
 This must be treated as an opaque token.
*************************************************************************/
static SMB_BIG_UINT getalsunixpwpos(void *vp)
{
	return (SMB_BIG_UINT)0;
}

/*************************************************************************
 Set the current position in the alspasswd list from an SMB_BIG_UINT.
 This must be treated as an opaque token.
*************************************************************************/
static BOOL setalsunixpwpos(void *vp, SMB_BIG_UINT tok)
{
	return False;
}

/*************************************************************************
 maps a unix group to a domain sid and an nt alias name.  
*************************************************************************/
static void map_unix_grp_to_nt_als(char *unix_name,
	struct group *unix_grp, char *nt_name, DOM_SID *sid)
{
	BOOL found = False;
	uint32 rid;
	fstring ntname;
	fstring ntdomain;

	if (isdigit(unix_name[0]))
	{
		unix_grp->gr_gid = get_number(unix_name);
		unix_grp->gr_name = unix_name;
		found = map_alias_gid(unix_grp->gr_gid, sid, ntname, ntdomain);
	}
	else
	{
		unix_grp->gr_name = unix_name;
		found = map_unix_alias_name(unix_grp->gr_name, sid, ntname, ntdomain);
	}

	if (found)
	{
		/*
		 * find the NT name represented by this UNIX gid.
		 * then, only accept NT aliass that are in our domain
		 */

		sid_split_rid(sid, &rid);
	}
	else
	{
		/*
		 * assume that the UNIX group is an NT alias with
		 * the same name.  convert gid to a alias rid.
		 */
		
		fstrcpy(ntdomain, global_sam_name);
		fstrcpy(ntname, unix_grp->gr_name);
		sid_copy(sid, &global_sam_sid);
	}

	slprintf(nt_name, sizeof(fstring)-1, "\\%s\\%s",
	         ntdomain, ntname);
}

/*************************************************************************
 Routine to return the next entry in the smbdomainalias list.
 *************************************************************************/
BOOL get_unixalias_members(struct group *als,
				int *num_mem, LOCAL_GRP_MEMBER **members)
{
	int i;
	char *unix_name;
	fstring nt_name;

	if (num_mem == NULL || members == NULL)
	{
		return False;
	}

	(*num_mem) = 0;
	(*members) = NULL;

	for (i = 0; (unix_name = als->gr_mem[i]) != NULL; i++)
	{
		DOM_SID sid;
		struct group unix_grp;

		map_unix_grp_to_nt_als(unix_name, &unix_grp, nt_name, &sid);

		if (!sid_equal(&sid, &global_sam_sid))
		{
			DEBUG(0,("alias database: could not resolve name %s in domain %s\n",
			          unix_name, global_sam_name));
			continue;
		}

		(*members) = Realloc((*members), ((*num_mem)+1) * sizeof(LOCAL_GRP_MEMBER));
		if ((*members) == NULL)
		{
			return False;
		}

		fstrcpy((*members)[(*num_mem)].name, nt_name);
		(*num_mem)++;
	}
	return True;
}

/*************************************************************************
 Routine to return the next entry in the domain alias list.

 when we are a PDC or BDC, then unix groups that are explicitly NOT mapped
 to aliases (map_alias_gid) are treated as DOMAIN groups (see groupunix.c).

 when we are a member of a domain (not a PDC or BDC) then unix groups
 that are explicitly NOT mapped to aliases (map_alias_gid) are treated
 as LOCAL groups.

 the reasoning behind this is to make it as simple as possible (not an easy
 task) for people to set up a domain-aware samba server, in each role that
 the server can take.

 *************************************************************************/
static LOCAL_GRP *getalsunixpwent(void *vp, LOCAL_GRP_MEMBER **mem, int *num_mem)
{
	/* Static buffers we will return. */
	static LOCAL_GRP gp_buf;
	struct group *unix_grp;

	if (lp_server_role() == ROLE_DOMAIN_NONE)
	{
		/*
		 * no domain role, no domain aliases (or domain groups,
		 * but that's dealt with by groupdb...).
		 */

		return NULL;
	}

	aldb_init_als(&gp_buf);

	fstrcpy(gp_buf.comment, "");

	/* cycle through unix groups */
	while ((unix_grp = getgrent()) != NULL)
	{
		DOM_SID sid;
		if (map_alias_gid(unix_grp->gr_gid, &sid, gp_buf.name, NULL))
		{
			/*
			 * find the NT name represented by this UNIX gid.
			 * then, only accept NT aliases that are in our domain
			 */

			sid_split_rid(&sid, &gp_buf.rid);
			if (sid_equal(&sid, &global_sam_sid))
			{
				break; /* hooray. */
			}
		}
		else if (lp_server_role() == ROLE_DOMAIN_MEMBER)
		{
			/*
			 * if we are a member of a domain,
			 * assume that the UNIX alias is an NT alias with
			 * the same name.  convert gid to a alias rid.
			 */
			
			fstrcpy(gp_buf.name, unix_grp->gr_name);
			gp_buf.rid = pwdb_gid_to_alias_rid(unix_grp->gr_gid);
		}
	}

	if (unix_grp == NULL)
	{
		return NULL;
	}

	/* get the user's domain aliases.  there are a maximum of 32 */

	if (mem != NULL && num_mem != NULL)
	{
		(*mem) = NULL;
		(*num_mem) = 0;

		get_unixalias_members(unix_grp, num_mem, mem);
	}

	{
		pstring linebuf;
		make_alias_line(linebuf, sizeof(linebuf), &gp_buf, mem, num_mem);
		DEBUG(10,("line: '%s'\n", linebuf));
	}

	return &gp_buf;
}

/************************************************************************
 Routine to add an entry to the alspasswd file.
*************************************************************************/

static BOOL add_alsunixgrp_entry(LOCAL_GRP *newals)
{
	DEBUG(0, ("add_alsunixgrp_entry: NOT IMPLEMENTED\n"));
	return False;
}

/************************************************************************
 Routine to search the alspasswd file for an entry matching the aliasname.
 and then modify its alias entry. We can't use the startalspwent()/
 getalspwent()/endalspwent() interfaces here as we depend on looking
 in the actual file to decide how much room we have to write data.
 override = False, normal
 override = True, override XXXXXXXX'd out alias or NO PASS
************************************************************************/

static BOOL mod_alsunixgrp_entry(LOCAL_GRP* als)
{
	DEBUG(0, ("mod_alsunixgrp_entry: NOT IMPLEMENTED\n"));
	return False;
}


static struct aliasdb_ops unix_ops =
{
	startalsunixpwent,
	endalsunixpwent,
	getalsunixpwpos,
	setalsunixpwpos,

	iterate_getaliasnam,          /* In aliasdb.c */
	iterate_getaliasgid,          /* In aliasdb.c */
	iterate_getaliasrid,          /* In aliasdb.c */
	getalsunixpwent,

	add_alsunixgrp_entry,
	mod_alsunixgrp_entry,

	iterate_getuseraliasnam      /* in aliasdb.c */
};

struct aliasdb_ops *unix_initialise_alias_db(void)
{    
	return &unix_ops;
}

#else
 /* Do *NOT* make this function static. It breaks the compile on gcc. JRA */
 void unix_alspass_dummy_function(void) { } /* stop some compilers complaining */
#endif /* USE_SMBPASS_DB */
