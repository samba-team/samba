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

struct unix_entries
{
	struct group *grps;
	int num_grps;
	int grp_idx;
};

/***************************************************************
 Start to enumerate the alspasswd list. Returns a void pointer
 to ensure no modification outside this module.
****************************************************************/

static void *startalsunixpwent(BOOL update)
{
	struct unix_entries *grps;
	grps = (struct unix_entries*)malloc(sizeof(struct unix_entries));

	if (grps == NULL)
	{
		return NULL;
	}

	if (!get_unix_grps(&grps->num_grps, &grps->grps))
	{
		free(grps);
		return NULL;
	}

	grps->grp_idx = 0;

	return (void*)grps;
}

/***************************************************************
 End enumeration of the alspasswd list.
****************************************************************/

static void endalsunixpwent(void *vp)
{
	struct unix_entries *grps = (struct unix_entries *)vp;

	if (grps != NULL)
	{
		free_unix_grps(grps->num_grps, grps->grps);
		free(vp);
	}
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
 Routine to return the next entry in the smbdomainalias list.
 *************************************************************************/
BOOL get_unixalias_members(struct group *grp,
				int *num_mem, LOCAL_GRP_MEMBER **members)
{
	int i;
	char *unix_name;

	if (num_mem == NULL || members == NULL)
	{
		return False;
	}

	(*num_mem) = 0;
	(*members) = NULL;

	for (i = 0; (unix_name = grp->gr_mem[i]) != NULL; i++)
	{
		fstring name;
		DOM_NAME_MAP gmep;
		LOCAL_GRP_MEMBER *mem;

		fstrcpy(name, unix_name);

		if (!lookupsmbpwnam (name, &gmep) &&
		    !lookupsmbgrpnam(name, &gmep))
		{
			continue;
		}

		if (!sid_front_equal(&global_sam_sid, &gmep.sid))
		{
			DEBUG(0,("alias database: could not resolve name %s (wrong Domain SID)\n",
			          name));
			continue;
		}

		(*num_mem)++;
		(*members) = Realloc((*members), (*num_mem) * sizeof(LOCAL_GRP_MEMBER));
		if ((*members) == NULL)
		{
			DEBUG(0,("get_unixalias_members: could not realloc LOCAL_GRP_MEMBERs\n"));
			return False;
		}

		mem = &(*members)[(*num_mem)-1];
		slprintf(mem->name, sizeof(mem->name)-1, "%s\\%s",
		         gmep.nt_domain, gmep.nt_name);
		sid_copy(&mem->sid, &gmep.sid);
		mem->sid_use = gmep.type;

		DEBUG(10,("get_unixalias_members: adding alias %s\n",
		           mem->name));
	}
	return True;
}

/*************************************************************************
 Routine to return the next entry in the domain alias list.

 when we are a PDC or BDC, then unix groups that are explicitly NOT mapped
 to aliases are treated as DOMAIN groups (see groupunix.c).

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
	struct group unix_grp;
	struct unix_entries *grps = (struct unix_entries *)vp;

	aldb_init_als(&gp_buf);

	/* get array of unix names + gids.  this function does NOT
	   get a copy of the unix group members
	 */

	/* cycle through unix groups */
	for (; grps->grp_idx < grps->num_grps; grps->grp_idx++)
	{
		DOM_NAME_MAP gmep;
		fstring sid_str;

		memcpy(&unix_grp, &grps->grps[grps->grp_idx], sizeof(unix_grp));

		DEBUG(10,("getgrpunixpwent: enum unix group entry %s\n",
		           unix_grp.gr_name));
			
		if (!lookupsmbgrpgid(unix_grp.gr_gid, &gmep))
		{
			continue;
		}

		sid_to_string(sid_str, &gmep.sid);
		DEBUG(10,("group %s found, sid %s type %d\n",
			gmep.nt_name, sid_str, gmep.type));

		if (gmep.type != SID_NAME_ALIAS)
		{
			continue;
		}

		sid_split_rid(&gmep.sid, &gp_buf.rid);
		if (!sid_equal(&global_sam_sid, &gmep.sid))
		{
			continue;
		}

		fstrcpy(gp_buf.name, gmep.nt_name);
		break;
	}

	if (grps->grp_idx >= grps->num_grps)
	{
		return NULL;
	}

	/* get the user's domain aliases.  there are a maximum of 32 */

	if (mem != NULL && num_mem != NULL)
	{
		(*mem) = NULL;
		(*num_mem) = 0;

		memcpy(&unix_grp, getgrgid(unix_grp.gr_gid), sizeof(unix_grp));
		get_unixalias_members(&unix_grp, num_mem, mem);
	}

	{
		pstring linebuf;
		make_alias_line(linebuf, sizeof(linebuf), &gp_buf, mem, num_mem);
		DEBUG(10,("line: '%s'\n", linebuf));
	}

	grps->grp_idx++; /* advance so next enum gets next entry */
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
 and then modify its alias entry. 
************************************************************************/

static BOOL mod_alsunixgrp_entry(LOCAL_GRP* als)
{
	DEBUG(0, ("mod_alsunixgrp_entry: NOT IMPLEMENTED\n"));
	return False;
}

/************************************************************************
 Routine to search the grppasswd file for an entry matching the rid.
 and then delete it.
************************************************************************/

static BOOL del_alsunixgrp_entry(uint32 rid)
{
	DEBUG(0, ("del_alsunixgrp_entry: NOT IMPLEMENTED\n"));
	return False;
}

/************************************************************************
 Routine to add a member to an entry to the grppasswd file.
*************************************************************************/
static BOOL add_alsunixgrp_member(uint32 rid, DOM_SID *member_sid)
{
	DEBUG(0, ("add_alsunixgrp_member: NOT IMPLEMENTED\n"));
	return False;
}

/************************************************************************
 Routine to delete a member from an entry to the grppasswd file.
*************************************************************************/
static BOOL del_alsunixgrp_member(uint32 rid, DOM_SID *member_sid)
{
	DEBUG(0, ("del_alsunixgrp_member: NOT IMPLEMENTED\n"));
	return False;
}


static struct aliasdb_ops unix_ops =
{
	startalsunixpwent,
	endalsunixpwent,
	getalsunixpwpos,
	setalsunixpwpos,

	iterate_getaliasntnam,          /* In aliasdb.c */
	iterate_getaliasgid,          /* In aliasdb.c */
	iterate_getaliasrid,          /* In aliasdb.c */
	getalsunixpwent,

	add_alsunixgrp_entry,
	mod_alsunixgrp_entry,
	del_alsunixgrp_entry,

	add_alsunixgrp_member,
	del_alsunixgrp_member,

	iterate_getuseraliasntnam      /* in aliasdb.c */
};

struct aliasdb_ops *unix_initialise_alias_db(void)
{    
	return &unix_ops;
}

#else
 /* Do *NOT* make this function static. It breaks the compile on gcc. JRA */
 void unix_alspass_dummy_function(void) { } /* stop some compilers complaining */
#endif /* USE_SMBPASS_DB */
