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
 Start to enumerate the grppasswd list. Returns a void pointer
 to ensure no modification outside this module.
****************************************************************/

struct unix_entries
{
	struct group *grps;
	int num_grps;
	int grp_idx;
};

static void *startgrpunixpwent(BOOL update)
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
 End enumeration of the grppasswd list.
****************************************************************/

static void endgrpunixpwent(void *vp)
{
	struct unix_entries *grps = (struct unix_entries *)vp;

	if (grps != NULL)
	{
		free_unix_grps(grps->num_grps, grps->grps);
		free(vp);
	}
}

/*************************************************************************
 Return the current position in the grppasswd list as an SMB_BIG_UINT.
 This must be treated as an opaque token.
*************************************************************************/
static SMB_BIG_UINT getgrpunixpwpos(void *vp)
{
	return (SMB_BIG_UINT)0;
}

/*************************************************************************
 Set the current position in the grppasswd list from an SMB_BIG_UINT.
 This must be treated as an opaque token.
*************************************************************************/
static BOOL setgrpunixpwpos(void *vp, SMB_BIG_UINT tok)
{
	return False;
}

/*************************************************************************
 Routine to return the next entry in the smbdomaingroup list.
 *************************************************************************/
BOOL get_unixgroup_members(struct group *grp,
				int *num_mem, DOMAIN_GRP_MEMBER **members)
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
		DOM_NAME_MAP gmep;
		DOMAIN_GRP_MEMBER *mem;
		uint32 rid;

		if (!lookupsmbpwnam (unix_name, &gmep) &&
		    !lookupsmbgrpnam(unix_name, &gmep))
		{
			continue;
		}

		if (gmep.type != SID_NAME_DOM_GRP &&
		    gmep.type != SID_NAME_USER &&
		    gmep.type != SID_NAME_WKN_GRP)
		{
			DEBUG(0,("group database: name %s is not in a Domain Group\n",
			          unix_name));
			continue;
		}
			
		sid_split_rid(&gmep.sid, &rid);
		if (!sid_equal(&global_sam_sid, &gmep.sid))
		{
			DEBUG(0,("group database: could not resolve name %s (wrong Domain SID)\n",
			          unix_name));
			continue;
		}

		(*members) = Realloc((*members), ((*num_mem)+1) * sizeof(DOMAIN_GRP_MEMBER));
		if ((*members) == NULL)
		{
			return False;
		}

		mem = &(*members)[(*num_mem)];
		(*num_mem)++;

		fstrcpy(mem->name, gmep.nt_name);
		mem->attr    = 0x07;
		mem->sid_use = gmep.type;
		mem->rid     = rid;
	}
	return True;
}

/*************************************************************************
 Routine to return the next entry in the domain group list.

 if we are not a PDC or BDC, then we do NOT support Domain groups, only
 aliases.  try running MUSRMGR.EXE or running USRMGR.EXE selected on a
 workstation, you will find that no Domain groups are listed: only aliases.

 so, as a PDC or BDC, all unix groups not explicitly mapped using
 map_group_gid() are treated as Domain groups.

 *************************************************************************/
static DOMAIN_GRP *getgrpunixpwent(void *vp, DOMAIN_GRP_MEMBER **mem, int *num_mem)
{
	/* Static buffers we will return. */
	static DOMAIN_GRP gp_buf;
	struct group unix_grp;
	struct unix_entries *grps = (struct unix_entries *)vp;

	if (grps == NULL)
	{
		return NULL;
	}

	if (lp_server_role() == ROLE_STANDALONE || 
	    lp_server_role() == ROLE_DOMAIN_MEMBER)
	{
		/*
		 * only PDC and BDC have domain groups in the SAM.
		 * (however as member of domain you can have LOCAL groups,
		 * but that's dealt with in the aliasdb...)
		 */

		return NULL;
	}

	gpdb_init_grp(&gp_buf);

	fstrcpy(gp_buf.comment, "");
	gp_buf.attr    = 0x07;

	/* get array of unix names + gids.  this function does NOT
	   get a copy of the unix group members
	 */

	/* cycle through unix groups */
	for (; grps->grp_idx < grps->num_grps; grps->grp_idx++)
	{
		DOM_NAME_MAP gmep;

		unix_grp = grps->grps[grps->grp_idx];

		DEBUG(10, ("getgrpunixpwent: enum unix group entry %s\n",
		           unix_grp.gr_name));
			
		if (!lookupsmbgrpgid(unix_grp.gr_gid, &gmep))
		{
			continue;
		}

		if (gmep.type != SID_NAME_DOM_GRP &&
		    gmep.type != SID_NAME_WKN_GRP)
		{
			continue;
		}

		sid_split_rid(&gmep.sid, &gp_buf.rid);
		if (!sid_equal(&gmep.sid, &global_sam_sid))
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

	/* get the user's domain groups.  there are a maximum of 32 */

	if (mem != NULL && num_mem != NULL)
	{
		(*mem) = NULL;
		(*num_mem) = 0;

		unix_grp = *(getgrgid(unix_grp.gr_gid));
		get_unixgroup_members(&unix_grp, num_mem, mem);
	}

	{
		pstring linebuf;
		make_group_line(linebuf, sizeof(pstring), &gp_buf, mem, num_mem);
		DEBUG(10,("line: '%s'\n", linebuf));
	}

	grps->grp_idx++; /* advance so next enum gets next entry */
	return &gp_buf;
}

/************************************************************************
 Routine to add an entry to the grppasswd file.
*************************************************************************/

static BOOL add_grpunixgrp_entry(DOMAIN_GRP *newgrp)
{
	DEBUG(0, ("add_grpunixgrp_entry: NOT IMPLEMENTED\n"));
	return False;
}

/************************************************************************
 Routine to search database for entry matching the groupname and/or rid.
 and then modify its group entry. 
************************************************************************/

static BOOL mod_grpunixgrp_entry(DOMAIN_GRP* grp)
{
	DEBUG(0, ("mod_grpunixgrp_entry: NOT IMPLEMENTED\n"));
	return False;
}

/************************************************************************
 Routine to search the grppasswd file for an entry matching the rid.
 and then delete it.
************************************************************************/

static BOOL del_grpunixgrp_entry(uint32 rid)
{
	DEBUG(0, ("del_grpunixgrp_entry: NOT IMPLEMENTED\n"));
	return False;
}

/************************************************************************
 Routine to add a member to an entry to the grppasswd file.
*************************************************************************/
static BOOL add_grpunixgrp_member(uint32 rid, uint32 member_rid)
{
	DEBUG(0, ("add_grpunixgrp_member: NOT IMPLEMENTED\n"));
	return False;
}

/************************************************************************
 Routine to delete a member from an entry to the grppasswd file.
*************************************************************************/
static BOOL del_grpunixgrp_member(uint32 rid, uint32 member_rid)
{
	DEBUG(0, ("del_grpunixgrp_member: NOT IMPLEMENTED\n"));
	return False;
}

static struct groupdb_ops unix_ops =
{
	startgrpunixpwent,
	endgrpunixpwent,
	getgrpunixpwpos,
	setgrpunixpwpos,

	iterate_getgroupntnam,          /* In groupdb.c */
	iterate_getgroupgid,          /* In groupdb.c */
	iterate_getgrouprid,          /* In groupdb.c */
	getgrpunixpwent,

	add_grpunixgrp_entry,
	mod_grpunixgrp_entry,
	del_grpunixgrp_entry,

	add_grpunixgrp_member,
	del_grpunixgrp_member,

	iterate_getusergroupsnam      /* in groupdb.c */
};

struct groupdb_ops *unix_initialise_group_db(void)
{    
	return &unix_ops;
}

#else
 /* Do *NOT* make this function static. It breaks the compile on gcc. JRA */
 void unix_grppass_dummy_function(void) { } /* stop some compilers complaining */
#endif /* USE_SMBPASS_DB */
