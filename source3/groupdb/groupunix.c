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

/***************************************************************
 Start to enumerate the grppasswd list. Returns a void pointer
 to ensure no modification outside this module.
****************************************************************/

static void *startgrpunixpwent(BOOL update)
{
	setgrent();
	return (void*)(-1);
}

/***************************************************************
 End enumeration of the grppasswd list.
****************************************************************/

static void endgrpunixpwent(void *vp)
{
	endgrent();
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
			
		if (!sid_front_equal(&global_sam_sid, &gmep.sid))
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

		fstrcpy((*members)[(*num_mem)].name, gmep.nt_name);
		(*members)[(*num_mem)].attr = 0x07;
		(*num_mem)++;
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
	struct group *unix_grp;

	if (lp_server_role() == ROLE_DOMAIN_NONE || 
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

	/* cycle through unix groups */
	while ((unix_grp = getgrent()) != NULL)
	{
		DOM_NAME_MAP gmep;
		DEBUG(10,("getgrpunixpwent: enum unix group entry %s\n",
		           unix_grp->gr_name));
			
		if (!lookupsmbgrpgid(unix_grp->gr_gid, &gmep))
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

	if (unix_grp == NULL)
	{
		return NULL;
	}

	/* get the user's domain groups.  there are a maximum of 32 */

	if (mem != NULL && num_mem != NULL)
	{
		(*mem) = NULL;
		(*num_mem) = 0;

		get_unixgroup_members(unix_grp, num_mem, mem);
	}

	{
		pstring linebuf;
		make_group_line(linebuf, sizeof(linebuf), &gp_buf, mem, num_mem);
		DEBUG(10,("line: '%s'\n", linebuf));
	}

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
 Routine to search the grppasswd file for an entry matching the groupname.
 and then modify its group entry. We can't use the startgrppwent()/
 getgrppwent()/endgrppwent() interfaces here as we depend on looking
 in the actual file to decide how much room we have to write data.
 override = False, normal
 override = True, override XXXXXXXX'd out group or NO PASS
************************************************************************/

static BOOL mod_grpunixgrp_entry(DOMAIN_GRP* grp)
{
	DEBUG(0, ("mod_grpunixgrp_entry: NOT IMPLEMENTED\n"));
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
