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

#ifdef USE_SMBGROUP_DB

static int gp_file_lock_depth = 0;
extern int DEBUGLEVEL;

static char s_readbuf[1024];

/***************************************************************
 Start to enumerate the grppasswd list. Returns a void pointer
 to ensure no modification outside this module.
****************************************************************/

static void *startgrpfilepwent(BOOL update)
{
	return startfileent(lp_smb_group_file(),
	                      s_readbuf, sizeof(s_readbuf),
	                      &gp_file_lock_depth, update);
}

/***************************************************************
 End enumeration of the grppasswd list.
****************************************************************/

static void endgrpfilepwent(void *vp)
{
	endfileent(vp, &gp_file_lock_depth);
}

/*************************************************************************
 Return the current position in the grppasswd list as an SMB_BIG_UINT.
 This must be treated as an opaque token.
*************************************************************************/
static SMB_BIG_UINT getgrpfilepwpos(void *vp)
{
	return getfilepwpos(vp);
}

/*************************************************************************
 Set the current position in the grppasswd list from an SMB_BIG_UINT.
 This must be treated as an opaque token.
*************************************************************************/
static BOOL setgrpfilepwpos(void *vp, SMB_BIG_UINT tok)
{
	return setfilepwpos(vp, tok);
}


/*************************************************************************
 Routine to return the next entry in the smbdomaingroup list.
 *************************************************************************/
static char *get_group_members(char *p, int *num_mem, DOMAIN_GRP_MEMBER **members)
{
	fstring name;

	if (num_mem == NULL || members == NULL)
	{
		return NULL;
	}

	(*num_mem) = 0;
	(*members) = NULL;

	while (next_token(&p, name, ",", sizeof(fstring)))
	{
		DOM_SID sid;
		uint8 type;
		BOOL found = False;

		if (isdigit(name))
		{
			uint32 rid = get_number(name);
			sid_copy(&sid, &global_sam_sid);
			sid_append_rid(&sid, rid);
			
			found = lookup_sid(&sid, name, &type) == 0x0;
		}
		else
		{
			found = lookup_name(name, &sid, &type) == 0x0;
		}

		if (!found)
		{
			DEBUG(0,("group database: could not resolve name %s in domain %s\n",
			          name, global_sam_name));
			continue;
		}

		(*members) = Realloc((*members), ((*num_mem)+1) * sizeof(DOMAIN_GRP_MEMBER));
		if ((*members) == NULL)
		{
			return NULL;
		}

		fstrcpy((*members)[(*num_mem)].name, name);
		(*members)[(*num_mem)].attr = 0x07;
		(*num_mem)++;
	}
	return p;
}

/*************************************************************************
 Routine to return the next entry in the smbdomaingroup list.
 *************************************************************************/
static DOMAIN_GRP *getgrpfilepwent(void *vp, DOMAIN_GRP_MEMBER **mem, int *num_mem)
{
	/* Static buffers we will return. */
	static DOMAIN_GRP gp_buf;
	DOM_NAME_MAP gmep;

	int gidval;

	pstring linebuf;
	char  *p;

	gpdb_init_grp(&gp_buf);

	/*
	 * Scan the file, a line at a time and check if the name matches.
	 */
	while (getfileline(vp, linebuf, sizeof(linebuf)) > 0)
	{
		/* get group name */

		p = strncpyn(gp_buf.name, linebuf, sizeof(gp_buf.name), ':');
		if (p == NULL)
		{
			DEBUG(0, ("getgrpfilepwent: malformed group entry (no :)\n"));
			continue;
		}

		/* Go past ':' */
		p++;

		/* get group comment */

		p = strncpyn(gp_buf.comment, p, sizeof(gp_buf.comment), ':');
		if (p == NULL)
		{
			DEBUG(0, ("getgrpfilepwent: malformed group entry (no :)\n"));
			continue;
		}

		/* Go past ':' */
		p++;

		/* Get group gid. */

		p = Atoic(p, &gidval, ":");

		if (p == NULL)
		{
			DEBUG(0, ("getgrpfilepwent: malformed group entry (no : after uid)\n"));
			continue;
		}

		/* Go past ':' */
		p++;

		/* now get the user's groups.  there are a maximum of 32 */

		if (mem != NULL && num_mem != NULL)
		{
			(*mem) = NULL;
			(*num_mem) = 0;

			p = get_group_members(p, num_mem, mem);
			if (p == NULL)
			{
				DEBUG(0, ("getgrpfilepwent: malformed group entry (no : after members)\n"));
			}
		}

		/* ok, set up the static data structure and return it */

		if (!lookupsmbgrpgid((gid_t)gidval, &gmep))
		{
			continue;
		}
		if (gmep.type != SID_NAME_DOM_GRP &&
		    gmep.type != SID_NAME_WKN_GRP))
		{
			continue;
		}

		sid_split_rid(&gmep.sid, &gp_buf.rid);
		if (!sid_equal(&gmep.sid, &global_sam_sid))
		{
			continue;
		}

		gp_buf.attr    = 0x07;

		make_group_line(linebuf, sizeof(linebuf), &gp_buf, mem, num_mem);
		DEBUG(10,("line: '%s'\n", linebuf));

		return &gp_buf;
	}

	DEBUG(5,("getgrpfilepwent: end of file reached.\n"));
	return NULL;
}

/************************************************************************
 Routine to add an entry to the grppasswd file.
*************************************************************************/

static BOOL add_grpfilegrp_entry(DOMAIN_GRP *newgrp)
{
	DEBUG(0, ("add_grpfilegrp_entry: NOT IMPLEMENTED\n"));
	return False;
}

/************************************************************************
 Routine to search the grppasswd file for an entry matching the groupname.
 and then modify its group entry. 
************************************************************************/

static BOOL mod_grpfilegrp_entry(DOMAIN_GRP* grp)
{
	DEBUG(0, ("mod_grpfilegrp_entry: NOT IMPLEMENTED\n"));
	return False;
}


static struct groupdb_ops file_ops =
{
	startgrpfilepwent,
	endgrpfilepwent,
	getgrpfilepwpos,
	setgrpfilepwpos,

	iterate_getgroupntnam,          /* In groupdb.c */
	iterate_getgroupgid,          /* In groupdb.c */
	iterate_getgrouprid,          /* In groupdb.c */
	getgrpfilepwent,

	add_grpfilegrp_entry,
	mod_grpfilegrp_entry,

	iterate_getusergroupntnam      /* in groupdb.c */
};

struct groupdb_ops *file_initialise_group_db(void)
{    
	return &file_ops;
}

#else
 /* Do *NOT* make this function static. It breaks the compile on gcc. JRA */
 void grppass_dummy_function(void) { } /* stop some compilers complaining */
#endif /* USE_SMBPASS_DB */
