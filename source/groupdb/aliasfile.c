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

#ifdef USE_SMBGROUP_DB

static int al_file_lock_depth = 0;
extern int DEBUGLEVEL;

static char s_readbuf[1024];

/***************************************************************
 Start to enumerate the aliasdb list. Returns a void pointer
 to ensure no modification outside this module.
****************************************************************/

static void *startalsfilepwent(BOOL update)
{
	return startfileent(lp_smb_alias_file(),
	                      s_readbuf, sizeof(s_readbuf),
	                      &al_file_lock_depth, update);
}

/***************************************************************
 End enumeration of the aliasdb list.
****************************************************************/

static void endalsfilepwent(void *vp)
{
	endfileent(vp, &al_file_lock_depth);
}

/*************************************************************************
 Return the current position in the aliasdb list as an SMB_BIG_UINT.
 This must be treated as an opaque token.
*************************************************************************/
static SMB_BIG_UINT getalsfilepwpos(void *vp)
{
	return getfilepwpos(vp);
}

/*************************************************************************
 Set the current position in the aliasdb list from an SMB_BIG_UINT.
 This must be treated as an opaque token.
*************************************************************************/
static BOOL setalsfilepwpos(void *vp, SMB_BIG_UINT tok)
{
	return setfilepwpos(vp, tok);
}


/*************************************************************************
 Routine to return the next entry in the smbdomainalias list.
 *************************************************************************/
static char *get_alias_members(char *p, int *num_mem, LOCAL_GRP_MEMBER **members)
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

		if (strnequal(name, "S-", 2))
		{
			/* sid entered directly */
			string_to_sid(&sid, name);
			found = lookup_sid(&sid, name, &type) == 0x0;
		}
		else
		{
			found = lookup_name(name, &sid, &type) == 0x0;
		}

		if (!found)
		{
			DEBUG(0,("alias database: could not resolve alias named %s\n", name));
			continue;
		}

		(*members) = Realloc((*members), ((*num_mem)+1) * sizeof(LOCAL_GRP_MEMBER));

		if ((*members) == NULL)
		{
			return NULL;
		}

		fstrcpy((*members)[*num_mem].name, name);
		(*members)[*num_mem].sid_use = type;
		sid_copy(&(*members)[*num_mem].sid, &sid);
		(*num_mem)++;
	}
	return p;
}

/*************************************************************************
 Routine to return the next entry in the smbdomainalias list.
 *************************************************************************/
static LOCAL_GRP *getalsfilepwent(void *vp, LOCAL_GRP_MEMBER **mem, int *num_mem)
{
	/* Static buffers we will return. */
	static LOCAL_GRP al_buf;

	int gidval;

	pstring linebuf;
	char  *p;
	uint8 type;

	aldb_init_als(&al_buf);

	/*
	 * Scan the file, a line at a time and check if the name matches.
	 */
	while (getfileline(vp, linebuf, sizeof(linebuf)) > 0)
	{
		DOM_NAME_MAP gmep;

		/* get alias name */

		p = strncpyn(al_buf.name, linebuf, sizeof(al_buf.name), ':');
		if (p == NULL)
		{
			DEBUG(0, ("getalsfilepwent: malformed alias entry (no :)\n"));
			continue;
		}

		/* Go past ':' */
		p++;

		/* get alias comment */

		p = strncpyn(al_buf.comment, p, sizeof(al_buf.comment), ':');
		if (p == NULL)
		{
			DEBUG(0, ("getalsfilepwent: malformed alias entry (no :)\n"));
			continue;
		}

		/* Go past ':' */
		p++;

		/* Get alias gid. */

		p = Atoic(p, &gidval, ":");

		if (p == NULL)
		{
			DEBUG(0, ("getalsfilepwent: malformed alias entry (no : after uid)\n"));
			continue;
		}

		/* Go past ':' */
		p++;

		/* now get the user's aliases.  there are a maximum of 32 */

		if (mem != NULL && num_mem != NULL)
		{
			(*mem) = NULL;
			(*num_mem) = 0;

			p = get_alias_members(p, num_mem, mem);
			if (p == NULL)
			{
				DEBUG(0, ("getalsfilepwent: malformed alias entry (no : after members)\n"));
			}
		}

		/*
		 * look up the gid, turn it into a rid.  the _correct_ type of rid */
		 */

		if (!lookupsmbgrpgid((gid_t)gidval, &gmep))
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

		make_alias_line(linebuf, sizeof(linebuf), &al_buf, mem, num_mem);
		DEBUG(10,("line: '%s'\n", linebuf));

		return &al_buf;
	}

	DEBUG(5,("getalsfilepwent: end of file reached.\n"));
	return NULL;
}

/************************************************************************
 Routine to add an entry to the aliasdb file.
*************************************************************************/

static BOOL add_alsfileals_entry(LOCAL_GRP *newals)
{
	DEBUG(0, ("add_alsfileals_entry: NOT IMPLEMENTED\n"));
	return False;
}

/************************************************************************
 Routine to search the aliasdb file for an entry matching the aliasname.
 and then modify its alias entry. 
************************************************************************/

static BOOL mod_alsfileals_entry(LOCAL_GRP* als)
{
	DEBUG(0, ("mod_alsfileals_entry: NOT IMPLEMENTED\n"));
	return False;
}


static struct aliasdb_ops file_ops =
{
	startalsfilepwent,
	endalsfilepwent,
	getalsfilepwpos,
	setalsfilepwpos,

	iterate_getaliasntnam,          /* In aliasdb.c */
	iterate_getaliasgid,          /* In aliasdb.c */
	iterate_getaliasrid,          /* In aliasdb.c */
	getalsfilepwent,

	add_alsfileals_entry,
	mod_alsfileals_entry,

	iterate_getuseraliasntnam      /* in aliasdb.c */
};

struct aliasdb_ops *file_initialise_alias_db(void)
{    
	return &file_ops;
}

#else
 /* Do *NOT* make this function static. It breaks the compile on gcc. JRA */
 void als_dummy_function(void) { } /* stop some compilers complaining */
#endif /* USE_SMBPASS_DB */
