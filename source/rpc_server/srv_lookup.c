
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1998,2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1998,2000,
 *  Copyright (C) Paul Ashton                  1997-1998,2000,
 *  Copyright (C) Elrond                                 2000.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 *
 *

 this module provides nt user / nt rid lookup functions.
 users, local groups, domain groups.

 no unix / samba functions should be called in this module:
 it should purely provide a gateway to the password database API,
 the local group database API or the domain group database API,
 but first checking built-in rids.

 did i say rids?  oops, what about "S-1-1" the "Everyone" group
 and other such well-known sids...

 speed is not of the essence: no particular optimisation is in place.

 *
 *
 */

#include "includes.h"
#include "rpc_client.h"
#include "nterr.h"
#include "sids.h"

extern int DEBUGLEVEL;


uint32 make_dom_gids(DOMAIN_GRP * mem, int num_members, DOM_GID ** ppgids)
{
	uint32 count;
	int i;
	DOM_GID *gids = NULL;

	*ppgids = NULL;

	DEBUG(4, ("make_dom_gids: %d\n", num_members));

	if (mem == NULL || num_members == 0)
	{
		return 0;
	}

#if 0
	for (i = 0, count = 0; i < num_members && count < LSA_MAX_GROUPS; i++)
	{
		uint32 status;

		uint32 rid;
		DOM_SID sid;
		uint32 type;

		uint8 attr = mem[count].attr;
		char *name = mem[count].name;

		status = lookup_lsa_name(global_sam_name, name, &sid, &type);

		if (status == 0x0 && !sid_front_equal(&global_sam_sid, &sid))
		{
			fstring sid_str;
			sid_to_string(sid_str, &sid);
			DEBUG(1,
			      ("make_dom_gids: unknown sid %s for groupname %s\n",
			       sid_str, name));
		}
		else if (status == 0x0)
		{
			sid_split_rid(&sid, &rid);

			gids =
				(DOM_GID *) Realloc(gids,
						    sizeof(DOM_GID) * (count +
								       1));

			if (gids == NULL)
			{
				DEBUG(0, ("make_dom_gids: Realloc fail !\n"));
				return 0;
			}

			gids[count].g_rid = rid;
			gids[count].attr = attr;

			DEBUG(5, ("group name: %s rid: %d attr: %d\n",
				  name, rid, attr));
			count++;
		}
		else
		{
			DEBUG(1,
			      ("make_dom_gids: unknown groupname %s\n",
			       name));
		}
	}
#else
	count = num_members;
	gids = g_new(DOM_GID, count);

	if (gids == NULL)
	{
		DEBUG(0, ("make_dom_gids: malloc for %d entries failed\n",
			  count));
		return 0;
	}

	for (i = 0; i < count; i++)
	{
		gids[i].g_rid = mem[i].rid;
		gids[i].attr = mem[i].attr;
	}
#endif

	*ppgids = gids;
	return count;
}

/*******************************************************************
 gets a domain user's groups
 ********************************************************************/
static int get_domain_user_groups(DOMAIN_GRP_MEMBER ** grp_members, uint32 group_rid)
{
	DOMAIN_GRP *grp;
	int num_mem;

	if (grp_members == NULL)
		return 0;

	grp = getgrouprid(group_rid, grp_members, &num_mem);

	if (grp == NULL)
	{
		return 0;
	}

	return num_mem;
}


/*******************************************************************
 lookup_wk_group_sid
 ********************************************************************/
static uint32 lookup_wk_group_sid(DOM_SID *sid, char *group_name,
				  uint32 *type)
{
	uint32 rid;
	DOM_SID tmp;
	char *mapped;

	sid_copy(&tmp, sid);
	sid_split_rid(&tmp, &rid);

	if (!sid_equal(global_sid_builtin, &tmp))
	{
		return NT_STATUS_NONE_MAPPED;
	}

	DEBUG(5, ("lookup_wk_group_sid: rid: %d", rid));

	/* look up the well-known domain group rids first */
	mapped = lookup_wk_group_rid(rid);
	if (mapped == NULL)
	{
		DEBUG(5, (" none mapped\n"));
		return NT_STATUS_NONE_MAPPED;
	}
	fstrcpy(group_name, mapped);
	(*type) = SID_NAME_DOM_GRP;
	DEBUG(5, (" = %s\n", group_name));
	return 0x0;
}

/*******************************************************************
 lookup_group_sid
 ********************************************************************/
static uint32 lookup_group_sid(DOM_SID *sid, char *group_name, uint32 *type)
{
	pstring sid_str;
	uint32 rid;
	DOM_SID tmp;
	DOMAIN_GRP *grp = NULL;
	uint32 status = NT_STATUS_NONE_MAPPED;

	sid_to_string(sid_str, sid);
	DEBUG(5, ("lookup_group_sid: sid: %s", sid_str));

	sid_copy(&tmp, sid);
	sid_split_rid(&tmp, &rid);

	if (!sid_equal(&global_sam_sid, &tmp))
	{
		DEBUG(5, ("not our SID\n"));
		return NT_STATUS_NONE_MAPPED;
	}

	grp = getgrouprid(rid, NULL, NULL);

	if (grp != NULL)
	{
		fstrcpy(group_name, grp->name);
		(*type) = SID_NAME_DOM_GRP;
		DEBUG(5, (" = %s\n", group_name));
		return 0x0;
	}

	DEBUG(5, (" none mapped\n"));
	return status;
}

/*******************************************************************
 lookup_wk_alias_sid
 ********************************************************************/
static uint32 lookup_wk_alias_sid(DOM_SID *sid, char *alias_name,
				  uint32 *type)
{
	uint32 rid;
	DOM_SID tmp;
	char *mapped;

	sid_copy(&tmp, sid);
	sid_split_rid(&tmp, &rid);

	if (!sid_equal(global_sid_builtin, &tmp))
	{
		return NT_STATUS_NONE_MAPPED;
	}

	DEBUG(5, ("lookup_wk_alias_sid: rid: %d", rid));

	/* look up the well-known alias group rids first */
	mapped = lookup_wk_alias_rid(rid);
	if (mapped == NULL)
	{
		DEBUG(5, (" none mapped\n"));
		return NT_STATUS_NONE_MAPPED;
	}
	fstrcpy(alias_name, mapped);
	(*type) = SID_NAME_ALIAS;
	DEBUG(5, (" = %s\n", alias_name));
	return 0x0;
}

/*******************************************************************
 lookup_alias_sid
 ********************************************************************/
static uint32 lookup_alias_sid(DOM_SID *sid, char *alias_name, uint32 *type)
{
	pstring sid_str;
	uint32 rid;
	DOM_SID tmp;
	LOCAL_GRP *als = NULL;
	uint32 status = NT_STATUS_NONE_MAPPED;

	sid_to_string(sid_str, sid);
	DEBUG(5, ("lookup_alias_sid: sid: %s", sid_str));

	sid_copy(&tmp, sid);
	sid_split_rid(&tmp, &rid);

	if (!sid_equal(&global_sam_sid, &tmp))
	{
		DEBUG(5, ("not our SID\n"));
		return NT_STATUS_NONE_MAPPED;
	}

	als = getaliasrid(rid, NULL, NULL);

	if (als != NULL)
	{
		fstrcpy(alias_name, als->name);
		(*type) = SID_NAME_ALIAS;
		DEBUG(5, (" = %s\n", alias_name));
		return 0x0;
	}

	DEBUG(5, (" none mapped\n"));
	return status;
}

/*******************************************************************
 lookup well-known user name
 ********************************************************************/
static uint32 lookup_wk_user_sid(DOM_SID *sid, char *user_name, uint32 *type)
{
	uint32 rid;
	DOM_SID tmp;
	char *mapped;

	sid_copy(&tmp, sid);
	sid_split_rid(&tmp, &rid);

	if (!sid_equal(global_sid_builtin, &tmp))
	{
		return NT_STATUS_NONE_MAPPED;
	}

	DEBUG(5, ("lookup_wk_user_sid: rid: %d", rid));

	/* look up the well-known domain user rids first */
	mapped = lookup_wk_user_rid(rid);
	if (mapped == NULL)
	{
		DEBUG(5, (" none mapped\n"));
		return NT_STATUS_NONE_MAPPED;
	}
	fstrcpy(user_name, mapped);
	(*type) = SID_NAME_USER;
	DEBUG(5, (" = %s\n", user_name));
	return 0x0;
}

/*******************************************************************
 lookup user name
 ********************************************************************/
static uint32 lookup_user_sid(DOM_SID *sid, char *user_name, uint32 *type)
{
	struct sam_disp_info *disp_info;
	uint32 rid;
	DOM_SID tmp;

	sid_copy(&tmp, sid);
	sid_split_rid(&tmp, &rid);

	if (sid_equal(&global_sam_sid, &tmp))
	{
		DEBUG(5, ("lookup_user_sid in SAM %s: rid: %d",
			  global_sam_name, rid));

		/* find the user account */
		become_root(True);
		disp_info = getsamdisprid(rid);
		unbecome_root(True);

		if (disp_info != NULL)
		{
			fstrcpy(user_name, disp_info->nt_name);
			(*type) = SID_NAME_USER;
			DEBUG(5, (" = %s\n", user_name));
			return 0x0;
		}

		DEBUG(5, (" none mapped\n"));
	}

	return NT_STATUS_NONE_MAPPED;
}

/*******************************************************************
 lookup_builtin_sid
 ********************************************************************/
static uint32 lookup_builtin_sid(DOM_SID *sid, char *name, uint32 *type)
{
	uint32 status = NT_STATUS_NONE_MAPPED;

	if (status != 0x0)
		status = lookup_wk_user_sid(sid, name, type);
	if (status != 0x0)
		status = lookup_wk_group_sid(sid, name, type);
	if (status != 0x0)
		status = lookup_wk_alias_sid(sid, name, type);

	return status;
}

/*******************************************************************
 lookup_added_sid - names that have been added to the SAM database by admins.
 ********************************************************************/
static uint32 lookup_added_sid(DOM_SID *sid, char *name, uint32 *type)
{
	uint32 status = NT_STATUS_NONE_MAPPED;

	if (status != 0x0)
		status = lookup_user_sid(sid, name, type);
	if (status != 0x0)
		status = lookup_group_sid(sid, name, type);
	if (status != 0x0)
		status = lookup_alias_sid(sid, name, type);

	return status;
}


/*******************************************************************
 lookup_sid
 ********************************************************************/
uint32 lookup_sid(DOM_SID *sid, char *name, uint32 *type)
{
	uint32 status = NT_STATUS_NONE_MAPPED;

	if (status != 0x0)
		status = lookup_builtin_sid(sid, name, type);
	if (status != 0x0)
		status = lookup_added_sid(sid, name, type);

	return status;
}


/*******************************************************************
 lookup_group_rid
 ********************************************************************/
static uint32 lookup_added_group_name(const char *grp_name,
				      const char *domain,
				      DOM_SID *sid, uint32 *type)
{
	DOMAIN_GRP *grp = NULL;

	DEBUG(5, ("lookup_added_group_name: name: %s", grp_name));

	if (!strequal(domain, global_sam_name))
	{
		DEBUG(5, (" not our domain\n"));
		return NT_STATUS_NONE_MAPPED;
	}

	grp = getgroupntnam(grp_name, NULL, NULL);

	if (grp != NULL)
	{
		sid_copy(sid, &global_sam_sid);
		sid_append_rid(sid, grp->rid);
		(*type) = SID_NAME_DOM_GRP;

		DEBUG(5, (" = 0x%x\n", grp->rid));
		return 0x0;
	}

	DEBUG(5, (" none mapped\n"));
	return NT_STATUS_NONE_MAPPED;
}

/*******************************************************************
 lookup_added_alias_name
 ********************************************************************/
static uint32 lookup_added_alias_name(const char *als_name,
				      const char *domain,
				      DOM_SID *sid, uint32 *type)
{
	LOCAL_GRP *als = NULL;

	DEBUG(5, ("lookup_added_alias_name: name: %s\\%s", domain, als_name));

	if (!strequal(domain, global_sam_name))
	{
		DEBUG(5, (" not our domain\n"));
		return NT_STATUS_NONE_MAPPED;
	}

	als = getaliasntnam(als_name, NULL, NULL);

	if (als != NULL)
	{
		sid_copy(sid, &global_sam_sid);
		sid_append_rid(sid, als->rid);
		(*type) = SID_NAME_ALIAS;

		DEBUG(5, (" = 0x%x\n", als->rid));
		return 0x0;
	}

	DEBUG(5, (" none mapped\n"));
	return NT_STATUS_NONE_MAPPED;
}

/*******************************************************************
 lookup_added_user_rid
 ********************************************************************/
uint32 lookup_added_user_rids(char *nt_name, uint32 *usr_rid, uint32 *grp_rid)
{
	struct sam_passwd *sam_pass;
	(*usr_rid) = 0;
	(*grp_rid) = 0;

	/* find the user account */
	become_root(True);
	sam_pass = getsam21pwntnam(nt_name);
	unbecome_root(True);

	if (sam_pass != NULL)
	{
		(*usr_rid) = sam_pass->user_rid;
		(*grp_rid) = sam_pass->group_rid;
		return 0x0;
	}

	return NT_STATUS_NONE_MAPPED;
}

/*******************************************************************
 lookup_added_user_name
 ********************************************************************/
static uint32 lookup_added_user_name(const char *nt_name, const char *domain,
				     DOM_SID *sid, uint32 *type)
{
	struct sam_passwd *sam_pass;

	if (!strequal(domain, global_sam_name))
	{
		return NT_STATUS_NONE_MAPPED;
	}

	/* find the user account */
	become_root(True);
	sam_pass = getsam21pwntnam(nt_name);
	unbecome_root(True);

	if (sam_pass != NULL)
	{
		DEBUG(10, ("lookup_added_user_name: nt name: %s rid: %x\n",
			   nt_name, sam_pass->user_rid));
		sid_copy(sid, &global_sam_sid);
		sid_append_rid(sid, sam_pass->user_rid);
		(*type) = SID_NAME_USER;

		return 0x0;
	}

	return NT_STATUS_NONE_MAPPED;
}

/*******************************************************************
 lookup_grp_name
 ********************************************************************/
static uint32 lookup_grp_name(const char *name, const char *domain,
			      DOM_SID *sid, uint32 *type)
{
	uint32 status = NT_STATUS_NONE_MAPPED;

	if (status != 0x0)
		status = lookup_wk_group_name(name, domain, sid, type);
	if (status != 0x0)
		status = lookup_builtin_alias_name(name, domain, sid, type);
	if (status != 0x0)
		status = lookup_added_group_name(name, domain, sid, type);
	if (status != 0x0)
		status = lookup_added_alias_name(name, domain, sid, type);

	return status;
}

/*******************************************************************
 lookup_user_name
 ********************************************************************/
static uint32 lookup_user_name(const char *name, const char *domain,
			       DOM_SID *sid, uint32 *type)
{
	uint32 status = NT_STATUS_NONE_MAPPED;

	if (status != 0x0)
		status = lookup_wk_user_name(name, domain, sid, type);
	if (status != 0x0)
		status = lookup_added_user_name(name, domain, sid, type);

	return status;
}

/*******************************************************************
 lookup_name
 ********************************************************************/
uint32 lookup_name(const char *name, DOM_SID *sid, uint32 *type)
{
	uint32 status = NT_STATUS_NONE_MAPPED;
	fstring domain;
	fstring user;

	split_domain_name(name, domain, user);

	if (status != 0x0)
		status = lookup_user_name(user, domain, sid, type);
	if (status != 0x0)
		status = lookup_grp_name(user, domain, sid, type);
#if 0
	if (status != 0x0)
		status = lookup_domain_name(domain, sid, type);
#endif

	return status;
}
