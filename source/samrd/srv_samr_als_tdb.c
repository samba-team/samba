/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Sander Striker               2000
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


#include "includes.h"
#include "nterr.h"
#include "sids.h"

extern int DEBUGLEVEL;

/*******************************************************************
 opens a samr group by rid, returns a policy handle.
 ********************************************************************/
static uint32 samr_open_by_tdbsid(TDB_CONTEXT *ptdb,
				const DOM_SID *dom_sid,
				POLICY_HND *pol,
				uint32 access_mask,
				uint32 rid)
{
	DOM_SID sid;

	/* get a (unique) handle.  open a policy on it. */
	if (!open_policy_hnd(get_global_hnd_cache(), pol, access_mask))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	DEBUG(0,("TODO: verify that the rid exists\n"));

	/* associate a SID with the (unique) handle. */
	sid_copy(&sid, dom_sid);
	sid_append_rid(&sid, rid);

	/* associate an group SID with the (unique) handle. */
	if (!set_tdbsid(get_global_hnd_cache(), pol, ptdb, &sid))
	{
		/* close the policy in case we can't associate a group SID */
		close_policy_hnd(get_global_hnd_cache(), pol);
		return NT_STATUS_ACCESS_DENIED;
	}

	return 0x0;
}

/*******************************************************************
 samr_reply_add_aliasmem
 ********************************************************************/
uint32 _samr_add_aliasmem(const POLICY_HND *alias_pol, const DOM_SID *sid)
{
	DOM_SID alias_sid;
	uint32 alias_rid;
	fstring alias_sid_str;
	TDB_CONTEXT *tdb = NULL;

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbsid(get_global_hnd_cache(), alias_pol, &tdb, &alias_sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}
	sid_to_string(alias_sid_str, &alias_sid);
	sid_split_rid(&alias_sid, &alias_rid);

	DEBUG(10,("sid is %s\n", alias_sid_str));

	if (sid_equal(&alias_sid, &global_sam_sid))
	{
		DEBUG(10,("add member on Domain SID\n"));

		if (!add_alias_member(alias_rid, sid))
		{
			return NT_STATUS_ACCESS_DENIED;
		}
	}
	else if (sid_equal(&alias_sid, &global_sid_S_1_5_20))
	{
		DEBUG(10,("add member on BUILTIN SID\n"));

		if (!add_builtin_member(alias_rid, sid))
		{
			return NT_STATUS_ACCESS_DENIED;
		}
	}
	else
	{
		return NT_STATUS_NO_SUCH_ALIAS;
	}

	return 0x0;
}

/*******************************************************************
 samr_reply_del_aliasmem
 ********************************************************************/
uint32 _samr_del_aliasmem(const POLICY_HND *alias_pol, const DOM_SID *sid)
{
	DOM_SID alias_sid;
	uint32 alias_rid;
	fstring alias_sid_str;
	TDB_CONTEXT *tdb = NULL;

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbsid(get_global_hnd_cache(), alias_pol, &tdb, &alias_sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}
	sid_to_string(alias_sid_str, &alias_sid);
	sid_split_rid(&alias_sid, &alias_rid);

	DEBUG(10,("sid is %s\n", alias_sid_str));

	if (sid_equal(&alias_sid, &global_sam_sid))
	{
		DEBUG(10,("del member on Domain SID\n"));

		if (!del_alias_member(alias_rid, sid))
		{
			return NT_STATUS_ACCESS_DENIED;
		}
	}
	else if (sid_equal(&alias_sid, &global_sid_S_1_5_20))
	{
		DEBUG(10,("del member on BUILTIN SID\n"));

		if (!del_builtin_member(alias_rid, sid))
		{
			return NT_STATUS_ACCESS_DENIED;
		}
	}
	else
	{
		return NT_STATUS_NO_SUCH_ALIAS;
	}

	return 0x0;
}

/*******************************************************************
 samr_reply_query_aliasinfo
 ********************************************************************/
uint32 _samr_query_aliasinfo(const POLICY_HND *alias_pol,
				uint16 switch_level,
				ALIAS_INFO_CTR *ctr)
{
	/* find the policy handle.  open a policy on it. */
	if ((find_policy_by_hnd(get_global_hnd_cache(), alias_pol) == -1))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	switch (switch_level)
	{
		case 3:
		{
			ctr->switch_value1 = 3;
			make_samr_alias_info3(&ctr->alias.info3,
			           "<fake account description>");
			break;
		}
		default:
		{
			return NT_STATUS_INVALID_INFO_CLASS;
		}
	}

	return 0x0;
}


/*******************************************************************
 samr_reply_delete_dom_alias
 ********************************************************************/
uint32 _samr_delete_dom_alias(POLICY_HND *alias_pol)
{
	TDB_CONTEXT *tdb = NULL;
	DOM_SID alias_sid;
	uint32 alias_rid;
	fstring alias_sid_str;

	DEBUG(5,("samr_delete_dom_alias: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbsid(get_global_hnd_cache(), alias_pol, &tdb, &alias_sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	sid_to_string(alias_sid_str, &alias_sid     );
	sid_split_rid(&alias_sid, &alias_rid);

	DEBUG(10,("sid is %s\n", alias_sid_str));

	if (!sid_equal(&alias_sid, &global_sam_sid))
	{
		return NT_STATUS_NO_SUCH_ALIAS;
	}

	DEBUG(10,("lookup on Domain SID\n"));

	if (!del_alias_entry(alias_rid))
	{
		return NT_STATUS_NO_SUCH_ALIAS;
	}

	return _samr_close(alias_pol);
}


/*******************************************************************
 samr_reply_query_aliasmem
 ********************************************************************/
uint32 _samr_query_aliasmem(const POLICY_HND *alias_pol, 
				uint32 *num_mem, DOM_SID2 **sid)
{
	TDB_CONTEXT *tdb = NULL;
	LOCAL_GRP_MEMBER *mem_grp = NULL;
	LOCAL_GRP *grp = NULL;
	int num_sids = 0;
	DOM_SID alias_sid;
	uint32 alias_rid;
	fstring alias_sid_str;

	DEBUG(5,("samr_query_aliasmem: %d\n", __LINE__));

	(*sid) = NULL;
	(*num_mem) = 0;

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbsid(get_global_hnd_cache(), alias_pol, &tdb, &alias_sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}
	sid_to_string(alias_sid_str, &alias_sid     );
	sid_split_rid(&alias_sid, &alias_rid);

	DEBUG(10,("sid is %s\n", alias_sid_str));

	if (sid_equal(&alias_sid, &global_sid_S_1_5_20))
	{
		DEBUG(10,("lookup on S-1-5-20\n"));

		become_root(True);
		grp = getbuiltinrid(alias_rid, &mem_grp, &num_sids);
		unbecome_root(True);
	}
	else if (sid_equal(&alias_sid, &global_sam_sid))
	{
		DEBUG(10,("lookup on Domain SID\n"));

		become_root(True);
		grp = getaliasrid(alias_rid, &mem_grp, &num_sids);
		unbecome_root(True);
	}
	else
	{
		return NT_STATUS_NO_SUCH_ALIAS;
	}

	if (grp == NULL)
	{
		return NT_STATUS_NO_SUCH_ALIAS;
	}

	if (num_sids > 0)
	{
		(*sid) = malloc(num_sids * sizeof(DOM_SID2));
		if (mem_grp != NULL && sid != NULL)
		{
			int i;
			for (i = 0; i < num_sids; i++)
			{
				make_dom_sid2(&(*sid)[i], &mem_grp[i].sid);
			}
		}
	}

	(*num_mem) = num_sids;

	if (mem_grp != NULL)
	{
		free(mem_grp);
	}

	return 0x0;
}

/*******************************************************************
 _samr_create_dom_alias
 ********************************************************************/
uint32 _samr_create_dom_alias(const POLICY_HND *domain_pol,
				const UNISTR2 *uni_acct_name,
				uint32 access_mask,
				POLICY_HND *alias_pol, uint32 *rid)
{
	uint32 status;
	DOM_SID dom_sid;
	LOCAL_GRP grp;
	TDB_CONTEXT *dom_tdb = NULL;
	TDB_CONTEXT *tdb_grp = NULL;

	bzero(alias_pol, POL_HND_SIZE);

	/* find the policy handle.  open a policy on it. */
	if (find_policy_by_hnd(get_global_hnd_cache(), domain_pol) == -1)
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* find the domain sid */
	if (!get_tdbsid(get_global_hnd_cache(), domain_pol, &dom_tdb, &dom_sid))
	{
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	if (!sid_equal(&dom_sid, &global_sam_sid))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	unistr2_to_ascii(grp.name, uni_acct_name, sizeof(grp.name)-1);
	fstrcpy(grp.comment, "");
	*rid = grp.rid = 0xffffffff;

	*rid = grp.rid;
	status = samr_open_by_tdbsid(tdb_grp, &dom_sid, alias_pol, access_mask, grp.rid);

	if (status != 0x0)
	{
		return status;
	}

	if (!add_alias_entry(&grp))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	return 0x0;
}

/*******************************************************************
 _samr_open_alias
 ********************************************************************/
uint32 _samr_open_alias(const POLICY_HND *domain_pol,
					uint32 access_mask, uint32 alias_rid,
					POLICY_HND *alias_pol)
{
	DOM_SID sid;
	TDB_CONTEXT *dom_tdb = NULL;
	TDB_CONTEXT *tdb_als = NULL;

	/* find the domain sid associated with the policy handle */
	if (!get_tdbsid(get_global_hnd_cache(), domain_pol, &dom_tdb, &sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* this should not be hard-coded like this */
	if (!sid_equal(&sid, &global_sam_sid) &&
	    !sid_equal(&sid, &global_sid_S_1_5_20))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	return samr_open_by_tdbsid(tdb_als, &sid, alias_pol, access_mask, alias_rid);
}

