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

	return NT_STATUS_NOPROBLEMO;
}


/*******************************************************************
 samr_reply_add_groupmem
 ********************************************************************/
uint32 _samr_add_groupmem(const POLICY_HND *pol, uint32 rid, uint32 unknown)
{
	DOM_SID group_sid;
	uint32 group_rid;
	fstring group_sid_str;
	TDB_CONTEXT *tdb = NULL;

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbsid(get_global_hnd_cache(), pol, &tdb, &group_sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	sid_to_string(group_sid_str, &group_sid);
	sid_split_rid(&group_sid, &group_rid);

	DEBUG(10,("sid is %s\n", group_sid_str));

	if (!sid_equal(&group_sid, &global_sam_sid))
	{
		return NT_STATUS_NO_SUCH_GROUP;
	}

	DEBUG(10,("lookup on Domain SID\n"));

#if 0
	if (!add_group_member(group_rid, rid))
#endif
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_reply_del_groupmem
 ********************************************************************/
uint32 _samr_del_groupmem(const POLICY_HND *pol, uint32 rid)
{
	DOM_SID group_sid;
	uint32 group_rid;
	fstring group_sid_str;
	TDB_CONTEXT *tdb = NULL;

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbsid(get_global_hnd_cache(), pol, &tdb, &group_sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	sid_to_string(group_sid_str, &group_sid);
	sid_split_rid(&group_sid, &group_rid);

	DEBUG(10,("sid is %s\n", group_sid_str));

	if (!sid_equal(&group_sid, &global_sam_sid))
	{
		return NT_STATUS_NO_SUCH_GROUP;
	}
	DEBUG(10,("lookup on Domain SID\n"));

#if 0
	if (!del_group_member(group_rid, rid))
#endif
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_reply_delete_dom_group
 ********************************************************************/
uint32 _samr_delete_dom_group(POLICY_HND *group_pol)
{
	DOM_SID group_sid;
	uint32 group_rid;
	fstring group_sid_str;
	TDB_CONTEXT *tdb = NULL;

	DEBUG(5,("samr_delete_dom_group: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbsid(get_global_hnd_cache(), group_pol, &tdb, &group_sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}
	sid_to_string(group_sid_str, &group_sid);
	sid_split_rid(&group_sid, &group_rid);

	DEBUG(10,("sid is %s\n", group_sid_str));

	if (!sid_equal(&group_sid, &global_sam_sid))
	{
		return NT_STATUS_NO_SUCH_GROUP;
	}

	DEBUG(10,("lookup on Domain SID\n"));

#if 0
	if (!del_group_entry(group_rid))
#endif
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	return _samr_close(group_pol);
}


/*******************************************************************
 samr_reply_query_groupmem
 ********************************************************************/
uint32 _samr_query_groupmem(const POLICY_HND *group_pol, 
					uint32 *num_mem,
					uint32 **rid,
					uint32 **attr)
{
	TDB_CONTEXT *g_tdb = NULL;
	DOMAIN_GRP_MEMBER *mem_grp = NULL;
	DOMAIN_GRP *grp = NULL;
	int num_rids = 0;
	DOM_SID group_sid;
	uint32 group_rid;
	fstring group_sid_str;

	DEBUG(5,("samr_query_groupmem: %d\n", __LINE__));

	(*rid) = NULL;
	(*attr) = NULL;
	(*num_mem) = 0;

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbsid(get_global_hnd_cache(), group_pol, &g_tdb, &group_sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}
	sid_to_string(group_sid_str, &group_sid);
	sid_split_rid(&group_sid, &group_rid);

	DEBUG(10,("sid is %s\n", group_sid_str));

	if (!sid_equal(&group_sid, &global_sam_sid))
	{
		return NT_STATUS_NO_SUCH_GROUP;
	}

	DEBUG(10,("lookup on Domain SID\n"));

	become_root(True);
#if 0
	grp = getgrouprid(group_rid, &mem_grp, &num_rids);
#endif
	unbecome_root(True);

 	if (grp == NULL)
 	{
 		return NT_STATUS_NO_SUCH_GROUP;
 	}

	if (num_rids > 0)
	{
		(*rid)  = malloc(num_rids * sizeof(uint32));
		(*attr) = malloc(num_rids * sizeof(uint32));
		if (mem_grp != NULL && (*rid) != NULL && (*attr) != NULL)
		{
			int i;
			for (i = 0; i < num_rids; i++)
			{
				(*rid) [i] = mem_grp[i].rid;
				(*attr)[i] = mem_grp[i].attr;
			}
		}
	}

	safe_free(mem_grp);
	
	(*num_mem) = num_rids;

	return NT_STATUS_NOPROBLEMO;
}


/*******************************************************************
 samr_reply_query_groupinfo
 ********************************************************************/
uint32 _samr_query_groupinfo(const POLICY_HND *pol,
				uint16 switch_level,
				GROUP_INFO_CTR* ctr)
{
	/* find the policy handle.  open a policy on it. */
	if ((find_policy_by_hnd(get_global_hnd_cache(), pol) == -1))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	switch (switch_level)
	{
		case 1:
		{
			ctr->switch_value1 = 1;
			make_samr_group_info1(&ctr->group.info1,
			                      "fake account name",
			                      "fake account description", 2);
			break;
		}
		case 4:
		{
			ctr->switch_value1 = 4;
			make_samr_group_info4(&ctr->group.info4,
			                     "fake account description");
			break;
		}
		default:
		{
			return NT_STATUS_INVALID_INFO_CLASS;
		}
	}

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 _samr_create_dom_group
 ********************************************************************/
uint32 _samr_create_dom_group(const POLICY_HND *domain_pol,
				const UNISTR2 *uni_acct_name,
				uint32 access_mask,
				POLICY_HND *group_pol, uint32 *rid)
{
	uint32 status;
	DOM_SID dom_sid;
	DOMAIN_GRP grp;
	TDB_CONTEXT *dom_tdb = NULL;
	TDB_CONTEXT *tdb_grp = NULL;

	bzero(group_pol, POL_HND_SIZE);

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
	grp.attr = 0x07;

	*rid = grp.rid;
	status = samr_open_by_tdbsid(tdb_grp, &dom_sid, group_pol,
	                              access_mask, grp.rid);
	if (status != NT_STATUS_NOPROBLEMO)
	{
		return status;
	}

#if 0
	if (!add_group_entry(&grp))
#endif
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 _samr_open_group
 ********************************************************************/
uint32 _samr_open_group(const POLICY_HND *domain_pol, uint32 access_mask,
				uint32 group_rid,
				POLICY_HND *group_pol)
{
	DOM_SID sid;
	TDB_CONTEXT *tdb = NULL;
	TDB_CONTEXT *tdb_grp = NULL;

	/* find the domain sid associated with the policy handle */
	if (!get_tdbsid(get_global_hnd_cache(), domain_pol, &tdb, &sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* this should not be hard-coded like this */
	if (!sid_equal(&sid, &global_sam_sid))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	return samr_open_by_tdbsid(tdb_grp, &sid, group_pol, access_mask, group_rid);
}

