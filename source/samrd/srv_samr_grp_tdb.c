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
#include "rpc_parse.h"
#include "nterr.h"
#include "sids.h"

extern int DEBUGLEVEL;

static BOOL tdb_lookup_group_mem(TDB_CONTEXT *tdb,
				uint32 rid,
				uint32 *num_rids,
				uint32 **rids,
				uint32 *num_types,
				uint32 **types)
{
	prs_struct key;
	prs_struct data;

	prs_init(&key, 0, 4, False);
	if (!_prs_uint32("sid", &key, 0, &rid))
	{
		return False;
	}

	prs_tdb_fetch(tdb, &key, &data);

	if (!samr_io_rids("rids", num_rids, rids, &data, 0) ||
	    !samr_io_rids("types", num_types, types, &data, 0))
	{
		prs_free_data(&key);
		prs_free_data(&data);
		return False;
	}

	prs_free_data(&key);
	prs_free_data(&data);

	return True;
}

static BOOL tdb_lookup_group(TDB_CONTEXT *tdb,
				uint32 rid,
				GROUP_INFO1 *grp)
{
	prs_struct key;
	prs_struct data;

	prs_init(&key, 0, 4, False);
	if (!_prs_uint32("rid", &key, 0, &rid))
	{
		return False;
	}

	prs_tdb_fetch(tdb, &key, &data);

	if (!samr_io_group_info1("grp", grp, &data, 0))
	{
		prs_free_data(&key);
		prs_free_data(&data);
		return False;
	}

	prs_free_data(&key);
	prs_free_data(&data);

	return True;
}

static BOOL tdb_store_group_mem(TDB_CONTEXT *tdb,
				uint32 rid,
				uint32 *num_rids,
				uint32 **rids,
				uint32 *num_types,
				uint32 **types)
{
	prs_struct key;
	prs_struct data;

	if (DEBUGLVL(10))
	{
		DEBUG(10,("storing group members %x\n", rid));
	}

	prs_init(&key, 0, 4, False);
	prs_init(&data, 0, 4, False);

	if (!_prs_uint32("sid", &key, 0, &rid) ||
	    !samr_io_rids("rids", num_rids, rids, &data, 0) ||
	    !samr_io_rids("types", num_types, types, &data, 0) ||
	     prs_tdb_store(tdb, TDB_REPLACE, &key, &data) != 0)
	{
		prs_free_data(&key);
		prs_free_data(&data);
		return False;
	}

	prs_free_data(&key);
	prs_free_data(&data);
	return True;
}

static BOOL tdb_store_group(TDB_CONTEXT *tdb, uint32 rid, GROUP_INFO1 *grp)
{
	prs_struct key;
	prs_struct data;

	DEBUG(10,("storing group %x\n", rid));

	prs_init(&key, 0, 4, False);
	prs_init(&data, 0, 4, False);

	if (!_prs_uint32("rid", &key, 0, &rid) ||
	    !samr_io_group_info1("grp", grp, &data, 0) ||
	     prs_tdb_store(tdb, TDB_REPLACE, &key, &data) != 0)
	{
		prs_free_data(&key);
		prs_free_data(&data);
		return False;
	}

	prs_free_data(&key);
	prs_free_data(&data);
	return True;
}

static BOOL tdb_set_groupinfo_4(TDB_CONTEXT *tdb,
				uint32 rid,
				const UNISTR2 *uni_acct_desc)
{
	GROUP_INFO1 grp;

	if (tdb_writelock(tdb) != 0)
	{
		return False;
	}

	if (!tdb_lookup_group(tdb, rid, &grp))
	{
		tdb_writeunlock(tdb);
		return False;
	}

	copy_unistr2(&grp.uni_acct_desc, uni_acct_desc);
	make_uni_hdr(&grp.hdr_acct_desc, uni_acct_desc->uni_str_len);

	if (!tdb_store_group(tdb, rid, &grp))
	{
		tdb_writeunlock(tdb);
		return False;
	}

	tdb_writeunlock(tdb);
	return True;
}


/*******************************************************************
 samr_reply_add_groupmem
 ********************************************************************/
uint32 _samr_add_groupmem(const POLICY_HND *pol, uint32 rid, uint32 unknown)
{
	uint32 group_rid;
	TDB_CONTEXT *tdb = NULL;

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbrid(get_global_hnd_cache(), pol, NULL, &tdb, NULL, &group_rid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

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
	uint32 group_rid;
	TDB_CONTEXT *tdb = NULL;

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbrid(get_global_hnd_cache(), pol, NULL, &tdb, NULL, &group_rid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

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
	uint32 group_rid;
	TDB_CONTEXT *tdb = NULL;

	DEBUG(5,("samr_delete_dom_group: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbrid(get_global_hnd_cache(), group_pol, NULL, &tdb, NULL, &group_rid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}
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
	int num_rids = 0;
	uint32 group_rid;

	DEBUG(5,("samr_query_groupmem: %d\n", __LINE__));

	(*rid) = NULL;
	(*attr) = NULL;
	(*num_mem) = 0;

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbrid(get_global_hnd_cache(), group_pol, NULL, &g_tdb, NULL, &group_rid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	DEBUG(10,("lookup on Domain SID\n"));

#if 0
	grp = getgrouprid(group_rid, &mem_grp, &num_rids);
#endif

 	{
 		return NT_STATUS_NO_SUCH_GROUP;
 	}

#if 0
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

#endif

	(*num_mem) = num_rids;

	return NT_STATUS_NOPROBLEMO;
}


/*******************************************************************
 samr_set_groupinfo
 ********************************************************************/
uint32 _samr_set_groupinfo(const POLICY_HND *pol,
				uint16 switch_level,
				const GROUP_INFO_CTR* ctr)
{
	uint32 group_rid;
	TDB_CONTEXT *tdb = NULL;

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbrid(get_global_hnd_cache(), pol, NULL, &tdb, NULL, &group_rid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	switch (switch_level)
	{
		case 1:
		{
			GROUP_INFO1 grp;
			memcpy(&grp, &ctr->group.info1, sizeof(grp));
			if (!tdb_store_group(tdb, group_rid, &grp))
			{
				return NT_STATUS_ACCESS_DENIED;
			}
			break;
		}
		case 4:
		{
			if (!tdb_set_groupinfo_4(tdb, group_rid,
			                     &ctr->group.info4.uni_acct_desc))
			{
				return NT_STATUS_ACCESS_DENIED;
			}
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
 samr_reply_query_groupinfo
 ********************************************************************/
uint32 _samr_query_groupinfo(const POLICY_HND *pol,
				uint16 switch_level,
				GROUP_INFO_CTR* ctr)
{
	uint32 group_rid;
	TDB_CONTEXT *tdb = NULL;
	GROUP_INFO1 grp;

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbrid(get_global_hnd_cache(), pol, NULL, &tdb, NULL, &group_rid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	if (!tdb_lookup_group(tdb, group_rid, &grp))
	{
		return NT_STATUS_NO_SUCH_GROUP;
	}

	switch (switch_level)
	{
		case 1:
		{
			ctr->switch_value1 = 1;
			memcpy(&ctr->group.info1, &grp, sizeof(grp));
			break;
		}
		case 4:
		{
			ctr->switch_value1 = 4;
			copy_unistr2(&ctr->group.info1.uni_acct_desc,
			              &grp.uni_acct_desc);
			make_uni_hdr(&ctr->group.info1.hdr_acct_desc,
			              grp.uni_acct_desc.uni_str_len);
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
				POLICY_HND *group_pol, uint32 *group_rid)
{
	DOM_SID dom_sid;
	DOM_SID grp_sid;
	DOM_SID sid;
	TDB_CONTEXT *tdb_grp = NULL;

	GROUP_INFO1 grp;
	uint32 status1;
	uint32 rid;
	uint32 type;
	uint32 num_rids;
	uint32 num_types;

	struct group *uxgrp = NULL;

	(*group_rid) = 0x0;

	/* find the machine account: tell the caller if it exists.
	   lkclXXXX i have *no* idea if this is a problem or not
	   or even if you are supposed to construct a different
	   reply if the account already exists...
	 */

	/* find the domain sid associated with the policy handle */
	if (!get_tdbdomsid(get_global_hnd_cache(), domain_pol,
					NULL, &tdb_grp, NULL,
					NULL, NULL, &dom_sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	status1 = _samr_lookup_names(domain_pol, 1,  0x3e8, 1, uni_acct_name,
			&num_rids,
			&rid,
			&num_types,
			&type);

	if (status1 == NT_STATUS_NOPROBLEMO)
	{
		switch (type)
		{
			case SID_NAME_USER: return NT_STATUS_USER_EXISTS;
			case SID_NAME_ALIAS: return NT_STATUS_ALIAS_EXISTS;
			case SID_NAME_DOM_GRP:
			case SID_NAME_WKN_GRP: return NT_STATUS_GROUP_EXISTS;
			case SID_NAME_DOMAIN: return NT_STATUS_DOMAIN_EXISTS;
			default:
			{
				DEBUG(3,("create group: unknown, ignoring\n"));
				break;
			}
		}
	}

	{
		fstring grp_name;
		unistr2_to_ascii(grp_name, uni_acct_name, sizeof(grp_name)-1);
		uxgrp = getgrnam(grp_name);
		DEBUG(10,("create group: %s\n", grp_name));
		if (uxgrp == NULL)
		{
			DEBUG(0,("create group: no unix group named %s\n",
			          grp_name));
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	/* create a User SID for the unix group */
	if (!sursalg_unixid_to_sam_sid(uxgrp->gr_gid, SID_NAME_DOM_GRP,
	                               &grp_sid, True))
	{
		DEBUG(0,("create group: unix gid %d to RID failed\n",
		          uxgrp->gr_gid));
		return NT_STATUS_ACCESS_DENIED;
	}

	sid_copy(&sid, &grp_sid);

	if (!sid_split_rid(&sid, group_rid) ||
	    !sid_equal(&dom_sid, &sid))
	{
		fstring tmp;
		DEBUG(0,("create group: invalid Group SID %s\n",
		         sid_to_string(tmp, &grp_sid)));
		return NT_STATUS_ACCESS_DENIED;
	}

	ZERO_STRUCT(grp);
	copy_unistr2(&grp.uni_acct_name, uni_acct_name);
	make_uni_hdr(&grp.hdr_acct_name, uni_acct_name->uni_str_len);
	grp.unknown_1 = 0x3;
	grp.num_members = 0x0;

	if (!tdb_store_group(tdb_grp, (*group_rid), &grp))
	{
		/* account doesn't exist: say so */
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_ACCESS_DENIED;
#if 0
	if (!tdb_store_group_mem(tdb_usg, (*group_rid), 0, NULL, 0, NULL))
	{
		/* account doesn't exist: say so */
		return NT_STATUS_ACCESS_DENIED;
	}

	return samr_open_by_tdbrid(domain_pol, NULL, tdb_grp, NULL,
	                           group_pol, access_mask, *group_rid);
#endif
}

/*******************************************************************
 _samr_open_group
 ********************************************************************/
uint32 _samr_open_group(const POLICY_HND *domain_pol, uint32 access_mask,
				uint32 group_rid,
				POLICY_HND *group_pol)
{
	DOM_SID dom_sid;
	TDB_CONTEXT *tdb_grp = NULL;
	GROUP_INFO1 grp;

	if (!get_tdbdomsid(get_global_hnd_cache(), domain_pol,
					NULL, NULL, NULL,
					&tdb_grp, NULL, &dom_sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	if (!tdb_lookup_group(tdb_grp, group_rid, &grp))
	{
		return NT_STATUS_NO_SUCH_GROUP;
	}

	return NT_STATUS_NO_SUCH_GROUP;
#if 0
	return samr_open_by_tdbrid(domain_pol,
	                           NULL, tdb_grp, NULL, 
	                           group_pol, access_mask, group_rid);
#endif
}


