/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1994-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996-1999
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/



#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"
#include "rpc_parse.h"
#include "nterr.h"

extern int DEBUGLEVEL;

#define DEBUG_TESTING

/****************************************************************************
lookup SID for a domain in a sam database
****************************************************************************/
uint32 lookup_sam_domainname(const char *srv_name,
			     const char *domain, DOM_SID *sid)
{
	POLICY_HND sam_pol;
	BOOL res = True;
	BOOL res1 = True;

	if (srv_name == NULL)
	{
		srv_name = "\\\\.";
	}

	/* establish a connection. */
	res  = res ? samr_connect(srv_name, 0x02000000, &sam_pol) : False;

	res1 = res ? samr_query_lookup_domain(&sam_pol, domain, sid) : False;

	res  = res ? samr_close(&sam_pol) : False;

	if (! res1)
	{
		return NT_STATUS_NONE_MAPPED | 0xC0000000;
	}
	return 0x0;
}


/****************************************************************************
lookup in a sam database
****************************************************************************/
uint32 lookup_sam_names(const char *domain, const DOM_SID *sid,
			uint32 num_names, char **names,
			uint32 *num_rids, uint32 **rids, uint32 **types)
{
	fstring srv_name;
	BOOL res = True;
	BOOL res1 = True;
	uint32 *my_types = NULL;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	if (domain == NULL)
	{
		fstrcpy(srv_name, "\\\\.");
	}
	else if (!get_any_dc_name(domain, srv_name))
	{
		return NT_STATUS_NONE_MAPPED | 0xC0000000;
	}

	if (num_rids)
	{
		*num_rids = 0;
	}
	if (rids)
	{
		*rids = NULL;
	}
	if (types)
	{
		*types = NULL;
	}

	if (!num_names || !names || !num_rids || (!types && !rids))
	{
		/* Not sure, wether that's a good error-code */
		return NT_STATUS_NONE_MAPPED | 0xC0000000;
	}

	/* establish a connection. */
	res =  res ? samr_connect(srv_name, 0x02000000, &sam_pol) : False;

	/* connect to the domain */
	res  = res ? samr_open_domain(&sam_pol, ace_perms, sid, &pol_dom) : False;

	res1 = res ? samr_query_lookup_names(&pol_dom, 0x000003e8,
					num_names, names,
					num_rids, rids, &my_types) : False;

	res  = res ? samr_close(&pol_dom) : False;
	res  = res ? samr_close(&sam_pol) : False;

	if (! res1)
	{
		return NT_STATUS_NONE_MAPPED | 0xC0000000;
	}
	if (types) 
	{
		uint32 i, num;
		num = *num_rids;
		*types = g_new(uint32, num);
		if (*types == NULL)
		{
			safe_free(my_types);
			return NT_STATUS_NONE_MAPPED | 0xC0000000;
		}
		for(i = 0; i < num; i++)
		{
			(*types)[i] = my_types[i];
		}
	}
	safe_free(my_types);

	return 0x0;
}

/****************************************************************************
lookup in a sam database
****************************************************************************/
uint32 lookup_sam_name(const char *domain, DOM_SID *sid,
				char *name, uint32 *rid, uint32 *type)
{
	fstring srv_name;
	BOOL res = True;
	BOOL res1 = True;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	const char *names[1];
	uint32 *rids;
	uint32 *types;
	uint32 num_rids;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	if (domain == NULL)
	{
		fstrcpy(srv_name, "\\\\.");
	}
	else if (!get_any_dc_name(domain, srv_name))
	{
		return NT_STATUS_NONE_MAPPED | 0xC0000000;
	}

	/* establish a connection. */
	res = res ? samr_connect( srv_name, 0x02000000, &sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain( &sam_pol, ace_perms, sid, &pol_dom) : False;

	names[0] = name;

	res1 = res ? samr_query_lookup_names( &pol_dom, 0x000003e8,
	            1, names,
	            &num_rids, &rids, &types) : False;

	res  = res  ? samr_close(&pol_dom) : False;
	res  = res  ? samr_close(&sam_pol) : False;

	if (!res1 || num_rids != 1)
	{
		return NT_STATUS_NONE_MAPPED | 0xC0000000;
	}

	*rid = rids[0];
	*type = (uint32)(types[0]);

	free(rids);
	free(types);

	return 0x0;
}

/****************************************************************************
lookup in a sam database
****************************************************************************/
uint32 lookup_sam_rid(const char *domain, DOM_SID *sid,
				uint32 rid, char *name, uint32 *type)
{
	fstring srv_name;
	int i;
	BOOL res = True;
	BOOL res1 = True;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	char **names = NULL;
	uint32 *rid_mem;
	uint32 *types = NULL;
	uint32 num_names;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	if (!get_any_dc_name(domain, srv_name))
	{
		return NT_STATUS_NONE_MAPPED | 0xC0000000;
	}

	/* establish a connection. */
	res = res ? samr_connect( srv_name, 0x02000000, &sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain( &sam_pol, ace_perms, sid, &pol_dom) : False;

	rid_mem = (uint32*)malloc(1 * sizeof(rid_mem[0]));

	if (rid_mem == NULL)
	{
		return NT_STATUS_NONE_MAPPED | 0xC0000000;
	}

	for (i = 0; i < 1; i++)
	{
		rid_mem[i] = rid;
	}

	res1 = res ? samr_query_lookup_rids( &pol_dom, 0x3e8,
			1, rid_mem, 
			&num_names, &names, &types) : False;

	res  = res  ? samr_close(&pol_dom) : False;
	res  = res  ? samr_close(&sam_pol) : False;

	free(rid_mem);

	if (!res1 || num_names != 1)
	{
		return NT_STATUS_NONE_MAPPED | 0xC0000000;
	}

	fstrcpy(name, names[0]);
	*type = types[0];

	free_char_array(num_names, names);
	
	if (types != NULL)
	{
		free(types);
	}

	return 0x0;
}

BOOL req_user_info( const POLICY_HND *pol_dom,
				const char *domain,
				const DOM_SID *sid,
				uint32 user_rid, uint16 info_level,
				USER_INFO_FN(usr_inf))
{
	SAM_USERINFO_CTR ctr;
	/* send user info query, level 0x15 */
	if (get_samr_query_userinfo( pol_dom,
				    info_level, user_rid, &ctr))
	{
		if (usr_inf != NULL)
		{
			usr_inf(domain, sid, user_rid, &ctr);
		}
		return True;
	}
	return False;
}

/****************************************************************************
SAM Query User Groups.
****************************************************************************/
uint32 sam_query_usergroups( const POLICY_HND *pol_dom,
				const char *domain,
				const DOM_SID *sid,
				uint32 user_rid,
				const char *user_name,
				uint32 *num_groups,
				DOM_GID **gid,
				char    ***name,
				uint32  **type,
				USER_MEM_FN(usr_mem))
{
	uint32 num_names = 0;
	(*gid) = NULL;
	/* send user group query */
	if (get_samr_query_usergroups( pol_dom,
				      user_rid, num_groups, gid) &&
	    gid != NULL)
	{
		uint32 i;
		uint32 *rid_mem;

		rid_mem = (uint32*)malloc((*num_groups) * sizeof(rid_mem[0]));

		if (rid_mem == NULL)
		{
			free(*gid);
			(*gid) = NULL;
			return 0;
		}

		for (i = 0; i < (*num_groups); i++)
		{
			rid_mem[i] = (*gid)[i].g_rid;
		}

		if (samr_query_lookup_rids( pol_dom, 0x3e8,
				(*num_groups), rid_mem, 
				&num_names, name, type))
		{
			usr_mem(domain, sid,
			       user_rid, user_name,
			       num_names, rid_mem, *name, *type);
		}

		free(rid_mem);
	}

	return num_names;
}

static uint32 req_group_info( const POLICY_HND *pol_dom,
				const char *domain, const DOM_SID *sid,
				uint32 user_rid, const char *user_name,
				USER_MEM_FN(usr_mem))
{
	uint32 num_groups;
	uint32 num_names;
	DOM_GID *gid = NULL;
	char    **name   = NULL;
	uint32  *type    = NULL;

	num_names = sam_query_usergroups( pol_dom,
				domain, sid,
				user_rid, user_name,
				&num_groups, &gid,
				&name, &type, usr_mem);

	free_char_array(num_names, name);
	if (type != NULL)
	{
		free(type);
	}

	if (gid != NULL)
	{
		free(gid);
	}

	return num_names;
}

static void req_alias_info( const POLICY_HND *pol_dom,
				const char *domain,
				const DOM_SID *sid1, uint32 user_rid,
				const char *user_name,
				USER_MEM_FN(usr_mem))
{
	uint32 num_aliases;
	uint32 *rid_mem = NULL;
	uint32 *ptr_sid;
	DOM_SID2 *als_sid;

	if (pol_dom == NULL)
	{
		return;
	}

	ptr_sid = (uint32*)  malloc(sizeof(ptr_sid[0]) * 1);
	als_sid = (DOM_SID2*)malloc(sizeof(als_sid[0]) * 1);

        sid_copy(&als_sid[0].sid, sid1);
	sid_append_rid(&als_sid[0].sid, user_rid);
	als_sid[0].num_auths = als_sid[0].sid.num_auths;

	ptr_sid[0] = 1;

	/* send user alias query */
	if (samr_query_useraliases( pol_dom,
				ptr_sid, als_sid, &num_aliases, &rid_mem))
	{
		uint32 num_names;
		char    **name = NULL;
		uint32  *type = NULL;

		uint32 *rid_copy = (uint32*)malloc(num_aliases * sizeof(*rid_copy));

		if (rid_copy != NULL)
		{
			uint32 i;
			for (i = 0; i < num_aliases; i++)
			{
				rid_copy[i] = rid_mem[i];
			}
			if (samr_query_lookup_rids( 
					pol_dom, 0x3e8,
					num_aliases, rid_copy, 
					&num_names, &name, &type))
			{
				usr_mem(domain, sid1,
				       user_rid, user_name,
				       num_names, rid_mem, name, type);
			}

			free(rid_copy);
		}

		free_char_array(num_names, name);
		if (type != NULL)
		{
			free(type);
		}
	}

	if (rid_mem != NULL)
	{
		free(rid_mem);
		rid_mem = NULL;
	}
}

/****************************************************************************
experimental SAM user display info.
****************************************************************************/
void msrpc_sam_user( const POLICY_HND *pol_dom, const POLICY_HND *pol_blt,
			const char* domain,
			const DOM_SID *sid1,
			const DOM_SID *blt_sid1,
			uint32 user_rid, uint16 info_level,
			char  *user_name,
			USER_FN(usr_fn),
			USER_INFO_FN(usr_inf_fn),
			USER_MEM_FN(usr_grp_fn),
			USER_MEM_FN(usr_als_fn))
{
	if (usr_fn != NULL)
	{
		usr_fn(domain, sid1, user_rid, user_name);
	}

	if (usr_inf_fn != NULL)
	{
		req_user_info(pol_dom,
				  domain, sid1,
				  user_rid, info_level,
				  usr_inf_fn);
	}

	if (usr_grp_fn != NULL)
	{
		req_group_info(pol_dom,
				  domain, sid1,
				  user_rid, user_name,
				  usr_grp_fn);
	}

	if (usr_als_fn != NULL)
	{
		req_alias_info(pol_dom,
				  domain, sid1,
				  user_rid, user_name,
				  usr_als_fn);
		req_alias_info(pol_blt,
				  domain, blt_sid1,
				  user_rid, user_name,
				  usr_als_fn);
	}
}

/****************************************************************************
experimental SAM user query.
****************************************************************************/
BOOL msrpc_sam_query_user( const char* srv_name,
			const char* domain,
			const DOM_SID *sid,
			char  *user_name,
			USER_FN(usr_fn),
			USER_INFO_FN(usr_inf_fn),
			USER_MEM_FN(usr_grp_fn),
			USER_MEM_FN(usr_als_fn))
{
	BOOL res = True;
	BOOL res1 = True;

	const char *names[1];
	uint32 num_rids;
	uint32 *rid;
	uint32 *type;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	/* establish a connection. */
	res = res ? samr_connect( srv_name, 0x02000000, &sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain( &sam_pol, 0x304, sid, &pol_dom) : False;

	/* look up user rid */
	names[0] = user_name;
	res1 = res ? samr_query_lookup_names( &pol_dom, 0x3e8,
					1, names,
					&num_rids, &rid, &type) : False;

	/* send user info query */
	if (res1 && num_rids == 1)
	{
		msrpc_sam_user( &pol_dom, NULL,
				domain,
				sid, NULL,
				rid[0], 0x15,
				user_name,
				usr_fn, usr_inf_fn,
		                usr_grp_fn, usr_als_fn);
	}
	else
	{
		res1 = False;
	}

	if (rid)
		free(rid);
	if (type)
		free(type);

	res = res ? samr_close( &pol_dom) : False;
	res = res ? samr_close( &sam_pol) : False;

	return res1;
}

/****************************************************************************
experimental SAM users enum.
****************************************************************************/
int msrpc_sam_enum_users( const char* srv_name,
			const char* domain,
			const DOM_SID *sid1,
			struct acct_info **sam,
			uint32 *num_sam_entries,
			USER_FN(usr_fn),
			USER_INFO_FN(usr_inf_fn),
			USER_MEM_FN(usr_grp_fn),
			USER_MEM_FN(usr_als_fn))
{
	DOM_SID sid_1_5_20;
	uint32 user_idx;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	uint32 start_idx = 0x0;
	uint16 unk_0 = 0x0;
	uint16 acb_mask = 0;
	uint16 unk_1 = 0x0;
	uint32 ace_perms = 0x304; /* access control permissions */
	uint32 status;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;
	POLICY_HND pol_blt;

	(*sam) = NULL;
	(*num_sam_entries) = 0;

	string_to_sid(&sid_1_5_20, "S-1-5-32");

	DEBUG(5,("Number of entries:%d unk_0:%04x acb_mask:%04x unk_1:%04x\n",
	          start_idx, unk_0, acb_mask, unk_1));

	/* establish a connection. */
	res = res ? samr_connect( srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res1 = res ? samr_open_domain( &sam_pol, ace_perms, sid1,
	            &pol_dom) : False;

	/* connect to the S-1-5-20 domain */
	res2 = res ? samr_open_domain( &sam_pol, ace_perms, &sid_1_5_20,
	            &pol_blt) : False;

	if (res1)
	{
		/* read some users */
		do
		{
			status = samr_enum_dom_users( &pol_dom,
			     &start_idx, acb_mask, unk_1, 0x10000,
			     sam, num_sam_entries);

		} while (status == STATUS_MORE_ENTRIES);

#if 0
		if ((*num_sam_entries) == 0)
		{
			report(out_hnd, "No users\n");
		}
#endif

		/* query all the users */
		for (user_idx = 0; res && user_idx <
			      (*num_sam_entries); user_idx++)
		{
			uint32 user_rid  = (*sam)[user_idx].rid;
			char  *user_name = (*sam)[user_idx].acct_name;

			msrpc_sam_user( &pol_dom, &pol_blt,
					domain,
					sid1, &sid_1_5_20,
					user_rid, 0x15, user_name,
					usr_fn, usr_inf_fn,
					usr_grp_fn, usr_als_fn);
		}
	}

	res2 = res2 ? samr_close( &pol_blt) : False;
	res1 = res1 ? samr_close( &pol_dom) : False;
	res  = res  ? samr_close( &sam_pol) : False;

	if (res)
	{
		DEBUG(5,("msrpc_sam_enum_users: succeeded\n"));
	}
	else
	{
		DEBUG(5,("msrpc_sam_enum_users: failed\n"));
	}

	return (*num_sam_entries);
}


/****************************************************************************
experimental SAM domain info query.
****************************************************************************/
BOOL sam_query_dominfo(const char* srv_name,
				const DOM_SID *sid1,
				uint32 switch_value, SAM_UNK_CTR *ctr)
{
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	/* establish a connection. */
	res = res ? samr_connect( 
				srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res1 = res ? samr_open_domain( &sam_pol, ace_perms, sid1,
	            &pol_dom) : False;

	/* send a samr 0x8 command */
	res2 = res ? samr_query_dom_info( &pol_dom, switch_value, ctr) : False;

	res1 = res1 ? samr_close( &pol_dom) : False;
	res = res ? samr_close( &sam_pol) : False;

	if (res2)
	{
		DEBUG(5,("sam_query_dominfo: succeeded\n"));
	}
	else
	{
		DEBUG(5,("sam_query_dominfo: failed\n"));
	}

	return res2;
}


BOOL query_aliasinfo( const POLICY_HND *pol_dom,
				const char *domain,
				const DOM_SID *sid,
				uint32 alias_rid,
				ALIAS_INFO_FN(grp_inf))
{
	ALIAS_INFO_CTR ctr;

	/* send alias info query */
	if (get_samr_query_aliasinfo( pol_dom,
				      3, /* info level */
	                              alias_rid, &ctr))
	{
		if (grp_inf != NULL)
		{
			grp_inf(domain, sid, alias_rid, &ctr);
		}
		return True;
	}
	return False;
}

BOOL sam_query_aliasmem(const char *srv_name,
				const POLICY_HND *pol_dom,
				uint32 alias_rid,
				uint32 *num_names,
				DOM_SID ***sids,
				char ***name,
				uint32 **type)
{
	BOOL res3 = True;
	BOOL res4 = True;
	DOM_SID2 sid_mem[MAX_LOOKUP_SIDS];
	uint32 num_aliases = 0;

	*sids = NULL;
	*num_names = 0;
	*name = NULL;
	*type = NULL;

	/* get alias members */
	res3 = get_samr_query_aliasmem( 
			pol_dom,
			alias_rid, &num_aliases, sid_mem);

	if (res3 && num_aliases != 0)
	{
		POLICY_HND lsa_pol;

		uint32 i;
		uint32 numsids = 0;

		for (i = 0; i < num_aliases; i++)
		{
			add_sid_to_array(&numsids, sids, &sid_mem[i].sid);
		}

		/* lookup domain controller; receive a policy handle */
		res3 = res3 ? lsa_open_policy( srv_name,
					&lsa_pol, True, 0x02000000) : False;

		/* send lsa lookup sids call */
		res4 = res3 ? lsa_lookup_sids( &lsa_pol,
					       num_aliases, *sids, 
					       name, type, num_names) : False;

		res3 = res3 ? lsa_close(&lsa_pol) : False;
	}

	if (!res4)
	{
		free_char_array(*num_names, *name);
		if ((*type) != NULL)
		{
			free(*type);
		}
		if ((*sids) != NULL)
		{
			free_sid_array(num_aliases, *sids);
		}
		*num_names = 0;
		*name = NULL;
		*type = NULL;
		*sids = NULL;
	}

	return res4;
}

BOOL req_aliasmem_info(const char* srv_name,
				const POLICY_HND *pol_dom,
				const char *domain,
				const DOM_SID *sid,
				uint32 alias_rid,
				const char *alias_name,
				ALIAS_MEM_FN(als_mem))
{
	uint32 num_names = 0;
	char **name = NULL;
	uint32 *type = NULL;
	DOM_SID **sids = NULL;

	if (sam_query_aliasmem( srv_name, pol_dom, alias_rid,
					&num_names, &sids,
					&name, &type))
	{
		als_mem(domain, sid,
		       alias_rid, alias_name,
		       num_names, sids, name, type);

		free_char_array(num_names, name);
		if (type != NULL)
		{
			free(type);
		}
		if (sids != NULL)
		{
			free_sid_array(num_names, sids);
		}
		return True;
	}
	return False;
}

BOOL sam_query_groupmem( const POLICY_HND *pol_dom,
				uint32 group_rid,
				uint32 *num_names,
				uint32 **rid_mem,
				char ***name,
				uint32 **type)
{
	uint32 num_mem;
	uint32 *attr_mem = NULL;
	BOOL res3;

	*rid_mem = NULL;
	*num_names = 0;
	*name = NULL;
	*type = NULL;

	/* get group members */
	res3 = get_samr_query_groupmem( 
		pol_dom,
		group_rid, &num_mem, rid_mem, &attr_mem);

	if (res3 && num_mem != 0)
	{
		uint32 *rid_copy = (uint32*)malloc(num_mem *
		                                   sizeof(rid_copy[0]));

		if (rid_copy != NULL)
		{
			uint32 i;
			for (i = 0; i < num_mem; i++)
			{
				rid_copy[i] = (*rid_mem)[i];
			}
			/* resolve names */
			res3 = samr_query_lookup_rids( pol_dom, 1000,
		                   num_mem, rid_copy, num_names, name, type);

			free(rid_copy);
		}
	}
	else
	{
		if (attr_mem != NULL)
		{
			free(attr_mem);
		}
		if ((*rid_mem) != NULL)
		{
			free(*rid_mem);
		}
		attr_mem = NULL;
		*rid_mem = NULL;
	}

	if (!res3)
	{
		free_char_array(*num_names, *name);
		if ((*type) != NULL)
		{
			free(*type);
		}
		*num_names = 0;
		*name = NULL;
		*type = NULL;
	}

	if (attr_mem != NULL)
	{
		free(attr_mem);
	}

	return res3;
}

BOOL query_groupinfo( const POLICY_HND *pol_dom,
				const char *domain,
				const DOM_SID *sid,
				uint32 group_rid,
				GROUP_INFO_FN(grp_inf))
{
	GROUP_INFO_CTR ctr;

	/* send group info query */
	if (get_samr_query_groupinfo( pol_dom,
				      1, /* info level */
	                              group_rid, &ctr))
	{
		if (grp_inf != NULL)
		{
			grp_inf(domain, sid, group_rid, &ctr);
		}
		return True;
	}
	return False;
}

BOOL req_groupmem_info( const POLICY_HND *pol_dom,
				const char *domain,
				const DOM_SID *sid,
				uint32 group_rid,
				const char *group_name,
				GROUP_MEM_FN(grp_mem))
{
	uint32 num_names = 0;
	char **name = NULL;
	uint32 *type = NULL;
	uint32 *rid_mem = NULL;

	if (sam_query_groupmem(pol_dom, group_rid,
				&num_names, &rid_mem, &name, &type))
	{
		grp_mem(domain, sid,
		       group_rid, group_name,
		       num_names, rid_mem, name, type);

		free_char_array(num_names, name);
		if (type != NULL)
		{
			free(type);
		}
		if (rid_mem != NULL)
		{
			free(rid_mem);
		}
		return True;
	}
	return False;
}

/****************************************************************************
SAM Domains query.
				DOMAIN_INFO_FN(dom_inf_fn),
				DOMAIN_MEM_FN(dom_mem_fn))
****************************************************************************/
uint32 msrpc_sam_enum_domains( const char* srv_name,
				struct acct_info **sam,
				uint32 *num_sam_entries,
				DOMAIN_FN(dom_fn),
				DOMAIN_INFO_FN(dom_inf_fn))
{
	BOOL res = True;
	uint32 ace_perms = 0x02000000; /* access control permissions. */
	POLICY_HND sam_pol;
	uint32 status;

	/* establish a connection. */
	res = res ? samr_connect( srv_name, ace_perms,
				&sam_pol) : False;

	(*sam) = NULL;
	(*num_sam_entries) = 0;

	if (res)
	{
		uint32 domain_idx;
		uint32 start_idx = 0;
		/* read some domains */
		do
		{
			status = samr_enum_domains( &sam_pol,
			     &start_idx, 0x10000,
			     sam, num_sam_entries);

		} while (status == STATUS_MORE_ENTRIES);

#if 0
		if ((*num_sam_entries) == 0)
		{
			report(out_hnd, "No domains\n");
		}
#endif

		for (domain_idx = 0; domain_idx < (*num_sam_entries); domain_idx++)
		{
			char *domain_name = (*sam)[domain_idx].acct_name;

			if (dom_fn != NULL)
			{
				dom_fn(domain_name);
			}

			if (dom_inf_fn != NULL)
			{
				uint32 switch_value = 2;
				SAM_UNK_CTR ctr;
				DOM_SID dom_sid;
				/* connect to the domain */
				if (samr_query_lookup_domain( &sam_pol,
				                              domain_name,
				                              &dom_sid) &&
				    sam_query_dominfo(srv_name, &dom_sid,
				                      switch_value, &ctr))
				{
					dom_inf_fn(domain_name, &dom_sid,
					           switch_value, &ctr);
				}
			}
		}
	}

	res = res ? samr_close(&sam_pol) : False;

	if (res)
	{
		DEBUG(5,("msrpc_sam_enum_domains: succeeded\n"));
	}
	else
	{
		DEBUG(5,("msrpc_sam_enum_domains: failed\n"));
	}
	return (*num_sam_entries);
}

/****************************************************************************
SAM groups query.
****************************************************************************/
uint32 msrpc_sam_enum_groups( const char* srv_name,
				const char* domain,
				const DOM_SID *sid1,
				struct acct_info **sam,
				uint32 *num_sam_entries,
				GROUP_FN(grp_fn),
				GROUP_INFO_FN(grp_inf_fn),
				GROUP_MEM_FN(grp_mem_fn))
{
	BOOL res = True;
	uint32 ace_perms = 0x02000000; /* access control permissions. */
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;
	uint32 status;

	/* establish a connection. */
	res = res ? samr_connect( srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain( &sam_pol, ace_perms, sid1,
	            &pol_dom) : False;

	(*sam) = NULL;
	(*num_sam_entries) = 0;

	if (res)
	{
		uint32 group_idx;
		uint32 start_idx = 0;
		/* read some groups */
		do
		{
			status = samr_enum_dom_groups( &pol_dom,
			     &start_idx, 0x100000,
			     sam, num_sam_entries);

		} while (status == STATUS_MORE_ENTRIES);

#if 0
		if ((*num_sam_entries) == 0)
		{
			report(out_hnd, "No groups\n");
		}
#endif

		for (group_idx = 0; group_idx < (*num_sam_entries); group_idx++)
		{
			uint32 group_rid = (*sam)[group_idx].rid;
			char *group_name = (*sam)[group_idx].acct_name;

			if (grp_fn != NULL)
			{
				grp_fn(domain, sid1, group_rid, group_name);
			}

			if (grp_inf_fn != NULL)
			{
				query_groupinfo(&pol_dom,
				                  domain, sid1,
				                  group_rid, 
				                  grp_inf_fn);
			}
			if (grp_mem_fn != NULL)
			{
				req_groupmem_info(&pol_dom,
				                  domain, sid1,
				                  group_rid, group_name,
				                  grp_mem_fn);
			}
		}
	}

	res = res ? samr_close(&pol_dom) : False;
	res = res ? samr_close(&sam_pol) : False;

	if (res)
	{
		DEBUG(5,("msrpc_sam_enum_groups: succeeded\n"));
	}
	else
	{
		DEBUG(5,("msrpc_sam_enum_groups: failed\n"));
	}
	return (*num_sam_entries);
}

/****************************************************************************
SAM aliases query.
****************************************************************************/
uint32 msrpc_sam_enum_aliases( const char* srv_name,
				const char* domain,
				const DOM_SID *sid1,
				struct acct_info **sam,
				uint32 *num_sam_entries,
				ALIAS_FN(als_fn),
				ALIAS_INFO_FN(als_inf_fn),
				ALIAS_MEM_FN(als_mem_fn))
{
	BOOL res = True;
	uint32 ace_perms = 0x02000000; /* access control permissions */
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;
	uint32 status = 0x0;

	/* establish a connection. */
	res = res ? samr_connect( srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain( &sam_pol, ace_perms, sid1,
	            &pol_dom) : False;

	(*sam) = NULL;
	(*num_sam_entries) = 0;

	if (res)
	{
		uint32 alias_idx;
		uint32 start_idx = 0;
		/* read some groups */
		do
		{
			status = samr_enum_dom_aliases( &pol_dom,
			     &start_idx, 0x100000,
			     sam, num_sam_entries);

		} while (status == STATUS_MORE_ENTRIES);

#if 0
		if ((*num_sam_entries) == 0)
		{
			report(out_hnd, "No aliases\n");
		}
#endif

		for (alias_idx = 0; alias_idx < (*num_sam_entries); alias_idx++)
		{
			uint32 alias_rid = (*sam)[alias_idx].rid;
			char *alias_name = (*sam)[alias_idx].acct_name;

			if (als_fn != NULL)
			{
				als_fn(domain, sid1, alias_rid, alias_name);
			}

			if (als_inf_fn != NULL)
			{
				query_aliasinfo(&pol_dom,
				                  domain, sid1,
				                  alias_rid, 
				                  als_inf_fn);
			}
			if (als_mem_fn != NULL)
			{
				req_aliasmem_info(srv_name, &pol_dom,
				                  domain, sid1,
				                  alias_rid, alias_name,
				                  als_mem_fn);
			}
		}
	}

	res = res ? samr_close(&pol_dom) : False;
	res = res ? samr_close(&sam_pol) : False;

	if (res)
	{
		DEBUG(5,("msrpc_sam_enum_aliases: succeeded\n"));
	}
	else
	{
		DEBUG(5,("msrpc_sam_enum_aliases: failed\n"));
	}

	return (*num_sam_entries);
}

/****************************************************************************
do a SAMR create domain user
****************************************************************************/
BOOL create_samr_domain_user( POLICY_HND *pol_dom,
				char *acct_name, uint16 acb_info,
				const char* password, int plen,
				uint32 *rid)
{
	POLICY_HND pol_open_user;
	BOOL ret = True;
	BOOL res1 = True;
	char pwbuf[516];
	SAM_USER_INFO_24 *p24;
	SAM_USER_INFO_16 *p16;
	SAM_USER_INFO_16 usr16;

	if (pol_dom == NULL || acct_name == NULL) return False;

	/* send create user */
	ret = samr_create_dom_user( pol_dom,
				acct_name, acb_info, 0xe005000b,
				&pol_open_user, rid);

	if (ret == 0x0)
	{
		samr_close(&pol_open_user);
	}

	if (ret != 0 && ret != (NT_STATUS_USER_EXISTS | 0xC0000000))
	{
		return False;
	}

	if (ret == (NT_STATUS_USER_EXISTS | 0xC0000000))
	{
		uint32 num_rids;
		const char *names[1];
		uint32 *types;
		uint32 *rids;

		names[0] = acct_name;
		res1 = samr_query_lookup_names( pol_dom, 0x3e8,
						1, names,
						&num_rids, &rids, &types);
		if (res1 == False || types[0] != SID_NAME_USER)
		{
			if(rids)
				free(rids);
			if(types)
				free(types);
			return False;
		}

		*rid = rids[0];

		safe_free(rids);
		safe_free(types);
	}

	DEBUG(5,("create_samr_domain_user: name: %s rid 0x%x\n",
	          acct_name, *rid));

	if (IS_BITS_SET_SOME(acb_info, ACB_NORMAL | ACB_DOMTRUST) &&
	    password == NULL)
	{
		return True;
	}

	encode_pw_buffer(pwbuf, password, plen, False);

	p24 = (SAM_USER_INFO_24*)malloc(sizeof(SAM_USER_INFO_24));
	if (p24 == NULL)
	{
		return False;
	}

	make_sam_user_info24(p24, pwbuf, plen);
		
	res1 = set_samr_set_userinfo( pol_dom, 0x18, *rid, (void*)p24);

	if (res1 == False)
	{
		return False;
	}

	/* send set user info */
	res1 = get_samr_query_userinfo( pol_dom, 0x10, *rid, (void*)&usr16);

	if (res1 == False)
	{
		return False;
	}

	if (usr16.acb_info != acb_info)
	{
		p16 = (SAM_USER_INFO_16 *) malloc(sizeof(SAM_USER_INFO_16));
		if (p16 == NULL)
		{
			return False;
		}
		p16->acb_info = acb_info;

		res1 = set_samr_set_userinfo2( pol_dom, 0x10, *rid, (void*)p16);
	}

	return res1;
}

/****************************************************************************
do a SAMR create domain alias
****************************************************************************/
BOOL create_samr_domain_alias( POLICY_HND *pol_open_domain,
				const char *acct_name, const char *acct_desc,
				uint32 *rid)
{
	POLICY_HND pol_open_alias;
	ALIAS_INFO_CTR ctr;
	BOOL ret = True;

	if (pol_open_domain == NULL || acct_name == NULL || acct_desc == NULL) return False;

	/* send create alias */
	if (!samr_create_dom_alias( pol_open_domain,
				acct_name,
				&pol_open_alias, rid))
	{
		return False;
	}

	DEBUG(5,("create_samr_domain_alias: name: %s rid 0x%x\n",
	          acct_name, *rid));

	ctr.switch_value1 = 3;
	make_samr_alias_info3(&ctr.alias.info3, acct_desc);

	/* send set alias info */
	if (!samr_set_aliasinfo( &pol_open_alias,
				&ctr))
	{
		DEBUG(5,("create_samr_domain_alias: error in samr_set_aliasinfo\n"));
		ret = False;
	}

	return samr_close(&pol_open_alias) && ret;
}

/****************************************************************************
do a SAMR create domain group
****************************************************************************/
BOOL create_samr_domain_group( POLICY_HND *pol_open_domain,
				const char *acct_name, const char *acct_desc,
				uint32 *rid)
{
	POLICY_HND pol_open_group;
	GROUP_INFO_CTR ctr;
	BOOL ret = True;

	if (pol_open_domain == NULL || acct_name == NULL || acct_desc == NULL) return False;

	/* send create group*/
	if (!samr_create_dom_group( pol_open_domain,
				acct_name,
				&pol_open_group, rid))
	{
		return False;
	}

	DEBUG(5,("create_samr_domain_group: name: %s rid 0x%x\n",
	          acct_name, *rid));

	ctr.switch_value1 = 4;
	ctr.switch_value2 = 4;
	make_samr_group_info4(&ctr.group.info4, acct_desc);

	/* send user groups query */
	if (!samr_set_groupinfo( &pol_open_group,
				&ctr))
	{
		DEBUG(5,("create_samr_domain_group: error in samr_set_groupinfo\n"));
		ret = False;
	}

	return samr_close(&pol_open_group) && ret;
}

/****************************************************************************
do a SAMR query user groups
****************************************************************************/
BOOL get_samr_query_usergroups( const POLICY_HND *pol_open_domain,
				uint32 user_rid,
				uint32 *num_groups, DOM_GID **gid)
{
	POLICY_HND pol_open_user;
	BOOL ret = True;

	if (pol_open_domain == NULL || num_groups == NULL || gid == NULL) return False;

	/* send open domain (on user sid) */
	if (!samr_open_user( pol_open_domain,
				0x02011b, user_rid,
				&pol_open_user))
	{
		return False;
	}

	/* send user groups query */
	if (!samr_query_usergroups( &pol_open_user, num_groups, gid))
	{
		DEBUG(5,("samr_query_usergroups: error in query user groups\n"));
		ret = False;
	}

	return samr_close(&pol_open_user) && ret;
}

/****************************************************************************
do a SAMR delete group 
****************************************************************************/
BOOL delete_samr_dom_group( POLICY_HND *pol_open_domain,
				uint32 group_rid)
{
	POLICY_HND pol_open_group;

	if (pol_open_domain == NULL) return False;

	/* send open domain (on group rid) */
	if (!samr_open_group(pol_open_domain,
				0x00000010, group_rid,
				&pol_open_group))
	{
		return False;
	}

	/* send group delete */
	if (!samr_delete_dom_group(&pol_open_group))
				
	{
		DEBUG(5,("delete_samr_dom_group: error in delete domain group\n"));
		samr_close(&pol_open_group);
		return False;
	}

	return True;
}


/****************************************************************************
do a SAMR query group members 
****************************************************************************/
BOOL get_samr_query_groupmem( 
				const POLICY_HND *pol_open_domain,
				uint32 group_rid, uint32 *num_mem,
				uint32 **rid, uint32 **attr)
{
	POLICY_HND pol_open_group;
	BOOL ret = True;

	if (pol_open_domain == NULL || num_mem == NULL || rid == NULL || attr == NULL) return False;

	/* send open domain (on group sid) */
	if (!samr_open_group( pol_open_domain,
				0x00000010, group_rid,
				&pol_open_group))
	{
		return False;
	}

	/* send group info query */
	if (!samr_query_groupmem(&pol_open_group, num_mem, rid, attr))
				
	{
		DEBUG(5,("samr_query_group: error in query group members\n"));
		ret = False;
	}

	return samr_close(&pol_open_group) && ret;
}

/****************************************************************************
do a SAMR delete alias 
****************************************************************************/
BOOL delete_samr_dom_alias( 
				POLICY_HND *pol_open_domain,
				uint32 alias_rid)
{
	POLICY_HND pol_open_alias;

	if (pol_open_domain == NULL) return False;

	/* send open domain (on alias rid) */
	if (!samr_open_alias(pol_open_domain,
				0x000f001f, alias_rid, &pol_open_alias))
	{
		return False;
	}

	/* send alias delete */
	if (!samr_delete_dom_alias(&pol_open_alias))
				
	{
		DEBUG(5,("delete_samr_dom_alias: error in delete domain alias\n"));
		samr_close(&pol_open_alias);
		return False;
	}

	return True;
}


/****************************************************************************
do a SAMR query alias members 
****************************************************************************/
BOOL get_samr_query_aliasmem( 
				const POLICY_HND *pol_open_domain,
				uint32 alias_rid, uint32 *num_mem, DOM_SID2 *sid)
{
	POLICY_HND pol_open_alias;
	BOOL ret = True;

	if (pol_open_domain == NULL || num_mem == NULL || sid == NULL) return False;

	/* send open domain (on alias sid) */
	if (!samr_open_alias( pol_open_domain,
				0x000f001f, alias_rid,
				&pol_open_alias))
	{
		return False;
	}

	/* send alias info query */
	if (!samr_query_aliasmem( &pol_open_alias, num_mem, sid))
				
	{
		DEBUG(5,("samr_query_alias: error in query alias members\n"));
		ret = False;
	}

	return samr_close(&pol_open_alias) && ret;
}

/****************************************************************************
do a SAMR set user info
****************************************************************************/
BOOL set_samr_set_userinfo2( 
				POLICY_HND *pol_open_domain,
				uint32 info_level,
				uint32 user_rid, void *usr)
{
	POLICY_HND pol_open_user;
	BOOL ret = True;

	if (pol_open_domain == NULL || usr == NULL) return False;

	/* send open domain (on user sid) */
	if (!samr_open_user( pol_open_domain,
				0x000601b4, user_rid,
				&pol_open_user))
	{
		return False;
	}

	/* send user info query */
	if (!samr_set_userinfo2( &pol_open_user, info_level, usr))
	{
		DEBUG(5,("samr_set_userinfo: error in query user info, level 0x%x\n",
		          info_level));
		ret = False;
	}

	return samr_close(&pol_open_user) && ret;
}

/****************************************************************************
do a SAMR set user info
****************************************************************************/
BOOL set_samr_set_userinfo( 
				POLICY_HND *pol_open_domain,
				uint32 info_level,
				uint32 user_rid, void *usr)
{
	POLICY_HND pol_open_user;
	BOOL ret = True;

	if (pol_open_domain == NULL || usr == NULL) return False;

	/* send open domain (on user sid) */
	if (!samr_open_user( pol_open_domain,
				0x000601b4, user_rid,
				&pol_open_user))
	{
		return False;
	}

	/* send user info query */
	if (!samr_set_userinfo( &pol_open_user,
				info_level, usr))
	{
		DEBUG(5,("samr_set_userinfo: error in query user info, level 0x%x\n",
		          info_level));
		ret = False;
	}

	return samr_close(&pol_open_user) && ret;
}

/****************************************************************************
do a SAMR query user info
****************************************************************************/
BOOL get_samr_query_userinfo( 
				const POLICY_HND *pol_open_domain,
				uint32 info_level,
				uint32 user_rid, SAM_USERINFO_CTR *ctr)
{
	POLICY_HND pol_open_user;
	BOOL ret = True;

	if (pol_open_domain == NULL || ctr == NULL) return False;

	/* send open domain (on user sid) */
	if (!samr_open_user( pol_open_domain,
				0x02011b, user_rid,
				&pol_open_user))
	{
		return False;
	}

	/* send user info query */
	if (!samr_query_userinfo( &pol_open_user, info_level, ctr))
	{
		DEBUG(5,("samr_query_userinfo: error in query user info, level 0x%x\n",
		          info_level));
		ret = False;
	}

	return samr_close(&pol_open_user) && ret;
}

/****************************************************************************
do a SAMR query group info
****************************************************************************/
BOOL get_samr_query_groupinfo( 
				const POLICY_HND *pol_open_domain,
				uint32 info_level,
				uint32 group_rid, GROUP_INFO_CTR *ctr)
{
	POLICY_HND pol_open_group;
	BOOL ret = True;

	if (pol_open_domain == NULL || ctr == NULL) return False;

	bzero(ctr, sizeof(*ctr));

	/* send open domain (on group sid) */
	if (!samr_open_group( pol_open_domain,
				0x02000000, group_rid, &pol_open_group))
	{
		return False;
	}

	/* send group info query */
	if (!samr_query_groupinfo( &pol_open_group, info_level, ctr))
	{
		DEBUG(5,("samr_query_groupinfo: error in query group info, level 0x%x\n",
		          info_level));
		ret = False;
	}

	return samr_close(&pol_open_group) && ret;
}

/****************************************************************************
do a SAMR query alias info
****************************************************************************/
BOOL get_samr_query_aliasinfo( 
				const POLICY_HND *pol_open_domain,
				uint32 info_level,
				uint32 alias_rid, ALIAS_INFO_CTR *ctr)
{
	POLICY_HND pol_open_alias;
	BOOL ret = True;

	if (pol_open_domain == NULL || ctr == NULL) return False;

	bzero(ctr, sizeof(*ctr));

	/* send open domain (on alias sid) */
	if (!samr_open_alias( pol_open_domain,
				0x02000000, alias_rid, &pol_open_alias))
	{
		return False;
	}

	/* send alias info query */
	if (!samr_query_aliasinfo( &pol_open_alias, info_level, ctr))
	{
		DEBUG(5,("samr_query_aliasinfo: error in query alias info, level 0x%x\n",
		          info_level));
		ret = False;
	}

	return samr_close(&pol_open_alias) && ret;
}

/****************************************************************************
SAM create domain user.
****************************************************************************/
BOOL msrpc_sam_create_dom_user(const char* srv_name, DOM_SID *sid1,
				char *acct_name, uint16 acb_info,
				const char *password, int plen,
				uint32 *rid)
{
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	uint32 user_rid; 
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	/* establish a connection. */
	res = res ? samr_connect( 
				srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res1 = res ? samr_open_domain( &sam_pol, ace_perms, sid1,
	            &pol_dom) : False;

	/* create a domain user */
	res2 = res1 ? create_samr_domain_user( &pol_dom,
	                        acct_name, 
				acb_info, password, plen, &user_rid) : False;

	res1 = res1 ? samr_close( &pol_dom) : False;
	res  = res  ? samr_close( &sam_pol) : False;

	if (res2)
	{
		DEBUG(5,("msrpc_sam_create_dom_user: succeeded\n"));
	}
	else
	{
		DEBUG(5,("msrpc_sam_create_dom_user: failed\n"));
	}

	return res2;
}

/****************************************************************************
experimental SAM query display info.
****************************************************************************/
BOOL msrpc_sam_query_dispinfo(const char* srv_name, const char* domain,
				DOM_SID *sid1,
				uint16 switch_value,
				uint32 *num_entries, SAM_DISPINFO_CTR *ctr,
				DISP_FN(disp_fn))
{
	BOOL res = True;
	BOOL res1 = True;
	uint32 ace_perms = 0x304; /* absolutely no idea. */
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	/* establish a connection. */
	res = res ? samr_connect( srv_name, 0x02000000, &sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain( &sam_pol, ace_perms, sid1,
	            &pol_dom) : False;

	/* send a samr query_disp_info command */
	res1 = res ? samr_query_dispinfo( &pol_dom, switch_value, 
		    num_entries, ctr) : False;

	res = res ? samr_close(&pol_dom) : False;
	res = res ? samr_close(&sam_pol) : False;

	if (res1 && disp_fn != NULL)
	{
		disp_fn(domain, sid1, switch_value, *num_entries, ctr);
	}

	return res1;
}

/****************************************************************************
SAM password change
****************************************************************************/
BOOL msrpc_sam_ntchange_pwd(const char* srv_name,
				const char* domain,
				const char *ntuser, 
				const uchar lm_oldhash[16],
				const uchar nt_oldhash[16],
				const char* new_passwd)
{
	BOOL ret;

	char nt_newpass[516];
	uchar nt_hshhash[16];
	uchar nt_newhash[16];

	char lm_newpass[516];
	uchar lm_newhash[16];
	uchar lm_hshhash[16];

	extern struct user_creds *usr_creds;
	struct ntuser_creds samr_creds;

	copy_nt_creds(&samr_creds, usr_creds != NULL ? &usr_creds->ntc : NULL);

	if (ntuser != NULL)
	{
		safe_strcpy(samr_creds.user_name, ntuser,
		            sizeof(samr_creds.user_name)-1);
	}

	if (domain != NULL)
	{
		safe_strcpy(samr_creds.domain, ntuser,
		            sizeof(samr_creds.domain)-1);
	}

	if (lm_oldhash != NULL || nt_oldhash != NULL)
	{
		pwd_set_lm_nt_16(&samr_creds.pwd, lm_oldhash, nt_oldhash);
	}

	samr_creds.ntlmssp_flags = NTLMSSP_NEGOTIATE_UNICODE |
		                    NTLMSSP_NEGOTIATE_OEM |
		                    NTLMSSP_NEGOTIATE_SIGN |
		                    NTLMSSP_NEGOTIATE_SEAL |
		                    NTLMSSP_NEGOTIATE_LM_KEY |
		                    NTLMSSP_NEGOTIATE_NTLM |
		                    NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
		                    NTLMSSP_NEGOTIATE_00001000 |
		                    NTLMSSP_NEGOTIATE_00002000;

	nt_lm_owf_gen(new_passwd, nt_newhash, lm_newhash);
	make_oem_passwd_hash(nt_newpass, new_passwd, 0, nt_oldhash, True);
	make_oem_passwd_hash(lm_newpass, new_passwd, 0, lm_oldhash, True);
	E_old_pw_hash(nt_newhash, lm_oldhash, lm_hshhash);
	E_old_pw_hash(nt_newhash, nt_oldhash, nt_hshhash);

#ifdef DEBUG_PASSWORD
	dump_data(100, nt_newhash, 16);
	dump_data(100, lm_oldhash, 16);
	dump_data(100, lm_hshhash, 16);
#endif

	ret = msrpc_sam_ntpasswd_set(srv_name, ntuser, &samr_creds,
	                        lm_newpass, lm_hshhash,
	                        nt_newpass, nt_hshhash);
	return ret;
}

/****************************************************************************
SAM password change
****************************************************************************/
BOOL msrpc_sam_ntpasswd_set(const char* srv_name, const char *user, 
				struct ntuser_creds *samr_creds,
				const uchar lm_newpass[516],
				const uchar lm_hshhash[16],
				const uchar nt_newpass[516],
				const uchar nt_hshhash[16])
{
	BOOL res  = True;
	BOOL res1 = True;

	struct cli_connection *con = NULL;
	extern cli_auth_fns cli_ntlmssp_fns;

	DEBUG(10,("msrpc_sam_ntpasswd_set: user: %s\n", user));

	/* open SAMR session.  */
	res = res ? cli_connection_init_auth(srv_name, PIPE_SAMR, &con,
			     samr_creds != NULL ? &cli_ntlmssp_fns : NULL,
	                     (void*)samr_creds) : False;

	res1 = res  ? samr_get_dom_pwinfo(con, srv_name) : False;
	res1 = res1 ? samr_chgpasswd_user(con, srv_name, user,
	                                   nt_newpass, nt_hshhash,
	                                   lm_newpass, lm_hshhash) : False;
	/* close the session */
	if (res)
	{
		cli_connection_unlink(con);
	}

	return res1;
}
