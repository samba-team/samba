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
#include "nterr.h"

extern int DEBUGLEVEL;

#define DEBUG_TESTING

extern struct cli_state *smb_cli;

extern FILE* out_hnd;

static void sam_display_alias_info(const char *domain, const DOM_SID *sid,
				uint32 alias_rid, 
				ALIAS_INFO_CTR *const ctr)
{
	display_alias_info_ctr(out_hnd, ACTION_HEADER   , ctr);
	display_alias_info_ctr(out_hnd, ACTION_ENUMERATE, ctr);
	display_alias_info_ctr(out_hnd, ACTION_FOOTER   , ctr);
}

static void sam_display_alias(const char *domain, const DOM_SID *sid,
				uint32 alias_rid, const char *alias_name)
{
	report(out_hnd, "Alias RID: %8x  Alias Name: %s\n",
			  alias_rid, alias_name);
}

static void sam_display_alias_members(const char *domain, const DOM_SID *sid,
				uint32 alias_rid, const char *alias_name,
				uint32 num_names,
				DOM_SID *const *const sids,
				char *const *const name,
				uint8 *const type)
{
	display_alias_members(out_hnd, ACTION_HEADER   , num_names, name, type);
	display_alias_members(out_hnd, ACTION_ENUMERATE, num_names, name, type);
	display_alias_members(out_hnd, ACTION_FOOTER   , num_names, name, type);
}

static void sam_display_group_info(const char *domain, const DOM_SID *sid,
				uint32 group_rid, 
				GROUP_INFO_CTR *const ctr)
{
	display_group_info_ctr(out_hnd, ACTION_HEADER   , ctr);
	display_group_info_ctr(out_hnd, ACTION_ENUMERATE, ctr);
	display_group_info_ctr(out_hnd, ACTION_FOOTER   , ctr);
}

static void sam_display_group(const char *domain, const DOM_SID *sid,
				uint32 group_rid, const char *group_name)
{
	report(out_hnd, "Group RID: %8x  Group Name: %s\n",
			  group_rid, group_name);
}

static void sam_display_group_members(const char *domain, const DOM_SID *sid,
				uint32 group_rid, const char *group_name,
				uint32 num_names,
				const uint32 *rid_mem,
				char *const *const name,
				uint32 *const type)
{
	display_group_members(out_hnd, ACTION_HEADER   , num_names, name, type);
	display_group_members(out_hnd, ACTION_ENUMERATE, num_names, name, type);
	display_group_members(out_hnd, ACTION_FOOTER   , num_names, name, type);
}

static void sam_display_user_info(const char *domain, const DOM_SID *sid,
				uint32 user_rid, 
				SAM_USER_INFO_21 *const usr)
{
	display_sam_user_info_21(out_hnd, ACTION_HEADER   , usr);
	display_sam_user_info_21(out_hnd, ACTION_ENUMERATE, usr);
	display_sam_user_info_21(out_hnd, ACTION_FOOTER   , usr);
}

static void sam_display_user(const char *domain, const DOM_SID *sid,
				uint32 user_rid, const char *user_name)
{
	report(out_hnd, "User RID: %8x  User Name: %s\n",
			user_rid, user_name);
}

static BOOL req_user_info(struct cli_state *cli, uint16 fnum,
				POLICY_HND *pol_dom,
				const char *domain,
				const DOM_SID *sid,
				uint32 user_rid,
				USER_INFO_FN(usr_inf))
{
	SAM_USER_INFO_21 usr;
	/* send user info query, level 0x15 */
	if (get_samr_query_userinfo(smb_cli, fnum,
				    pol_dom,
				    0x15, user_rid, &usr))
	{
		if (usr_inf != NULL)
		{
			usr_inf(domain, sid, user_rid, &usr);
		}
		return True;
	}
	return False;
}

/****************************************************************************
SAM Query User Groups.
****************************************************************************/
uint32 sam_query_usergroups(struct cli_state *cli, uint16 fnum,
				const POLICY_HND *pol_dom,
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
	if (get_samr_query_usergroups(smb_cli, fnum,
				      pol_dom,
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

		if (samr_query_lookup_rids(smb_cli, fnum, 
				pol_dom, 0x3e8,
				(*num_groups), rid_mem, 
				&num_names, name, type))
		{
			usr_mem(domain, sid,
			       user_rid, user_name,
			       num_names, rid_mem, *name, *type);
		}
	}

	return num_names;
}

static uint32 req_group_info(struct cli_state *cli, uint16 fnum,
				const POLICY_HND *pol_dom,
				const char *domain, const DOM_SID *sid,
				uint32 user_rid, const char *user_name,
				USER_MEM_FN(usr_mem))
{
	uint32 num_groups;
	uint32 num_names;
	DOM_GID *gid = NULL;
	char    **name   = NULL;
	uint32  *type    = NULL;

	num_names = sam_query_usergroups(cli, fnum, pol_dom,
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

static void req_alias_info(struct cli_state *cli, uint16 fnum,
				const POLICY_HND *pol_dom,
				const char *domain,
				const DOM_SID *sid1, uint32 user_rid,
				const char *user_name,
				USER_MEM_FN(usr_mem))
{
	uint32 num_aliases;
	uint32 *rid_mem = NULL;
	uint32 *ptr_sid;
	DOM_SID2 *als_sid;

	ptr_sid = (uint32*)  malloc(sizeof(ptr_sid[0]) * 1);
	als_sid = (DOM_SID2*)malloc(sizeof(als_sid[0]) * 1);

        sid_copy(&als_sid[0].sid, sid1);
	sid_append_rid(&als_sid[0].sid, user_rid);
	als_sid[0].num_auths = als_sid[0].sid.num_auths;

	ptr_sid[0] = 1;

	/* send user alias query */
	if (samr_query_useraliases(cli, fnum,
				pol_dom,
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
			if (samr_query_lookup_rids(cli, fnum, 
					pol_dom, 0x3e8,
					num_aliases, rid_copy, 
					&num_names, &name, &type))
			{
				usr_mem(domain, sid1,
				       user_rid, user_name,
				       num_names, rid_mem, name, type);
			}
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

	if (ptr_sid != NULL)
	{
		free(ptr_sid);
		ptr_sid = NULL;
	}
	if (als_sid != NULL)
	{
		free(als_sid);
		als_sid = NULL;
	}
}

/****************************************************************************
experimental SAM users enum.
****************************************************************************/
int msrpc_sam_enum_users(struct cli_state *cli,
			const char* domain,
			const DOM_SID *sid1,
			const char* srv_name,
			struct acct_info **sam,
			uint32 *num_sam_entries,
			USER_FN(usr_fn),
			USER_INFO_FN(usr_inf_fn),
			USER_MEM_FN(usr_grp_fn),
			USER_MEM_FN(usr_als_fn))
{
	uint16 fnum;
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

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(cli, fnum, 
				srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res1 = res ? samr_open_domain(cli, fnum, 
	            &sam_pol, ace_perms, sid1,
	            &pol_dom) : False;

	/* connect to the S-1-5-20 domain */
	res2 = res ? samr_open_domain(cli, fnum, 
	            &sam_pol, ace_perms, &sid_1_5_20,
	            &pol_blt) : False;

	if (res1)
	{
		/* read some users */
		do
		{
			status = samr_enum_dom_users(cli, fnum, 
			     &pol_dom,
			     &start_idx, acb_mask, unk_1, 0x100000,
			     sam, num_sam_entries);

		} while (status == STATUS_MORE_ENTRIES);

		if ((*num_sam_entries) == 0)
		{
			report(out_hnd, "No users\n");
		}

		/* query all the users */
		for (user_idx = 0; res && user_idx <
			      (*num_sam_entries); user_idx++)
		{
			uint32 user_rid  = (*sam)[user_idx].rid;
			char  *user_name = (*sam)[user_idx].acct_name;

			if (usr_fn != NULL)
			{
				usr_fn(domain, sid1, user_rid, user_name);
			}

			if (usr_inf_fn != NULL)
			{
				req_user_info(cli, fnum, &pol_dom,
				                  domain, sid1,
				                  user_rid, 
				                  usr_inf_fn);
			}

			if (usr_grp_fn != NULL)
			{
				req_group_info(cli, fnum, &pol_dom,
				                  domain, sid1,
				                  user_rid, user_name,
				                  usr_grp_fn);
			}

			if (usr_als_fn != NULL)
			{
				req_alias_info(cli, fnum, &pol_dom,
				                  domain, sid1,
				                  user_rid, user_name,
				                  usr_als_fn);
				req_alias_info(cli, fnum, &pol_blt,
				                  domain, sid1,
				                  user_rid, user_name,
				                  usr_als_fn);
			}
		}
	}

	res2 = res2 ? samr_close(cli, fnum, &pol_blt) : False;
	res1 = res1 ? samr_close(cli, fnum, &pol_dom) : False;
	res  = res  ? samr_close(cli, fnum, &sam_pol) : False;

	/* close the session */
	cli_nt_session_close(cli, fnum);

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
BOOL sam_query_dominfo(struct client_info *info, const DOM_SID *sid1,
				uint32 switch_value, SAM_UNK_CTR *ctr)
{
	uint16 fnum;
	fstring srv_name;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res1 = res ? samr_open_domain(smb_cli, fnum, 
	            &sam_pol, ace_perms, sid1,
	            &pol_dom) : False;

	/* send a samr 0x8 command */
	res2 = res ? samr_query_dom_info(smb_cli, fnum,
	            &pol_dom, switch_value, ctr) : False;

	res1 = res1 ? samr_close(smb_cli, fnum,
	            &sam_pol) : False;

	res = res ? samr_close(smb_cli, fnum, 
	            &pol_dom) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

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


static BOOL query_aliasinfo(struct cli_state *cli, uint16 fnum,
				const POLICY_HND *pol_dom,
				const char *domain,
				const DOM_SID *sid,
				uint32 alias_rid,
				ALIAS_INFO_FN(grp_inf))
{
	ALIAS_INFO_CTR ctr;

	/* send alias info query */
	if (get_samr_query_aliasinfo(smb_cli, fnum,
				      pol_dom,
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

BOOL sam_query_aliasmem(struct cli_state *cli, uint16 fnum,
				const POLICY_HND *pol_dom,
				uint32 alias_rid,
				uint32 *num_names,
				DOM_SID ***sids,
				char ***name,
				uint8 **type)
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
	res3 = get_samr_query_aliasmem(smb_cli, fnum, 
			pol_dom,
			alias_rid, &num_aliases, sid_mem);

	if (res3 && num_aliases != 0)
	{
		fstring srv_name;
		uint16 fnum_lsa;
		POLICY_HND lsa_pol;

		uint32 i;
		uint32 numsids = 0;

		fstrcpy(srv_name, "\\\\");
		fstrcat(srv_name, cli->desthost);
		strupper(srv_name);

		for (i = 0; i < num_aliases; i++)
		{
			add_sid_to_array(&numsids, sids, &sid_mem[i].sid);
		}

		/* open LSARPC session. */
		res3 = res3 ? cli_nt_session_open(smb_cli, PIPE_LSARPC, &fnum_lsa) : False;

		/* lookup domain controller; receive a policy handle */
		res3 = res3 ? lsa_open_policy(smb_cli, fnum_lsa,
					srv_name,
					&lsa_pol, True) : False;

		/* send lsa lookup sids call */
		res4 = res3 ? lsa_lookup_sids(smb_cli, fnum_lsa, 
					       &lsa_pol,
					       num_aliases, *sids, 
					       name, type, num_names) : False;

		res3 = res3 ? lsa_close(smb_cli, fnum_lsa, &lsa_pol) : False;

		cli_nt_session_close(smb_cli, fnum_lsa);
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

static BOOL req_aliasmem_info(struct cli_state *cli, uint16 fnum,
				const POLICY_HND *pol_dom,
				const char *domain,
				const DOM_SID *sid,
				uint32 alias_rid,
				const char *alias_name,
				ALIAS_MEM_FN(als_mem))
{
	uint32 num_names = 0;
	char **name = NULL;
	uint8 *type = NULL;
	DOM_SID **sids = NULL;

	if (sam_query_aliasmem(cli, fnum, pol_dom, alias_rid,
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

BOOL sam_query_groupmem(struct cli_state *cli, uint16 fnum,
				const POLICY_HND *pol_dom,
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
	res3 = get_samr_query_groupmem(cli, fnum, 
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
			res3 = samr_query_lookup_rids(cli, fnum,
		                   pol_dom, 1000,
		                   num_mem, rid_copy, num_names, name, type);
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

static BOOL query_groupinfo(struct cli_state *cli, uint16 fnum,
				const POLICY_HND *pol_dom,
				const char *domain,
				const DOM_SID *sid,
				uint32 group_rid,
				GROUP_INFO_FN(grp_inf))
{
	GROUP_INFO_CTR ctr;

	/* send group info query */
	if (get_samr_query_groupinfo(smb_cli, fnum,
				      pol_dom,
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

static BOOL req_groupmem_info(struct cli_state *cli, uint16 fnum,
				const POLICY_HND *pol_dom,
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

	if (sam_query_groupmem(cli, fnum, pol_dom, group_rid,
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
SAM groups query.
****************************************************************************/
uint32 msrpc_sam_enum_groups(struct cli_state *cli,
				const char* domain,
				const DOM_SID *sid1,
				const char* srv_name,
				struct acct_info **sam,
				uint32 *num_sam_entries,
				GROUP_FN(grp_fn),
				GROUP_INFO_FN(grp_inf_fn),
				GROUP_MEM_FN(grp_mem_fn))
{
	uint16 fnum;
	BOOL res = True;
	uint32 ace_perms = 0x02000000; /* access control permissions. */
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;
	uint32 status;

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(cli, fnum,
				srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(cli, fnum,
	            &sam_pol, ace_perms, sid1,
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
			status = samr_enum_dom_groups(cli, fnum, 
			     &pol_dom,
			     &start_idx, 0x100000,
			     sam, num_sam_entries);

		} while (status == STATUS_MORE_ENTRIES);

		if ((*num_sam_entries) == 0)
		{
			report(out_hnd, "No groups\n");
		}

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
				query_groupinfo(cli, fnum, &pol_dom,
				                  domain, sid1,
				                  group_rid, 
				                  grp_inf_fn);
			}
			if (grp_mem_fn != NULL)
			{
				req_groupmem_info(cli, fnum, &pol_dom,
				                  domain, sid1,
				                  group_rid, group_name,
				                  grp_mem_fn);
			}
		}
	}

	res = res ? samr_close(cli, fnum, &pol_dom) : False;
	res = res ? samr_close(cli, fnum, &sam_pol) : False;

	/* close the session */
	cli_nt_session_close(cli, fnum);

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
uint32 msrpc_sam_enum_aliases(struct cli_state *cli,
				const char* domain,
				const DOM_SID *sid1,
				const char* srv_name,
				struct acct_info **sam,
				uint32 *num_sam_entries,
				ALIAS_FN(als_fn),
				ALIAS_INFO_FN(als_inf_fn),
				ALIAS_MEM_FN(als_mem_fn))
{
	uint16 fnum;
	BOOL res = True;
	uint32 ace_perms = 0x02000000; /* access control permissions */
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;
	uint32 status = 0x0;

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(cli, fnum,
				srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(cli, fnum,
	            &sam_pol, ace_perms, sid1,
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
			status = samr_enum_dom_aliases(cli, fnum, 
			     &pol_dom,
			     &start_idx, 0x100000,
			     sam, num_sam_entries);

		} while (status == STATUS_MORE_ENTRIES);

		if ((*num_sam_entries) == 0)
		{
			report(out_hnd, "No aliases\n");
		}

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
				query_aliasinfo(cli, fnum, &pol_dom,
				                  domain, sid1,
				                  alias_rid, 
				                  als_inf_fn);
			}
			if (als_mem_fn != NULL)
			{
				req_aliasmem_info(cli, fnum, &pol_dom,
				                  domain, sid1,
				                  alias_rid, alias_name,
				                  als_mem_fn);
			}
		}
	}

	res = res ? samr_close(cli, fnum, &sam_pol) : False;
	res = res ? samr_close(cli, fnum, &pol_dom) : False;

	/* close the session */
	cli_nt_session_close(cli, fnum);

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
SAM password change
****************************************************************************/
void cmd_sam_ntchange_pwd(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring sid;
	char *new_passwd;
	BOOL res = True;
	char nt_newpass[516];
	uchar nt_hshhash[16];
	uchar nt_newhash[16];
	uchar nt_oldhash[16];
	char lm_newpass[516];
	uchar lm_newhash[16];
	uchar lm_hshhash[16];
	uchar lm_oldhash[16];

	sid_to_string(sid, &info->dom.level5_sid);
	fstrcpy(domain, info->dom.level5_dom);

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	report(out_hnd, "SAM NT Password Change\n");

#if 0
	struct pwd_info new_pwd;
	pwd_read(&new_pwd, "New Password (ONCE: this is test code!):", True);
#endif
	new_passwd = (char*)getpass("New Password (ONCE ONLY - get it right :-)");

	nt_lm_owf_gen(new_passwd, lm_newhash, nt_newhash);
	pwd_get_lm_nt_16(&(smb_cli->pwd), lm_oldhash, nt_oldhash );
	make_oem_passwd_hash(nt_newpass, new_passwd, nt_oldhash, True);
	make_oem_passwd_hash(lm_newpass, new_passwd, lm_oldhash, True);
	E_old_pw_hash(lm_newhash, lm_oldhash, lm_hshhash);
	E_old_pw_hash(lm_newhash, nt_oldhash, nt_hshhash);

	cli_nt_set_ntlmssp_flgs(smb_cli,
		                    NTLMSSP_NEGOTIATE_UNICODE |
		                    NTLMSSP_NEGOTIATE_OEM |
		                    NTLMSSP_NEGOTIATE_SIGN |
		                    NTLMSSP_NEGOTIATE_SEAL |
		                    NTLMSSP_NEGOTIATE_LM_KEY |
		                    NTLMSSP_NEGOTIATE_NTLM |
		                    NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
		                    NTLMSSP_NEGOTIATE_00001000 |
		                    NTLMSSP_NEGOTIATE_00002000);

	/* open SAMR session.  */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_unknown_38(smb_cli, fnum, srv_name) : False;

	/* establish a connection. */
	res = res ? samr_chgpasswd_user(smb_cli, fnum,
	                                   srv_name, smb_cli->user_name,
	                                   nt_newpass, nt_hshhash,
	                                   lm_newpass, lm_hshhash) : False;
	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res)
	{
		report(out_hnd, "NT Password changed OK\n");
	}
	else
	{
		report(out_hnd, "NT Password change FAILED\n");
	}
}


/****************************************************************************
experimental SAM encryted rpc test connection
****************************************************************************/
void cmd_sam_test(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring sid;
	BOOL res = True;

	sid_to_string(sid, &info->dom.level5_sid);
	fstrcpy(domain, info->dom.level5_dom);

/*
	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}
*/
	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	report(out_hnd, "SAM Encryption Test\n");

	cli_nt_set_ntlmssp_flgs(smb_cli,
		                    NTLMSSP_NEGOTIATE_UNICODE |
		                    NTLMSSP_NEGOTIATE_OEM |
		                    NTLMSSP_NEGOTIATE_SIGN |
		                    NTLMSSP_NEGOTIATE_SEAL |
		                    NTLMSSP_NEGOTIATE_LM_KEY |
		                    NTLMSSP_NEGOTIATE_NTLM |
		                    NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
		                    NTLMSSP_NEGOTIATE_00001000 |
		                    NTLMSSP_NEGOTIATE_00002000);

	/* open SAMR session.  */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_unknown_38(smb_cli, fnum, srv_name) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res)
	{
		DEBUG(5,("cmd_sam_test: succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_sam_test: failed\n"));
	}
}

/****************************************************************************
Lookup domain in SAM server.
****************************************************************************/
void cmd_sam_lookup_domain(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring str_sid;
	DOM_SID dom_sid;
	BOOL res = True;
	POLICY_HND sam_pol;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (!next_token(NULL, domain, NULL, sizeof(domain)))
	{
		report(out_hnd, "lookupdomain: <name>\n");
		return;
	}

	report(out_hnd, "Lookup Domain in SAM Server\n");

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_query_lookup_domain(smb_cli, fnum, 
	            &sam_pol, domain, &dom_sid) : False;

	res = res ? samr_close(smb_cli, fnum, &sam_pol) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res)
	{
		DEBUG(5,("cmd_sam_lookup_domain: succeeded\n"));

		sid_to_string(str_sid, &dom_sid);
		report(out_hnd, "%s SID: %s\n", domain, str_sid);
		report(out_hnd, "Lookup Domain: OK\n");
	}
	else
	{
		DEBUG(5,("cmd_sam_lookup_domain: failed\n"));
		report(out_hnd, "Lookup Domain: FAILED\n");
	}
}

/****************************************************************************
SAM delete alias member.
****************************************************************************/
void cmd_sam_del_aliasmem(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring tmp;
	fstring sid;
	DOM_SID sid1;
	POLICY_HND alias_pol;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	DOM_SID member_sid; 
	uint32 alias_rid;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (!next_token(NULL, tmp, NULL, sizeof(tmp)))
	{
		report(out_hnd, "delaliasmem: <alias rid> [member sid1] [member sid2] ...\n");
		return;
	}
	alias_rid = get_number(tmp);

	report(out_hnd, "SAM Domain Alias Member\n");

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum, 
	            &sam_pol, ace_perms, &sid1,
	            &pol_dom) : False;

	/* connect to the domain */
	res1 = res ? samr_open_alias(smb_cli, fnum,
	            &pol_dom,
	            0x000f001f, alias_rid, &alias_pol) : False;

	while (next_token(NULL, tmp, NULL, sizeof(tmp)) && res2 && res1)
	{
		/* get a sid, delete a member from the alias */
		res2 = res2 ? string_to_sid(&member_sid, tmp) : False;
		res2 = res2 ? samr_del_aliasmem(smb_cli, fnum, &alias_pol, &member_sid) : False;

		if (res2)
		{
			report(out_hnd, "SID deleted from Alias 0x%x: %s\n", alias_rid, tmp);
		}
	}

	res1 = res1 ? samr_close(smb_cli, fnum, &alias_pol) : False;
	res  = res  ? samr_close(smb_cli, fnum, &pol_dom) : False;
	res  = res  ? samr_close(smb_cli, fnum, &sam_pol) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res && res1 && res2)
	{
		DEBUG(5,("cmd_sam_del_aliasmem: succeeded\n"));
		report(out_hnd, "Delete Domain Alias Member: OK\n");
	}
	else
	{
		DEBUG(5,("cmd_sam_del_aliasmem: failed\n"));
		report(out_hnd, "Delete Domain Alias Member: FAILED\n");
	}
}

/****************************************************************************
SAM delete alias.
****************************************************************************/
void cmd_sam_delete_dom_alias(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring name;
	fstring sid;
	DOM_SID sid1;
	POLICY_HND alias_pol;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	uint32 alias_rid = 0;
	char *names[1];
	uint32 rid [MAX_LOOKUP_SIDS];
	uint32 type[MAX_LOOKUP_SIDS];
	uint32 num_rids;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (!next_token(NULL, name, NULL, sizeof(name)))
	{
		report(out_hnd, "delalias <alias name>\n");
		return;
	}

	report(out_hnd, "SAM Delete Domain Alias\n");

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum, 
	            &sam_pol, ace_perms, &sid1,
	            &pol_dom) : False;

	names[0] = name;

	res1 = res ? samr_query_lookup_names(smb_cli, fnum,
	            &pol_dom, 0x000003e8,
	            1, names,
	            &num_rids, rid, type) : False;

	if (res1 && num_rids == 1)
	{
		alias_rid = rid[0];
	}

	/* connect to the domain */
	res1 = res1 ? samr_open_alias(smb_cli, fnum,
	            &pol_dom,
	            0x000f001f, alias_rid, &alias_pol) : False;

	res2 = res1 ? samr_delete_dom_alias(smb_cli, fnum, &alias_pol) : False;

	res1 = res1 ? samr_close(smb_cli, fnum, &alias_pol) : False;
	res  = res  ? samr_close(smb_cli, fnum, &pol_dom) : False;
	res  = res  ? samr_close(smb_cli, fnum, &sam_pol) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res && res1 && res2)
	{
		DEBUG(5,("cmd_sam_delete_dom_alias: succeeded\n"));
		report(out_hnd, "Delete Domain Alias: OK\n");
	}
	else
	{
		DEBUG(5,("cmd_sam_delete_dom_alias: failed\n"));
		report(out_hnd, "Delete Domain Alias: FAILED\n");
	}
}

/****************************************************************************
SAM add alias member.
****************************************************************************/
void cmd_sam_add_aliasmem(struct client_info *info)
{
	uint16 fnum;
	uint16 fnum_lsa;
	fstring srv_name;
	fstring domain;
	fstring tmp;
	fstring sid;
	DOM_SID sid1;
	POLICY_HND alias_pol;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	BOOL res3 = True;
	BOOL res4 = True;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	uint32 alias_rid;
	char **names = NULL;
	int num_names = 0;
	DOM_SID *sids = NULL; 
	int num_sids = 0;
	int i;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;
	POLICY_HND lsa_pol;

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	while (next_token(NULL, tmp, NULL, sizeof(tmp)))
	{
		if (add_chars_to_array(&num_names, &names, tmp) == NULL)
		{
			return;
		}
	}

	if (num_names < 2)
	{
		report(out_hnd, "addaliasmem <group name> [member name1] [member name2] ...\n");
		return;
	}
	
	report(out_hnd, "SAM Domain Alias Member\n");

	/* open LSARPC session. */
	res3 = res3 ? cli_nt_session_open(smb_cli, PIPE_LSARPC, &fnum_lsa) : False;

	/* lookup domain controller; receive a policy handle */
	res3 = res3 ? lsa_open_policy(smb_cli, fnum_lsa,
				srv_name,
				&lsa_pol, True) : False;

	/* send lsa lookup sids call */
	res4 = res3 ? lsa_lookup_names(smb_cli, fnum_lsa, 
				       &lsa_pol,
				       num_names, names, 
				       &sids, NULL, &num_sids) : False;

	res3 = res3 ? lsa_close(smb_cli, fnum_lsa, &lsa_pol) : False;

	cli_nt_session_close(smb_cli, fnum_lsa);

	res4 = num_sids < 2 ? False : res4;

	if (res4)
	{
		/*
		 * accept domain sid or builtin sid
		 */

		DOM_SID sid_1_5_20;
		string_to_sid(&sid_1_5_20, "S-1-5-32");
		sid_split_rid(&sids[0], &alias_rid);

		if (sid_equal(&sids[0], &sid_1_5_20))
		{
			sid_copy(&sid1, &sid_1_5_20);
		}
		else if (!sid_equal(&sids[0], &sid1))
		{	
			res4 = False;
		}
	}

	/* open SAMR session.  negotiate credentials */
	res = res4 ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum, 
	            &sam_pol, ace_perms, &sid1,
	            &pol_dom) : False;

	/* connect to the domain */
	res1 = res ? samr_open_alias(smb_cli, fnum,
	            &pol_dom,
	            0x000f001f, alias_rid, &alias_pol) : False;

	for (i = 1; i < num_sids && res2 && res1; i++)
	{
		/* add a member to the alias */
		res2 = res2 ? samr_add_aliasmem(smb_cli, fnum, &alias_pol, &sids[i]) : False;

		if (res2)
		{
			sid_to_string(tmp, &sids[i]);
			report(out_hnd, "SID added to Alias 0x%x: %s\n", alias_rid, tmp);
		}
	}

	res1 = res1 ? samr_close(smb_cli, fnum, &alias_pol) : False;
	res  = res  ? samr_close(smb_cli, fnum, &pol_dom) : False;
	res  = res  ? samr_close(smb_cli, fnum, &sam_pol) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (sids != NULL)
	{
		free(sids);
	}
	
	free_char_array(num_names, names);

	if (res && res1 && res2)
	{
		DEBUG(5,("cmd_sam_add_aliasmem: succeeded\n"));
		report(out_hnd, "Add Domain Alias Member: OK\n");
	}
	else
	{
		DEBUG(5,("cmd_sam_add_aliasmem: failed\n"));
		report(out_hnd, "Add Domain Alias Member: FAILED\n");
	}
}


/****************************************************************************
SAM create domain user.
****************************************************************************/
void cmd_sam_create_dom_user(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring acct_name;
	fstring acct_desc;
	fstring sid;
	DOM_SID sid1;
	BOOL res = True;
	BOOL res1 = True;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	uint32 user_rid; 
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}


	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (!next_token(NULL, acct_name, NULL, sizeof(acct_name)))
	{
		report(out_hnd, "createuser: <acct name> [acct description]\n");
	}

	if (!next_token(NULL, acct_desc, NULL, sizeof(acct_desc)))
	{
		acct_desc[0] = 0;
	}


	report(out_hnd, "SAM Create Domain User\n");
	report(out_hnd, "Domain: %s Name: %s Description: %s\n",
	                  domain, acct_name, acct_desc);

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum, 
	            &sam_pol, ace_perms, &sid1,
	            &pol_dom) : False;

	/* create a domain user */
	res1 = res ? create_samr_domain_user(smb_cli, fnum, 
				&pol_dom,
	                        acct_name, ACB_NORMAL, &user_rid) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &pol_dom) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &sam_pol) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res && res1)
	{
		DEBUG(5,("cmd_sam_create_dom_user: succeeded\n"));
		report(out_hnd, "Create Domain User: OK\n");
	}
	else
	{
		DEBUG(5,("cmd_sam_create_dom_user: failed\n"));
		report(out_hnd, "Create Domain User: FAILED\n");
	}
}


/****************************************************************************
SAM create domain alias.
****************************************************************************/
void cmd_sam_create_dom_alias(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring acct_name;
	fstring acct_desc;
	fstring sid;
	DOM_SID sid1;
	BOOL res = True;
	BOOL res1 = True;
	uint32 ace_perms = 0x02000000; /* permissions */
	uint32 alias_rid; 
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}


	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (!next_token(NULL, acct_name, NULL, sizeof(acct_name)))
	{
		report(out_hnd, "createalias: <acct name> [acct description]\n");
	}

	if (!next_token(NULL, acct_desc, NULL, sizeof(acct_desc)))
	{
		acct_desc[0] = 0;
	}


	report(out_hnd, "SAM Create Domain Alias\n");
	report(out_hnd, "Domain: %s Name: %s Description: %s\n",
	                  domain, acct_name, acct_desc);

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum, 
	            &sam_pol, ace_perms, &sid1,
	            &pol_dom) : False;

	/* create a domain alias */
	res1 = res ? create_samr_domain_alias(smb_cli, fnum, 
				&pol_dom,
	                        acct_name, acct_desc, &alias_rid) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &pol_dom) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &sam_pol) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res && res1)
	{
		DEBUG(5,("cmd_sam_create_dom_alias: succeeded\n"));
		report(out_hnd, "Create Domain Alias: OK\n");
	}
	else
	{
		DEBUG(5,("cmd_sam_create_dom_alias: failed\n"));
		report(out_hnd, "Create Domain Alias: FAILED\n");
	}
}


/****************************************************************************
SAM delete group member.
****************************************************************************/
void cmd_sam_del_groupmem(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring tmp;
	fstring sid;
	DOM_SID sid1;
	POLICY_HND pol_grp;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	uint32 member_rid; 
	uint32 group_rid;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (!next_token(NULL, tmp, NULL, sizeof(tmp)))
	{
		report(out_hnd, "delgroupmem: <group rid> [member rid1] [member rid2] ...\n");
		return;
	}
	group_rid = get_number(tmp);

	report(out_hnd, "SAM Add Domain Group member\n");

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum, 
	            &sam_pol, ace_perms, &sid1,
	            &pol_dom) : False;

	/* connect to the domain */
	res1 = res ? samr_open_group(smb_cli, fnum,
	            &pol_dom,
	            0x0000001f, group_rid, &pol_grp) : False;

	while (next_token(NULL, tmp, NULL, sizeof(tmp)) && res2 && res1)
	{
		/* get a rid, delete a member from the group */
		member_rid = get_number(tmp);
		res2 = res2 ? samr_del_groupmem(smb_cli, fnum, &pol_grp, member_rid) : False;

		if (res2)
		{
			report(out_hnd, "RID deleted from Group 0x%x: 0x%x\n", group_rid, member_rid);
		}
	}

	res1 = res1 ? samr_close(smb_cli, fnum, &pol_grp) : False;
	res  = res  ? samr_close(smb_cli, fnum, &pol_dom) : False;
	res  = res  ? samr_close(smb_cli, fnum, &sam_pol) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res && res1 && res2)
	{
		DEBUG(5,("cmd_sam_del_groupmem: succeeded\n"));
		report(out_hnd, "Add Domain Group Member: OK\n");
	}
	else
	{
		DEBUG(5,("cmd_sam_del_groupmem: failed\n"));
		report(out_hnd, "Add Domain Group Member: FAILED\n");
	}
}


/****************************************************************************
SAM delete group.
****************************************************************************/
void cmd_sam_delete_dom_group(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring name;
	fstring sid;
	DOM_SID sid1;
	POLICY_HND pol_grp;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	uint32 group_rid = 0;
	char *names[1];
	uint32 rid [MAX_LOOKUP_SIDS];
	uint32 type[MAX_LOOKUP_SIDS];
	uint32 num_rids;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (!next_token(NULL, name, NULL, sizeof(name)))
	{
		report(out_hnd, "delgroup <group name>\n");
		return;
	}

	report(out_hnd, "SAM Delete Domain Group\n");

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum, 
	            &sam_pol, ace_perms, &sid1,
	            &pol_dom) : False;

	names[0] = name;

	res1 = res ? samr_query_lookup_names(smb_cli, fnum,
	            &pol_dom, 0x000003e8,
	            1, names,
	            &num_rids, rid, type) : False;

	if (res1 && num_rids == 1)
	{
		group_rid = rid[0];
	}

	/* connect to the domain */
	res1 = res1 ? samr_open_group(smb_cli, fnum,
	            &pol_dom,
	            0x0000001f, group_rid, &pol_grp) : False;

	res2 = res1 ? samr_delete_dom_group(smb_cli, fnum, &pol_grp) : False;

	res1 = res1 ? samr_close(smb_cli, fnum, &pol_grp) : False;
	res  = res  ? samr_close(smb_cli, fnum, &pol_dom) : False;
	res  = res  ? samr_close(smb_cli, fnum, &sam_pol) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res && res1 && res2)
	{
		DEBUG(5,("cmd_sam_delete_dom_group: succeeded\n"));
		report(out_hnd, "Delete Domain Group: OK\n");
	}
	else
	{
		DEBUG(5,("cmd_sam_delete_dom_group: failed\n"));
		report(out_hnd, "Delete Domain Group: FAILED\n");
	}
}


/****************************************************************************
SAM add group member.
****************************************************************************/
void cmd_sam_add_groupmem(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring tmp;
	fstring sid;
	DOM_SID sid1;
	POLICY_HND pol_grp;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	BOOL res3 = True;
	BOOL res4 = True;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	uint32 group_rid[0];
	uint32 group_type[1];
	char **names = NULL;
	uint32 num_names = 0;
	fstring group_name;
	char *group_names[1];
	uint32 rid [MAX_LOOKUP_SIDS];
	uint32 type[MAX_LOOKUP_SIDS];
	uint32 num_rids;
	uint32 num_group_rids;
	uint32 i;
	DOM_SID sid_1_5_20;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;
	POLICY_HND pol_blt;

	string_to_sid(&sid_1_5_20, "S-1-5-32");

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	res = next_token(NULL, group_name, NULL, sizeof(group_name));
	group_names[0] = group_name;

	while (res && next_token(NULL, tmp, NULL, sizeof(tmp)))
	{
		if (add_chars_to_array(&num_names, &names, tmp) == NULL)
		{
			return;
		}
	}

	if (num_names < 1)
	{
		report(out_hnd, "addgroupmem <group name> [member name1] [member name2] ...\n");
		return;
	}
	
	report(out_hnd, "SAM Add Domain Group member\n");

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res4 = res ? samr_open_domain(smb_cli, fnum, 
	            &sam_pol, ace_perms, &sid1,
	            &pol_dom) : False;

	/* connect to the domain */
	res3 = res ? samr_open_domain(smb_cli, fnum, 
	            &sam_pol, ace_perms, &sid_1_5_20,
	            &pol_blt) : False;

	res2 = res4 ? samr_query_lookup_names(smb_cli, fnum,
	            &pol_dom, 0x000003e8,
	            1, group_names,
	            &num_group_rids, group_rid, group_type) : False;

	/* open the group */
	res2 = res2 ? samr_open_group(smb_cli, fnum,
	            &pol_dom,
	            0x0000001f, group_rid[0], &pol_grp) : False;

	if (!res2 || (group_type != NULL && group_type[0] == SID_NAME_UNKNOWN))
	{
		res2 = res3 ? samr_query_lookup_names(smb_cli, fnum,
			    &pol_blt, 0x000003e8,
			    1, group_names, 
			    &num_group_rids, group_rid, group_type) : False;

		/* open the group */
		res2 = res2 ? samr_open_group(smb_cli, fnum,
			    &pol_blt,
			    0x0000001f, group_rid[0], &pol_grp) : False;
	}

	if (res2 && group_type[0] == SID_NAME_ALIAS)
	{
		report(out_hnd, "%s is a local alias, not a group.  Use addaliasmem command instead\n",
			group_name);
		return;
	}
	res1 = res2 ? samr_query_lookup_names(smb_cli, fnum,
	            &pol_dom, 0x000003e8,
	            num_names, names,
	            &num_rids, rid, type) : False;

	if (num_rids == 0)
	{
		report(out_hnd, "Member names not known\n");
	}
	for (i = 0; i < num_rids && res2 && res1; i++)
	{
		if (type[i] == SID_NAME_UNKNOWN)
		{
			report(out_hnd, "Name %s unknown\n", names[i]);
		}
		else
		{
			if (samr_add_groupmem(smb_cli, fnum, &pol_grp, rid[i]))
			{
				report(out_hnd, "RID added to Group 0x%x: 0x%x\n",
						 group_rid[0], rid[i]);
			}
		}
	}

	res1 = res ? samr_close(smb_cli, fnum, &pol_grp) : False;
	res1 = res3 ? samr_close(smb_cli, fnum, &pol_blt) : False;
	res1 = res4 ? samr_close(smb_cli, fnum, &pol_dom) : False;
	res  = res ? samr_close(smb_cli, fnum, &sam_pol) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	free_char_array(num_names, names);
	
	if (res && res1 && res2)
	{
		DEBUG(5,("cmd_sam_add_groupmem: succeeded\n"));
		report(out_hnd, "Add Domain Group Member: OK\n");
	}
	else
	{
		DEBUG(5,("cmd_sam_add_groupmem: failed\n"));
		report(out_hnd, "Add Domain Group Member: FAILED\n");
	}
#if 0
	if (group_rid != NULL)
	{
		free(group_rid);
	}
	if (group_type != NULL)
	{
		free(group_type);
	}
#endif
}


/****************************************************************************
SAM create domain group.
****************************************************************************/
void cmd_sam_create_dom_group(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring acct_name;
	fstring acct_desc;
	fstring sid;
	DOM_SID sid1;
	BOOL res = True;
	BOOL res1 = True;
	uint32 ace_perms = 0x02000000; /* absolutely no idea. */
	uint32 group_rid; 
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}


	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (!next_token(NULL, acct_name, NULL, sizeof(acct_name)))
	{
		report(out_hnd, "creategroup: <acct name> [acct description]\n");
	}

	if (!next_token(NULL, acct_desc, NULL, sizeof(acct_desc)))
	{
		acct_desc[0] = 0;
	}


	report(out_hnd, "SAM Create Domain Group\n");
	report(out_hnd, "Domain: %s Name: %s Description: %s\n",
	                  domain, acct_name, acct_desc);

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum, 
	            &sam_pol, ace_perms, &sid1,
	            &pol_dom) : False;

	/* read some users */
	res1 = res ? create_samr_domain_group(smb_cli, fnum, 
				&pol_dom,
	                        acct_name, acct_desc, &group_rid) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &pol_dom) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &sam_pol) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res && res1)
	{
		DEBUG(5,("cmd_sam_create_dom_group: succeeded\n"));
		report(out_hnd, "Create Domain Group: OK\n");
	}
	else
	{
		DEBUG(5,("cmd_sam_create_dom_group: failed\n"));
		report(out_hnd, "Create Domain Group: FAILED\n");
	}
}

/****************************************************************************
experimental SAM users enum.
****************************************************************************/
void cmd_sam_enum_users(struct client_info *info)
{
	BOOL request_user_info  = False;
	BOOL request_group_info = False;
	BOOL request_alias_info = False;
	fstring tmp;
	struct acct_info *sam = NULL;
	uint32 num_sam_entries = 0;
	int i;

	fstring srv_name;
	fstring domain;
	fstring sid;
	DOM_SID sid1;
	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	for (i = 0; i < 3; i++)
	{
		/* a bad way to do token parsing... */
		if (next_token(NULL, tmp, NULL, sizeof(tmp)))
		{
			request_user_info  |= strequal(tmp, "-u");
			request_group_info |= strequal(tmp, "-g");
			request_alias_info |= strequal(tmp, "-a");
		}
		else
		{
			break;
		}
	}

	report(out_hnd, "SAM Enumerate Users\n");

	msrpc_sam_enum_users(smb_cli, domain, &sid1, srv_name,
	            &sam, &num_sam_entries,
	            sam_display_user,
	            request_user_info  ? sam_display_user_info     : NULL,
	            request_group_info ? sam_display_group_members : NULL,
	            request_alias_info ? sam_display_group_members : NULL);

	if (sam != NULL)
	{
		free(sam);
	}
}


/****************************************************************************
experimental SAM group query members.
****************************************************************************/
void cmd_sam_query_groupmem(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring sid_str;
	DOM_SID sid;
	BOOL res = True;
	BOOL res1 = True;

	fstring group_name;
	char *names[1];
	uint32 num_rids;
	uint32 rid[MAX_LOOKUP_SIDS];
	uint32 type[MAX_LOOKUP_SIDS];
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	fstrcpy(domain, info->dom.level5_dom);
	sid_copy(&sid, &info->dom.level5_sid);

	if (sid.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	if (!next_token(NULL, group_name, NULL, sizeof(group_name)))
	{
		report(out_hnd, "samgroup <name>\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_to_string(sid_str, &sid);

	report(out_hnd, "SAM Query Group: %s\n", group_name);
	report(out_hnd, "From: %s To: %s Domain: %s SID: %s\n",
	                  info->myhostname, srv_name, domain, sid_str);

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum,
				srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum,
	            &sam_pol, 0x304, &sid,
	            &pol_dom) : False;

	/* look up group rid */
	names[0] = group_name;
	res1 = res ? samr_query_lookup_names(smb_cli, fnum,
					&pol_dom, 0x3e8,
					1, names,
					&num_rids, rid, type) : False;

	if (res1 && num_rids == 1)
	{
		res1 = req_groupmem_info(smb_cli, fnum,
				&pol_dom,
				domain,
				&sid,
				rid[0],
	                        names[0],
				sam_display_group_members);
	}

	res = res ? samr_close(smb_cli, fnum,
	            &sam_pol) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &pol_dom) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res1)
	{
		DEBUG(5,("cmd_sam_query_group: succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_sam_query_group: failed\n"));
	}
}


/****************************************************************************
experimental SAM group query.
****************************************************************************/
void cmd_sam_query_group(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring sid_str;
	DOM_SID sid;
	BOOL res = True;
	BOOL res1 = True;

	fstring group_name;
	char *names[1];
	uint32 num_rids;
	uint32 rid[MAX_LOOKUP_SIDS];
	uint32 type[MAX_LOOKUP_SIDS];
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	fstrcpy(domain, info->dom.level5_dom);
	sid_copy(&sid, &info->dom.level5_sid);

	if (sid.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	if (!next_token(NULL, group_name, NULL, sizeof(group_name)))
	{
		report(out_hnd, "samgroup <name>\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_to_string(sid_str, &sid);

	report(out_hnd, "SAM Query Group: %s\n", group_name);
	report(out_hnd, "From: %s To: %s Domain: %s SID: %s\n",
	                  info->myhostname, srv_name, domain, sid_str);

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum,
				srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum,
	            &sam_pol, 0x304, &sid,
	            &pol_dom) : False;

	/* look up group rid */
	names[0] = group_name;
	res1 = res ? samr_query_lookup_names(smb_cli, fnum,
					&pol_dom, 0x3e8,
					1, names,
					&num_rids, rid, type) : False;

	if (res1 && num_rids == 1)
	{
		res1 = query_groupinfo(smb_cli, fnum,
				&pol_dom,
				domain,
				&sid,
				rid[0],
				sam_display_group_info);
	}

	res = res ? samr_close(smb_cli, fnum,
	            &sam_pol) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &pol_dom) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res1)
	{
		DEBUG(5,("cmd_sam_query_group: succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_sam_query_group: failed\n"));
	}
}


/****************************************************************************
experimental SAM user query.
****************************************************************************/
void cmd_sam_query_user(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring sid_str;
	DOM_SID sid;
	BOOL res = True;
	BOOL res1 = True;

	fstring user_name;
	char *names[1];
	uint32 num_rids;
	uint32 rid[MAX_LOOKUP_SIDS];
	uint32 type[MAX_LOOKUP_SIDS];
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	fstrcpy(domain, info->dom.level5_dom);
	sid_copy(&sid, &info->dom.level5_sid);

	if (sid.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	if (!next_token(NULL, user_name, NULL, sizeof(user_name)))
	{
		report(out_hnd, "samuser <name>\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_to_string(sid_str, &sid);

	report(out_hnd, "SAM Query User: %s\n", user_name);
	report(out_hnd, "From: %s To: %s Domain: %s SID: %s\n",
	                  info->myhostname, srv_name, domain, sid_str);

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum,
				srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum,
	            &sam_pol, 0x304, &sid,
	            &pol_dom) : False;

	/* look up user rid */
	names[0] = user_name;
	res1 = res ? samr_query_lookup_names(smb_cli, fnum,
					&pol_dom, 0x3e8,
					1, names,
					&num_rids, rid, type) : False;

	/* send user info query */
	if (res1 && num_rids == 1)
	{
		res1 = req_user_info(smb_cli, fnum,
				&pol_dom,
				domain,
				&sid,
				rid[0],
				sam_display_user_info);
	}
	res = res ? samr_close(smb_cli, fnum,
	            &sam_pol) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &pol_dom) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res1)
	{
		DEBUG(5,("cmd_sam_query_user: succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_sam_query_user: failed\n"));
	}
}


/****************************************************************************
experimental SAM user set.
****************************************************************************/
void cmd_sam_set_userinfo(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring sid_str;
	DOM_SID sid;
	BOOL res = True;
	BOOL res1 = True;
	uint32 argc = 0;
	char **argv = NULL;
	uint32 cp_argc = 0;
	char **cp_argv = NULL;
	extern int optind;
	int opt;
	BOOL set_passwd = False;

	fstring user_name;
	fstring password;
	fstring tmp;

	char *names[1];
	uint32 num_rids;
	uint32 rid[MAX_LOOKUP_SIDS];
	uint32 type[MAX_LOOKUP_SIDS];
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;
	SAM_USER_INFO_21 usr21;

	fstrcpy(domain, info->dom.level5_dom);
	sid_copy(&sid, &info->dom.level5_sid);

	if (sid.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	/* create arguments array */
	while (next_token(NULL, tmp, NULL, sizeof(tmp)))
	{
		add_chars_to_array(&argc, &argv, tmp);
	}

	cp_argc = argc;
	cp_argv = argv;

	if (cp_argc == 0)
	{
		report(out_hnd, "samuserset <name> [-p password]\n");
		return;
	}

	safe_strcpy(user_name, cp_argv[0], sizeof(user_name));

	cp_argc--;
	cp_argv++;

	if (cp_argc == 0)
	{
		fstring pass_str;
		char *pass;
		slprintf(pass_str, sizeof(pass_str)-1, "Enter %s's Password:",
		         user_name);
		pass = (char*)getpass(pass_str);

		if (pass != NULL)
		{
			safe_strcpy(password, pass,
				    sizeof(password)-1);
			set_passwd = True;
		}
	}
	else
	{
		optind = -1;
		while ((opt = getopt(cp_argc, cp_argv,"p:")) != EOF)
		{
			switch (opt)
			{
				case 'p':
				{
					set_passwd = True;
					safe_strcpy(password, optarg,
					            sizeof(password)-1);
					break;
				}
			}
		}
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_to_string(sid_str, &sid);

	report(out_hnd, "SAM Set User Info: %s\n", user_name);
	report(out_hnd, "Password: %s\n", password);

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum,
				srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum,
	            &sam_pol, 0x02000000, &sid,
	            &pol_dom) : False;

	/* look up user rid */
	names[0] = user_name;
	res1 = res ? samr_query_lookup_names(smb_cli, fnum,
					&pol_dom, 0x3e8,
					1, names,
					&num_rids, rid, type) : False;

	/* send set user info */
	if (res1 && num_rids == 1 && get_samr_query_userinfo(smb_cli, fnum,
						    &pol_dom,
						    0x15, rid[0], &usr21))
	{
		void *usr = NULL;
		uint32 switch_value = 0;
		char pwbuf[516];

		if (set_passwd)
		{
			encode_pw_buffer(pwbuf, password,
			               strlen(password), True);
			SamOEMhash(pwbuf, smb_cli->sess_key, 1);
		}

		if (True)
		{
			SAM_USER_INFO_24 *p = malloc(sizeof(SAM_USER_INFO_24));
			make_sam_user_info24(p, pwbuf);

			usr = p;
			switch_value = 24;
		}
		
		if (False)
		{
			SAM_USER_INFO_23 *p = malloc(sizeof(SAM_USER_INFO_23));
			/* send user info query, level 0x15 */
			make_sam_user_info23W(p,
				&usr21.logon_time, 
				&usr21.logoff_time, 
				&usr21.kickoff_time, 
				&usr21.pass_last_set_time, 
				&usr21.pass_can_change_time, 
				&usr21.pass_must_change_time, 

				&usr21.uni_user_name, 
				&usr21.uni_full_name,
				&usr21.uni_home_dir,
				&usr21.uni_dir_drive,
				&usr21.uni_logon_script,
				&usr21.uni_profile_path,
				&usr21.uni_acct_desc,
				&usr21.uni_workstations,
				&usr21.uni_unknown_str,
				&usr21.uni_munged_dial,

				0x0, 
				usr21.group_rid,
				usr21.acb_info, 

				0x09f827fa,
				usr21.logon_divs,
				&usr21.logon_hrs,
				usr21.unknown_5,
				pwbuf,
				usr21.unknown_6);

			usr = p;
			switch_value = 23;
		}
		if (usr != NULL)
		{
			res1 = set_samr_set_userinfo(smb_cli, fnum,
					    &pol_dom,
					    switch_value, rid[0], usr);
		}
	}
	res = res ? samr_close(smb_cli, fnum,
	            &sam_pol) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &pol_dom) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res1)
	{
		report(out_hnd, "Set User Info: OK\n");
		DEBUG(5,("cmd_sam_query_user: succeeded\n"));
	}
	else
	{
		report(out_hnd, "Set User Info: Failed\n");
		DEBUG(5,("cmd_sam_query_user: failed\n"));
	}

	free_char_array(argc, argv);
}


/****************************************************************************
experimental SAM query display info.
****************************************************************************/
void cmd_sam_query_dispinfo(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring sid;
	DOM_SID sid1;
	BOOL res = True;
	fstring info_str;
	uint16 switch_value = 1;
	uint32 ace_perms = 0x304; /* absolutely no idea. */
	SAM_DISPINFO_CTR ctr;
	SAM_DISPINFO_1 inf1;
	uint32 num_entries;
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	sid_to_string(sid, &info->dom.level5_sid);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		fprintf(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	string_to_sid(&sid1, sid);

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (next_token(NULL, info_str, NULL, sizeof(info_str)))
	{
		switch_value = strtoul(info_str, (char**)NULL, 10);
	}

	fprintf(out_hnd, "SAM Query Domain Info: info level %d\n", switch_value);
	fprintf(out_hnd, "From: %s To: %s Domain: %s SID: %s\n",
	                  info->myhostname, srv_name, domain, sid);

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum, 
				srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum, 
	            &sam_pol, ace_perms, &sid1,
	            &pol_dom) : False;

	ctr.sam.info1 = &inf1;

	/* send a samr query_disp_info command */
	res = res ? samr_query_dispinfo(smb_cli, fnum,
	            &pol_dom, switch_value, 
		    &num_entries, &ctr) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &sam_pol) : False;

	res = res ? samr_close(smb_cli, fnum, 
	            &pol_dom) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res)
	{
		DEBUG(5,("cmd_sam_query_dispinfo: succeeded\n"));
#if 0
		display_sam_disp_info_ctr(out_hnd, ACTION_HEADER   , switch_value, &ctr);
		display_sam_disp_info_ctr(out_hnd, ACTION_ENUMERATE, switch_value, &ctr);
		display_sam_disp_info_ctr(out_hnd, ACTION_FOOTER   , switch_value, &ctr);
#endif
	}
	else
	{
		DEBUG(5,("cmd_sam_query_dispinfo: failed\n"));
	}
}

/****************************************************************************
experimental SAM domain info query.
****************************************************************************/
void cmd_sam_query_dominfo(struct client_info *info)
{
	fstring domain;
	fstring sid;
	DOM_SID sid1;
	fstring info_str;
	uint32 switch_value = 2;
	SAM_UNK_CTR ctr;

	sid_to_string(sid, &info->dom.level5_sid);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	string_to_sid(&sid1, sid);

	if (next_token(NULL, info_str, NULL, sizeof(info_str)))
	{
		switch_value = strtoul(info_str, (char**)NULL, 10);
	}

	report(out_hnd, "SAM Query Domain Info: info level %d\n", switch_value);
	report(out_hnd, "From: %s Domain: %s SID: %s\n",
	                  info->myhostname, domain, sid);

	if (sam_query_dominfo(info, &sid1, switch_value, &ctr))
	{
		DEBUG(5,("cmd_sam_query_dominfo: succeeded\n"));
		display_sam_unk_ctr(out_hnd, ACTION_HEADER   , switch_value, &ctr);
		display_sam_unk_ctr(out_hnd, ACTION_ENUMERATE, switch_value, &ctr);
		display_sam_unk_ctr(out_hnd, ACTION_FOOTER   , switch_value, &ctr);
	}
	else
	{
		DEBUG(5,("cmd_sam_query_dominfo: failed\n"));
	}
}

/****************************************************************************
experimental SAM alias query members.
****************************************************************************/
void cmd_sam_query_aliasmem(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring sid_str;
	DOM_SID sid;
	BOOL res = True;
	BOOL res1 = True;

	fstring alias_name;
	char *names[1];
	uint32 num_rids;
	uint32 rid[MAX_LOOKUP_SIDS];
	uint32 type[MAX_LOOKUP_SIDS];
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	fstrcpy(domain, info->dom.level5_dom);
	sid_copy(&sid, &info->dom.level5_sid);

	if (sid.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	if (!next_token(NULL, alias_name, NULL, sizeof(alias_name)))
	{
		report(out_hnd, "samalias <name>\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_to_string(sid_str, &sid);

	report(out_hnd, "SAM Query Alias: %s\n", alias_name);
	report(out_hnd, "From: %s To: %s Domain: %s SID: %s\n",
	                  info->myhostname, srv_name, domain, sid_str);

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum,
				srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum,
	            &sam_pol, 0x304, &sid,
	            &pol_dom) : False;

	/* look up alias rid */
	names[0] = alias_name;
	res1 = res ? samr_query_lookup_names(smb_cli, fnum,
					&pol_dom, 0x3e8,
					1, names,
					&num_rids, rid, type) : False;

	if (res1 && num_rids == 1)
	{
		res1 = req_aliasmem_info(smb_cli, fnum,
				&pol_dom,
				domain,
				&sid,
				rid[0],
	                        names[0],
				sam_display_alias_members);
	}

	res = res ? samr_close(smb_cli, fnum,
	            &sam_pol) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &pol_dom) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res1)
	{
		DEBUG(5,("cmd_sam_query_alias: succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_sam_query_alias: failed\n"));
	}
}


/****************************************************************************
experimental SAM alias query.
****************************************************************************/
void cmd_sam_query_alias(struct client_info *info)
{
	uint16 fnum;
	fstring srv_name;
	fstring domain;
	fstring sid_str;
	DOM_SID sid;
	BOOL res = True;
	BOOL res1 = True;

	fstring alias_name;
	char *names[1];
	uint32 num_rids;
	uint32 rid[MAX_LOOKUP_SIDS];
	uint32 type[MAX_LOOKUP_SIDS];
	POLICY_HND sam_pol;
	POLICY_HND pol_dom;

	fstrcpy(domain, info->dom.level5_dom);
	sid_copy(&sid, &info->dom.level5_sid);

	if (sid.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	if (!next_token(NULL, alias_name, NULL, sizeof(alias_name)))
	{
		report(out_hnd, "samalias <name>\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	sid_to_string(sid_str, &sid);

	report(out_hnd, "SAM Query Alias: %s\n", alias_name);
	report(out_hnd, "From: %s To: %s Domain: %s SID: %s\n",
	                  info->myhostname, srv_name, domain, sid_str);

	/* open SAMR session.  negotiate credentials */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SAMR, &fnum) : False;

	/* establish a connection. */
	res = res ? samr_connect(smb_cli, fnum,
				srv_name, 0x02000000,
				&sam_pol) : False;

	/* connect to the domain */
	res = res ? samr_open_domain(smb_cli, fnum,
	            &sam_pol, 0x304, &sid,
	            &pol_dom) : False;

	/* look up alias rid */
	names[0] = alias_name;
	res1 = res ? samr_query_lookup_names(smb_cli, fnum,
					&pol_dom, 0x3e8,
					1, names,
					&num_rids, rid, type) : False;

	if (res1 && num_rids == 1)
	{
		res1 = query_aliasinfo(smb_cli, fnum,
				&pol_dom,
				domain,
				&sid,
				rid[0],
				sam_display_alias_info);
	}

	res = res ? samr_close(smb_cli, fnum,
	            &sam_pol) : False;

	res = res ? samr_close(smb_cli, fnum,
	            &pol_dom) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, fnum);

	if (res1)
	{
		DEBUG(5,("cmd_sam_query_alias: succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_sam_query_alias: failed\n"));
	}
}


/****************************************************************************
SAM aliases query.
****************************************************************************/
void cmd_sam_enum_aliases(struct client_info *info)
{
	BOOL request_member_info = False;
	BOOL request_alias_info = False;
	fstring tmp;
	int i;
	struct acct_info *sam = NULL;
	uint32 num_sam_entries = 0;

	fstring domain;
	fstring srv_name;
	fstring sid;
	DOM_SID sid1;
	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	for (i = 0; i < 2; i++)
	{
		/* a bad way to do token parsing... */
		if (next_token(NULL, tmp, NULL, sizeof(tmp)))
		{
			request_member_info |= strequal(tmp, "-m");
			request_alias_info  |= strequal(tmp, "-a");
		}
		else
		{
			break;
		}
	}

	report(out_hnd, "SAM Enumerate Aliases\n");

	msrpc_sam_enum_aliases(smb_cli, domain, &sid1, srv_name,
	            &sam, &num_sam_entries,
	            sam_display_alias,
	            request_alias_info  ? sam_display_alias_info    : NULL,
	            request_member_info ? sam_display_alias_members : NULL);

	if (sam != NULL)
	{
		free(sam);
	}
}

/****************************************************************************
experimental SAM groups enum.
****************************************************************************/
void cmd_sam_enum_groups(struct client_info *info)
{
	BOOL request_member_info = False;
	BOOL request_group_info = False;
	fstring tmp;
	int i;
	struct acct_info *sam = NULL;
	uint32 num_sam_entries = 0;

	fstring srv_name;
	fstring domain;
	fstring sid;
	DOM_SID sid1;
	sid_copy(&sid1, &info->dom.level5_sid);
	sid_to_string(sid, &sid1);
	fstrcpy(domain, info->dom.level5_dom);

	if (sid1.num_auths == 0)
	{
		report(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	for (i = 0; i < 3; i++)
	{
		/* a bad way to do token parsing... */
		if (next_token(NULL, tmp, NULL, sizeof(tmp)))
		{
			request_member_info |= strequal(tmp, "-m");
			request_group_info  |= strequal(tmp, "-g");
		}
		else
		{
			break;
		}
	}

	report(out_hnd, "SAM Enumerate Groups\n");

	msrpc_sam_enum_groups(smb_cli, domain, &sid1, srv_name,
	            &sam, &num_sam_entries,
	            sam_display_group,
	            request_group_info  ? sam_display_group_info    : NULL,
	            request_member_info ? sam_display_group_members : NULL);

	if (sam != NULL)
	{
		free(sam);
	}
}
