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


/****************************************************************************
  set samr sid
****************************************************************************/
static BOOL set_policy_samr_sid(struct policy_cache *cache, POLICY_HND *hnd,
				const DOM_SID *sid)
{
	pstring sidstr;
	DOM_SID *dev = sid_dup(sid);

	DEBUG(3,("Setting policy sid=%s\n", sid_to_string(sidstr, sid)));

	if (dev != NULL)
	{
		if (set_policy_state(cache, hnd, NULL, (void*)dev))
		{
			DEBUG(3,("Service setting policy sid=%s\n", sidstr));
			return True;
		}
		free(dev);
		return True;
	}
	DEBUG(3,("Error setting policy sid\n"));
	return False;
}

/****************************************************************************
  get samr sid
****************************************************************************/
static BOOL get_policy_samr_sid(struct policy_cache *cache,
				const POLICY_HND *hnd, DOM_SID *sid)
{
	DOM_SID *dev = (DOM_SID*)get_policy_state_info(cache, hnd);

	if (dev != NULL)
	{
		pstring tmp;
		sid_copy(sid, dev);
		DEBUG(3,("Getting policy sid=%s\n", sid_to_string(tmp, sid)));
		return True;
	}

	DEBUG(3,("Error getting policy sid\n"));
	return False;
}

/*******************************************************************
  This next function should be replaced with something that
  dynamically returns the correct user info..... JRA.
 ********************************************************************/

static BOOL get_sampwd_entries(SAM_USER_INFO_21 *pw_buf,
				int start_idx,
                                int *total_entries, int *num_entries,
                                int max_num_entries,
                                uint16 acb_mask)
{
	void *vp = NULL;
	struct sam_passwd *pwd = NULL;

	(*num_entries) = 0;
	(*total_entries) = 0;

	if (pw_buf == NULL) return False;

	vp = startsmbpwent(False);
	if (!vp)
	{
		DEBUG(0, ("get_sampwd_entries: Unable to open SMB password database.\n"));
		return False;
	}

	while (((pwd = getsam21pwent(vp)) != NULL) && (*num_entries) < max_num_entries)
	{
		int user_name_len;

		if (start_idx > 0)
		{
			/* skip the requested number of entries.
			   not very efficient, but hey...
			 */
			if (acb_mask == 0 || IS_BITS_SET_SOME(pwd->acct_ctrl, acb_mask))
			{
				start_idx--;
			}
			continue;
		}

		user_name_len = strlen(pwd->nt_name);
		make_unistr2(&(pw_buf[(*num_entries)].uni_user_name), pwd->nt_name, user_name_len);
		make_uni_hdr(&(pw_buf[(*num_entries)].hdr_user_name), user_name_len);
		pw_buf[(*num_entries)].user_rid = pwd->user_rid;
		bzero( pw_buf[(*num_entries)].nt_pwd , 16);

		/* Now check if the NT compatible password is available. */
		if (pwd->smb_nt_passwd != NULL)
		{
			memcpy( pw_buf[(*num_entries)].nt_pwd , pwd->smb_nt_passwd, 16);
		}

		pw_buf[(*num_entries)].acb_info = (uint16)pwd->acct_ctrl;

		DEBUG(5, ("entry idx: %d user %s, rid 0x%x, acb %x",
		          (*num_entries), pwd->nt_name,
		          pwd->user_rid, pwd->acct_ctrl));

		if (acb_mask == 0 || IS_BITS_SET_SOME(pwd->acct_ctrl, acb_mask))
		{
			DEBUG(5,(" acb_mask %x accepts\n", acb_mask));
			(*num_entries)++;
		}
		else
		{
			DEBUG(5,(" acb_mask %x rejects\n", acb_mask));
		}

		(*total_entries)++;
	}

	endsmbpwent(vp);

	return (*total_entries) > 0;
}

/*******************************************************************
 opens a samr group by rid, returns a policy handle.
 ********************************************************************/
static uint32 samr_open_by_sid( const POLICY_HND *parent_pol,
				const DOM_SID *dom_sid,
				POLICY_HND *pol,
				uint32 access_mask,
				uint32 rid)
{
	DOM_SID sid;
	
	/* get a (unique) handle.  open a policy on it. */
	if (!open_policy_hnd_link(get_global_hnd_cache(),
		parent_pol, pol, access_mask))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	DEBUG(0,("TODO: verify that the rid exists\n"));

	/* associate a SID with the (unique) handle. */
	sid_copy(&sid, dom_sid);
	sid_append_rid(&sid, rid);

	/* associate an group SID with the (unique) handle. */
	if (!set_policy_samr_sid(get_global_hnd_cache(), pol, &sid))
	{
		/* close the policy in case we can't associate a group SID */
		close_policy_hnd(get_global_hnd_cache(), pol);
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 _samr_close
 ********************************************************************/
uint32 _samr_close(POLICY_HND *hnd)
{
	/* set up the SAMR unknown_1 response */

	/* close the policy handle */
	if (close_policy_hnd(get_global_hnd_cache(), hnd))
	{
		bzero(hnd, sizeof(*hnd));
		return NT_STATUS_NOPROBLEMO;
	}
	return NT_STATUS_OBJECT_NAME_INVALID;
}

/*******************************************************************
 samr_reply_open_domain
 ********************************************************************/
uint32 _samr_open_domain(const POLICY_HND *connect_pol,
				uint32 ace_perms,
				const DOM_SID *sid,
				POLICY_HND *domain_pol)
{
	/* find the connection policy handle. */
	if (find_policy_by_hnd(get_global_hnd_cache(), connect_pol) == -1)
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* get a (unique) handle.  open a policy on it. */
	if (!open_policy_hnd_link(get_global_hnd_cache(),
		connect_pol, domain_pol, ace_perms))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	/* associate the domain SID with the (unique) handle. */
	if (!set_policy_samr_sid(get_global_hnd_cache(), domain_pol, sid))
	{
		close_policy_hnd(get_global_hnd_cache(), domain_pol);
		return NT_STATUS_ACCESS_DENIED;
	}

	DEBUG(5,("_samr_open_domain: %d\n", __LINE__));

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_reply_get_usrdom_pwinfo
 ********************************************************************/
uint32 _samr_get_usrdom_pwinfo(const POLICY_HND *user_pol,
				uint32 *unknown_0,
				uint32 *unknown_1)
{
	uint32 rid;
	DOM_SID sid;

	/* find the policy handle.  open a policy on it. */
	if (!get_policy_samr_sid(get_global_hnd_cache(), user_pol, &sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	sid_split_rid(&sid, &rid);

	*unknown_0 = 0x00150000;
	*unknown_1 = 0x00000000;

	DEBUG(5,("samr_get_usrdom_pwinfo: %d\n", __LINE__));

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_reply_query_sec_obj
 ********************************************************************/
uint32 _samr_query_sec_obj(const POLICY_HND *user_pol, SEC_DESC_BUF *buf)
{
	DOM_SID usr_sid;

	/* find the policy handle.  open a policy on it. */
	if (!get_policy_samr_sid(get_global_hnd_cache(), user_pol, &usr_sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	SMB_ASSERT_ARRAY(usr_sid.sub_auths, usr_sid.num_auths+1);

#if 0
	/* maybe need another 1 or 2 (S-1-5-0x20-0x220 and S-1-5-20-0x224) */
	/* these two are DOMAIN_ADMIN and DOMAIN_ACCT_OP group RIDs */
	make_dom_sid3(&sid_stuff->sid[0], 0x035b, 0x0002, &global_sid_S_1_1);
	make_dom_sid3(&sid_stuff->sid[1], 0x0044, 0x0002, &usr_sid);

	make_sam_sid_stuff(sid_stuff, 
				0x0001, 0x8004,
				0x00000014, 0x0002, 0x0070,
				2);

#endif
	DEBUG(5,("samr_query_sec_obj: %d\n", __LINE__));

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
makes a SAM_ENTRY / UNISTR2* structure.
********************************************************************/
static void make_samr_dom_users(SAM_ENTRY **sam, UNISTR2 **uni_acct_name,
		uint32 num_sam_entries,
		SAM_USER_INFO_21 pass[MAX_SAM_ENTRIES])
{
	uint32 i;

	*sam = NULL;
	*uni_acct_name = NULL;

	if (num_sam_entries == 0)
	{
		return;
	}

	(*sam) = (SAM_ENTRY*)Realloc(NULL, num_sam_entries * sizeof((*sam)[0]));
	(*uni_acct_name) = (UNISTR2*)Realloc(NULL, num_sam_entries * sizeof((*uni_acct_name)[0]));

	if ((*sam) == NULL || (*uni_acct_name) == NULL)
	{
		DEBUG(0,("NULL pointers in SAMR_R_QUERY_DISPINFO\n"));
		return;
	}

	for (i = 0; i < num_sam_entries; i++)
	{
		make_sam_entry(&((*sam)[i]),
			       pass[i].uni_user_name.uni_str_len,
			       pass[i].user_rid);

		copy_unistr2(&((*uni_acct_name)[i]), &(pass[i].uni_user_name));
	}
}

/*******************************************************************
 samr_reply_enum_dom_users
 ********************************************************************/
uint32 _samr_enum_dom_users(  const POLICY_HND *pol, uint32 *start_idx, 
				uint16 acb_mask, uint16 unk_1, uint32 size,
				SAM_ENTRY **sam,
				UNISTR2 **uni_acct_name,
				uint32 *num_sam_users)
{
	SAM_USER_INFO_21 pass[MAX_SAM_ENTRIES];
	int total_entries;
	BOOL ret;

	/* find the policy handle.  open a policy on it. */
	if (find_policy_by_hnd(get_global_hnd_cache(), pol) == -1)
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	DEBUG(5,("samr_reply_enum_dom_users: %d\n", __LINE__));

	become_root(True);
	ret = get_sampwd_entries(pass, (*start_idx), &total_entries,
	                   num_sam_users,
	                   MAX_SAM_ENTRIES, acb_mask);
	unbecome_root(True);
	if (!ret)
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	(*start_idx) += (*num_sam_users);
	make_samr_dom_users(sam, uni_acct_name, (*num_sam_users), pass);

	DEBUG(5,("samr_enum_dom_users: %d\n", __LINE__));

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

	/* find the policy handle.  open a policy on it. */
	if (!get_policy_samr_sid(get_global_hnd_cache(), pol, &group_sid))
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

	if (!add_group_member(group_rid, rid))
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

	/* find the policy handle.  open a policy on it. */
	if (!get_policy_samr_sid(get_global_hnd_cache(), pol, &group_sid))
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

	if (!del_group_member(group_rid, rid))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_reply_add_aliasmem
 ********************************************************************/
uint32 _samr_add_aliasmem(const POLICY_HND *alias_pol, const DOM_SID *sid)
{
	DOM_SID alias_sid;
	uint32 alias_rid;
	fstring alias_sid_str;

	/* find the policy handle.  open a policy on it. */
	if (!get_policy_samr_sid(get_global_hnd_cache(), alias_pol, &alias_sid))
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

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_reply_del_aliasmem
 ********************************************************************/
uint32 _samr_del_aliasmem(const POLICY_HND *alias_pol, const DOM_SID *sid)
{
	DOM_SID alias_sid;
	uint32 alias_rid;
	fstring alias_sid_str;

	/* find the policy handle.  open a policy on it. */
	if (!get_policy_samr_sid(get_global_hnd_cache(), alias_pol, &alias_sid))
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

	return NT_STATUS_NOPROBLEMO;
}

/******************************************************************
makes a SAMR_R_ENUM_DOMAINS structure.
********************************************************************/
static void make_enum_domains(SAM_ENTRY **sam, UNISTR2 **uni_dom_name,
		uint32 num_sam_entries, char **doms)
{
	uint32 i;

	DEBUG(5,("make_enum_domains\n"));

	(*sam) = NULL;
	(*uni_dom_name) = NULL;

	if (num_sam_entries == 0)
	{
		return;
	}

	(*sam) = (SAM_ENTRY*)Realloc(NULL, num_sam_entries * sizeof((*sam)[0]));
	(*uni_dom_name) = (UNISTR2*)Realloc(NULL, num_sam_entries * sizeof((*uni_dom_name)[0]));

	if ((*sam) == NULL || (*uni_dom_name) == NULL)
	{
		DEBUG(0,("NULL pointers in make_enum_domains\n"));
		return;
	}

	for (i = 0; i < num_sam_entries; i++)
	{
		int len = doms[i] != NULL ? strlen(doms[i]) : 0;

		make_sam_entry(&((*sam)[i]), len, 0);
		make_unistr2(&((*uni_dom_name)[i]), doms[i], len);
	}
}

/*******************************************************************
 samr_reply_enum_domains
 ********************************************************************/
uint32 _samr_enum_domains(const POLICY_HND *pol, uint32 *start_idx, 
				uint32 size,
				SAM_ENTRY **sam,
				UNISTR2 **uni_acct_name,
				uint32 *num_sam_users)
{
	char  **doms = NULL;
	uint32 num_entries = 0;

	/* find the connection policy handle. */
	if (find_policy_by_hnd(get_global_hnd_cache(), pol) == -1)
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	DEBUG(5,("samr_reply_enum_domains:\n"));

	if (!enumdomains(&doms, &num_entries))
	{
		return NT_STATUS_NO_MEMORY;
	}

	make_enum_domains(sam, uni_acct_name, num_entries, doms);

	(*start_idx) += num_entries;
	(*num_sam_users) = num_entries;

	free_char_array(num_entries, doms);

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
makes a SAMR_R_ENUM_DOM_GROUPS structure.
********************************************************************/
static void make_samr_dom_groups(SAM_ENTRY **sam, UNISTR2 **uni_grp_name,
		uint32 num_sam_entries, DOMAIN_GRP *grps)
{
	uint32 i;

	DEBUG(5,("make_samr_dom_groups\n"));

	(*sam) = NULL;
	(*uni_grp_name) = NULL;

	if (num_sam_entries == 0)
	{
		return;
	}

	(*sam) = (SAM_ENTRY*)Realloc(NULL, num_sam_entries * sizeof((*sam)[0]));
	(*uni_grp_name) = (UNISTR2*)Realloc(NULL, num_sam_entries * sizeof((*uni_grp_name)[0]));

	if ((*sam) == NULL || (*uni_grp_name) == NULL)
	{
		DEBUG(0,("NULL pointers in SAMR_R_ENUM_DOM_GROUPS\n"));
		return;
	}

	for (i = 0; i < num_sam_entries; i++)
	{
		int len = strlen(grps[i].name);

		make_sam_entry(&((*sam)[i]), len, grps[i].rid);
		make_unistr2(&((*uni_grp_name)[i]), grps[i].name, len);
	}
}

/*******************************************************************
 samr_reply_enum_dom_groups
 ********************************************************************/
uint32 _samr_enum_dom_groups(const POLICY_HND *pol,
				uint32 *start_idx, uint32 size,
				SAM_ENTRY **sam,
				UNISTR2 **uni_acct_name,
				uint32 *num_sam_groups)
{
	DOMAIN_GRP *grps = NULL;
	int num_entries = 0;
	DOM_SID sid;
	fstring sid_str;
	BOOL ret;

	/* find the policy handle.  open a policy on it. */
	if (!get_policy_samr_sid(get_global_hnd_cache(), pol, &sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	sid_to_string(sid_str, &sid);

	DEBUG(5,("samr_reply_enum_dom_groups: sid %s\n", sid_str));

	if (!sid_equal(&sid, &global_sam_sid))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	become_root(True);
	ret = enumdomgroups(&grps, &num_entries);
	unbecome_root(True);
	if (!ret)
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	(*start_idx) += num_entries;
	(*num_sam_groups) = num_entries;

	make_samr_dom_groups(sam, uni_acct_name, num_entries, grps);

	safe_free(grps);

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
makes a SAMR_R_ENUM_DOM_ALIASES structure.
********************************************************************/
static void make_samr_dom_aliases(SAM_ENTRY **sam, UNISTR2 **uni_grp_name,
		uint32 num_sam_entries, LOCAL_GRP *alss)
{
	uint32 i;

	DEBUG(5,("make_samr_r_enum_dom_aliases\n"));

	(*sam) = NULL;
	(*uni_grp_name) = NULL;

	if (num_sam_entries == 0)
	{
		return;
	}

	(*sam) = (SAM_ENTRY*)Realloc(NULL, num_sam_entries * sizeof((*sam)[0]));
	(*uni_grp_name) = (UNISTR2*)Realloc(NULL, num_sam_entries * sizeof((*uni_grp_name)[0]));

	if ((*sam) == NULL || (*uni_grp_name) == NULL)
	{
		DEBUG(0,("NULL pointers in SAMR_R_ENUM_DOM_ALIASES\n"));
		return;
	}

	for (i = 0; i < num_sam_entries; i++)
	{
		int len = strlen(alss[i].name);

		make_sam_entry(&((*sam)[i]), len, alss[i].rid); 
		make_unistr2(&((*uni_grp_name)[i]), alss[i].name, len);
	}
}

/*******************************************************************
 samr_reply_enum_dom_aliases
 ********************************************************************/
uint32 _samr_enum_dom_aliases(const POLICY_HND *pol,
					uint32 *start_idx, uint32 size,
					SAM_ENTRY **sam,
					UNISTR2 **uni_acct_name,
					uint32 *num_sam_aliases)
{
	LOCAL_GRP *alss = NULL;
	int num_entries = 0;
	DOM_SID sid;
	fstring sid_str;

	/* find the policy handle.  open a policy on it. */
	if (!get_policy_samr_sid(get_global_hnd_cache(), pol, &sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	sid_to_string(sid_str, &sid);

	DEBUG(5,("samr_reply_enum_dom_aliases: sid %s\n", sid_str));

	/* well-known aliases */
	if (sid_equal(&sid, &global_sid_S_1_5_20))
	{
		BOOL ret;
		/* builtin aliases */

		become_root(True);
		ret = enumdombuiltins(&alss, &num_entries);
		unbecome_root(True);
		if (!ret)
		{
			return NT_STATUS_ACCESS_DENIED;
		}
	}
	else if (sid_equal(&sid, &global_sam_sid))
	{
		BOOL ret;
		/* local aliases */

		become_root(True);
		ret = enumdomaliases(&alss, &num_entries);
		unbecome_root(True);
		if (!ret)
		{
			return NT_STATUS_ACCESS_DENIED;
		}
	}
		
	(*start_idx) += num_entries;
	(*num_sam_aliases) = num_entries;

	make_samr_dom_aliases(sam, uni_acct_name, num_entries, alss);

	safe_free(alss);

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_reply_query_dispinfo
 ********************************************************************/
uint32 _samr_query_dispinfo(  const POLICY_HND *domain_pol, uint16 level,
					uint32 start_idx,
					uint32 max_entries,
					uint32 max_size,
					uint32 *data_size,
					uint32 *num_entries,
					SAM_DISPINFO_CTR *ctr)
{
	SAM_USER_INFO_21 pass[MAX_SAM_ENTRIES];
	DOMAIN_GRP *grps = NULL;
	DOMAIN_GRP *sam_grps = NULL;
	uint16 acb_mask = ACB_NORMAL;
	int num_sam_entries = 0;
	int total_entries = 0;

	DEBUG(5,("samr_reply_query_dispinfo: %d\n", __LINE__));

	(*num_entries) = 0;
	(*data_size) = 0;

	/* find the policy handle.  open a policy on it. */
	if (find_policy_by_hnd(get_global_hnd_cache(), domain_pol) == -1)
	{
		DEBUG(5,("samr_reply_query_dispinfo: invalid handle\n"));
		return NT_STATUS_INVALID_HANDLE;
	}

	/* Get what we need from the password database */
	switch (level)
	{
		case 0x2:
		{
			acb_mask = ACB_WSTRUST;
			/* Fall through */
		}
		case 0x1:
		case 0x4:
		{
			BOOL ret;

			become_root(True);
			ret = get_sampwd_entries(pass, start_idx,
				      &total_entries, &num_sam_entries,
				      MAX_SAM_ENTRIES, acb_mask);
			unbecome_root(True);
			if (!ret)
			{
				DEBUG(5,("get_sampwd_entries: failed\n"));
				return NT_STATUS_ACCESS_DENIED;
			}
			break;
		}
		case 0x3:
		case 0x5:
		{
			BOOL ret;

			become_root(True);
			ret = enumdomgroups(&sam_grps, &num_sam_entries);
			unbecome_root(True);
			if (!ret)
			{
				return NT_STATUS_ACCESS_DENIED;
			}

			if (start_idx < num_sam_entries) {
				grps = sam_grps + start_idx;
				num_sam_entries -= start_idx;
			} else {
				num_sam_entries = 0;
			}
			break;
		}
	}


	(*num_entries) = num_sam_entries;

	if ((*num_entries) > max_entries)
	{
		(*num_entries) = max_entries;
	}

	if ((*num_entries) > MAX_SAM_ENTRIES)
	{
		(*num_entries) = MAX_SAM_ENTRIES;
		DEBUG(5,("limiting number of entries to %d\n", 
			 (*num_entries)));
	}

	(*data_size) = max_size;

	/* Now create reply structure */
	switch (level)
	{
		case 0x1:
		{
			ctr->sam.info1 = malloc(sizeof(SAM_DISPINFO_1));
			make_sam_dispinfo_1(ctr->sam.info1,
					    num_entries, data_size,
					    start_idx, pass);
			break;
		}
		case 0x2:
		{
			ctr->sam.info2 = malloc(sizeof(SAM_DISPINFO_2));
			make_sam_dispinfo_2(ctr->sam.info2,
					    num_entries, data_size,
					    start_idx, pass);
			break;
		}
		case 0x3:
		{
			ctr->sam.info3 = malloc(sizeof(SAM_DISPINFO_3));
			make_sam_dispinfo_3(ctr->sam.info3,
					    num_entries, data_size,
					    start_idx, grps);
			break;
		}
		case 0x4:
		{
			ctr->sam.info4 = malloc(sizeof(SAM_DISPINFO_4));
			make_sam_dispinfo_4(ctr->sam.info4,
					    num_entries, data_size,
					    start_idx, pass);
			break;
		}
		case 0x5:
		{
			ctr->sam.info5 = malloc(sizeof(SAM_DISPINFO_5));
			make_sam_dispinfo_5(ctr->sam.info5,
					    num_entries, data_size,
					    start_idx, grps);
			break;
		}
		default:
		{
			ctr->sam.info = NULL;
			safe_free(sam_grps);
			return NT_STATUS_INVALID_INFO_CLASS;
		}
	}

	DEBUG(5,("samr_reply_query_dispinfo: %d\n", __LINE__));

	safe_free(sam_grps);

	if ((*num_entries) < num_sam_entries)
	{
		return STATUS_MORE_ENTRIES;
	}

	return NT_STATUS_NOPROBLEMO;
}


/*******************************************************************
 samr_reply_delete_dom_user
 ********************************************************************/
uint32 _samr_delete_dom_user(POLICY_HND *user_pol)
{
	DEBUG(0,("samr_delete_dom_user: not implemented\n"));
	return NT_STATUS_ACCESS_DENIED;
}


/*******************************************************************
 samr_reply_delete_dom_group
 ********************************************************************/
uint32 _samr_delete_dom_group(POLICY_HND *group_pol)
{
	DOM_SID group_sid;
	uint32 group_rid;
	fstring group_sid_str;

	DEBUG(5,("samr_delete_dom_group: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!get_policy_samr_sid(get_global_hnd_cache(), group_pol, &group_sid))
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

	if (!del_group_entry(group_rid))
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
	if (!get_policy_samr_sid(get_global_hnd_cache(), group_pol, &group_sid))
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
	grp = getgrouprid(group_rid, &mem_grp, &num_rids);
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
 samr_set_groupinfo
 ********************************************************************/
uint32 _samr_set_groupinfo(const POLICY_HND *pol,
				uint16 switch_level,
				const GROUP_INFO_CTR* ctr)
{
	return NT_STATUS_ACCESS_DENIED;
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

	return NT_STATUS_NOPROBLEMO;
}


/*******************************************************************
 samr_reply_query_useraliases
 ********************************************************************/
uint32 _samr_query_useraliases(const POLICY_HND *pol,
				const uint32 *ptr_sid, const DOM_SID2 *sid,
				uint32 *num_aliases, uint32 **rid)
{
	LOCAL_GRP *mem_grp = NULL;
	int num_rids = 0;
	struct sam_passwd *sam_pass;
	DOM_SID usr_sid;
	DOM_SID dom_sid;
	uint32 user_rid;
	fstring sam_sid_str;
	fstring dom_sid_str;
	fstring usr_sid_str;

	DEBUG(5,("samr_query_useraliases: %d\n", __LINE__));

	(*rid) = NULL;
	(*num_aliases) = 0;

	/* find the policy handle.  open a policy on it. */
	if (!get_policy_samr_sid(get_global_hnd_cache(), pol, &dom_sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}
	sid_to_string(dom_sid_str, &dom_sid       );
	sid_to_string(sam_sid_str, &global_sam_sid);

	usr_sid = sid[0].sid;
	sid_split_rid(&usr_sid, &user_rid);
	sid_to_string(usr_sid_str, &usr_sid);

	/* find the user account */
	become_root(True);
	sam_pass = getsam21pwrid(user_rid);
	unbecome_root(True);

	if (sam_pass == NULL)
	{
		return NT_STATUS_NO_SUCH_USER;
	}

	DEBUG(10,("sid is %s\n", dom_sid_str));

	if (sid_equal(&dom_sid, &global_sid_S_1_5_20))
	{
		BOOL ret;
		DEBUG(10,("lookup on S-1-5-20\n"));

		become_root(True);
		ret = getuserbuiltinntnam(sam_pass->nt_name, &mem_grp,
		                          &num_rids);
		unbecome_root(True);

		if (!ret)
		{
			return NT_STATUS_ACCESS_DENIED;
		}
	}
	else if (sid_equal(&dom_sid, &usr_sid))
	{
		BOOL ret;
		DEBUG(10,("lookup on Domain SID\n"));

		become_root(True);
		ret = getuseraliasntnam(sam_pass->nt_name, &mem_grp,
		                          &num_rids);
		unbecome_root(True);

		if (!ret)
		{
			return NT_STATUS_ACCESS_DENIED;
		}
	}
	else
	{
		return NT_STATUS_NO_SUCH_USER;
	}

	if (num_rids > 0)
	{
		(*rid) = malloc(num_rids * sizeof(uint32));
		if (mem_grp != NULL && (*rid) != NULL)
		{
			int i;
			for (i = 0; i < num_rids; i++)
			{
				(*rid)[i] = mem_grp[i].rid;
			}
		}
	}

	(*num_aliases) = num_rids;
	safe_free(mem_grp);

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_reply_delete_dom_alias
 ********************************************************************/
uint32 _samr_delete_dom_alias(POLICY_HND *alias_pol)
{
	DOM_SID alias_sid;
	uint32 alias_rid;
	fstring alias_sid_str;

	DEBUG(5,("samr_delete_dom_alias: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!get_policy_samr_sid(get_global_hnd_cache(), alias_pol, &alias_sid))
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
	if (!get_policy_samr_sid(get_global_hnd_cache(), alias_pol, &alias_sid))
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

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_reply_lookup_names
 ********************************************************************/
uint32 _samr_lookup_names(const POLICY_HND *pol,
				
			uint32 num_names1,
			uint32 flags,
			uint32 ptr,
			const UNISTR2 *uni_name,

			uint32 *num_rids1,
			uint32 rid[MAX_SAM_ENTRIES],
			uint32 *num_types1,
			uint32 type[MAX_SAM_ENTRIES])
{
	int i;
	int num_rids = num_names1;
	DOM_SID pol_sid;
	fstring tmp;
	BOOL found_one = False;

	DEBUG(5,("samr_lookup_names: %d\n", __LINE__));

	if (!get_policy_samr_sid(get_global_hnd_cache(), pol, &pol_sid))
	{
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	sid_to_string(tmp, &pol_sid);
	DEBUG(5,("pol_sid: %s\n", tmp));

	if (num_rids > MAX_SAM_ENTRIES)
	{
		num_rids = MAX_SAM_ENTRIES;
		DEBUG(5,("samr_lookup_names: truncating entries to %d\n", num_rids));
	}

	for (i = 0; i < num_rids; i++)
	{
		DOM_SID sid;
		fstring name;
		uint32 status1;
		unistr2_to_ascii(name, &uni_name[i], sizeof(name)-1);

		status1 = lookup_name(name, &sid, &(type[i]));
		if (status1 == 0x0)
		{
			found_one = True;
			sid_split_rid(&sid, &rid[i]);
		}
		if ((status1 != 0x0) || !sid_equal(&pol_sid, &sid))
		{
			rid [i] = 0xffffffff;
			type[i] = SID_NAME_UNKNOWN;
		}

		sid_to_string(tmp, &sid);
		DEBUG(10,("name: %s sid: %s rid: %x type: %d\n",
			name, tmp, rid[i], type[i]));
	}

	if (!found_one)
	{
		return NT_STATUS_NONE_MAPPED;
	}

	(*num_rids1) = num_rids;
	(*num_types1) = num_rids;

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_reply_chgpasswd_user
 ********************************************************************/
uint32 _samr_chgpasswd_user( const UNISTR2 *uni_dest_host,
				const UNISTR2 *uni_user_name,
				const char nt_newpass[516],
				const uchar nt_oldhash[16],
				const char lm_newpass[516],
				const uchar lm_oldhash[16])
{
	fstring user_name;
	fstring wks;

	unistr2_to_ascii(user_name, uni_user_name, sizeof(user_name)-1);
	unistr2_to_ascii(wks, uni_dest_host, sizeof(wks)-1);

	DEBUG(5,("samr_chgpasswd_user: user: %s wks: %s\n", user_name, wks));

	if (!pass_oem_change(user_name,
	                     lm_newpass, lm_oldhash,
	                     nt_newpass, nt_oldhash))
	{
		return NT_STATUS_WRONG_PASSWORD;
	}

	return NT_STATUS_NOPROBLEMO;
}


/*******************************************************************
 samr_reply_get_dom_pwinfo
 ********************************************************************/
uint32 _samr_get_dom_pwinfo(const UNISTR2 *uni_srv_name,
				uint16 *unk_0, uint16 *unk_1, uint16 *unk_2)
{
	/* absolutely no idea what to do, here */
	*unk_0 = 0;
	*unk_1 = 0;
	*unk_2 = 0;

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
makes a SAMR_R_LOOKUP_RIDS structure.
********************************************************************/
static BOOL make_samr_lookup_rids( uint32 num_names, char *const *name, 
				UNIHDR **hdr_name, UNISTR2** uni_name)
{
	uint32 i;
	if (name == NULL) return False;

	*uni_name = NULL;
	*hdr_name = NULL;

	if (num_names != 0)
	{
		(*hdr_name) = (UNIHDR*)malloc(num_names * sizeof((*hdr_name)[0]));
		if ((*hdr_name) == NULL)
		{
			return False;
		}
		(*uni_name) = (UNISTR2*)malloc(num_names * sizeof((*uni_name)[0]));
		if ((*uni_name) == NULL)
		{
			free(*uni_name);
			*uni_name = NULL;
			return False;
		}
	}

	for (i = 0; i < num_names; i++)
	{
		int len = name[i] != NULL ? strlen(name[i]) : 0;
		DEBUG(10,("name[%d]:%s\n", i, name[i]));
		make_uni_hdr(&((*hdr_name)[i]), len);
		make_unistr2(&((*uni_name)[i]), name[i], len);
	}

	return True;
}

/*******************************************************************
 samr_reply_lookup_rids
 ********************************************************************/
uint32 _samr_lookup_rids(const POLICY_HND *pol,
				uint32 num_rids, uint32 flags,
				const uint32 *rids,
				uint32 *num_names,
				UNIHDR **hdr_name, UNISTR2** uni_name,
				uint32 **types)
{
	char **grp_names = NULL;
	DOM_SID pol_sid;
	BOOL found_one = False;
		int i;

	DEBUG(5,("samr_lookup_rids: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (find_policy_by_hnd(get_global_hnd_cache(), pol) == -1)
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	if (!get_policy_samr_sid(get_global_hnd_cache(), pol, &pol_sid))
	{
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	(*types) = malloc(num_rids * sizeof(**types));

	if ((*types) == NULL)
	{
		return NT_STATUS_NO_MEMORY;
	}

	grp_names = g_new(char *, num_rids);
	if (grp_names == NULL)
	{
		free(*types);
		(*types) = NULL;
		return NT_STATUS_NO_MEMORY;
	}


	for (i = 0; i < num_rids; i++)
	{
		uint32 status1;
		DOM_SID sid;
		fstring tmpname;

		sid_copy(&sid, &pol_sid);
		sid_append_rid(&sid, rids[i]);

		status1 = lookup_sid(&sid, tmpname, &(*types)[i]);

		if (status1 == 0)
		{
			found_one = True;
			grp_names[i] = strdup(tmpname);
		}
		else
		{
			(*types)[i] = SID_NAME_UNKNOWN;
			grp_names[i] = NULL;
		}
	}

	if (!found_one)
	{
		return NT_STATUS_NONE_MAPPED;
	}

	(*num_names) = num_rids;
	make_samr_lookup_rids(num_rids, grp_names, hdr_name, uni_name);

	free_char_array(num_rids, grp_names);
	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_reply_open_user
 ********************************************************************/
uint32 _samr_open_user(const POLICY_HND *domain_pol,
					uint32 access_mask, uint32 user_rid, 
					POLICY_HND *user_pol)
{
	struct sam_passwd *sam_pass;
	DOM_SID sid;

	/* set up the SAMR open_user response */
	bzero(user_pol->data, POL_HND_SIZE);

	/* find the policy handle.  open a policy on it. */
	if (!get_policy_samr_sid(get_global_hnd_cache(), domain_pol, &sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* this should not be hard-coded like this */
	if (!sid_equal(&sid, &global_sam_sid))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	become_root(True);
	sam_pass = getsam21pwrid(user_rid);
	unbecome_root(True);

	/* check that the RID exists in our domain. */
	if (sam_pass == NULL)
	{
		close_policy_hnd(get_global_hnd_cache(), user_pol);
		return NT_STATUS_NO_SUCH_USER;
	}

	return samr_open_by_sid(domain_pol, &sid, user_pol,
	                        access_mask, user_rid);
}


/*************************************************************************
 get_user_info_10
 *************************************************************************/
static BOOL get_user_info_10(SAM_USER_INFO_10 *id10, uint32 user_rid)
{
	struct sam_passwd *sam_pass;

	become_root(True);
	sam_pass = getsam21pwrid(user_rid);
	unbecome_root(True);

	if (sam_pass == NULL)
	{
		DEBUG(4,("User 0x%x not found\n", user_rid));
		return False;
	}

	DEBUG(3,("User:[%s]\n", sam_pass->nt_name));

	make_sam_user_info10(id10, sam_pass->acct_ctrl); 

	return True;
}

/*************************************************************************
 get_user_info_21
 *************************************************************************/
static BOOL get_user_info_12(SAM_USER_INFO_12 *id12, uint32 user_rid)
{
	struct sam_passwd *sam_pass;

	become_root(True);
	sam_pass = getsam21pwrid(user_rid);
	unbecome_root(True);

	if (sam_pass == NULL)
	{
		DEBUG(4,("User 0x%x not found\n", user_rid));
		return False;
	}

	DEBUG(3,("User:[%s] %x\n", sam_pass->nt_name, sam_pass->acct_ctrl));

	if (IS_BITS_SET_ALL(sam_pass->acct_ctrl, ACB_DISABLED))
	{
		return False;
	}

	make_sam_user_info12(id12, sam_pass->acct_ctrl,
	                     sam_pass->smb_passwd,
	                     sam_pass->smb_nt_passwd);

	return True;
}

/*************************************************************************
 get_user_info_21
 *************************************************************************/
static BOOL get_user_info_21(SAM_USER_INFO_21 *id21, uint32 user_rid)
{
	struct sam_passwd *sam_pass;
	LOGON_HRS hrs;
	int i;

	become_root(True);
	sam_pass = getsam21pwrid(user_rid);
	unbecome_root(True);

	if (sam_pass == NULL)
	{
		DEBUG(4,("User 0x%x not found\n", user_rid));
		return False;
	}

	DEBUG(3,("User:[%s]\n", sam_pass->nt_name));

	/* create a LOGON_HRS structure */
	hrs.len = sam_pass->hours_len;
	SMB_ASSERT_ARRAY(hrs.hours, hrs.len);
	for (i = 0; i < hrs.len; i++)
	{
		hrs.hours[i] = sam_pass->hours[i];
	}

	make_sam_user_info21A(id21,

			   &sam_pass->logon_time,
			   &sam_pass->logoff_time,
			   &sam_pass->kickoff_time,
			   &sam_pass->pass_last_set_time,
			   &sam_pass->pass_can_change_time,
			   &sam_pass->pass_must_change_time,

			   sam_pass->nt_name, /* user_name */
			   sam_pass->full_name, /* full_name */
			   sam_pass->home_dir, /* home_dir */
			   sam_pass->dir_drive, /* dir_drive */
			   sam_pass->logon_script, /* logon_script */
			   sam_pass->profile_path, /* profile_path */
			   sam_pass->acct_desc, /* description */
			   sam_pass->workstations, /* workstations user can log in from */
			   sam_pass->unknown_str, /* don't know, yet */
			   sam_pass->munged_dial, /* dialin info.  contains dialin path and tel no */

			   sam_pass->user_rid, /* RID user_id */
			   sam_pass->group_rid, /* RID group_id */
	                   sam_pass->acct_ctrl,

	                   sam_pass->unknown_3, /* unknown_3 */
	                   sam_pass->logon_divs, /* divisions per week */
	                   &hrs, /* logon hours */
	                   sam_pass->unknown_5,
	                   sam_pass->unknown_6);

	return True;
}

/*******************************************************************
 samr_reply_query_userinfo
 ********************************************************************/
uint32 _samr_query_userinfo(const POLICY_HND *pol, uint16 switch_value,
				SAM_USERINFO_CTR *ctr)
{
	uint32 rid = 0x0;
	DOM_SID group_sid;

	/* find the policy handle.  open a policy on it. */
	if (!get_policy_samr_sid(get_global_hnd_cache(), pol, &group_sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}
	sid_split_rid(&group_sid, &rid);

	DEBUG(5,("samr_reply_query_userinfo: rid:0x%x\n", rid));

	/* ok!  user info levels (lots: see MSDEV help), off we go... */
	ctr->switch_value = switch_value;
	switch (switch_value)
	{
		case 0x10:
		{
			ctr->info.id = (SAM_USER_INFO_10*)Realloc(NULL,
					 sizeof(*ctr->info.id10));
			if (ctr->info.id == NULL)
			{
				return NT_STATUS_NO_MEMORY;
			}
			if (!get_user_info_10(ctr->info.id10, rid))
			{
				return NT_STATUS_NO_SUCH_USER;
			}
			break;
		}
#if 0
/* whoops - got this wrong.  i think.  or don't understand what's happening. */
		case 0x11:
		{
			NTTIME expire;
			info = (void*)&id11;
			
			expire.low  = 0xffffffff;
			expire.high = 0x7fffffff;

			ctr->info.id = (SAM_USER_INFO_11*)Realloc(NULL,
					 sizeof(*ctr->info.id11));
			make_sam_user_info11(ctr->info.id11, &expire,
					     "BROOKFIELDS$", /* name */
					     0x03ef, /* user rid */
					     0x201, /* group rid */
					     0x0080); /* acb info */

			break;
		}
#endif
		case 0x12:
		{
			ctr->info.id = (SAM_USER_INFO_12*)Realloc(NULL,
					 sizeof(*ctr->info.id12));
			if (ctr->info.id == NULL)
			{
				return NT_STATUS_NO_MEMORY;
			}
			if (!get_user_info_12(ctr->info.id12, rid))
			{
				return NT_STATUS_NO_SUCH_USER;
			}
			break;
		}
		case 21:
		{
			ctr->info.id = (SAM_USER_INFO_21*)Realloc(NULL,
					 sizeof(*ctr->info.id21));
			if (ctr->info.id == NULL)
			{
				return NT_STATUS_NO_MEMORY;
			}
			if (!get_user_info_21(ctr->info.id21, rid))
			{
				return NT_STATUS_NO_SUCH_USER;
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
 set_user_info_12
 ********************************************************************/
static BOOL set_user_info_12(const SAM_USER_INFO_12 *id12, uint32 rid)
{
	struct sam_passwd *pwd = getsam21pwrid(rid);
	struct sam_passwd new_pwd;
	static uchar nt_hash[16];
	static uchar lm_hash[16];

	if (pwd == NULL)
	{
		return False;
	}

	pwdb_init_sam(&new_pwd);
	copy_sam_passwd(&new_pwd, pwd);

	memcpy(nt_hash, id12->nt_pwd, sizeof(nt_hash));
	memcpy(lm_hash, id12->lm_pwd, sizeof(lm_hash));

	new_pwd.smb_passwd    = lm_hash;
	new_pwd.smb_nt_passwd = nt_hash;

	return mod_sam21pwd_entry(&new_pwd, True);
}

/*******************************************************************
 set_user_info_24
 ********************************************************************/
static BOOL set_user_info_24(const SAM_USER_INFO_24 *id24, uint32 rid)
{
	struct sam_passwd *pwd = getsam21pwrid(rid);
	struct sam_passwd new_pwd;
	static uchar nt_hash[16];
	static uchar lm_hash[16];
	UNISTR2 new_pw;
	uint32 len;

	if (pwd == NULL)
	{
		return False;
	}

	pwdb_init_sam(&new_pwd);
	copy_sam_passwd(&new_pwd, pwd);

	if (!decode_pw_buffer(id24->pass, (char *)new_pw.buffer, 256, &len))
	{
		return False;
	}

	new_pw.uni_max_len = len / 2;
	new_pw.uni_str_len = len / 2;

	nt_lm_owf_genW(&new_pw, nt_hash, lm_hash);

	new_pwd.smb_passwd    = lm_hash;
	new_pwd.smb_nt_passwd = nt_hash;

	return mod_sam21pwd_entry(&new_pwd, True);
}

/*******************************************************************
 set_user_info_23
 ********************************************************************/
static BOOL set_user_info_23(const SAM_USER_INFO_23 *id23, uint32 rid)
{
	struct sam_passwd *pwd = getsam21pwrid(rid);
	struct sam_passwd new_pwd;
	static uchar nt_hash[16];
	static uchar lm_hash[16];
	UNISTR2 new_pw;
	uint32 len;

	if (id23 == NULL)
	{
		DEBUG(5, ("set_user_info_23: NULL id23\n"));
		return False;
	}
	if (pwd == NULL)
	{
		return False;
	}

	pwdb_init_sam(&new_pwd);
	copy_sam_passwd(&new_pwd, pwd);
	copy_id23_to_sam_passwd(&new_pwd, id23);

	if (!decode_pw_buffer(id23->pass, (char*)new_pw.buffer, 256, &len))
	{
		return False;
	}

	new_pw.uni_max_len = len / 2;
	new_pw.uni_str_len = len / 2;

	nt_lm_owf_genW(&new_pw, nt_hash, lm_hash);

	new_pwd.smb_passwd    = lm_hash;
	new_pwd.smb_nt_passwd = nt_hash;

	return mod_sam21pwd_entry(&new_pwd, True);
}

/*******************************************************************
 samr_reply_set_userinfo
 ********************************************************************/
uint32 _samr_set_userinfo(const POLICY_HND *pol, uint16 switch_value,
				SAM_USERINFO_CTR *ctr)
{
	uchar user_sess_key[16];
	uint32 rid = 0x0;
	DOM_SID sid;

	DEBUG(5,("samr_reply_set_userinfo: %d\n", __LINE__));

	/* search for the handle */
	if (find_policy_by_hnd(get_global_hnd_cache(), pol) == -1)
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	if (!pol_get_usr_sesskey(get_global_hnd_cache(), pol, user_sess_key))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* find the policy handle.  open a policy on it. */
	if (!get_policy_samr_sid(get_global_hnd_cache(), pol, &sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	sid_split_rid(&sid, &rid);

	DEBUG(5,("samr_reply_set_userinfo: rid:0x%x\n", rid));

	if (ctr == NULL)
	{
		DEBUG(5,("samr_reply_set_userinfo: NULL info level\n"));
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	/* ok!  user info levels (lots: see MSDEV help), off we go... */
	switch (switch_value)
	{
		case 0x12:
		{
			SAM_USER_INFO_12 *id12 = ctr->info.id12;
			if (!set_user_info_12(id12, rid))
			{
				return NT_STATUS_ACCESS_DENIED;
			}
			break;
		}

		case 24:
		{
			SAM_USER_INFO_24 *id24 = ctr->info.id24;
			SamOEMhash(id24->pass, user_sess_key, True);
			if (!set_user_info_24(id24, rid))
			{
				return NT_STATUS_ACCESS_DENIED;
			}
			break;
		}

		case 23:
		{
			SAM_USER_INFO_23 *id23 = ctr->info.id23;
			SamOEMhash(id23->pass, user_sess_key, 1);
			dump_data_pw("pass buff:\n", id23->pass, sizeof(id23->pass));
			dbgflush();

			if (!set_user_info_23(id23, rid))
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
 set_user_info_10
 ********************************************************************/
static BOOL set_user_info_10(const SAM_USER_INFO_10 *id10, uint32 rid)
{
	struct sam_passwd *pwd = getsam21pwrid(rid);
	struct sam_passwd new_pwd;

	if (id10 == NULL)
	{
		DEBUG(5, ("set_user_info_10: NULL id10\n"));
		return False;
	}
	if (pwd == NULL)
	{
		return False;
	}

	copy_sam_passwd(&new_pwd, pwd);

	new_pwd.acct_ctrl = id10->acb_info;

	return mod_sam21pwd_entry(&new_pwd, True);
}

/*******************************************************************
 samr_reply_set_userinfo2
 ********************************************************************/
uint32 _samr_set_userinfo2(const POLICY_HND *pol, uint16 switch_value,
				SAM_USERINFO_CTR *ctr)
{
	DOM_SID sid;
	uint32 rid = 0x0;

	DEBUG(5,("samr_reply_set_userinfo2: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!get_policy_samr_sid(get_global_hnd_cache(), pol, &sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	sid_split_rid(&sid, &rid);

	DEBUG(5,("samr_reply_set_userinfo2: rid:0x%x\n", rid));

	if (ctr == NULL)
	{
		DEBUG(5,("samr_reply_set_userinfo2: NULL info level\n"));
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	ctr->switch_value = switch_value;

	/* ok!  user info levels (lots: see MSDEV help), off we go... */
	switch (switch_value)
	{
		case 16:
		{
			SAM_USER_INFO_10 *id10 = ctr->info.id10;
			if (!set_user_info_10(id10, rid))
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
 samr_reply_query_usergroups
 ********************************************************************/
uint32 _samr_query_usergroups(const POLICY_HND *pol,
				uint32 *num_groups,
				DOM_GID **gids)
{
	DOMAIN_GRP *mem_grp = NULL;
	struct sam_passwd *sam_pass;
	DOM_SID sid;
	uint32 rid;
	BOOL ret;

	DEBUG(5,("samr_query_usergroups: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!get_policy_samr_sid(get_global_hnd_cache(), pol, &sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	sid_split_rid(&sid, &rid);

	become_root(True);
	sam_pass = getsam21pwrid(rid);
	unbecome_root(True);

	if (sam_pass == NULL)
	{
		return NT_STATUS_NO_SUCH_USER;
	}

	become_root(True);
	ret = getusergroupsntnam(sam_pass->nt_name, &mem_grp, num_groups);
	unbecome_root(True);

	if (!ret)
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	(*gids) = NULL;
	(*num_groups) = make_dom_gids(mem_grp, *num_groups, gids);

	if (mem_grp != NULL)
	{
		free(mem_grp);
	}

	return NT_STATUS_NOPROBLEMO;
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

	bzero(alias_pol, POL_HND_SIZE);

	/* find the policy handle.  open a policy on it. */
	if (find_policy_by_hnd(get_global_hnd_cache(), domain_pol) == -1)
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* find the domain sid */
	if (!get_policy_samr_sid(get_global_hnd_cache(), domain_pol, &dom_sid))
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
	status = samr_open_by_sid(domain_pol, &dom_sid, alias_pol,
	                          access_mask, grp.rid);

	if (status != 0x0)
	{
		return status;
	}

	if (!add_alias_entry(&grp))
	{
		return NT_STATUS_ACCESS_DENIED;
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

	bzero(group_pol, POL_HND_SIZE);

	/* find the policy handle.  open a policy on it. */
	if (find_policy_by_hnd(get_global_hnd_cache(), domain_pol) == -1)
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* find the domain sid */
	if (!get_policy_samr_sid(get_global_hnd_cache(), domain_pol, &dom_sid))
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
	status = samr_open_by_sid(domain_pol, &dom_sid, group_pol,
	                              access_mask, grp.rid);
	if (status != 0x0)
	{
		return status;
	}

	if (!add_group_entry(&grp))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 _samr_query_dom_info
 ********************************************************************/
uint32 _samr_query_dom_info(const POLICY_HND *domain_pol,
				uint16 switch_value,
				SAM_UNK_CTR *ctr)
{
	/* find the policy handle.  open a policy on it. */
	if (find_policy_by_hnd(get_global_hnd_cache(), domain_pol) == -1)
	{
		DEBUG(5,("samr_reply_query_dom_info: invalid handle\n"));
		return NT_STATUS_INVALID_HANDLE;
	}

	switch (switch_value)
	{
		case 0x07:
		{
			make_unk_info7(&(ctr->info.inf7));
			break;
		}
		case 0x06:
		{
			make_unk_info6(&(ctr->info.inf6));
			break;
		}
		case 0x03:
		{
			make_unk_info3(&(ctr->info.inf3));
			break;
		}
		case 0x02:
		{
			extern fstring global_sam_name;
			extern pstring global_myname;
			make_unk_info2(&(ctr->info.inf2), global_sam_name, global_myname);
			break;
		}
		case 0x01:
		{
			make_unk_info1(&(ctr->info.inf1));
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
 _samr_create_user
 ********************************************************************/
uint32 _samr_create_user(const POLICY_HND *domain_pol,
				const UNISTR2 *uni_username,
				uint16 acb_info, uint32 access_mask, 
				POLICY_HND *user_pol,
				uint32 *unknown_0, uint32 *user_rid)
{
	DOM_SID sid;

	struct sam_passwd *sam_pass;
	fstring user_name;
	pstring err_str;
	pstring msg_str;

	(*unknown_0) = 0x30;
	(*user_rid) = 0x0;

	/* find the machine account: tell the caller if it exists.
	   lkclXXXX i have *no* idea if this is a problem or not
	   or even if you are supposed to construct a different
	   reply if the account already exists...
	 */

	/* find the domain sid associated with the policy handle */
	if (!get_policy_samr_sid(get_global_hnd_cache(), domain_pol, &sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}
	if (!sid_equal(&sid, &global_sam_sid))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	unistr2_to_ascii(user_name, uni_username, sizeof(user_name)-1);

	sam_pass = getsam21pwntnam(user_name);

	if (sam_pass != NULL)
	{
		/* account exists: say so */
		return NT_STATUS_USER_EXISTS;
	}

	if (!local_password_change(user_name, True,
		  acb_info | ACB_DISABLED | ACB_PWNOTREQ, 0xffff,
		  NULL,
		  err_str, sizeof(err_str),
		  msg_str, sizeof(msg_str)))
	{
		DEBUG(0,("%s\n", err_str));
		return NT_STATUS_ACCESS_DENIED;
	}

	sam_pass = getsam21pwntnam(user_name);
	if (sam_pass == NULL)
	{
		/* account doesn't exist: say so */
		return NT_STATUS_ACCESS_DENIED;
	}

	*unknown_0 = 0x000703ff;
	*user_rid = sam_pass->user_rid;

	return samr_open_by_sid(domain_pol, &sid, user_pol,
	                        access_mask, *user_rid);
}

/*******************************************************************
 _samr_connect_anon
 ********************************************************************/
uint32 _samr_connect_anon(const UNISTR2 *srv_name, uint32 access_mask,
				POLICY_HND *connect_pol)

{
	/* get a (unique) handle.  open a policy on it. */
	if (!open_policy_hnd(get_global_hnd_cache(),
		get_sec_ctx(), connect_pol, access_mask))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 _samr_connect
 ********************************************************************/
uint32 _samr_connect(const UNISTR2 *srv_name, uint32 access_mask,
				POLICY_HND *connect_pol)
{
	/* get a (unique) handle.  open a policy on it. */
	if (!open_policy_hnd(get_global_hnd_cache(),
		get_sec_ctx(), connect_pol, access_mask))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 _samr_open_alias
 ********************************************************************/
uint32 _samr_open_alias(const POLICY_HND *domain_pol,
					uint32 access_mask, uint32 alias_rid,
					POLICY_HND *alias_pol)
{
	DOM_SID sid;

	/* find the domain sid associated with the policy handle */
	if (!get_policy_samr_sid(get_global_hnd_cache(), domain_pol, &sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* this should not be hard-coded like this */
	if (!sid_equal(&sid, &global_sam_sid) &&
	    !sid_equal(&sid, &global_sid_S_1_5_20))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	return samr_open_by_sid(domain_pol, &sid, alias_pol, access_mask, alias_rid);
}

/*******************************************************************
 _samr_open_group
 ********************************************************************/
uint32 _samr_open_group(const POLICY_HND *domain_pol, uint32 access_mask,
				uint32 group_rid,
				POLICY_HND *group_pol)
{
	DOM_SID sid;

	/* find the domain sid associated with the policy handle */
	if (!get_policy_samr_sid(get_global_hnd_cache(), domain_pol, &sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* this should not be hard-coded like this */
	if (!sid_equal(&sid, &global_sam_sid))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	return samr_open_by_sid(domain_pol, &sid, group_pol, access_mask, group_rid);
}

/*******************************************************************
_samr_lookup_domain
********************************************************************/
uint32 _samr_lookup_domain(const POLICY_HND *connect_pol,
				const UNISTR2 *uni_domain,
				DOM_SID *dom_sid)
{
	fstring domain;

	/* find the connection policy handle */
	if (find_policy_by_hnd(get_global_hnd_cache(), connect_pol) == -1)
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	unistr2_to_ascii(domain, uni_domain, sizeof(domain));
	DEBUG(5, ("Lookup Domain: %s\n", domain));

	/* check it's one of ours */
	if (strequal(domain, global_sam_name))
	{
		sid_copy(dom_sid, &global_sam_sid);
		return 0x0;
	}
	else if (strequal(domain, "BUILTIN"))
	{
		sid_copy(dom_sid, &global_sid_S_1_5_20);
		return 0x0;
	}

	return NT_STATUS_NO_SUCH_DOMAIN;
}

BOOL pwdbsam_initialise(void)
{
	return	initialise_password_db() &&
		initialise_sam_password_db() &&
		initialise_passgrp_db() &&
		initialise_group_db() &&
		initialise_alias_db() &&
		initialise_builtin_db();
}
