
#if 0
	BOOL samr_chgpasswd_user( struct cli_connection *con, 
			const char *srv_name, const char *user_name,
			const char nt_newpass[516], const uchar nt_oldhash[16],
			const char lm_newpass[516], const uchar lm_oldhash[16]);
	BOOL samr_unknown_38(struct cli_connection *con, const char *srv_name);
	BOOL samr_query_dom_info(  POLICY_HND *domain_pol, uint16 switch_value,
					SAM_UNK_CTR *ctr);
	uint32 samr_enum_domains(  POLICY_HND *pol,
					uint32 *start_idx, uint32 size,
					struct acct_info **sam,
					uint32 *num_sam_domains);
	uint32 samr_enum_dom_groups(  POLICY_HND *pol,
					uint32 *start_idx, uint32 size,
					struct acct_info **sam,
					uint32 *num_sam_groups);
	uint32 samr_enum_dom_aliases(  POLICY_HND *pol,
					uint32 *start_idx, uint32 size,
					struct acct_info **sam,
					uint32 *num_sam_aliases);
	uint32 samr_enum_dom_users(  POLICY_HND *pol, uint32 *start_idx, 
					uint16 acb_mask, uint16 unk_1, uint32 size,
					struct acct_info **sam,
					uint32 *num_sam_users);
	BOOL samr_connect(  const char *srv_name, uint32 unknown_0,
					POLICY_HND *connect_pol);
	BOOL samr_open_user(  const POLICY_HND *pol,
					uint32 unk_0, uint32 rid, 
					POLICY_HND *user_pol);
	BOOL samr_open_alias(  const POLICY_HND *domain_pol,
					uint32 flags, uint32 rid,
					POLICY_HND *alias_pol);
	BOOL samr_delete_dom_alias(  POLICY_HND *alias_pol);
	uint32 samr_create_dom_user(  POLICY_HND *domain_pol, const char *acct_name,
					uint32 unk_0, uint32 unk_1,
					POLICY_HND *user_pol, uint32 *rid);
	BOOL samr_create_dom_alias(  POLICY_HND *domain_pol, const char *acct_name,
					POLICY_HND *alias_pol, uint32 *rid);
	BOOL samr_query_aliasinfo(  POLICY_HND *alias_pol, uint16 switch_value,
					ALIAS_INFO_CTR *ctr);
	BOOL samr_set_aliasinfo(  POLICY_HND *alias_pol, ALIAS_INFO_CTR *ctr);
	BOOL samr_open_group(  const POLICY_HND *domain_pol,
					uint32 flags, uint32 rid,
					POLICY_HND *group_pol);
	BOOL samr_delete_dom_group(  POLICY_HND *group_pol);
	BOOL samr_create_dom_group(  POLICY_HND *domain_pol, const char *acct_name,
					POLICY_HND *group_pol, uint32 *rid);
	BOOL samr_set_groupinfo(  POLICY_HND *group_pol, GROUP_INFO_CTR *ctr);
	BOOL samr_query_lookup_domain(  POLICY_HND *pol, const char *dom_name,
				      DOM_SID *dom_sid);
	BOOL samr_query_lookup_names(const POLICY_HND *pol, uint32 flags,
				     uint32 num_names, const char **names,
				     uint32 *num_rids, uint32 **rids, uint32 **types);
	BOOL samr_query_lookup_rids(  const POLICY_HND *pol, uint32 flags,
					uint32 num_rids, const uint32 *rids,
					uint32 *num_names,
					char   ***names,
					uint32 **type);
	BOOL samr_query_aliasmem(  const POLICY_HND *alias_pol, 
					uint32 *num_mem, DOM_SID2 *sid);
	BOOL samr_query_useraliases(  const POLICY_HND *pol,
					uint32 *ptr_sid, DOM_SID2 *sid,
					uint32 *num_aliases, uint32 **rid);
	BOOL samr_query_groupmem(  POLICY_HND *group_pol, 
					uint32 *num_mem, uint32 **rid, uint32 **attr);
	BOOL samr_query_usergroups(  POLICY_HND *pol, uint32 *num_groups,
					DOM_GID **gid);
	BOOL samr_query_groupinfo(  POLICY_HND *pol,
					uint16 switch_value, GROUP_INFO_CTR* ctr);
	BOOL samr_set_userinfo2(  POLICY_HND *pol, uint16 switch_value,
					void* usr);
	BOOL samr_set_userinfo(  POLICY_HND *pol, uint16 switch_value, void* usr);
	BOOL samr_query_userinfo(  POLICY_HND *pol, uint16 switch_value, void* usr);
	BOOL samr_close(  POLICY_HND *hnd);
	BOOL samr_query_dispinfo(  POLICY_HND *pol_domain, uint16 level,
					uint32 *num_entries,
					SAM_DISPINFO_CTR *ctr);
#endif

/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
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

extern int DEBUGLEVEL;

extern fstring global_sam_name;
extern pstring global_myname;
extern DOM_SID global_sam_sid;
extern DOM_SID global_sid_S_1_1;
extern DOM_SID global_sid_S_1_5_20;

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

	return (*num_entries) > 0;
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
		bzero(hnd, POL_HND_SIZE);
		return 0x0;
	}
	else
	{
		return 0xC0000000 | NT_STATUS_OBJECT_NAME_INVALID;
	}
}

/*******************************************************************
 samr_reply_open_domain
 ********************************************************************/
uint32 _samr_open_domain(const POLICY_HND *connect_pol,
				uint32 ace_perms,
				const DOM_SID *sid,
				POLICY_HND *domain_pol)
{
	BOOL pol_open = False;
	uint32 status = 0x0;

	/* find the connection policy handle. */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), connect_pol) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* get a (unique) handle.  open a policy on it. */
	if (status == 0x0 && !(pol_open = open_policy_hnd(get_global_hnd_cache(), domain_pol)))
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/* associate the domain SID with the (unique) handle. */
	if (status == 0x0 && !set_policy_samr_sid(get_global_hnd_cache(), domain_pol, sid))
	{
		/* oh, whoops.  don't know what error message to return, here */
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (status != 0 && pol_open)
	{
		close_policy_hnd(get_global_hnd_cache(), domain_pol);
	}

	DEBUG(5,("_samr_open_domain: %d\n", __LINE__));

	return status;
}

/*******************************************************************
 samr_reply_unknown_2c
 ********************************************************************/
uint32 _samr_unknown_2c(const POLICY_HND *user_pol,
				uint32 *unknown_0,
				uint32 *unknown_1)
{
	uint32 status = 0x0;

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), user_pol) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* find the user's rid */
	if ((status == 0x0) && (get_policy_samr_rid(get_global_hnd_cache(), user_pol) == 0xffffffff))
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	*unknown_0 = 0x00150000;
	*unknown_1 = 0x00000000;

	DEBUG(5,("samr_unknown_2c: %d\n", __LINE__));

	return status;
}

/*******************************************************************
 samr_reply_unknown_3
 ********************************************************************/
uint32 _samr_unknown_3(const POLICY_HND *user_pol, SAM_SID_STUFF *sid_stuff)
{
	uint32 rid;
	uint32 status;

	status = 0x0;

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), user_pol) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* find the user's rid */
	if (status == 0x0 && (rid = get_policy_samr_rid(get_global_hnd_cache(), user_pol)) == 0xffffffff)
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	if (status == 0x0)
	{
		DOM_SID usr_sid;
		usr_sid = global_sam_sid;

		SMB_ASSERT_ARRAY(usr_sid.sub_auths, usr_sid.num_auths+1);

		/*
		 * Add the user RID.
		 */
		sid_append_rid(&usr_sid, rid);
		
		/* maybe need another 1 or 2 (S-1-5-0x20-0x220 and S-1-5-20-0x224) */
		/* these two are DOMAIN_ADMIN and DOMAIN_ACCT_OP group RIDs */
		make_dom_sid3(&sid_stuff->sid[0], 0x035b, 0x0002, &global_sid_S_1_1);
		make_dom_sid3(&sid_stuff->sid[1], 0x0044, 0x0002, &usr_sid);
	}

	if (status == 0x0)
	{
		make_sam_sid_stuff(sid_stuff, 
					0x0001, 0x8004,
					0x00000014, 0x0002, 0x0070,
					2);
	}

	DEBUG(5,("samr_unknown_3: %d\n", __LINE__));

	return status;
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
uint32 _samr_enum_dom_users(  POLICY_HND *pol, uint32 *start_idx, 
				uint16 acb_mask, uint16 unk_1, uint32 size,
				SAM_ENTRY **sam,
				UNISTR2 **uni_acct_name,
				uint32 *num_sam_users)
{
	SAM_USER_INFO_21 pass[MAX_SAM_ENTRIES];
	int total_entries;

	uint32 status = 0x0;

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), pol) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	DEBUG(5,("samr_reply_enum_dom_users: %d\n", __LINE__));

	become_root(True);
	get_sampwd_entries(pass, (*start_idx), &total_entries, num_sam_users,
	                   MAX_SAM_ENTRIES, acb_mask);
	unbecome_root(True);

	(*start_idx) += (*num_sam_users);
	make_samr_dom_users(sam, uni_acct_name, (*num_sam_users), pass);

	DEBUG(5,("samr_enum_dom_users: %d\n", __LINE__));

	return status;
}

/*******************************************************************
 samr_reply_add_groupmem
 ********************************************************************/
uint32 _samr_add_groupmem(POLICY_HND *pol, uint32 rid, uint32 unknown)
{
	DOM_SID group_sid;
	uint32 group_rid;
	fstring group_sid_str;

	uint32 status = 0x0;

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), pol, &group_sid))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}
	else
	{
		sid_to_string(group_sid_str, &group_sid);
		sid_split_rid(&group_sid, &group_rid);
	}

	if (status == 0x0)
	{
		DEBUG(10,("sid is %s\n", group_sid_str));

		if (sid_equal(&group_sid, &global_sam_sid))
		{
			DEBUG(10,("lookup on Domain SID\n"));

			status = add_group_member(group_rid, rid) ? 0x0 : (0xC0000000 | NT_STATUS_ACCESS_DENIED);
		}
		else
		{
			status = 0xC0000000 | NT_STATUS_NO_SUCH_GROUP;
		}
	}

	return status;
}

/*******************************************************************
 samr_reply_del_groupmem
 ********************************************************************/
uint32 _samr_del_groupmem(POLICY_HND *pol, uint32 rid)
{
	DOM_SID group_sid;
	uint32 group_rid;
	fstring group_sid_str;

	uint32 status = 0x0;

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), pol, &group_sid))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}
	else
	{
		sid_to_string(group_sid_str, &group_sid);
		sid_split_rid(&group_sid, &group_rid);
	}

	if (status == 0x0)
	{
		DEBUG(10,("sid is %s\n", group_sid_str));

		if (sid_equal(&group_sid, &global_sam_sid))
		{
			DEBUG(10,("lookup on Domain SID\n"));

			status = del_group_member(group_rid, rid) ? 0x0 : (0xC0000000 | NT_STATUS_ACCESS_DENIED);
		}
		else
		{
			status = 0xC0000000 | NT_STATUS_NO_SUCH_GROUP;
		}
	}

	return status;
}

/*******************************************************************
 samr_reply_add_aliasmem
 ********************************************************************/
uint32 _samr_add_aliasmem(POLICY_HND *alias_pol, DOM_SID *sid)
{
	DOM_SID alias_sid;
	uint32 alias_rid;
	fstring alias_sid_str;

	uint32 status = 0x0;

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), alias_pol, &alias_sid))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}
	else
	{
		sid_to_string(alias_sid_str, &alias_sid);
		sid_split_rid(&alias_sid, &alias_rid);
	}

	if (status == 0x0)
	{
		DEBUG(10,("sid is %s\n", alias_sid_str));

		if (sid_equal(&alias_sid, &global_sam_sid))
		{
			DEBUG(10,("add member on Domain SID\n"));

			status = add_alias_member(alias_rid, sid) ? 0x0 : (0xC0000000 | NT_STATUS_ACCESS_DENIED);
		}
		else if (sid_equal(&alias_sid, &global_sid_S_1_5_20))
		{
			DEBUG(10,("add member on BUILTIN SID\n"));

			status = add_builtin_member(alias_rid, sid) ? 0x0 : (0xC0000000 | NT_STATUS_ACCESS_DENIED);
		}
		else
		{
			status = 0xC0000000 | NT_STATUS_NO_SUCH_ALIAS;
		}
	}

	return status;
}

/*******************************************************************
 samr_reply_del_aliasmem
 ********************************************************************/
uint32 _samr_del_aliasmem(POLICY_HND *alias_pol, DOM_SID *sid)
{
	DOM_SID alias_sid;
	uint32 alias_rid;
	fstring alias_sid_str;

	uint32 status = 0x0;

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), alias_pol, &alias_sid))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}
	else
	{
		sid_to_string(alias_sid_str, &alias_sid);
		sid_split_rid(&alias_sid, &alias_rid);
	}

	if (status == 0x0)
	{
		DEBUG(10,("sid is %s\n", alias_sid_str));

		if (sid_equal(&alias_sid, &global_sam_sid))
		{
			DEBUG(10,("del member on Domain SID\n"));

			status = del_alias_member(alias_rid, sid) ? 0x0 : (0xC0000000 | NT_STATUS_ACCESS_DENIED);
		}
		else if (sid_equal(&alias_sid, &global_sid_S_1_5_20))
		{
			DEBUG(10,("del member on BUILTIN SID\n"));

			status = del_builtin_member(alias_rid, sid) ? 0x0 : (0xC0000000 | NT_STATUS_ACCESS_DENIED);
		}
		else
		{
			status = 0xC0000000 | NT_STATUS_NO_SUCH_ALIAS;
		}
	}

	return status;
}

#if 0
/*******************************************************************
 samr_reply_enum_domains
 ********************************************************************/
uint32 _samr_enum_domains(SAMR_Q_ENUM_DOMAINS *q_u,
				prs_struct *rdata)
{
	SAMR_R_ENUM_DOMAINS r_e;
	char  **doms = NULL;
	uint32 num_entries = 0;

	status = 0x0;
	num_entries2 = 0;

	ZERO_STRUCT(r_e);

	status = 0x0;

	/* find the connection policy handle. */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(pol)) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	DEBUG(5,("samr_reply_enum_domains:\n"));

	if (!enumdomains(&doms, &num_entries))
	{
		status = 0xC0000000 | NT_STATUS_NO_MEMORY;
	}

	if (status == 0x0)
	{
		make_samr_r_enum_domains(&r_e,
		          start_idx + num_entries,
		          num_entries, doms, status);
	}

	/* store the response in the SMB stream */
	samr_io_r_enum_domains("", &r_e, rdata, 0);

	free_char_array(num_entries, doms);

	if (sam != NULL)
	{
		free(sam);
	}

	if (uni_dom_name != NULL)
	{
		free(uni_dom_name);
	}

	DEBUG(5,("samr_enum_domains: %d\n", __LINE__));
}

/*******************************************************************
 samr_reply_enum_dom_groups
 ********************************************************************/
uint32 _samr_enum_dom_groups(SAMR_Q_ENUM_DOM_GROUPS *q_u,
				prs_struct *rdata)
{
	SAMR_R_ENUM_DOM_GROUPS r_e;
	DOMAIN_GRP *grps = NULL;
	int num_entries = 0;
	DOM_SID sid;
	fstring sid_str;

	status = 0x0;
	num_entries2 = 0;

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &pol, &sid))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	sid_to_string(sid_str, &sid);

	DEBUG(5,("samr_reply_enum_dom_groups: sid %s\n", sid_str));

	if (sid_equal(&sid, &global_sam_sid))
	{
		BOOL ret;

		become_root(True);
		ret = enumdomgroups(&grps, &num_entries);
		unbecome_root(True);
		if (!ret)
		{
			status = 0xC0000000 | NT_STATUS_NO_MEMORY;
		}
	}

	if (status == 0x0)
	{
		make_samr_r_enum_dom_groups(&r_e,
		          start_idx + num_entries,
		          num_entries, grps, status);
	}

	/* store the response in the SMB stream */
	samr_io_r_enum_dom_groups("", &r_e, rdata, 0);

	if (grps != NULL)
	{
		free(grps);
	}

	if (sam != NULL)
	{
		free(sam);
	}

	if (uni_grp_name != NULL)
	{
		free(uni_grp_name);
	}

	DEBUG(5,("samr_enum_dom_groups: %d\n", __LINE__));
}


/*******************************************************************
 samr_reply_enum_dom_aliases
 ********************************************************************/
uint32 _samr_enum_dom_aliases(SAMR_Q_ENUM_DOM_ALIASES *q_u,
				prs_struct *rdata)
{
	SAMR_R_ENUM_DOM_ALIASES r_e;
	LOCAL_GRP *alss = NULL;
	int num_entries = 0;
	DOM_SID sid;
	fstring sid_str;

	ZERO_STRUCT(r_e);

	status = 0x0;
	num_entries2 = 0;

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &pol, &sid))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
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
			status = 0xC0000000 | NT_STATUS_NO_MEMORY;
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
			status = 0xC0000000 | NT_STATUS_NO_MEMORY;
		}
	}
		
	if (status == 0x0)
	{
		make_samr_r_enum_dom_aliases(&r_e,
		               start_idx + num_entries,
		               num_entries, alss, status);
	}

	/* store the response in the SMB stream */
	samr_io_r_enum_dom_aliases("", &r_e, rdata, 0);

	if (alss != NULL)
	{
		free(alss);
	}

	if (sam != NULL)
	{
		free(sam);
	}

	if (uni_grp_name != NULL)
	{
		free(uni_grp_name);
	}

	DEBUG(5,("samr_enum_dom_aliases: %d\n", __LINE__));

}


/*******************************************************************
 samr_reply_query_dispinfo
 ********************************************************************/
uint32 _samr_query_dispinfo(SAMR_Q_QUERY_DISPINFO *q_u,
				prs_struct *rdata)
{
	SAMR_R_QUERY_DISPINFO r_e;
	SAM_DISPINFO_CTR ctr;
	SAM_USER_INFO_21 pass[MAX_SAM_ENTRIES];
	DOMAIN_GRP *grps = NULL;
	DOMAIN_GRP *sam_grps = NULL;
	uint32 data_size = 0;
	uint32 status = 0x0;
	uint16 acb_mask = ACB_NORMAL;
	int num_sam_entries = 0;
	int num_entries = 0;
	int total_entries;

	DEBUG(5,("samr_reply_query_dispinfo: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (find_policy_by_hnd(get_global_hnd_cache(), &(domain_pol)) == -1)
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
		DEBUG(5,("samr_reply_query_dispinfo: invalid handle\n"));
	}

	if (status == 0x0)
	{
		become_root(True);

		/* Get what we need from the password database */
		switch (switch_level)
		{
			case 0x2:
			{
				acb_mask = ACB_WSTRUST;
				/* Fall through */
			}
			case 0x1:
			case 0x4:
			{
				get_sampwd_entries(pass, start_idx,
					      &total_entries, &num_sam_entries,
					      MAX_SAM_ENTRIES, acb_mask);
				break;
			}
			case 0x3:
			case 0x5:
			{
				enumdomgroups(&sam_grps, &num_sam_entries);

				if (start_idx < num_sam_entries) {
					grps = sam_grps + start_idx;
					num_sam_entries -= start_idx;
				} else {
					num_sam_entries = 0;
				}
				break;
			}
		}

		unbecome_root(True);

		num_entries = num_sam_entries;

		if (num_entries > max_entries)
		{
			num_entries = max_entries;
		}

		if (num_entries > MAX_SAM_ENTRIES)
		{
			num_entries = MAX_SAM_ENTRIES;
			DEBUG(5,("limiting number of entries to %d\n", 
				 num_entries));
		}

		data_size = max_size;

		/* Now create reply structure */
		switch (switch_level)
		{
			case 0x1:
			{
				ctr.sam.info1 = malloc(sizeof(SAM_DISPINFO_1));
				make_sam_dispinfo_1(ctr.sam.info1,
						    &num_entries, &data_size,
						    start_idx, pass);
				break;
			}
			case 0x2:
			{
				ctr.sam.info2 = malloc(sizeof(SAM_DISPINFO_2));
				make_sam_dispinfo_2(ctr.sam.info2,
						    &num_entries, &data_size,
						    start_idx, pass);
				break;
			}
			case 0x3:
			{
				ctr.sam.info3 = malloc(sizeof(SAM_DISPINFO_3));
				make_sam_dispinfo_3(ctr.sam.info3,
						    &num_entries, &data_size,
						    start_idx, grps);
				break;
			}
	  		case 0x4:
			{
				ctr.sam.info4 = malloc(sizeof(SAM_DISPINFO_4));
				make_sam_dispinfo_4(ctr.sam.info4,
						    &num_entries, &data_size,
						    start_idx, pass);
				break;
			}
			case 0x5:
			{
				ctr.sam.info5 = malloc(sizeof(SAM_DISPINFO_5));
				make_sam_dispinfo_5(ctr.sam.info5,
						    &num_entries, &data_size,
						    start_idx, grps);
				break;
			}
			default:
			{
				ctr.sam.info = NULL;
				status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;
				break;
			}
		}
	}

	if ((status == 0) && (num_entries < num_sam_entries))
	{
		status = STATUS_MORE_ENTRIES;
	}

	make_samr_r_query_dispinfo(&r_e, num_entries, data_size,
				   switch_level, &ctr, status);

	/* store the response in the SMB stream */
	samr_io_r_query_dispinfo("", &r_e, rdata, 0);

	/* free malloc'd areas */
	if (sam_grps != NULL)
	{
		free(sam_grps);
	}

	if (ctr.sam.info != NULL)
	{
		free(ctr.sam.info);
	}

	DEBUG(5,("samr_reply_query_dispinfo: %d\n", __LINE__));
}


/*******************************************************************
 samr_reply_delete_dom_group
 ********************************************************************/
uint32 _samr_delete_dom_group(SAMR_Q_DELETE_DOM_GROUP *q_u,
				prs_struct *rdata)
{
	uint32 status = 0;

	DOM_SID group_sid;
	uint32 group_rid;
	fstring group_sid_str;

	SAMR_R_DELETE_DOM_GROUP r_u;

	DEBUG(5,("samr_delete_dom_group: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &group_pol, &group_sid))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}
	else
	{
		sid_to_string(group_sid_str, &group_sid     );
		sid_split_rid(&group_sid, &group_rid);
	}

	if (status == 0x0)
	{
		DEBUG(10,("sid is %s\n", group_sid_str));

		if (sid_equal(&group_sid, &global_sam_sid))
		{
			DEBUG(10,("lookup on Domain SID\n"));

			status = del_group_entry(group_rid) ? 0x0 : (0xC0000000 | NT_STATUS_NO_SUCH_GROUP);
		}
		else
		{
			status = 0xC0000000 | NT_STATUS_NO_SUCH_GROUP;
		}
	}

	make_samr_r_delete_dom_group(&r_u, status);

	/* store the response in the SMB stream */
	samr_io_r_delete_dom_group("", &r_u, rdata, 0);
}


/*******************************************************************
 samr_reply_query_groupmem
 ********************************************************************/
uint32 _samr_query_groupmem(SAMR_Q_QUERY_GROUPMEM *q_u,
				prs_struct *rdata)
{
	uint32 status = 0;

	DOMAIN_GRP_MEMBER *mem_grp = NULL;
	uint32 *rid = NULL;
	uint32 *attr = NULL;
	int num_rids = 0;
	DOM_SID group_sid;
	uint32 group_rid;
	fstring group_sid_str;

	SAMR_R_QUERY_GROUPMEM r_u;

	DEBUG(5,("samr_query_groupmem: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &group_pol, &group_sid))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}
	else
	{
		sid_to_string(group_sid_str, &group_sid     );
		sid_split_rid(&group_sid, &group_rid);
	}

	if (status == 0x0)
	{
		DEBUG(10,("sid is %s\n", group_sid_str));

		if (sid_equal(&group_sid, &global_sam_sid))
		{
			DEBUG(10,("lookup on Domain SID\n"));

			become_root(True);
			status = getgrouprid(group_rid, &mem_grp, &num_rids) != NULL ? 0x0 : (0xC0000000 | NT_STATUS_NO_SUCH_GROUP);
			unbecome_root(True);
		}
		else
		{
			status = 0xC0000000 | NT_STATUS_NO_SUCH_GROUP;
		}
	}

	if (status == 0x0 && num_rids > 0)
	{
		rid  = malloc(num_rids * sizeof(uint32));
		attr = malloc(num_rids * sizeof(uint32));
		if (mem_grp != NULL && rid != NULL && attr != NULL)
		{
			int i;
			for (i = 0; i < num_rids; i++)
			{
				rid [i] = mem_grp[i].rid;
				attr[i] = mem_grp[i].attr;
			}
			free(mem_grp);
		}
	}

	make_samr_r_query_groupmem(&r_u, num_rids, rid, attr, status);

	/* store the response in the SMB stream */
	samr_io_r_query_groupmem("", &r_u, rdata, 0);

	samr_free_r_query_groupmem(&r_u);

	DEBUG(5,("samr_query_groupmem: %d\n", __LINE__));

}


/*******************************************************************
 samr_reply_query_groupinfo
 ********************************************************************/
uint32 _samr_query_groupinfo(SAMR_Q_QUERY_GROUPINFO *q_u,
				prs_struct *rdata)
{
	SAMR_R_QUERY_GROUPINFO r_e;
	GROUP_INFO_CTR ctr;
	uint32 status = 0x0;

	ptr = 0;

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(pol)) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	DEBUG(5,("samr_reply_query_groupinfo: %d\n", __LINE__));

	if (status == 0x0)
	{
		if (switch_level == 1)
		{
			ptr = 1;
			ctr.switch_value1 = 1;
			make_samr_group_info1(&ctr.group.info1,
			                      "fake account name",
			                      "fake account description", 2);
		}
		else if (switch_level == 4)
		{
			ptr = 1;
			ctr.switch_value1 = 4;
			make_samr_group_info4(&ctr.group.info4,
			                     "fake account description");
		}
		else
		{
			status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;
		}
	}

	make_samr_r_query_groupinfo(&r_e, status == 0 ? &ctr : NULL, status);

	/* store the response in the SMB stream */
	samr_io_r_query_groupinfo("", &r_e, rdata, 0);

	DEBUG(5,("samr_query_groupinfo: %d\n", __LINE__));

}


/*******************************************************************
 samr_reply_query_aliasinfo
 ********************************************************************/
uint32 _samr_query_aliasinfo(SAMR_Q_QUERY_ALIASINFO *q_u,
				prs_struct *rdata)
{
	SAMR_R_QUERY_ALIASINFO r_e;
	ALIAS_INFO_CTR ctr;
	uint32 status = 0x0;

	ptr = 0;

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(pol)) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	DEBUG(5,("samr_reply_query_aliasinfo: %d\n", __LINE__));

	if (status == 0x0)
	{
		if (switch_level == 3)
		{
			ptr = 1;
			ctr.switch_value1 = 3;
			make_samr_alias_info3(&ctr.alias.info3, "<fake account description>");
		}
		else
		{
			status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;
		}
	}

	make_samr_r_query_aliasinfo(&r_e, status == 0 ? &ctr : NULL, status);

	/* store the response in the SMB stream */
	samr_io_r_query_aliasinfo("", &r_e, rdata, 0);

	DEBUG(5,("samr_query_aliasinfo: %d\n", __LINE__));

}


/*******************************************************************
 samr_reply_query_useraliases
 ********************************************************************/
uint32 _samr_query_useraliases(SAMR_Q_QUERY_USERALIASES *q_u,
				prs_struct *rdata)
{
	uint32 status = 0;

	LOCAL_GRP *mem_grp = NULL;
	uint32 *rid = NULL;
	int num_rids = 0;
	struct sam_passwd *sam_pass;
	DOM_SID usr_sid;
	DOM_SID dom_sid;
	uint32 user_rid;
	fstring sam_sid_str;
	fstring dom_sid_str;
	fstring usr_sid_str;

	SAMR_R_QUERY_USERALIASES r_u;
	ZERO_STRUCT(r_u);

	DEBUG(5,("samr_query_useraliases: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &pol, &dom_sid))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}
	else
	{
		sid_to_string(dom_sid_str, &dom_sid       );
		sid_to_string(sam_sid_str, &global_sam_sid);
	}

	if (status == 0x0)
	{
		usr_sid = sid[0].sid;
		sid_split_rid(&usr_sid, &user_rid);
		sid_to_string(usr_sid_str, &usr_sid);

	}

	if (status == 0x0)
	{
		/* find the user account */
		become_root(True);
		sam_pass = getsam21pwrid(user_rid);
		unbecome_root(True);

		if (sam_pass == NULL)
		{
			status = 0xC0000000 | NT_STATUS_NO_SUCH_USER;
			num_rids = 0;
		}
	}

	if (status == 0x0)
	{
		DEBUG(10,("sid is %s\n", dom_sid_str));

		if (sid_equal(&dom_sid, &global_sid_S_1_5_20))
		{
			DEBUG(10,("lookup on S-1-5-20\n"));

			become_root(True);
			getuserbuiltinntnam(sam_pass->nt_name, &mem_grp, &num_rids);
			unbecome_root(True);
		}
		else if (sid_equal(&dom_sid, &usr_sid))
		{
			DEBUG(10,("lookup on Domain SID\n"));

			become_root(True);
			getuseraliasntnam(sam_pass->nt_name, &mem_grp, &num_rids);
			unbecome_root(True);
		}
		else
		{
			status = 0xC0000000 | NT_STATUS_NO_SUCH_USER;
		}
	}

	if (status == 0x0 && num_rids > 0)
	{
		rid = malloc(num_rids * sizeof(uint32));
		if (mem_grp != NULL && rid != NULL)
		{
			int i;
			for (i = 0; i < num_rids; i++)
			{
				rid[i] = mem_grp[i].rid;
			}
			free(mem_grp);
		}
	}

	make_samr_r_query_useraliases(&r_u, num_rids, rid, status);

	/* store the response in the SMB stream */
	samr_io_r_query_useraliases("", &r_u, rdata, 0);

	samr_free_r_query_useraliases(&r_u);

	DEBUG(5,("samr_query_useraliases: %d\n", __LINE__));

}

/*******************************************************************
 samr_reply_delete_dom_alias
 ********************************************************************/
uint32 _samr_delete_dom_alias(SAMR_Q_DELETE_DOM_ALIAS *q_u,
				prs_struct *rdata)
{
	uint32 status = 0;

	DOM_SID alias_sid;
	uint32 alias_rid;
	fstring alias_sid_str;

	SAMR_R_DELETE_DOM_ALIAS r_u;

	DEBUG(5,("samr_delete_dom_alias: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &alias_pol, &alias_sid))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}
	else
	{
		sid_to_string(alias_sid_str, &alias_sid     );
		sid_split_rid(&alias_sid, &alias_rid);
	}

	if (status == 0x0)
	{
		DEBUG(10,("sid is %s\n", alias_sid_str));

		if (sid_equal(&alias_sid, &global_sam_sid))
		{
			DEBUG(10,("lookup on Domain SID\n"));

			status = del_alias_entry(alias_rid) ? 0x0 : (0xC0000000 | NT_STATUS_NO_SUCH_ALIAS);
		}
		else
		{
			status = 0xC0000000 | NT_STATUS_NO_SUCH_ALIAS;
		}
	}

	make_samr_r_delete_dom_alias(&r_u, status);

	/* store the response in the SMB stream */
	samr_io_r_delete_dom_alias("", &r_u, rdata, 0);
}


/*******************************************************************
 samr_reply_query_aliasmem
 ********************************************************************/
uint32 _samr_query_aliasmem(SAMR_Q_QUERY_ALIASMEM *q_u,
				prs_struct *rdata)
{
	uint32 status = 0;

	LOCAL_GRP_MEMBER *mem_grp = NULL;
	DOM_SID2 *sid = NULL;
	int num_sids = 0;
	DOM_SID alias_sid;
	uint32 alias_rid;
	fstring alias_sid_str;

	SAMR_R_QUERY_ALIASMEM r_u;

	DEBUG(5,("samr_query_aliasmem: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &alias_pol, &alias_sid))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}
	else
	{
		sid_to_string(alias_sid_str, &alias_sid     );
		sid_split_rid(&alias_sid, &alias_rid);
	}

	if (status == 0x0)
	{
		DEBUG(10,("sid is %s\n", alias_sid_str));

		if (sid_equal(&alias_sid, &global_sid_S_1_5_20))
		{
			DEBUG(10,("lookup on S-1-5-20\n"));

			become_root(True);
			status = getbuiltinrid(alias_rid, &mem_grp, &num_sids) != NULL ? 0x0 : 0xC0000000 | NT_STATUS_NO_SUCH_ALIAS;
			unbecome_root(True);
		}
		else if (sid_equal(&alias_sid, &global_sam_sid))
		{
			DEBUG(10,("lookup on Domain SID\n"));

			become_root(True);
			status = getaliasrid(alias_rid, &mem_grp, &num_sids) != NULL ? 0x0 : 0xC0000000 | NT_STATUS_NO_SUCH_ALIAS;
			unbecome_root(True);
		}
		else
		{
			status = 0xC0000000 | NT_STATUS_NO_SUCH_ALIAS;
		}
	}

	if (status == 0x0 && num_sids > 0)
	{
		sid = malloc(num_sids * sizeof(DOM_SID));
		if (mem_grp != NULL && sid != NULL)
		{
			int i;
			for (i = 0; i < num_sids; i++)
			{
				make_dom_sid2(&sid[i], &mem_grp[i].sid);
			}
			free(mem_grp);
		}
	}

	make_samr_r_query_aliasmem(&r_u, num_sids, sid, status);

	/* store the response in the SMB stream */
	samr_io_r_query_aliasmem("", &r_u, rdata, 0);

	if (sid != NULL)
	{
		free(sid);
	}

	DEBUG(5,("samr_query_aliasmem: %d\n", __LINE__));

}


/*******************************************************************
 samr_reply_lookup_names
 ********************************************************************/
uint32 _samr_lookup_names(const SAMR_Q_LOOKUP_NAMES *q_u,
				prs_struct *rdata)
{
	uint32 rid [MAX_SAM_ENTRIES];
	uint8  type[MAX_SAM_ENTRIES];
	uint32 status     = 0;
	int i;
	int num_rids = num_names1;
	DOM_SID pol_sid;
	fstring tmp;

	SAMR_R_LOOKUP_NAMES r_u;

	DEBUG(5,("samr_lookup_names: %d\n", __LINE__));

	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &pol, &pol_sid))
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	sid_to_string(tmp, &pol_sid);
	DEBUG(5,("pol_sid: %s\n", tmp));

	if (num_rids > MAX_SAM_ENTRIES)
	{
		num_rids = MAX_SAM_ENTRIES;
		DEBUG(5,("samr_lookup_names: truncating entries to %d\n", num_rids));
	}

	SMB_ASSERT_ARRAY(uni_name, num_rids);

	for (i = 0; i < num_rids && status == 0; i++)
	{
		DOM_SID sid;
		fstring name;
		unistr2_to_ascii(name, &uni_name[i], sizeof(name)-1);

		status = lookup_name(name, &sid, &(type[i]));
		if (status == 0x0)
		{
			sid_split_rid(&sid, &rid[i]);
		}
		if ((status != 0x0) || !sid_equal(&pol_sid, &sid))
		{
			rid [i] = 0xffffffff;
			type[i] = SID_NAME_UNKNOWN;
		}

		sid_to_string(tmp, &sid);
		DEBUG(10,("name: %s sid: %s rid: %x type: %d\n",
			name, tmp, rid[i], type[i]));
		
	}

	make_samr_r_lookup_names(&r_u, num_rids, rid, type, status);

	/* store the response in the SMB stream */
	samr_io_r_lookup_names("", &r_u, rdata, 0);

	DEBUG(5,("samr_lookup_names: %d\n", __LINE__));
}

/*******************************************************************
 samr_reply_chgpasswd_user
 ********************************************************************/
uint32 _samr_chgpasswd_user(SAMR_Q_CHGPASSWD_USER *q_u,
				prs_struct *rdata)
{
	SAMR_R_CHGPASSWD_USER r_u;
	uint32 status = 0x0;
	fstring user_name;
	fstring wks;
	uchar *lm_newpass = NULL;
	uchar *nt_newpass = NULL;
	uchar *lm_oldhash = NULL;
	uchar *nt_oldhash = NULL;

	unistr2_to_ascii(user_name, &uni_user_name, sizeof(user_name)-1);
	unistr2_to_ascii(wks, &uni_dest_host, sizeof(wks)-1);

	DEBUG(5,("samr_chgpasswd_user: user: %s wks: %s\n", user_name, wks));

	if (lm_newpass.ptr)
	{
		lm_newpass = lm_newpass.pass;
	}
	if (lm_oldhash.ptr)
	{
		lm_oldhash = lm_oldhash.hash;
	}
	if (nt_newpass.ptr)
	{
        	nt_newpass = nt_newpass.pass;
	}
	if (nt_oldhash.ptr)
	{
        	nt_oldhash = nt_oldhash.hash;
        }
	if (!pass_oem_change(user_name,
	                     lm_newpass, lm_oldhash,
	                     nt_newpass, nt_oldhash))
	{
		status = 0xC0000000 | NT_STATUS_WRONG_PASSWORD;
	}

	make_samr_r_chgpasswd_user(&r_u, status);

	/* store the response in the SMB stream */
	samr_io_r_chgpasswd_user("", &r_u, rdata, 0);

	DEBUG(5,("samr_chgpasswd_user: %d\n", __LINE__));
}


/*******************************************************************
 samr_reply_unknown_38
 ********************************************************************/
uint32 _samr_unknown_38(SAMR_Q_UNKNOWN_38 *q_u,
				prs_struct *rdata)
{
	SAMR_R_UNKNOWN_38 r_u;

	DEBUG(5,("samr_unknown_38: %d\n", __LINE__));

	make_samr_r_unknown_38(&r_u);

	/* store the response in the SMB stream */
	samr_io_r_unknown_38("", &r_u, rdata, 0);

	DEBUG(5,("samr_unknown_38: %d\n", __LINE__));
}

/*******************************************************************
 samr_reply_lookup_rids
 ********************************************************************/
uint32 _samr_lookup_rids(SAMR_Q_LOOKUP_RIDS *q_u,
				prs_struct *rdata)
{
	fstring group_names[MAX_SAM_ENTRIES];
	uint8   types[MAX_SAM_ENTRIES];
	uint32 status     = 0;
	int num_rids = num_rids1;
	DOM_SID pol_sid;

	SAMR_R_LOOKUP_RIDS r_u;
	ZERO_STRUCT(r_u);

	DEBUG(5,("samr_lookup_rids: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(pol)) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &pol, &pol_sid))
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	if (status == 0x0)
	{
		int i;
		if (num_rids > MAX_SAM_ENTRIES)
		{
			num_rids = MAX_SAM_ENTRIES;
			DEBUG(5,("samr_lookup_rids: truncating entries to %d\n", num_rids));
		}

		for (i = 0; i < num_rids && status == 0; i++)
		{
			DOM_SID sid;
			sid_copy(&sid, &pol_sid);
			sid_append_rid(&sid, rid[i]);
			status = lookup_sid(&sid, group_names[i], &types[i]);
			if (status != 0)
				types[i] = SID_NAME_UNKNOWN;
		}
	}

	make_samr_r_lookup_rids(&r_u, num_rids, group_names, types, status);

	/* store the response in the SMB stream */
	samr_io_r_lookup_rids("", &r_u, rdata, 0);

	DEBUG(5,("samr_lookup_rids: %d\n", __LINE__));

}


/*******************************************************************
 samr_reply_open_user
 ********************************************************************/
uint32 _samr_open_user(SAMR_Q_OPEN_USER *q_u,
				prs_struct *rdata,
				int status)
{
	SAMR_R_OPEN_USER r_u;
	struct sam_passwd *sam_pass;
	BOOL pol_open = False;

	/* set up the SAMR open_user response */
	bzero(user_pol.data, POL_HND_SIZE);

	status = 0x0;

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(domain_pol)) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* get a (unique) handle.  open a policy on it. */
	if (status == 0x0 && !(pol_open = open_policy_hnd(get_global_hnd_cache(), &(user_pol))))
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	become_root(True);
	sam_pass = getsam21pwrid(user_rid);
	unbecome_root(True);

	/* check that the RID exists in our domain. */
	if (status == 0x0 && sam_pass == NULL)
	{
		status = 0xC0000000 | NT_STATUS_NO_SUCH_USER;
	}

	/* associate the RID with the (unique) handle. */
	if (status == 0x0 && !set_policy_samr_rid(get_global_hnd_cache(), &(user_pol), user_rid))
	{
		/* oh, whoops.  don't know what error message to return, here */
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (status != 0 && pol_open)
	{
		close_policy_hnd(get_global_hnd_cache(), &(user_pol));
	}

	DEBUG(5,("samr_open_user: %d\n", __LINE__));

	/* store the response in the SMB stream */
	samr_io_r_open_user("", &r_u, rdata, 0);

	DEBUG(5,("samr_open_user: %d\n", __LINE__));

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

	make_sam_user_info21(id21,

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
uint32 _samr_query_userinfo(SAMR_Q_QUERY_USERINFO *q_u,
				prs_struct *rdata)
{
	SAMR_R_QUERY_USERINFO r_u;
#if 0
	SAM_USER_INFO_11 id11;
#endif
	SAM_USER_INFO_10 id10;
	SAM_USER_INFO_21 id21;
	void *info = NULL;

	uint32 status = 0x0;
	uint32 rid = 0x0;

	DEBUG(5,("samr_reply_query_userinfo: %d\n", __LINE__));

	/* search for the handle */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(pol)) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* find the user's rid */
	if (status == 0x0 && (rid = get_policy_samr_rid(get_global_hnd_cache(), &(pol))) == 0xffffffff)
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	DEBUG(5,("samr_reply_query_userinfo: rid:0x%x\n", rid));

	/* ok!  user info levels (there are lots: see MSDEV help), off we go... */
	if (status == 0x0)
	{
		switch (switch_value)
		{
			case 0x10:
			{
				info = (void*)&id10;
				status = get_user_info_10(&id10, rid) ? 0 : (0xC0000000 | NT_STATUS_NO_SUCH_USER);
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

				make_sam_user_info11(&id11, &expire, "BROOKFIELDS$", 0x03ef, 0x201, 0x0080);

				break;
			}
#endif
			case 21:
			{
				info = (void*)&id21;
				status = get_user_info_21(&id21, rid) ? 0 : (0xC0000000 | NT_STATUS_NO_SUCH_USER);
				break;
			}

			default:
			{
				status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;

				break;
			}
		}
	}

	make_samr_r_query_userinfo(&r_u, switch_value, info, status);

	/* store the response in the SMB stream */
	samr_io_r_query_userinfo("", &r_u, rdata, 0);

	DEBUG(5,("samr_reply_query_userinfo: %d\n", __LINE__));

}

/*******************************************************************
 set_user_info_24
 ********************************************************************/
static BOOL set_user_info_24(SAM_USER_INFO_24 *id24, uint32 rid)
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
static BOOL set_user_info_23(SAM_USER_INFO_23 *id23, uint32 rid)
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
 set_user_info_16
 ********************************************************************/
static BOOL set_user_info_16(SAM_USER_INFO_16 *id16, uint32 rid)
{
	struct sam_passwd *pwd = getsam21pwrid(rid);
	struct sam_passwd new_pwd;

	if (id16 == NULL)
	{
		DEBUG(5, ("set_user_info_16: NULL id16\n"));
		return False;
	}
	if (pwd == NULL)
	{
		return False;
	}

	copy_sam_passwd(&new_pwd, pwd);

	new_pwd.acct_ctrl = id16->acb_info;

	return mod_sam21pwd_entry(&new_pwd, True);
}


/*******************************************************************
 samr_reply_set_userinfo2
 ********************************************************************/
uint32 _samr_set_userinfo2(SAMR_Q_SET_USERINFO2 *q_u,
				prs_struct *rdata, uchar user_sess_key[16])
{
	SAMR_R_SET_USERINFO2 r_u;

	uint32 status = 0x0;
	uint32 rid = 0x0;

	DEBUG(5,("samr_reply_set_userinfo2: %d\n", __LINE__));

	/* search for the handle */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(pol)) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* find the user's rid */
	if (status == 0x0 && (rid = get_policy_samr_rid(get_global_hnd_cache(), &(pol))) == 0xffffffff)
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	DEBUG(5,("samr_reply_set_userinfo2: rid:0x%x\n", rid));

	/* ok!  user info levels (there are lots: see MSDEV help), off we go... */
	if (status == 0x0 && info.id == NULL)
	{
		DEBUG(5,("samr_reply_set_userinfo2: NULL info level\n"));
		status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;
	}

	if (status == 0x0)
	{
		switch (switch_value)
		{
			case 16:
			{
				SAM_USER_INFO_16 *id16 = info.id16;
				status = set_user_info_16(id16, rid) ? 0 : (0xC0000000 | NT_STATUS_ACCESS_DENIED);
				break;
			}
			default:
			{
				status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;

				break;
			}
		}
	}

	make_samr_r_set_userinfo2(&r_u, status);

	/* store the response in the SMB stream */
	samr_io_r_set_userinfo2("", &r_u, rdata, 0);

	DEBUG(5,("samr_reply_set_userinfo2: %d\n", __LINE__));

}


/*******************************************************************
 samr_reply_set_userinfo
 ********************************************************************/
uint32 _samr_set_userinfo(SAMR_Q_SET_USERINFO *q_u,
				prs_struct *rdata, uchar user_sess_key[16])
{
	SAMR_R_SET_USERINFO r_u;

	uint32 status = 0x0;
	uint32 rid = 0x0;

	DEBUG(5,("samr_reply_set_userinfo: %d\n", __LINE__));

	/* search for the handle */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(pol)) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* find the user's rid */
	if (status == 0x0 && (rid = get_policy_samr_rid(get_global_hnd_cache(), &(pol))) == 0xffffffff)
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	DEBUG(5,("samr_reply_set_userinfo: rid:0x%x\n", rid));

	/* ok!  user info levels (there are lots: see MSDEV help), off we go... */
	if (status == 0x0 && info.id == NULL)
	{
		DEBUG(5,("samr_reply_set_userinfo: NULL info level\n"));
		status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;
	}

	if (status == 0x0)
	{
		switch (switch_value)
		{
			case 24:
			{
				SAM_USER_INFO_24 *id24 = info.id24;
				SamOEMhash(id24->pass, user_sess_key, True);
				status = set_user_info_24(id24, rid) ? 0 : (0xC0000000 | NT_STATUS_ACCESS_DENIED);
				break;
			}

			case 23:
			{
				SAM_USER_INFO_23 *id23 = info.id23;
				SamOEMhash(id23->pass, user_sess_key, 1);
#if DEBUG_PASSWORD
				DEBUG(100,("pass buff:\n"));
				dump_data(100, id23->pass, sizeof(id23->pass));
#endif
				dbgflush();

				status = set_user_info_23(id23, rid) ? 0 : (0xC0000000 | NT_STATUS_ACCESS_DENIED);
				break;
			}

			default:
			{
				status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;

				break;
			}
		}
	}

	make_samr_r_set_userinfo(&r_u, status);

	/* store the response in the SMB stream */
	samr_io_r_set_userinfo("", &r_u, rdata, 0);

	DEBUG(5,("samr_reply_set_userinfo: %d\n", __LINE__));

}


/*******************************************************************
 samr_reply_query_usergroups
 ********************************************************************/
uint32 _samr_query_usergroups(SAMR_Q_QUERY_USERGROUPS *q_u,
				prs_struct *rdata)
{
	SAMR_R_QUERY_USERGROUPS r_u;
	uint32 status = 0x0;

	struct sam_passwd *sam_pass;
	DOM_GID *gids = NULL;
	int num_groups = 0;
	uint32 rid;

	DEBUG(5,("samr_query_usergroups: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(pol)) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* find the user's rid */
	if (status == 0x0 && (rid = get_policy_samr_rid(get_global_hnd_cache(), &(pol))) == 0xffffffff)
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	if (status == 0x0)
	{
		become_root(True);
		sam_pass = getsam21pwrid(rid);
		unbecome_root(True);

		if (sam_pass == NULL)
		{
			status = 0xC0000000 | NT_STATUS_NO_SUCH_USER;
		}
	}

	if (status == 0x0)
	{
		DOMAIN_GRP *mem_grp = NULL;

		become_root(True);
		getusergroupsntnam(sam_pass->nt_name, &mem_grp, &num_groups);
		unbecome_root(True);

                gids = NULL;
		num_groups = make_dom_gids(mem_grp, num_groups, &gids);

		if (mem_grp != NULL)
		{
			free(mem_grp);
		}
	}

	/* construct the response */
	make_samr_r_query_usergroups(&r_u, num_groups, gids, status);

	/* store the response in the SMB stream */
	samr_io_r_query_usergroups("", &r_u, rdata, 0);

	if (gids)
	{
		free((char *)gids);
	}

	DEBUG(5,("samr_query_usergroups: %d\n", __LINE__));

}


/*******************************************************************
 opens a samr alias by rid, returns a policy handle.
 ********************************************************************/
static uint32 open_samr_alias(DOM_SID *sid, POLICY_HND *alias_pol,
				uint32 alias_rid)
{
	BOOL pol_open = False;
	uint32 status = 0x0;

	/* get a (unique) handle.  open a policy on it. */
	if (status == 0x0 && !(pol_open = open_policy_hnd(get_global_hnd_cache(), alias_pol)))
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	DEBUG(0,("TODO: verify that the alias rid exists\n"));

	/* associate a RID with the (unique) handle. */
	if (status == 0x0 && !set_policy_samr_rid(get_global_hnd_cache(), alias_pol, alias_rid))
	{
		/* oh, whoops.  don't know what error message to return, here */
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	sid_append_rid(sid, alias_rid);

	/* associate an alias SID with the (unique) handle. */
	if (status == 0x0 && !set_policy_samr_sid(get_global_hnd_cache(), alias_pol, sid))
	{
		/* oh, whoops.  don't know what error message to return, here */
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (status != 0 && pol_open)
	{
		close_policy_hnd(get_global_hnd_cache(), alias_pol);
	}

	return status;
}

/*******************************************************************
 samr_reply_create_dom_alias
 ********************************************************************/
uint32 _samr_create_dom_alias(SAMR_Q_CREATE_DOM_ALIAS *q_u,
				prs_struct *rdata)
{
	SAMR_R_CREATE_DOM_ALIAS r_u;
	DOM_SID dom_sid;
	LOCAL_GRP grp;
	POLICY_HND alias_pol;
	uint32 status = 0x0;

	bzero(&alias_pol, sizeof(alias_pol));

	DEBUG(5,("samr_create_dom_alias: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(dom_pol)) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* find the domain sid */
	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &dom_pol, &dom_sid))
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	if (!sid_equal(&dom_sid, &global_sam_sid))
	{
		status = 0xC0000000 | NT_STATUS_ACCESS_DENIED;
	}

	if (status == 0x0)
	{
		unistr2_to_ascii(grp.name, &uni_acct_desc, sizeof(grp.name)-1);
		fstrcpy(grp.comment, "");
		grp.rid = 0xffffffff;

		status = add_alias_entry(&grp) ? 0 : (0xC0000000 | NT_STATUS_ACCESS_DENIED);
	}

	if (status == 0x0)
	{
		status = open_samr_alias(&dom_sid, &alias_pol, grp.rid);
	}

	/* construct the response. */
	make_samr_r_create_dom_alias(&r_u, &alias_pol, grp.rid, status);

	/* store the response in the SMB stream */
	samr_io_r_create_dom_alias("", &r_u, rdata, 0);

	DEBUG(5,("samr_create_dom_alias: %d\n", __LINE__));

}


/*******************************************************************
 opens a samr group by rid, returns a policy handle.
 ********************************************************************/
static uint32 open_samr_group(DOM_SID *sid, POLICY_HND *group_pol,
				uint32 group_rid)
{
	BOOL pol_open = False;
	uint32 status = 0x0;

	/* get a (unique) handle.  open a policy on it. */
	if (status == 0x0 && !(pol_open = open_policy_hnd(get_global_hnd_cache(), group_pol)))
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	DEBUG(0,("TODO: verify that the group rid exists\n"));

	/* associate a RID with the (unique) handle. */
	if (status == 0x0 && !set_policy_samr_rid(get_global_hnd_cache(), group_pol, group_rid))
	{
		/* oh, whoops.  don't know what error message to return, here */
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	sid_append_rid(sid, group_rid);

	/* associate an group SID with the (unique) handle. */
	if (status == 0x0 && !set_policy_samr_sid(get_global_hnd_cache(), group_pol, sid))
	{
		/* oh, whoops.  don't know what error message to return, here */
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (status != 0 && pol_open)
	{
		close_policy_hnd(get_global_hnd_cache(), group_pol);
	}

	return status;
}

/*******************************************************************
 samr_reply_create_dom_group
 ********************************************************************/
uint32 _samr_create_dom_group(SAMR_Q_CREATE_DOM_GROUP *q_u,
				prs_struct *rdata)
{
	SAMR_R_CREATE_DOM_GROUP r_u;
	DOM_SID dom_sid;
	DOMAIN_GRP grp;
	POLICY_HND group_pol;
	uint32 status = 0x0;

	bzero(&group_pol, sizeof(group_pol));

	DEBUG(5,("samr_create_dom_group: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(pol)) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* find the domain sid */
	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &pol, &dom_sid))
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	if (!sid_equal(&dom_sid, &global_sam_sid))
	{
		status = 0xC0000000 | NT_STATUS_ACCESS_DENIED;
	}

	if (status == 0x0)
	{
		unistr2_to_ascii(grp.name, &uni_acct_desc, sizeof(grp.name)-1);
		fstrcpy(grp.comment, "");
		grp.rid = 0xffffffff;
		grp.attr = 0x07;

		status = add_group_entry(&grp) ? 0x0 : (0xC0000000 | NT_STATUS_ACCESS_DENIED);
	}

	if (status == 0x0)
	{
		status = open_samr_group(&dom_sid, &group_pol, grp.rid);
	}

	/* construct the response. */
	make_samr_r_create_dom_group(&r_u, &group_pol, grp.rid, status);

	/* store the response in the SMB stream */
	samr_io_r_create_dom_group("", &r_u, rdata, 0);

	DEBUG(5,("samr_create_dom_group: %d\n", __LINE__));

}


/*******************************************************************
 samr_reply_query_dom_info
 ********************************************************************/
uint32 _samr_query_dom_info(SAMR_Q_QUERY_DOMAIN_INFO *q_u,
				prs_struct *rdata)
{
	SAMR_R_QUERY_DOMAIN_INFO r_u;
	SAM_UNK_CTR ctr;
	uint16 switch_value = 0x0;
	uint32 status = 0x0;

	ZERO_STRUCT(r_u);
	ZERO_STRUCT(ctr);

	ctr = &ctr;

	DEBUG(5,("samr_reply_query_dom_info: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(domain_pol)) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
		DEBUG(5,("samr_reply_query_dom_info: invalid handle\n"));
	}

	if (status == 0x0)
	{
		switch (switch_value)
		{
			case 0x07:
			{
				switch_value = 0x7;
				make_unk_info7(&ctr.info.inf7);

				break;
			}
			case 0x06:
			{
				switch_value = 0x6;
				make_unk_info6(&ctr.info.inf6);

				break;
			}
			case 0x03:
			{
				switch_value = 0x3;
				make_unk_info3(&ctr.info.inf3);

				break;
			}
			case 0x02:
			{
				switch_value = 0x2;
				make_unk_info2(&ctr.info.inf2, global_sam_name, global_myname);

				break;
			}
			case 0x01:
			{
				switch_value = 0x1;
				make_unk_info1(&ctr.info.inf1);

				break;
			}
			default:
			{
				status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;
				break;
			}
		}
	}

	make_samr_r_query_dom_info(&r_u, switch_value, &ctr, status);

	/* store the response in the SMB stream */
	samr_io_r_query_dom_info("", &r_u, rdata, 0);

	DEBUG(5,("samr_query_dom_info: %d\n", __LINE__));

}


/*******************************************************************
 samr_reply_create_user
 ********************************************************************/
uint32 _samr_create_user(SAMR_Q_CREATE_USER *q_u,
				prs_struct *rdata)
{
	struct sam_passwd *sam_pass;
	fstring user_name;

	SAMR_R_CREATE_USER r_u;
	POLICY_HND pol;
	uint32 status = 0x0;
	uint32 user_rid = 0x0;
	BOOL pol_open = False;
	uint32 unk_0 = 0x30;

	/* find the machine account: tell the caller if it exists.
	   lkclXXXX i have *no* idea if this is a problem or not
	   or even if you are supposed to construct a different
	   reply if the account already exists...
	 */

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(domain_pol)) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* get a (unique) handle.  open a policy on it. */
	if (status == 0x0 && !(pol_open = open_policy_hnd(get_global_hnd_cache(), &pol)))
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	unistr2_to_ascii(user_name, &uni_name, sizeof(user_name)-1);

	sam_pass = getsam21pwntnam(user_name);

	if (sam_pass != NULL)
	{
		/* account exists: say so */
		status = 0xC0000000 | NT_STATUS_USER_EXISTS;
	}
	else
	{
		pstring err_str;
		pstring msg_str;

		if (!local_password_change(user_name, True,
		          acb_info | ACB_DISABLED | ACB_PWNOTREQ, 0xffff,
		          NULL,
		          err_str, sizeof(err_str),
		          msg_str, sizeof(msg_str)))
		{
			DEBUG(0,("%s\n", err_str));
			status = 0xC0000000 | NT_STATUS_ACCESS_DENIED;
		}
		else
		{
			sam_pass = getsam21pwntnam(user_name);
			if (sam_pass == NULL)
			{
				/* account doesn't exist: say so */
				status = 0xC0000000 | NT_STATUS_ACCESS_DENIED;
			}
			else
			{
				user_rid = sam_pass->user_rid;
				unk_0 = 0x000703ff;
			}
		}
	}

	/* associate the RID with the (unique) handle. */
	if (status == 0x0 && !set_policy_samr_rid(get_global_hnd_cache(), &pol, user_rid))
	{
		/* oh, whoops.  don't know what error message to return, here */
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (status != 0 && pol_open)
	{
		close_policy_hnd(get_global_hnd_cache(), &pol);
	}

	DEBUG(5,("samr_create_user: %d\n", __LINE__));

	make_samr_r_create_user(&r_u, &pol, unk_0, user_rid, status);

	/* store the response in the SMB stream */
	samr_io_r_create_user("", &r_u, rdata, 0);

	DEBUG(5,("samr_create_user: %d\n", __LINE__));

}


/*******************************************************************
 samr_reply_connect_anon
 ********************************************************************/
uint32 _samr_connect_anon(SAMR_Q_CONNECT_ANON *q_u,
				prs_struct *rdata)
{
	SAMR_R_CONNECT_ANON r_u;
	BOOL pol_open = False;

	/* set up the SAMR connect_anon response */

	status = 0x0;
	/* get a (unique) handle.  open a policy on it. */
	if (status == 0x0 && !(pol_open = open_policy_hnd(get_global_hnd_cache(), &(connect_pol))))
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/* associate the domain SID with the (unique) handle. */
	if (status == 0x0 && !set_policy_samr_pol_status(get_global_hnd_cache(), &(connect_pol), unknown_0))
	{
		/* oh, whoops.  don't know what error message to return, here */
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (status != 0 && pol_open)
	{
		close_policy_hnd(get_global_hnd_cache(), &(connect_pol));
	}

	DEBUG(5,("samr_connect_anon: %d\n", __LINE__));

	/* store the response in the SMB stream */
	samr_io_r_connect_anon("", &r_u, rdata, 0);

	DEBUG(5,("samr_connect_anon: %d\n", __LINE__));

}


/*******************************************************************
 samr_reply_connect
 ********************************************************************/
uint32 _samr_connect(SAMR_Q_CONNECT *q_u,
				prs_struct *rdata)
{
	SAMR_R_CONNECT r_u;
	BOOL pol_open = False;

	/* set up the SAMR connect response */

	status = 0x0;
	/* get a (unique) handle.  open a policy on it. */
	if (status == 0x0 && !(pol_open = open_policy_hnd(get_global_hnd_cache(), &(connect_pol))))
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/* associate the domain SID with the (unique) handle. */
	if (status == 0x0 && !set_policy_samr_pol_status(get_global_hnd_cache(), &(connect_pol), unknown_0))
	{
		/* oh, whoops.  don't know what error message to return, here */
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (status != 0 && pol_open)
	{
		close_policy_hnd(get_global_hnd_cache(), &(connect_pol));
	}

	DEBUG(5,("samr_connect: %d\n", __LINE__));

	/* store the response in the SMB stream */
	samr_io_r_connect("", &r_u, rdata, 0);

	DEBUG(5,("samr_connect: %d\n", __LINE__));

}


/*******************************************************************
 samr_reply_open_alias
 ********************************************************************/
uint32 _samr_open_alias(SAMR_Q_OPEN_ALIAS *q_u,
				prs_struct *rdata)
{
	SAMR_R_OPEN_ALIAS r_u;
	DOM_SID sid;
	BOOL pol_open = False;

	/* set up the SAMR open_alias response */

	status = 0x0;
	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &dom_pol, &sid))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* get a (unique) handle.  open a policy on it. */
	if (status == 0x0 && !(pol_open = open_policy_hnd(get_global_hnd_cache(), &(pol))))
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	DEBUG(0,("TODO: verify that the alias rid exists\n"));

	/* associate a RID with the (unique) handle. */
	if (status == 0x0 && !set_policy_samr_rid(get_global_hnd_cache(), &(pol), rid_alias))
	{
		/* oh, whoops.  don't know what error message to return, here */
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	sid_append_rid(&sid, rid_alias);

	/* associate an alias SID with the (unique) handle. */
	if (status == 0x0 && !set_policy_samr_sid(get_global_hnd_cache(), &(pol), &sid))
	{
		/* oh, whoops.  don't know what error message to return, here */
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (status != 0 && pol_open)
	{
		close_policy_hnd(get_global_hnd_cache(), &(pol));
	}

	DEBUG(5,("samr_open_alias: %d\n", __LINE__));

	/* store the response in the SMB stream */
	samr_io_r_open_alias("", &r_u, rdata, 0);

	DEBUG(5,("samr_open_alias: %d\n", __LINE__));

}


/*******************************************************************
 samr_reply_open_group
 ********************************************************************/
uint32 _samr_open_group(SAMR_Q_OPEN_GROUP *q_u,
				prs_struct *rdata)
{
	SAMR_R_OPEN_GROUP r_u;
	DOM_SID sid;

	DEBUG(5,("samr_open_group: %d\n", __LINE__));

	status = 0x0;

	/* find the domain sid associated with the policy handle */
	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &domain_pol, &sid))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	if (status == 0x0 && !sid_equal(&sid, &global_sam_sid))
	{
		status = 0xC0000000 | NT_STATUS_ACCESS_DENIED;
	}

	if (status == 0x0)
	{
		status = open_samr_group(&sid, &pol, rid_group);
	}

	/* store the response in the SMB stream */
	samr_io_r_open_group("", &r_u, rdata, 0);

	DEBUG(5,("samr_open_group: %d\n", __LINE__));

}


/*******************************************************************
 samr_reply_lookup_domain
 ********************************************************************/
uint32 _samr_lookup_domain(SAMR_Q_LOOKUP_DOMAIN *q_u,
				prs_struct *rdata)
{
	SAMR_R_LOOKUP_DOMAIN r_u;
	fstring domain;

	DEBUG(5,("samr_lookup_domain: %d\n", __LINE__));

	ptr_sid = 0;
	status = 0x0;

	/* find the connection policy handle */
	if (find_policy_by_hnd(get_global_hnd_cache(), &(connect_pol)) == -1)
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	if (status == 0x0)
        {
		unistr2_to_ascii(domain, &(uni_domain), sizeof(domain));
		DEBUG(5, ("Lookup Domain: %s\n", domain));

		/* check it's one of ours */
		if (strequal(domain, global_sam_name))
		{
			make_dom_sid2(&(dom_sid), &global_sam_sid);
			ptr_sid = 1;
		}
		else if (strequal(domain, "BUILTIN"))
		{
			make_dom_sid2(&(dom_sid), &global_sid_S_1_5_20);
			ptr_sid = 1;
		}
		else
		{
			status = 0xC0000000 | NT_STATUS_NO_SUCH_DOMAIN;
		}
	}

	/* store the response in the SMB stream */
	samr_io_r_lookup_domain("", &r_u, rdata, 0);

	DEBUG(5,("samr_lookup_domain: %d\n", __LINE__));
}

#endif
