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
 samr_reply_open_domain
 ********************************************************************/
uint32 _samr_open_domain(const POLICY_HND *connect_pol,
				uint32 ace_perms,
				const DOM_SID *sid,
				POLICY_HND *domain_pol)
{
	TDB_CONTEXT *dom_tdb = NULL;
	TDB_CONTEXT *usr_tdb = NULL;
	TDB_CONTEXT *grp_tdb = NULL;
	TDB_CONTEXT *als_tdb = NULL;
	fstring usr;
	fstring grp;
	fstring als;

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbsam(get_global_hnd_cache(), connect_pol, &dom_tdb))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* get a (unique) handle.  open a policy on it. */
	if (!open_policy_hnd(get_global_hnd_cache(), domain_pol, ace_perms))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	sid_to_string(usr, sid);
	sid_to_string(grp, sid);
	sid_to_string(als, sid);
	safe_strcat(usr, ".usr.tdb", sizeof(usr)-1);
	safe_strcat(grp, ".grp.tdb", sizeof(grp)-1);
	safe_strcat(als, ".als.tdb", sizeof(als)-1);

	become_root(True);
	if (sid_equal(sid, &global_sid_S_1_5_20))
	{
		als_tdb = tdb_open(passdb_path(als),0,0,O_RDWR|O_CREAT, 0600);
	}
	if (sid_equal(sid, &global_sam_sid))
	{

		usr_tdb = tdb_open(passdb_path(usr),0,0,O_RDWR|O_CREAT, 0600);
#if 0
		grp_tdb = tdb_open(passdb_path(grp),0,0,O_RDWR|O_CREAT, 0600);
		als_tdb = tdb_open(passdb_path(als),0,0,O_RDWR|O_CREAT, 0600);
#endif
	}
	unbecome_root(True);

	if (sid_equal(sid, &global_sid_S_1_5_20))
	{
		if (als_tdb == NULL)
		{
			tdb_close(usr_tdb);
			tdb_close(grp_tdb);
			tdb_close(als_tdb);
			close_policy_hnd(get_global_hnd_cache(), domain_pol);
			return NT_STATUS_ACCESS_DENIED;
		}
	}
	if (sid_equal(sid, &global_sam_sid))
	{
		if (usr_tdb == NULL)
		{
			tdb_close(usr_tdb);
			tdb_close(grp_tdb);
			tdb_close(als_tdb);
			close_policy_hnd(get_global_hnd_cache(), domain_pol);
			return NT_STATUS_ACCESS_DENIED;
		}
#if 0
		if (grp_tdb == NULL || als_tdb == NULL)
		{
			tdb_close(usr_tdb);
			tdb_close(grp_tdb);
			tdb_close(als_tdb);
			close_policy_hnd(get_global_hnd_cache(), domain_pol);
			return NT_STATUS_ACCESS_DENIED;
		}
#endif
	}

	/* associate the domain SID with the (unique) handle. */
	if (!set_tdbdomsid(get_global_hnd_cache(), domain_pol,
	                   usr_tdb, grp_tdb, als_tdb, sid))
	{
		tdb_close(usr_tdb);
		tdb_close(grp_tdb);
		tdb_close(als_tdb);
		close_policy_hnd(get_global_hnd_cache(), domain_pol);
		return NT_STATUS_ACCESS_DENIED;
	}

	DEBUG(5,("_samr_open_domain: %d\n", __LINE__));

	return 0x0;
}

typedef struct sam_data_info
{
	SAM_ENTRY *sam;
	UNISTR2 *uni_name;
	uint32 num_sam_entries;
	uint32 start_idx;
	uint32 current_idx;;

} SAM_DATA;

/******************************************************************
makes a SAMR_R_ENUM_USERS structure.
********************************************************************/
static int tdb_user_traverse(TDB_CONTEXT *tdb,
				TDB_DATA kbuf,
				TDB_DATA dbuf,
				void *state)
{
	prs_struct ps;
	SAM_USER_INFO_21 usr;
	SAM_DATA *data = (SAM_DATA*)state;
	uint32 num_sam_entries = data->num_sam_entries + 1;
	SAM_ENTRY *sam;
	UNISTR2 *str;

	DEBUG(5,("tdb_user_traverse: idx: %d %d\n",
					data->current_idx,
					num_sam_entries));

	dump_data_pw("usr:\n", dbuf.dptr, dbuf.dsize);
	dump_data_pw("rid:\n", kbuf.dptr, kbuf.dsize);

	/* skip first requested items */
	if (data->current_idx < data->start_idx)
	{
		data->current_idx++;
		return 0x0;
	}

	data->sam = (SAM_ENTRY*)Realloc(data->sam,
	                    num_sam_entries * sizeof(data->sam[0]));
	data->uni_name = (UNISTR2*)Realloc(data->uni_name,
	                    num_sam_entries * sizeof(data->uni_name[0]));

	if (data->sam == NULL || data->uni_name == NULL)
	{
		DEBUG(0,("NULL pointers in tdb_user_traverse\n"));
		return -1;
	}

	sam = &data->sam[data->num_sam_entries];
	str = &data->uni_name[data->num_sam_entries];

	ZERO_STRUCTP(sam);
	ZERO_STRUCTP(str);

	prs_create(&ps, dbuf.dptr, dbuf.dsize, 4, True);

	if (sam_io_user_info21("usr", &usr, &ps, 0))
	{
		sam->rid = usr.user_rid;
		copy_unistr2(str, &usr.uni_user_name);
		make_uni_hdr(&sam->hdr_name, str->uni_str_len);

		data->num_sam_entries++;
	}

	return 0x0;
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
	TDB_CONTEXT *sam_tdb = NULL;
	SAM_DATA state;

	/* find the domain sid associated with the policy handle */
	if (!get_tdbdomsid(get_global_hnd_cache(), pol, &sam_tdb,
					NULL, NULL, NULL))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	DEBUG(5,("samr_reply_enum_users:\n"));

	ZERO_STRUCT(state);

	state.start_idx = (*start_idx);
	tdb_traverse(sam_tdb, tdb_user_traverse, (void*)&state);

	(*sam) = state.sam;
	(*uni_acct_name) = state.uni_name;
	(*start_idx) += state.num_sam_entries;
	(*num_sam_users) = state.num_sam_entries;

	return 0x0;
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
	TDB_CONTEXT *tdb = NULL;

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbsid(get_global_hnd_cache(), pol, &tdb, &sid))
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

	return 0x0;
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
	TDB_CONTEXT *tdb = NULL;

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbsid(get_global_hnd_cache(), pol, &tdb, &sid))
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

	return 0x0;
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
	int total_entries;

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
			safe_free(grps);
			return NT_STATUS_INVALID_INFO_CLASS;
		}
	}

	DEBUG(5,("samr_reply_query_dispinfo: %d\n", __LINE__));

	safe_free(sam_grps);
	safe_free(grps);

	if ((*num_entries) < num_sam_entries)
	{
		return STATUS_MORE_ENTRIES;
	}

	return 0x0;
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
	TDB_CONTEXT *tdb = NULL;
	int i;
	int num_rids = num_names1;
	DOM_SID pol_sid;
	fstring tmp;
	BOOL found_one = False;

	DEBUG(5,("samr_lookup_names: %d\n", __LINE__));

	if (!get_tdbsid(get_global_hnd_cache(), pol, &tdb, &pol_sid))
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

	return 0x0;
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
uint32 _samr_lookup_rids(const POLICY_HND *pol, uint32 flags,
					uint32 num_rids, const uint32 *rids,
					uint32 *num_names,
					UNIHDR **hdr_name, UNISTR2** uni_name,
					uint32 **types)
{
	TDB_CONTEXT *tdb = NULL;
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

	if (!get_tdbsid(get_global_hnd_cache(), pol, &tdb, &pol_sid))
	{
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	(*types) = malloc(num_rids * sizeof(**types));

	if ((*types) == NULL)
	{
		return NT_STATUS_NO_MEMORY;
	}


	for (i = 0; i < num_rids; i++)
	{
		uint32 status1;
		DOM_SID sid;
		sid_copy(&sid, &pol_sid);
		sid_append_rid(&sid, rids[i]);

		status1 = lookup_sid(&sid, grp_names[i], &(*types)[i]);

		if (status1 == 0)
		{
			found_one = True;
		}
		else
		{
			(*types)[i] = SID_NAME_UNKNOWN;
		}
	}

	if (!found_one)
	{
		return NT_STATUS_NONE_MAPPED;
	}

	(*num_names) = num_rids;
	make_samr_lookup_rids(num_rids, grp_names, hdr_name, uni_name);

	return 0x0;
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

	return 0x0;
}

