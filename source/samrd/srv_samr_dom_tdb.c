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
#include "rpc_parse.h"
#include "sids.h"

extern int DEBUGLEVEL;

typedef struct sam_data21_info
{
	SAM_USER_INFO_21 *usr;
	uint32 num_sam_entries;
	uint32 start_idx;
	uint32 current_idx;;

} SAM_DATA_21;

/******************************************************************
makes a SAMR_R_ENUM_USERS structure.
********************************************************************/
static int tdb_user21_traverse(TDB_CONTEXT *tdb,
				TDB_DATA kbuf,
				TDB_DATA dbuf,
				void *state)
{
	prs_struct ps;
	SAM_USER_INFO_21 *usr;
	SAM_DATA_21 *data = (SAM_DATA_21*)state;
	uint32 num_sam_entries = data->num_sam_entries + 1;

	DEBUG(5,("tdb_user_traverse: idx: %d %d\n",
					data->current_idx,
					num_sam_entries));

	dump_data_pw("usr:\n", dbuf.dptr, dbuf.dsize);
	dump_data_pw("rid:\n", kbuf.dptr, kbuf.dsize);

	/* skip first requested items */
	if (data->current_idx < data->start_idx)
	{
		data->current_idx++;
		return 0;
	}

	data->usr = (SAM_USER_INFO_21*)Realloc(data->usr,
	                    num_sam_entries * sizeof(data->usr[0]));

	if (data->usr == NULL)
	{
		DEBUG(0,("NULL pointers in tdb_user21_traverse\n"));
		return -1;
	}

	prs_create(&ps, dbuf.dptr, dbuf.dsize, 4, True);

	usr = &data->usr[data->num_sam_entries];
	if (sam_io_user_info21("usr", usr, &ps, 0))
	{
		data->num_sam_entries++;
	}

	return 0;
}

static uint32 open_dom_dbs(const DOM_SID *sid, int perms,
			TDB_CONTEXT **usr_tdb,
			TDB_CONTEXT **grp_tdb,
			TDB_CONTEXT **als_tdb)
{
	fstring usr;
	fstring grp;
	fstring als;
	fstring tmp;

	sid_to_string(tmp, sid);

	slprintf(usr, sizeof(usr)-1, "%s.usr.tdb", tmp);
	slprintf(als, sizeof(als)-1, "%s.als.tdb", tmp);
	slprintf(grp, sizeof(grp)-1, "%s.grp.tdb", tmp);

	DEBUG(10,("opening domain %s with ", tmp));
	DEBUGADD(10, ("rdonly: %s ", BOOLSTR(IS_BITS_SET_ALL(perms, O_RDONLY))));
	DEBUGADD(10, ("wronly: %s", BOOLSTR(IS_BITS_SET_ALL(perms, O_WRONLY))));
	DEBUGADD(10, ("rdwr: %s", BOOLSTR(IS_BITS_SET_ALL(perms, O_RDWR))));
	DEBUGADD(10, ("\n"));

	(*usr_tdb) = tdb_open(passdb_path(usr),0,0,perms, 0644);
	(*grp_tdb) = tdb_open(passdb_path(grp),0,0,perms, 0644);
	(*als_tdb) = tdb_open(passdb_path(als),0,0,perms, 0644);
	if ((*usr_tdb) == NULL || (*grp_tdb) == NULL || (*als_tdb) == NULL)
	{
		tdb_close(*usr_tdb);
		tdb_close(*grp_tdb);
		tdb_close(*als_tdb);
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_NOPROBLEMO;
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

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbsam(get_global_hnd_cache(), connect_pol, &dom_tdb))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* get a (unique) handle.  open a policy on it. */
	if (!open_policy_hnd(get_global_hnd_cache(),
		get_sec_ctx(), domain_pol, ace_perms))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	if (ace_perms == SEC_RIGHTS_MAXIMUM_ALLOWED)
	{
		uint32 status;

		DEBUG(10,("_samr_open_domain: max perms requested\n"));

		status = open_dom_dbs(sid, O_RDWR,
		                      &usr_tdb, &grp_tdb, &als_tdb);
		if (status != 0x0)
		{
			status = open_dom_dbs(sid, O_RDONLY,
					      &usr_tdb, &grp_tdb, &als_tdb);
		}
		if (status != 0x0)
		{
			return status;
		}
	}
	else
	{
		int perms = 0;
		BOOL perms_read;
		BOOL perms_write;
		uint32 status;

		perms_write = IS_BITS_SET_SOME(ace_perms,
		                SEC_RIGHTS_WRITE_OWNER|SEC_RIGHTS_WRITE_DAC);
		perms_read = IS_BITS_SET_ALL(ace_perms, SEC_RIGHTS_READ);

		if (perms_write              ) perms = O_WRONLY;
		if (perms_read               ) perms = O_RDONLY;
		if (perms_write && perms_read) perms = O_RDWR;

		status = open_dom_dbs(sid, perms,
		                      &usr_tdb, &grp_tdb, &als_tdb);
		if (status != 0x0)
		{
			return status;
		}
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

	return NT_STATUS_NOPROBLEMO;
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

	DEBUG(5,("tdb_user21_traverse: idx: %d %d\n",
					data->current_idx,
					num_sam_entries));

	dump_data_pw("usr:\n", dbuf.dptr, dbuf.dsize);
	dump_data_pw("rid:\n", kbuf.dptr, kbuf.dsize);

	/* skip first requested items */
	if (data->current_idx < data->start_idx)
	{
		data->current_idx++;
		return 0;
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

	return 0;
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
	BOOL ret = False;
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
#if 0
	ret = enumdomgroups(&grps, &num_entries);
#endif
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
	TDB_CONTEXT *als_tdb = NULL;

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbdomsid(get_global_hnd_cache(), pol,
	                   NULL, NULL, &als_tdb, &sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	sid_to_string(sid_str, &sid);

	DEBUG(5,("samr_reply_enum_dom_aliases: sid %s\n", sid_str));

	/* well-known aliases */
	if (sid_equal(&sid, &global_sid_S_1_5_20))
	{
		BOOL ret = True;
		/* builtin aliases */

		become_root(True);
#if 0
		ret = enumdombuiltins(&alss, &num_entries);
#endif
		unbecome_root(True);
		if (!ret)
		{
			return NT_STATUS_ACCESS_DENIED;
		}
	}
	else if (sid_equal(&sid, &global_sam_sid))
	{
		BOOL ret = True;
		/* local aliases */

		become_root(True);
#if 0
		ret = enumdomaliases(&alss, &num_entries);
#endif
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
	SAM_USER_INFO_21 *pass = NULL;
	DOMAIN_GRP *grps = NULL;
	DOMAIN_GRP *sam_grps = NULL;
	uint16 acb_mask = ACB_NORMAL;
	int num_sam_entries = 0;
	int total_entries;

	TDB_CONTEXT *sam_tdb = NULL;

	/* find the domain sid associated with the policy handle */
	if (!get_tdbdomsid(get_global_hnd_cache(), domain_pol, &sam_tdb,
					NULL, NULL, NULL))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

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
			SAM_DATA_21 state;
			ZERO_STRUCT(state);

			state.start_idx = start_idx;
			total_entries = tdb_traverse(sam_tdb,
			                             tdb_user21_traverse,
			                             (void*)&state);

			pass = state.usr;
			start_idx += state.num_sam_entries;
			num_sam_entries = state.num_sam_entries;

			break;
		}
		case 0x3:
		case 0x5:
		{
			BOOL ret = True;

			become_root(True);
#if 0
			ret = enumdomgroups(&sam_grps, &num_sam_entries);
#endif
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
			safe_free(pass);
			return NT_STATUS_INVALID_INFO_CLASS;
		}
	}

	DEBUG(5,("samr_reply_query_dispinfo: %d\n", __LINE__));

	safe_free(sam_grps);
	safe_free(grps);
	safe_free(pass);

	if ((*num_entries) < num_sam_entries)
	{
		return STATUS_MORE_ENTRIES;
	}

	return NT_STATUS_NOPROBLEMO;
}

typedef struct tdb_name_info
{
	const UNISTR2 *uni_name;
	uint32 *rids;
	uint32 *types;
	uint32 num_names;
	BOOL found_one;

} TDB_NAME_INFO;

/******************************************************************
tdb_userlookup_names
********************************************************************/
static int tdb_userlookup_names(TDB_CONTEXT *tdb,
				TDB_DATA kbuf,
				TDB_DATA dbuf,
				void *state)
{
	prs_struct ps;
	SAM_USER_INFO_21 usr;
	TDB_NAME_INFO *data = (TDB_NAME_INFO*)state;
	uint32 rid;
	int i;

	DEBUG(5,("tdb_userlookup_names\n"));

	dump_data_pw("usr:\n", dbuf.dptr, dbuf.dsize);
	dump_data_pw("rid:\n", kbuf.dptr, kbuf.dsize);

	prs_create(&ps, dbuf.dptr, dbuf.dsize, 4, True);
	if (!sam_io_user_info21("usr", &usr, &ps, 0))
	{
		DEBUG(5,("tdb_userlookup_names: user convert failed\n"));
		return 0;
	}
	prs_create(&ps, kbuf.dptr, kbuf.dsize, 4, True);
	if (!_prs_uint32("rid", &ps, 0, &rid))
	{
		DEBUG(5,("tdb_userlookup_names: rid convert failed\n"));
		return 0;
	}

	for (i = 0; i < data->num_names; i++)
	{
		const UNISTR2 *str = &data->uni_name[i];
		if (unistr2equal(str, &usr.uni_user_name))
		{
			DEBUG(10,("found user rid[i]: %d\n", i));

			data->types[i] = SID_NAME_USER;
			data->rids[i] = rid;
			data->found_one = True;

			return 0;
		}
	}

	return 0;
}

/*******************************************************************
 samr_reply_lookup_names
 ********************************************************************/
uint32 _samr_lookup_names(const POLICY_HND *dom_pol,
				
			uint32 num_names,
			uint32 flags,
			uint32 ptr,
			const UNISTR2 *uni_name,

			uint32 *num_rids,
			uint32 rid[MAX_SAM_ENTRIES],
			uint32 *num_types,
			uint32 type[MAX_SAM_ENTRIES])
{
	TDB_CONTEXT *usr_tdb = NULL;
	DOM_SID dom_sid;
	TDB_NAME_INFO state;

	DEBUG(5,("samr_lookup_names: %d\n", __LINE__));

	if (!get_tdbdomsid(get_global_hnd_cache(), dom_pol,
	                   &usr_tdb, NULL, NULL, &dom_sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* prepare memory, ready for state-based traversion */

	if (num_names > MAX_SAM_ENTRIES)
	{
		num_names = MAX_SAM_ENTRIES;
	}

	state.found_one = False;
	state.num_names = num_names;
	state.rids = rid;
	state.types = type;
	state.uni_name = uni_name;

	if (state.rids == NULL ||
	    state.types == NULL ||
	    state.uni_name == NULL)
	{
		return NT_STATUS_NO_MEMORY;
	}

	/* lookups */
	tdb_traverse(usr_tdb, tdb_userlookup_names, (void*)&state);

	if (!state.found_one)
	{
		return NT_STATUS_NONE_MAPPED;
	}

	(*num_types) = num_names;
	(*num_rids) = num_names;

	return NT_STATUS_NOPROBLEMO;
}

typedef struct tdb_rid_info
{
	const uint32 *rids;
	uint32 *types;
	UNIHDR *hdr_name;
	UNISTR2 *uni_name;
	uint32 num_rids;
	BOOL found_one;

} TDB_RID_INFO;

/******************************************************************
tdb_userlookup_rids
********************************************************************/
static int tdb_userlookup_rids(TDB_CONTEXT *tdb,
				TDB_DATA kbuf,
				TDB_DATA dbuf,
				void *state)
{
	prs_struct ps;
	SAM_USER_INFO_21 usr;
	TDB_RID_INFO *data = (TDB_RID_INFO*)state;
	uint32 rid;
	int i;

	DEBUG(5,("tdb_userlookup_rids\n"));

	dump_data_pw("usr:\n", dbuf.dptr, dbuf.dsize);
	dump_data_pw("rid:\n", kbuf.dptr, kbuf.dsize);

	prs_create(&ps, dbuf.dptr, dbuf.dsize, 4, True);
	if (!sam_io_user_info21("usr", &usr, &ps, 0))
	{
		DEBUG(5,("tdb_userlookup_rids: user convert failed\n"));
		return 0;
	}
	prs_create(&ps, kbuf.dptr, kbuf.dsize, 4, True);
	if (!_prs_uint32("rid", &ps, 0, &rid))
	{
		DEBUG(5,("tdb_userlookup_rids: rid convert failed\n"));
		return 0;
	}

	for (i = 0; i < data->num_rids; i++)
	{
		if (rid == data->rids[i])
		{
			UNISTR2 *str = &data->uni_name[i];
			UNIHDR  *hdr = &data->hdr_name[i];

			DEBUG(10,("found user rid[i]: %d\n", i));

			data->types[i] = SID_NAME_USER;
			copy_unistr2(str, &usr.uni_user_name);
			make_uni_hdr(hdr, str->uni_str_len);

			data->found_one = True;

			return 0;
		}
	}

	return 0;
}
/*******************************************************************
 samr_reply_lookup_rids
 ********************************************************************/
uint32 _samr_lookup_rids(const POLICY_HND *dom_pol,
				uint32 num_rids, uint32 flags,
				const uint32 *rids,
				uint32 *num_names,
				UNIHDR **hdr_name, UNISTR2** uni_name,
				uint32 **types)
{
	TDB_CONTEXT *usr_tdb = NULL;
	DOM_SID dom_sid;
	TDB_RID_INFO state;

	DEBUG(5,("samr_lookup_rids: %d\n", __LINE__));

	if (!get_tdbdomsid(get_global_hnd_cache(), dom_pol,
	                   &usr_tdb, NULL, NULL, &dom_sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* prepare memory, ready for state-based traversion */

	state.found_one = False;
	state.num_rids = num_rids;
	state.rids = rids;
	state.types = malloc(num_rids * sizeof(*state.types));
	state.hdr_name = (UNIHDR*)malloc(num_rids * sizeof(*state.hdr_name));
	state.uni_name = (UNISTR2*)malloc(num_rids * sizeof(*state.uni_name));

	if (state.types == NULL ||
	    state.hdr_name == NULL ||
	    state.uni_name == NULL)
	{
		safe_free(state.types);
		safe_free(state.hdr_name);
		safe_free(state.uni_name);

		return NT_STATUS_NO_MEMORY;
	}

	/* lookups */
	tdb_traverse(usr_tdb, tdb_userlookup_rids, (void*)&state);

	if (!state.found_one)
	{
		safe_free(state.types);
		safe_free(state.hdr_name);
		safe_free(state.uni_name);

		return NT_STATUS_NONE_MAPPED;
	}

	(*num_names) = num_rids;
	(*types) = state.types;
	(*hdr_name) = state.hdr_name;
	(*uni_name) = state.uni_name;

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

