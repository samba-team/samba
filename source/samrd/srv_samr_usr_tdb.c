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

static BOOL tdb_lookup_user_als(TDB_CONTEXT *tdb,
				const DOM_SID *sid,
				uint32 *num_rids,
				uint32 **rids)
{
	prs_struct key;
	prs_struct data;
	DOM_SID s;
	sid_copy(&s, sid);

	prs_init(&key, 0, 4, False);
	if (!smb_io_dom_sid("sid", &s, &key, 0))
	{
		return False;
	}

	prs_tdb_fetch(tdb, &key, &data);

	if (!samr_io_rids("rids", num_rids, rids, &data, 0))
	{
		prs_free_data(&key);
		prs_free_data(&data);
		return False;
	}

	prs_free_data(&key);
	prs_free_data(&data);

	return True;
}

static BOOL tdb_lookup_user_grps(TDB_CONTEXT *tdb,
				uint32 rid,
				uint32 *num_gids,
				DOM_GID **gids)
{
	prs_struct key;
	prs_struct data;

	prs_init(&key, 0, 4, False);
	if (!_prs_uint32("rid", &key, 0, &rid))
	{
		return False;
	}

	prs_tdb_fetch(tdb, &key, &data);

	if (!samr_io_gids("grps", num_gids, gids, &data, 0))
	{
		prs_free_data(&key);
		prs_free_data(&data);
		return False;
	}

	prs_free_data(&key);
	prs_free_data(&data);

	return True;
}

static BOOL tdb_lookup_user(TDB_CONTEXT *tdb,
				uint32 rid,
				SAM_USER_INFO_21 *usr)
{
	prs_struct key;
	prs_struct data;

	prs_init(&key, 0, 4, False);
	if (!_prs_uint32("rid", &key, 0, &rid))
	{
		return False;
	}

	prs_tdb_fetch(tdb, &key, &data);

	if (!sam_io_user_info21("usr", usr, &data, 0))
	{
		prs_free_data(&key);
		prs_free_data(&data);
		return False;
	}

	prs_free_data(&key);
	prs_free_data(&data);

	return True;
}

static BOOL tdb_store_user_grps(TDB_CONTEXT *tdb,
				uint32 rid, uint32 num_gids,
				DOM_GID *gids)
{
	prs_struct key;
	prs_struct data;

	DEBUG(10,("storing user group GIDs %x\n", rid));

	prs_init(&key, 0, 4, False);
	prs_init(&data, 0, 4, False);

	if (!_prs_uint32("rid", &key, 0, &rid) ||
	    !samr_io_gids("grps", &num_gids, &gids, &data, 0) ||
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

static BOOL tdb_store_user_als(TDB_CONTEXT *tdb,
				const DOM_SID *sid,
				uint32 num_rids,
				uint32 *rids)
{
	prs_struct key;
	prs_struct data;
	fstring tmp;
	DOM_SID s;
	sid_copy(&s, sid);

	if (DEBUGLVL(10))
	{
		DEBUG(10,("storing user alias RIDs %s\n",
		            sid_to_string(tmp, sid)));
	}

	prs_init(&key, 0, 4, False);
	prs_init(&data, 0, 4, False);

	if (!smb_io_dom_sid("sid", &s, &key, 0) ||
	    !samr_io_rids("rids", &num_rids, &rids, &data, 0) ||
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

static BOOL tdb_store_user(TDB_CONTEXT *tdb, uint32 rid, SAM_USER_INFO_21 *usr)
{
	prs_struct key;
	prs_struct data;

	DEBUG(10,("storing user %x\n", rid));

	prs_init(&key, 0, 4, False);
	prs_init(&data, 0, 4, False);

	if (!_prs_uint32("rid", &key, 0, &rid) ||
	    !sam_io_user_info21("usr", usr, &data, 0) ||
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

static BOOL tdb_set_userinfo_10(TDB_CONTEXT *tdb, uint32 rid,
				uint16 acb_info)
{
	SAM_USER_INFO_21 usr;

	if (tdb_writelock(tdb) != 0)
	{
		return False;
	}

	if (!tdb_lookup_user(tdb, rid, &usr))
	{
		tdb_writeunlock(tdb);
		return False;
	}

	usr.acb_info = acb_info;

	if (!tdb_store_user(tdb, rid, &usr))
	{
		tdb_writeunlock(tdb);
		return False;
	}

	tdb_writeunlock(tdb);
	return True;
}

static BOOL tdb_set_userinfo_pwds(TDB_CONTEXT *tdb, uint32 rid,
				const uchar lm_pwd[16], const uchar nt_pwd[16])
{
	SAM_USER_INFO_21 usr;

	if (tdb_writelock(tdb) != 0)
	{
		return False;
	}

	if (!tdb_lookup_user(tdb, rid, &usr))
	{
		tdb_writeunlock(tdb);
		return False;
	}

	memcpy(usr.lm_pwd, lm_pwd, sizeof(usr.lm_pwd));
	memcpy(usr.nt_pwd, nt_pwd, sizeof(usr.nt_pwd));

	if (!tdb_store_user(tdb, rid, &usr))
	{
		tdb_writeunlock(tdb);
		return False;
	}

	tdb_writeunlock(tdb);
	return True;
}

static BOOL tdb_set_userinfo_23(TDB_CONTEXT *tdb, uint32 rid,
				const SAM_USER_INFO_23 *usr23,
				const uchar lm_pwd[16], const uchar nt_pwd[16])
{
	SAM_USER_INFO_21 usr;

	if (tdb_writelock(tdb) != 0)
	{
		return False;
	}

	if (!tdb_lookup_user(tdb, rid, &usr))
	{
		tdb_writeunlock(tdb);
		return False;
	}

	if (!make_sam_user_info21W(&usr,
				&usr23->logon_time, 
				&usr23->logoff_time, 
				&usr23->kickoff_time, 
				&usr23->pass_last_set_time, 
				&usr23->pass_can_change_time, 
				&usr23->pass_must_change_time, 

				&usr23->uni_user_name, 
				&usr23->uni_full_name,
				&usr23->uni_home_dir,
				&usr23->uni_dir_drive,
				&usr23->uni_logon_script,
				&usr23->uni_profile_path,
				&usr23->uni_acct_desc,
				&usr23->uni_workstations,
				&usr23->uni_unknown_str,
				&usr23->uni_munged_dial,

				lm_pwd, nt_pwd,

				usr.user_rid, 
				usr23->group_rid,
				usr23->acb_info, 

				usr.unknown_3,
				usr23->logon_divs,
				&usr23->logon_hrs,
				usr23->unknown_5,
				usr.unknown_6))
	{
		tdb_writeunlock(tdb);
		return False;
	}

	if (!tdb_store_user(tdb, rid, &usr))
	{
		tdb_writeunlock(tdb);
		return False;
	}

	tdb_writeunlock(tdb);
	return True;
}

/*******************************************************************
 samr_reply_get_usrdom_pwinfo
 ********************************************************************/
uint32 _samr_get_usrdom_pwinfo(const POLICY_HND *user_pol,
				uint32 *unknown_0,
				uint32 *unknown_1)
{
	uint32 rid;
	TDB_CONTEXT *tdb = NULL;

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbrid(get_global_hnd_cache(), user_pol, &tdb,
	                                       NULL, NULL, &rid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	*unknown_0 = 0x00150000;
	*unknown_1 = 0x00000000;

	DEBUG(5,("samr_get_usrdom_pwinfo: %d\n", __LINE__));

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_reply_query_usergroups
 ********************************************************************/
uint32 _samr_query_usergroups(const POLICY_HND *pol,
				uint32 *num_groups,
				DOM_GID **gids)
{
	uint32 rid;
	TDB_CONTEXT *usr_tdb = NULL;
	TDB_CONTEXT *usg_tdb = NULL;

	(*gids) = NULL;
	(*num_groups) = 0;

	DEBUG(5,("samr_query_usergroups: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbrid(get_global_hnd_cache(), pol, &usr_tdb, 
	                                       &usg_tdb, NULL, &rid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	if (!tdb_lookup_user_grps(usg_tdb, rid, num_groups, gids))
	{
		return NT_STATUS_NO_SUCH_USER;
	}

	return NT_STATUS_NOPROBLEMO;
}
/*******************************************************************
 samr_reply_query_useraliases
 ********************************************************************/
uint32 _samr_query_useraliases(const POLICY_HND *domain_pol,
				const uint32 *ptr_sid, const DOM_SID2 *sid,
				uint32 *num_aliases, uint32 **rid)
{
	TDB_CONTEXT *tdb = NULL;
	DOM_SID dom_sid;

	DEBUG(5,("samr_query_useraliases: %d\n", __LINE__));

	(*rid) = NULL;
	(*num_aliases) = 0;

	if (sid == NULL)
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbdomsid(get_global_hnd_cache(), domain_pol,
	                     NULL, NULL, &tdb, NULL, NULL, &dom_sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

#if 0
	if (!tdb_lookup_user_als(tdb, &sid->sid, num_aliases, rid))
	{
		return NT_STATUS_NO_SUCH_USER;
	}
#endif
	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_reply_open_user
 ********************************************************************/
uint32 _samr_open_user(const POLICY_HND *domain_pol,
					uint32 access_mask, uint32 user_rid, 
					POLICY_HND *user_pol)
{
	TDB_CONTEXT *tdb_usr = NULL;
	TDB_CONTEXT *tdb_usg = NULL;
	TDB_CONTEXT *tdb_usa = NULL;
	DOM_SID dom_sid;
	SAM_USER_INFO_21 usr;

	if (!get_tdbdomsid(get_global_hnd_cache(), domain_pol,
					&tdb_usr, &tdb_usg, &tdb_usa, 
					NULL, NULL, &dom_sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	if (!tdb_lookup_user(tdb_usr, user_rid, &usr))
	{
		return NT_STATUS_NO_SUCH_USER;
	}

	return samr_open_by_tdbrid(domain_pol,
	                           tdb_usr, tdb_usg, tdb_usa, 
	                           user_pol, access_mask, user_rid);
}

/*******************************************************************
 samr_reply_query_userinfo
 ********************************************************************/
uint32 _samr_query_userinfo(const POLICY_HND *pol, uint16 switch_value,
				SAM_USERINFO_CTR *ctr)
{
	TDB_CONTEXT *tdb_usr = NULL;
	uint32 rid = 0x0;
	SAM_USER_INFO_21 usr;

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbrid(get_global_hnd_cache(), pol, &tdb_usr, 
	                                             NULL, NULL, &rid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}
	if (!tdb_lookup_user(tdb_usr, rid, &usr))
	{
		return NT_STATUS_NO_SUCH_USER;
	}

	DEBUG(5,("samr_reply_query_userinfo: rid:0x%x\n", rid));

	return make_samr_userinfo_ctr_usr21(ctr, switch_value, &usr);
}

/*******************************************************************
 set_user_info_24
 ********************************************************************/
static BOOL set_user_info_24(TDB_CONTEXT *usr_tdb, uint32 rid,
				const SAM_USER_INFO_24 *id24)
{
	static uchar nt_hash[16];
	static uchar lm_hash[16];
	UNISTR2 new_pw;
	uint32 len;

	if (!decode_pw_buffer(id24->pass, (char *)new_pw.buffer, 256, &len))
	{
		return False;
	}

	new_pw.uni_max_len = len / 2;
	new_pw.uni_str_len = len / 2;

	nt_lm_owf_genW(&new_pw, nt_hash, lm_hash);

	return tdb_set_userinfo_pwds(usr_tdb, rid, lm_hash, nt_hash);
}

/*******************************************************************
 set_user_info_12
 ********************************************************************/
static BOOL set_user_info_12(TDB_CONTEXT *usr_tdb, uint32 rid,
				const SAM_USER_INFO_12 *id12)
{
	return tdb_set_userinfo_pwds(usr_tdb, rid, id12->lm_pwd, id12->nt_pwd);
}

/*******************************************************************
 set_user_info_23
 ********************************************************************/
static BOOL set_user_info_23(TDB_CONTEXT *usr_tdb, uint32 rid,
				const SAM_USER_INFO_23 *id23)
{
	static uchar nt_hash[16];
	static uchar lm_hash[16];
	UNISTR2 new_pw;
	uint32 len;

	if (id23 == NULL)
	{
		DEBUG(5, ("set_user_info_23: NULL id23\n"));
		return False;
	}

	if (!decode_pw_buffer(id23->pass, (char*)new_pw.buffer, 256, &len))
	{
		return False;
	}

	new_pw.uni_max_len = len / 2;
	new_pw.uni_str_len = len / 2;

	nt_lm_owf_genW(&new_pw, nt_hash, lm_hash);

	return tdb_set_userinfo_23(usr_tdb, rid, id23, lm_hash, nt_hash);
}

/*******************************************************************
 samr_reply_set_userinfo
 ********************************************************************/
uint32 _samr_set_userinfo(const POLICY_HND *pol, uint16 switch_value,
				SAM_USERINFO_CTR *ctr)
{
	TDB_CONTEXT *tdb_usr = NULL;
	uchar user_sess_key[16];
	uint32 rid = 0x0;

	DEBUG(5,("samr_reply_set_userinfo: %d\n", __LINE__));

	/* find the domain rid associated with the policy handle */
	if (!get_tdbrid(get_global_hnd_cache(), pol, &tdb_usr, 
	                                       NULL, NULL, &rid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	DEBUG(5,("samr_reply_set_userinfo: rid:0x%x\n", rid));

	if (!pol_get_usr_sesskey(get_global_hnd_cache(), pol, user_sess_key))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

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
			if (!set_user_info_12(tdb_usr, rid, id12))
			{
				return NT_STATUS_ACCESS_DENIED;
			}
			break;
		}

		case 24:
		{
			SAM_USER_INFO_24 *id24 = ctr->info.id24;
			SamOEMhash(id24->pass, user_sess_key, True);
			if (!set_user_info_24(tdb_usr, rid, id24))
			{
				return NT_STATUS_ACCESS_DENIED;
			}
			break;
		}

		case 23:
		{
			SAM_USER_INFO_23 *id23 = ctr->info.id23;
			SamOEMhash(id23->pass, user_sess_key, 1);
			dump_data_pw("pass buff:\n",
			              id23->pass, sizeof(id23->pass));
			dbgflush();

			if (!set_user_info_23(tdb_usr, rid, id23))
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
static BOOL set_user_info_10(TDB_CONTEXT *usr_tdb, uint32 rid,
				const SAM_USER_INFO_10 *id16)
{
	return tdb_set_userinfo_10(usr_tdb, rid, id16->acb_info);
}

/*******************************************************************
 samr_reply_set_userinfo2
 ********************************************************************/
uint32 _samr_set_userinfo2(const POLICY_HND *pol, uint16 switch_value,
				SAM_USERINFO_CTR *ctr)
{
	TDB_CONTEXT *tdb_usr = NULL;
	uint32 rid = 0x0;

	/* find the domain sid associated with the policy handle */
	if (!get_tdbrid(get_global_hnd_cache(), pol, &tdb_usr, 
	                                       NULL, NULL, &rid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

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
			if (!set_user_info_10(tdb_usr, rid, id10))
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

static void create_user_info_21(SAM_USER_INFO_21 *usr,
				const UNISTR2 *uni_user_name,
				uint16 acb_info, uint32 user_rid,
				uint32 group_rid)
{
	time_t t = time(NULL);

	ZERO_STRUCTP(usr);

	init_nt_time(&usr->logon_time);
	init_nt_time(&usr->logoff_time);
	init_nt_time(&usr->kickoff_time);
	init_nt_time(&usr->pass_must_change_time);
	unix_to_nt_time(&usr->pass_last_set_time, t);
	unix_to_nt_time(&usr->pass_can_change_time, t);

	usr->acb_info = acb_info | ACB_DISABLED | ACB_PWNOTREQ;
	usr->user_rid = user_rid;
	usr->group_rid = group_rid;

	make_uni_hdr(&(usr->hdr_full_name   ), 0);
	make_uni_hdr(&(usr->hdr_home_dir    ), 1);
	make_uni_hdr(&(usr->hdr_dir_drive   ), 0);
	make_uni_hdr(&(usr->hdr_logon_script), 0);
	make_uni_hdr(&(usr->hdr_profile_path), 1);
	make_uni_hdr(&(usr->hdr_acct_desc   ), 0);
	make_uni_hdr(&(usr->hdr_workstations), 0);
	make_uni_hdr(&(usr->hdr_unknown_str ), 0);
	make_uni_hdr(&(usr->hdr_munged_dial ), 0);

	make_unistr2(&(usr->uni_user_name   ), "", 0);
	make_unistr2(&(usr->uni_full_name   ), "", 0);
	make_unistr2(&(usr->uni_home_dir    ), "", 1);
	make_unistr2(&(usr->uni_dir_drive   ), "", 0);
	make_unistr2(&(usr->uni_logon_script), "", 0);
	make_unistr2(&(usr->uni_profile_path), "", 1);
	make_unistr2(&(usr->uni_acct_desc   ), "", 0 );
	make_unistr2(&(usr->uni_workstations), "", 0);
	make_unistr2(&(usr->uni_unknown_str ), "", 0 );
	make_unistr2(&(usr->uni_munged_dial ), "", 0 );

	copy_unistr2(&usr->uni_user_name, uni_user_name);
	make_uni_hdr(&usr->hdr_user_name, uni_user_name->uni_str_len);

	usr->unknown_3 = 0xffffff; /* don't know */
	usr->logon_divs = 168; /* hours per week */
	usr->ptr_logon_hrs = 1;
	usr->logon_hrs.len = 21;
	memset(&usr->logon_hrs.hours, 0xff, sizeof(usr->logon_hrs.hours)); 
	usr->unknown_5 = 0x00020000; /* don't know */
	usr->unknown_6 = 0x000004ec; /* don't know */
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
	DOM_SID dom_sid;
	DOM_SID usr_sid;
	DOM_SID sid;
	DOM_SID grp_sid;
	TDB_CONTEXT *tdb_usr = NULL;
	TDB_CONTEXT *tdb_usg = NULL;
	TDB_CONTEXT *tdb_usa = NULL;

	SAM_USER_INFO_21 usr;
	uint32 status1;
	uint32 rid;
	uint32 type;
	uint32 num_rids;
	uint32 num_types;

	struct passwd *pass = NULL;
	uint32 group_rid;

	uint32 num_gids = 0;
	DOM_GID *gids = NULL;

	uint32 num_alss = 0;
	uint32 *als_rids = NULL;

	(*unknown_0) = 0x30;
	(*user_rid) = 0x0;

	/* find the machine account: tell the caller if it exists.
	   lkclXXXX i have *no* idea if this is a problem or not
	   or even if you are supposed to construct a different
	   reply if the account already exists...
	 */

	/* find the domain sid associated with the policy handle */
	if (!get_tdbdomsid(get_global_hnd_cache(), domain_pol,
					&tdb_usr, &tdb_usg, &tdb_usa,
					NULL, NULL, &dom_sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	status1 = _samr_lookup_names(domain_pol, 1,  0x3e8, 1, uni_username,

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
				DEBUG(3,("create user: unknown, ignoring\n"));
				break;
			}
		}
	}

	{
		int i;
		int n_groups = 0;
		gid_t *groups = NULL;
		fstring user_name;
		unistr2_to_ascii(user_name, uni_username, sizeof(user_name)-1);
		pass = Get_Pwnam(user_name, False);
		DEBUG(10,("create user: %s\n", user_name));
		if (pass == NULL)
		{
			DEBUG(0,("create user: no unix user named %s\n",
			          user_name));
			return NT_STATUS_ACCESS_DENIED;
		}
		get_unixgroups(user_name,pass->pw_uid,pass->pw_gid,
				&n_groups,
		       		&groups);

		for (i = 0; i < n_groups; i++)
		{
			if (sursalg_unixid_to_sam_sid(groups[i],
			                               SID_NAME_ALIAS,
			                               &grp_sid,
						       True))
			{
				uint32 grp_rid = 0xffffffff;
				if (!sid_split_rid(&grp_sid, &grp_rid))
				{
					continue;
				}
				if (sid_equal(&grp_sid, &dom_sid))
				{
					als_rids = g_renew(uint32, als_rids, num_alss+1);
					als_rids[num_alss] = grp_rid;
					num_alss++;
				}
			}
			if (sursalg_unixid_to_sam_sid(groups[i],
			                               SID_NAME_DOM_GRP,
			                               &grp_sid,
						       True))
			{
				uint32 grp_rid = 0xffffffff;
				if (!sid_split_rid(&grp_sid, &grp_rid))
				{
					continue;
				}
				if (sid_equal(&grp_sid, &global_sam_sid))
				{
					gids = g_renew(DOM_GID, gids, num_gids+1);
					gids[num_gids].g_rid = grp_rid;
					gids[num_gids].attr  = 0x7;
					num_gids++;
				}
			}
		}
	}

	/* create a User SID for the unix user */
	if (!sursalg_unixid_to_sam_sid(pass->pw_uid, SID_NAME_USER, &usr_sid,
	                               True))
	{
		DEBUG(0,("create user: unix uid %d to RID failed\n",
		          pass->pw_uid));
		return NT_STATUS_ACCESS_DENIED;
	}

	/* create a Group SID for the unix user */
	if (!sursalg_unixid_to_sam_sid(pass->pw_gid, SID_NAME_DOM_GRP, &grp_sid,
	                               True))
	{
		DEBUG(0,("create user: unix uid %d to RID failed\n",
		          pass->pw_uid));
		return NT_STATUS_ACCESS_DENIED;
	}

	sid_copy(&sid, &usr_sid);

	if (!sid_split_rid(&sid, user_rid) ||
	    !sid_equal(&dom_sid, &sid))
	{
		fstring tmp;
		DEBUG(0,("create user: invalid User SID %s\n",
		         sid_to_string(tmp, &usr_sid)));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!sid_split_rid(&grp_sid, &group_rid) ||
	    !sid_equal(&dom_sid, &grp_sid))
	{
		fstring tmp;
		DEBUG(0,("create user: invalid Group SID %s\n",
		         sid_to_string(tmp, &grp_sid)));
		return NT_STATUS_ACCESS_DENIED;
	}

	create_user_info_21(&usr, uni_username, acb_info,
	                    (*user_rid), group_rid);

	if (!tdb_store_user(tdb_usr, usr.user_rid, &usr))
	{
		/* account doesn't exist: say so */
		return NT_STATUS_ACCESS_DENIED;
	}


	if (!tdb_store_user_grps(tdb_usg, usr.user_rid, num_gids, gids))
	{
		/* account doesn't exist: say so */
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!tdb_store_user_als(tdb_usa, &usr_sid, num_alss, als_rids))
	{
		/* account doesn't exist: say so */
		return NT_STATUS_ACCESS_DENIED;
	}

	*unknown_0 = 0x000703ff;

	return samr_open_by_tdbrid(domain_pol, tdb_usr, tdb_usg,
	                           tdb_usa, 
	                           user_pol, access_mask, *user_rid);
}

