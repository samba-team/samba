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

static BOOL tdb_create_user(TDB_CONTEXT *tdb, uint32 rid, SAM_USER_INFO_21 *usr)
{
	prs_struct key;
	prs_struct data;

	DEBUG(10,("creating user %x\n", rid));

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

/*******************************************************************
 samr_reply_unknown_2c
 ********************************************************************/
uint32 _samr_unknown_2c(const POLICY_HND *user_pol,
				uint32 *unknown_0,
				uint32 *unknown_1)
{
	uint32 rid;
	DOM_SID sid;
	TDB_CONTEXT *tdb = NULL;

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbsid(get_global_hnd_cache(), user_pol, &tdb, &sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	sid_split_rid(&sid, &rid);

	*unknown_0 = 0x00150000;
	*unknown_1 = 0x00000000;

	DEBUG(5,("samr_unknown_2c: %d\n", __LINE__));

	return 0x0;
}

/*******************************************************************
 samr_reply_unknown_3
 ********************************************************************/
uint32 _samr_unknown_3(const POLICY_HND *user_pol, SAM_SID_STUFF *sid_stuff)
{
	DOM_SID usr_sid;
	TDB_CONTEXT *tdb = NULL;

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbsid(get_global_hnd_cache(), user_pol, &tdb, &usr_sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	SMB_ASSERT_ARRAY(usr_sid.sub_auths, usr_sid.num_auths+1);

	/* maybe need another 1 or 2 (S-1-5-0x20-0x220 and S-1-5-20-0x224) */
	/* these two are DOMAIN_ADMIN and DOMAIN_ACCT_OP group RIDs */
	make_dom_sid3(&sid_stuff->sid[0], 0x035b, 0x0002, &global_sid_S_1_1);
	make_dom_sid3(&sid_stuff->sid[1], 0x0044, 0x0002, &usr_sid);

	make_sam_sid_stuff(sid_stuff, 
				0x0001, 0x8004,
				0x00000014, 0x0002, 0x0070,
				2);

	DEBUG(5,("samr_unknown_3: %d\n", __LINE__));

	return 0x0;
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
	TDB_CONTEXT *tdb = NULL;

	DEBUG(5,("samr_query_usergroups: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbsid(get_global_hnd_cache(), pol, &tdb, &sid))
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

	return 0x0;
}
/*******************************************************************
 samr_reply_query_useraliases
 ********************************************************************/
uint32 _samr_query_useraliases(const POLICY_HND *pol,
				const uint32 *ptr_sid, const DOM_SID2 *sid,
				uint32 *num_aliases, uint32 **rid)
{
	TDB_CONTEXT *tdb = NULL;
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
	if (!get_tdbsid(get_global_hnd_cache(), pol, &tdb, &dom_sid))
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

	return 0x0;
}

/*******************************************************************
 samr_reply_open_user
 ********************************************************************/
uint32 _samr_open_user(const POLICY_HND *domain_pol,
					uint32 access_mask, uint32 user_rid, 
					POLICY_HND *user_pol)
{
	TDB_CONTEXT *tdb_usr = NULL;
	DOM_SID dom_sid;
	SAM_USER_INFO_21 usr;

	if (!get_tdbdomsid(get_global_hnd_cache(), domain_pol,
					&tdb_usr, NULL, NULL, &dom_sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	if (!tdb_lookup_user(tdb_usr, user_rid, &usr))
	{
		return NT_STATUS_NO_SUCH_USER;
	}

	return samr_open_by_tdbrid(tdb_usr, user_pol, access_mask, user_rid);
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
	if (!get_tdbrid(get_global_hnd_cache(), pol, &tdb_usr, &rid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}
	if (!tdb_lookup_user(tdb_usr, rid, &usr))
	{
		return NT_STATUS_NO_SUCH_USER;
	}

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
		case 21:
		{
			ctr->info.id = (SAM_USER_INFO_21*)Realloc(NULL,
					 sizeof(*ctr->info.id21));
			if (ctr->info.id == NULL)
			{
				return NT_STATUS_NO_MEMORY;
			}
			memcpy(ctr->info.id21, &usr, sizeof(usr));
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
	TDB_CONTEXT *tdb = NULL;
	uchar user_sess_key[16];
	uint32 rid = 0x0;
	DOM_SID sid;

	DEBUG(5,("samr_reply_set_userinfo: %d\n", __LINE__));

	/* search for the handle */
	if (find_policy_by_hnd(get_global_hnd_cache(), pol) == -1)
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	if (!cli_get_usr_sesskey(pol, user_sess_key))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbsid(get_global_hnd_cache(), pol, &tdb, &sid))
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

	return 0x0;
}

/*******************************************************************
 set_user_info_16
 ********************************************************************/
static BOOL set_user_info_16(const SAM_USER_INFO_16 *id16, uint32 rid)
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
uint32 _samr_set_userinfo2(const POLICY_HND *pol, uint16 switch_value,
				SAM_USERINFO2_CTR *ctr)
{
	DOM_SID sid;
	TDB_CONTEXT *tdb = NULL;
	uint32 rid = 0x0;

	DEBUG(5,("samr_reply_set_userinfo2: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbsid(get_global_hnd_cache(), pol, &tdb, &sid))
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
			SAM_USER_INFO_16 *id16 = ctr->info.id16;
			if (!set_user_info_16(id16, rid))
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

	return 0x0;
}

static void create_user_info_21(SAM_USER_INFO_21 *usr,
				const UNISTR2 *uni_user_name,
				uint16 acb_info, uint32 user_rid)
{
	ZERO_STRUCTP(usr);

	usr->acb_info = acb_info | ACB_DISABLED | ACB_PWNOTREQ;
	usr->user_rid = user_rid;
	copy_unistr2(&usr->uni_user_name, uni_user_name);
	make_uni_hdr(&usr->hdr_user_name, uni_user_name->uni_str_len);
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
	TDB_CONTEXT *tdb_usr = NULL;
	struct passwd *pass = NULL;

	SAM_USER_INFO_21 usr;
	uint32 status1;
	uint32 rid;
	uint32 type;
	uint32 num_rids;
	uint32 num_types;

	(*unknown_0) = 0x30;
	(*user_rid) = 0x0;

	/* find the machine account: tell the caller if it exists.
	   lkclXXXX i have *no* idea if this is a problem or not
	   or even if you are supposed to construct a different
	   reply if the account already exists...
	 */

	/* find the domain sid associated with the policy handle */
	if (!get_tdbdomsid(get_global_hnd_cache(), domain_pol,
					&tdb_usr, NULL, NULL, &dom_sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	status1 = _samr_lookup_names(domain_pol, 1,  0x3e8, 1, uni_username,

			&num_rids,
			&rid,
			&num_types,
			&type);

	if (status1 == 0x0)
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
			
	}

	/* create a SID for the unix user */
	if (!sursalg_unixid_to_sam_sid(pass->pw_uid, SID_NAME_USER, &usr_sid,
	                               True))
	{
		DEBUG(0,("create user: unix uid %d to RID failed\n",
		          pass->pw_uid));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!sid_split_rid(&usr_sid, user_rid) ||
	    !sid_equal(&dom_sid, &usr_sid))
	{
		fstring tmp;
		DEBUG(0,("create user: invalid SID %s\n",
		         sid_to_string(tmp, &usr_sid)));
		return NT_STATUS_ACCESS_DENIED;
	}

	create_user_info_21(&usr, uni_username, acb_info, (*user_rid));

	if (!tdb_create_user(tdb_usr, usr.user_rid, &usr))
	{
		/* account doesn't exist: say so */
		return NT_STATUS_ACCESS_DENIED;
	}

	*unknown_0 = 0x000703ff;

	return samr_open_by_tdbrid(tdb_usr, user_pol, access_mask, *user_rid);
}

