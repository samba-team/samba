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

	return 0x0;
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
	TDB_CONTEXT *tdb_dom = NULL;
	struct sam_passwd *sam_pass;
	DOM_SID sid;
	TDB_CONTEXT *tdb_usr = NULL;

	/* set up the SAMR open_user response */
	bzero(user_pol->data, POL_HND_SIZE);

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbsid(get_global_hnd_cache(), domain_pol, &tdb_dom, &sid))
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

	return samr_open_by_tdbsid(tdb_usr, &sid, user_pol, access_mask, user_rid);
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
uint32 _samr_query_userinfo(const POLICY_HND *pol, uint16 switch_value,
				SAM_USERINFO_CTR *ctr)
{
	TDB_CONTEXT *tdb = NULL;
	uint32 rid = 0x0;
	DOM_SID group_sid;

	/* find the policy handle.  open a policy on it. */
	if (!get_tdbsid(get_global_hnd_cache(), pol, &tdb, &group_sid))
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
	TDB_CONTEXT *dom_tdb = NULL;
	TDB_CONTEXT *tdb_usr = NULL;

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
	if (!get_tdbsid(get_global_hnd_cache(), domain_pol, &dom_tdb, &sid))
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

	return samr_open_by_tdbsid(tdb_usr, &sid, user_pol, access_mask, *user_rid);
}

