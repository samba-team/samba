/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Sander Striker               2000
 *  Copyright (C) Luke Howard                  2000
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

#ifdef WITH_NT5LDAP

#include "nterr.h"
#include "sids.h"
#include "ldapdb.h"

extern int DEBUGLEVEL;

static BOOL nt5ldap_lookup_user(LDAPDB *hds,
				uint32 rid,
				SAM_USER_INFO_21 *usr)
{
	if (!ldapdb_lookup_by_rid(hds, rid))
	{
		return False;
	}

	return nt5ldap_make_sam_user_info21(hds, usr);
}

static BOOL nt5ldap_set_userinfo_16(LDAPDB *hds, uint32 rid,
				uint16 acb_info)
{
	LDAPMod **mods = NULL;
	pstring dn;

	if (!ldapdb_rid_to_dn(hds, rid, dn))
	{
		return False;
	}

	if (!ldapdb_queue_uint32_mod(&mods, LDAP_MOD_REPLACE, "userAccountControl",
		pwdb_acct_ctrl_to_ad(acb_info)))
	{
		return False;
	}

	return ldapdb_commit(hds, dn, mods, False);
}

static BOOL nt5ldap_set_userinfo_24(LDAPDB *hds, uint32 rid,
				const uchar lm_pwd[16], const uchar nt_pwd[16])
{
	LDAPMod **mods = NULL;
	pstring dn;
	struct berval *bv;

	if (!ldapdb_rid_to_dn(hds, rid, dn))
	{
		return False;
	}

	if (dbcspwd_to_berval(lm_pwd, &bv))
	{
		if (!ldapdb_queue_mod_len(&mods, LDAP_MOD_REPLACE, "dBCSPwd", bv))
		{
			ber_bvfree(bv);
			return False;
		}
	}

	if (unicodepwd_to_berval(nt_pwd, &bv))
	{
		if (!ldapdb_queue_mod_len(&mods, LDAP_MOD_REPLACE, "unicodePwd", bv))
		{
			ber_bvfree(bv);
			return False;
		}
	}

	return ldapdb_commit(hds, dn, mods, False);
}

static BOOL nt5ldap_set_userinfo_23(LDAPDB *hds, uint32 rid,
				const SAM_USER_INFO_23 *usr23,
				const uchar lm_pwd[16], const uchar nt_pwd[16])
{
	SAM_USER_INFO_21 usr;
	LDAPMod **mods = NULL;
	fstring dn;

	if (!ldapdb_rid_to_dn(hds, rid, dn))
	{
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
		return False;
	}

	DEBUG(10,("storing user %x\n", rid));

	if (!nt5ldap_sam_user_info21_mods(&usr, &mods, LDAP_MOD_REPLACE, NULL, 0, NULL))
	{
		return False;
	}

	return ldapdb_commit(hds, dn, mods, False);
}

/*******************************************************************
 samr_reply_get_usrdom_pwinfo
 ********************************************************************/
uint32 _samr_get_usrdom_pwinfo(const POLICY_HND *user_pol,
				uint16 *unknown_0,
				uint16 *unknown_1,
				uint32 *unknown_2)
{
	uint32 rid;
	LDAPDB *hds = NULL;

	/* find the policy handle.  open a policy on it. */
	if (!get_nt5ldaprid(get_global_hnd_cache(), user_pol, &hds, &rid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	*unknown_0 = 0x0000;
	*unknown_1 = 0x0015;
	*unknown_2 = 0x00000000;

	DEBUG(5,("samr_get_usrdom_pwinfo: %d\n", __LINE__));

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 samr_reply_query_sec_obj
 ********************************************************************/
uint32 _samr_query_sec_obj(const POLICY_HND *pol, SEC_DESC_BUF *buf)
{
	uint32 rid;
	DOM_SID usr_sid;
	DOM_SID adm_sid;
	DOM_SID glb_sid;
	SEC_ACL *dacl = NULL;
	SEC_ACE *dace = NULL;
	SEC_ACCESS mask;
	SEC_DESC *sec = NULL;
	int len;

	LDAPDB *hds = NULL;

	/* find the policy handle.  open a policy on it. */
	if (!get_nt5ldaprid(get_global_hnd_cache(), user_pol, &hds, &rid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	sid_copy(&usr_sid, &global_sam_sid);
	sid_append_rid(&usr_sid, rid);

	sid_copy(&adm_sid, &global_sid_S_1_5_20);
	sid_append_rid(&adm_sid, BUILTIN_ALIAS_RID_ADMINS);

	sid_copy(&glb_sid, &global_sid_S_1_1);
	sid_append_rid(&glb_sid, 0x0);

	dacl = malloc(sizeof(*dacl));
	dace = malloc(3 * sizeof(*dace));
	sec = malloc(sizeof(*sec));

	if (dacl == NULL || dace == NULL || sec == NULL)
	{
		safe_free(dacl);
		safe_free(dace);
		safe_free(sec);
		return NT_STATUS_NO_MEMORY;
	}


	mask.mask = 0x20044;
	make_sec_ace(&dace[0], &usr_sid         , 0, mask, 0);
	mask.mask = 0xf07ff;
	make_sec_ace(&dace[1], &adm_sid         , 0, mask, 0);
	mask.mask = 0x2035b;
	make_sec_ace(&dace[2], &glb_sid, 0, mask, 0);

	make_sec_acl(dacl, 2, 3, dace);

	len = make_sec_desc(sec, 1,
	              SEC_DESC_DACL_PRESENT|SEC_DESC_SELF_RELATIVE,
	              NULL, NULL, NULL, dacl);

	make_sec_desc_buf(buf, len, sec);
	buf->undoc = 0x1;

	DEBUG(5,("samr_query_sec_obj: %d\n", __LINE__));

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
	struct sam_passwd *sam_pass = NULL;
	uint32 rid;
	BOOL ret = False;
	LDAPDB *hds = NULL;

	DEBUG(5,("samr_query_usergroups: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (!get_nt5ldaprid(get_global_hnd_cache(), pol, &hds, &rid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	become_root(True);
#if 0
	sam_pass = getsam21pwrid(rid);
#endif
	unbecome_root(True);

	if (sam_pass == NULL)
	{
		return NT_STATUS_NO_SUCH_USER;
	}

	become_root(True);
#if 0
	ret = getusergroupsntnam(sam_pass->nt_name, &mem_grp, num_groups);
#endif
	unbecome_root(True);

	if (!ret)
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	(*gids) = NULL;
#if 0
	(*num_groups) = make_dom_gids(mem_grp, *num_groups, gids);
#endif

	if (mem_grp != NULL)
	{
		free(mem_grp);
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
	LDAPDB *hds = NULL;
	LOCAL_GRP *mem_grp = NULL;
	int num_rids = 0;
	uint32 user_rid;

	DEBUG(5,("samr_query_useraliases: %d\n", __LINE__));

	(*rid) = NULL;
	(*num_aliases) = 0;

	/* find the policy handle.  open a policy on it. */
	if (!get_nt5ldaprid(get_global_hnd_cache(), pol, &hds, &user_rid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* find the user account */

#if 0
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
#endif
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
 samr_reply_open_user
 ********************************************************************/
uint32 _samr_open_user(const POLICY_HND *domain_pol,
					uint32 access_mask, uint32 user_rid, 
					POLICY_HND *user_pol)
{
	LDAPDB *hds = NULL;
	DOM_SID dom_sid;
	SAM_USER_INFO_21 usr;

	if (!get_nt5ldapdomsid(get_global_hnd_cache(), domain_pol,
					&hds, NULL, NULL, &dom_sid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	if (!nt5ldap_lookup_user(hds, user_rid, &usr))
	{
		return NT_STATUS_NO_SUCH_USER;
	}

	return samr_open_by_nt5ldaprid(hds, domain_pol,
	                  user_pol, access_mask, user_rid);
}

/*******************************************************************
 samr_reply_query_userinfo
 ********************************************************************/
uint32 _samr_query_userinfo(const POLICY_HND *pol, uint16 switch_value,
				SAM_USERINFO_CTR *ctr)
{
	LDAPDB *hds = NULL;
	uint32 rid = 0x0;
	SAM_USER_INFO_21 usr;

	/* find the policy handle.  open a policy on it. */
	if (!get_nt5ldaprid(get_global_hnd_cache(), pol, &hds, &rid))
	{
		return NT_STATUS_INVALID_HANDLE;
	}
	if (!nt5ldap_lookup_user(hds, rid, &usr))
	{
		return NT_STATUS_NO_SUCH_USER;
	}

	DEBUG(5,("samr_reply_query_userinfo: rid:0x%x\n", rid));

	return make_samr_userinfo_ctr_usr21(ctr, switch_value, &usr);
}

/*******************************************************************
 set_user_info_24
 ********************************************************************/
static BOOL set_user_info_24(LDAPDB *hds, uint32 rid,
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

	return nt5ldap_set_userinfo_24(hds, rid, lm_hash, nt_hash);
}

/*******************************************************************
 set_user_info_23
 ********************************************************************/
static BOOL set_user_info_23(LDAPDB *hds, uint32 rid,
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

	return nt5ldap_set_userinfo_23(hds, rid, id23, lm_hash, nt_hash);
}

/*******************************************************************
 samr_reply_set_userinfo
 ********************************************************************/
uint32 _samr_set_userinfo(const POLICY_HND *pol, uint16 switch_value,
				SAM_USERINFO_CTR *ctr)
{
	LDAPDB *hds = NULL;
	uchar user_sess_key[16];
	uint32 rid = 0x0;

	DEBUG(5,("samr_reply_set_userinfo: %d\n", __LINE__));

	/* find the domain rid associated with the policy handle */
	if (!get_nt5ldaprid(get_global_hnd_cache(), pol, &hds, &rid))
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
		case 24:
		{
			SAM_USER_INFO_24 *id24 = ctr->info.id24;
			SamOEMhash(id24->pass, user_sess_key, True);
			if (!set_user_info_24(hds, rid, id24))
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

			if (!set_user_info_23(hds, rid, id23))
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
 set_user_info_16
 ********************************************************************/
static BOOL set_user_info_16(LDAPDB *hds, uint32 rid,
				const SAM_USER_INFO_16 *id16)
{
	return nt5ldap_set_userinfo_16(hds, rid, id16->acb_info);
}

/*******************************************************************
 samr_reply_set_userinfo2
 ********************************************************************/
uint32 _samr_set_userinfo2(const POLICY_HND *pol, uint16 switch_value,
				SAM_USERINFO_CTR *ctr)
{
	LDAPDB *hds = NULL;
	uint32 rid = 0x0;

	/* find the domain sid associated with the policy handle */
	if (!get_nt5ldaprid(get_global_hnd_cache(), pol, &hds, &rid))
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
			SAM_USER_INFO_16 *id16 = ctr->info.id16;
			if (!set_user_info_16(hds, rid, id16))
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
	init_nt_time(&usr->pass_can_change_time);
	unix_to_nt_time(&usr->pass_last_set_time, t);
	unix_to_nt_time(&usr->pass_must_change_time, t);

	usr->acb_info = acb_info | ACB_DISABLED | ACB_PWNOTREQ;
	usr->user_rid = user_rid;
	usr->group_rid = group_rid;

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
	DOM_SID grp_sid;
	LDAPDB *hds = NULL;

	LDAPMod **mods = NULL;
	fstring rdn;
	BOOL iscomputer;
	char *container;

	SAM_USER_INFO_21 usr;
	uint32 status1;
	uint32 rid;
	uint32 type;
	uint32 num_rids;
	uint32 num_types;

	struct passwd *pass = NULL;
	uint32 group_rid;

	(*unknown_0) = 0x30;
	(*user_rid) = 0x0;

	/* find the machine account: tell the caller if it exists.
	   lkclXXXX i have *no* idea if this is a problem or not
	   or even if you are supposed to construct a different
	   reply if the account already exists...
	 */

	/* find the domain sid associated with the policy handle */
	if (!get_nt5ldapdomsid(get_global_hnd_cache(), domain_pol,
					&hds, NULL, NULL, &dom_sid))
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

	/* create a User SID for the unix user */
	if (!surs_unixid_to_sam_sid(hds, pass->pw_uid, SID_NAME_USER, &usr_sid,
	                               True))
	{
		DEBUG(0,("create user: unix uid %d to RID failed\n",
		          pass->pw_uid));
		return NT_STATUS_ACCESS_DENIED;
	}

	/* create a Group SID for the unix user */
	if (!surs_unixid_to_sam_sid(hds, pass->pw_gid, SID_NAME_DOM_GRP, &grp_sid,
	                               True))
	{
		DEBUG(0,("create user: unix uid %d to RID failed\n",
		          pass->pw_uid));
		return NT_STATUS_ACCESS_DENIED;
	}

	/* Get those posixAccount attributes in. Of course, SURS needs to use them. */
	if (!ldapdb_queue_uint32_mod(&mods, LDAP_MOD_ADD, "gidNumber",   pass->pw_gid) ||
	    !ldapdb_queue_uint32_mod(&mods, LDAP_MOD_ADD, "uidNumber",   pass->pw_uid) ||
	    !ldapdb_queue_mod       (&mods, LDAP_MOD_ADD, "uid",         pass->pw_name) ||
	    !ldapdb_queue_mod       (&mods, LDAP_MOD_ADD, "mSSFUName",   pass->pw_name) ||
	    !ldapdb_queue_mod       (&mods, LDAP_MOD_ADD, "gECOS",       pass->pw_gecos) ||
	    !ldapdb_queue_mod       (&mods, LDAP_MOD_ADD, "loginShell",  pass->pw_shell) ||
	    !ldapdb_queue_mod       (&mods, LDAP_MOD_ADD, "objectClass", "posixAccount"))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!sid_split_rid(&usr_sid, user_rid) ||
	    !sid_equal(&dom_sid, &usr_sid))
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

	DEBUG(10,("storing user %x\n", rid));

	if (!nt5ldap_sam_user_info21_mods(&usr, &mods, LDAP_MOD_ADD, rdn, sizeof(rdn)-1, &iscomputer))
	{
		/* account doesn't exist: say so */
		return NT_STATUS_ACCESS_DENIED;
	}

	container = iscomputer ? lp_ldap_computers_subcontext() : lp_ldap_users_subcontext();
	if (!ldapdb_update(hds, container, "cn", rdn, mods, True))
	{
		/* account doesn't exist: say so */
		return NT_STATUS_ACCESS_DENIED;
	}

	*unknown_0 = 0x000703ff;

	return samr_open_by_nt5ldaprid(hds, domain_pol,
	                  user_pol, access_mask, *user_rid);
}

/*******************************************************************
 samr_reply_delete_dom_user
 ********************************************************************/
uint32 _samr_delete_dom_user(POLICY_HND *user_pol)
{
	DEBUG(0,("samr_delete_dom_user: not implemented\n"));
	return NT_STATUS_ACCESS_DENIED;
}

#endif /* WITH_NT5LDAP */

