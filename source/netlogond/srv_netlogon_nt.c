/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Paul Ashton                  1997-2000,
 *  Copyright (C) Jeremy Allison               1998-2000,
 *  Copyright (C) Sander Striker                    2000
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
#include "rpc_parse.h"

extern int DEBUGLEVEL;

extern pstring global_myname;

/******************************************************************
 gets a machine password entry.  checks access rights of the host.
 ******************************************************************/
static uint32 direct_samr_userinfo(const UNISTR2 *uni_user,
				uint16 level,
				SAM_USERINFO_CTR *ctr,
				BOOL set)
{
	POLICY_HND sam_pol;
	POLICY_HND dom_pol;
	POLICY_HND usr_pol;
	uint32 user_rid = 0xffffffff;

	uint32 status_sam = NT_STATUS_NOPROBLEMO;
	uint32 status_dom = NT_STATUS_NOPROBLEMO;
	uint32 status_usr = NT_STATUS_NOPROBLEMO;
	uint32 status_pwd = NT_STATUS_NOPROBLEMO;

	ZERO_STRUCTP(ctr);

	status_sam = _samr_connect(NULL, 0x02000000, &sam_pol);
	if (status_sam == NT_STATUS_NOPROBLEMO)
	{
		status_dom = _samr_open_domain(&sam_pol, 0x02000000,
		                               &global_sam_sid, &dom_pol);
	}
	if (status_dom == NT_STATUS_NOPROBLEMO)
	{
		uint32 type;
		uint32 num_rids;
		uint32 num_types;

		status_usr = _samr_lookup_names(&dom_pol, 1, 0x3e8,
		                                1, uni_user,
		                                &num_rids, &user_rid,
		                                &num_types, &type);
		if (type != SID_NAME_USER)
		{
			status_usr = NT_STATUS_ACCESS_DENIED;
		}
	}
	if (status_usr == NT_STATUS_NOPROBLEMO)
	{
		status_usr = _samr_open_user(&dom_pol, 0x02000000,
		                             user_rid, &usr_pol);
	}
	if (status_usr == NT_STATUS_NOPROBLEMO)
	{
		if (set)
		{
			status_pwd = _samr_set_userinfo(&usr_pol, level, ctr);
		}
		else
		{
			status_pwd = _samr_query_userinfo(&usr_pol, level, ctr);
		}
	}
	if (status_usr == NT_STATUS_NOPROBLEMO) _samr_close(&usr_pol);
	if (status_dom == NT_STATUS_NOPROBLEMO) _samr_close(&dom_pol);
	if (status_sam == NT_STATUS_NOPROBLEMO) _samr_close(&sam_pol);

	if (status_pwd == NT_STATUS_NOPROBLEMO && ctr->info.id == NULL)
	{
		status_pwd = NT_STATUS_NO_MEMORY;
	}

	return status_pwd;
}

/******************************************************************
 gets a machine password entry.  checks access rights of the host.
 ******************************************************************/
static BOOL get_md4pw(char *md4pw, char *trust_name, char *trust_acct)
{
	SAM_USERINFO_CTR ctr;
	uint32 status_pwd = NT_STATUS_NOPROBLEMO;
	UNISTR2 uni_trust_acct;

	ZERO_STRUCT(ctr);

	make_unistr2(&uni_trust_acct, trust_acct, strlen(trust_acct));

#if 0
    /*
     * Currently this code is redundent as we already have a filter
     * by hostname list. What this code really needs to do is to 
     * get a hosts allowed/hosts denied list from the SAM database
     * on a per user basis, and make the access decision there.
     * I will leave this code here for now as a reminder to implement
     * this at a later date. JRA.
     */

	if (!allow_access(lp_domain_hostsdeny(), lp_domain_hostsallow(),
	                  client_connection_name(), client_connection_addr()))
	{
		DEBUG(0,("get_md4pw: Workstation %s denied access to domain\n", trust_acct));
		return False;
	}
#endif /* 0 */

	/*
	 * must do all this as root
	 */
	become_root(True);
	status_pwd = direct_samr_userinfo(&uni_trust_acct, 0x12, &ctr, False);
	unbecome_root(True);

	if (status_pwd == NT_STATUS_NOPROBLEMO)
	{
		memcpy(md4pw, ctr.info.id12->lm_pwd, 16);
		dump_data_pw("md4pw", md4pw, 16);
	}

	free_samr_userinfo_ctr(&ctr);

	return status_pwd == NT_STATUS_NOPROBLEMO;
}

/*************************************************************************
 net_login_interactive:
 *************************************************************************/
static uint32 net_login_interactive(NET_ID_INFO_1 *id1,
				struct dcinfo *dc)
{
	const UNISTR2 *uni_samusr = &id1->uni_user_name;
	uint32 status = NT_STATUS_NOPROBLEMO;

	char nt_pwd[16];
	char lm_pwd[16];
	unsigned char key[16];

	SAM_USERINFO_CTR ctr;

	become_root(True);
	status = direct_samr_userinfo(uni_samusr, 0x12, &ctr, False);
	unbecome_root(True);

	if (status != NT_STATUS_NOPROBLEMO)
	{
		free_samr_userinfo_ctr(&ctr);
		return status;
	}

	memset(key, 0, 16);
	memcpy(key, dc->sess_key, 8);

	memcpy(lm_pwd, id1->lm_owf.data, 16);
	memcpy(nt_pwd, id1->nt_owf.data, 16);

	dump_data_pw("key:", key, 16);

	dump_data_pw("lm owf password:", lm_pwd, 16);
	dump_data_pw("nt owf password:", nt_pwd, 16);

	SamOEMhash((uchar *)lm_pwd, key, 0);
	SamOEMhash((uchar *)nt_pwd, key, 0);

	dump_data_pw("decrypt of lm owf password:", lm_pwd, 16);
	dump_data_pw("decrypt of nt owf password:", nt_pwd, 16);

	if (memcmp(ctr.info.id12->lm_pwd, lm_pwd, 16) != 0 ||
	    memcmp(ctr.info.id12->nt_pwd, nt_pwd, 16) != 0)
	{
		status = NT_STATUS_WRONG_PASSWORD;
	}

	free_samr_userinfo_ctr(&ctr);

	return status;
}

/*************************************************************************
 net_login_network:
 *************************************************************************/
static uint32 net_login_general(NET_ID_INFO_4 *id4,
				struct dcinfo *dc,
				char usr_sess_key[16])
{
	fstring user;
	fstring domain;
	char *general;

	int pw_len = id4->str_general.str_str_len;

	unistr2_to_ascii(user  , &id4->uni_user_name, sizeof(user)-1);
	unistr2_to_ascii(domain, &id4->uni_domain_name, sizeof(domain)-1);
	general = id4->str_general.buffer;

	DEBUG(5,("net_login_general: user:%s domain:%s", user, domain));
#ifdef DEBUG_PASSWORD
	DEBUG(100,("password:%s", general));
#endif
	DEBUG(5,("\n"));

	if (pass_check(user, general, pw_len, NULL,
	                    lp_update_encrypted() ?
	                    update_smbpassword_file : NULL) ) 
	{
		unsigned char key[16];

		memset(key, 0, 16);
		memcpy(key, dc->sess_key, 8);

#ifdef DEBUG_PASSWORD
		DEBUG(100,("key:"));
		dump_data(100, key, 16);

		DEBUG(100,("user sess key:"));
		dump_data(100, usr_sess_key, 16);
#endif
		SamOEMhash((uchar *)usr_sess_key, key, 0);

#ifdef DEBUG_PASSWORD
		DEBUG(100,("encrypt of user session key:"));
		dump_data(100, usr_sess_key, 16);
#endif

                  return NT_STATUS_NOPROBLEMO;
	}

	return NT_STATUS_WRONG_PASSWORD;
}

/*************************************************************************
 net_login_network:
 *************************************************************************/
static uint32 net_login_network(NET_ID_INFO_2 *id2,
				uint16 acb_info,
				struct dcinfo *dc,
				char usr_sess_key[16],
				char lm_pw8[8])
{
	const UNISTR2 *uni_samusr = &id2->uni_user_name;
	fstring user;
	fstring domain;

	SAM_USERINFO_CTR ctr;

	uint32 status;

	int nt_pw_len = id2->hdr_nt_chal_resp.str_str_len;
	int lm_pw_len = id2->hdr_lm_chal_resp.str_str_len;

	unistr2_to_ascii(user  , uni_samusr, sizeof(user)-1);
	unistr2_to_ascii(domain, &id2->uni_domain_name, sizeof(domain)-1);

	become_root(True);
	status = direct_samr_userinfo(uni_samusr, 0x12, &ctr, False);
	unbecome_root(True);

	if (status != NT_STATUS_NOPROBLEMO)
	{
		free_samr_userinfo_ctr(&ctr);
		return status;
	}

	DEBUG(5,("net_login_network: lm_len:%d nt_len:%d user:%s domain:%s\n",
		lm_pw_len, nt_pw_len, user, domain));

	DEBUG(0,("net_login_network: HACK alert - unix name is nt name\n"));

	if (smb_password_ok(acb_info, ctr.info.id12->lm_pwd,
	                    ctr.info.id12->nt_pwd,
	                    id2->lm_chal, 
	                    user, domain,
	                    (const uchar *)id2->lm_chal_resp.buffer, lm_pw_len, 
	                    (const uchar *)id2->nt_chal_resp.buffer, nt_pw_len,
	                    usr_sess_key)) 
	{
		unsigned char key[16];

		memcpy(lm_pw8, ctr.info.id12->lm_pwd, 8);

		memset(key, 0, 16);
		memcpy(key, dc->sess_key, 8);

		dump_data_pw("key:", key, 16);
		dump_data_pw("user sess key:", usr_sess_key, 16);
		dump_data_pw("lm_pw8:", lm_pw8, 16);

		SamOEMhash((uchar *)lm_pw8, key, 3);
		SamOEMhash((uchar *)usr_sess_key, key, 0);

		dump_data_pw("encrypt of user session key:", usr_sess_key, 16);
		dump_data_pw("encrypt of lm_pw8:", lm_pw8, 16);

		status = NT_STATUS_NOPROBLEMO;
	}
	else
	{
		status = NT_STATUS_WRONG_PASSWORD;
	}
	free_samr_userinfo_ctr(&ctr);
	return status;
}

/*************************************************************************
 _net_req_chal
 *************************************************************************/
uint32 _net_req_chal(	const UNISTR2 *uni_logon_server,
				const UNISTR2 *uni_logon_client,
				const DOM_CHAL *clnt_chal,
				DOM_CHAL *srv_chal,
				uint16 remote_pid	) 
{
	fstring trust_acct;
	fstring trust_name;

	struct dcinfo dc;

	ZERO_STRUCT(dc);

	unistr2_to_ascii(trust_acct, uni_logon_client, sizeof(trust_acct)-1);

	fstrcpy(trust_name, trust_acct);
	strlower(trust_name);

	fstrcat(trust_acct, "$");

	if (!get_md4pw((char *)dc.md4pw, trust_name, trust_acct))
	{
		/* lkclXXXX take a guess at a good error message to return :-) */
		return NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT;
	}

	/* copy the client credentials */
	memcpy(dc.clnt_chal.data          , clnt_chal->data, sizeof(clnt_chal->data));
	memcpy(dc.clnt_cred.challenge.data, clnt_chal->data, sizeof(clnt_chal->data));

	/* create a server challenge for the client */
	/* Set these to random values. */
	generate_random_buffer(srv_chal->data, sizeof(srv_chal->data), False);

	/* copy the server credentials */
	memcpy(dc.srv_chal.data          , srv_chal->data, sizeof(srv_chal->data));
	memcpy(dc.srv_cred.challenge.data, srv_chal->data, sizeof(srv_chal->data));

	bzero(dc.sess_key, sizeof(dc.sess_key));

	/* from client / server challenges and md4 password, generate sess key */
	cred_session_key(&(dc.clnt_chal), &(dc.srv_chal),
				 (char *)dc.md4pw, dc.sess_key);

	if (!cred_store(remote_pid, global_sam_name, trust_name, &dc))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	return NT_STATUS_NOPROBLEMO;
}


/*************************************************************************
 error messages cropping up when using nltest.exe...
 *************************************************************************/
#define ERROR_NO_SUCH_DOMAIN   0x54b
#define ERROR_NO_LOGON_SERVERS 0x51f

/*******************************************************************
creates a NETLOGON_INFO_3 structure.
********************************************************************/
static BOOL make_netinfo_3(NETLOGON_INFO_3 *info, uint32 flags, uint32 logon_attempts)
{
	info->flags          = flags;
	info->logon_attempts = logon_attempts;
	info->reserved_1     = 0x0;
	info->reserved_2     = 0x0;
	info->reserved_3     = 0x0;
	info->reserved_4     = 0x0;
	info->reserved_5     = 0x0;

	return True;
}


/*******************************************************************
creates a NETLOGON_INFO_1 structure.
********************************************************************/
static BOOL make_netinfo_1(NETLOGON_INFO_1 *info, uint32 flags, uint32 pdc_status)
{
	info->flags      = flags;
	info->pdc_status = pdc_status;

	return True;
}

/*******************************************************************
creates a NETLOGON_INFO_2 structure.
********************************************************************/
static BOOL make_netinfo_2(NETLOGON_INFO_2 *info, uint32 flags, uint32 pdc_status,
				uint32 tc_status, char *trusted_dc_name)
{
	int len_dc_name = strlen(trusted_dc_name);
	info->flags      = flags;
	info->pdc_status = pdc_status;
	info->ptr_trusted_dc_name = 1;
	info->tc_status  = tc_status;

	if (trusted_dc_name != NULL)
	{
		make_unistr2(&(info->uni_trusted_dc_name), trusted_dc_name, len_dc_name+1);
	}
	else
	{
		make_unistr2(&(info->uni_trusted_dc_name), "", 1);
	}

	return True;
}

/*************************************************************************
 _net_logon_ctrl2
 *************************************************************************/
uint32 _net_logon_ctrl2(const	UNISTR2 *uni_server_name, 
				uint32 function_code,
				uint32 query_level,
				uint32 switch_value,
				uint32 *reply_switch_value,
				NETLOGON_INFO *logon_info)
{
	/* lkclXXXX - guess what - absolutely no idea what these are! */
	uint32 flags = 0x0;
	uint32 pdc_status = 0x0;
	uint32 logon_attempts = 0x0;
	uint32 tc_status = ERROR_NO_LOGON_SERVERS;
	char *trusted_domain = "test_domain";

	*reply_switch_value = query_level;

	switch (query_level)
	{
		case 1:
		{
			make_netinfo_1(&logon_info->info1, flags, pdc_status);	
			break;
		}
		case 2:
		{
			make_netinfo_2(&logon_info->info2, flags, pdc_status,
			               tc_status, trusted_domain);	
			break;
		}
		case 3:
		{
			make_netinfo_3(&logon_info->info3, flags,
			                logon_attempts);	
			break;
		}
		default:
		{
			/* take a guess at an error code... */
			return NT_STATUS_INVALID_INFO_CLASS;
			break;
		}
	}

	return NT_STATUS_NOPROBLEMO;
}

/*************************************************************************
 _net_trust_dom_list
 *************************************************************************/
uint32 _net_trust_dom_list(const UNISTR2 *uni_server_name,
				   uint32 function_code,
				   BUFFER2 *uni_trust_dom_name)
{
	char **doms = NULL;
	uint32 num_doms = 0;

	enumtrustdoms(&doms, &num_doms);

	make_buffer2_multi(uni_trust_dom_name, doms, num_doms);

	if (num_doms == 0)
	{
		uni_trust_dom_name->buf_max_len = 0x2;
		uni_trust_dom_name->buf_len = 0x2;
	}
	uni_trust_dom_name->undoc = 0x1;
	
	free_char_array(num_doms, doms);

	return NT_STATUS_NOPROBLEMO;
}

/*************************************************************************
 _net_auth
 *************************************************************************/
uint32 _net_auth(const DOM_LOG_INFO *clnt_id,
			     const DOM_CHAL *clnt_chal,
			     DOM_CHAL *srv_chal,
			     uint16 remote_pid)
{
	UTIME srv_time;
	fstring trust_name;
	struct dcinfo dc;

	ZERO_STRUCT(dc);

	srv_time.time = 0;

	unistr2_to_ascii(trust_name, &clnt_id->uni_comp_name,
	                             sizeof(trust_name)-1);

	if (!cred_get(remote_pid, global_sam_name, trust_name, &dc))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* check that the client credentials are valid */
	if (!cred_assert(clnt_chal, dc.sess_key, &(dc.clnt_cred.challenge), srv_time))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	/* create server challenge for inclusion in the reply */
	cred_create(dc.sess_key, &(dc.srv_cred.challenge), srv_time, srv_chal);

	/* copy the received client credentials for use next time */
	memcpy(dc.clnt_cred.challenge.data, clnt_chal->data, sizeof(clnt_chal->data));
	memcpy(dc.srv_cred .challenge.data, clnt_chal->data, sizeof(clnt_chal->data));

	if (!cred_store(remote_pid, global_sam_name, trust_name, &dc))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	return NT_STATUS_NOPROBLEMO;
}

/*************************************************************************
 _net_auth_2
 *************************************************************************/
uint32 _net_auth_2(const DOM_LOG_INFO *clnt_id,
				 const DOM_CHAL *clnt_chal,
				 const NEG_FLAGS *clnt_flgs,
				 DOM_CHAL *srv_chal,
				 NEG_FLAGS *srv_flgs,
				 uint16 remote_pid)
{
	UTIME srv_time;
	fstring trust_name;
	struct dcinfo dc;

	ZERO_STRUCT(dc);

	srv_time.time = 0;

	unistr2_to_ascii(trust_name, &(clnt_id->uni_comp_name),
	                             sizeof(trust_name)-1);

	if (!cred_get(remote_pid, global_sam_name, trust_name, &dc))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* check that the client credentials are valid */
	if (!cred_assert(clnt_chal, dc.sess_key,
			    &(dc.clnt_cred.challenge), srv_time))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	/* create server challenge for inclusion in the reply */
	cred_create(dc.sess_key, &(dc.srv_cred.challenge), srv_time, srv_chal);

	/* copy the received client credentials for use next time */
	memcpy(dc.clnt_cred.challenge.data, clnt_chal->data, sizeof(clnt_chal->data));
	memcpy(dc.srv_cred .challenge.data, clnt_chal->data, sizeof(clnt_chal->data));

	if (!cred_store(remote_pid, global_sam_name, trust_name, &dc))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* mask out unsupported bits */
	srv_flgs->neg_flags = clnt_flgs->neg_flags & 0x400001ff;

	/* minimum bits required */
	if (!IS_BITS_SET_ALL(srv_flgs->neg_flags, 0x000000ff))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	/* secure channel NOT to be used */
	if (!lp_server_schannel())
	{
		srv_flgs->neg_flags &= ~0x40000000;
	}
	else
	{
		/* secure channel MUST be used */
		if (IS_BITS_CLR_ALL(srv_flgs->neg_flags, 0x40000000))
		{
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	return NT_STATUS_NOPROBLEMO;
}

/*************************************************************************
 _net_srv_pwset
 *************************************************************************/
uint32 _net_srv_pwset(const DOM_CLNT_INFO *clnt_id,
			    const uint8 pwd[16],
			    DOM_CRED *srv_cred,
			    uint16 remote_pid)
{
	pstring trust_acct;
	struct smb_passwd *smb_pass;
	unsigned char hash3_pwd[16];
	BOOL ret;

	fstring trust_name;
	struct dcinfo dc;

	ZERO_STRUCT(dc);

	unistr2_to_ascii(trust_name, &(clnt_id->login.uni_comp_name),
	                             sizeof(trust_name)-1);

	if (!cred_get(remote_pid, global_sam_name, trust_name, &dc))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* checks and updates credentials.  creates reply credentials */
	if (!deal_with_creds(dc.sess_key, &(dc.clnt_cred), &(clnt_id->cred), srv_cred))
	{
		/* lkclXXXX take a guess at a sensible error code to return... */
		return NT_STATUS_ACCESS_DENIED;
	}

	memcpy(&(dc.srv_cred), &(dc.clnt_cred), sizeof(dc.clnt_cred));

	unistr2_to_ascii(trust_acct, &(clnt_id->login.uni_acct_name),
				 sizeof(trust_acct)-1);

	DEBUG(3,("Server Password Set Wksta:[%s]\n", trust_acct));

	become_root(True);
	smb_pass = getsmbpwnam(trust_acct);
	unbecome_root(True);

	if (smb_pass == NULL)
	{
		return NT_STATUS_WRONG_PASSWORD;
	}

	/* Some debug output, needed an iterater variable */
	{
		int i;

		DEBUG(100,("Server password set : new given value was :\n"));
		for(i = 0; i < 16; i++)
		{
			DEBUG(100,("%02X ", pwd[i]));
		}
		DEBUG(100,("\n"));
	}

	cred_hash3( hash3_pwd, pwd, dc.sess_key, 0);

	/* lies!  nt and lm passwords are _not_ the same: don't care */
	smb_pass->smb_passwd    = hash3_pwd;
	smb_pass->smb_nt_passwd = hash3_pwd;
	smb_pass->acct_ctrl     = ACB_WSTRUST;

	become_root(True);
	ret = mod_smbpwd_entry(smb_pass,False);
	unbecome_root(True);

	if (!ret)
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!cred_store(remote_pid, global_sam_name, trust_name, &dc))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	return NT_STATUS_NOPROBLEMO;
}

/*************************************************************************
 _net_sam_logon
 *************************************************************************/
uint32 _net_sam_logon(const DOM_SAM_INFO *sam_id,
				    uint16 validation_level,
				    DOM_CRED *srv_creds,
				    uint16 *switch_value,
				    NET_USER_INFO_3 *user,
				    uint32 *auth_resp,
				    uint16 remote_pid)
{
	UNISTR2 *uni_samusr = NULL;
	UNISTR2 *uni_domain = NULL;
	fstring nt_username;
	char *enc_user_sess_key = NULL;
	char usr_sess_key[16];
	char lm_pw8[16];
	char *padding = NULL;
	uint32 status_pwd = 0x0;
	SAM_USERINFO_CTR ctr;

	NTTIME logon_time           ;
	NTTIME logoff_time          ;
	NTTIME kickoff_time         ;
	NTTIME pass_last_set_time   ;
	NTTIME pass_can_change_time ;
	NTTIME pass_must_change_time;

	UNISTR2 *uni_nt_name     ;
	UNISTR2 *uni_full_name   ;
	UNISTR2 *uni_logon_script;
	UNISTR2 *uni_profile_path;
	UNISTR2 *uni_home_dir    ;
	UNISTR2 *uni_dir_drive   ;

	uint32 user_rid ;
	uint32 group_rid;

	int num_gids = 0;
	DOMAIN_GRP *grp_mem = NULL;
	DOM_GID *gids = NULL;

	fstring trust_name;
	struct dcinfo dc;
	uint16 acb_info;

	UNISTR2 uni_myname;
	UNISTR2 uni_sam_name;

	*auth_resp = 1; /* authoritative response */

	unistr2_to_ascii(trust_name, &(sam_id->client.login.uni_comp_name),
	                             sizeof(trust_name)-1);

	if (!cred_get(remote_pid, global_sam_name, trust_name, &dc))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* checks and updates credentials.  creates reply credentials */
	if (!deal_with_creds(dc.sess_key, &dc.clnt_cred, 
	                     &(sam_id->client.cred), srv_creds))
	{
		return NT_STATUS_ACCESS_DENIED;
	}
	
	memcpy(&dc.srv_cred, &dc.clnt_cred, sizeof(dc.clnt_cred));

	/* find the username */

	switch (sam_id->logon_level)
	{
		case INTERACTIVE_LOGON_TYPE:
		{
			uni_samusr = &(sam_id->ctr->auth.id1.uni_user_name);
			uni_domain = &(sam_id->ctr->auth.id1.uni_domain_name);

			DEBUG(3,("SAM Logon (Interactive). Domain:[%s].  ", global_sam_name));
			break;
		}
		case NETWORK_LOGON_TYPE:
		{
			uni_samusr = &(sam_id->ctr->auth.id2.uni_user_name);
			uni_domain = &(sam_id->ctr->auth.id2.uni_domain_name);

			DEBUG(3,("SAM Logon (Network). Domain:[%s].  ", global_sam_name));
			break;
		}
		case GENERAL_LOGON_TYPE:
		{
			uni_samusr = &(sam_id->ctr->auth.id4.uni_user_name);
			uni_domain = &(sam_id->ctr->auth.id4.uni_domain_name);

			DEBUG(3,("SAM Logon (General). Domain:[%s].  ", global_sam_name));
			break;
		}
		default:
		{
			DEBUG(2,("SAM Logon: unsupported switch value\n"));
			return NT_STATUS_INVALID_INFO_CLASS;
		}
	} 

	/* check username exists */

	unistr2_to_ascii(nt_username, uni_samusr,
			 sizeof(nt_username)-1);

	DEBUG(3,("User:[%s]\n", nt_username));

	/*
	 * IMPORTANT: do a General Login BEFORE the others,
	 * because "update encrypted" may be enabled, which
	 * will result in the smb password entry being added.
	 *
	 * calling general login AFTER the getsampwntname() is
	 * not guaranteed to deliver.
	 */

	if (sam_id->logon_level == GENERAL_LOGON_TYPE)
	{
		/* general login.  cleartext password */
		uint32 status = NT_STATUS_NOPROBLEMO;
		status = net_login_general(&(sam_id->ctr->auth.id4), &dc, usr_sess_key);
		enc_user_sess_key = usr_sess_key;

		if (status != NT_STATUS_NOPROBLEMO)
		{
			return status;
		}
	}

	/*
	 * now obtain smb passwd entry, which MAY have just been
	 * added by "update encrypted" in general login
	 */
	become_root(True);
	status_pwd = direct_samr_userinfo(uni_samusr, 21, &ctr, False);
	unbecome_root(True);

	if (status_pwd != NT_STATUS_NOPROBLEMO)
	{
		free_samr_userinfo_ctr(&ctr);
		return status_pwd;
	}
	
	acb_info = ctr.info.id21->acb_info;
	if (IS_BITS_SET_ALL(acb_info, ACB_DISABLED) &&
	    IS_BITS_CLR_ALL(acb_info, ACB_PWNOTREQ))
	{
		return NT_STATUS_ACCOUNT_DISABLED;
	}

	if (IS_BITS_SET_ALL(acb_info, ACB_DOMTRUST))
	{
		return NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT;
	}

	if (IS_BITS_SET_ALL(acb_info, ACB_SVRTRUST))
	{
		return NT_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT;
	}
	 
	if (IS_BITS_SET_ALL(acb_info, ACB_WSTRUST))
	{
		return NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT;
	}

	logon_time            = ctr.info.id21->logon_time;
	logoff_time           = ctr.info.id21->logoff_time;
	kickoff_time          = ctr.info.id21->kickoff_time;
	pass_last_set_time    = ctr.info.id21->pass_last_set_time;
	pass_can_change_time  = ctr.info.id21->pass_can_change_time;
	pass_must_change_time = ctr.info.id21->pass_must_change_time;

	uni_nt_name = &ctr.info.id21->uni_user_name;
	uni_full_name = &ctr.info.id21->uni_full_name;
	uni_home_dir = &ctr.info.id21->uni_home_dir;
	uni_dir_drive = &ctr.info.id21->uni_dir_drive;
	uni_logon_script = &ctr.info.id21->uni_logon_script;
	uni_profile_path = &ctr.info.id21->uni_profile_path;

	user_rid  = ctr.info.id21->user_rid;
	group_rid = ctr.info.id21->group_rid;

	/* validate password - if required */

	if (!(IS_BITS_SET_ALL(acb_info, ACB_PWNOTREQ)))
	{
		uint32 status = NT_STATUS_NOPROBLEMO;
		switch (sam_id->logon_level)
		{
			case INTERACTIVE_LOGON_TYPE:
			{
				/* interactive login. */
				status = net_login_interactive(&(sam_id->ctr->auth.id1), &dc);
				break;
			}
			case NETWORK_LOGON_TYPE:
			{
				/* network login.  lm challenge and 24 byte responses */
				status = net_login_network(&(sam_id->ctr->auth.id2), acb_info, &dc, usr_sess_key, lm_pw8);
				padding = lm_pw8;
				enc_user_sess_key = usr_sess_key;
				break;
			}
			case GENERAL_LOGON_TYPE:
			{
				/* general login type ALREADY been checked */
				break;
			}
		}
		if (status != NT_STATUS_NOPROBLEMO)
		{
			free_samr_userinfo_ctr(&ctr);
			return status;
		}
	}

	/* lkclXXXX this is the point at which, if the login was
	successful, that the SAM Local Security Authority should
	record that the user is logged in to the domain.
	*/

	/* return the profile plus other bits :-) */

	/* set up pointer indicating user/password failed to be found */
	user->ptr_user_info = 0;

	if (!getusergroupsntnam(nt_username, &grp_mem, &num_gids))
	{
		free_samr_userinfo_ctr(&ctr);
		return NT_STATUS_INVALID_PRIMARY_GROUP;
	}

	num_gids = make_dom_gids(grp_mem, num_gids, &gids);

	make_unistr2(&uni_myname, global_myname, strlen(global_myname));
	make_unistr2(&uni_sam_name, global_sam_name, strlen(global_sam_name));

	make_net_user_info3W(user,
		&logon_time,
		&logoff_time,
		&kickoff_time,
		&pass_last_set_time,
		&pass_can_change_time,
		&pass_must_change_time,

		uni_nt_name         , /* user_name */
		uni_full_name       , /* full_name */
		uni_logon_script    , /* logon_script */
		uni_profile_path    , /* profile_path */
		uni_home_dir        , /* home_dir */
		uni_dir_drive       , /* dir_drive */

		0, /* logon_count */
		0, /* bad_pw_count */

		user_rid   , /* RID user_id */
		group_rid  , /* RID group_id */
		num_gids,    /* uint32 num_groups */
		gids    , /* DOM_GID *gids */
		0x20    , /* uint32 user_flgs (?) */

		enc_user_sess_key, /* char usr_sess_key[16] */

		&uni_myname  , /* char *logon_srv */
		&uni_sam_name, /* char *logon_dom */

		padding,

		&global_sam_sid, /* DOM_SID *dom_sid */
		NULL); /* char *other_sids */

	/* Free any allocated groups array. */
	safe_free(gids);

	free_samr_userinfo_ctr(&ctr);

	if (!cred_store(remote_pid, global_sam_name, trust_name, &dc))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	return NT_STATUS_NOPROBLEMO;
}

/*************************************************************************
 _net_sam_logoff
 *************************************************************************/
uint32 _net_sam_logoff(const DOM_SAM_INFO *sam_id,
			     DOM_CRED *srv_creds,
			     uint16 remote_pid)
{
	fstring trust_name;
	struct dcinfo dc;

	ZERO_STRUCT(dc);

	unistr2_to_ascii(trust_name, &(sam_id->client.login.uni_comp_name),
	                             sizeof(trust_name)-1);

	if (!cred_get(remote_pid, global_sam_name, trust_name, &dc))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* checks and updates credentials.  creates reply credentials */
	if (!deal_with_creds(dc.sess_key, &(dc.clnt_cred), 
	                &(sam_id->client.cred), srv_creds))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	memcpy(&(dc.srv_cred), &(dc.clnt_cred), sizeof(dc.clnt_cred));

	if (!cred_store(remote_pid, global_sam_name, trust_name, &dc))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	return NT_STATUS_NOPROBLEMO;
}

/*************************************************************************
 _net_sam_sync
 *************************************************************************/
uint32 _net_sam_sync(const UNISTR2 *uni_srv_name,
			   const UNISTR2 *uni_cli_name,
			   uint32 database_id,
			   uint32 restart_state,
			   uint32 *sync_context,
			   uint32 max_size,
			   uint32 *num_deltas,
			   uint32 *num_deltas2,
			   SAM_DELTA_HDR *hdr_deltas,
			   SAM_DELTA_CTR *deltas)
{
	fstring trust_name;

	int i = 0;
	struct sam_passwd *pwd;
	void *vp;

	unistr2_to_ascii(trust_name, uni_cli_name, sizeof(trust_name)-1);

	(*sync_context) = 1;

	if ((vp = startsmbpwent(False)) == NULL)
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	/* Give the poor BDC some accounts */

	while (((pwd = getsam21pwent(vp)) != NULL) && (i < MAX_SAM_DELTAS))
	{
		make_sam_delta_hdr(&hdr_deltas[i], 5, pwd->user_rid);
		make_sam_account_info(&deltas[i].account_info,
				 	    pwd->nt_name, pwd->full_name, pwd->user_rid,
				 	    pwd->group_rid, pwd->home_dir, pwd->dir_drive,
				 	    pwd->logon_script, pwd->acct_desc,
				 	    pwd->acct_ctrl, pwd->profile_path);
		i++;
	}

	endsmbpwent(vp);

	*num_deltas = *num_deltas2 = i;

	return NT_STATUS_NOPROBLEMO;
}

