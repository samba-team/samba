/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  Copyright (C) Jeremy Allison                    1998.
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

extern pstring global_myname;
extern DOM_SID global_sam_sid;
extern fstring global_sam_name;

/*************************************************************************
 make_net_r_req_chal:
 *************************************************************************/
static void make_net_r_req_chal(NET_R_REQ_CHAL *r_c,
                                DOM_CHAL *srv_chal, int status)
{
	DEBUG(6,("make_net_r_req_chal: %d\n", __LINE__));
	memcpy(r_c->srv_chal.data, srv_chal->data, sizeof(srv_chal->data));
	r_c->status = status;
}

/*************************************************************************
 net_reply_req_chal:
 *************************************************************************/
static void net_reply_req_chal(NET_Q_REQ_CHAL *q_c, prs_struct *rdata,
					DOM_CHAL *srv_chal, uint32 srv_time)
{
	NET_R_REQ_CHAL r_c;

	DEBUG(6,("net_reply_req_chal: %d\n", __LINE__));

	/* set up the LSA REQUEST CHALLENGE response */
	make_net_r_req_chal(&r_c, srv_chal, srv_time);

	/* store the response in the SMB stream */
	net_io_r_req_chal("", &r_c, rdata, 0);

	DEBUG(6,("net_reply_req_chal: %d\n", __LINE__));

}

/*************************************************************************
 net_reply_logon_ctrl2:
 *************************************************************************/
static void net_reply_logon_ctrl2(NET_Q_LOGON_CTRL2 *q_l, prs_struct *rdata,
			uint32 flags, uint32 pdc_status, uint32 logon_attempts,
			uint32 tc_status, char *trust_domain_name)
{
	NET_R_LOGON_CTRL2 r_l;

	DEBUG(6,("net_reply_logon_ctrl2: %d\n", __LINE__));

	/* set up the Logon Control2 response */
	make_r_logon_ctrl2(&r_l, q_l->query_level,
	                   flags, pdc_status, logon_attempts,
	                   tc_status, trust_domain_name);

	/* store the response in the SMB stream */
	net_io_r_logon_ctrl2("", &r_l, rdata, 0);

	DEBUG(6,("net_reply_logon_ctrl2: %d\n", __LINE__));

}

/*************************************************************************
 net_reply_trust_dom_list:
 *************************************************************************/
static void net_reply_trust_dom_list(NET_Q_TRUST_DOM_LIST *q_t, prs_struct *rdata,
			uint32 num_trust_domains, char **trust_domain_name)
{
	NET_R_TRUST_DOM_LIST r_t;

	DEBUG(6,("net_reply_trust_dom_list: %d\n", __LINE__));

	/* set up the Trusted Domain List response */
	make_r_trust_dom(&r_t, num_trust_domains, trust_domain_name);

	/* store the response in the SMB stream */
	net_io_r_trust_dom("", &r_t, rdata, 0);

	DEBUG(6,("net_reply_trust_dom_list: %d\n", __LINE__));

}


/*************************************************************************
 make_net_r_auth:
 *************************************************************************/
static void make_net_r_auth(NET_R_AUTH *r_a,
                              DOM_CHAL *resp_cred, int status)
{
	memcpy(  r_a->srv_chal.data, resp_cred->data, sizeof(resp_cred->data));
	r_a->status = status;
}

/*************************************************************************
 net_reply_auth:
 *************************************************************************/
static void net_reply_auth(NET_Q_AUTH *q_a, prs_struct *rdata,
				DOM_CHAL *resp_cred, int status)
{
	NET_R_AUTH r_a;

	/* set up the LSA AUTH 2 response */

	make_net_r_auth(&r_a, resp_cred, status);

	/* store the response in the SMB stream */
	net_io_r_auth("", &r_a, rdata, 0);

}

/*************************************************************************
 make_net_r_auth_2:
 *************************************************************************/
static void make_net_r_auth_2(NET_R_AUTH_2 *r_a,
                              DOM_CHAL *resp_cred, NEG_FLAGS *flgs, int status)
{
	memcpy(  r_a->srv_chal.data, resp_cred->data, sizeof(resp_cred->data));
	memcpy(&(r_a->srv_flgs)    , flgs           , sizeof(r_a->srv_flgs));
	r_a->status = status;
}

/*************************************************************************
 net_reply_auth_2:
 *************************************************************************/
static void net_reply_auth_2(NET_Q_AUTH_2 *q_a, prs_struct *rdata,
				DOM_CHAL *resp_cred, int status)
{
	NET_R_AUTH_2 r_a;
	NEG_FLAGS srv_flgs;

	srv_flgs.neg_flags = 0x000001ff;

	/* set up the LSA AUTH 2 response */

	make_net_r_auth_2(&r_a, resp_cred, &srv_flgs, status);

	/* store the response in the SMB stream */
	net_io_r_auth_2("", &r_a, rdata, 0);

}

/***********************************************************************************
 make_net_r_srv_pwset:
 ***********************************************************************************/
static void make_net_r_srv_pwset(NET_R_SRV_PWSET *r_s,
                             DOM_CRED *srv_cred, int status)  
{
	DEBUG(5,("make_net_r_srv_pwset: %d\n", __LINE__));

	memcpy(&(r_s->srv_cred), srv_cred, sizeof(r_s->srv_cred));
	r_s->status = status;

	DEBUG(5,("make_net_r_srv_pwset: %d\n", __LINE__));
}

/*************************************************************************
 net_reply_srv_pwset:
 *************************************************************************/
static void net_reply_srv_pwset(NET_Q_SRV_PWSET *q_s, prs_struct *rdata,
				DOM_CRED *srv_cred, int status)
{
	NET_R_SRV_PWSET r_s;

	DEBUG(5,("net_srv_pwset: %d\n", __LINE__));

	/* set up the LSA Server Password Set response */
	make_net_r_srv_pwset(&r_s, srv_cred, status);

	/* store the response in the SMB stream */
	net_io_r_srv_pwset("", &r_s, rdata, 0);

	DEBUG(5,("net_srv_pwset: %d\n", __LINE__));

}

/*************************************************************************
 net_reply_sam_logon:
 *************************************************************************/
static void net_reply_sam_logon(NET_Q_SAM_LOGON *q_s, prs_struct *rdata,
				DOM_CRED *srv_cred, NET_USER_INFO_3 *user_info,
				uint32 status)
{
	NET_R_SAM_LOGON r_s;

	/* XXXX maybe we want to say 'no', reject the client's credentials */
	r_s.buffer_creds = 1; /* yes, we have valid server credentials */
	memcpy(&(r_s.srv_creds), srv_cred, sizeof(r_s.srv_creds));

	/* store the user information, if there is any. */
	r_s.user = user_info;
	if (status == 0x0 && user_info != NULL && user_info->ptr_user_info != 0)
	{
		r_s.switch_value = 3; /* indicates type of validation user info */
	}
	else
	{
		r_s.switch_value = 0; /* indicates no info */
	}

	r_s.status = status;
	r_s.auth_resp = 1; /* authoritative response */

	/* store the response in the SMB stream */
	net_io_r_sam_logon("", &r_s, rdata, 0);

}


/*************************************************************************
 net_reply_sam_logoff:
 *************************************************************************/
static void net_reply_sam_logoff(NET_Q_SAM_LOGOFF *q_s, prs_struct *rdata,
				DOM_CRED *srv_cred, 
				uint32 status)
{
	NET_R_SAM_LOGOFF r_s;

	/* XXXX maybe we want to say 'no', reject the client's credentials */
	r_s.buffer_creds = 1; /* yes, we have valid server credentials */
	memcpy(&(r_s.srv_creds), srv_cred, sizeof(r_s.srv_creds));

	r_s.status = status;

	/* store the response in the SMB stream */
	net_io_r_sam_logoff("", &r_s, rdata, 0);

}

/*************************************************************************
 net_reply_sam_sync:
 *************************************************************************/
static void net_reply_sam_sync(NET_Q_SAM_SYNC *q_s, prs_struct *rdata,
				uint8 sess_key[16],
				DOM_CRED *srv_creds, uint32 status)
{
	NET_R_SAM_SYNC r_s;
	int i = 0;
	struct sam_passwd *pwd;
	void *vp;

	memcpy(&(r_s.srv_creds), srv_creds, sizeof(r_s.srv_creds));
	r_s.sync_context = 1;
	r_s.ptr_deltas = 0;

	if ((status == 0x0) && ((vp = startsmbpwent(False)) != NULL))
	{
		/* Give the poor BDC some accounts */

		while (((pwd = getsam21pwent(vp)) != NULL) && (i < MAX_SAM_DELTAS))
		{
			make_sam_delta_hdr(&r_s.hdr_deltas[i], 5, pwd->user_rid);
			make_sam_account_info(&r_s.deltas[i].account_info,
				 pwd->nt_name, pwd->full_name, pwd->user_rid,
				 pwd->group_rid, pwd->home_dir, pwd->dir_drive,
				 pwd->logon_script, pwd->acct_desc,
				 pwd->acct_ctrl, pwd->profile_path);

			i++;
		}

		endsmbpwent(vp);

		r_s.ptr_deltas = r_s.ptr_deltas2 = 1;
		r_s.num_deltas = r_s.num_deltas2 = i;
	}

	r_s.status = status;

	/* store the response in the SMB stream */
	net_io_r_sam_sync("", sess_key, &r_s, rdata, 0);

}

/******************************************************************
 gets a machine password entry.  checks access rights of the host.
 ******************************************************************/
static BOOL get_md4pw(char *md4pw, char *mach_name, char *mach_acct)
{
	struct smb_passwd *smb_pass;

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
	                  client_name(Client), client_addr(Client)))
	{
		DEBUG(0,("get_md4pw: Workstation %s denied access to domain\n", mach_acct));
		return False;
	}
#endif /* 0 */

	become_root(True);
	smb_pass = getsmbpwnam(mach_acct);
	unbecome_root(True);

	if ((smb_pass) != NULL && !(smb_pass->acct_ctrl & ACB_DISABLED) &&
        (smb_pass->smb_nt_passwd != NULL))
	{
		memcpy(md4pw, smb_pass->smb_nt_passwd, 16);
		dump_data(5, md4pw, 16);

		return True;
	}
	if (strequal(mach_name, global_myname))
	{
		DEBUG(0,("get_md4pw: *** LOOPBACK DETECTED - USING NULL KEY ***\n"));
		memset(md4pw, 0, 16);
		return True;
	}

	DEBUG(0,("get_md4pw: Workstation %s: no account in domain\n", mach_acct));
	return False;
}

/*************************************************************************
 api_net_req_chal:
 *************************************************************************/
static void api_net_req_chal( rpcsrv_struct *p,
                              prs_struct *data,
                              prs_struct *rdata)
{
	NET_Q_REQ_CHAL q_r;
	uint32 status = 0x0;

	fstring mach_acct;
	fstring mach_name;

	DEBUG(5,("api_net_req_chal(%d)\n", __LINE__));

	/* grab the challenge... */
	net_io_q_req_chal("", &q_r, data, 0);

	unistr2_to_ascii(mach_acct, &q_r.uni_logon_clnt, sizeof(mach_acct)-1);

	fstrcpy(mach_name, mach_acct);
	strlower(mach_name);

	fstrcat(mach_acct, "$");

	if (get_md4pw((char *)p->dc.md4pw, mach_name, mach_acct))
	{
		/* copy the client credentials */
		memcpy(p->dc.clnt_chal.data          , q_r.clnt_chal.data, sizeof(q_r.clnt_chal.data));
		memcpy(p->dc.clnt_cred.challenge.data, q_r.clnt_chal.data, sizeof(q_r.clnt_chal.data));

		/* create a server challenge for the client */
		/* Set these to random values. */
                generate_random_buffer(p->dc.srv_chal.data, 8, False);

		memcpy(p->dc.srv_cred.challenge.data, p->dc.srv_chal.data, 8);

		bzero(p->dc.sess_key, sizeof(p->dc.sess_key));

		/* from client / server challenges and md4 password, generate sess key */
		cred_session_key(&(p->dc.clnt_chal), &(p->dc.srv_chal),
				 (char *)p->dc.md4pw, p->dc.sess_key);
	}
	else
	{
		/* lkclXXXX take a guess at a good error message to return :-) */
		status = 0xC0000000 | NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT;
	}

	/* construct reply. */
	net_reply_req_chal(&q_r, rdata,
					&(p->dc.srv_chal), status);

}

/*************************************************************************
 api_net_auth:
 *************************************************************************/
static void api_net_auth( rpcsrv_struct *p,
                            prs_struct *data,
                            prs_struct *rdata)
{
	NET_Q_AUTH q_a;
	uint32 status = 0x0;

	DOM_CHAL srv_cred;
	UTIME srv_time;

	srv_time.time = 0;

	/* grab the challenge... */
	net_io_q_auth("", &q_a, data, 0);

	/* check that the client credentials are valid */
	if (cred_assert(&(q_a.clnt_chal), p->dc.sess_key,
                    &(p->dc.clnt_cred.challenge), srv_time))
	{

		/* create server challenge for inclusion in the reply */
		cred_create(p->dc.sess_key, &(p->dc.srv_cred.challenge), srv_time, &srv_cred);

		/* copy the received client credentials for use next time */
		memcpy(p->dc.clnt_cred.challenge.data, q_a.clnt_chal.data, sizeof(q_a.clnt_chal.data));
		memcpy(p->dc.srv_cred .challenge.data, q_a.clnt_chal.data, sizeof(q_a.clnt_chal.data));
	}
	else
	{
		status = NT_STATUS_ACCESS_DENIED | 0xC0000000;
	}

	/* construct reply. */
	net_reply_auth(&q_a, rdata, &srv_cred, status);
}

/*************************************************************************
 api_net_auth_2:
 *************************************************************************/
static void api_net_auth_2( rpcsrv_struct *p,
                            prs_struct *data,
                            prs_struct *rdata)
{
	NET_Q_AUTH_2 q_a;
	uint32 status = 0x0;

	DOM_CHAL srv_cred;
	UTIME srv_time;

	srv_time.time = 0;

	/* grab the challenge... */
	net_io_q_auth_2("", &q_a, data, 0);

	/* check that the client credentials are valid */
	if (cred_assert(&(q_a.clnt_chal), p->dc.sess_key,
                    &(p->dc.clnt_cred.challenge), srv_time))
	{

		/* create server challenge for inclusion in the reply */
		cred_create(p->dc.sess_key, &(p->dc.srv_cred.challenge), srv_time, &srv_cred);

		/* copy the received client credentials for use next time */
		memcpy(p->dc.clnt_cred.challenge.data, q_a.clnt_chal.data, sizeof(q_a.clnt_chal.data));
		memcpy(p->dc.srv_cred .challenge.data, q_a.clnt_chal.data, sizeof(q_a.clnt_chal.data));
	}
	else
	{
		status = NT_STATUS_ACCESS_DENIED | 0xC0000000;
	}

	/* construct reply. */
	net_reply_auth_2(&q_a, rdata, &srv_cred, status);
}

/*************************************************************************
 api_net_srv_pwset:
 *************************************************************************/
static void api_net_srv_pwset( rpcsrv_struct *p,
                               prs_struct *data,
                               prs_struct *rdata)
{
	NET_Q_SRV_PWSET q_a;
	uint32 status = NT_STATUS_WRONG_PASSWORD|0xC0000000;
	DOM_CRED srv_cred;
	pstring mach_acct;
	struct smb_passwd *smb_pass;
	BOOL ret;

	/* grab the challenge and encrypted password ... */
	net_io_q_srv_pwset("", &q_a, data, 0);

	/* checks and updates credentials.  creates reply credentials */
	if (deal_with_creds(p->dc.sess_key, &(p->dc.clnt_cred), 
	                    &(q_a.clnt_id.cred), &srv_cred))
	{
		memcpy(&(p->dc.srv_cred), &(p->dc.clnt_cred), sizeof(p->dc.clnt_cred));

		DEBUG(5,("api_net_srv_pwset: %d\n", __LINE__));

		unistr2_to_ascii(mach_acct, &q_a.clnt_id.login.uni_acct_name,
				 sizeof(mach_acct)-1);

		DEBUG(3,("Server Password Set Wksta:[%s]\n", mach_acct));

		become_root(True);
		smb_pass = getsmbpwnam(mach_acct);
		unbecome_root(True);

		if (smb_pass != NULL)
		{
			unsigned char pwd[16];
			int i;

			DEBUG(100,("Server password set : new given value was :\n"));
			for(i = 0; i < 16; i++)
			{
				DEBUG(100,("%02X ", q_a.pwd[i]));
			}
			DEBUG(100,("\n"));

			cred_hash3( pwd, q_a.pwd, p->dc.sess_key, 0);

			/* lies!  nt and lm passwords are _not_ the same: don't care */
			smb_pass->smb_passwd    = pwd;
			smb_pass->smb_nt_passwd = pwd;
			smb_pass->acct_ctrl     = ACB_WSTRUST;

			become_root(True);
			ret = mod_smbpwd_entry(smb_pass,False);
			unbecome_root(True);

			if (ret)
			{
				/* hooray! */
				status = 0x0;
			}
		}

		DEBUG(5,("api_net_srv_pwset: %d\n", __LINE__));

	}
	else
	{
		/* lkclXXXX take a guess at a sensible error code to return... */
		status = 0xC0000000 | NT_STATUS_NETWORK_CREDENTIAL_CONFLICT;
	}

	/* Construct reply. */
	net_reply_srv_pwset(&q_a, rdata, &srv_cred, status);
}


/*************************************************************************
 api_net_sam_logoff:
 *************************************************************************/
static void api_net_sam_logoff( rpcsrv_struct *p,
                                prs_struct *data,
                                prs_struct *rdata)
{
	NET_Q_SAM_LOGOFF q_l;
	NET_ID_INFO_CTR ctr;	

	DOM_CRED srv_cred;

	/* the DOM_ID_INFO_1 structure is a bit big.  plus we might want to
	   dynamically allocate it inside net_io_q_sam_logon, at some point */
	q_l.sam_id.ctr = &ctr;

	/* grab the challenge... */
	net_io_q_sam_logoff("", &q_l, data, 0);

	/* checks and updates credentials.  creates reply credentials */
	deal_with_creds(p->dc.sess_key, &(p->dc.clnt_cred), 
	                &(q_l.sam_id.client.cred), &srv_cred);
	memcpy(&(p->dc.srv_cred), &(p->dc.clnt_cred), sizeof(p->dc.clnt_cred));

	/* construct reply.  always indicate success */
	net_reply_sam_logoff(&q_l, rdata, &srv_cred, 0x0);
}

/*************************************************************************
 api_net_sam_sync:
 *************************************************************************/
static void api_net_sam_sync( rpcsrv_struct *p,
                              prs_struct *data,
                              prs_struct *rdata)
{
	NET_Q_SAM_SYNC q_s;
	DOM_CRED srv_creds;
	uint32 status = 0x0;

	/* grab the challenge... */
	net_io_q_sam_sync("", &q_s, data, 0);

	/* checks and updates credentials.  creates reply credentials */
	if (deal_with_creds(p->dc.sess_key, &(p->dc.clnt_cred), 
	                &(q_s.cli_creds), &srv_creds))
	{
		memcpy(&(p->dc.srv_cred), &(p->dc.clnt_cred),
		       sizeof(p->dc.clnt_cred));
	}
	else
	{
		status = 0xC0000000 | NT_STATUS_NETWORK_CREDENTIAL_CONFLICT;
	}

	/* construct reply. */
	net_reply_sam_sync(&q_s, rdata, p->dc.sess_key, &srv_creds, status);
}


/*************************************************************************
 net_login_interactive:
 *************************************************************************/
static uint32 net_login_interactive(NET_ID_INFO_1 *id1,
				struct sam_passwd *smb_pass,
				struct dcinfo *dc)
{
	uint32 status = 0x0;

	char nt_pwd[16];
	char lm_pwd[16];
	unsigned char key[16];

	memset(key, 0, 16);
	memcpy(key, dc->sess_key, 8);

	memcpy(lm_pwd, id1->lm_owf.data, 16);
	memcpy(nt_pwd, id1->nt_owf.data, 16);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("key:"));
	dump_data(100, key, 16);

	DEBUG(100,("lm owf password:"));
	dump_data(100, lm_pwd, 16);

	DEBUG(100,("nt owf password:"));
	dump_data(100, nt_pwd, 16);
#endif

	SamOEMhash((uchar *)lm_pwd, key, 0);
	SamOEMhash((uchar *)nt_pwd, key, 0);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("decrypt of lm owf password:"));
	dump_data(100, lm_pwd, 16);

	DEBUG(100,("decrypt of nt owf password:"));
	dump_data(100, nt_pwd, 16);
#endif

	if (smb_pass->smb_nt_passwd == NULL)
	{
		DEBUG(5,("warning: NETLOGON user %s only has an LM password\n",
		          smb_pass->unix_name));
	}

	if (memcmp(smb_pass->smb_passwd   , lm_pwd, 16) != 0 ||
	    smb_pass->smb_nt_passwd == NULL ||
	    memcmp(smb_pass->smb_nt_passwd, nt_pwd, 16) != 0)
	{
		status = 0xC0000000 | NT_STATUS_WRONG_PASSWORD;
	}

	return status;
}

/*************************************************************************
 net_login_network:
 *************************************************************************/
static uint32 net_login_network(NET_ID_INFO_2 *id2,
				struct sam_passwd *sam_pass,
				struct dcinfo *dc,
				char sess_key[16])
{
	fstring user;
	fstring domain;

	int nt_pw_len = id2->hdr_nt_chal_resp.str_str_len;
	int lm_pw_len = id2->hdr_lm_chal_resp.str_str_len;

	unistr2_to_ascii(user  , &id2->uni_user_name, sizeof(user)-1);
	unistr2_to_ascii(domain, &id2->uni_domain_name, sizeof(domain)-1);

	DEBUG(5,("net_login_network: lm_len:%d nt_len:%d user:%s domain:%s\n",
		lm_pw_len, nt_pw_len, user, domain));

	if (pass_check_smb(pwdb_sam_to_smb(sam_pass),
	                    domain,
	                    id2->lm_chal, 
	                    (uchar *)id2->lm_chal_resp.buffer, lm_pw_len, 
	                    (uchar *)id2->nt_chal_resp.buffer, nt_pw_len,
	                    NULL, sess_key)) 
	{
		unsigned char key[16];

		memset(key, 0, 16);
		memcpy(key, dc->sess_key, 8);

#ifdef DEBUG_PASSWORD
		DEBUG(100,("key:"));
		dump_data(100, key, 16);

		DEBUG(100,("user sess key:"));
		dump_data(100, sess_key, 16);
#endif

		SamOEMhash((uchar *)sess_key, key, 0);

#ifdef DEBUG_PASSWORD
		DEBUG(100,("encrypt of user session key:"));
		dump_data(100, sess_key, 16);
#endif

                  return 0x0;
	}

	return 0xC0000000 | NT_STATUS_WRONG_PASSWORD;
}

/*************************************************************************
 api_net_sam_logon:
 *************************************************************************/
static uint32 reply_net_sam_logon(NET_Q_SAM_LOGON *q_l,
				struct dcinfo *dc,
				DOM_CRED *srv_cred, NET_USER_INFO_3 *usr_info)
{
	struct sam_passwd *sam_pass = NULL;
	UNISTR2 *uni_samusr = NULL;
	UNISTR2 *uni_domain = NULL;
	fstring nt_username;
	char *enc_user_sess_key = NULL;
	char sess_key[16];

	NTTIME logon_time           ;
	NTTIME logoff_time          ;
	NTTIME kickoff_time         ;
	NTTIME pass_last_set_time   ;
	NTTIME pass_can_change_time ;
	NTTIME pass_must_change_time;

	fstring nt_name     ;
	fstring full_name   ;
	fstring logon_script;
	fstring profile_path;
	fstring home_dir    ;
	fstring dir_drive   ;

	uint32 user_rid ;
	uint32 group_rid;

	int num_gids = 0;
	DOMAIN_GRP *grp_mem = NULL;
	DOM_GID *gids = NULL;

	/* checks and updates credentials.  creates reply credentials */
	if (!deal_with_creds(dc->sess_key, &(dc->clnt_cred), 
	                     &(q_l->sam_id.client.cred), srv_cred))
	{
		return 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}
	
	memcpy(&(dc->srv_cred), &(dc->clnt_cred), sizeof(dc->clnt_cred));

	/* find the username */

	switch (q_l->sam_id.logon_level)
	{
		case INTERACTIVE_LOGON_TYPE:
		{
			uni_samusr = &(q_l->sam_id.ctr->auth.id1.uni_user_name);
			uni_domain        = &(q_l->sam_id.ctr->auth.id1.uni_domain_name);

			DEBUG(3,("SAM Logon (Interactive). Domain:[%s].  ", global_sam_name));
			break;
		}
		case NET_LOGON_TYPE:
		{
			uni_samusr = &(q_l->sam_id.ctr->auth.id2.uni_user_name);
			uni_domain        = &(q_l->sam_id.ctr->auth.id2.uni_domain_name);

			DEBUG(3,("SAM Logon (Network). Domain:[%s].  ", global_sam_name));
			break;
		}
		default:
		{
			DEBUG(2,("SAM Logon: unsupported switch value\n"));
			return 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;
		}
	} 

	/* check username exists */

	unistr2_to_ascii(nt_username, uni_samusr,
			 sizeof(nt_username)-1);

	DEBUG(3,("User:[%s]\n", nt_username));

	become_root(True);
	sam_pass = getsam21pwntnam(nt_username);
	unbecome_root(True);

	if (sam_pass == NULL)
	{
		return 0xC0000000 | NT_STATUS_NO_SUCH_USER;
	}
	else if (IS_BITS_SET_ALL(sam_pass->acct_ctrl, ACB_DISABLED) &&
		 IS_BITS_CLR_ALL(sam_pass->acct_ctrl, ACB_PWNOTREQ))
	{
		return 0xC0000000 | NT_STATUS_ACCOUNT_DISABLED;
	}

	logon_time            = sam_pass->logon_time;
	logoff_time           = sam_pass->logoff_time;
	kickoff_time          = sam_pass->kickoff_time;
	pass_last_set_time    = sam_pass->pass_last_set_time;
	pass_can_change_time  = sam_pass->pass_can_change_time;
	pass_must_change_time = sam_pass->pass_must_change_time;

	fstrcpy(nt_name     , sam_pass->nt_name);
	fstrcpy(full_name   , sam_pass->full_name);
	fstrcpy(logon_script, sam_pass->logon_script);
	fstrcpy(profile_path, sam_pass->profile_path);
	fstrcpy(home_dir    , sam_pass->home_dir);
	fstrcpy(dir_drive   , sam_pass->dir_drive);

	user_rid  = sam_pass->user_rid;
	group_rid = sam_pass->group_rid;

	/* validate password - if required */

	if (!(IS_BITS_SET_ALL(sam_pass->acct_ctrl, ACB_PWNOTREQ)))
	{
		uint32 status = 0x0;
		switch (q_l->sam_id.logon_level)
		{
			case INTERACTIVE_LOGON_TYPE:
			{
				/* interactive login. */
				status = net_login_interactive(&q_l->sam_id.ctr->auth.id1, sam_pass, dc);
				break;
			}
			case NET_LOGON_TYPE:
			{
				/* network login.  lm challenge and 24 byte responses */
				status = net_login_network(&q_l->sam_id.ctr->auth.id2, sam_pass, dc, sess_key);
				enc_user_sess_key = sess_key;
				break;
			}
		}
		if (status != 0x0)
		{
			return status;
		}
	}

	/* lkclXXXX this is the point at which, if the login was
	successful, that the SAM Local Security Authority should
	record that the user is logged in to the domain.
	*/

	/* return the profile plus other bits :-) */

	/* set up pointer indicating user/password failed to be found */
	usr_info->ptr_user_info = 0;

	if (!getusergroupsntnam(nt_username, &grp_mem, &num_gids))
	{
		return 0xC0000000 | NT_STATUS_INVALID_PRIMARY_GROUP;
	}

	num_gids = make_dom_gids(grp_mem, num_gids, &gids);

	make_net_user_info3(usr_info,
		&logon_time,
		&logoff_time,
		&kickoff_time,
		&pass_last_set_time,
		&pass_can_change_time,
		&pass_must_change_time,

		nt_name         , /* user_name */
		full_name       , /* full_name */
		logon_script    , /* logon_script */
		profile_path    , /* profile_path */
		home_dir        , /* home_dir */
		dir_drive       , /* dir_drive */

		0, /* logon_count */
		0, /* bad_pw_count */

		user_rid   , /* RID user_id */
		group_rid  , /* RID group_id */
		num_gids,    /* uint32 num_groups */
		gids    , /* DOM_GID *gids */
		0x20    , /* uint32 user_flgs (?) */

		enc_user_sess_key, /* char sess_key[16] */

		global_myname  , /* char *logon_srv */
		global_sam_name, /* char *logon_dom */
		&global_sam_sid, /* DOM_SID *dom_sid */
		NULL); /* char *other_sids */

	/* Free any allocated groups array. */
	if (gids)
	{
		free((char *)gids);
	}

	return 0x0;
}

/*************************************************************************
 api_net_sam_logon:
 *************************************************************************/
static void api_net_sam_logon( rpcsrv_struct *p,
                               prs_struct *data,
                               prs_struct *rdata)
{
	NET_Q_SAM_LOGON q_l;
	NET_ID_INFO_CTR ctr;	
	NET_USER_INFO_3 usr_info;
	uint32 status = 0x0;
	DOM_CRED srv_cred;

	q_l.sam_id.ctr = &ctr;
	net_io_q_sam_logon("", &q_l, data, 0);

	status = reply_net_sam_logon(&q_l, &p->dc, &srv_cred, &usr_info);
	net_reply_sam_logon(&q_l, rdata, &srv_cred, &usr_info, status);
}


/*************************************************************************
 api_net_trust_dom_list:
 *************************************************************************/
static void api_net_trust_dom_list( rpcsrv_struct *p,
                                    prs_struct *data,
                                    prs_struct *rdata)
{
	NET_Q_TRUST_DOM_LIST q_t;
	char **doms = NULL;
	uint32 num_doms = 0;

	enumtrustdoms(&doms, &num_doms);

	DEBUG(6,("api_net_trust_dom_list: %d\n", __LINE__));

	/* grab the lsa trusted domain list query... */
	net_io_q_trust_dom("", &q_t, data, 0);

	/* construct reply. */
	net_reply_trust_dom_list(&q_t, rdata,
				num_doms, doms);

	free_char_array(num_doms, doms);

	DEBUG(6,("api_net_trust_dom_list: %d\n", __LINE__));
}


/*************************************************************************
 error messages cropping up when using nltest.exe...
 *************************************************************************/
#define ERROR_NO_SUCH_DOMAIN   0x54b
#define ERROR_NO_LOGON_SERVERS 0x51f

/*************************************************************************
 api_net_logon_ctrl2:
 *************************************************************************/
static void api_net_logon_ctrl2( rpcsrv_struct *p,
                                 prs_struct *data,
                                 prs_struct *rdata)
{
	NET_Q_LOGON_CTRL2 q_l;

	/* lkclXXXX - guess what - absolutely no idea what these are! */
	uint32 flags = 0x0;
	uint32 pdc_connection_status = 0x0;
	uint32 logon_attempts = 0x0;
	uint32 tc_status = ERROR_NO_LOGON_SERVERS;
	char *trusted_domain = "test_domain";

	DEBUG(6,("api_net_logon_ctrl2: %d\n", __LINE__));

	/* grab the lsa netlogon ctrl2 query... */
	net_io_q_logon_ctrl2("", &q_l, data, 0);

	/* construct reply. */
	net_reply_logon_ctrl2(&q_l, rdata,
				flags, pdc_connection_status, logon_attempts,
				tc_status, trusted_domain);

	DEBUG(6,("api_net_logon_ctrl2: %d\n", __LINE__));
}

/*******************************************************************
 array of \PIPE\NETLOGON operations
 ********************************************************************/
static struct api_struct api_net_cmds [] =
{
	{ "NET_REQCHAL"       , NET_REQCHAL       , api_net_req_chal       }, 
	{ "NET_AUTH"          , NET_AUTH          , api_net_auth           },
	{ "NET_AUTH2"         , NET_AUTH2         , api_net_auth_2         }, 
	{ "NET_SRVPWSET"      , NET_SRVPWSET      , api_net_srv_pwset      }, 
	{ "NET_SAMLOGON"      , NET_SAMLOGON      , api_net_sam_logon      }, 
	{ "NET_SAMLOGOFF"     , NET_SAMLOGOFF     , api_net_sam_logoff     }, 
	{ "NET_LOGON_CTRL2"   , NET_LOGON_CTRL2   , api_net_logon_ctrl2    }, 
	{ "NET_TRUST_DOM_LIST", NET_TRUST_DOM_LIST, api_net_trust_dom_list },
	{ "NET_SAM_SYNC"      , NET_SAM_SYNC      , api_net_sam_sync       },
        {  NULL               , 0                 , NULL                   }
};

/*******************************************************************
 receives a netlogon pipe and responds.
 ********************************************************************/
BOOL api_netlog_rpc(rpcsrv_struct *p)
{
	return api_rpcTNP(p, "api_netlog_rpc", api_net_cmds);
}
