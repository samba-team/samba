/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997,
 *  Copyright (C) Jeremy Allison                    1998,
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

#if 0

void gen_next_creds( struct ntdom_info *nt, DOM_CRED *new_clnt_cred);
#endif

#include "includes.h"
#include "nterr.h"
#include "sids.h"

extern int DEBUGLEVEL;

extern pstring global_myname;

/*************************************************************************
 _net_req_chal
 *************************************************************************/
/*
uint32 cli_net_req_chal( const char *srv_name, const char* myhostname,
				DOM_CHAL *clnt_chal, DOM_CHAL *srv_chal);

typedef struct net_q_req_chal_info
{
    uint32  undoc_buffer; /* undocumented buffer pointer */
    UNISTR2 uni_logon_srv; /* logon server unicode string */
    UNISTR2 uni_logon_clnt; /* logon client unicode string */
    DOM_CHAL clnt_chal; /* client challenge */

} NET_Q_REQ_CHAL;

typedef struct net_r_req_chal_info
{
    DOM_CHAL srv_chal; /* server challenge */

  uint32 status; /* return code */

} NET_R_REQ_CHAL;

static void net_reply_req_chal(NET_Q_REQ_CHAL *q_c, prs_struct *rdata,
					DOM_CHAL *srv_chal, uint32 srv_time)
*/
uint32 _net_req_chal(	const UNISTR2 *uni_logon_server,
				const UNISTR *uni_logon_client,
				const DOM_CHAL *clnt_chal,
				DOM_CHAL *server_challenge,
				uint16 remote_pid	); /* strikerXXXX added this parameter */
{
	fstring trust_acct;
	fstring trust_name;

	struct dcinfo dc;

	ZERO_STRUCT(dc);

	unistr2_to_ascii(trust_acct, uni_logon_clnt, sizeof(trust_acct)-1);

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
	memcpy(dc.clnt_chal.data          , srv_chal->data, sizeof(srv_chal->data));
	memcpy(dc.clnt_cred.challenge.data, srv_chal->data, sizeof(srv_chal->data));

	bzero(dc.sess_key, sizeof(dc.sess_key));

	/* from client / server challenges and md4 password, generate sess key */
	cred_session_key(&(dc.clnt_chal), &(dc.srv_chal),
				 (char *)dc.md4pw, dc.sess_key);

	if (!cred_store(p->remote_pid, global_sam_name, trust_name, &dc))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	return NT_STATUS_NOPROBLEMO;
}

/*************************************************************************
 api_net_req_chal
 *************************************************************************/
static void api_net_req_chal( rpcsrv_struct *p,
                              prs_struct *data,
                              prs_struct *rdata)
{
	NET_Q_REQ_CHAL q_r;
	NET_R_REQ_CHAL r_c;

	ZERO_STRUCT(q_r);
	ZERO_STRUCT(r_c);

	/* grab the challenge... */
	net_io_q_req_chal("", &q_r, data, 0);
	r_c.status = _net_req_chal(&q_r.uni_logon_srv, &q_r.uni_logon_clnt, 
					   &q_r.clnt_chal, &r_c.srv_chal,
					   p->remote_pid); /* strikerXXXX have to pass this parameter */

	/* store the response in the SMB stream */
	net_io_r_req_chal("", &r_c, rdata, 0);
}

/*************************************************************************
 _net_logon_ctrl2
 *************************************************************************/
/*
BOOL cli_net_logon_ctrl2(const char* srv_name, uint32 status_level);

typedef struct net_q_logon_ctrl2_info
{
	uint32       ptr;             /* undocumented buffer pointer */
	UNISTR2      uni_server_name; /* server name, starting with two '\'s */
	
	uint32       function_code; /* 0x1 */
	uint32       query_level;   /* 0x1, 0x3 */
	uint32       switch_value;  /* 0x1 */

} NET_Q_LOGON_CTRL2;

typedef struct net_r_logon_ctrl2_info
{
	uint32       switch_value;  /* 0x1, 0x3 */
	uint32       ptr;

	NETLOGON_INFO logon;

	uint32 status; /* return code */

} NET_R_LOGON_CTRL2;


uint32 _net_logon_ctrl2(NET_Q_LOGON_CTRL2 *q_l, prs_struct *rdata,
			uint32 flags, uint32 pdc_status, uint32 logon_attempts,
			uint32 tc_status, char *trust_domain_name)
*/
uint32 _net_logon_ctrl2(const	UNISTR2 *uni_server_name, /* server name, starting with two '\'s */
				uint32 function_code,
				uint32 query_level,
				uint32 switch_value,
				uint32 *reply_switch_value,
				NETLOGON_INFO *logon_info)
{
	/* lkclXXXX - guess what - absolutely no idea what these are! */
	uint32 flags = 0x0;
	uint32 pdc_connection_status = 0x0;
	uint32 logon_attempts = 0x0;
	uint32 tc_status = ERROR_NO_LOGON_SERVERS;
	char *trusted_domain = "test_domain";

	*reply_switch_value = query_level;

	switch (query_level)
	{
		case 1:
		{
			make_netinfo_1(&(logon_info->info1), flags, pdc_status);	
			break;
		}
		case 2:
		{
			make_netinfo_2(&(logon_info->info2), flags, pdc_status,
			               tc_status, trusted_domain_name);	
			break;
		}
		case 3:
		{
			make_netinfo_3(&(logon_info->info3), flags, logon_attempts);	
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
 api_net_logon_ctrl2
 *************************************************************************/
static void api_net_logon_ctrl2( rpcsrv_struct *p,
                                 prs_struct *data,
                                 prs_struct *rdata)
{
	NET_Q_LOGON_CTRL2 q_l;
	NET_R_LOGON_CTRL2 r_l;

	NETLOGON_INFO logon_info;
	uint32 switch_value;
	uint32 status;

	ZERO_STRUCT(q_l);
	ZERO_STRUCT(r_l);

	/* grab the lsa netlogon ctrl2 query... */
	net_io_q_logon_ctrl2("", &q_l, data, 0);
	status = _net_logon_ctrl2(&q_l.uni_server_name,
					  q_l.function_code,
					  q_l.query_level,
					  q_l.switch_value,
					  &switch_value,
					  &logon_info);
	make_r_logon_ctrl2(&r_l, switch_value, &logon_info, status);

	/* store the response in the SMB stream */
	net_io_r_logon_ctrl2("", &r_l, rdata, 0);
}

/*************************************************************************
 _net_trust_dom_list
 *************************************************************************/
/*
typedef struct net_q_trust_dom_info
{
	uint32       ptr;             /* undocumented buffer pointer */
	UNISTR2      uni_server_name; /* server name, starting with two '\'s */
	
	uint32       function_code; /* 0x31 */

} NET_Q_TRUST_DOM_LIST;

typedef struct net_r_trust_dom_info
{
	BUFFER2 uni_trust_dom_name;

	uint32 status; /* return code */

} NET_R_TRUST_DOM_LIST;

static void net_reply_trust_dom_list(NET_Q_TRUST_DOM_LIST *q_t, prs_struct *rdata,
			uint32 num_trust_domains, char **trust_domain_name)
*/
uint32 _net_reply_trust_dom_list(const UNISTR2 *uni_server_name,
					   uint32 function_code,
					   BUFFER2 *uni_trust_dom_name)
{
	char **doms = NULL;
	uint32 num_doms = 0;

	enumtrustdoms(&doms, &num_doms);

	make_buffer2_multi(uni_trust_dom_name,
			dom_name, num_doms);

	if (num_doms == 0)
	{
		uni_trust_dom_name->buf_max_len = 0x2;
		uni_trust_dom_name->buf_len = 0x2;
	}
	uni_trust_dom_name->undoc = 0x1;
	
	free_char_array(num_doms, doms);

	return NT_STATUS_NO_PROBLEMO;
}

/*************************************************************************
 api_net_trust_dom_list
 *************************************************************************/
static void api_net_trust_dom_list( rpcsrv_struct *p,
                                    prs_struct *data,
                                    prs_struct *rdata)
{
	NET_Q_TRUST_DOM_LIST q_t;
	NET_R_TRUST_DOM_LIST r_t;

	ZERO_STRUCT(q_t);
	ZERO_STRUCT(r_t);

	/* grab the lsa trusted domain list query... */
	net_io_q_trust_dom("", &q_t, data, 0);
	r_t.status = _net_trust_dom_list(&q_t.uni_server_name,
						   q_t.function_code,
						   &r_t.uni_trust_dom_name);
	
	/* store the response in the SMB stream */
	net_io_r_trust_dom("", &r_t, rdata, 0);
}

/*************************************************************************
 _net_auth
 *************************************************************************/
/*
typedef struct net_q_auth_info
{
    DOM_LOG_INFO clnt_id; /* client identification info */
    DOM_CHAL clnt_chal;     /* client-calculated credentials */


} NET_Q_AUTH;

typedef struct net_r_auth_info
{
    DOM_CHAL srv_chal;     /* server-calculated credentials */

  uint32 status; /* return code */

} NET_R_AUTH;

static void net_reply_auth(NET_Q_AUTH *q_a, prs_struct *rdata,
				DOM_CHAL *resp_cred, int status)
*/
uint32 _net_auth(const DOM_LOG_INFO *clnt_id,
		     const DOM_CHAL *clnt_chal,
		     DOM_CHAL *srv_chal,
		     uint16 remote_pid); /* strikerXXXX added this parameter */
{
	UTIME srv_time;
	fstring trust_name;
	struct dcinfo dc;

	ZERO_STRUCT(dc);

	srv_time.time = 0;

	unistr2_to_ascii(trust_name, clnt_id->uni_comp_name,
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

	/* set up the LSA AUTH 2 response */

	make_net_r_auth(&r_a, resp_cred, status);


}

/*************************************************************************
 api_net_auth
 *************************************************************************/
static void api_net_auth( rpcsrv_struct *p,
                            prs_struct *data,
                            prs_struct *rdata)
{
	NET_Q_AUTH q_a;
	NET_R_AUTH r_a;

	ZERO_STRUCT(q_a);
	ZERO_STRUCT(r_a);

	/* grab the challenge... */
	net_io_q_auth("", &q_a, data, 0);
	r_a.status = _net_auth(&q_a.clnt_id,
				     &q_a.clnt_chal,
				     &r_a.srv_chal,
				     p->remote_pid); /* strikerXXXX have to pass this parameter */

	/* store the response in the SMB stream */
	net_io_r_auth("", &r_a, rdata, 0);
}

/*************************************************************************
 _net_auth_2
 *************************************************************************/
/*
uint32 cli_net_auth2(const char *srv_name,
				const char *trust_acct, 
				const char *acct_name, 
				uint16 sec_chan, 
				uint32 *neg_flags, DOM_CHAL *srv_chal);

typedef struct net_q_auth2_info
{
    DOM_LOG_INFO clnt_id; /* client identification info */
    DOM_CHAL clnt_chal;     /* client-calculated credentials */

    NEG_FLAGS clnt_flgs; /* usually 0x0000 01ff */

} NET_Q_AUTH_2;

typedef struct net_r_auth2_info
{
    DOM_CHAL srv_chal;     /* server-calculated credentials */
    NEG_FLAGS srv_flgs; /* usually 0x0000 01ff */

  uint32 status; /* return code */

} NET_R_AUTH_2;

static void net_reply_auth_2(NET_Q_AUTH_2 *q_a, prs_struct *rdata,
				DOM_CHAL *resp_cred, int status)
*/
uint32 _net_auth_2(const DOM_LOG_INFO *clnt_id,
			 const DOM_CHAL *clnt_chal,
			 const NEG_FLAGS *clnt_flgs,
			 DOM_CHAL *srv_chal,
			 NEG_FLAGS *srv_flgs,
			 uint16 remote_pid); /* strikerXXXX added this parameter */
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
 api_net_auth_2:
 *************************************************************************/
static void api_net_auth_2( rpcsrv_struct *p,
                            prs_struct *data,
                            prs_struct *rdata)
{
	NET_Q_AUTH_2 q_a;
	NET_R_AUTH_2 r_a;

	ZERO_STRUCT(q_a);
	ZERO_STRUCT(r_a);

	/* grab the challenge... */
	net_io_q_auth_2("", &q_a, data, 0);
	r_a.status = _net_auth2(&q_a.clnt_id,
					&q_a.clnt_chal,
					&q_a.clnt_flgs,
					&r_a.srv_chal,
					&r_a.srv_flgs,
					p->remote_pid); /* strikerXXXX have to pass this parameter */

	/* store the response in the SMB stream */
	net_io_r_auth_2("", &r_a, rdata, 0);
}

/*************************************************************************
 _net_srv_pwset
 *************************************************************************/
/*
BOOL cli_net_srv_pwset(const char* srv_name,
				const char* myhostname,
				const char* trust_acct,
				uint8 hashed_trust_pwd[16],
				uint16 sec_chan_type);

typedef struct net_q_srv_pwset_info
{
    DOM_CLNT_INFO clnt_id; /* client identification/authentication info */
    uint8 pwd[16]; /* new password - undocumented. */

} NET_Q_SRV_PWSET;
    
typedef struct net_r_srv_pwset_info
{
    DOM_CRED srv_cred;     /* server-calculated credentials */

  uint32 status; /* return code */

} NET_R_SRV_PWSET;

static void net_reply_srv_pwset(NET_Q_SRV_PWSET *q_s, prs_struct *rdata,
				DOM_CRED *srv_cred, int status)
*/
uint32 _net_srv_pwset(const DOM_CLNT_INFO *clnt_id,
			    const uint8 *pwd,
			    DOM_CRED *srv_cred,
			    uint16 remote_pid); /* strikerXXXX added this parameter */
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
		/* bogus! */
		/* strikerXXXX Luke could you have a look at this and make up some
               reasonable return code? */
	}

	if (!cred_store(remote_pid, global_sam_name, trust_name, &dc))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	return NT_STATUS_NOPROBLEMO;
}

/*************************************************************************
 api_net_srv_pwset:
 *************************************************************************/
static void api_net_srv_pwset( rpcsrv_struct *p,
                               prs_struct *data,
                               prs_struct *rdata)
{
	NET_Q_SRV_PWSET q_a;
	NET_R_SRV_PWSET r_s;

	ZERO_STRUCT(q_a);
	ZERO_STRUCT(r_s);

	/* grab the challenge and encrypted password ... */
	net_io_q_srv_pwset("", &q_a, data, 0);
	r_s.status = _net_srv_pwset(&q_a.clnt_id,
					    q_a.pwd,
					    r_s.srv_cred,
					    p->remote_pid); /* strikerXXXX have to pass this parameter */

	/* store the response in the SMB stream */
	net_io_r_srv_pwset("", &r_s, rdata, 0);
}

/* strikerXXXX GOT TO HERE!!!!!!!! */

/*************************************************************************
 _net_sam_logon
 *************************************************************************/
/*
uint32 cli_net_sam_logon(const char* srv_name, const char* myhostname,
				NET_ID_INFO_CTR *ctr, 
				NET_USER_INFO_3 *user_info3);

typedef struct net_q_sam_logon_info
{
	DOM_SAM_INFO sam_id;
	uint16          validation_level;

} NET_Q_SAM_LOGON;

typedef struct net_r_sam_logon_info
{
    uint32 buffer_creds; /* undocumented buffer pointer */
    DOM_CRED srv_creds; /* server credentials.  server time stamp appears to be ignored. */
    
	uint16 switch_value; /* 3 - indicates type of USER INFO */
    NET_USER_INFO_3 *user;

    uint32 auth_resp; /* 1 - Authoritative response; 0 - Non-Auth? */

  uint32 status; /* return code */

} NET_R_SAM_LOGON;

static void net_reply_sam_logon(NET_Q_SAM_LOGON *q_s, prs_struct *rdata,
				DOM_CRED *srv_cred, NET_USER_INFO_3 *user_info,
				uint32 status)
*/
uint32 _net_sam_logon(const DOM_SAM_INFO *sam_id,
			    uint16 validation_level,
			    DOM_CRED *srv_creds,
			    uint16 *switch_value,
			    NET_USER_INFO_3 *user,
			    uint32 *auth_resp,
			    uint16 remote_pid); /* strikerXXXX added this parameter */
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
 api_net_sam_logon
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

	status = reply_net_sam_logon(p->remote_pid, &q_l, &srv_cred, &usr_info);
	net_reply_sam_logon(&q_l, rdata, &srv_cred, &usr_info, status);
}


/*************************************************************************
 net_reply_sam_logoff:
 *************************************************************************/
/*
BOOL cli_net_sam_logoff(const char* srv_name, const char* myhostname,
				NET_ID_INFO_CTR *ctr);
*/
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
/*
BOOL cli_net_sam_sync( const char* srv_name, const char* myhostname,
				uint32 database_id,
				uint32 *num_deltas,
				SAM_DELTA_HDR *hdr_deltas,
				SAM_DELTA_CTR *deltas);
*/
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
static BOOL get_md4pw(char *md4pw, char *trust_name, char *trust_acct)
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
	                  client_connection_name(), client_connection_addr()))
	{
		DEBUG(0,("get_md4pw: Workstation %s denied access to domain\n", trust_acct));
		return False;
	}
#endif /* 0 */

	become_root(True);
	smb_pass = getsmbpwnam(trust_acct);
	unbecome_root(True);

	if ((smb_pass) != NULL && !(smb_pass->acct_ctrl & ACB_DISABLED) &&
        (smb_pass->smb_nt_passwd != NULL))
	{
		memcpy(md4pw, smb_pass->smb_nt_passwd, 16);
		dump_data(5, md4pw, 16);

		return True;
	}
	if (strequal(trust_name, global_myname))
	{
		DEBUG(0,("get_md4pw: *** LOOPBACK DETECTED - USING NULL KEY ***\n"));
		memset(md4pw, 0, 16);
		return True;
	}

	DEBUG(0,("get_md4pw: Workstation %s: no account in domain\n", trust_acct));
	return False;
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
	uint32 status = 0x0;

	fstring trust_name;
	struct dcinfo dc;

	/* the DOM_ID_INFO_1 structure is a bit big.  plus we might want to
	   dynamically allocate it inside net_io_q_sam_logon, at some point */
	q_l.sam_id.ctr = &ctr;

	/* grab the challenge... */
	net_io_q_sam_logoff("", &q_l, data, 0);

	unistr2_to_ascii(trust_name, &q_l.sam_id.client.login.uni_comp_name,
	                             sizeof(trust_name)-1);

	if (!cred_get(p->remote_pid, global_sam_name, trust_name, &dc))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* checks and updates credentials.  creates reply credentials */
	deal_with_creds(dc.sess_key, &(dc.clnt_cred), 
	                &(q_l.sam_id.client.cred), &srv_cred);
	memcpy(&(dc.srv_cred), &(dc.clnt_cred), sizeof(dc.clnt_cred));

	if (status == 0x0 && !cred_store(p->remote_pid, global_sam_name, trust_name, &dc))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}
	/* construct reply.  always indicate success */
	net_reply_sam_logoff(&q_l, rdata, &srv_cred, status);
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

	fstring trust_name;
	struct dcinfo dc;

	/* grab the challenge... */
	net_io_q_sam_sync("", &q_s, data, 0);

	unistr2_to_ascii(trust_name, &q_s.uni_cli_name,
	                             sizeof(trust_name)-1);

	if (!cred_get(p->remote_pid, global_sam_name, trust_name, &dc))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	if (status == 0x0)
	{
		/* checks and updates credentials.  creates reply credentials */
		if (deal_with_creds(dc.sess_key, &(dc.clnt_cred), 
				&(q_s.cli_creds), &srv_creds))
		{
			memcpy(&(dc.srv_cred), &(dc.clnt_cred),
			       sizeof(dc.clnt_cred));
		}
		else
		{
			status = 0xC0000000 | NT_STATUS_ACCESS_DENIED;
		}
	}

	if (status == 0x0 && !cred_store(p->remote_pid, global_sam_name, trust_name, &dc))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* construct reply. */
	net_reply_sam_sync(&q_s, rdata, dc.sess_key, &srv_creds, status);
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

	dump_data_pw("key:", key, 16);

	dump_data_pw("lm owf password:", lm_pwd, 16);
	dump_data_pw("nt owf password:", nt_pwd, 16);

	SamOEMhash((uchar *)lm_pwd, key, 0);
	SamOEMhash((uchar *)nt_pwd, key, 0);

	dump_data_pw("decrypt of lm owf password:", lm_pwd, 16);
	dump_data_pw("decrypt of nt owf password:", nt_pwd, 16);

	if (smb_pass->smb_passwd == NULL)
	{
		DEBUG(5,("warning: NETLOGON user %s has no LM password\n",
		          smb_pass->unix_name));
	}

	if (smb_pass->smb_nt_passwd == NULL)
	{
		DEBUG(5,("warning: NETLOGON user %s has no NT password\n",
		          smb_pass->unix_name));
	}

	if (smb_pass->smb_passwd == NULL ||
	    memcmp(smb_pass->smb_passwd   , lm_pwd, 16) != 0 ||
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

                  return 0x0;
	}

	return 0xC0000000 | NT_STATUS_WRONG_PASSWORD;
}

/*************************************************************************
 net_login_network:
 *************************************************************************/
static uint32 net_login_network(NET_ID_INFO_2 *id2,
				struct sam_passwd *sam_pass,
				struct dcinfo *dc,
				char usr_sess_key[16],
				char lm_pw8[8])
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
	                    NULL, usr_sess_key)) 
	{
		unsigned char key[16];

		memcpy(lm_pw8, sam_pass->smb_passwd, 8);

		memset(key, 0, 16);
		memcpy(key, dc->sess_key, 8);

#ifdef DEBUG_PASSWORD
		DEBUG(100,("key:"));
		dump_data(100, key, 16);

		DEBUG(100,("user sess key:"));
		dump_data(100, usr_sess_key, 16);

		DEBUG(100,("lm_pw8:"));
		dump_data(100, lm_pw8, 16);
#endif
		SamOEMhash((uchar *)lm_pw8, key, 3);
		SamOEMhash((uchar *)usr_sess_key, key, 0);

#ifdef DEBUG_PASSWORD
		DEBUG(100,("encrypt of user session key:"));
		dump_data(100, usr_sess_key, 16);
		DEBUG(100,("encrypt of lm_pw8:"));
		dump_data(100, lm_pw8, 16);
#endif

		return 0x0;
	}

	return 0xC0000000 | NT_STATUS_WRONG_PASSWORD;
}

/*************************************************************************
 api_net_sam_logon:
 *************************************************************************/
static uint32 reply_net_sam_logon(uint32 remote_pid,
				NET_Q_SAM_LOGON *q_l,
				DOM_CRED *srv_cred, NET_USER_INFO_3 *usr_info)
{
	struct sam_passwd *sam_pass = NULL;
	UNISTR2 *uni_samusr = NULL;
	UNISTR2 *uni_domain = NULL;
	fstring nt_username;
	char *enc_user_sess_key = NULL;
	char usr_sess_key[16];
	char lm_pw8[16];
	char *padding = NULL;

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

	fstring trust_name;
	struct dcinfo dc;

	unistr2_to_ascii(trust_name, &q_l->sam_id.client.login.uni_comp_name,
	                             sizeof(trust_name)-1);

	if (!cred_get(remote_pid, global_sam_name, trust_name, &dc))
	{
		return 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* checks and updates credentials.  creates reply credentials */
	if (!deal_with_creds(dc.sess_key, &dc.clnt_cred, 
	                     &(q_l->sam_id.client.cred), srv_cred))
	{
		return 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}
	
	memcpy(&dc.srv_cred, &dc.clnt_cred, sizeof(dc.clnt_cred));

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
		case NETWORK_LOGON_TYPE:
		{
			uni_samusr = &(q_l->sam_id.ctr->auth.id2.uni_user_name);
			uni_domain        = &(q_l->sam_id.ctr->auth.id2.uni_domain_name);

			DEBUG(3,("SAM Logon (Network). Domain:[%s].  ", global_sam_name));
			break;
		}
		case GENERAL_LOGON_TYPE:
		{
			uni_samusr = &(q_l->sam_id.ctr->auth.id4.uni_user_name);
			uni_domain = &(q_l->sam_id.ctr->auth.id4.uni_domain_name);

			DEBUG(3,("SAM Logon (General). Domain:[%s].  ", global_sam_name));
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

	/*
	 * IMPORTANT: do a General Login BEFORE the others,
	 * because "update encrypted" may be enabled, which
	 * will result in the smb password entry being added.
	 *
	 * calling general login AFTER the getsampwntname() is
	 * not guaranteed to deliver.
	 */

	if (q_l->sam_id.logon_level == GENERAL_LOGON_TYPE)
	{
		/* general login.  cleartext password */
		uint32 status = 0x0;
		status = net_login_general(&q_l->sam_id.ctr->auth.id4, &dc, usr_sess_key);
		enc_user_sess_key = usr_sess_key;

		if (status != 0x0)
		{
			return status;
		}
	}

	/*
	 * now obtain smb passwd entry, which MAY have just been
	 * added by "update encrypted" in general login
	 */
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
	else if (IS_BITS_SET_ALL(sam_pass->acct_ctrl, ACB_DOMTRUST))
	{
		return 0xc0000000|NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT;
	}
	else if (IS_BITS_SET_ALL(sam_pass->acct_ctrl, ACB_SVRTRUST))
	{
		return 0xc0000000|NT_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT;
	}
	else if (IS_BITS_SET_ALL(sam_pass->acct_ctrl, ACB_WSTRUST))
	{
		return 0xc0000000|NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT;
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
				status = net_login_interactive(&q_l->sam_id.ctr->auth.id1, sam_pass, &dc);
				break;
			}
			case NETWORK_LOGON_TYPE:
			{
				/* network login.  lm challenge and 24 byte responses */
				status = net_login_network(&q_l->sam_id.ctr->auth.id2, sam_pass, &dc, usr_sess_key, lm_pw8);
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

		enc_user_sess_key, /* char usr_sess_key[16] */

		global_myname  , /* char *logon_srv */
		global_sam_name, /* char *logon_dom */

		padding,

		&global_sam_sid, /* DOM_SID *dom_sid */
		NULL); /* char *other_sids */

	/* Free any allocated groups array. */
	if (gids)
	{
		free((char *)gids);
	}

	if (!cred_store(remote_pid, global_sam_name, trust_name, &dc))
	{
		return 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	return 0x0;
}



/*************************************************************************
 error messages cropping up when using nltest.exe...
 *************************************************************************/
#define ERROR_NO_SUCH_DOMAIN   0x54b
#define ERROR_NO_LOGON_SERVERS 0x51f


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
