/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  Copyright (C) Jeremy Allison               1998-2001.
 *  Copyright (C) Andrew Bartlett                   2001.
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

/* This is the implementation of the netlogon pipe. */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/*************************************************************************
 init_net_r_req_chal:
 *************************************************************************/

static void init_net_r_req_chal(NET_R_REQ_CHAL *r_c,
                                DOM_CHAL *srv_chal, NTSTATUS status)
{
	DEBUG(6,("init_net_r_req_chal: %d\n", __LINE__));
	memcpy(r_c->srv_chal.data, srv_chal->data, sizeof(srv_chal->data));
	r_c->status = status;
}

/*************************************************************************
 error messages cropping up when using nltest.exe...
 *************************************************************************/

#define ERROR_NO_SUCH_DOMAIN   0x54b
#define ERROR_NO_LOGON_SERVERS 0x51f

/*************************************************************************
 net_reply_logon_ctrl:
 *************************************************************************/

/* Some flag values reverse engineered from NLTEST.EXE */

#define LOGON_CTRL_IN_SYNC          0x00
#define LOGON_CTRL_REPL_NEEDED      0x01
#define LOGON_CTRL_REPL_IN_PROGRESS 0x02

NTSTATUS _net_logon_ctrl(pipes_struct *p, NET_Q_LOGON_CTRL *q_u, 
		       NET_R_LOGON_CTRL *r_u)
{
	uint32 flags = 0x0;
	uint32 pdc_connection_status = 0x00; /* Maybe a win32 error code? */
	
	/* Setup the Logon Control response */

	init_net_r_logon_ctrl(r_u, q_u->query_level, flags, 
			      pdc_connection_status);

	return r_u->status;
}

/****************************************************************************
Send a message to smbd to do a sam synchronisation
**************************************************************************/
static void send_sync_message(void)
{
        TDB_CONTEXT *tdb;

        tdb = tdb_open_log(lock_path("connections.tdb"), 0,
                           TDB_DEFAULT, O_RDONLY, 0);

        if (!tdb) {
                DEBUG(3, ("send_sync_message(): failed to open connections "
                          "database\n"));
                return;
        }

        DEBUG(3, ("sending sam synchronisation message\n"));
        
        message_send_all(tdb, MSG_SMB_SAM_SYNC, NULL, 0, False, NULL);

        tdb_close(tdb);
}

/*************************************************************************
 net_reply_logon_ctrl2:
 *************************************************************************/

NTSTATUS _net_logon_ctrl2(pipes_struct *p, NET_Q_LOGON_CTRL2 *q_u, NET_R_LOGON_CTRL2 *r_u)
{
        uint32 flags = 0x0;
        uint32 pdc_connection_status = 0x0;
        uint32 logon_attempts = 0x0;
        uint32 tc_status = ERROR_NO_LOGON_SERVERS;
        const char *trusted_domain = "test_domain";

        DEBUG(0, ("*** net long ctrl2 %d, %d, %d\n",
                  q_u->function_code, q_u->query_level, q_u->switch_value));

	DEBUG(6,("_net_logon_ctrl2: %d\n", __LINE__));


	/* set up the Logon Control2 response */
	init_net_r_logon_ctrl2(r_u, q_u->query_level,
			       flags, pdc_connection_status, logon_attempts,
			       tc_status, trusted_domain);

        if (lp_server_role() == ROLE_DOMAIN_BDC)
                send_sync_message();

	DEBUG(6,("_net_logon_ctrl2: %d\n", __LINE__));

	return r_u->status;
}

/*************************************************************************
 net_reply_trust_dom_list:
 *************************************************************************/

NTSTATUS _net_trust_dom_list(pipes_struct *p, NET_Q_TRUST_DOM_LIST *q_u, NET_R_TRUST_DOM_LIST *r_u)
{
	const char *trusted_domain = "test_domain";
	uint32 num_trust_domains = 1;

	DEBUG(6,("_net_trust_dom_list: %d\n", __LINE__));

	/* set up the Trusted Domain List response */
	init_r_trust_dom(r_u, num_trust_domains, trusted_domain);

	DEBUG(6,("_net_trust_dom_list: %d\n", __LINE__));

	return r_u->status;
}

/***********************************************************************************
 init_net_r_srv_pwset:
 ***********************************************************************************/

static void init_net_r_srv_pwset(NET_R_SRV_PWSET *r_s,
				 DOM_CRED *srv_cred, NTSTATUS status)  
{
	DEBUG(5,("init_net_r_srv_pwset: %d\n", __LINE__));

	memcpy(&r_s->srv_cred, srv_cred, sizeof(r_s->srv_cred));
	r_s->status = status;

	DEBUG(5,("init_net_r_srv_pwset: %d\n", __LINE__));
}

/******************************************************************
 gets a machine password entry.  checks access rights of the host.
 ******************************************************************/

static BOOL get_md4pw(char *md4pw, char *mach_acct)
{
	SAM_ACCOUNT *sampass = NULL;
	const uint8 *pass;
	BOOL ret;
	uint32 acct_ctrl;

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
	                  client_name(), client_addr()))
	{
		DEBUG(0,("get_md4pw: Workstation %s denied access to domain\n", mach_acct));
		return False;
	}
#endif /* 0 */

	if(!NT_STATUS_IS_OK(pdb_init_sam(&sampass)))
		return False;

	/* JRA. This is ok as it is only used for generating the challenge. */
	become_root();
	ret=pdb_getsampwnam(sampass, mach_acct);
	unbecome_root();
 
 	if (ret==False) {
 		DEBUG(0,("get_md4pw: Workstation %s: no account in domain\n", mach_acct));
		pdb_free_sam(&sampass);
		return False;
	}

	acct_ctrl = pdb_get_acct_ctrl(sampass);
	if (!(acct_ctrl & ACB_DISABLED) &&
	    ((acct_ctrl & ACB_DOMTRUST) ||
	     (acct_ctrl & ACB_WSTRUST) ||
	     (acct_ctrl & ACB_SVRTRUST)) &&
	    ((pass=pdb_get_nt_passwd(sampass)) != NULL)) {
		memcpy(md4pw, pass, 16);
		dump_data(5, md4pw, 16);
 		pdb_free_sam(&sampass);
		return True;
	}
 	
	DEBUG(0,("get_md4pw: Workstation %s: no account in domain\n", mach_acct));
	pdb_free_sam(&sampass);
	return False;

}

/*************************************************************************
 _net_req_chal
 *************************************************************************/

NTSTATUS _net_req_chal(pipes_struct *p, NET_Q_REQ_CHAL *q_u, NET_R_REQ_CHAL *r_u)
{
	NTSTATUS status = NT_STATUS_OK;

	rpcstr_pull(p->dc.remote_machine,q_u->uni_logon_clnt.buffer,sizeof(fstring),q_u->uni_logon_clnt.uni_str_len*2,0);

	/* create a server challenge for the client */
	/* Set these to random values. */
	generate_random_buffer(p->dc.srv_chal.data, 8, False);
	
	memcpy(p->dc.srv_cred.challenge.data, p->dc.srv_chal.data, 8);

	memcpy(p->dc.clnt_chal.data          , q_u->clnt_chal.data, sizeof(q_u->clnt_chal.data));
	memcpy(p->dc.clnt_cred.challenge.data, q_u->clnt_chal.data, sizeof(q_u->clnt_chal.data));

	memset((char *)p->dc.sess_key, '\0', sizeof(p->dc.sess_key));

	p->dc.challenge_sent = True;
	/* set up the LSA REQUEST CHALLENGE response */
	init_net_r_req_chal(r_u, &p->dc.srv_chal, status);
	
	return status;
}

/*************************************************************************
 init_net_r_auth:
 *************************************************************************/

static void init_net_r_auth(NET_R_AUTH *r_a, DOM_CHAL *resp_cred, NTSTATUS status)
{
	memcpy(r_a->srv_chal.data, resp_cred->data, sizeof(resp_cred->data));
	r_a->status = status;
}

/*************************************************************************
 _net_auth
 *************************************************************************/

NTSTATUS _net_auth(pipes_struct *p, NET_Q_AUTH *q_u, NET_R_AUTH *r_u)
{
	NTSTATUS status = NT_STATUS_OK;
	DOM_CHAL srv_cred;
	UTIME srv_time;
	fstring mach_acct;

	srv_time.time = 0;

	rpcstr_pull(mach_acct, q_u->clnt_id.uni_acct_name.buffer,sizeof(fstring),q_u->clnt_id.uni_acct_name.uni_str_len*2,0);

	if (p->dc.challenge_sent && get_md4pw((char *)p->dc.md4pw, mach_acct)) {

		/* from client / server challenges and md4 password, generate sess key */
		cred_session_key(&p->dc.clnt_chal, &p->dc.srv_chal,
				 p->dc.md4pw, p->dc.sess_key);
		
		/* check that the client credentials are valid */
		if (cred_assert(&q_u->clnt_chal, p->dc.sess_key, &p->dc.clnt_cred.challenge, srv_time)) {
			
			/* create server challenge for inclusion in the reply */
			cred_create(p->dc.sess_key, &p->dc.srv_cred.challenge, srv_time, &srv_cred);
		
			/* copy the received client credentials for use next time */
			memcpy(p->dc.clnt_cred.challenge.data, q_u->clnt_chal.data, sizeof(q_u->clnt_chal.data));
			memcpy(p->dc.srv_cred .challenge.data, q_u->clnt_chal.data, sizeof(q_u->clnt_chal.data));
			
			/* Save the machine account name. */
			fstrcpy(p->dc.mach_acct, mach_acct);
		
			p->dc.authenticated = True;

		} else {
			status = NT_STATUS_ACCESS_DENIED;
		}
	} else {
		status = NT_STATUS_ACCESS_DENIED;
	}
	
	/* set up the LSA AUTH response */
	init_net_r_auth(r_u, &srv_cred, status);

	return r_u->status;
}

/*************************************************************************
 init_net_r_auth_2:
 *************************************************************************/

static void init_net_r_auth_2(NET_R_AUTH_2 *r_a,
                              DOM_CHAL *resp_cred, NEG_FLAGS *flgs, NTSTATUS status)
{
	memcpy(r_a->srv_chal.data, resp_cred->data, sizeof(resp_cred->data));
	memcpy(&r_a->srv_flgs, flgs, sizeof(r_a->srv_flgs));
	r_a->status = status;
}

/*************************************************************************
 _net_auth_2
 *************************************************************************/

NTSTATUS _net_auth_2(pipes_struct *p, NET_Q_AUTH_2 *q_u, NET_R_AUTH_2 *r_u)
{
	NTSTATUS status = NT_STATUS_OK;
	DOM_CHAL srv_cred;
	UTIME srv_time;
	NEG_FLAGS srv_flgs;
	fstring mach_acct;

	srv_time.time = 0;

	if ( (lp_server_schannel() == True) &&
	     ((q_u->clnt_flgs.neg_flags & NETLOGON_NEG_SCHANNEL) == 0) ) {

		/* schannel must be used, but client did not offer it. */
		status = NT_STATUS_ACCESS_DENIED;
	}

	rpcstr_pull(mach_acct, q_u->clnt_id.uni_acct_name.buffer,sizeof(fstring),q_u->clnt_id.uni_acct_name.uni_str_len*2,0);

	if (p->dc.challenge_sent && get_md4pw((char *)p->dc.md4pw, mach_acct)) {
		
		/* from client / server challenges and md4 password, generate sess key */
		cred_session_key(&p->dc.clnt_chal, &p->dc.srv_chal,
				 p->dc.md4pw, p->dc.sess_key);
		
		/* check that the client credentials are valid */
		if (cred_assert(&q_u->clnt_chal, p->dc.sess_key, &p->dc.clnt_cred.challenge, srv_time)) {
			
			/* create server challenge for inclusion in the reply */
			cred_create(p->dc.sess_key, &p->dc.srv_cred.challenge, srv_time, &srv_cred);
			
			/* copy the received client credentials for use next time */
			memcpy(p->dc.clnt_cred.challenge.data, q_u->clnt_chal.data, sizeof(q_u->clnt_chal.data));
			memcpy(p->dc.srv_cred .challenge.data, q_u->clnt_chal.data, sizeof(q_u->clnt_chal.data));
			
			/* Save the machine account name. */
			fstrcpy(p->dc.mach_acct, mach_acct);
			
			p->dc.authenticated = True;

		} else {
			status = NT_STATUS_ACCESS_DENIED;
		}
	} else {
		status = NT_STATUS_ACCESS_DENIED;
	}
	
	srv_flgs.neg_flags = 0x000001ff;

	if (lp_server_schannel() != False) {
		srv_flgs.neg_flags |= NETLOGON_NEG_SCHANNEL;
	}

	/* set up the LSA AUTH 2 response */
	init_net_r_auth_2(r_u, &srv_cred, &srv_flgs, status);

	if (NT_STATUS_IS_OK(status)) {
		extern struct dcinfo last_dcinfo;
		last_dcinfo = p->dc;
	}

	return r_u->status;
}

/*************************************************************************
 _net_srv_pwset
 *************************************************************************/

NTSTATUS _net_srv_pwset(pipes_struct *p, NET_Q_SRV_PWSET *q_u, NET_R_SRV_PWSET *r_u)
{
	NTSTATUS status = NT_STATUS_ACCESS_DENIED;
	DOM_CRED srv_cred;
	pstring workstation;
	SAM_ACCOUNT *sampass=NULL;
	BOOL ret = False;
	unsigned char pwd[16];
	int i;
	uint32 acct_ctrl;

	/* checks and updates credentials.  creates reply credentials */
	if (!(p->dc.authenticated && deal_with_creds(p->dc.sess_key, &p->dc.clnt_cred, &q_u->clnt_id.cred, &srv_cred)))
		return NT_STATUS_INVALID_HANDLE;

	memcpy(&p->dc.srv_cred, &p->dc.clnt_cred, sizeof(p->dc.clnt_cred));

	DEBUG(5,("_net_srv_pwset: %d\n", __LINE__));

	rpcstr_pull(workstation,q_u->clnt_id.login.uni_comp_name.buffer,
		    sizeof(workstation),q_u->clnt_id.login.uni_comp_name.uni_str_len*2,0);

	DEBUG(3,("Server Password Set by Wksta:[%s] on account [%s]\n", workstation, p->dc.mach_acct));
	
	pdb_init_sam(&sampass);

	become_root();
	ret=pdb_getsampwnam(sampass, p->dc.mach_acct);
	unbecome_root();

	/* Ensure the account exists and is a machine account. */
	
	acct_ctrl = pdb_get_acct_ctrl(sampass);

	if (!(ret 
	      && (acct_ctrl & ACB_WSTRUST ||
		      acct_ctrl & ACB_SVRTRUST ||
		      acct_ctrl & ACB_DOMTRUST))) {
		pdb_free_sam(&sampass);
		return NT_STATUS_NO_SUCH_USER;
	}
	
	if (pdb_get_acct_ctrl(sampass) & ACB_DISABLED) {
		pdb_free_sam(&sampass);
		return NT_STATUS_ACCOUNT_DISABLED;
	}

	DEBUG(100,("Server password set : new given value was :\n"));
	for(i = 0; i < 16; i++)
		DEBUG(100,("%02X ", q_u->pwd[i]));
	DEBUG(100,("\n"));

	cred_hash3( pwd, q_u->pwd, p->dc.sess_key, 0);

	/* lies!  nt and lm passwords are _not_ the same: don't care */
	if (!pdb_set_lanman_passwd (sampass, pwd, PDB_CHANGED)) {
		pdb_free_sam(&sampass);
		return NT_STATUS_NO_MEMORY;
	}

	if (!pdb_set_nt_passwd     (sampass, pwd, PDB_CHANGED)) {
		pdb_free_sam(&sampass);
		return NT_STATUS_NO_MEMORY;
	}

	if (!pdb_set_pass_changed_now     (sampass)) {
		pdb_free_sam(&sampass);
		/* Not quite sure what this one qualifies as, but this will do */
		return NT_STATUS_UNSUCCESSFUL; 
	}
 
	become_root();
	ret = pdb_update_sam_account (sampass);
	unbecome_root();
 
	if (ret)
		status = NT_STATUS_OK;

	/* set up the LSA Server Password Set response */
	init_net_r_srv_pwset(r_u, &srv_cred, status);

	pdb_free_sam(&sampass);
	return r_u->status;
}


/*************************************************************************
 _net_sam_logoff:
 *************************************************************************/

NTSTATUS _net_sam_logoff(pipes_struct *p, NET_Q_SAM_LOGOFF *q_u, NET_R_SAM_LOGOFF *r_u)
{
	DOM_CRED srv_cred;

	if (!get_valid_user_struct(p->vuid))
		return NT_STATUS_NO_SUCH_USER;

	/* checks and updates credentials.  creates reply credentials */
	if (!(p->dc.authenticated && deal_with_creds(p->dc.sess_key, &p->dc.clnt_cred, 
						     &q_u->sam_id.client.cred, &srv_cred)))
		return NT_STATUS_INVALID_HANDLE;

	memcpy(&p->dc.srv_cred, &p->dc.clnt_cred, sizeof(p->dc.clnt_cred));

	/* XXXX maybe we want to say 'no', reject the client's credentials */
	r_u->buffer_creds = 1; /* yes, we have valid server credentials */
	memcpy(&r_u->srv_creds, &srv_cred, sizeof(r_u->srv_creds));

	r_u->status = NT_STATUS_OK;

	return r_u->status;
}


/*************************************************************************
 _net_sam_logon
 *************************************************************************/

NTSTATUS _net_sam_logon(pipes_struct *p, NET_Q_SAM_LOGON *q_u, NET_R_SAM_LOGON *r_u)
{
	NTSTATUS status = NT_STATUS_OK;
	NET_USER_INFO_3 *usr_info = NULL;
	NET_ID_INFO_CTR *ctr = q_u->sam_id.ctr;
	DOM_CRED srv_cred;
	UNISTR2 *uni_samlogon_user = NULL;
	UNISTR2 *uni_samlogon_domain = NULL;
	UNISTR2 *uni_samlogon_workstation = NULL;
	fstring nt_username, nt_domain, nt_workstation;
	auth_usersupplied_info *user_info = NULL;
	auth_serversupplied_info *server_info = NULL;
	extern userdom_struct current_user_info;
	SAM_ACCOUNT *sampw;
	struct auth_context *auth_context = NULL;
	        
	usr_info = (NET_USER_INFO_3 *)talloc(p->mem_ctx, sizeof(NET_USER_INFO_3));
	if (!usr_info)
		return NT_STATUS_NO_MEMORY;

	ZERO_STRUCTP(usr_info);

 	/* store the user information, if there is any. */
	r_u->user = usr_info;
	r_u->switch_value = 0; /* indicates no info */
	r_u->auth_resp = 1; /* authoritative response */
	r_u->switch_value = 3; /* indicates type of validation user info */
 
	if (!get_valid_user_struct(p->vuid))
		return NT_STATUS_NO_SUCH_USER;


	if ( (lp_server_schannel() == True) && (!p->netsec_auth_validated) ) {
		/* 'server schannel = yes' should enforce use of
		   schannel, the client did offer it in auth2, but
		   obviously did not use it. */
		return NT_STATUS_ACCESS_DENIED;
	}

	/* checks and updates credentials.  creates reply credentials */
	if (!(p->dc.authenticated && deal_with_creds(p->dc.sess_key, &p->dc.clnt_cred, &q_u->sam_id.client.cred, &srv_cred)))
		return NT_STATUS_INVALID_HANDLE;

	memcpy(&p->dc.srv_cred, &p->dc.clnt_cred, sizeof(p->dc.clnt_cred));
    
	r_u->buffer_creds = 1; /* yes, we have valid server credentials */
	memcpy(&r_u->srv_creds, &srv_cred, sizeof(r_u->srv_creds));

	/* find the username */
    
	switch (q_u->sam_id.logon_level) {
	case INTERACTIVE_LOGON_TYPE:
		uni_samlogon_user = &ctr->auth.id1.uni_user_name;
 		uni_samlogon_domain = &ctr->auth.id1.uni_domain_name;

                uni_samlogon_workstation = &ctr->auth.id1.uni_wksta_name;
            
		DEBUG(3,("SAM Logon (Interactive). Domain:[%s].  ", lp_workgroup()));
		break;
	case NET_LOGON_TYPE:
		uni_samlogon_user = &ctr->auth.id2.uni_user_name;
		uni_samlogon_domain = &ctr->auth.id2.uni_domain_name;
		uni_samlogon_workstation = &ctr->auth.id2.uni_wksta_name;
            
		DEBUG(3,("SAM Logon (Network). Domain:[%s].  ", lp_workgroup()));
		break;
	default:
		DEBUG(2,("SAM Logon: unsupported switch value\n"));
		return NT_STATUS_INVALID_INFO_CLASS;
	} /* end switch */

	rpcstr_pull(nt_username,uni_samlogon_user->buffer,sizeof(nt_username),uni_samlogon_user->uni_str_len*2,0);
	rpcstr_pull(nt_domain,uni_samlogon_domain->buffer,sizeof(nt_domain),uni_samlogon_domain->uni_str_len*2,0);
	rpcstr_pull(nt_workstation,uni_samlogon_workstation->buffer,sizeof(nt_workstation),uni_samlogon_workstation->uni_str_len*2,0);

	DEBUG(3,("User:[%s@%s] Requested Domain:[%s]\n", nt_username, 
                 nt_workstation, nt_domain));
   	
	fstrcpy(current_user_info.smb_name, nt_username);
	sub_set_smb_name(nt_username);
     
	DEBUG(5,("Attempting validation level %d for unmapped username %s.\n", q_u->sam_id.ctr->switch_value, nt_username));

	status = NT_STATUS_OK;
	
	switch (ctr->switch_value) {
	case NET_LOGON_TYPE:
	{
		const char *wksname = nt_workstation;
		
		if (!NT_STATUS_IS_OK(status = make_auth_context_fixed(&auth_context, ctr->auth.id2.lm_chal))) {
			return status;
		}

		/* For a network logon, the workstation name comes in with two
		 * backslashes in the front. Strip them if they are there. */

		if (*wksname == '\\') wksname++;
		if (*wksname == '\\') wksname++;

		/* Standard challenge/response authenticaion */
		if (!make_user_info_netlogon_network(&user_info, 
						     nt_username, nt_domain, 
						     wksname,
						     ctr->auth.id2.lm_chal_resp.buffer,
						     ctr->auth.id2.lm_chal_resp.str_str_len,
						     ctr->auth.id2.nt_chal_resp.buffer,
						     ctr->auth.id2.nt_chal_resp.str_str_len)) {
			status = NT_STATUS_NO_MEMORY;
		}	
		break;
	}
	case INTERACTIVE_LOGON_TYPE:
		/* 'Interactive' autheticaion, supplies the password in its
		   MD4 form, encrypted with the session key.  We will
		   convert this to chellange/responce for the auth
		   subsystem to chew on */
	{
		const uint8 *chal;
		
		if (!NT_STATUS_IS_OK(status = make_auth_context_subsystem(&auth_context))) {
			return status;
		}
		
		chal = auth_context->get_ntlm_challenge(auth_context);

		if (!make_user_info_netlogon_interactive(&user_info, 
							 nt_username, nt_domain, 
							 nt_workstation, chal,
							 ctr->auth.id1.lm_owf.data, 
							 ctr->auth.id1.nt_owf.data, 
							 p->dc.sess_key)) {
			status = NT_STATUS_NO_MEMORY;
		}
		break;
	}
	default:
		DEBUG(2,("SAM Logon: unsupported switch value\n"));
		return NT_STATUS_INVALID_INFO_CLASS;
	} /* end switch */
	
	if ( NT_STATUS_IS_OK(status) ) {
		status = auth_context->check_ntlm_password(auth_context, 
			user_info, &server_info);
	}

	(auth_context->free)(&auth_context);	
	free_user_info(&user_info);
	
	DEBUG(5, ("_net_sam_logon: check_password returned status %s\n", 
		  nt_errstr(status)));

	/* Check account and password */
    
	if (!NT_STATUS_IS_OK(status)) {
		free_server_info(&server_info);
		return status;
	}

	if (server_info->guest) {
		/* We don't like guest domain logons... */
		DEBUG(5,("_net_sam_logon: Attempted domain logon as GUEST denied.\n"));
		free_server_info(&server_info);
		return NT_STATUS_LOGON_FAILURE;
	}

	/* This is the point at which, if the login was successful, that
           the SAM Local Security Authority should record that the user is
           logged in to the domain.  */
    
	{
		DOM_GID *gids = NULL;
		const DOM_SID *user_sid = NULL;
		const DOM_SID *group_sid = NULL;
		DOM_SID domain_sid;
		uint32 user_rid, group_rid; 

		int num_gids = 0;
		pstring my_name;
		fstring user_sid_string;
		fstring group_sid_string;
		uchar user_session_key[16];
		uchar lm_session_key[16];
		uchar netlogon_sess_key[16];

		sampw = server_info->sam_account;

		/* set up pointer indicating user/password failed to be found */
		usr_info->ptr_user_info = 0;

		user_sid = pdb_get_user_sid(sampw);
		group_sid = pdb_get_group_sid(sampw);

		sid_copy(&domain_sid, user_sid);
		sid_split_rid(&domain_sid, &user_rid);

		if (!sid_peek_check_rid(&domain_sid, group_sid, &group_rid)) {
			DEBUG(1, ("_net_sam_logon: user %s\\%s has user sid %s\n but group sid %s.\nThe conflicting domain portions are not supported for NETLOGON calls\n", 	    
				  pdb_get_domain(sampw), pdb_get_username(sampw),
				  sid_to_string(user_sid_string, user_sid),
				  sid_to_string(group_sid_string, group_sid)));
			return NT_STATUS_UNSUCCESSFUL;
		}
		
		pstrcpy(my_name, global_myname());

		if (!NT_STATUS_IS_OK(status 
				     = nt_token_to_group_list(p->mem_ctx, 
							      &domain_sid, 
							      server_info->ptok, 
							      &num_gids, 
							      &gids))) {
			return status;
		}

		ZERO_STRUCT(netlogon_sess_key);
		memcpy(netlogon_sess_key, p->dc.sess_key, 8);
		if (server_info->user_session_key.length) {
			memcpy(user_session_key, server_info->user_session_key.data, 
			       MIN(sizeof(user_session_key), server_info->user_session_key.length));
			SamOEMhash(user_session_key, netlogon_sess_key, 16);
		}
		if (server_info->lm_session_key.length) {
			memcpy(lm_session_key, server_info->lm_session_key.data, 
			       MIN(sizeof(lm_session_key), server_info->lm_session_key.length));
			SamOEMhash(lm_session_key, netlogon_sess_key, 16);
		}
		ZERO_STRUCT(netlogon_sess_key);
		
		init_net_user_info3(p->mem_ctx, usr_info, 
				    user_rid,
				    group_rid,   
				    pdb_get_username(sampw),
				    pdb_get_fullname(sampw),
				    pdb_get_homedir(sampw),
				    pdb_get_dir_drive(sampw),
				    pdb_get_logon_script(sampw),
				    pdb_get_profile_path(sampw),
				    pdb_get_logon_time(sampw),
				    get_time_t_max(),
				    get_time_t_max(),
				    pdb_get_pass_last_set_time(sampw),
				    pdb_get_pass_can_change_time(sampw),
				    pdb_get_pass_must_change_time(sampw),
				    
				    0, /* logon_count */
				    0, /* bad_pw_count */
				    num_gids,    /* uint32 num_groups */
				    gids    , /* DOM_GID *gids */
				    0x20    , /* uint32 user_flgs (?) */
				    server_info->user_session_key.length ? user_session_key : NULL,
				    server_info->lm_session_key.length ? lm_session_key : NULL,
				    my_name     , /* char *logon_srv */
				    pdb_get_domain(sampw),
				    &domain_sid,     /* DOM_SID *dom_sid */  
				    /* Should be users domain sid, not servers - for trusted domains */
				  
				    NULL); /* char *other_sids */
		ZERO_STRUCT(user_session_key);
		ZERO_STRUCT(lm_session_key);
	}
	free_server_info(&server_info);
	return status;
}

/*************************************************************************
 _ds_enum_dom_trusts
 *************************************************************************/
#if 0	/* JERRY -- not correct */
NTSTATUS _ds_enum_dom_trusts(pipes_struct *p, DS_Q_ENUM_DOM_TRUSTS *q_u,
			     DS_R_ENUM_DOM_TRUSTS *r_u)
{
	NTSTATUS status = NT_STATUS_OK;

	/* TODO: According to MSDN, the can only be executed against a 
	   DC or domain member running Windows 2000 or later.  Need
	   to test against a standalone 2k server and see what it 
	   does.  A windows 2000 DC includes its own domain in the 
	   list.  --jerry */

	return status;
}
#endif	/* JERRY */
