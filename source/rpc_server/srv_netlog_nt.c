/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  Copyright (C) Jeremy Allison               1998-2001.
 *  Copyright (C) Andrew Bartlett                   2001.
 *  Copyright (C) Guenther Deschner		    2008.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* This is the implementation of the netlogon pipe. */

#include "includes.h"

extern userdom_struct current_user_info;

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/*************************************************************************
 init_net_r_req_chal:
 *************************************************************************/

static void init_net_r_req_chal(struct netr_Credential *r,
				struct netr_Credential *srv_chal)
{
	DEBUG(6,("init_net_r_req_chal: %d\n", __LINE__));

	memcpy(r->data, srv_chal->data, sizeof(r->data));
}

/*******************************************************************
 Inits a netr_NETLOGON_INFO_1 structure.
********************************************************************/

static void init_netlogon_info1(struct netr_NETLOGON_INFO_1 *r,
				uint32_t flags,
				uint32_t pdc_connection_status)
{
	r->flags = flags;
	r->pdc_connection_status = pdc_connection_status;
}

/*******************************************************************
 Inits a netr_NETLOGON_INFO_2 structure.
********************************************************************/

static void init_netlogon_info2(struct netr_NETLOGON_INFO_2 *r,
				uint32_t flags,
				uint32_t pdc_connection_status,
				const char *trusted_dc_name,
				uint32_t tc_connection_status)
{
	r->flags = flags;
	r->pdc_connection_status = pdc_connection_status;
	r->trusted_dc_name = trusted_dc_name;
	r->tc_connection_status = tc_connection_status;
}

/*******************************************************************
 Inits a netr_NETLOGON_INFO_3 structure.
********************************************************************/

static void init_netlogon_info3(struct netr_NETLOGON_INFO_3 *r,
				uint32_t flags,
				uint32_t logon_attempts)
{
	r->flags = flags;
	r->logon_attempts = logon_attempts;
}

/*************************************************************************
 _netr_LogonControl
 *************************************************************************/

WERROR _netr_LogonControl(pipes_struct *p,
			  struct netr_LogonControl *r)
{
	struct netr_NETLOGON_INFO_1 *info1;
	uint32_t flags = 0x0;
	uint32_t pdc_connection_status = W_ERROR_V(WERR_OK);

	/* Setup the Logon Control response */

	switch (r->in.level) {
		case 1:
			info1 = TALLOC_ZERO_P(p->mem_ctx, struct netr_NETLOGON_INFO_1);
			if (!info1) {
				return WERR_NOMEM;
			}
			init_netlogon_info1(info1,
					    flags,
					    pdc_connection_status);
			r->out.info->info1 = info1;
			break;
		default:
			return WERR_UNKNOWN_LEVEL;
	}

	return WERR_OK;
}

/****************************************************************************
Send a message to smbd to do a sam synchronisation
**************************************************************************/

static void send_sync_message(void)
{
        DEBUG(3, ("sending sam synchronisation message\n"));
        message_send_all(smbd_messaging_context(), MSG_SMB_SAM_SYNC, NULL, 0,
			 NULL);
}

/*************************************************************************
 _netr_LogonControl2
 *************************************************************************/

WERROR _netr_LogonControl2(pipes_struct *p,
			   struct netr_LogonControl2 *r)
{
        uint32 flags = 0x0;
        uint32 pdc_connection_status = 0x0;
        uint32 logon_attempts = 0x0;
        uint32 tc_status;
	fstring dc_name2;
	const char *dc_name = NULL;
	struct sockaddr_storage dc_ss;
	const char *domain = NULL;
	struct netr_NETLOGON_INFO_1 *info1;
	struct netr_NETLOGON_INFO_2 *info2;
	struct netr_NETLOGON_INFO_3 *info3;

	tc_status = W_ERROR_V(WERR_NO_SUCH_DOMAIN);

	switch (r->in.function_code) {
		case NETLOGON_CONTROL_TC_QUERY:
			domain = r->in.data->domain;

			if ( !is_trusted_domain( domain ) )
				break;

			if ( !get_dc_name( domain, NULL, dc_name2, &dc_ss ) ) {
				tc_status = W_ERROR_V(WERR_NO_LOGON_SERVERS);
				break;
			}

			dc_name = talloc_asprintf(p->mem_ctx, "\\\\%s", dc_name2);
			if (!dc_name) {
				return WERR_NOMEM;
			}

			tc_status = W_ERROR_V(WERR_OK);

			break;

		case NETLOGON_CONTROL_REDISCOVER:
			domain = r->in.data->domain;

			if ( !is_trusted_domain( domain ) )
				break;

			if ( !get_dc_name( domain, NULL, dc_name2, &dc_ss ) ) {
				tc_status = W_ERROR_V(WERR_NO_LOGON_SERVERS);
				break;
			}

			dc_name = talloc_asprintf(p->mem_ctx, "\\\\%s", dc_name2);
			if (!dc_name) {
				return WERR_NOMEM;
			}

			tc_status = W_ERROR_V(WERR_OK);

			break;

		default:
			/* no idea what this should be */
			DEBUG(0,("_netr_LogonControl2: unimplemented function level [%d]\n",
				r->in.function_code));
			return WERR_UNKNOWN_LEVEL;
	}

	/* prepare the response */

	switch (r->in.level) {
		case 1:
			info1 = TALLOC_ZERO_P(p->mem_ctx, struct netr_NETLOGON_INFO_1);
			W_ERROR_HAVE_NO_MEMORY(info1);

			init_netlogon_info1(info1,
					    flags,
					    pdc_connection_status);
			r->out.query->info1 = info1;
			break;
		case 2:
			info2 = TALLOC_ZERO_P(p->mem_ctx, struct netr_NETLOGON_INFO_2);
			W_ERROR_HAVE_NO_MEMORY(info2);

			init_netlogon_info2(info2,
					    flags,
					    pdc_connection_status,
					    dc_name,
					    tc_status);
			r->out.query->info2 = info2;
			break;
		case 3:
			info3 = TALLOC_ZERO_P(p->mem_ctx, struct netr_NETLOGON_INFO_3);
			W_ERROR_HAVE_NO_MEMORY(info3);

			init_netlogon_info3(info3,
					    flags,
					    logon_attempts);
			r->out.query->info3 = info3;
			break;
		default:
			return WERR_UNKNOWN_LEVEL;
	}

        if (lp_server_role() == ROLE_DOMAIN_BDC) {
                send_sync_message();
	}

	return WERR_OK;
}

/*************************************************************************
 _netr_NetrEnumerateTrustedDomains
 *************************************************************************/

WERROR _netr_NetrEnumerateTrustedDomains(pipes_struct *p,
					 struct netr_NetrEnumerateTrustedDomains *r)
{
	struct netr_Blob trusted_domains_blob;
	DATA_BLOB blob;

	DEBUG(6,("_netr_NetrEnumerateTrustedDomains: %d\n", __LINE__));

	/* set up the Trusted Domain List response */

	blob = data_blob_talloc_zero(p->mem_ctx, 2);
	trusted_domains_blob.data = blob.data;
	trusted_domains_blob.length = blob.length;

	DEBUG(6,("_netr_NetrEnumerateTrustedDomains: %d\n", __LINE__));

	*r->out.trusted_domains_blob = trusted_domains_blob;

	return WERR_OK;
}

/******************************************************************
 gets a machine password entry.  checks access rights of the host.
 ******************************************************************/

static NTSTATUS get_md4pw(char *md4pw, const char *mach_acct, uint16 sec_chan_type)
{
	struct samu *sampass = NULL;
	const uint8 *pass;
	bool ret;
	uint32 acct_ctrl;

#if 0
	char addr[INET6_ADDRSTRLEN];

    /*
     * Currently this code is redundent as we already have a filter
     * by hostname list. What this code really needs to do is to
     * get a hosts allowed/hosts denied list from the SAM database
     * on a per user basis, and make the access decision there.
     * I will leave this code here for now as a reminder to implement
     * this at a later date. JRA.
     */

	if (!allow_access(lp_domain_hostsdeny(), lp_domain_hostsallow(),
			client_name(get_client_fd()),
			client_addr(get_client_fd(),addr,sizeof(addr)))) {
		DEBUG(0,("get_md4pw: Workstation %s denied access to domain\n", mach_acct));
		return False;
	}
#endif /* 0 */

	if ( !(sampass = samu_new( NULL )) ) {
		return NT_STATUS_NO_MEMORY;
	}

	/* JRA. This is ok as it is only used for generating the challenge. */
	become_root();
	ret = pdb_getsampwnam(sampass, mach_acct);
	unbecome_root();

 	if (!ret) {
 		DEBUG(0,("get_md4pw: Workstation %s: no account in domain\n", mach_acct));
		TALLOC_FREE(sampass);
		return NT_STATUS_ACCESS_DENIED;
	}

	acct_ctrl = pdb_get_acct_ctrl(sampass);
	if (acct_ctrl & ACB_DISABLED) {
		DEBUG(0,("get_md4pw: Workstation %s: account is disabled\n", mach_acct));
		TALLOC_FREE(sampass);
		return NT_STATUS_ACCOUNT_DISABLED;
	}

	if (!(acct_ctrl & ACB_SVRTRUST) &&
	    !(acct_ctrl & ACB_WSTRUST) &&
	    !(acct_ctrl & ACB_DOMTRUST))
	{
		DEBUG(0,("get_md4pw: Workstation %s: account is not a trust account\n", mach_acct));
		TALLOC_FREE(sampass);
		return NT_STATUS_NO_TRUST_SAM_ACCOUNT;
	}

	switch (sec_chan_type) {
		case SEC_CHAN_BDC:
			if (!(acct_ctrl & ACB_SVRTRUST)) {
				DEBUG(0,("get_md4pw: Workstation %s: BDC secure channel requested "
					 "but not a server trust account\n", mach_acct));
				TALLOC_FREE(sampass);
				return NT_STATUS_NO_TRUST_SAM_ACCOUNT;
			}
			break;
		case SEC_CHAN_WKSTA:
			if (!(acct_ctrl & ACB_WSTRUST)) {
				DEBUG(0,("get_md4pw: Workstation %s: WORKSTATION secure channel requested "
					 "but not a workstation trust account\n", mach_acct));
				TALLOC_FREE(sampass);
				return NT_STATUS_NO_TRUST_SAM_ACCOUNT;
			}
			break;
		case SEC_CHAN_DOMAIN:
			if (!(acct_ctrl & ACB_DOMTRUST)) {
				DEBUG(0,("get_md4pw: Workstation %s: DOMAIN secure channel requested "
					 "but not a interdomain trust account\n", mach_acct));
				TALLOC_FREE(sampass);
				return NT_STATUS_NO_TRUST_SAM_ACCOUNT;
			}
			break;
		default:
			break;
	}

	if ((pass = pdb_get_nt_passwd(sampass)) == NULL) {
		DEBUG(0,("get_md4pw: Workstation %s: account does not have a password\n", mach_acct));
		TALLOC_FREE(sampass);
		return NT_STATUS_LOGON_FAILURE;
	}

	memcpy(md4pw, pass, 16);
	dump_data(5, (uint8 *)md4pw, 16);

	TALLOC_FREE(sampass);

	return NT_STATUS_OK;


}

/*************************************************************************
 _netr_ServerReqChallenge
 *************************************************************************/

NTSTATUS _netr_ServerReqChallenge(pipes_struct *p,
				  struct netr_ServerReqChallenge *r)
{
	if (!p->dc) {
		p->dc = TALLOC_ZERO_P(p->pipe_state_mem_ctx, struct dcinfo);
		if (!p->dc) {
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		DEBUG(10,("_netr_ServerReqChallenge: new challenge requested. Clearing old state.\n"));
		ZERO_STRUCTP(p->dc);
	}

	fstrcpy(p->dc->remote_machine, r->in.computer_name);

	/* Save the client challenge to the server. */
	memcpy(p->dc->clnt_chal.data, r->in.credentials->data,
		sizeof(r->in.credentials->data));

	/* Create a server challenge for the client */
	/* Set this to a random value. */
	generate_random_buffer(p->dc->srv_chal.data, 8);

	/* set up the LSA REQUEST CHALLENGE response */
	init_net_r_req_chal(r->out.return_credentials, &p->dc->srv_chal);

	p->dc->challenge_sent = True;

	return NT_STATUS_OK;
}

/*************************************************************************
 _netr_ServerAuthenticate
 Create the initial credentials.
 *************************************************************************/

NTSTATUS _netr_ServerAuthenticate(pipes_struct *p,
				  struct netr_ServerAuthenticate *r)
{
	NTSTATUS status;
	struct netr_Credential srv_chal_out;

	if (!p->dc || !p->dc->challenge_sent) {
		return NT_STATUS_ACCESS_DENIED;
	}

	status = get_md4pw((char *)p->dc->mach_pw,
			   r->in.account_name,
			   r->in.secure_channel_type);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("_netr_ServerAuthenticate: get_md4pw failed. Failed to "
			"get password for machine account %s "
			"from client %s: %s\n",
			r->in.account_name,
			r->in.computer_name,
			nt_errstr(status) ));
		/* always return NT_STATUS_ACCESS_DENIED */
		return NT_STATUS_ACCESS_DENIED;
	}

	/* From the client / server challenges and md4 password, generate sess key */
	creds_server_init(0,			/* No neg flags. */
			p->dc,
			&p->dc->clnt_chal,	/* Stored client chal. */
			&p->dc->srv_chal,	/* Stored server chal. */
			p->dc->mach_pw,
			&srv_chal_out);

	/* Check client credentials are valid. */
	if (!netlogon_creds_server_check(p->dc, r->in.credentials)) {
		DEBUG(0,("_netr_ServerAuthenticate: netlogon_creds_server_check failed. Rejecting auth "
			"request from client %s machine account %s\n",
			r->in.computer_name,
			r->in.account_name));
		return NT_STATUS_ACCESS_DENIED;
	}

	fstrcpy(p->dc->mach_acct, r->in.account_name);
	fstrcpy(p->dc->remote_machine, r->in.computer_name);
	p->dc->authenticated = True;

	/* set up the LSA AUTH response */
	/* Return the server credentials. */

	memcpy(r->out.return_credentials->data, &srv_chal_out.data,
	       sizeof(r->out.return_credentials->data));

	return NT_STATUS_OK;
}

/*************************************************************************
 _netr_ServerAuthenticate2
 *************************************************************************/

NTSTATUS _netr_ServerAuthenticate2(pipes_struct *p,
				   struct netr_ServerAuthenticate2 *r)
{
	NTSTATUS status;
	uint32_t srv_flgs;
	struct netr_Credential srv_chal_out;

	/* We use this as the key to store the creds: */
	/* r->in.computer_name */

	if (!p->dc || !p->dc->challenge_sent) {
		DEBUG(0,("_netr_ServerAuthenticate2: no challenge sent to client %s\n",
			r->in.computer_name));
		return NT_STATUS_ACCESS_DENIED;
	}

	if ( (lp_server_schannel() == true) &&
	     ((*r->in.negotiate_flags & NETLOGON_NEG_SCHANNEL) == 0) ) {

		/* schannel must be used, but client did not offer it. */
		DEBUG(0,("_netr_ServerAuthenticate2: schannel required but client failed "
			"to offer it. Client was %s\n",
			r->in.account_name));
		return NT_STATUS_ACCESS_DENIED;
	}

	status = get_md4pw((char *)p->dc->mach_pw,
			   r->in.account_name,
			   r->in.secure_channel_type);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("_netr_ServerAuthenticate2: failed to get machine password for "
			"account %s: %s\n",
			r->in.account_name, nt_errstr(status) ));
		/* always return NT_STATUS_ACCESS_DENIED */
		return NT_STATUS_ACCESS_DENIED;
	}

	/* From the client / server challenges and md4 password, generate sess key */
	creds_server_init(*r->in.negotiate_flags,
			p->dc,
			&p->dc->clnt_chal,	/* Stored client chal. */
			&p->dc->srv_chal,	/* Stored server chal. */
			p->dc->mach_pw,
			&srv_chal_out);

	/* Check client credentials are valid. */
	if (!netlogon_creds_server_check(p->dc, r->in.credentials)) {
		DEBUG(0,("_netr_ServerAuthenticate2: netlogon_creds_server_check failed. Rejecting auth "
			"request from client %s machine account %s\n",
			r->in.computer_name,
			r->in.account_name));
		return NT_STATUS_ACCESS_DENIED;
	}

	srv_flgs = 0x000001ff;

	if (lp_server_schannel() != false) {
		srv_flgs |= NETLOGON_NEG_SCHANNEL;
	}

	/* set up the LSA AUTH 2 response */
	memcpy(r->out.return_credentials->data, &srv_chal_out.data,
	       sizeof(r->out.return_credentials->data));
	*r->out.negotiate_flags = srv_flgs;

	fstrcpy(p->dc->mach_acct, r->in.account_name);
	fstrcpy(p->dc->remote_machine, r->in.computer_name);
	fstrcpy(p->dc->domain, lp_workgroup() );

	p->dc->authenticated = True;

	/* Store off the state so we can continue after client disconnect. */
	become_root();
	secrets_store_schannel_session_info(p->mem_ctx,
					    r->in.computer_name,
					    p->dc);
	unbecome_root();

	return NT_STATUS_OK;
}

/*************************************************************************
 _netr_ServerPasswordSet
 *************************************************************************/

NTSTATUS _netr_ServerPasswordSet(pipes_struct *p,
				 struct netr_ServerPasswordSet *r)
{
	NTSTATUS status = NT_STATUS_OK;
	fstring remote_machine;
	struct samu *sampass=NULL;
	bool ret = False;
	unsigned char pwd[16];
	int i;
	uint32 acct_ctrl;
	struct netr_Authenticator cred_out;
	const uchar *old_pw;

	DEBUG(5,("_netr_ServerPasswordSet: %d\n", __LINE__));

	/* We need the remote machine name for the creds lookup. */
	fstrcpy(remote_machine, r->in.computer_name);

	if ( (lp_server_schannel() == True) && (p->auth.auth_type != PIPE_AUTH_TYPE_SCHANNEL) ) {
		/* 'server schannel = yes' should enforce use of
		   schannel, the client did offer it in auth2, but
		   obviously did not use it. */
		DEBUG(0,("_netr_ServerPasswordSet: client %s not using schannel for netlogon\n",
			remote_machine ));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!p->dc) {
		/* Restore the saved state of the netlogon creds. */
		become_root();
		ret = secrets_restore_schannel_session_info(p->pipe_state_mem_ctx,
							remote_machine,
							&p->dc);
		unbecome_root();
		if (!ret) {
			return NT_STATUS_INVALID_HANDLE;
		}
	}

	if (!p->dc || !p->dc->authenticated) {
		return NT_STATUS_INVALID_HANDLE;
	}

	DEBUG(3,("_netr_ServerPasswordSet: Server Password Set by remote machine:[%s] on account [%s]\n",
			remote_machine, p->dc->mach_acct));

	/* Step the creds chain forward. */
	if (!netlogon_creds_server_step(p->dc, r->in.credential, &cred_out)) {
		DEBUG(2,("_netr_ServerPasswordSet: netlogon_creds_server_step failed. Rejecting auth "
			"request from client %s machine account %s\n",
			remote_machine, p->dc->mach_acct ));
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* We must store the creds state after an update. */
	sampass = samu_new( NULL );
	if (!sampass) {
		return NT_STATUS_NO_MEMORY;
	}

	become_root();
	secrets_store_schannel_session_info(p->pipe_state_mem_ctx,
						remote_machine,
						p->dc);
	ret = pdb_getsampwnam(sampass, p->dc->mach_acct);
	unbecome_root();

	if (!ret) {
		TALLOC_FREE(sampass);
		return NT_STATUS_ACCESS_DENIED;
	}

	/* Ensure the account exists and is a machine account. */

	acct_ctrl = pdb_get_acct_ctrl(sampass);

	if (!(acct_ctrl & ACB_WSTRUST ||
		      acct_ctrl & ACB_SVRTRUST ||
		      acct_ctrl & ACB_DOMTRUST)) {
		TALLOC_FREE(sampass);
		return NT_STATUS_NO_SUCH_USER;
	}

	if (pdb_get_acct_ctrl(sampass) & ACB_DISABLED) {
		TALLOC_FREE(sampass);
		return NT_STATUS_ACCOUNT_DISABLED;
	}

	/* Woah - what does this to to the credential chain ? JRA */
	cred_hash3(pwd, r->in.new_password->hash, p->dc->sess_key, 0);

	DEBUG(100,("_netr_ServerPasswordSet: new given value was :\n"));
	for(i = 0; i < sizeof(pwd); i++)
		DEBUG(100,("%02X ", pwd[i]));
	DEBUG(100,("\n"));

	old_pw = pdb_get_nt_passwd(sampass);

	if (old_pw && memcmp(pwd, old_pw, 16) == 0) {
		/* Avoid backend modificiations and other fun if the
		   client changed the password to the *same thing* */

		ret = True;
	} else {

		/* LM password should be NULL for machines */
		if (!pdb_set_lanman_passwd(sampass, NULL, PDB_CHANGED)) {
			TALLOC_FREE(sampass);
			return NT_STATUS_NO_MEMORY;
		}

		if (!pdb_set_nt_passwd(sampass, pwd, PDB_CHANGED)) {
			TALLOC_FREE(sampass);
			return NT_STATUS_NO_MEMORY;
		}

		if (!pdb_set_pass_last_set_time(sampass, time(NULL), PDB_CHANGED)) {
			TALLOC_FREE(sampass);
			/* Not quite sure what this one qualifies as, but this will do */
			return NT_STATUS_UNSUCCESSFUL;
		}

		become_root();
		status = pdb_update_sam_account(sampass);
		unbecome_root();
	}

	/* set up the LSA Server Password Set response */

	memcpy(r->out.return_authenticator, &cred_out,
	       sizeof(r->out.return_authenticator));

	TALLOC_FREE(sampass);
	return status;
}

/*************************************************************************
 _netr_LogonSamLogoff
 *************************************************************************/

NTSTATUS _netr_LogonSamLogoff(pipes_struct *p,
			      struct netr_LogonSamLogoff *r)
{
	if ( (lp_server_schannel() == True) && (p->auth.auth_type != PIPE_AUTH_TYPE_SCHANNEL) ) {
		/* 'server schannel = yes' should enforce use of
		   schannel, the client did offer it in auth2, but
		   obviously did not use it. */
		DEBUG(0,("_netr_LogonSamLogoff: client %s not using schannel for netlogon\n",
			get_remote_machine_name() ));
		return NT_STATUS_ACCESS_DENIED;
	}


	if (!get_valid_user_struct(p->vuid))
		return NT_STATUS_NO_SUCH_USER;

	/* Using the remote machine name for the creds store: */
	/* r->in.computer_name */

	if (!p->dc) {
		/* Restore the saved state of the netlogon creds. */
		bool ret;

		become_root();
		ret = secrets_restore_schannel_session_info(p->pipe_state_mem_ctx,
							    r->in.computer_name,
							    &p->dc);
		unbecome_root();
		if (!ret) {
			return NT_STATUS_INVALID_HANDLE;
		}
	}

	if (!p->dc || !p->dc->authenticated) {
		return NT_STATUS_INVALID_HANDLE;
	}

	/* checks and updates credentials.  creates reply credentials */
	if (!netlogon_creds_server_step(p->dc, r->in.credential, r->out.return_authenticator)) {
		DEBUG(2,("_netr_LogonSamLogoff: netlogon_creds_server_step failed. Rejecting auth "
			"request from client %s machine account %s\n",
			r->in.computer_name, p->dc->mach_acct ));
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* We must store the creds state after an update. */
	become_root();
	secrets_store_schannel_session_info(p->pipe_state_mem_ctx,
					    r->in.computer_name,
					    p->dc);
	unbecome_root();

	return NT_STATUS_OK;
}

/*******************************************************************
 gets a domain user's groups from their already-calculated NT_USER_TOKEN
 ********************************************************************/

static NTSTATUS nt_token_to_group_list(TALLOC_CTX *mem_ctx,
				       const DOM_SID *domain_sid,
				       size_t num_sids,
				       const DOM_SID *sids,
				       int *numgroups, DOM_GID **pgids)
{
	int i;

	*numgroups=0;
	*pgids = NULL;

	for (i=0; i<num_sids; i++) {
		DOM_GID gid;
		if (!sid_peek_check_rid(domain_sid, &sids[i], &gid.g_rid)) {
			continue;
		}
		gid.attr = (SE_GROUP_MANDATORY|SE_GROUP_ENABLED_BY_DEFAULT|
			    SE_GROUP_ENABLED);
		ADD_TO_ARRAY(mem_ctx, DOM_GID, gid, pgids, numgroups);
		if (*pgids == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}
	return NT_STATUS_OK;
}

/*************************************************************************
 _netr_LogonSamLogon
 *************************************************************************/

NTSTATUS _netr_LogonSamLogon(pipes_struct *p,
			     struct netr_LogonSamLogon *r)
{
	NTSTATUS status = NT_STATUS_OK;
	struct netr_SamInfo3 *sam3 = NULL;
	union netr_LogonInfo *logon = r->in.logon;
	fstring nt_username, nt_domain, nt_workstation;
	auth_usersupplied_info *user_info = NULL;
	auth_serversupplied_info *server_info = NULL;
	struct samu *sampw;
	struct auth_context *auth_context = NULL;
	bool process_creds = true;

	switch (p->hdr_req.opnum) {
		case NDR_NETR_LOGONSAMLOGON:
			process_creds = true;
			break;
		case NDR_NETR_LOGONSAMLOGONEX:
		default:
			process_creds = false;
	}

	if ( (lp_server_schannel() == True) && (p->auth.auth_type != PIPE_AUTH_TYPE_SCHANNEL) ) {
		/* 'server schannel = yes' should enforce use of
		   schannel, the client did offer it in auth2, but
		   obviously did not use it. */
		DEBUG(0,("_netr_LogonSamLogon: client %s not using schannel for netlogon\n",
			get_remote_machine_name() ));
		return NT_STATUS_ACCESS_DENIED;
	}

	sam3 = TALLOC_ZERO_P(p->mem_ctx, struct netr_SamInfo3);
	if (!sam3) {
		return NT_STATUS_NO_MEMORY;
	}

 	/* store the user information, if there is any. */
	r->out.validation->sam3 = sam3;
	*r->out.authoritative = true; /* authoritative response */
	if (r->in.validation_level != 2 && r->in.validation_level != 3) {
		DEBUG(0,("_netr_LogonSamLogon: bad validation_level value %d.\n",
			(int)r->in.validation_level));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!get_valid_user_struct(p->vuid))
		return NT_STATUS_NO_SUCH_USER;

	if (process_creds) {
		fstring remote_machine;

		/* Get the remote machine name for the creds store. */
		/* Note this is the remote machine this request is coming from (member server),
		   not neccessarily the workstation name the user is logging onto.
		*/

		fstrcpy(remote_machine, r->in.computer_name);

		if (!p->dc) {
			/* Restore the saved state of the netlogon creds. */
			bool ret;

			become_root();
			ret = secrets_restore_schannel_session_info(p->pipe_state_mem_ctx,
					remote_machine,
					&p->dc);
			unbecome_root();
			if (!ret) {
				return NT_STATUS_INVALID_HANDLE;
			}
		}

		if (!p->dc || !p->dc->authenticated) {
			return NT_STATUS_INVALID_HANDLE;
		}

		/* checks and updates credentials.  creates reply credentials */
		if (!netlogon_creds_server_step(p->dc, r->in.credential,  r->out.return_authenticator)) {
			DEBUG(2,("_netr_LogonSamLogon: creds_server_step failed. Rejecting auth "
				"request from client %s machine account %s\n",
				remote_machine, p->dc->mach_acct ));
			return NT_STATUS_INVALID_PARAMETER;
		}

		/* We must store the creds state after an update. */
		become_root();
		secrets_store_schannel_session_info(p->pipe_state_mem_ctx,
					remote_machine,
					p->dc);
		unbecome_root();
	}

	switch (r->in.logon_level) {
	case INTERACTIVE_LOGON_TYPE:
		fstrcpy(nt_username,
			logon->password->identity_info.account_name.string);
		fstrcpy(nt_domain,
			logon->password->identity_info.domain_name.string);
		fstrcpy(nt_workstation,
			logon->password->identity_info.workstation.string);

		DEBUG(3,("SAM Logon (Interactive). Domain:[%s].  ", lp_workgroup()));
		break;
	case NET_LOGON_TYPE:
		fstrcpy(nt_username,
			logon->network->identity_info.account_name.string);
		fstrcpy(nt_domain,
			logon->network->identity_info.domain_name.string);
		fstrcpy(nt_workstation,
			logon->network->identity_info.workstation.string);

		DEBUG(3,("SAM Logon (Network). Domain:[%s].  ", lp_workgroup()));
		break;
	default:
		DEBUG(2,("SAM Logon: unsupported switch value\n"));
		return NT_STATUS_INVALID_INFO_CLASS;
	} /* end switch */

	DEBUG(3,("User:[%s@%s] Requested Domain:[%s]\n", nt_username, nt_workstation, nt_domain));
	fstrcpy(current_user_info.smb_name, nt_username);
	sub_set_smb_name(nt_username);

	DEBUG(5,("Attempting validation level %d for unmapped username %s.\n",
		r->in.validation_level, nt_username));

	status = NT_STATUS_OK;

	switch (r->in.logon_level) {
	case NET_LOGON_TYPE:
	{
		const char *wksname = nt_workstation;

		status = make_auth_context_fixed(&auth_context,
						 logon->network->challenge);
		if (!NT_STATUS_IS_OK(status)) {
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
						     logon->network->identity_info.parameter_control,
						     logon->network->lm.data,
						     logon->network->lm.length,
						     logon->network->nt.data,
						     logon->network->nt.length)) {
			status = NT_STATUS_NO_MEMORY;
		}
		break;
	}
	case INTERACTIVE_LOGON_TYPE:
		/* 'Interactive' authentication, supplies the password in its
		   MD4 form, encrypted with the session key.  We will convert
		   this to challenge/response for the auth subsystem to chew
		   on */
	{
		const uint8 *chal;

		if (!NT_STATUS_IS_OK(status = make_auth_context_subsystem(&auth_context))) {
			return status;
		}

		chal = auth_context->get_ntlm_challenge(auth_context);

		if (!make_user_info_netlogon_interactive(&user_info,
							 nt_username, nt_domain,
							 nt_workstation,
							 logon->password->identity_info.parameter_control,
							 chal,
							 logon->password->lmpassword.hash,
							 logon->password->ntpassword.hash,
							 p->dc->sess_key)) {
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

	DEBUG(5,("_netr_LogonSamLogon: check_password returned status %s\n",
		  nt_errstr(status)));

	/* Check account and password */

	if (!NT_STATUS_IS_OK(status)) {
		/* If we don't know what this domain is, we need to
		   indicate that we are not authoritative.  This
		   allows the client to decide if it needs to try
		   a local user.  Fix by jpjanosi@us.ibm.com, #2976 */
                if ( NT_STATUS_EQUAL(status, NT_STATUS_NO_SUCH_USER)
		     && !strequal(nt_domain, get_global_sam_name())
		     && !is_trusted_domain(nt_domain) )
			*r->out.authoritative = false; /* We are not authoritative */

		TALLOC_FREE(server_info);
		return status;
	}

	if (server_info->guest) {
		/* We don't like guest domain logons... */
		DEBUG(5,("_netr_LogonSamLogon: Attempted domain logon as GUEST "
			 "denied.\n"));
		TALLOC_FREE(server_info);
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
		const char *my_name;

		struct netr_UserSessionKey user_session_key;
		struct netr_LMSessionKey lm_session_key;
		unsigned char pipe_session_key[16];

		NTTIME last_logon, last_logoff, acct_expiry, last_password_change;
		NTTIME allow_password_change, force_password_change;
		struct samr_RidWithAttributeArray groups;
		int i;
		struct dom_sid2 *sid = NULL;

		ZERO_STRUCT(user_session_key);
		ZERO_STRUCT(lm_session_key);

		sampw = server_info->sam_account;

		user_sid = pdb_get_user_sid(sampw);
		group_sid = pdb_get_group_sid(sampw);

		if ((user_sid == NULL) || (group_sid == NULL)) {
			DEBUG(1, ("_netr_LogonSamLogon: User without group or user SID\n"));
			return NT_STATUS_UNSUCCESSFUL;
		}

		sid_copy(&domain_sid, user_sid);
		sid_split_rid(&domain_sid, &user_rid);

		sid = sid_dup_talloc(p->mem_ctx, &domain_sid);
		if (!sid) {
			return NT_STATUS_NO_MEMORY;
		}

		if (!sid_peek_check_rid(&domain_sid, group_sid, &group_rid)) {
			DEBUG(1, ("_netr_LogonSamLogon: user %s\\%s has user sid "
				  "%s\n but group sid %s.\n"
				  "The conflicting domain portions are not "
				  "supported for NETLOGON calls\n",
				  pdb_get_domain(sampw),
				  pdb_get_username(sampw),
				  sid_string_dbg(user_sid),
				  sid_string_dbg(group_sid)));
			return NT_STATUS_UNSUCCESSFUL;
		}

		if(server_info->login_server) {
		        my_name = server_info->login_server;
		} else {
		        my_name = global_myname();
		}

		status = nt_token_to_group_list(p->mem_ctx, &domain_sid,
						server_info->num_sids,
						server_info->sids,
						&num_gids, &gids);

		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		if (server_info->user_session_key.length) {
			memcpy(user_session_key.key,
			       server_info->user_session_key.data,
			       MIN(sizeof(user_session_key.key),
				   server_info->user_session_key.length));
			if (process_creds) {
				/* Get the pipe session key from the creds. */
				memcpy(pipe_session_key, p->dc->sess_key, 16);
			} else {
				/* Get the pipe session key from the schannel. */
				if (p->auth.auth_type != PIPE_AUTH_TYPE_SCHANNEL || p->auth.a_u.schannel_auth == NULL) {
					return NT_STATUS_INVALID_HANDLE;
				}
				memcpy(pipe_session_key, p->auth.a_u.schannel_auth->sess_key, 16);
			}
			SamOEMhash(user_session_key.key, pipe_session_key, 16);
			memset(pipe_session_key, '\0', 16);
		}
		if (server_info->lm_session_key.length) {
			memcpy(lm_session_key.key,
			       server_info->lm_session_key.data,
			       MIN(sizeof(lm_session_key.key),
				   server_info->lm_session_key.length));
			if (process_creds) {
				/* Get the pipe session key from the creds. */
				memcpy(pipe_session_key, p->dc->sess_key, 16);
			} else {
				/* Get the pipe session key from the schannel. */
				if (p->auth.auth_type != PIPE_AUTH_TYPE_SCHANNEL || p->auth.a_u.schannel_auth == NULL) {
					return NT_STATUS_INVALID_HANDLE;
				}
				memcpy(pipe_session_key, p->auth.a_u.schannel_auth->sess_key, 16);
			}
			SamOEMhash(lm_session_key.key, pipe_session_key, 8);
			memset(pipe_session_key, '\0', 16);
		}

		groups.count = num_gids;
		groups.rids = TALLOC_ARRAY(p->mem_ctx, struct samr_RidWithAttribute,
					   groups.count);
		if (!groups.rids) {
			return NT_STATUS_NO_MEMORY;
		}

		for (i=0; i < groups.count; i++) {
			groups.rids[i].rid = gids[i].g_rid;
			groups.rids[i].attributes = gids[i].attr;
		}

		unix_to_nt_time(&last_logon, pdb_get_logon_time(sampw));
		unix_to_nt_time(&last_logoff, get_time_t_max());
		unix_to_nt_time(&acct_expiry, get_time_t_max());
		unix_to_nt_time(&last_password_change, pdb_get_pass_last_set_time(sampw));
		unix_to_nt_time(&allow_password_change, pdb_get_pass_can_change_time(sampw));
		unix_to_nt_time(&force_password_change, pdb_get_pass_must_change_time(sampw));

		init_netr_SamInfo3(sam3,
				   last_logon,
				   last_logoff,
				   acct_expiry,
				   last_password_change,
				   allow_password_change,
				   force_password_change,
				   talloc_strdup(p->mem_ctx, pdb_get_username(sampw)),
				   talloc_strdup(p->mem_ctx, pdb_get_fullname(sampw)),
				   talloc_strdup(p->mem_ctx, pdb_get_logon_script(sampw)),
				   talloc_strdup(p->mem_ctx, pdb_get_profile_path(sampw)),
				   talloc_strdup(p->mem_ctx, pdb_get_homedir(sampw)),
				   talloc_strdup(p->mem_ctx, pdb_get_dir_drive(sampw)),
				   0, /* logon_count */
				   0, /* bad_password_count */
				   user_rid,
				   group_rid,
				   groups,
				   NETLOGON_EXTRA_SIDS,
				   user_session_key,
				   my_name,
				   talloc_strdup(p->mem_ctx, pdb_get_domain(sampw)),
				   sid,
				   lm_session_key,
				   pdb_get_acct_ctrl(sampw),
				   0, /* sidcount */
				   NULL); /* struct netr_SidAttr *sids */
		ZERO_STRUCT(user_session_key);
		ZERO_STRUCT(lm_session_key);
	}
	TALLOC_FREE(server_info);
	return status;
}

/*************************************************************************
 _netr_LogonSamLogonEx
 - no credential chaining. Map into net sam logon.
 *************************************************************************/

NTSTATUS _netr_LogonSamLogonEx(pipes_struct *p,
			       struct netr_LogonSamLogonEx *r)
{
	struct netr_LogonSamLogon q;

	/* Only allow this if the pipe is protected. */
	if (p->auth.auth_type != PIPE_AUTH_TYPE_SCHANNEL) {
		DEBUG(0,("_net_sam_logon_ex: client %s not using schannel for netlogon\n",
			get_remote_machine_name() ));
		return NT_STATUS_INVALID_PARAMETER;
        }

	q.in.server_name 	= r->in.server_name;
	q.in.computer_name	= r->in.computer_name;
	q.in.logon_level	= r->in.logon_level;
	q.in.logon		= r->in.logon;
	q.in.validation_level	= r->in.validation_level;
	/* we do not handle the flags */
	/*			= r->in.flags; */

	q.out.validation	= r->out.validation;
	q.out.authoritative	= r->out.authoritative;
	/* we do not handle the flags */
	/*			= r->out.flags; */

	return _netr_LogonSamLogon(p, &q);
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


/****************************************************************
****************************************************************/

WERROR _netr_LogonUasLogon(pipes_struct *p,
			   struct netr_LogonUasLogon *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_LogonUasLogoff(pipes_struct *p,
			    struct netr_LogonUasLogoff *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_DatabaseDeltas(pipes_struct *p,
			      struct netr_DatabaseDeltas *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_DatabaseSync(pipes_struct *p,
			    struct netr_DatabaseSync *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_AccountDeltas(pipes_struct *p,
			     struct netr_AccountDeltas *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_AccountSync(pipes_struct *p,
			   struct netr_AccountSync *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_GetDcName(pipes_struct *p,
		       struct netr_GetDcName *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_GetAnyDCName(pipes_struct *p,
			  struct netr_GetAnyDCName *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_DatabaseSync2(pipes_struct *p,
			     struct netr_DatabaseSync2 *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_DatabaseRedo(pipes_struct *p,
			    struct netr_DatabaseRedo *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_LogonControl2Ex(pipes_struct *p,
			     struct netr_LogonControl2Ex *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_DsRGetDCName(pipes_struct *p,
			  struct netr_DsRGetDCName *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_NETRLOGONDUMMYROUTINE1(pipes_struct *p,
				    struct netr_NETRLOGONDUMMYROUTINE1 *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_NETRLOGONSETSERVICEBITS(pipes_struct *p,
				     struct netr_NETRLOGONSETSERVICEBITS *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_LogonGetTrustRid(pipes_struct *p,
			      struct netr_LogonGetTrustRid *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_NETRLOGONCOMPUTESERVERDIGEST(pipes_struct *p,
					  struct netr_NETRLOGONCOMPUTESERVERDIGEST *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_NETRLOGONCOMPUTECLIENTDIGEST(pipes_struct *p,
					  struct netr_NETRLOGONCOMPUTECLIENTDIGEST *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_ServerAuthenticate3(pipes_struct *p,
				   struct netr_ServerAuthenticate3 *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_DsRGetDCNameEx(pipes_struct *p,
			    struct netr_DsRGetDCNameEx *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_DsRGetSiteName(pipes_struct *p,
			    struct netr_DsRGetSiteName *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_LogonGetDomainInfo(pipes_struct *p,
				  struct netr_LogonGetDomainInfo *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_ServerPasswordSet2(pipes_struct *p,
				  struct netr_ServerPasswordSet2 *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_ServerPasswordGet(pipes_struct *p,
			       struct netr_ServerPasswordGet *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_NETRLOGONSENDTOSAM(pipes_struct *p,
				struct netr_NETRLOGONSENDTOSAM *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_DsRAddressToSitenamesW(pipes_struct *p,
				    struct netr_DsRAddressToSitenamesW *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_DsRGetDCNameEx2(pipes_struct *p,
			     struct netr_DsRGetDCNameEx2 *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_NETRLOGONGETTIMESERVICEPARENTDOMAIN(pipes_struct *p,
						 struct netr_NETRLOGONGETTIMESERVICEPARENTDOMAIN *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_NetrEnumerateTrustedDomainsEx(pipes_struct *p,
					   struct netr_NetrEnumerateTrustedDomainsEx *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_DsRAddressToSitenamesExW(pipes_struct *p,
				      struct netr_DsRAddressToSitenamesExW *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_DsrGetDcSiteCoverageW(pipes_struct *p,
				   struct netr_DsrGetDcSiteCoverageW *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_DsrEnumerateDomainTrusts(pipes_struct *p,
				      struct netr_DsrEnumerateDomainTrusts *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_DsrDeregisterDNSHostRecords(pipes_struct *p,
					 struct netr_DsrDeregisterDNSHostRecords *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_ServerTrustPasswordsGet(pipes_struct *p,
				       struct netr_ServerTrustPasswordsGet *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_DsRGetForestTrustInformation(pipes_struct *p,
					  struct netr_DsRGetForestTrustInformation *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_GetForestTrustInformation(pipes_struct *p,
				       struct netr_GetForestTrustInformation *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_LogonSamLogonWithFlags(pipes_struct *p,
				      struct netr_LogonSamLogonWithFlags *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_NETRSERVERGETTRUSTINFO(pipes_struct *p,
				    struct netr_NETRSERVERGETTRUSTINFO *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

