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
	struct netr_LogonControl2Ex l;

	switch (r->in.level) {
	case 1:
		break;
	case 2:
		return WERR_NOT_SUPPORTED;
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	l.in.logon_server	= r->in.logon_server;
	l.in.function_code	= r->in.function_code;
	l.in.level		= r->in.level;
	l.in.data		= NULL;
	l.out.query		= r->out.info;

	return _netr_LogonControl2Ex(p, &l);
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
	struct netr_LogonControl2Ex l;

	l.in.logon_server	= r->in.logon_server;
	l.in.function_code	= r->in.function_code;
	l.in.level		= r->in.level;
	l.in.data		= r->in.data;
	l.out.query		= r->out.query;

	return _netr_LogonControl2Ex(p, &l);
}

/****************************************************************
 _netr_LogonControl2Ex
****************************************************************/

WERROR _netr_LogonControl2Ex(pipes_struct *p,
			     struct netr_LogonControl2Ex *r)
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
	const char *fn;

	switch (p->hdr_req.opnum) {
		case NDR_NETR_LOGONCONTROL:
			fn = "_netr_LogonControl";
			break;
		case NDR_NETR_LOGONCONTROL2:
			fn = "_netr_LogonControl2";
			break;
		case NDR_NETR_LOGONCONTROL2EX:
			fn = "_netr_LogonControl2Ex";
			break;
		default:
			return WERR_INVALID_PARAM;
	}

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
			DEBUG(0,("%s: unimplemented function level [%d]\n",
				fn, r->in.function_code));
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

static NTSTATUS get_md4pw(char *md4pw, const char *mach_acct,
			  uint16_t sec_chan_type, uint32_t *rid)
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

	if (rid) {
		*rid = pdb_get_user_rid(sampass);
	}

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
		p->dc = TALLOC_ZERO_P(p, struct dcinfo);
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
			   r->in.secure_channel_type,
			   NULL);
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
 _netr_ServerAuthenticate3
 *************************************************************************/

NTSTATUS _netr_ServerAuthenticate3(pipes_struct *p,
				   struct netr_ServerAuthenticate3 *r)
{
	NTSTATUS status;
	uint32_t srv_flgs;
	/* r->in.negotiate_flags is an aliased pointer to r->out.negotiate_flags,
	 * so use a copy to avoid destroying the client values. */
	uint32_t in_neg_flags = *r->in.negotiate_flags;
	struct netr_Credential srv_chal_out;
	const char *fn;

	/* According to Microsoft (see bugid #6099)
	 * Windows 7 looks at the negotiate_flags
	 * returned in this structure *even if the
	 * call fails with access denied* ! So in order
	 * to allow Win7 to connect to a Samba NT style
	 * PDC we set the flags before we know if it's
	 * an error or not.
	 */

	/* 0x000001ff */
	srv_flgs = NETLOGON_NEG_ACCOUNT_LOCKOUT |
		   NETLOGON_NEG_PERSISTENT_SAMREPL |
		   NETLOGON_NEG_ARCFOUR |
		   NETLOGON_NEG_PROMOTION_COUNT |
		   NETLOGON_NEG_CHANGELOG_BDC |
		   NETLOGON_NEG_FULL_SYNC_REPL |
		   NETLOGON_NEG_MULTIPLE_SIDS |
		   NETLOGON_NEG_REDO |
		   NETLOGON_NEG_PASSWORD_CHANGE_REFUSAL;

	/* Ensure we support strong (128-bit) keys. */
	if (in_neg_flags & NETLOGON_NEG_STRONG_KEYS) {
		srv_flgs |= NETLOGON_NEG_STRONG_KEYS;
	}

	if (lp_server_schannel() != false) {
		srv_flgs |= NETLOGON_NEG_SCHANNEL;
	}

	switch (p->hdr_req.opnum) {
		case NDR_NETR_SERVERAUTHENTICATE2:
			fn = "_netr_ServerAuthenticate2";
			break;
		case NDR_NETR_SERVERAUTHENTICATE3:
			fn = "_netr_ServerAuthenticate3";
			break;
		default:
			return NT_STATUS_INTERNAL_ERROR;
	}

	/* We use this as the key to store the creds: */
	/* r->in.computer_name */

	if (!p->dc || !p->dc->challenge_sent) {
		DEBUG(0,("%s: no challenge sent to client %s\n", fn,
			r->in.computer_name));
		status = NT_STATUS_ACCESS_DENIED;
		goto out;
	}

	if ( (lp_server_schannel() == true) &&
	     ((in_neg_flags & NETLOGON_NEG_SCHANNEL) == 0) ) {

		/* schannel must be used, but client did not offer it. */
		DEBUG(0,("%s: schannel required but client failed "
			"to offer it. Client was %s\n",
			fn, r->in.account_name));
		status = NT_STATUS_ACCESS_DENIED;
		goto out;
	}

	status = get_md4pw((char *)p->dc->mach_pw,
			   r->in.account_name,
			   r->in.secure_channel_type,
			   r->out.rid);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("%s: failed to get machine password for "
			"account %s: %s\n",
			fn, r->in.account_name, nt_errstr(status) ));
		/* always return NT_STATUS_ACCESS_DENIED */
		status = NT_STATUS_ACCESS_DENIED;
		goto out;
	}

	/* From the client / server challenges and md4 password, generate sess key */
	creds_server_init(in_neg_flags,
			p->dc,
			&p->dc->clnt_chal,	/* Stored client chal. */
			&p->dc->srv_chal,	/* Stored server chal. */
			p->dc->mach_pw,
			&srv_chal_out);

	/* Check client credentials are valid. */
	if (!netlogon_creds_server_check(p->dc, r->in.credentials)) {
		DEBUG(0,("%s: netlogon_creds_server_check failed. Rejecting auth "
			"request from client %s machine account %s\n",
			fn, r->in.computer_name,
			r->in.account_name));
		status = NT_STATUS_ACCESS_DENIED;
		goto out;
	}
	/* set up the LSA AUTH 2 response */
	memcpy(r->out.return_credentials->data, &srv_chal_out.data,
	       sizeof(r->out.return_credentials->data));

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
	status = NT_STATUS_OK;

  out:

	*r->out.negotiate_flags = srv_flgs;
	return status;
}

/*************************************************************************
 _netr_ServerAuthenticate2
 *************************************************************************/

NTSTATUS _netr_ServerAuthenticate2(pipes_struct *p,
				   struct netr_ServerAuthenticate2 *r)
{
	struct netr_ServerAuthenticate3 a;
	uint32_t rid;

	a.in.server_name		= r->in.server_name;
	a.in.account_name		= r->in.account_name;
	a.in.secure_channel_type	= r->in.secure_channel_type;
	a.in.computer_name		= r->in.computer_name;
	a.in.credentials		= r->in.credentials;
	a.in.negotiate_flags		= r->in.negotiate_flags;

	a.out.return_credentials	= r->out.return_credentials;
	a.out.rid			= &rid;
	a.out.negotiate_flags		= r->out.negotiate_flags;

	return _netr_ServerAuthenticate3(p, &a);
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
		ret = secrets_restore_schannel_session_info(p, remote_machine,
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
	secrets_store_schannel_session_info(p, remote_machine, p->dc);
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
	       sizeof(*(r->out.return_authenticator)));

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


	/* Using the remote machine name for the creds store: */
	/* r->in.computer_name */

	if (!p->dc) {
		/* Restore the saved state of the netlogon creds. */
		bool ret;

		become_root();
		ret = secrets_restore_schannel_session_info(
			p, r->in.computer_name, &p->dc);
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
	secrets_store_schannel_session_info(p, r->in.computer_name, p->dc);
	unbecome_root();

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
	union netr_LogonLevel *logon = r->in.logon;
	fstring nt_username, nt_domain, nt_workstation;
	auth_usersupplied_info *user_info = NULL;
	auth_serversupplied_info *server_info = NULL;
	struct auth_context *auth_context = NULL;
	uint8_t pipe_session_key[16];
	bool process_creds = true;
	const char *fn;

	switch (p->hdr_req.opnum) {
		case NDR_NETR_LOGONSAMLOGON:
			process_creds = true;
			fn = "_netr_LogonSamLogon";
			break;
		case NDR_NETR_LOGONSAMLOGONEX:
			fn = "_netr_LogonSamLogonEx";
		default:
			fn = "";
			process_creds = false;
	}

	if ( (lp_server_schannel() == True) && (p->auth.auth_type != PIPE_AUTH_TYPE_SCHANNEL) ) {
		/* 'server schannel = yes' should enforce use of
		   schannel, the client did offer it in auth2, but
		   obviously did not use it. */
		DEBUG(0,("%s: client %s not using schannel for netlogon\n",
			fn, get_remote_machine_name() ));
		return NT_STATUS_ACCESS_DENIED;
	}

	*r->out.authoritative = true; /* authoritative response */
	if (r->in.validation_level != 2 && r->in.validation_level != 3) {
		DEBUG(0,("%s: bad validation_level value %d.\n",
			fn, (int)r->in.validation_level));
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	sam3 = TALLOC_ZERO_P(p->mem_ctx, struct netr_SamInfo3);
	if (!sam3) {
		return NT_STATUS_NO_MEMORY;
	}

 	/* store the user information, if there is any. */
	r->out.validation->sam3 = sam3;

	if (process_creds) {

		/* Get the remote machine name for the creds store. */
		/* Note this is the remote machine this request is coming from (member server),
		   not neccessarily the workstation name the user is logging onto.
		*/

		if (!p->dc) {
			/* Restore the saved state of the netlogon creds. */
			bool ret;

			become_root();
			ret = secrets_restore_schannel_session_info(
				p, r->in.computer_name, &p->dc);
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
			DEBUG(2,("%s: creds_server_step failed. Rejecting auth "
				"request from client %s machine account %s\n",
				fn, r->in.computer_name, p->dc->mach_acct ));
			return NT_STATUS_INVALID_PARAMETER;
		}

		/* We must store the creds state after an update. */
		become_root();
		secrets_store_schannel_session_info(p, r->in.computer_name, p->dc);
		unbecome_root();
	}

	switch (r->in.logon_level) {
	case NetlogonInteractiveInformation:
		fstrcpy(nt_username,
			logon->password->identity_info.account_name.string);
		fstrcpy(nt_domain,
			logon->password->identity_info.domain_name.string);
		fstrcpy(nt_workstation,
			logon->password->identity_info.workstation.string);

		DEBUG(3,("SAM Logon (Interactive). Domain:[%s].  ", lp_workgroup()));
		break;
	case NetlogonNetworkInformation:
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
	case NetlogonNetworkInformation:
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
	case NetlogonInteractiveInformation:
		/* 'Interactive' authentication, supplies the password in its
		   MD4 form, encrypted with the session key.  We will convert
		   this to challenge/response for the auth subsystem to chew
		   on */
	{
		uint8_t chal[8];

		if (!NT_STATUS_IS_OK(status = make_auth_context_subsystem(&auth_context))) {
			return status;
		}

		auth_context->get_ntlm_challenge(auth_context, chal);

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

	DEBUG(5,("%s: check_password returned status %s\n",
		  fn, nt_errstr(status)));

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
		DEBUG(5,("%s: Attempted domain logon as GUEST "
			 "denied.\n", fn));
		TALLOC_FREE(server_info);
		return NT_STATUS_LOGON_FAILURE;
	}

	/* This is the point at which, if the login was successful, that
           the SAM Local Security Authority should record that the user is
           logged in to the domain.  */

	if (process_creds) {
		/* Get the pipe session key from the creds. */
		memcpy(pipe_session_key, p->dc->sess_key, 16);
	} else {
		/* Get the pipe session key from the schannel. */
		if ((p->auth.auth_type != PIPE_AUTH_TYPE_SCHANNEL)
		    || (p->auth.a_u.schannel_auth == NULL)) {
			return NT_STATUS_INVALID_HANDLE;
		}
		memcpy(pipe_session_key, p->auth.a_u.schannel_auth->sess_key, 16);
	}

	status = serverinfo_to_SamInfo3(server_info, pipe_session_key, 16, sam3);
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
		DEBUG(0,("_netr_LogonSamLogonEx: client %s not using schannel for netlogon\n",
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

WERROR _netr_DsRGetDCName(pipes_struct *p,
			  struct netr_DsRGetDCName *r)
{
	p->rng_fault_state = true;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_LogonGetCapabilities(pipes_struct *p,
				    struct netr_LogonGetCapabilities *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
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

NTSTATUS _netr_ServerGetTrustInfo(pipes_struct *p,
				  struct netr_ServerGetTrustInfo *r)
{
	p->rng_fault_state = true;
	return NT_STATUS_NOT_IMPLEMENTED;
}

