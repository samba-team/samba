/*
 *  Unix SMB/CIFS implementation.
 *  Routines to operate on various trust relationships
 *  Copyright (C) Andrew Bartlett                   2001
 *  Copyright (C) Rafal Szczesniak                  2003
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

#include "includes.h"

/*********************************************************
 Change the domain password on the PDC.

 Just changes the password betwen the two values specified.

 Caller must have the cli connected to the netlogon pipe
 already.
**********************************************************/

static NTSTATUS just_change_the_password(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, 
					 const unsigned char orig_trust_passwd_hash[16],
					 const char *new_trust_pwd_cleartext,
					 const unsigned char new_trust_passwd_hash[16],
					 uint32 sec_channel_type)
{
	NTSTATUS result;
	uint32_t neg_flags = NETLOGON_NEG_AUTH2_ADS_FLAGS;

	result = rpccli_netlogon_setup_creds(cli,
					     cli->cli->desthost, /* server name */
					     lp_workgroup(), /* domain */
					     global_myname(), /* client name */
					     global_myname(), /* machine account name */
					     orig_trust_passwd_hash,
					     sec_channel_type,
					     &neg_flags);

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(3,("just_change_the_password: unable to setup creds (%s)!\n",
			 nt_errstr(result)));
		return result;
	}

	if (neg_flags & NETLOGON_NEG_PASSWORD_SET2) {

		struct netr_Authenticator clnt_creds, srv_cred;
		struct netr_CryptPassword new_password;
		struct samr_CryptPassword password_buf;

		netlogon_creds_client_step(cli->dc, &clnt_creds);

		encode_pw_buffer(password_buf.data, new_trust_pwd_cleartext, STR_UNICODE);

		SamOEMhash(password_buf.data, cli->dc->sess_key, 516);
		memcpy(new_password.data, password_buf.data, 512);
		new_password.length = IVAL(password_buf.data, 512);

		result = rpccli_netr_ServerPasswordSet2(cli, mem_ctx,
						       cli->dc->remote_machine,
						       cli->dc->mach_acct,
						       sec_channel_type,
						       global_myname(),
						       &clnt_creds,
						       &srv_cred,
						       &new_password);

		/* Always check returned credentials. */
		if (!netlogon_creds_client_check(cli->dc, &srv_cred.cred)) {
			DEBUG(0,("rpccli_netr_ServerPasswordSet2: "
				"credentials chain check failed\n"));
			return NT_STATUS_ACCESS_DENIED;
		}

	} else {

		struct netr_Authenticator clnt_creds, srv_cred;
		struct samr_Password new_password;

		netlogon_creds_client_step(cli->dc, &clnt_creds);

		cred_hash3(new_password.hash,
			   new_trust_passwd_hash,
			   cli->dc->sess_key, 1);

		result = rpccli_netr_ServerPasswordSet(cli, mem_ctx,
						       cli->dc->remote_machine,
						       cli->dc->mach_acct,
						       sec_channel_type,
						       global_myname(),
						       &clnt_creds,
						       &srv_cred,
						       &new_password);

		/* Always check returned credentials. */
		if (!netlogon_creds_client_check(cli->dc, &srv_cred.cred)) {
			DEBUG(0,("rpccli_netr_ServerPasswordSet: "
				"credentials chain check failed\n"));
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0,("just_change_the_password: unable to change password (%s)!\n",
			 nt_errstr(result)));
	}
	return result;
}

/*********************************************************
 Change the domain password on the PDC.
 Store the password ourselves, but use the supplied password
 Caller must have already setup the connection to the NETLOGON pipe
**********************************************************/

NTSTATUS trust_pw_change_and_store_it(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, 
				      const char *domain,
				      unsigned char orig_trust_passwd_hash[16],
				      uint32 sec_channel_type)
{
	unsigned char new_trust_passwd_hash[16];
	char *new_trust_passwd;
	char *str;
	NTSTATUS nt_status;
		
	/* Create a random machine account password */
	str = generate_random_str(DEFAULT_TRUST_ACCOUNT_PASSWORD_LENGTH);

	if ((new_trust_passwd = talloc_strdup(mem_ctx, str)) == NULL) {
		DEBUG(0, ("talloc_strdup failed\n"));
		return NT_STATUS_NO_MEMORY;
	}
	
	E_md4hash(new_trust_passwd, new_trust_passwd_hash);

	nt_status = just_change_the_password(cli, mem_ctx,
					     orig_trust_passwd_hash,
					     new_trust_passwd,
					     new_trust_passwd_hash,
					     sec_channel_type);
	
	if (NT_STATUS_IS_OK(nt_status)) {
		DEBUG(3,("%s : trust_pw_change_and_store_it: Changed password.\n", 
			 current_timestring(debug_ctx(), False)));
		/*
		 * Return the result of trying to write the new password
		 * back into the trust account file.
		 */
		if (!secrets_store_machine_password(new_trust_passwd, domain, sec_channel_type)) {
			nt_status = NT_STATUS_UNSUCCESSFUL;
		}
	}

	return nt_status;
}

/*********************************************************
 Change the domain password on the PDC.
 Do most of the legwork ourselfs.  Caller must have
 already setup the connection to the NETLOGON pipe
**********************************************************/

NTSTATUS trust_pw_find_change_and_store_it(struct rpc_pipe_client *cli, 
					   TALLOC_CTX *mem_ctx, 
					   const char *domain) 
{
	unsigned char old_trust_passwd_hash[16];
	uint32 sec_channel_type = 0;

	if (!secrets_fetch_trust_account_password(domain,
						  old_trust_passwd_hash, 
						  NULL, &sec_channel_type)) {
		DEBUG(0, ("could not fetch domain secrets for domain %s!\n", domain));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	return trust_pw_change_and_store_it(cli, mem_ctx, domain,
					    old_trust_passwd_hash,
					    sec_channel_type);
}

/*********************************************************************
 Enumerate the list of trusted domains from a DC
*********************************************************************/

bool enumerate_domain_trusts( TALLOC_CTX *mem_ctx, const char *domain,
                                     char ***domain_names, uint32 *num_domains,
				     DOM_SID **sids )
{
	POLICY_HND 	pol;
	NTSTATUS 	result = NT_STATUS_UNSUCCESSFUL;
	fstring 	dc_name;
	struct sockaddr_storage	dc_ss;
	uint32 		enum_ctx = 0;
	struct cli_state *cli = NULL;
	struct rpc_pipe_client *lsa_pipe;
	bool 		retry;
	struct lsa_DomainList dom_list;
	int i;

	*domain_names = NULL;
	*num_domains = 0;
	*sids = NULL;

	/* lookup a DC first */

	if ( !get_dc_name(domain, NULL, dc_name, &dc_ss) ) {
		DEBUG(3,("enumerate_domain_trusts: can't locate a DC for domain %s\n",
			domain));
		return False;
	}

	/* setup the anonymous connection */

	result = cli_full_connection( &cli, global_myname(), dc_name, &dc_ss, 0, "IPC$", "IPC",
		"", "", "", 0, Undefined, &retry);
	if ( !NT_STATUS_IS_OK(result) )
		goto done;

	/* open the LSARPC_PIPE	*/

	lsa_pipe = cli_rpc_pipe_open_noauth( cli, PI_LSARPC, &result );
	if ( !lsa_pipe) {
		goto done;
	}

	/* get a handle */

	result = rpccli_lsa_open_policy(lsa_pipe, mem_ctx, True,
		LSA_POLICY_VIEW_LOCAL_INFORMATION, &pol);
	if ( !NT_STATUS_IS_OK(result) )
		goto done;

	/* Lookup list of trusted domains */

	result = rpccli_lsa_EnumTrustDom(lsa_pipe, mem_ctx,
					 &pol,
					 &enum_ctx,
					 &dom_list,
					 (uint32_t)-1);
	if ( !NT_STATUS_IS_OK(result) )
		goto done;

	*num_domains = dom_list.count;

	*domain_names = TALLOC_ZERO_ARRAY(mem_ctx, char *, *num_domains);
	if (!*domain_names) {
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

	*sids = TALLOC_ZERO_ARRAY(mem_ctx, DOM_SID, *num_domains);
	if (!*sids) {
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

	for (i=0; i< *num_domains; i++) {
		(*domain_names)[i] = CONST_DISCARD(char *, dom_list.domains[i].name.string);
		(*sids)[i] = *dom_list.domains[i].sid;
	}

done:
	/* cleanup */
	if (cli) {
		DEBUG(10,("enumerate_domain_trusts: shutting down connection...\n"));
		cli_shutdown( cli );
	}

	return NT_STATUS_IS_OK(result);
}
