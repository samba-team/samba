/* 
   Unix SMB/CIFS implementation.

   Authenticate a user to a domain controller

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   Copyright (C) Andrew Tridgell 2004

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "include/secrets.h"
#include "lib/ldb/include/ldb.h"
#include "auth/auth.h"

/* Authenticate a user with a challenge/response */
static NTSTATUS domain_check_password(struct auth_method_context *ctx,
				      TALLOC_CTX *mem_ctx,
				      const struct auth_usersupplied_info *user_info, 
				      struct auth_serversupplied_info **server_info)
{
	NTSTATUS status;

	struct dcerpc_pipe *p;
	struct dcerpc_binding *b;
	struct netr_LogonSamLogon r;
	struct netr_Authenticator auth, auth2;
	struct netr_NetworkInfo ninfo;
	const char *machine_account;
	const char *password;
	struct ldb_context *ldb;
	int ldb_ret;
	struct ldb_message **msgs;
	const char *base_dn = SECRETS_PRIMARY_DOMAIN_DN;
	const char *attrs[] = {
		"secret",
		"samAccountName",
		NULL
	};

	struct creds_CredentialState *creds;
	struct cli_credentials *credentials;

	const char **bindings = lp_passwordserver();
	const char *binding;

	if (bindings && bindings[0]) {
		binding = bindings[0];
	}

	credentials = cli_credentials_init(mem_ctx);

	/* Fetch join password */

	/* Local secrets are stored in secrets.ldb */
	ldb = secrets_db_connect(mem_ctx);
	if (!ldb) {
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	/* search for the secret record */
	ldb_ret = samdb_search(ldb,
			       mem_ctx, base_dn, &msgs, attrs,
			       "(&(flatname=%s)(objectclass=primaryDomain))", 
			       lp_workgroup());
	if (ldb_ret == 0) {
		DEBUG(1, ("Could not find join record to domain: %s\n",
			  lp_workgroup()));
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	} else if (ldb_ret != 1) {
		DEBUG(1, ("Found %d records matching flatname=%s under DN %s\n", ldb_ret, 
			  lp_workgroup(), base_dn));
		return NT_STATUS_INTERNAL_ERROR;
	}

	password = ldb_msg_find_string(msgs[0], "secret", NULL);
	if (!password) {
		DEBUG(1, ("Could not find 'secret' in join record to domain: %s\n",
			  lp_workgroup()));
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}
		
	machine_account = ldb_msg_find_string(msgs[0], "samAccountName", NULL);
	if (!machine_account) {
		DEBUG(1, ("Could not find 'samAccountName' in join record to domain: %s\n",
			  lp_workgroup()));
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	cli_credentials_set_domain(credentials, lp_workgroup(), CRED_SPECIFIED);
	cli_credentials_set_username(credentials, machine_account, CRED_SPECIFIED);
	cli_credentials_set_password(credentials, password, CRED_SPECIFIED);
	
	cli_credentials_guess(credentials);

	/* Connect to DC (take a binding string for now) */

	status = dcerpc_parse_binding(mem_ctx, binding, &b);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Bad binding string %s\n", binding);
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* We like schannel */
	b->flags &= ~DCERPC_AUTH_OPTIONS;
	b->flags |= DCERPC_SCHANNEL_WORKSTATION | DCERPC_SEAL | DCERPC_SCHANNEL_128;

	/* Setup schannel */
	status = dcerpc_pipe_connect_b(mem_ctx, &p, b, 
				       DCERPC_NETLOGON_UUID,
				       DCERPC_NETLOGON_VERSION,
				       credentials);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* call domain logon */

	status = dcerpc_schannel_creds(p->conn->security_state.generic_state, mem_ctx, &creds);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	ninfo.identity_info.domain_name.string = user_info->domain_name;
	ninfo.identity_info.parameter_control = 0;
	ninfo.identity_info.logon_id_low = 0;
	ninfo.identity_info.logon_id_high = 0;
	ninfo.identity_info.account_name.string = user_info->account_name;
	ninfo.identity_info.workstation.string = user_info->workstation_name;
	memcpy(ninfo.challenge, ctx->auth_ctx->challenge.data.data, sizeof(ninfo.challenge));

	ninfo.nt.length = user_info->nt_resp.length;
	ninfo.nt.data =  user_info->nt_resp.data;
	ninfo.lm.length = user_info->lm_resp.length;
	ninfo.lm.data = user_info->lm_resp.data;

	r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.workstation = creds->computer_name;
	r.in.credential = &auth;
	r.in.return_authenticator = &auth2;
	r.in.logon_level = 2;
	r.in.logon.network = &ninfo;
	r.in.validation_level = 3;

	ZERO_STRUCT(auth2);
	creds_client_authenticator(creds, &auth);
	
	status = dcerpc_netr_LogonSamLogon(p, mem_ctx, &r);
	
	if (!creds_client_check(creds, &r.out.return_authenticator->cred)) {
		DEBUG(1, ("Credential chaining failed\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	/* make server info */

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	status = make_server_info_netlogon_validation(mem_ctx, 
						      user_info->account_name, 
						      r.in.validation_level, &r.out.validation,
						      server_info);
	return status;
}

static const struct auth_operations domain_ops = {
	.name		= "domain",
	.get_challenge	= auth_get_challenge_not_implemented,
	.check_password	= domain_check_password
};

NTSTATUS auth_domain_init(void)
{
	NTSTATUS ret;

	ret = auth_register(&domain_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register 'domain' auth backend!\n"));
		return ret;
	}
	return ret;
}
