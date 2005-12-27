/* 
   Unix SMB/CIFS implementation.

   dcerpc schannel operations

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005

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
#include "librpc/gen_ndr/ndr_schannel.h"
#include "auth/auth.h"

/*
  get a schannel key using a netlogon challenge on a secondary pipe
*/
static NTSTATUS dcerpc_schannel_key(TALLOC_CTX *tmp_ctx, 
				    struct dcerpc_pipe *p,
				    struct cli_credentials *credentials)
{
	NTSTATUS status;
	struct dcerpc_binding *b;
	struct dcerpc_pipe *p2;
	struct netr_ServerReqChallenge r;
	struct netr_ServerAuthenticate2 a;
	struct netr_Credential credentials1, credentials2, credentials3;
	const struct samr_Password *mach_pwd;
	uint32_t negotiate_flags;
	struct creds_CredentialState *creds;
	creds = talloc(tmp_ctx, struct creds_CredentialState);
	if (!creds) {
		return NT_STATUS_NO_MEMORY;
	}

	if (p->conn->flags & DCERPC_SCHANNEL_128) {
		negotiate_flags = NETLOGON_NEG_AUTH2_ADS_FLAGS;
	} else {
		negotiate_flags = NETLOGON_NEG_AUTH2_FLAGS;
	}

	/*
	  step 1 - establish a netlogon connection, with no authentication
	*/

	/* Find the original binding string */
	status = dcerpc_parse_binding(tmp_ctx, p->conn->binding_string, &b);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to parse dcerpc binding '%s'\n", p->conn->binding_string));
		return status;
	}

	/* Make binding string for netlogon, not the other pipe */
	status = dcerpc_epm_map_binding(tmp_ctx, b, 
									&dcerpc_table_netlogon,
					p->conn->event_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to map DCERPC/TCP NCACN_NP pipe for '%s' - %s\n", 
			 DCERPC_NETLOGON_UUID, nt_errstr(status)));
		return status;
	}

	status = dcerpc_secondary_connection(p, &p2, b);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = dcerpc_bind_auth_none(p2, &dcerpc_table_netlogon);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(p2);
                return status;
        }

	/*
	  step 2 - request a netlogon challenge
	*/
	r.in.server_name = talloc_asprintf(tmp_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computer_name = cli_credentials_get_workstation(credentials);
	r.in.credentials = &credentials1;
	r.out.credentials = &credentials2;

	generate_random_buffer(credentials1.data, sizeof(credentials1.data));

	status = dcerpc_netr_ServerReqChallenge(p2, tmp_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	  step 3 - authenticate on the netlogon pipe
	*/
	mach_pwd = cli_credentials_get_nt_hash(credentials, tmp_ctx);

	creds_client_init(creds, &credentials1, &credentials2, 
			  mach_pwd, &credentials3,
			  negotiate_flags);

	a.in.server_name = r.in.server_name;
	a.in.account_name = cli_credentials_get_username(credentials);
	a.in.secure_channel_type = 
		cli_credentials_get_secure_channel_type(credentials);
	a.in.computer_name = cli_credentials_get_workstation(credentials);
	a.in.negotiate_flags = &negotiate_flags;
	a.out.negotiate_flags = &negotiate_flags;
	a.in.credentials = &credentials3;
	a.out.credentials = &credentials3;

	status = dcerpc_netr_ServerAuthenticate2(p2, tmp_ctx, &a);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!creds_client_check(creds, a.out.credentials)) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	cli_credentials_set_netlogon_creds(credentials, creds);

	/*
	  the schannel session key is now in creds.session_key

	  we no longer need the netlogon pipe open
	*/
	talloc_free(p2);

	return NT_STATUS_OK;
}

NTSTATUS dcerpc_bind_auth_schannel(TALLOC_CTX *tmp_ctx, 
				   struct dcerpc_pipe *p,
				   const struct dcerpc_interface_table *table,
				   struct cli_credentials *credentials)
{
	NTSTATUS status;

	/* Fills in NETLOGON credentials */
	status = dcerpc_schannel_key(tmp_ctx, 
				     p, credentials);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to setup credentials for account %s: %s\n",
			  cli_credentials_get_username(credentials), 
			  nt_errstr(status)));
		return status;
	}

	return dcerpc_bind_auth(p, table, credentials, DCERPC_AUTH_TYPE_SCHANNEL,
				NULL);
}

