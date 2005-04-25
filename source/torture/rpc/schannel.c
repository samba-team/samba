/* 
   Unix SMB/CIFS implementation.

   test suite for schannel operations

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
#include "librpc/gen_ndr/ndr_samr.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "lib/cmdline/popt_common.h"

#define TEST_MACHINE_NAME "schanneltest"

/*
  do some samr ops using the schannel connection
 */
static BOOL test_samr_ops(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct samr_GetDomPwInfo r;
	int i;
	struct samr_String name;

	name.string = lp_workgroup();
	r.in.domain_name = &name;

	printf("Testing GetDomPwInfo with name %s\n", r.in.domain_name->string);
	
	/* do several ops to test credential chaining */
	for (i=0;i<5;i++) {
		status = dcerpc_samr_GetDomPwInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("GetDomPwInfo op %d failed - %s\n", i, nt_errstr(status));
			return False;
		}
	}

	return True;
}


/*
  try a netlogon SamLogon
*/
static BOOL test_netlogon_ops(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				  struct creds_CredentialState *creds)
{
	NTSTATUS status;
	struct netr_LogonSamLogon r;
	struct netr_Authenticator auth, auth2;
	struct netr_NetworkInfo ninfo;
	const char *username = cli_credentials_get_username(cmdline_credentials);
	const char *password = cli_credentials_get_password(cmdline_credentials);
	int i;
	BOOL ret = True;

	ninfo.identity_info.domain_name.string = lp_workgroup();
	ninfo.identity_info.parameter_control = 0;
	ninfo.identity_info.logon_id_low = 0;
	ninfo.identity_info.logon_id_high = 0;
	ninfo.identity_info.account_name.string = username;
	ninfo.identity_info.workstation.string = TEST_MACHINE_NAME;
	generate_random_buffer(ninfo.challenge, 
			       sizeof(ninfo.challenge));
	ninfo.nt.length = 24;
	ninfo.nt.data = talloc_size(mem_ctx, 24);
	SMBNTencrypt(password, ninfo.challenge, ninfo.nt.data);
	ninfo.lm.length = 24;
	ninfo.lm.data = talloc_size(mem_ctx, 24);
	SMBencrypt(password, ninfo.challenge, ninfo.lm.data);


	r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.workstation = TEST_MACHINE_NAME;
	r.in.credential = &auth;
	r.in.return_authenticator = &auth2;
	r.in.logon_level = 2;
	r.in.logon.network = &ninfo;

	printf("Testing LogonSamLogon with name %s\n", username);
	
	for (i=2;i<3;i++) {
		ZERO_STRUCT(auth2);
		creds_client_authenticator(creds, &auth);
		
		r.in.validation_level = i;
		
		status = dcerpc_netr_LogonSamLogon(p, mem_ctx, &r);
		
		if (!creds_client_check(creds, &r.out.return_authenticator->cred)) {
			printf("Credential chaining failed\n");
			ret = False;
		}
		
	}
	return ret;
}

/*
  test a schannel connection with the given flags
 */
static BOOL test_schannel(TALLOC_CTX *mem_ctx, 
			  uint16_t acct_flags, uint32_t dcerpc_flags,
			  uint32_t schannel_type)
{
	void *join_ctx;
	const char *machine_password;
	NTSTATUS status;
	const char *binding = lp_parm_string(-1, "torture", "binding");
	struct dcerpc_binding *b;
	struct dcerpc_pipe *p = NULL;
	struct dcerpc_pipe *p_netlogon = NULL;
	struct creds_CredentialState *creds;
	struct cli_credentials *credentials;

	TALLOC_CTX *test_ctx = talloc_named(mem_ctx, 0, "test_schannel context");
	char *test_machine_account = talloc_asprintf(NULL, "%s$", TEST_MACHINE_NAME);

	join_ctx = torture_create_testuser(test_machine_account, lp_workgroup(), 
					   acct_flags, &machine_password);
	if (!join_ctx) {
		printf("Failed to join domain with acct_flags=0x%x\n", acct_flags);
		talloc_free(test_ctx);
		return False;
	}

	status = dcerpc_parse_binding(test_ctx, binding, &b);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Bad binding string %s\n", binding);
		goto failed;
	}

	b->flags &= ~DCERPC_AUTH_OPTIONS;
	b->flags |= dcerpc_flags;

	credentials = cli_credentials_init(mem_ctx);
	cli_credentials_set_conf(credentials);

	cli_credentials_set_domain(credentials, lp_workgroup(), CRED_SPECIFIED);
	cli_credentials_set_workstation(credentials, TEST_MACHINE_NAME, CRED_SPECIFIED);
	cli_credentials_set_username(credentials, test_machine_account, CRED_SPECIFIED);
	cli_credentials_set_password(credentials, machine_password, CRED_SPECIFIED);

	status = dcerpc_pipe_connect_b(test_ctx, 
				       &p, b, 
				       DCERPC_SAMR_UUID,
				       DCERPC_SAMR_VERSION,
				       credentials);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to connect with schannel: %s\n", nt_errstr(status));
		goto failed;
	}

	if (!test_samr_ops(p, test_ctx)) {
		printf("Failed to process schannel secured ops\n");
		goto failed;
	}

	status = dcerpc_schannel_creds(p->conn->security_state.generic_state, test_ctx, &creds);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	/* Also test that when we connect to the netlogon pipe, that
	 * the credentials we setup on the first pipe are valid for
	 * the second */

	/* Swap the binding details from SAMR to NETLOGON */
	status = dcerpc_epm_map_binding(test_ctx, b, DCERPC_NETLOGON_UUID,
					DCERPC_NETLOGON_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	status = dcerpc_secondary_connection(p, &p_netlogon, 
					     b);

	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	status = dcerpc_bind_auth_password(p_netlogon, 
					   DCERPC_NETLOGON_UUID,
					   DCERPC_NETLOGON_VERSION, 
					   credentials, DCERPC_AUTH_TYPE_SCHANNEL,
					   NULL);

	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	status = dcerpc_schannel_creds(p_netlogon->conn->security_state.generic_state, test_ctx, &creds);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	/* do a couple of logins */
	if (!test_netlogon_ops(p_netlogon, test_ctx, creds)) {
		printf("Failed to process schannel secured ops\n");
		goto failed;
	}

	torture_leave_domain(join_ctx);
	talloc_free(test_ctx);
	return True;

failed:
	torture_leave_domain(join_ctx);
	talloc_free(test_ctx);
	return False;	
}

/*
  a schannel test suite
 */
BOOL torture_rpc_schannel(void)
{
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	struct {
		uint16_t acct_flags;
		uint32_t dcerpc_flags;
		uint32_t schannel_type;
	} tests[] = {
		{ ACB_WSTRUST,   DCERPC_SCHANNEL_WORKSTATION | DCERPC_SIGN,                       3 },
		{ ACB_WSTRUST,   DCERPC_SCHANNEL_WORKSTATION | DCERPC_SEAL,                       3 },
		{ ACB_WSTRUST,   DCERPC_SCHANNEL_WORKSTATION | DCERPC_SIGN | DCERPC_SCHANNEL_128, 3 },
		{ ACB_WSTRUST,   DCERPC_SCHANNEL_WORKSTATION | DCERPC_SEAL | DCERPC_SCHANNEL_128, 3 },
		{ ACB_SVRTRUST,  DCERPC_SCHANNEL_BDC | DCERPC_SIGN,                               3 },
		{ ACB_SVRTRUST,  DCERPC_SCHANNEL_BDC | DCERPC_SEAL,                               3 },
		{ ACB_SVRTRUST,  DCERPC_SCHANNEL_BDC | DCERPC_SIGN | DCERPC_SCHANNEL_128,         3 },
		{ ACB_SVRTRUST,  DCERPC_SCHANNEL_BDC | DCERPC_SEAL | DCERPC_SCHANNEL_128,         3 }
	};
	int i;

	mem_ctx = talloc_init("torture_rpc_schannel");

	for (i=0;i<ARRAY_SIZE(tests);i++) {
		if (!test_schannel(mem_ctx, 
				   tests[i].acct_flags, tests[i].dcerpc_flags, tests[i].schannel_type)) {
			printf("Failed with acct_flags=0x%x dcerpc_flags=0x%x schannel_type=%d\n",
			       tests[i].acct_flags, tests[i].dcerpc_flags, tests[i].schannel_type);
			ret = False;
			break;
		}
	}

	talloc_free(mem_ctx);

	return ret;
}
