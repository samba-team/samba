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

#define TEST_MACHINE_NAME "schanneltest"

/*
  do some samr ops using the schannel connection
 */
static BOOL test_samr_ops(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct samr_GetDomPwInfo r;
	int i;
	struct samr_Name name;

	name.name = lp_workgroup();
	r.in.name = &name;

	printf("Testing GetDomPwInfo with name %s\n", r.in.name->name);
	
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
	const char *username = lp_parm_string(-1, "torture", "username");
	const char *password = lp_parm_string(-1, "torture", "password");

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
	ninfo.nt.data = talloc(mem_ctx, 24);
	SMBNTencrypt(password, ninfo.challenge, ninfo.nt.data);
	ninfo.lm.length = 24;
	ninfo.lm.data = talloc(mem_ctx, 24);
	SMBencrypt(password, ninfo.challenge, ninfo.lm.data);


	r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.workstation = TEST_MACHINE_NAME;
	r.in.credential = &auth;
	r.in.return_authenticator = &auth2;
	r.in.logon_level = 2;
	r.in.logon.network = &ninfo;

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
			  uint16 acct_flags, uint32 dcerpc_flags,
			  uint32 schannel_type)
{
	void *join_ctx;
	const char *machine_password;
	NTSTATUS status;
	const char *binding = lp_parm_string(-1, "torture", "binding");
	struct dcerpc_binding b;
	struct dcerpc_pipe *p;
	struct dcerpc_pipe *p_netlogon;
	struct creds_CredentialState *creds;

	join_ctx = torture_join_domain(TEST_MACHINE_NAME, lp_workgroup(), acct_flags,
				       &machine_password);
	if (!join_ctx) {
		printf("Failed to join domain with acct_flags=0x%x\n", acct_flags);
		return False;
	}

	status = dcerpc_parse_binding(mem_ctx, binding, &b);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Bad binding string %s\n", binding);
		goto failed;
	}

	b.flags &= ~DCERPC_AUTH_OPTIONS;
	b.flags |= dcerpc_flags;

	status = dcerpc_pipe_connect_b(&p, &b, 
				       DCERPC_SAMR_UUID,
				       DCERPC_SAMR_VERSION,
				       lp_workgroup(), 
				       TEST_MACHINE_NAME,
				       machine_password);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to connect with schannel\n");
		goto failed;
	}

	if (!test_samr_ops(p, mem_ctx)) {
		printf("Failed to process schannel secured ops\n");
		goto failed;
	}


	status = dcerpc_parse_binding(mem_ctx, binding, &b);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Bad binding string %s\n", binding);
		goto failed;
	}


	/* Also test that when we connect to the netlogon pipe, that
	 * the credentials we setup on the first pipe are valid for
	 * the second */

	b.flags &= ~DCERPC_AUTH_OPTIONS;
	b.flags |= dcerpc_flags;

	status = dcerpc_pipe_connect_b(&p_netlogon, &b, 
				       DCERPC_NETLOGON_UUID,
				       DCERPC_NETLOGON_VERSION,
				       lp_workgroup(), 
				       TEST_MACHINE_NAME,
				       machine_password);

	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	status = dcerpc_schannel_creds(p_netlogon->security_state.generic_state, mem_ctx, &creds);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	/* do a couple of logins */
	if (!test_netlogon_ops(p_netlogon, mem_ctx, creds)) {
		printf("Failed to process schannel secured ops\n");
		goto failed;
	}

	torture_leave_domain(join_ctx);
	dcerpc_pipe_close(p_netlogon);
	dcerpc_pipe_close(p);
	return True;

failed:
	torture_leave_domain(join_ctx);
	dcerpc_pipe_close(p_netlogon);
	dcerpc_pipe_close(p);
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
		uint16 acct_flags;
		uint32 dcerpc_flags;
		uint32 schannel_type;
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
