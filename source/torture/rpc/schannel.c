/* 
   Unix SMB/CIFS implementation.

   test suite for schannel operations

   Copyright (C) Andrew Tridgell 2004
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "librpc/gen_ndr/ndr_netlogon_c.h"
#include "librpc/gen_ndr/ndr_lsa_c.h"
#include "librpc/gen_ndr/ndr_samr_c.h"
#include "auth/credentials/credentials.h"
#include "torture/rpc/rpc.h"
#include "lib/cmdline/popt_common.h"
#include "auth/gensec/schannel_proto.h"
#include "libcli/auth/libcli_auth.h"
#include "libcli/security/security.h"
#include "system/filesys.h"

#define TEST_MACHINE_NAME "schannel"

/*
  try a netlogon SamLogon
*/
BOOL test_netlogon_ex_ops(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			  struct cli_credentials *credentials, 
			  struct creds_CredentialState *creds)
{
	NTSTATUS status;
	struct netr_LogonSamLogonEx r;
	struct netr_NetworkInfo ninfo;
	DATA_BLOB names_blob, chal, lm_resp, nt_resp;
	int i;
	BOOL ret = True;
	int flags = CLI_CRED_NTLM_AUTH;
	if (lp_client_lanman_auth()) {
		flags |= CLI_CRED_LANMAN_AUTH;
	}

	if (lp_client_ntlmv2_auth()) {
		flags |= CLI_CRED_NTLMv2_AUTH;
	}

	cli_credentials_get_ntlm_username_domain(cmdline_credentials, mem_ctx, 
						 &ninfo.identity_info.account_name.string,
						 &ninfo.identity_info.domain_name.string);
	
	generate_random_buffer(ninfo.challenge, 
			       sizeof(ninfo.challenge));
	chal = data_blob_const(ninfo.challenge, 
			       sizeof(ninfo.challenge));

	names_blob = NTLMv2_generate_names_blob(mem_ctx, cli_credentials_get_workstation(credentials), 
						cli_credentials_get_domain(credentials));

	status = cli_credentials_get_ntlm_response(cmdline_credentials, mem_ctx, 
						   &flags, 
						   chal,
						   names_blob,
						   &lm_resp, &nt_resp,
						   NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_credentials_get_ntlm_response failed: %s\n", 
		       nt_errstr(status));
		return False;
	}

	ninfo.lm.data = lm_resp.data;
	ninfo.lm.length = lm_resp.length;

	ninfo.nt.data = nt_resp.data;
	ninfo.nt.length = nt_resp.length;

	ninfo.identity_info.parameter_control = 0;
	ninfo.identity_info.logon_id_low = 0;
	ninfo.identity_info.logon_id_high = 0;
	ninfo.identity_info.workstation.string = cli_credentials_get_workstation(credentials);

	r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computer_name = cli_credentials_get_workstation(credentials);
	r.in.logon_level = 2;
	r.in.logon.network = &ninfo;
	r.in.flags = 0;

	printf("Testing LogonSamLogonEx with name %s\n", ninfo.identity_info.account_name.string);
	
	for (i=2;i<3;i++) {
		r.in.validation_level = i;
		
		status = dcerpc_netr_LogonSamLogonEx(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("LogonSamLogon failed: %s\n", 
			       nt_errstr(status));
			return False;
		}
	}

	return ret;
}

/*
  do some samr ops using the schannel connection
 */
static BOOL test_samr_ops(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct samr_GetDomPwInfo r;
	struct samr_Connect connect;
	struct samr_OpenDomain opendom;
	int i;
	struct lsa_String name;
	struct policy_handle handle;
	struct policy_handle domain_handle;

	name.string = lp_workgroup();
	r.in.domain_name = &name;

	connect.in.system_name = 0;
	connect.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	connect.out.connect_handle = &handle;
	
	printf("Testing Connect and OpenDomain on BUILTIN\n");

	status = dcerpc_samr_Connect(p, mem_ctx, &connect);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
			printf("Connect failed (expected, schannel mapped to anonymous): %s\n",
			       nt_errstr(status));
		} else {
			printf("Connect failed - %s\n", nt_errstr(status));
			return False;
		}
	} else {
		opendom.in.connect_handle = &handle;
		opendom.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		opendom.in.sid = dom_sid_parse_talloc(mem_ctx, "S-1-5-32");
		opendom.out.domain_handle = &domain_handle;
		
		status = dcerpc_samr_OpenDomain(p, mem_ctx, &opendom);
		if (!NT_STATUS_IS_OK(status)) {
			printf("OpenDomain failed - %s\n", nt_errstr(status));
			return False;
		}
	}

	printf("Testing GetDomPwInfo with name %s\n", r.in.domain_name->string);
	
	/* do several ops to test credential chaining */
	for (i=0;i<5;i++) {
		status = dcerpc_samr_GetDomPwInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			if (!NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
				printf("GetDomPwInfo op %d failed - %s\n", i, nt_errstr(status));
				return False;
			}
		}
	}

	return True;
}


/*
  do some lsa ops using the schannel connection
 */
static BOOL test_lsa_ops(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	struct lsa_GetUserName r;
	NTSTATUS status;
	BOOL ret = True;
	struct lsa_StringPointer authority_name_p;

	printf("\nTesting GetUserName\n");

	r.in.system_name = "\\";	
	r.in.account_name = NULL;	
	r.in.authority_name = &authority_name_p;
	authority_name_p.string = NULL;

	/* do several ops to test credential chaining and various operations */
	status = dcerpc_lsa_GetUserName(p, mem_ctx, &r);
	
	if (NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROTSEQ_NOT_SUPPORTED)) {
		printf("not considering %s to be an error\n", nt_errstr(status));
	} else if (!NT_STATUS_IS_OK(status)) {
		printf("GetUserName failed - %s\n", nt_errstr(status));
		return False;
	} else {
		if (!r.out.account_name) {
			return False;
		}
		
		if (strcmp(r.out.account_name->string, "ANONYMOUS LOGON") != 0) {
			printf("GetUserName returned wrong user: %s, expected %s\n",
			       r.out.account_name->string, "ANONYMOUS LOGON");
			return False;
		}
		if (!r.out.authority_name || !r.out.authority_name->string) {
			return False;
		}
		
		if (strcmp(r.out.authority_name->string->string, "NT AUTHORITY") != 0) {
			printf("GetUserName returned wrong user: %s, expected %s\n",
			       r.out.authority_name->string->string, "NT AUTHORITY");
			return False;
		}
	}
	if (!test_many_LookupSids(p, mem_ctx, NULL)) {
		printf("LsaLookupSids3 failed!\n");
		return False;
	}

	return ret;
}


/*
  test a schannel connection with the given flags
 */
static BOOL test_schannel(TALLOC_CTX *mem_ctx, 
			  uint16_t acct_flags, uint32_t dcerpc_flags,
			  int i)
{
	BOOL ret = True;

	struct test_join *join_ctx;
	NTSTATUS status;
	const char *binding = lp_parm_string(-1, "torture", "binding");
	struct dcerpc_binding *b;
	struct dcerpc_pipe *p = NULL;
	struct dcerpc_pipe *p_netlogon = NULL;
	struct dcerpc_pipe *p_netlogon2 = NULL;
	struct dcerpc_pipe *p_netlogon3 = NULL;
	struct dcerpc_pipe *p_samr2 = NULL;
	struct dcerpc_pipe *p_lsa = NULL;
	struct creds_CredentialState *creds;
	struct cli_credentials *credentials;

	TALLOC_CTX *test_ctx = talloc_named(mem_ctx, 0, "test_schannel context");

	join_ctx = torture_join_domain(talloc_asprintf(mem_ctx, "%s%d", TEST_MACHINE_NAME, i), 
				       acct_flags, &credentials);
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

	status = dcerpc_pipe_connect_b(test_ctx, &p, b, &ndr_table_samr,
				       credentials, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to connect with schannel: %s\n", nt_errstr(status));
		goto failed;
	}

	if (!test_samr_ops(p, test_ctx)) {
		printf("Failed to process schannel secured SAMR ops\n");
		ret = False;
	}

	/* Also test that when we connect to the netlogon pipe, that
	 * the credentials we setup on the first pipe are valid for
	 * the second */

	/* Swap the binding details from SAMR to NETLOGON */
	status = dcerpc_epm_map_binding(test_ctx, b, &ndr_table_netlogon, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	status = dcerpc_secondary_connection(p, &p_netlogon, 
					     b);

	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	status = dcerpc_bind_auth(p_netlogon, &ndr_table_netlogon,
				  credentials, DCERPC_AUTH_TYPE_SCHANNEL,
				  dcerpc_auth_level(p->conn),
				  NULL);

	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	status = dcerpc_schannel_creds(p_netlogon->conn->security_state.generic_state, test_ctx, &creds);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	/* do a couple of logins */
	if (!test_netlogon_ops(p_netlogon, test_ctx, credentials, creds)) {
		printf("Failed to process schannel secured NETLOGON ops\n");
		ret = False;
	}

	if (!test_netlogon_ex_ops(p_netlogon, test_ctx, credentials, creds)) {
		printf("Failed to process schannel secured NETLOGON EX ops\n");
		ret = False;
	}

	/* Swap the binding details from SAMR to LSARPC */
	status = dcerpc_epm_map_binding(test_ctx, b, &ndr_table_lsarpc, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	status = dcerpc_secondary_connection(p, &p_lsa, 
					     b);

	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	status = dcerpc_bind_auth(p_lsa, &ndr_table_lsarpc,
				  credentials, DCERPC_AUTH_TYPE_SCHANNEL,
				  dcerpc_auth_level(p->conn),
				  NULL);

	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	if (!test_lsa_ops(p_lsa, test_ctx)) {
		printf("Failed to process schannel secured LSA ops\n");
		ret = False;
	}

	/* Drop the socket, we want to start from scratch */
	talloc_free(p);
	p = NULL;

	/* Now see what we are still allowed to do */
	
	status = dcerpc_parse_binding(test_ctx, binding, &b);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Bad binding string %s\n", binding);
		goto failed;
	}

	b->flags &= ~DCERPC_AUTH_OPTIONS;
	b->flags |= dcerpc_flags;

	status = dcerpc_pipe_connect_b(test_ctx, &p_samr2, b, &ndr_table_samr,
				       credentials, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to connect with schannel: %s\n", nt_errstr(status));
		goto failed;
	}

	/* do a some SAMR operations.  We have *not* done a new serverauthenticate */
	if (!test_samr_ops(p_samr2, test_ctx)) {
		printf("Failed to process schannel secured SAMR ops (on fresh connection)\n");
		goto failed;
	}

	/* Swap the binding details from SAMR to NETLOGON */
	status = dcerpc_epm_map_binding(test_ctx, b, &ndr_table_netlogon, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	status = dcerpc_secondary_connection(p_samr2, &p_netlogon2, 
					     b);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	/* and now setup an SCHANNEL bind on netlogon */
	status = dcerpc_bind_auth(p_netlogon2, &ndr_table_netlogon,
				  credentials, DCERPC_AUTH_TYPE_SCHANNEL,
				  dcerpc_auth_level(p_samr2->conn),
				  NULL);

	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}
	
	/* Try the schannel-only SamLogonEx operation */
	if (!test_netlogon_ex_ops(p_netlogon2, test_ctx, credentials, creds)) {
		printf("Failed to process schannel secured NETLOGON EX ops (on fresh connection)\n");
		ret = False;
	}

	/* And the more traditional style, proving that the
	 * credentials chaining state is fully present */
	if (!test_netlogon_ops(p_netlogon2, test_ctx, credentials, creds)) {
		printf("Failed to process schannel secured NETLOGON ops (on fresh connection)\n");
		ret = False;
	}

	/* Drop the socket, we want to start from scratch (again) */
	talloc_free(p_samr2);

	/* We don't want schannel for this test */
	b->flags &= ~DCERPC_AUTH_OPTIONS;

	status = dcerpc_pipe_connect_b(test_ctx, &p_netlogon3, b, &ndr_table_netlogon,
				       credentials, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to connect without schannel: %s\n", nt_errstr(status));
		goto failed;
	}

	if (test_netlogon_ex_ops(p_netlogon3, test_ctx, credentials, creds)) {
		printf("Processed NOT schannel secured NETLOGON EX ops without SCHANNEL (unsafe)\n");
		ret = False;
	}

	if (!test_netlogon_ops(p_netlogon3, test_ctx, credentials, creds)) {
		printf("Failed to processed NOT schannel secured NETLOGON ops without new ServerAuth\n");
		ret = False;
	}

	torture_leave_domain(join_ctx);
	talloc_free(test_ctx);
	return ret;

failed:
	torture_leave_domain(join_ctx);
	talloc_free(test_ctx);
	return False;	
}



/*
  a schannel test suite
 */
BOOL torture_rpc_schannel(struct torture_context *torture)
{
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	struct {
		uint16_t acct_flags;
		uint32_t dcerpc_flags;
	} tests[] = {
		{ ACB_WSTRUST,   DCERPC_SCHANNEL | DCERPC_SIGN},
		{ ACB_WSTRUST,   DCERPC_SCHANNEL | DCERPC_SEAL},
		{ ACB_WSTRUST,   DCERPC_SCHANNEL | DCERPC_SIGN | DCERPC_SCHANNEL_128},
		{ ACB_WSTRUST,   DCERPC_SCHANNEL | DCERPC_SEAL | DCERPC_SCHANNEL_128 },
		{ ACB_SVRTRUST,  DCERPC_SCHANNEL | DCERPC_SIGN },
		{ ACB_SVRTRUST,  DCERPC_SCHANNEL | DCERPC_SEAL },
		{ ACB_SVRTRUST,  DCERPC_SCHANNEL | DCERPC_SIGN | DCERPC_SCHANNEL_128 },
		{ ACB_SVRTRUST,  DCERPC_SCHANNEL | DCERPC_SEAL | DCERPC_SCHANNEL_128 }
	};
	int i;

	mem_ctx = talloc_init("torture_rpc_schannel");

	for (i=0;i<ARRAY_SIZE(tests);i++) {
		if (!test_schannel(mem_ctx, 
				   tests[i].acct_flags, tests[i].dcerpc_flags,
				   i)) {
			printf("Failed with acct_flags=0x%x dcerpc_flags=0x%x \n",
			       tests[i].acct_flags, tests[i].dcerpc_flags);
			ret = False;
			break;
		}
	}

	talloc_free(mem_ctx);

	return ret;
}

/*
  test two schannel connections
 */
BOOL torture_rpc_schannel2(struct torture_context *torture)
{
	BOOL ret = True;
	TALLOC_CTX *mem_ctx = talloc_new(torture);
	struct test_join *join_ctx;
	NTSTATUS status;
	const char *binding = lp_parm_string(-1, "torture", "binding");
	struct dcerpc_binding *b;
	struct dcerpc_pipe *p1 = NULL, *p2 = NULL;
	struct cli_credentials *credentials1, *credentials2;
	uint16_t acct_flags = ACB_WSTRUST;
	uint32_t dcerpc_flags = DCERPC_SCHANNEL | DCERPC_SIGN;
	TALLOC_CTX *test_ctx = talloc_named(mem_ctx, 0, "test_schannel2 context");

	join_ctx = torture_join_domain(talloc_asprintf(mem_ctx, "%s2", TEST_MACHINE_NAME), 
				       acct_flags, &credentials1);
	if (!join_ctx) {
		printf("Failed to join domain with acct_flags=0x%x\n", acct_flags);
		talloc_free(test_ctx);
		return False;
	}

	credentials2 = talloc_memdup(mem_ctx, credentials1, sizeof(*credentials1));
	credentials1->netlogon_creds = NULL;
	credentials2->netlogon_creds = NULL;

	status = dcerpc_parse_binding(test_ctx, binding, &b);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Bad binding string %s\n", binding);
		goto failed;
	}

	b->flags &= ~DCERPC_AUTH_OPTIONS;
	b->flags |= dcerpc_flags;

	printf("Opening first connection\n");
	status = dcerpc_pipe_connect_b(test_ctx, &p1, b, &ndr_table_netlogon,
				       credentials1, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to connect with schannel: %s\n", nt_errstr(status));
		goto failed;
	}

	printf("Opening second connection\n");
	status = dcerpc_pipe_connect_b(test_ctx, &p2, b, &ndr_table_netlogon,
				       credentials2, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to connect with schannel: %s\n", nt_errstr(status));
		goto failed;
	}

	credentials1->netlogon_creds = NULL;
	credentials2->netlogon_creds = NULL;

	printf("Testing logon on pipe1\n");
	if (!test_netlogon_ex_ops(p1, test_ctx, credentials1, NULL)) {
		printf("Failed to process schannel secured NETLOGON ops\n");
		ret = False;
	}

	printf("Testing logon on pipe2\n");
	if (!test_netlogon_ex_ops(p2, test_ctx, credentials2, NULL)) {
		printf("Failed to process schannel secured NETLOGON ops\n");
		ret = False;
	}

	printf("Again on pipe1\n");
	if (!test_netlogon_ex_ops(p1, test_ctx, credentials1, NULL)) {
		printf("Failed to process schannel secured NETLOGON ops\n");
		ret = False;
	}

	printf("Again on pipe2\n");
	if (!test_netlogon_ex_ops(p2, test_ctx, credentials2, NULL)) {
		printf("Failed to process schannel secured NETLOGON ops\n");
		ret = False;
	}

	torture_leave_domain(join_ctx);
	talloc_free(test_ctx);
	return ret;

failed:
	torture_leave_domain(join_ctx);
	talloc_free(test_ctx);
	return False;	
}

