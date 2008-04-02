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
#include "param/param.h"
#include "librpc/rpc/dcerpc_proto.h"
#include "auth/gensec/gensec.h"

#define TEST_MACHINE_NAME "schannel"

/*
  try a netlogon SamLogon
*/
bool test_netlogon_ex_ops(struct dcerpc_pipe *p, struct torture_context *tctx, 
			  struct cli_credentials *credentials, 
			  struct creds_CredentialState *creds)
{
	NTSTATUS status;
	struct netr_LogonSamLogonEx r;
	struct netr_NetworkInfo ninfo;
	DATA_BLOB names_blob, chal, lm_resp, nt_resp;
	int i;
	int flags = CLI_CRED_NTLM_AUTH;
	if (lp_client_lanman_auth(tctx->lp_ctx)) {
		flags |= CLI_CRED_LANMAN_AUTH;
	}

	if (lp_client_ntlmv2_auth(tctx->lp_ctx)) {
		flags |= CLI_CRED_NTLMv2_AUTH;
	}

	cli_credentials_get_ntlm_username_domain(cmdline_credentials, tctx, 
						 &ninfo.identity_info.account_name.string,
						 &ninfo.identity_info.domain_name.string);
	
	generate_random_buffer(ninfo.challenge, 
			       sizeof(ninfo.challenge));
	chal = data_blob_const(ninfo.challenge, 
			       sizeof(ninfo.challenge));

	names_blob = NTLMv2_generate_names_blob(tctx, lp_iconv_convenience(tctx->lp_ctx), cli_credentials_get_workstation(credentials), 
						cli_credentials_get_domain(credentials));

	status = cli_credentials_get_ntlm_response(cmdline_credentials, tctx, 
						   &flags, 
						   chal,
						   names_blob,
						   &lm_resp, &nt_resp,
						   NULL, NULL);
	torture_assert_ntstatus_ok(tctx, status, 
				   "cli_credentials_get_ntlm_response failed");

	ninfo.lm.data = lm_resp.data;
	ninfo.lm.length = lm_resp.length;

	ninfo.nt.data = nt_resp.data;
	ninfo.nt.length = nt_resp.length;

	ninfo.identity_info.parameter_control = 0;
	ninfo.identity_info.logon_id_low = 0;
	ninfo.identity_info.logon_id_high = 0;
	ninfo.identity_info.workstation.string = cli_credentials_get_workstation(credentials);

	r.in.server_name = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computer_name = cli_credentials_get_workstation(credentials);
	r.in.logon_level = 2;
	r.in.logon.network = &ninfo;
	r.in.flags = 0;

	torture_comment(tctx, 
			"Testing LogonSamLogonEx with name %s\n", 
			ninfo.identity_info.account_name.string);
	
	for (i=2;i<3;i++) {
		r.in.validation_level = i;
		
		status = dcerpc_netr_LogonSamLogonEx(p, tctx, &r);
		torture_assert_ntstatus_ok(tctx, status, "LogonSamLogon failed");
	}

	return true;
}

/*
  do some samr ops using the schannel connection
 */
static bool test_samr_ops(struct torture_context *tctx,
			  struct dcerpc_pipe *p)
{
	NTSTATUS status;
	struct samr_GetDomPwInfo r;
	struct samr_Connect connect;
	struct samr_OpenDomain opendom;
	int i;
	struct lsa_String name;
	struct policy_handle handle;
	struct policy_handle domain_handle;

	name.string = lp_workgroup(tctx->lp_ctx);
	r.in.domain_name = &name;

	connect.in.system_name = 0;
	connect.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	connect.out.connect_handle = &handle;
	
	printf("Testing Connect and OpenDomain on BUILTIN\n");

	status = dcerpc_samr_Connect(p, tctx, &connect);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
			printf("Connect failed (expected, schannel mapped to anonymous): %s\n",
			       nt_errstr(status));
		} else {
			printf("Connect failed - %s\n", nt_errstr(status));
			return false;
		}
	} else {
		opendom.in.connect_handle = &handle;
		opendom.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		opendom.in.sid = dom_sid_parse_talloc(tctx, "S-1-5-32");
		opendom.out.domain_handle = &domain_handle;
		
		status = dcerpc_samr_OpenDomain(p, tctx, &opendom);
		if (!NT_STATUS_IS_OK(status)) {
			printf("OpenDomain failed - %s\n", nt_errstr(status));
			return false;
		}
	}

	printf("Testing GetDomPwInfo with name %s\n", r.in.domain_name->string);
	
	/* do several ops to test credential chaining */
	for (i=0;i<5;i++) {
		status = dcerpc_samr_GetDomPwInfo(p, tctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			if (!NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
				printf("GetDomPwInfo op %d failed - %s\n", i, nt_errstr(status));
				return false;
			}
		}
	}

	return true;
}


/*
  do some lsa ops using the schannel connection
 */
static bool test_lsa_ops(struct torture_context *tctx, struct dcerpc_pipe *p)
{
	struct lsa_GetUserName r;
	NTSTATUS status;
	bool ret = true;
	struct lsa_StringPointer authority_name_p;

	printf("\nTesting GetUserName\n");

	r.in.system_name = "\\";	
	r.in.account_name = NULL;	
	r.in.authority_name = &authority_name_p;
	authority_name_p.string = NULL;

	/* do several ops to test credential chaining and various operations */
	status = dcerpc_lsa_GetUserName(p, tctx, &r);
	
	if (NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROTSEQ_NOT_SUPPORTED)) {
		printf("not considering %s to be an error\n", nt_errstr(status));
	} else if (!NT_STATUS_IS_OK(status)) {
		printf("GetUserName failed - %s\n", nt_errstr(status));
		return false;
	} else {
		if (!r.out.account_name) {
			return false;
		}
		
		if (strcmp(r.out.account_name->string, "ANONYMOUS LOGON") != 0) {
			printf("GetUserName returned wrong user: %s, expected %s\n",
			       r.out.account_name->string, "ANONYMOUS LOGON");
			return false;
		}
		if (!r.out.authority_name || !r.out.authority_name->string) {
			return false;
		}
		
		if (strcmp(r.out.authority_name->string->string, "NT AUTHORITY") != 0) {
			printf("GetUserName returned wrong user: %s, expected %s\n",
			       r.out.authority_name->string->string, "NT AUTHORITY");
			return false;
		}
	}
	if (!test_many_LookupSids(p, tctx, NULL)) {
		printf("LsaLookupSids3 failed!\n");
		return false;
	}

	return ret;
}


/*
  test a schannel connection with the given flags
 */
static bool test_schannel(struct torture_context *tctx,
			  uint16_t acct_flags, uint32_t dcerpc_flags,
			  int i)
{
	struct test_join *join_ctx;
	NTSTATUS status;
	const char *binding = torture_setting_string(tctx, "binding", NULL);
	struct dcerpc_binding *b;
	struct dcerpc_pipe *p = NULL;
	struct dcerpc_pipe *p_netlogon = NULL;
	struct dcerpc_pipe *p_netlogon2 = NULL;
	struct dcerpc_pipe *p_netlogon3 = NULL;
	struct dcerpc_pipe *p_samr2 = NULL;
	struct dcerpc_pipe *p_lsa = NULL;
	struct creds_CredentialState *creds;
	struct cli_credentials *credentials;

	join_ctx = torture_join_domain(tctx, 
				       talloc_asprintf(tctx, "%s%d", TEST_MACHINE_NAME, i), 
				       acct_flags, &credentials);
	torture_assert(tctx, join_ctx != NULL, "Failed to join domain");

	status = dcerpc_parse_binding(tctx, binding, &b);
	torture_assert_ntstatus_ok(tctx, status, "Bad binding string");

	b->flags &= ~DCERPC_AUTH_OPTIONS;
	b->flags |= dcerpc_flags;

	status = dcerpc_pipe_connect_b(tctx, &p, b, &ndr_table_samr,
				       credentials, NULL, tctx->lp_ctx);
	torture_assert_ntstatus_ok(tctx, status, 
		"Failed to connect with schannel");

	torture_assert(tctx, test_samr_ops(tctx, p), 
		       "Failed to process schannel secured SAMR ops");

	/* Also test that when we connect to the netlogon pipe, that
	 * the credentials we setup on the first pipe are valid for
	 * the second */

	/* Swap the binding details from SAMR to NETLOGON */
	status = dcerpc_epm_map_binding(tctx, b, &ndr_table_netlogon, NULL, tctx->lp_ctx);
	torture_assert_ntstatus_ok(tctx, status, "epm map");

	status = dcerpc_secondary_connection(p, &p_netlogon, 
					     b);
	torture_assert_ntstatus_ok(tctx, status, "seconday connection");

	status = dcerpc_bind_auth(p_netlogon, &ndr_table_netlogon, 
				  credentials, tctx->lp_ctx,
				  DCERPC_AUTH_TYPE_SCHANNEL,
				  dcerpc_auth_level(p->conn),
				  NULL);

	torture_assert_ntstatus_ok(tctx, status, "bind auth");

	status = dcerpc_schannel_creds(p_netlogon->conn->security_state.generic_state, tctx, &creds);
	torture_assert_ntstatus_ok(tctx, status, "schannel creds");

	/* do a couple of logins */
	torture_assert(tctx, test_netlogon_ops(p_netlogon, tctx, credentials, creds),
		"Failed to process schannel secured NETLOGON ops");

	torture_assert(tctx, test_netlogon_ex_ops(p_netlogon, tctx, credentials, creds),
		"Failed to process schannel secured NETLOGON EX ops");

	/* Swap the binding details from SAMR to LSARPC */
	status = dcerpc_epm_map_binding(tctx, b, &ndr_table_lsarpc, NULL, tctx->lp_ctx);
	torture_assert_ntstatus_ok(tctx, status, "epm map");

	status = dcerpc_secondary_connection(p, &p_lsa, 
					     b);

	torture_assert_ntstatus_ok(tctx, status, "seconday connection");

	status = dcerpc_bind_auth(p_lsa, &ndr_table_lsarpc,
				  credentials, tctx->lp_ctx,
				  DCERPC_AUTH_TYPE_SCHANNEL,
				  dcerpc_auth_level(p->conn),
				  NULL);

	torture_assert_ntstatus_ok(tctx, status, "bind auth");

	torture_assert(tctx, test_lsa_ops(tctx, p_lsa), 
		"Failed to process schannel secured LSA ops");

	/* Drop the socket, we want to start from scratch */
	talloc_free(p);
	p = NULL;

	/* Now see what we are still allowed to do */
	
	status = dcerpc_parse_binding(tctx, binding, &b);
	torture_assert_ntstatus_ok(tctx, status, "Bad binding string");

	b->flags &= ~DCERPC_AUTH_OPTIONS;
	b->flags |= dcerpc_flags;

	status = dcerpc_pipe_connect_b(tctx, &p_samr2, b, &ndr_table_samr,
				       credentials, NULL, tctx->lp_ctx);
	torture_assert_ntstatus_ok(tctx, status, 
		"Failed to connect with schannel");

	/* do a some SAMR operations.  We have *not* done a new serverauthenticate */
	torture_assert (tctx, test_samr_ops(tctx, p_samr2), 
			"Failed to process schannel secured SAMR ops (on fresh connection)");

	/* Swap the binding details from SAMR to NETLOGON */
	status = dcerpc_epm_map_binding(tctx, b, &ndr_table_netlogon, NULL, tctx->lp_ctx);
	torture_assert_ntstatus_ok(tctx, status, "epm");

	status = dcerpc_secondary_connection(p_samr2, &p_netlogon2, 
					     b);
	torture_assert_ntstatus_ok(tctx, status, "seconday connection");

	/* and now setup an SCHANNEL bind on netlogon */
	status = dcerpc_bind_auth(p_netlogon2, &ndr_table_netlogon,
				  credentials, tctx->lp_ctx,
				  DCERPC_AUTH_TYPE_SCHANNEL,
				  dcerpc_auth_level(p_samr2->conn),
				  NULL);

	torture_assert_ntstatus_ok(tctx, status, "auth failed");
	
	/* Try the schannel-only SamLogonEx operation */
	torture_assert(tctx, test_netlogon_ex_ops(p_netlogon2, tctx, credentials, creds), 
		       "Failed to process schannel secured NETLOGON EX ops (on fresh connection)");
		

	/* And the more traditional style, proving that the
	 * credentials chaining state is fully present */
	torture_assert(tctx, test_netlogon_ops(p_netlogon2, tctx, credentials, creds),
			     "Failed to process schannel secured NETLOGON ops (on fresh connection)");

	/* Drop the socket, we want to start from scratch (again) */
	talloc_free(p_samr2);

	/* We don't want schannel for this test */
	b->flags &= ~DCERPC_AUTH_OPTIONS;

	status = dcerpc_pipe_connect_b(tctx, &p_netlogon3, b, &ndr_table_netlogon,
				       credentials, NULL, tctx->lp_ctx);
	torture_assert_ntstatus_ok(tctx, status, "Failed to connect without schannel");

	torture_assert(tctx, !test_netlogon_ex_ops(p_netlogon3, tctx, credentials, creds),
			"Processed NOT schannel secured NETLOGON EX ops without SCHANNEL (unsafe)");

	/* Required because the previous call will mark the current context as having failed */
	tctx->last_result = TORTURE_OK;
	tctx->last_reason = NULL;

	torture_assert(tctx, test_netlogon_ops(p_netlogon3, tctx, credentials, creds),
			"Failed to processed NOT schannel secured NETLOGON ops without new ServerAuth");

	torture_leave_domain(join_ctx);
	return true;
}



/*
  a schannel test suite
 */
bool torture_rpc_schannel(struct torture_context *torture)
{
	bool ret = true;
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

	for (i=0;i<ARRAY_SIZE(tests);i++) {
		if (!test_schannel(torture, 
				   tests[i].acct_flags, tests[i].dcerpc_flags,
				   i)) {
			torture_comment(torture, "Failed with acct_flags=0x%x dcerpc_flags=0x%x \n",
			       tests[i].acct_flags, tests[i].dcerpc_flags);
			ret = false;
		}
	}

	return ret;
}

/*
  test two schannel connections
 */
bool torture_rpc_schannel2(struct torture_context *torture)
{
	struct test_join *join_ctx;
	NTSTATUS status;
	const char *binding = torture_setting_string(torture, "binding", NULL);
	struct dcerpc_binding *b;
	struct dcerpc_pipe *p1 = NULL, *p2 = NULL;
	struct cli_credentials *credentials1, *credentials2;
	uint32_t dcerpc_flags = DCERPC_SCHANNEL | DCERPC_SIGN;

	join_ctx = torture_join_domain(torture, talloc_asprintf(torture, "%s2", TEST_MACHINE_NAME), 
				       ACB_WSTRUST, &credentials1);
	torture_assert(torture, join_ctx != NULL, 
		       "Failed to join domain with acct_flags=ACB_WSTRUST");

	credentials2 = (struct cli_credentials *)talloc_memdup(torture, credentials1, sizeof(*credentials1));
	credentials1->netlogon_creds = NULL;
	credentials2->netlogon_creds = NULL;

	status = dcerpc_parse_binding(torture, binding, &b);
	torture_assert_ntstatus_ok(torture, status, "Bad binding string");

	b->flags &= ~DCERPC_AUTH_OPTIONS;
	b->flags |= dcerpc_flags;

	printf("Opening first connection\n");
	status = dcerpc_pipe_connect_b(torture, &p1, b, &ndr_table_netlogon,
				       credentials1, NULL, torture->lp_ctx);
	torture_assert_ntstatus_ok(torture, status, "Failed to connect with schannel");

	torture_comment(torture, "Opening second connection\n");
	status = dcerpc_pipe_connect_b(torture, &p2, b, &ndr_table_netlogon,
				       credentials2, NULL, torture->lp_ctx);
	torture_assert_ntstatus_ok(torture, status, "Failed to connect with schannel");

	credentials1->netlogon_creds = NULL;
	credentials2->netlogon_creds = NULL;

	torture_comment(torture, "Testing logon on pipe1\n");
	if (!test_netlogon_ex_ops(p1, torture, credentials1, NULL))
		return false;

	torture_comment(torture, "Testing logon on pipe2\n");
	if (!test_netlogon_ex_ops(p2, torture, credentials2, NULL))
		return false;

	torture_comment(torture, "Again on pipe1\n");
	if (!test_netlogon_ex_ops(p1, torture, credentials1, NULL))
		return false;

	torture_comment(torture, "Again on pipe2\n");
	if (!test_netlogon_ex_ops(p2, torture, credentials2, NULL))
		return false;

	torture_leave_domain(join_ctx);
	return true;
}

