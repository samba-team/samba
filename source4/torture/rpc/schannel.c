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
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "torture/rpc/proto.h"

#define TEST_MACHINE_NAME "schannel"

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

	status = dcerpc_pipe_connect_b(test_ctx, &p, b, &dcerpc_table_samr,
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
	status = dcerpc_epm_map_binding(test_ctx, b, &dcerpc_table_netlogon, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	status = dcerpc_secondary_connection(p, &p_netlogon, 
					     b);

	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	status = dcerpc_bind_auth(p_netlogon, &dcerpc_table_netlogon,
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

	/* Swap the binding details from SAMR to LSARPC */
	status = dcerpc_epm_map_binding(test_ctx, b, &dcerpc_table_lsarpc, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	status = dcerpc_secondary_connection(p, &p_lsa, 
					     b);

	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	status = dcerpc_bind_auth(p_lsa, &dcerpc_table_lsarpc,
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
BOOL torture_rpc_schannel(void)
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
