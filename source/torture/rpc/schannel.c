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

	torture_leave_domain(join_ctx);
	return True;

failed:
	torture_leave_domain(join_ctx);
	return False;	
}

/*
  a schannel test suite
 */
BOOL torture_rpc_schannel(int dummy)
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

	return ret;
}
