/* 
   Unix SMB/CIFS implementation.

   DRSUapi tests

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Stefan (metze) Metzmacher 2004
   
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

#define TEST_MACHINE_NAME "torturetest"

static BOOL test_DsBind(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
		      struct policy_handle *bind_handle)
{
	NTSTATUS status;
	struct drsuapi_DsBind r;
	BOOL ret = True;

	ZERO_STRUCT(r);
	r.out.bind_handle = bind_handle;

	status = dcerpc_drsuapi_DsBind(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("drsuapi_DsBind failed - %s\n", errstr);
		ret = False;
	}

	return ret;
}

static BOOL test_DsCrackNames(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
		      struct policy_handle *bind_handle)
{
	NTSTATUS status;
	struct drsuapi_DsCrackNames r;
	struct drsuapi_DsCrackNamesInInfo1Names names[1];
	BOOL ret = True;

	ZERO_STRUCT(r);
	r.in.bind_handle = bind_handle;
	r.in.level = 1;
	r.in.in.info1.unknown1 = 0x000004e4;
	r.in.in.info1.unknown2 = 0x00000407;
	r.in.in.info1.unknown3 = 0x00000000;
	r.in.in.info1.unknown4 = 0x00000007;
	r.in.in.info1.unknown5 = 0x00000002;
	r.in.in.info1.count = 1;
	r.in.in.info1.names = names;
	
	names[0].str = talloc_asprintf(mem_ctx, "%s/", lp_realm());

	status = dcerpc_drsuapi_DsCrackNames(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("drsuapi_DsCrackNames failed - %s\n", errstr);
		ret = False;
	}

	return ret;
}

static BOOL test_DsUnbind(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			struct policy_handle *bind_handle)
{
	NTSTATUS status;
	struct drsuapi_DsUnbind r;
	BOOL ret = True;

	r.in.bind_handle = bind_handle;
	r.out.bind_handle = bind_handle;

	status = dcerpc_drsuapi_DsUnbind(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("drsuapi_DsUnbind failed - %s\n", errstr);
		ret = False;
	}

	return ret;
}

BOOL torture_rpc_drsuapi(int dummy)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	struct policy_handle bind_handle;

	status = torture_rpc_connection(&p, 
					DCERPC_DRSUAPI_NAME,
					DCERPC_DRSUAPI_UUID,
					DCERPC_DRSUAPI_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	printf("Connected to DRAUAPI pipe\n");

	mem_ctx = talloc_init("torture_rpc_drsuapi");

	if (!test_DsBind(p, mem_ctx, &bind_handle)) {
		ret = False;
	}

	if (!test_DsCrackNames(p, mem_ctx, &bind_handle)) {
		ret = False;
	}

	if (!test_DsUnbind(p, mem_ctx, &bind_handle)) {
		ret = False;
	}

#if 0
	if (!test_scan(p, mem_ctx)) {
		ret = False;
	}
#endif
	talloc_destroy(mem_ctx);

        torture_rpc_close(p);

	return ret;
}
