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

static BOOL test_Bind(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
		      struct policy_handle *handle)
{
	NTSTATUS status;
	struct drsuapi_Bind r;
	BOOL ret = True;

	ZERO_STRUCT(r);
	r.out.handle = handle;

	status = dcerpc_drsuapi_Bind(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("drsuapi_Bind level failed - %s\n", errstr);
		ret = False;
	}

	return ret;
}

static BOOL test_Unbind(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			struct policy_handle *handle)
{
	NTSTATUS status;
	struct drsuapi_Unbind r;
	BOOL ret = True;

	r.in.handle = handle;

	status = dcerpc_drsuapi_Unbind(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("drsuapi_Unbind level failed - %s\n", errstr);
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
	struct policy_handle handle;

	status = torture_rpc_connection(&p, 
					DCERPC_DRSUAPI_NAME,
					DCERPC_DRSUAPI_UUID,
					DCERPC_DRSUAPI_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	printf("Connected to DRAUAPI pipe\n");

	event_loop_once(p->transport.event_context(p));

	mem_ctx = talloc_init("torture_rpc_drsuapi");

	if (!test_Bind(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_Unbind(p, mem_ctx, &handle)) {
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
