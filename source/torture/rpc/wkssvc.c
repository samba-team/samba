/* 
   Unix SMB/CIFS implementation.
   test suite for wkssvc rpc operations

   Copyright (C) Andrew Tridgell 2003
   
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


static BOOL test_NetWkstaGetInfo(struct dcerpc_pipe *p, 
			   TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct wkssvc_NetWkstaGetInfo r;
	uint16_t levels[] = {100, 101, 102, 502};
	int i;
	BOOL ret = True;

	r.in.server_name = dcerpc_server_name(p);

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		r.in.level = levels[i];
		printf("testing NetWkstaGetInfo level %u\n", r.in.level);
		status = dcerpc_wkssvc_NetWkstaGetInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("NetWkstaGetInfo level %u failed - %s\n", r.in.level, nt_errstr(status));
			ret = False;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("NetWkstaGetInfo level %u failed - %s\n", r.in.level, win_errstr(r.out.result));
		}
	}

	return ret;
}


static BOOL test_NetWkstaTransportEnum(struct dcerpc_pipe *p, 
			       TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct wkssvc_NetWkstaTransportEnum r;
	BOOL ret = True;
	uint32_t resume_handle = 0;
	struct wkssvc_NetWkstaTransportCtr0 ctr0;

	ZERO_STRUCT(ctr0);

	r.in.server_name = dcerpc_server_name(p);
	r.in.level = 0;
	r.in.ctr.ctr0 = &ctr0;
	r.in.max_buffer = (uint32_t)-1;
	r.in.resume_handle = &resume_handle;
	r.out.resume_handle = &resume_handle;

	printf("testing NetWkstaTransportEnum\n");
	status = dcerpc_wkssvc_NetWkstaTransportEnum(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("NetWkstaTransportEnum failed - %s\n", nt_errstr(status));
		ret = False;
	}
	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("NetWkstaTransportEnum level %u failed - %s\n", r.in.level, win_errstr(r.out.result));
	}

	return ret;
}



BOOL torture_rpc_wkssvc(int dummy)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_wkssvc");

	status = torture_rpc_connection(&p, 
					DCERPC_WKSSVC_NAME,
					DCERPC_WKSSVC_UUID,
					DCERPC_WKSSVC_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	if (!test_NetWkstaGetInfo(p, mem_ctx)) {
		ret = False;
	}

	if (!test_NetWkstaTransportEnum(p, mem_ctx)) {
		ret = False;
	}

	talloc_destroy(mem_ctx);

        torture_rpc_close(p);

	return ret;
}
