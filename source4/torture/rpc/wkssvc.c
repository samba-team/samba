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


static BOOL test_QueryInfo(struct dcerpc_pipe *p, 
			   TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct wkssvc_QueryInfo r;
	uint16 levels[] = {100, 101, 102, 502};
	int i;
	BOOL ret = True;

	r.in.server_name = dcerpc_server_name(p);

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		r.in.level = levels[i];
		printf("testing QueryInfo level %u\n", r.in.level);
		status = dcerpc_wkssvc_QueryInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("QueryInfo level %u failed - %s\n", r.in.level, nt_errstr(status));
			ret = False;
		}
	}

	return ret;
}


static BOOL test_TransportEnum(struct dcerpc_pipe *p, 
			       TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct wkssvc_TransportEnum r;
	BOOL ret = True;
	struct wkssvc_TransportInfo info;
	uint32 resume_handle = 0;
	struct wkssvc_TransportInfoArray info_array;

	ZERO_STRUCT(info);
	ZERO_STRUCT(info_array);

	info.u.array = &info_array;

	r.in.server_name = dcerpc_server_name(p);
	r.in.info = &info;
	r.out.info = &info;
	r.in.max_buffer = (uint32)-1;
	r.in.resume_handle = &resume_handle;
	r.out.resume_handle = &resume_handle;

	printf("testing TransportEnum\n");
	status = dcerpc_wkssvc_TransportEnum(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("TransportEnum failed - %s\n", nt_errstr(status));
		ret = False;
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

	p->flags |= DCERPC_DEBUG_PRINT_BOTH;
	
	if (!test_QueryInfo(p, mem_ctx)) {
		ret = False;
	}

	if (!test_TransportEnum(p, mem_ctx)) {
		ret = False;
	}

        torture_rpc_close(p);

	return ret;
}
