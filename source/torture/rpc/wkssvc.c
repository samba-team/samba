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
	struct wks_QueryInfo r;
	uint16 levels[] = {100, 101, 102};
	int i;

	r.in.server_name = dcerpc_server_name(p);

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		r.in.level = levels[i];
		printf("testing QueryInfo level %u\n", r.in.level);
		status = dcerpc_wks_QueryInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("QueryInfo level %u failed - %s\n", r.in.level, nt_errstr(status));
			return False;
		}
	}

	return True;
}

BOOL torture_rpc_wkssvc(int dummy)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_wkssvc");

	status = torture_rpc_connection(&p, "wkssvc");
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	p->flags |= DCERPC_DEBUG_PRINT_BOTH;
	
	if (!test_QueryInfo(p, mem_ctx)) {
		ret = False;
	}

        torture_rpc_close(p);

	return ret;
}
