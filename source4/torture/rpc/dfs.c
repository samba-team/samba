/* 
   Unix SMB/CIFS implementation.
   test suite for lsa dfs operations

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


static BOOL test_Exist(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct dfs_Exist r;
	uint32 exist = 0;

	r.out.exist_flag = &exist;

	status = dcerpc_dfs_Exist(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Exist failed - %s\n", nt_errstr(status));
		return False;
	}

	printf("exist=%d\n", exist);

	return True;
}

static BOOL test_Enum(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct dfs_Enum r;
	uint32 total=0;
	struct dfs_EnumStruct e;
	uint32 i = 0;
	struct dfs_String s;
	struct dfs_Enum1 e1;

	e.level = 1;
	e.e.enum1 = &e1;
	e.e.enum1->count = 0;
	e.e.enum1->s = &s;
	s.str = NULL;

	r.in.level = 1;
	r.in.bufsize = (uint32)-1;
	r.in.total = &total;
	r.in.unknown = NULL;
	r.in.info = &e;
	
	status = dcerpc_dfs_Enum(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Enum failed - %s\n", nt_errstr(status));
		return False;
	}

	NDR_PRINT_DEBUG(dfs_EnumStruct, r.out.info);

	printf("total=%d\n", r.out.total?*r.out.total:-1);

	return True;
}

BOOL torture_rpc_dfs(int dummy)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_dfs");

	status = torture_rpc_connection(&p, "netdfs");
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}
	
	if (!test_Exist(p, mem_ctx)) {
		ret = False;
	}

	if (!test_Enum(p, mem_ctx)) {
		ret = False;
	}

        torture_rpc_close(p);

	return ret;
}
