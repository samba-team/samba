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


static BOOL test_GetManagerVersion(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct dfs_GetManagerVersion r;
	uint32_t exist = 0;

	r.out.exist_flag = &exist;

	status = dcerpc_dfs_GetManagerVersion(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("GetManagerVersion failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_InfoLevel(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, uint16_t level,
			   const char *root)
{
	NTSTATUS status;
	struct dfs_GetInfo r;
	
	r.in.path = root;
	r.in.server = NULL;
	r.in.share = NULL;
	r.in.level = level;

	printf("Testing GetInfo level %u on '%s'\n", level, root);

	status = dcerpc_dfs_GetInfo(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Info failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_Info(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, const char *root)
{
	BOOL ret = True;
	uint16_t levels[] = {1, 2, 3, 4, 100, 101, 102, 200, 300};
	int i;
	for (i=0;i<ARRAY_SIZE(levels);i++) {
		if (!test_InfoLevel(p, mem_ctx, levels[i], root)) {
			ret = False;
		}
	}
	return ret;
}

static BOOL test_EnumLevel(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, uint16_t level)
{
	NTSTATUS status;
	struct dfs_Enum r;
	uint32_t total=0;
	struct dfs_EnumStruct e;
	struct dfs_Info1 s;
	struct dfs_EnumArray1 e1;
	BOOL ret = True;
	
	r.in.level = level;
	r.in.bufsize = (uint32_t)-1;
	r.in.total = &total;
	r.in.unknown = &total;
	r.in.info = &e;

	e.level = r.in.level;
	e.e.info1 = &e1;
	e.e.info1->count = 0;
	e.e.info1->s = &s;
	s.path = NULL;
	
	status = dcerpc_dfs_Enum(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Enum failed - %s\n", nt_errstr(status));
		return False;
	}

	if (level == 1 && r.out.total) {
		int i;
		for (i=0;i<*r.out.total;i++) {
			const char *root = r.out.info->e.info1->s[i].path;
			if (!test_Info(p, mem_ctx, root)) {
				ret = False;
			}
		}
		
	}

	return ret;
}


static BOOL test_Enum(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	BOOL ret = True;
	uint16_t levels[] = {1, 2, 3, 4, 200, 300};
	int i;
	for (i=0;i<ARRAY_SIZE(levels);i++) {
		if (!test_EnumLevel(p, mem_ctx, levels[i])) {
			ret = False;
		}
	}
	return ret;
}


static BOOL test_Add(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct dfs_Add add;
	struct dfs_Remove rem;
	
	add.in.path = "\\\\win2003\\2nd root\\test";
	add.in.server = "win2003";
	add.in.share = "e$";
	add.in.comment = "a test comment";
	add.in.flags = 1;

	status = dcerpc_dfs_Add(p, mem_ctx, &add);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Add failed - %s\n", nt_errstr(status));
		return False;
	}

	rem.in.path = add.in.path;
	rem.in.server = add.in.server;
	rem.in.share = add.in.share;
	
	status = dcerpc_dfs_Remove(p, mem_ctx, &rem);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Add failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}


BOOL torture_rpc_dfs(int dummy)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_dfs");

	status = torture_rpc_connection(&p, 
					DCERPC_NETDFS_NAME,
					DCERPC_NETDFS_UUID,
					DCERPC_NETDFS_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	if (!test_GetManagerVersion(p, mem_ctx)) {
		ret = False;
	}

#if 0
	if (!test_Add(p, mem_ctx)) {
		ret = False;
	}
#endif

	if (!test_Enum(p, mem_ctx)) {
		ret = False;
	}

	talloc_destroy(mem_ctx);

        torture_rpc_close(p);

	return ret;
}
