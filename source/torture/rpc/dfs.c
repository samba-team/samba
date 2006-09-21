/* 
   Unix SMB/CIFS implementation.
   test suite for rpc dfs operations

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
#include "torture/torture.h"
#include "torture/rpc/rpc.h"
#include "librpc/gen_ndr/ndr_dfs_c.h"

static BOOL test_GetManagerVersion(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, enum dfs_ManagerVersion *version)
{
	NTSTATUS status;
	struct dfs_GetManagerVersion r;

	r.out.version = version;

	status = dcerpc_dfs_GetManagerVersion(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("GetManagerVersion failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_GetInfoLevel(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, uint16_t level,
			      const char *root)
{
	NTSTATUS status;
	struct dfs_GetInfo r;

	printf("Testing GetInfo level %u on '%s'\n", level, root);

	r.in.path = talloc_strdup(mem_ctx, root);
	r.in.server = NULL;
	r.in.share = NULL;
	r.in.level = level;

	status = dcerpc_dfs_GetInfo(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Info failed - %s\n", nt_errstr(status));
		return False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("GetInfo failed - %s\n", win_errstr(r.out.result));
		return False;
	}

	return True;
}

static BOOL test_GetInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, const char *root)
{
	BOOL ret = True;
	/* 103, 104, 105, 106 is only available on Set */
	uint16_t levels[] = {1, 2, 3, 4, 5, 6, 7, 100, 101, 102, 103, 104, 105, 106, 200, 300};
	int i;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		if (!test_GetInfoLevel(p, mem_ctx, levels[i], root)) {
			ret = False;
		}
	}
	return ret;
}

static BOOL test_EnumLevelEx(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, uint16_t level, const char *dfs_name)
{
	NTSTATUS status;
	struct dfs_EnumEx rex;
	uint32_t total=0;
	struct dfs_EnumStruct e;
	struct dfs_Info1 s;
	struct dfs_EnumArray1 e1;
	BOOL ret = True;
	
	rex.in.level = level;
	rex.in.bufsize = (uint32_t)-1;
	rex.in.total = &total;
	rex.in.info = &e;
	rex.in.dfs_name = dfs_name;

	e.level = rex.in.level;
	e.e.info1 = &e1;
	e.e.info1->count = 0;
	e.e.info1->s = &s;
	s.path = NULL;

	printf("Testing EnumEx level %u on '%s'\n", level, dfs_name);

	status = dcerpc_dfs_EnumEx(p, mem_ctx, &rex);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumEx failed - %s\n", nt_errstr(status));
		return False;
	}

	if (level == 1 && rex.out.total) {
		int i;
		for (i=0;i<*rex.out.total;i++) {
			const char *root = talloc_strdup(mem_ctx, rex.out.info->e.info1->s[i].path);
			if (!test_GetInfo(p, mem_ctx, root)) {
				ret = False;
			}
		}
	}

	if (level == 300 && rex.out.total) {
		int i,k;
		for (i=0;i<*rex.out.total;i++) {
			uint16_t levels[] = {1, 2, 3, 4, 200}; /* 300 */
			const char *root = talloc_strdup(mem_ctx, rex.out.info->e.info300->s[i].dom_root);
			for (k=0;k<ARRAY_SIZE(levels);k++) {
				if (!test_EnumLevelEx(p, mem_ctx, levels[k], root)) {
					ret = False;
				}
			}
			if (!test_GetInfo(p, mem_ctx, root)) {
				ret = False;
			}
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
	r.in.info = &e;

	e.level = r.in.level;
	e.e.info1 = &e1;
	e.e.info1->count = 0;
	e.e.info1->s = &s;
	s.path = NULL;
	
	printf("Testing Enum level %u\n", level);

	status = dcerpc_dfs_Enum(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Enum failed - %s\n", nt_errstr(status));
		return False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("dfs_Enum failed - %s\n", win_errstr(r.out.result));
		return False;
	}

	if (level == 1 && r.out.total) {
		int i;
		for (i=0;i<*r.out.total;i++) {
			const char *root = r.out.info->e.info1->s[i].path;
			if (!test_GetInfo(p, mem_ctx, root)) {
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

static BOOL test_EnumEx(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, const char *host)
{
	BOOL ret = True;
	uint16_t levels[] = {1, 2, 3, 4, 200, 300};
	int i;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		if (!test_EnumLevelEx(p, mem_ctx, levels[i], host)) {
			ret = False;
		}
	}

	return ret;
}


BOOL torture_rpc_dfs(struct torture_context *torture)
{
	NTSTATUS status;
	struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	enum dfs_ManagerVersion version;
	const char *host = lp_parm_string(-1, "torture", "host");

	mem_ctx = talloc_init("torture_rpc_dfs");

	status = torture_rpc_connection(mem_ctx, 
					&p, 
					&dcerpc_table_netdfs);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	ret &= test_GetManagerVersion(p, mem_ctx, &version);
	ret &= test_Enum(p, mem_ctx);
	ret &= test_EnumEx(p, mem_ctx, host);

	talloc_free(mem_ctx);

	return ret;
}
