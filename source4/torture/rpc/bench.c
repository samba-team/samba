/* 
   Unix SMB/CIFS implementation.

   simple RPC benchmark

   Copyright (C) Andrew Tridgell 2005
   
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
#include "librpc/gen_ndr/ndr_srvsvc_c.h"
#include "torture/rpc/rpc.h"

/**************************/
/* srvsvc_NetShare        */
/**************************/
static BOOL test_NetShareEnumAll(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct srvsvc_NetShareEnumAll r;
	struct srvsvc_NetShareCtr0 c0;
	uint32_t levels[] = {0, 1, 2, 501, 502};
	int i;
	BOOL ret = True;
	uint32_t resume_handle;

	ZERO_STRUCT(c0);

	r.in.server_unc = talloc_asprintf(mem_ctx,"\\\\%s",dcerpc_server_name(p));
	r.in.ctr.ctr0 = &c0;
	r.in.max_buffer = (uint32_t)-1;
	r.in.resume_handle = &resume_handle;
	r.out.resume_handle = &resume_handle;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		ZERO_STRUCT(r.out);
		resume_handle = 0;
		r.in.level = levels[i];
		status = dcerpc_srvsvc_NetShareEnumAll(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("NetShareEnumAll level %u failed - %s\n", r.in.level, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("NetShareEnumAll level %u failed - %s\n", r.in.level, win_errstr(r.out.result));
			continue;
		}
	}

	return ret;
}

/*
  benchmark srvsvc netshareenumall queries
*/
static BOOL bench_NetShareEnumAll(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	struct timeval tv = timeval_current();
	BOOL ret = True;
	int timelimit = lp_parm_int(-1, "torture", "timelimit", 10);
	int count=0;

	printf("Running for %d seconds\n", timelimit);
	while (timeval_elapsed(&tv) < timelimit) {
		TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
		if (!test_NetShareEnumAll(p, tmp_ctx)) break;
		talloc_free(tmp_ctx);
		count++;
		if (count % 50 == 0) {
			if (lp_parm_bool(-1, "torture", "progress", true)) {
				printf("%.1f queries per second  \r", 
				       count / timeval_elapsed(&tv));
			}
		}
	}

	printf("%.1f queries per second  \n", count / timeval_elapsed(&tv));

	return ret;
}


BOOL torture_bench_rpc(struct torture_context *torture)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_srvsvc");

	status = torture_rpc_connection(mem_ctx, 
					&p,
					&dcerpc_table_srvsvc);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return False;
	}

	if (!bench_NetShareEnumAll(p, mem_ctx)) {
		ret = False;
	}

	talloc_free(mem_ctx);

	return ret;
}
