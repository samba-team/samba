/* 
   Unix SMB/CIFS implementation.
   test suite for srvsvc rpc operations

   Copyright (C) Stefan (metze) Metzmacher 2003
   
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


static BOOL test_NetConnEnum(struct dcerpc_pipe *p, 
			   TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct srvsvc_NetConnEnum r;
	struct srvsvc_NetConnCtr0 c0;
	uint32 levels[] = {0, 1};
	int i;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx,"\\\\%s",dcerpc_server_name(p));
	r.in.path = talloc_asprintf(mem_ctx,"%s","ADMIN$");
	r.in.ctr.subctr.ctr0 = &c0;
	r.in.ctr.subctr.ctr0->count = 0;
	r.in.ctr.subctr.ctr0->array = NULL;
	r.in.preferred_len = (uint32)-1;
	r.in.resume_handle = NULL;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		r.in.ctr.level = levels[i];
		r.in.ctr.level2 = levels[i];
		printf("testing NetConnEnum level %u\n", r.in.ctr.level);
		status = dcerpc_srvsvc_NetConnEnum(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("NetConnEnum level %u failed - %s\n", r.in.ctr.level, nt_errstr(status));
			ret = False;
		}
	}

	return True;
}

static BOOL test_NetFileEnum(struct dcerpc_pipe *p, 
			   TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct srvsvc_NetFileEnum r;
	struct srvsvc_NetFileCtr3 c3;
	uint32 levels[] = {2, 3};
	int i;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx,"\\\\%s",dcerpc_server_name(p));
	r.in.path = NULL;
	r.in.user = NULL;
	r.in.ctr.subctr.ctr3 = &c3;
	r.in.ctr.subctr.ctr3->count = 0;
	r.in.ctr.subctr.ctr3->array = NULL;
	r.in.preferred_len = (uint32)4096;
	r.in.resume_handle = NULL;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		r.in.ctr.level = levels[i];
		r.in.ctr.level2 = levels[i];
		printf("testing NetFileEnum level %u\n", r.in.ctr.level);
		status = dcerpc_srvsvc_NetFileEnum(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("NetFileEnum level %u failed - %s\n", r.in.ctr.level, nt_errstr(status));
			ret = False;
		}
	}

	return True;
}

static BOOL test_NetSessEnum(struct dcerpc_pipe *p, 
			   TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct srvsvc_NetSessEnum r;
	struct srvsvc_NetSessCtr0 c0;
	uint32 levels[] = {0, 1, 2, 10, 502};
	int i;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx,"\\\\%s",dcerpc_server_name(p));
	r.in.client = NULL;
	r.in.user = NULL;
	r.in.ctr.subctr.ctr0 = &c0;
	r.in.ctr.subctr.ctr0->count = 0;
	r.in.ctr.subctr.ctr0->array = NULL;
	r.in.preferred_len = (uint32)-1;
	r.in.resume_handle = NULL;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		r.in.ctr.level = levels[i];
		r.in.ctr.level2 = levels[i];
		printf("testing NetSessEnum level %u\n", r.in.ctr.level);
		status = dcerpc_srvsvc_NetSessEnum(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("NetSessEnum level %u failed - %s\n", r.in.ctr.level, nt_errstr(status));
			ret = False;
		}
	}

	return True;
}

static BOOL test_NetShareEnumAll(struct dcerpc_pipe *p, 
			   TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct srvsvc_NetShareEnumAll r;
	struct srvsvc_NetShareCtr0 c0;
	uint32 levels[] = {0, 1, 2, 501, 502};
	int i;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx,"\\\\%s",dcerpc_server_name(p));
	r.in.ctr.subctr.ctr0 = &c0;
	r.in.ctr.subctr.ctr0->count = 0;
	r.in.ctr.subctr.ctr0->array = NULL;
	r.in.preferred_len = (uint32)-1;
	r.in.resume_handle = NULL;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		r.in.ctr.level = levels[i];
		r.in.ctr.level2 = levels[i];
		printf("testing NetShareEnumAll level %u\n", r.in.ctr.level);
		status = dcerpc_srvsvc_NetShareEnumAll(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("NetShareEnumAll level %u failed - %s\n", r.in.ctr.level, nt_errstr(status));
			ret = False;
		}
	}

	return True;
}

#if 0
static BOOL test_NetDiskEnum(struct dcerpc_pipe *p, 
			   TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct srvsvc_NetDiskEnum r;
	struct srvsvc_NetDiskCtr0 c0;
	uint32 levels[] = {0, 1, 2, 3};
	int i;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx,"\\\\%s",dcerpc_server_name(p));
	r.in.preferred_len = (uint32)-1;
	r.in.resume_handle = NULL;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		r.in.level = levels[i];
		ZERO_STRUCT(r.out);
		printf("testing NetDiskEnum level %u\n", r.in.level);
		status = dcerpc_srvsvc_NetDiskEnum(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			NDR_PRINT_OUT_DEBUG(srvsvc_NetDiskEnum, &r);
			printf("NetDiskEnum level %u failed - %s\n", r.in.level, nt_errstr(status));
			ret = False;
		}
	}

	return True;
}

static BOOL test_NetTransportEnum(struct dcerpc_pipe *p, 
			   TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct srvsvc_NetTransportEnum r;
	struct srvsvc_NetTransportCtr0 c0;
	uint32 levels[] = {0, 1};
	int i;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx,"\\\\%s",dcerpc_server_name(p));
	r.in.ctr.subctr.ctr0 = &c0;
	r.in.ctr.subctr.ctr0->count = 0;
	r.in.ctr.subctr.ctr0->array = NULL;
	r.in.preferred_len = (uint32)-1;
	r.in.resume_handle = NULL;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		r.in.ctr.level = levels[i];
		r.in.ctr.level2 = levels[i];
		printf("testing NetTransportEnum level %u\n", r.in.ctr.level);
		status = dcerpc_srvsvc_NetTransportEnum(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("NetTransportEnum level %u failed - %s\n", r.in.ctr.level, nt_errstr(status));
			ret = False;
		}
	}

	return True;
}
#endif
static BOOL test_NetShareEnum(struct dcerpc_pipe *p, 
			   TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct srvsvc_NetShareEnum r;
	struct srvsvc_NetShareCtr0 c0;
	uint32 levels[] = {0, 1, 2, 502};
	int i;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx,"\\\\%s",dcerpc_server_name(p));
	r.in.ctr.subctr.ctr0 = &c0;
	r.in.ctr.subctr.ctr0->count = 0;
	r.in.ctr.subctr.ctr0->array = NULL;
	r.in.preferred_len = (uint32)-1;
	r.in.resume_handle = NULL;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		r.in.ctr.level = levels[i];
		r.in.ctr.level2 = levels[i];
		printf("testing NetShareEnum level %u\n", r.in.ctr.level);
		status = dcerpc_srvsvc_NetShareEnum(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("NetShareEnum level %u failed - %s\n", r.in.ctr.level, nt_errstr(status));
			ret = False;
		}
	}

	return True;
}

BOOL torture_rpc_srvsvc(int dummy)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_srvsvc");

	status = torture_rpc_connection(&p,
					DCERPC_SRVSVC_NAME,
					DCERPC_SRVSVC_UUID,
					DCERPC_SRVSVC_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	p->flags |= DCERPC_DEBUG_PRINT_BOTH;

	if (!test_NetConnEnum(p, mem_ctx)) {
		ret = False;
	}

	if (!test_NetFileEnum(p, mem_ctx)) {
		ret = False;
	}

	if (!test_NetSessEnum(p, mem_ctx)) {
		ret = False;
	}

	if (!test_NetShareEnumAll(p, mem_ctx)) {
		ret = False;
	}
#if 0
	if (!test_NetDiskEnum(p, mem_ctx)) {
		ret = False;
	}

	if (!test_NetTransportEnum(p, mem_ctx)) {
		ret = False;
	}
#endif
	if (!test_NetShareEnum(p, mem_ctx)) {
		ret = False;
	}

        torture_rpc_close(p);

	return ret;
}
