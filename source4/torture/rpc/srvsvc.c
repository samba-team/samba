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

/**************************/
/* srvsvc_NetCharDev      */
/**************************/
static BOOL test_NetCharDevGetInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				const char *devname)
{
	NTSTATUS status;
	struct srvsvc_NetCharDevGetInfo r;
	uint32_t levels[] = {0, 1};
	int i;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx,"\\\\%s",dcerpc_server_name(p));
	r.in.device_name = devname;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		ZERO_STRUCT(r.out);
		r.in.level = levels[i];
		printf("testing NetCharDevGetInfo level %u on device '%s'\n",
			r.in.level, r.in.device_name);
		status = dcerpc_srvsvc_NetCharDevGetInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("NetCharDevGetInfo level %u on device '%s' failed - %s\n",
				r.in.level, r.in.device_name, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("NetCharDevGetInfo level %u on device '%s' failed - %s\n",
				r.in.level, r.in.device_name, win_errstr(r.out.result));
			continue;
		}
	}

	return ret;
}

static BOOL test_NetCharDevControl(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				const char *devname)
{
	NTSTATUS status;
	struct srvsvc_NetCharDevControl r;
	uint32_t opcodes[] = {0, 1};
	int i;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx,"\\\\%s",dcerpc_server_name(p));
	r.in.device_name = devname;

	for (i=0;i<ARRAY_SIZE(opcodes);i++) {
		ZERO_STRUCT(r.out);
		r.in.opcode = opcodes[i];
		printf("testing NetCharDevControl opcode %u on device '%s'\n", 
			r.in.opcode, r.in.device_name);
		status = dcerpc_srvsvc_NetCharDevControl(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("NetCharDevControl opcode %u failed - %s\n", r.in.opcode, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("NetCharDevControl opcode %u failed - %s\n", r.in.opcode, win_errstr(r.out.result));
			continue;
		}
	}

	return ret;
}

static BOOL test_NetCharDevEnum(struct dcerpc_pipe *p, 
			   TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct srvsvc_NetCharDevEnum r;
	struct srvsvc_NetCharDevCtr0 c0;
	uint32_t levels[] = {0, 1};
	int i;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx,"\\\\%s",dcerpc_server_name(p));
	r.in.ctr.ctr0 = &c0;
	r.in.ctr.ctr0->count = 0;
	r.in.ctr.ctr0->array = NULL;
	r.in.max_buffer = (uint32)-1;
	r.in.resume_handle = NULL;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int j;


		ZERO_STRUCT(r.out);
		r.in.level = levels[i];
		printf("testing NetCharDevEnum level %u\n", r.in.level);
		status = dcerpc_srvsvc_NetCharDevEnum(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("NetCharDevEnum level %u failed - %s\n", r.in.level, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("NetCharDevEnum level %u failed - %s\n", r.in.level, win_errstr(r.out.result));
			continue;
		}

		/* call test_NetCharDevGetInfo and test_NetCharDevControl for each returned share */
		if (r.in.level == 1) {
			for (j=0;j<r.out.ctr.ctr1->count;j++) {
				const char *device;
				device = r.out.ctr.ctr1->array[j].device;
				if (!test_NetCharDevGetInfo(p, mem_ctx, device)) {
					ret = False;
				}
				if (!test_NetCharDevControl(p, mem_ctx, device)) {
					ret = False;
				}
			}
		}
	}

	return ret;
}

/**************************/
/* srvsvc_NetCharDevQ     */
/**************************/
static BOOL test_NetCharDevQGetInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				const char *devicequeue)
{
	NTSTATUS status;
	struct srvsvc_NetCharDevQGetInfo r;
	uint32_t levels[] = {0, 1};
	int i;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx,"\\\\%s",dcerpc_server_name(p));
	r.in.queue_name = devicequeue;
	r.in.user = talloc_asprintf(mem_ctx,"Administrator");

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		ZERO_STRUCT(r.out);
		r.in.level = levels[i];
		printf("testing NetCharDevQGetInfo level %u on devicequeue '%s'\n",
			r.in.level, r.in.queue_name);
		status = dcerpc_srvsvc_NetCharDevQGetInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("NetCharDevQGetInfo level %u on devicequeue '%s' failed - %s\n",
				r.in.level, r.in.queue_name, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("NetCharDevQGetInfo level %u on devicequeue '%s' failed - %s\n",
				r.in.level, r.in.queue_name, win_errstr(r.out.result));
			continue;
		}
	}

	return ret;
}

#if 0
static BOOL test_NetCharDevQSetInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				const char *devicequeue)
{
	NTSTATUS status;
	struct srvsvc_NetCharDevQSetInfo r;
	uint32_t parm_error;
	uint32_t levels[] = {0, 1};
	int i;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx,"\\\\%s",dcerpc_server_name(p));
	r.in.queue_name = devicequeue;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		ZERO_STRUCT(r.out);
		parm_error = 0;
		r.in.level = levels[i];
		printf("testing NetCharDevQSetInfo level %u on devicequeue '%s'\n", 
			r.in.level, devicequeue);
		switch (r.in.level) {
		case 0:
			r.in.info.info0 = talloc_p(mem_ctx, struct srvsvc_NetCharDevQInfo0);
			r.in.info.info0->device = r.in.queue_name;
			break;
		case 1:
			r.in.info.info1 = talloc_p(mem_ctx, struct srvsvc_NetCharDevQInfo1);
			r.in.info.info1->device = r.in.queue_name;
			r.in.info.info1->priority = 0x000;
			r.in.info.info1->devices = r.in.queue_name;
			r.in.info.info1->users = 0x000;
			r.in.info.info1->num_ahead = 0x000;
			break;
		default:
			break;
		}
		r.in.parm_error = &parm_error;
		status = dcerpc_srvsvc_NetCharDevQSetInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("NetCharDevQSetInfo level %u on devicequeue '%s' failed - %s\n",
				r.in.level, r.in.queue_name, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("NetCharDevQSetInfo level %u on devicequeue '%s' failed - %s\n",
				r.in.level, r.in.queue_name, win_errstr(r.out.result));
			continue;
		}
	}

	return ret;
}
#endif

static BOOL test_NetCharDevQEnum(struct dcerpc_pipe *p, 
			   TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct srvsvc_NetCharDevQEnum r;
	struct srvsvc_NetCharDevQCtr0 c0;
	uint32_t levels[] = {0, 1};
	int i;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx,"\\\\%s",dcerpc_server_name(p));
	r.in.user = talloc_asprintf(mem_ctx,"%s","Administrator");
	r.in.ctr.ctr0 = &c0;
	r.in.ctr.ctr0->count = 0;
	r.in.ctr.ctr0->array = NULL;
	r.in.max_buffer = (uint32)-1;
	r.in.resume_handle = NULL;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int j;

		ZERO_STRUCT(r.out);
		r.in.level = levels[i];
		printf("testing NetCharDevQEnum level %u\n", r.in.level);
		status = dcerpc_srvsvc_NetCharDevQEnum(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("NetCharDevQEnum level %u failed - %s\n", r.in.level, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("NetCharDevQEnum level %u failed - %s\n", r.in.level, win_errstr(r.out.result));
			continue;
		}

		/* call test_NetCharDevGetInfo and test_NetCharDevControl for each returned share */
		if (r.in.level == 1) {
			for (j=0;j<r.out.ctr.ctr1->count;j++) {
				const char *device;
				device = r.out.ctr.ctr1->array[j].device;
				if (!test_NetCharDevQGetInfo(p, mem_ctx, device)) {
					ret = False;
				}
			}
		}
	}

	return ret;
}


static BOOL test_NetConnEnum(struct dcerpc_pipe *p, 
			   TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct srvsvc_NetConnEnum r;
	struct srvsvc_NetConnCtr0 c0;
	uint32_t levels[] = {0, 1};
	int i;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx,"\\\\%s",dcerpc_server_name(p));
	r.in.path = talloc_asprintf(mem_ctx,"%s","ADMIN$");
	r.in.ctr.ctr0 = &c0;
	r.in.ctr.ctr0->count = 0;
	r.in.ctr.ctr0->array = NULL;
	r.in.max_buffer = (uint32_t)-1;
	r.in.resume_handle = NULL;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		ZERO_STRUCT(r.out);
		r.in.level = levels[i];
		printf("testing NetConnEnum level %u\n", r.in.level);
		status = dcerpc_srvsvc_NetConnEnum(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("NetConnEnum level %u failed - %s\n", r.in.level, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("NetConnEnum level %u failed - %s\n", r.in.level, win_errstr(r.out.result));
			continue;
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
	uint32_t levels[] = {2, 3};
	int i;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx,"\\\\%s",dcerpc_server_name(p));
	r.in.path = NULL;
	r.in.user = NULL;
	r.in.ctr.ctr3 = &c3;
	r.in.ctr.ctr3->count = 0;
	r.in.ctr.ctr3->array = NULL;
	r.in.max_buffer = (uint32_t)4096;
	r.in.resume_handle = NULL;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		ZERO_STRUCT(r.out);
		r.in.level = levels[i];
		printf("testing NetFileEnum level %u\n", r.in.level);
		status = dcerpc_srvsvc_NetFileEnum(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("NetFileEnum level %u failed - %s\n", r.in.level, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("NetFileEnum level %u failed - %s\n", r.in.level, win_errstr(r.out.result));
			continue;
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
	uint32_t levels[] = {0, 1, 2, 10, 502};
	int i;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx,"\\\\%s",dcerpc_server_name(p));
	r.in.client = NULL;
	r.in.user = NULL;
	r.in.ctr.ctr0 = &c0;
	r.in.ctr.ctr0->count = 0;
	r.in.ctr.ctr0->array = NULL;
	r.in.max_buffer = (uint32_t)-1;
	r.in.resume_handle = NULL;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		ZERO_STRUCT(r.out);
		r.in.level = levels[i];
		printf("testing NetSessEnum level %u\n", r.in.level);
		status = dcerpc_srvsvc_NetSessEnum(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("NetSessEnum level %u failed - %s\n", r.in.level, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("NetSessEnum level %u failed - %s\n", r.in.level, win_errstr(r.out.result));
			continue;
		}
	}

	return True;
}

/**************************/
/* srvsvc_NetShare        */
/**************************/
static BOOL test_NetShareGetInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				 const char *sharename)
{
	NTSTATUS status;
	struct srvsvc_NetShareGetInfo r;
	uint32_t levels[] = {0, 1, 2, 501, 502, 1005};
	int i;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.share_name = sharename;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		ZERO_STRUCT(r.out);
		r.in.level = levels[i];

		printf("testing NetShareGetInfo level %u on share '%s'\n", 
		       r.in.level, r.in.share_name);

		status = dcerpc_srvsvc_NetShareGetInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("NetShareGetInfo level %u on share '%s' failed - %s\n",
				r.in.level, r.in.share_name, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("NetShareGetInfo level %u on share '%s' failed - %s\n",
				r.in.level, r.in.share_name, win_errstr(r.out.result));
			continue;
		}
	}

	return ret;
}

static BOOL test_NetShareEnumAll(struct dcerpc_pipe *p, 
				 TALLOC_CTX *mem_ctx)
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
		int j;

		ZERO_STRUCT(r.out);
		resume_handle = 0;
		r.in.level = levels[i];
		printf("testing NetShareEnumAll level %u\n", r.in.level);
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

		/* call srvsvc_NetShareGetInfo for each returned share */
		if (r.in.level == 1) {
			for (j=0;j<r.out.ctr.ctr1->count;j++) {
				const char *name;
				name = r.out.ctr.ctr1->array[j].name;
				if (!test_NetShareGetInfo(p, mem_ctx, name)) {
					ret = False;
				}
			}
		}
	}

	return ret;
}

static BOOL test_NetShareEnum(struct dcerpc_pipe *p, 
			   TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct srvsvc_NetShareEnum r;
	struct srvsvc_NetShareCtr0 c0;
	uint32_t levels[] = {0, 1, 2, 502};
	int i;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx,"\\\\%s",dcerpc_server_name(p));
	r.in.ctr.ctr0 = &c0;
	r.in.ctr.ctr0->count = 0;
	r.in.ctr.ctr0->array = NULL;
	r.in.max_buffer = (uint32_t)-1;
	r.in.resume_handle = NULL;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		ZERO_STRUCT(r.out);
		r.in.level = levels[i];
		printf("testing NetShareEnum level %u\n", r.in.level);
		status = dcerpc_srvsvc_NetShareEnum(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("NetShareEnum level %u failed - %s\n", r.in.level, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("NetShareEnum level %u failed - %s\n", r.in.level, win_errstr(r.out.result));
			continue;
		}
	}

	return True;
}

/**************************/
/* srvsvc_NetSrv          */
/**************************/
static BOOL test_NetSrvGetInfo(struct dcerpc_pipe *p, 
				 TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct srvsvc_NetSrvGetInfo r;
	struct srvsvc_NetSrvInfo503 i503;
	uint32_t levels[] = {100, 101, 102, 502, 503};
	int i;
	BOOL ret = True;
	uint32_t resume_handle;

	ZERO_STRUCT(i503);

	r.in.server_unc = talloc_asprintf(mem_ctx,"\\\\%s",dcerpc_server_name(p));

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		ZERO_STRUCT(r.out);
		resume_handle = 0;
		r.in.level = levels[i];
		printf("testing NetSrvGetInfo level %u\n", r.in.level);
		status = dcerpc_srvsvc_NetSrvGetInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("NetSrvGetInfo level %u failed - %s\n", r.in.level, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("NetSrvGetInfo level %u failed - %s\n", r.in.level, win_errstr(r.out.result));
			continue;
		}
	}

	return ret;
}

/**************************/
/* srvsvc_NetDisk         */
/**************************/
static BOOL test_NetDiskEnum(struct dcerpc_pipe *p, 
			   TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct srvsvc_NetDiskEnum r;
	uint32_t levels[] = {0};
	int i;
	BOOL ret = True;
	uint32_t resume_handle=0;

	r.in.server_unc = NULL;
	r.in.unknown = 0;
	r.in.resume_handle = &resume_handle;
	r.in.ctr.ctr0 = NULL;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		ZERO_STRUCT(r.out);
		r.in.level = levels[i];
		printf("testing NetDiskEnum level %u\n", r.in.level);
		status = dcerpc_srvsvc_NetDiskEnum(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			NDR_PRINT_OUT_DEBUG(srvsvc_NetDiskEnum, &r);
			printf("NetDiskEnum level %u failed - %s\n", r.in.level, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("NetDiskEnum level %u failed - %s\n", r.in.level, win_errstr(r.out.result));
			continue;
		}
	}

	return ret;
}

/**************************/
/* srvsvc_NetTransport    */
/**************************/
static BOOL test_NetTransportEnum(struct dcerpc_pipe *p, 
			   TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct srvsvc_NetTransportEnum r;
	struct srvsvc_NetTransportCtr0 c0;
	uint32_t levels[] = {0, 1};
	int i;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx,"\\\\%s",dcerpc_server_name(p));
	r.in.ctr.ctr0 = &c0;
	r.in.ctr.ctr0->count = 0;
	r.in.ctr.ctr0->array = NULL;
	r.in.max_buffer = (uint32_t)-1;
	r.in.resume_handle = NULL;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		ZERO_STRUCT(r.out);
		r.in.level = levels[i];
		printf("testing NetTransportEnum level %u\n", r.in.level);
		status = dcerpc_srvsvc_NetTransportEnum(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("NetTransportEnum level %u failed - %s\n", r.in.level, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("NetTransportEnum level %u failed - %s\n", r.in.level, win_errstr(r.out.result));
			continue;
		}
	}

	return ret;
}

/**************************/
/* srvsvc_NetRemoteTOD    */
/**************************/
static BOOL test_NetRemoteTOD(struct dcerpc_pipe *p, 
			   TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct srvsvc_NetRemoteTOD r;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx,"\\\\%s",dcerpc_server_name(p));

	ZERO_STRUCT(r.out);
	printf("testing NetRemoteTOD\n");
	status = dcerpc_srvsvc_NetRemoteTOD(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("NetRemoteTOD failed - %s\n", nt_errstr(status));
		ret = False;
	}
	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("NetRemoteTOD failed - %s\n", win_errstr(r.out.result));
	}

	return ret;
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

	if (!test_NetCharDevEnum(p, mem_ctx)) {
		ret = False;
	}

	if (!test_NetCharDevQEnum(p, mem_ctx)) {
		ret = False;
	}

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

	if (!test_NetSrvGetInfo(p, mem_ctx)) {
		ret = False;
	}

	if (!test_NetDiskEnum(p, mem_ctx)) {
		ret = False;
	}

	if (!test_NetTransportEnum(p, mem_ctx)) {
		ret = False;
	}

	if (!test_NetRemoteTOD(p, mem_ctx)) {
		ret = False;
	}

	if (!test_NetShareEnum(p, mem_ctx)) {
		ret = False;
	}

	talloc_destroy(mem_ctx);

        torture_rpc_close(p);

	return ret;
}
