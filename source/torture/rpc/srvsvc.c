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
#include "torture/torture.h"
#include "librpc/gen_ndr/ndr_srvsvc.h"
#include "librpc/gen_ndr/ndr_srvsvc_c.h"
#include "torture/rpc/rpc.h"

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
		d_printf("testing NetCharDevGetInfo level %u on device '%s'\n",
			r.in.level, r.in.device_name);
		status = dcerpc_srvsvc_NetCharDevGetInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("NetCharDevGetInfo level %u on device '%s' failed - %s\n",
				r.in.level, r.in.device_name, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			d_printf("NetCharDevGetInfo level %u on device '%s' failed - %s\n",
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
		d_printf("testing NetCharDevControl opcode %u on device '%s'\n", 
			r.in.opcode, r.in.device_name);
		status = dcerpc_srvsvc_NetCharDevControl(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("NetCharDevControl opcode %u failed - %s\n", r.in.opcode, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			d_printf("NetCharDevControl opcode %u failed - %s\n", r.in.opcode, win_errstr(r.out.result));
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
	r.in.max_buffer = (uint32_t)-1;
	r.in.resume_handle = NULL;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int j;


		ZERO_STRUCT(r.out);
		r.in.level = levels[i];
		printf("testing NetCharDevEnum level %u\n", r.in.level);
		status = dcerpc_srvsvc_NetCharDevEnum(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("NetCharDevEnum level %u failed - %s\n", r.in.level, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			d_printf("NetCharDevEnum level %u failed - %s\n", r.in.level, win_errstr(r.out.result));
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
		d_printf("testing NetCharDevQGetInfo level %u on devicequeue '%s'\n",
			r.in.level, r.in.queue_name);
		status = dcerpc_srvsvc_NetCharDevQGetInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("NetCharDevQGetInfo level %u on devicequeue '%s' failed - %s\n",
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
		d_printf("testing NetCharDevQSetInfo level %u on devicequeue '%s'\n", 
			r.in.level, devicequeue);
		switch (r.in.level) {
		case 0:
			r.in.info.info0 = talloc(mem_ctx, struct srvsvc_NetCharDevQInfo0);
			r.in.info.info0->device = r.in.queue_name;
			break;
		case 1:
			r.in.info.info1 = talloc(mem_ctx, struct srvsvc_NetCharDevQInfo1);
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
			d_printf("NetCharDevQSetInfo level %u on devicequeue '%s' failed - %s\n",
				r.in.level, r.in.queue_name, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			d_printf("NetCharDevQSetInfo level %u on devicequeue '%s' failed - %s\n",
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
	r.in.max_buffer = (uint32_t)-1;
	r.in.resume_handle = NULL;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		int j;

		ZERO_STRUCT(r.out);
		r.in.level = levels[i];
		printf("testing NetCharDevQEnum level %u\n", r.in.level);
		status = dcerpc_srvsvc_NetCharDevQEnum(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("NetCharDevQEnum level %u failed - %s\n", r.in.level, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			d_printf("NetCharDevQEnum level %u failed - %s\n", r.in.level, win_errstr(r.out.result));
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

/**************************/
/* srvsvc_NetConn         */
/**************************/
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
		d_printf("testing NetConnEnum level %u\n", r.in.level);
		status = dcerpc_srvsvc_NetConnEnum(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("NetConnEnum level %u failed - %s\n", r.in.level, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			d_printf("NetConnEnum level %u failed - %s\n", r.in.level, win_errstr(r.out.result));
			continue;
		}
	}

	return ret;
}

/**************************/
/* srvsvc_NetFile         */
/**************************/
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
		d_printf("testing NetFileEnum level %u\n", r.in.level);
		status = dcerpc_srvsvc_NetFileEnum(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("NetFileEnum level %u failed - %s\n", r.in.level, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			d_printf("NetFileEnum level %u failed - %s\n", r.in.level, win_errstr(r.out.result));
			continue;
		}
	}

	return ret;
}

/**************************/
/* srvsvc_NetSess         */
/**************************/
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
		d_printf("testing NetSessEnum level %u\n", r.in.level);
		status = dcerpc_srvsvc_NetSessEnum(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("NetSessEnum level %u failed - %s\n", r.in.level, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			d_printf("NetSessEnum level %u failed - %s\n", r.in.level, win_errstr(r.out.result));
			continue;
		}
	}

	return ret;
}

/**************************/
/* srvsvc_NetShare        */
/**************************/
static BOOL test_NetShareCheck(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			       const char *device_name)
{
	NTSTATUS status;
	struct srvsvc_NetShareCheck r;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.device_name = device_name;

	d_printf("testing NetShareCheck on device '%s'\n", r.in.device_name);

	status = dcerpc_srvsvc_NetShareCheck(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("dcerpc_srvsvc_NetShareCheck on device '%s' failed - %s\n",
			r.in.device_name, nt_errstr(status));
		ret = False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		d_printf("NetShareCheck on device '%s' failed - %s\n",
			r.in.device_name, win_errstr(r.out.result));
		ret = False;
	}

	return ret;
}

static BOOL test_NetShareGetInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				 const char *sharename, BOOL admin)
{
	NTSTATUS status;
	struct srvsvc_NetShareGetInfo r;
	struct {
		uint32_t level;
		WERROR anon_status;
		WERROR admin_status;
	} levels[] = {
		 { 0,		WERR_OK,		WERR_OK },
		 { 1,		WERR_OK,		WERR_OK },
		 { 2,		WERR_ACCESS_DENIED,	WERR_OK },
		 { 501,		WERR_OK,		WERR_OK },
		 { 502,		WERR_ACCESS_DENIED,	WERR_OK },
		 { 1005,	WERR_OK,		WERR_OK },
	};
	int i;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.share_name = sharename;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		WERROR expected;

		r.in.level = levels[i].level;
		expected = levels[i].anon_status;
		if (admin) expected = levels[i].admin_status;
		ZERO_STRUCT(r.out);

		d_printf("testing NetShareGetInfo level %u on share '%s'\n", 
		       r.in.level, r.in.share_name);

		status = dcerpc_srvsvc_NetShareGetInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("NetShareGetInfo level %u on share '%s' failed - %s\n",
				r.in.level, r.in.share_name, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_EQUAL(r.out.result, expected)) {
			d_printf("NetShareGetInfo level %u on share '%s' failed - %s (expected %s)\n",
				r.in.level, r.in.share_name, win_errstr(r.out.result),
				win_errstr(expected));
			ret = False;
			continue;
		}

		if (r.in.level != 2) continue;
		if (!r.out.info.info2 || !r.out.info.info2->path) continue;
		if (!test_NetShareCheck(p, mem_ctx, r.out.info.info2->path)) {
			ret = False;
		}
	}

	return ret;
}

static BOOL test_NetShareAddSetDel(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct srvsvc_NetShareAdd a;
	struct srvsvc_NetShareSetInfo r;
	struct srvsvc_NetShareGetInfo q;
	struct srvsvc_NetShareDel d;
	struct {
		uint32_t level;
		WERROR expected;
	} levels[] = {
		 { 0,		WERR_UNKNOWN_LEVEL },
		 { 1,		WERR_OK },
		 { 2,		WERR_OK },
		 { 501,		WERR_UNKNOWN_LEVEL },
		 { 502,		WERR_OK },
		 { 1004,	WERR_OK },
		 { 1005,	WERR_OK },
		 { 1006,	WERR_OK },
/*		 { 1007,	WERR_OK }, */
		 { 1501,	WERR_OK },
	};
	int i;
	BOOL ret = True;

	a.in.server_unc = r.in.server_unc = q.in.server_unc = d.in.server_unc =
		talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.share_name = talloc_strdup(mem_ctx, "testshare");

	a.in.level = 2;
	a.in.info.info2 = talloc(mem_ctx, struct srvsvc_NetShareInfo2);
	a.in.info.info2->name = r.in.share_name;
	a.in.info.info2->type = STYPE_DISKTREE;
	a.in.info.info2->comment = talloc_strdup(mem_ctx, "test comment");
	a.in.info.info2->permissions = 123434566;
	a.in.info.info2->max_users = -1;
	a.in.info.info2->current_users = 0;
	a.in.info.info2->path = talloc_strdup(mem_ctx, "C:\\");
	a.in.info.info2->password = NULL;

	a.in.parm_error = NULL;

	status = dcerpc_srvsvc_NetShareAdd(p, mem_ctx, &a);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("NetShareAdd level 2 on share 'testshare' failed - %s\n",
			 nt_errstr(status));
		return False;
	} else if (!W_ERROR_EQUAL(a.out.result, WERR_OK)) {
		d_printf("NetShareAdd level 2 on share 'testshare' failed - %s\n",
			 win_errstr(a.out.result));
		return False;
	}

	r.in.parm_error = NULL;

	q.in.level = 502;

	for (i = 0; i < ARRAY_SIZE(levels); i++) {

		r.in.level = levels[i].level;
		ZERO_STRUCT(r.out);

		d_printf("testing NetShareSetInfo level %u on share '%s'\n", 
		       r.in.level, r.in.share_name);

		switch (levels[i].level) {
		case 0:
			r.in.info.info0 = talloc(mem_ctx, struct srvsvc_NetShareInfo0);
			r.in.info.info0->name = r.in.share_name;
			break;
		case 1:
			r.in.info.info1 = talloc(mem_ctx, struct srvsvc_NetShareInfo1);
			r.in.info.info1->name = r.in.share_name;
			r.in.info.info1->type = STYPE_DISKTREE;
			r.in.info.info1->comment = talloc_strdup(mem_ctx, "test comment 1");
			break;
		case 2:	
			r.in.info.info2 = talloc(mem_ctx, struct srvsvc_NetShareInfo2);
			r.in.info.info2->name = r.in.share_name;
			r.in.info.info2->type = STYPE_DISKTREE;
			r.in.info.info2->comment = talloc_strdup(mem_ctx, "test comment 2");
			r.in.info.info2->permissions = 0;
			r.in.info.info2->max_users = 2;
			r.in.info.info2->current_users = 1;
			r.in.info.info2->path = talloc_strdup(mem_ctx, "::BLaH::"); /* "C:\\"); */
			r.in.info.info2->password = NULL;
			break;
		case 501:
			r.in.info.info501 = talloc(mem_ctx, struct srvsvc_NetShareInfo501);
			r.in.info.info501->name = r.in.share_name;
			r.in.info.info501->type = STYPE_DISKTREE;
			r.in.info.info501->comment = talloc_strdup(mem_ctx, "test comment 501");
			r.in.info.info501->csc_policy = 0;
			break;
		case 502:
			r.in.info.info502 = talloc(mem_ctx, struct srvsvc_NetShareInfo502);
			r.in.info.info502->name = r.in.share_name;
			r.in.info.info502->type = STYPE_DISKTREE;
			r.in.info.info502->comment = talloc_strdup(mem_ctx, "test comment 502");
			r.in.info.info502->permissions = 0;
			r.in.info.info502->max_users = 502;
			r.in.info.info502->current_users = 1;
			r.in.info.info502->path = talloc_strdup(mem_ctx, "C:\\");
			r.in.info.info502->password = NULL;
			r.in.info.info502->unknown = 0;
			r.in.info.info502->sd = NULL;
			break;
		case 1004:
			r.in.info.info1004 = talloc(mem_ctx, struct srvsvc_NetShareInfo1004);
			r.in.info.info1004->comment = talloc_strdup(mem_ctx, "test comment 1004");
			break;
		case 1005:
			r.in.info.info1005 = talloc(mem_ctx, struct srvsvc_NetShareInfo1005);
			r.in.info.info1005->dfs_flags = 0;
			break;
		case 1006:
			r.in.info.info1006 = talloc(mem_ctx, struct srvsvc_NetShareInfo1006);
			r.in.info.info1006->max_users = 1006;
			break;
/*		case 1007:
			r.in.info.info1007 = talloc(mem_ctx, struct srvsvc_NetShareInfo1007);
			r.in.info.info1007->flags = 0;
			r.in.info.info1007->alternate_directory_name = talloc_strdup(mem_ctx, "test");
			break;
*/
		case 1501:
			r.in.info.info1501 = talloc_zero(mem_ctx, struct sec_desc_buf);
			break;
		}
		
		status = dcerpc_srvsvc_NetShareSetInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("NetShareGetInfo level %u on share '%s' failed - %s\n",
				r.in.level, r.in.share_name, nt_errstr(status));
			ret = False;
			continue;
		} else if (!W_ERROR_EQUAL(r.out.result, levels[i].expected)) {
			d_printf("NetShareSetInfo level %u on share '%s' failed - %s (expected %s)\n",
				r.in.level, r.in.share_name, win_errstr(r.out.result),
				win_errstr(levels[i].expected));
			ret = False;
			continue;
		}
		
		q.in.share_name = r.in.share_name;

		status = dcerpc_srvsvc_NetShareGetInfo(p, mem_ctx, &q);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("NetShareGetInfo level %u on share '%s' failed - %s\n",
				q.in.level, q.in.share_name, nt_errstr(status));
			ret = False;
			continue;
		} else if (!W_ERROR_EQUAL(q.out.result, WERR_OK)) {
			d_printf("NetShareGetInfo level %u on share '%s' failed - %s\n",
				q.in.level, q.in.share_name, win_errstr(q.out.result));
			ret = False;
			continue;
		}

		if (strcmp(q.out.info.info502->name, r.in.share_name) != 0) {
			ret = False;
		}
		switch (levels[i].level) {
		case 0:
			break;
		case 1:
			if (strcmp(q.out.info.info502->comment, "test comment 1") != 0)
				ret = False;
			break;
		case 2:
			if (strcmp(q.out.info.info502->comment, "test comment 2") != 0)
				ret = False;
			if (q.out.info.info2->max_users != 2)
				ret = False;
			if (strcmp(q.out.info.info2->path, "C:\\") != 0)
				ret = False;
			break;
		case 501:
			if (strcmp(q.out.info.info501->comment, "test comment 501") != 0)
				ret = False;
			break;
		case 502:
			if (strcmp(q.out.info.info502->comment, "test comment 502") != 0)
				ret = False;
			if (q.out.info.info2->max_users != 502)
				ret = False;
			if (strcmp(q.out.info.info2->path, "C:\\") != 0)
				ret = False;
			break;
		case 1004:
			if (strcmp(q.out.info.info502->comment, "test comment 1004") != 0)
				ret = False;
			break;
		case 1005:
			break;
		case 1006:
			if (q.out.info.info2->max_users != 1006)
				ret = False;
			break;
/*		case 1007:
			break;
*/
		case 1501:
			break;
		}
	}

	d.in.share_name = r.in.share_name;
	d.in.reserved = 0;

	status = dcerpc_srvsvc_NetShareDel(p, mem_ctx, &d);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("NetShareDel on share 'testshare502' failed - %s\n",
			 nt_errstr(status));
		ret = False;
	} else if (!W_ERROR_EQUAL(a.out.result, WERR_OK)) {
		d_printf("NetShareDel on share 'testshare502' failed - %s\n",
			 win_errstr(d.out.result));
		ret = False;
	}

	return ret;
}

/**************************/
/* srvsvc_NetShare        */
/**************************/
static BOOL test_NetShareEnumAll(struct dcerpc_pipe *p, 
				 TALLOC_CTX *mem_ctx, BOOL admin)
{
	NTSTATUS status;
	struct srvsvc_NetShareEnumAll r;
	struct srvsvc_NetShareCtr0 c0;
	struct {
		uint32_t level;
		WERROR anon_status;
		WERROR admin_status;
	} levels[] = {
		 { 0,	WERR_OK,		WERR_OK },
		 { 1,	WERR_OK,		WERR_OK },
		 { 2,	WERR_ACCESS_DENIED,	WERR_OK },
		 { 501,	WERR_ACCESS_DENIED,	WERR_OK },
		 { 502,	WERR_ACCESS_DENIED,	WERR_OK },
	};
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
		WERROR expected;

		r.in.level = levels[i].level;
		expected = levels[i].anon_status;
		if (admin) expected = levels[i].admin_status;

		ZERO_STRUCT(r.out);
		resume_handle = 0;

		d_printf("testing NetShareEnumAll level %u\n", r.in.level);
		status = dcerpc_srvsvc_NetShareEnumAll(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("NetShareEnumAll level %u failed - %s\n", r.in.level, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_EQUAL(r.out.result, expected)) {
			d_printf("NetShareEnumAll level %u failed - %s (expected %s)\n",
				r.in.level, win_errstr(r.out.result),
				win_errstr(expected));
			continue;
		}

		/* call srvsvc_NetShareGetInfo for each returned share */
		if (r.in.level == 2 && r.out.ctr.ctr2) {
			for (j=0;j<r.out.ctr.ctr2->count;j++) {
				const char *name;
				name = r.out.ctr.ctr2->array[j].name;
				if (!test_NetShareGetInfo(p, mem_ctx, name, admin)) {
					ret = False;
				}
			}
		}
	}

	return ret;
}

static BOOL test_NetShareEnum(struct dcerpc_pipe *p, 
			      TALLOC_CTX *mem_ctx, BOOL admin)
{
	NTSTATUS status;
	struct srvsvc_NetShareEnum r;
	struct srvsvc_NetShareCtr0 c0;
	struct {
		uint32_t level;
		WERROR anon_status;
		WERROR admin_status;
	} levels[] = {
		 { 0,	WERR_OK,		WERR_OK },
		 { 1,	WERR_OK,		WERR_OK },
		 { 2,	WERR_ACCESS_DENIED,	WERR_OK },
		 { 501,	WERR_UNKNOWN_LEVEL,	WERR_UNKNOWN_LEVEL },
		 { 502,	WERR_ACCESS_DENIED,	WERR_OK },
	};
	int i;
	BOOL ret = True;

	r.in.server_unc = talloc_asprintf(mem_ctx,"\\\\%s",dcerpc_server_name(p));
	r.in.ctr.ctr0 = &c0;
	r.in.ctr.ctr0->count = 0;
	r.in.ctr.ctr0->array = NULL;
	r.in.max_buffer = (uint32_t)-1;
	r.in.resume_handle = NULL;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		WERROR expected;

		r.in.level = levels[i].level;
		expected = levels[i].anon_status;
		if (admin) expected = levels[i].admin_status;

		ZERO_STRUCT(r.out);

		d_printf("testing NetShareEnum level %u\n", r.in.level);
		status = dcerpc_srvsvc_NetShareEnum(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("NetShareEnum level %u failed - %s\n", r.in.level, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_EQUAL(r.out.result, expected)) {
			d_printf("NetShareEnum level %u failed - %s (expected %s)\n",
				r.in.level, win_errstr(r.out.result),
				win_errstr(expected));
			continue;
		}
	}

	return ret;
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
		d_printf("testing NetSrvGetInfo level %u\n", r.in.level);
		status = dcerpc_srvsvc_NetSrvGetInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("NetSrvGetInfo level %u failed - %s\n", r.in.level, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			d_printf("NetSrvGetInfo level %u failed - %s\n", r.in.level, win_errstr(r.out.result));
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

	ZERO_STRUCT(r.in);
	r.in.server_unc = NULL;
	r.in.resume_handle = &resume_handle;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		ZERO_STRUCT(r.out);
		r.in.level = levels[i];
		d_printf("testing NetDiskEnum level %u\n", r.in.level);
		status = dcerpc_srvsvc_NetDiskEnum(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			NDR_PRINT_OUT_DEBUG(srvsvc_NetDiskEnum, &r);
			d_printf("NetDiskEnum level %u failed - %s\n", r.in.level, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			d_printf("NetDiskEnum level %u failed - %s\n", r.in.level, win_errstr(r.out.result));
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
	r.in.transports.ctr0 = &c0;
	r.in.transports.ctr0->count = 0;
	r.in.transports.ctr0->array = NULL;
	r.in.max_buffer = (uint32_t)-1;
	r.in.resume_handle = NULL;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		ZERO_STRUCT(r.out);
		r.in.level = levels[i];
		d_printf("testing NetTransportEnum level %u\n", r.in.level);
		status = dcerpc_srvsvc_NetTransportEnum(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("NetTransportEnum level %u failed - %s\n", r.in.level, nt_errstr(status));
			ret = False;
			continue;
		}
		if (!W_ERROR_IS_OK(r.out.result)) {
			d_printf("NetTransportEnum level %u failed - %s\n", r.in.level, win_errstr(r.out.result));
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
	d_printf("testing NetRemoteTOD\n");
	status = dcerpc_srvsvc_NetRemoteTOD(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("NetRemoteTOD failed - %s\n", nt_errstr(status));
		ret = False;
	}
	if (!W_ERROR_IS_OK(r.out.result)) {
		d_printf("NetRemoteTOD failed - %s\n", win_errstr(r.out.result));
	}

	return ret;
}

/**************************/
/* srvsvc_NetName         */
/**************************/

static BOOL test_NetNameValidate(struct dcerpc_pipe *p,
				 TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct srvsvc_NetNameValidate r;
	char *invalidc;
	char *name;
	int i, n, min, max;

	r.in.server_unc = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.flags = 0x0;

	d_printf("testing NetNameValidate\n");

	/* valid path types only between 1 and 13 */
	for (i = 1; i < 14; i++) {

again:
		/* let's limit ourselves to a maximum of 4096 bytes */
		r.in.name = name = talloc_array(mem_ctx, char, 4097);
		max = 4096;
		min = 0;
		n = max;

		while (1) {

			/* Find maximum length accepted by this type */
			ZERO_STRUCT(r.out);
			r.in.name_type = i;
			memset(name, 'A', n);
			name[n] = '\0';

			status = dcerpc_srvsvc_NetNameValidate(p, mem_ctx, &r);
			if (!NT_STATUS_IS_OK(status)) {
				d_printf("NetNameValidate failed while checking maximum size (%s)\n",
						nt_errstr(status));
				break;
			}

			if (W_ERROR_IS_OK(r.out.result)) {
				min = n;
				n += (max - min + 1)/2;
				continue;
				
			} else {
				if ((min + 1) >= max) break; /* found it */
				
				max = n;
				n -= (max - min)/2;
				continue;
			}
		}

		talloc_free(r.in.name);

		d_printf("Maximum length for type %2d, flags %08x: %d\n", i, r.in.flags, max);

		/* find invalid chars for this type check only ASCII between 0x20 and 0x7e */

		invalidc = talloc_strdup(mem_ctx, "");

		for (n = 0x20; n < 0x7e; n++) {
			r.in.name = talloc_asprintf(mem_ctx, "%c", (char)n);

			status = dcerpc_srvsvc_NetNameValidate(p, mem_ctx, &r);
			if (!NT_STATUS_IS_OK(status)) {
				d_printf("NetNameValidate failed while checking valid chars (%s)\n",
						nt_errstr(status));
				break;
			}

			if (!W_ERROR_IS_OK(r.out.result)) {
				invalidc = talloc_asprintf_append(invalidc, "%c", (char)n);
			}

			talloc_free(r.in.name);
		}

		d_printf(" Invalid chars for type %2d, flags %08x: \"%s\"\n", i, r.in.flags, invalidc);

		/* only two values are accepted for flags: 0x0 and 0x80000000 */
		if (r.in.flags == 0x0) {
			r.in.flags = 0x80000000;
			goto again;
		}

		r.in.flags = 0x0;
	}

	return True;
}

BOOL torture_rpc_srvsvc(struct torture_context *torture)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	const char *binding = torture_setting_string(torture, "binding", NULL);
	struct cli_credentials *anon_credentials;

	mem_ctx = talloc_init("torture_rpc_srvsvc");

	status = torture_rpc_connection(mem_ctx, &p, &dcerpc_table_srvsvc);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return False;
	}

	ret &= test_NetCharDevEnum(p, mem_ctx);
	ret &= test_NetCharDevQEnum(p, mem_ctx);
	ret &= test_NetConnEnum(p, mem_ctx);
	ret &= test_NetFileEnum(p, mem_ctx);
	ret &= test_NetSessEnum(p, mem_ctx);
	ret &= test_NetShareEnumAll(p, mem_ctx, True);
	ret &= test_NetSrvGetInfo(p, mem_ctx);
	ret &= test_NetDiskEnum(p, mem_ctx);
	ret &= test_NetTransportEnum(p, mem_ctx);
	ret &= test_NetRemoteTOD(p, mem_ctx);
	ret &= test_NetShareEnum(p, mem_ctx, True);
	ret &= test_NetShareGetInfo(p, mem_ctx, "ADMIN$", True);
/*	ret &= test_NetShareAddSetDel(p, mem_ctx); */
	ret &= test_NetNameValidate(p, mem_ctx);
	
	status = torture_rpc_connection(mem_ctx, &p, &dcerpc_table_srvsvc);

	if (!binding) {
		d_printf("You must specify a ncacn binding string\n");
		return False;
	}

	anon_credentials = cli_credentials_init_anon(mem_ctx);

	status = dcerpc_pipe_connect(mem_ctx, 
				     &p, binding, &dcerpc_table_srvsvc,
				     anon_credentials, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return False;
	}

	ret &= test_NetShareEnumAll(p, mem_ctx, False);
	ret &= test_NetShareEnum(p, mem_ctx, False);
	ret &= test_NetShareGetInfo(p, mem_ctx, "ADMIN$", False);

	talloc_free(mem_ctx);

	return ret;
}
