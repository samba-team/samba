/* 
   Unix SMB/CIFS implementation.
   test suite for atsvc rpc operations

   Copyright (C) Tim Potter 2003
   
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

static BOOL test_JobGetInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, uint32_t job_id)
{
	NTSTATUS status;
	struct atsvc_JobGetInfo r;

	r.in.servername = dcerpc_server_name(p);
	r.in.job_id = job_id;

	status = dcerpc_atsvc_JobGetInfo(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("JobGetInfo failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_JobDel(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, uint32_t min_job_id,
			uint32_t max_job_id)
{
	NTSTATUS status;
	struct atsvc_JobDel r;

	r.in.servername = dcerpc_server_name(p);
	r.in.min_job_id = min_job_id;
	r.in.max_job_id = max_job_id;

	status = dcerpc_atsvc_JobDel(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("JobDel failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_JobEnum(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct atsvc_JobEnum r;
	struct atsvc_enum_ctr ctr;
	uint32_t resume_handle = 0, i;
	BOOL ret = True;

	printf("\ntesting JobEnum\n");

	r.in.servername = dcerpc_server_name(p);
	ctr.entries_read = 0;
	ctr.first_entry = NULL;
	r.in.ctr = r.out.ctr = &ctr;
	r.in.preferred_max_len = 0xffffffff;
	r.in.resume_handle = r.out.resume_handle = &resume_handle;

	status = dcerpc_atsvc_JobEnum(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("JobEnum failed - %s\n", nt_errstr(status));
		return False;
	}

	for (i = 0; r.out.ctr && i < r.out.ctr->entries_read; i++) {
		if (!test_JobGetInfo(p, mem_ctx, r.out.ctr->first_entry[i].job_id)) {
			ret = False;
		}
	}

	return ret;
}

static BOOL test_JobAdd(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct atsvc_JobAdd r;
	struct atsvc_JobInfo info;

	printf("\ntesting JobAdd\n");

	r.in.servername = dcerpc_server_name(p);
	info.job_time = 0x050ae4c0; /* 11:30pm */
	info.days_of_month = 0;	    /* n/a */
	info.days_of_week = 0x02;   /* Tuesday */
	info.flags = 0x11;	    /* periodic, non-interactive */
	info.command = "foo.exe";
	r.in.job_info = &info;

	status = dcerpc_atsvc_JobAdd(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("JobAdd failed - %s\n", nt_errstr(status));
		return False;
	}

	/* Run EnumJobs again in case there were no jobs to begin with */

	if (!test_JobEnum(p, mem_ctx)) {
		return False;
	}

	if (!test_JobGetInfo(p, mem_ctx, r.out.job_id)) {
		return False;
	}

	if (!test_JobDel(p, mem_ctx, r.out.job_id, r.out.job_id)) {
		return False;
	}

	return True;
}

BOOL torture_rpc_atsvc(void)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_atsvc");

	status = torture_rpc_connection(&p, 
					DCERPC_ATSVC_NAME, 
					DCERPC_ATSVC_UUID, 
					DCERPC_ATSVC_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	if (!test_JobEnum(p, mem_ctx)) {
		return False;
	}

	if (!test_JobAdd(p, mem_ctx)) {
		return False;
	}

	talloc_destroy(mem_ctx);

        torture_rpc_close(p);

	return ret;
}
