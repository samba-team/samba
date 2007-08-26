/* 
   Unix SMB/CIFS implementation.
   test suite for srvsvc rpc operations

   Copyright (C) Jelmer Vernooij 2004
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "torture/torture.h"
#include "librpc/gen_ndr/ndr_svcctl_c.h"
#include "torture/rpc/rpc.h"

static BOOL test_EnumServicesStatus(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, struct policy_handle *h)
{
	struct svcctl_EnumServicesStatusW r;
	int i;
	NTSTATUS status;
	uint32_t resume_handle = 0;
	struct ENUM_SERVICE_STATUS *service = NULL; 

	r.in.handle = h;
	r.in.type = SERVICE_TYPE_WIN32;
	r.in.state = SERVICE_STATE_ALL;
	r.in.buf_size = 0;
	r.in.resume_handle = &resume_handle;
	r.out.service = NULL;
	r.out.resume_handle = &resume_handle;
	r.out.services_returned = 0;
	r.out.bytes_needed = 0;

	status = dcerpc_svcctl_EnumServicesStatusW(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("ËnumServicesStatus failed!\n");
		return False;
	}

	if (W_ERROR_EQUAL(r.out.result, WERR_MORE_DATA)) {
		r.in.buf_size = *r.out.bytes_needed;
		r.out.service = talloc_size(mem_ctx, *r.out.bytes_needed);
		
		status = dcerpc_svcctl_EnumServicesStatusW(p, mem_ctx, &r);

		if (!NT_STATUS_IS_OK(status)) {
			printf("ËnumServicesStatus failed!\n");
			return False;
		}

		if (!W_ERROR_IS_OK(r.out.result)) {
			printf("EnumServicesStatus failed\n");
			return False;
		}
		service = (struct ENUM_SERVICE_STATUS *)r.out.service;
	}

	for(i = 0; i < *r.out.services_returned; i++) {
		printf("Type: %d, State: %d\n", service[i].status.type, service[i].status.state);
	}
		
	return True;
}

static BOOL test_OpenSCManager(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, struct policy_handle *h)
{
	struct svcctl_OpenSCManagerW r;
	NTSTATUS status;
	
	r.in.MachineName = NULL;
	r.in.DatabaseName = NULL;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.handle = h;
	
	status = dcerpc_svcctl_OpenSCManagerW(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenSCManager failed!\n");
		return False;
	}
	
	return True;
}

static BOOL test_CloseServiceHandle(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, struct policy_handle *h)
{
	struct svcctl_CloseServiceHandle r; 
	NTSTATUS status;
	r.in.handle = h;
	r.out.handle = h;
	status = dcerpc_svcctl_CloseServiceHandle(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("CloseServiceHandle failed\n");
		return False;
	}

	return True;
}

BOOL torture_rpc_svcctl(struct torture_context *torture)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
		struct policy_handle h;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_svcctl");

	status = torture_rpc_connection(mem_ctx, &p, &ndr_table_svcctl);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return False;
	}

	if (!test_OpenSCManager(p, mem_ctx, &h)) {
		ret = False;
	}

	if (!test_EnumServicesStatus(p, mem_ctx, &h)) {
		ret = False;
	}

	if (!test_CloseServiceHandle(p, mem_ctx, &h)) {
		ret = False;
	}

	talloc_free(mem_ctx);

	return ret;
}
