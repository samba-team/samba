/* 
   Unix SMB/CIFS implementation.
   test suite for srvsvc rpc operations

   Copyright (C) Jelmer Vernooij 2004
   
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
#include "librpc/gen_ndr/ndr_svcctl.h"
#include "librpc/gen_ndr/ndr_security.h"

static BOOL test_EnumServicesStatus(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, struct policy_handle *h)
{
	struct svcctl_EnumServicesStatusW r;
	int i;
	NTSTATUS status;
	uint32 resume_handle = 0;
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
		r.in.buf_size = r.out.bytes_needed;
		r.out.service = talloc(mem_ctx, r.out.bytes_needed);
		
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

	for(i = 0; i < r.out.services_returned; i++) {
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
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
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

BOOL torture_rpc_svcctl(void)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
		struct policy_handle h;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_svcctl");

	status = torture_rpc_connection(&p,
					DCERPC_SVCCTL_NAME,
					DCERPC_SVCCTL_UUID,
					DCERPC_SVCCTL_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
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

	talloc_destroy(mem_ctx);

    torture_rpc_close(p);

	return ret;
}
