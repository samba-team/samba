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

static bool test_OpenSCManager(struct dcerpc_pipe *p, struct torture_context *tctx, struct policy_handle *h)
{
	struct svcctl_OpenSCManagerW r;
	
	r.in.MachineName = NULL;
	r.in.DatabaseName = NULL;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.handle = h;
	
	torture_assert_ntstatus_ok(tctx, 
							   dcerpc_svcctl_OpenSCManagerW(p, tctx, &r), 
							   "OpenSCManager failed!");
	
	return true;
}

static bool test_CloseServiceHandle(struct dcerpc_pipe *p, struct torture_context *tctx, struct policy_handle *h)
{
	struct svcctl_CloseServiceHandle r; 

	r.in.handle = h;
	r.out.handle = h;
	torture_assert_ntstatus_ok(tctx, 
							   dcerpc_svcctl_CloseServiceHandle(p, tctx, &r), 
							   "CloseServiceHandle failed");

	return true;
}

static bool test_EnumServicesStatus(struct torture_context *tctx, struct dcerpc_pipe *p)
{
	struct svcctl_EnumServicesStatusW r;
	struct policy_handle h;
	int i;
	NTSTATUS status;
	uint32_t resume_handle = 0;
	struct ENUM_SERVICE_STATUS *service = NULL; 

	if (!test_OpenSCManager(p, tctx, &h))
		return false;

	r.in.handle = &h;
	r.in.type = SERVICE_TYPE_WIN32;
	r.in.state = SERVICE_STATE_ALL;
	r.in.buf_size = 0;
	r.in.resume_handle = &resume_handle;
	r.out.service = NULL;
	r.out.resume_handle = &resume_handle;
	r.out.services_returned = 0;
	r.out.bytes_needed = 0;

	status = dcerpc_svcctl_EnumServicesStatusW(p, tctx, &r);

	torture_assert_ntstatus_ok(tctx, status, "EnumServicesStatus failed!");

	if (W_ERROR_EQUAL(r.out.result, WERR_MORE_DATA)) {
		r.in.buf_size = *r.out.bytes_needed;
		r.out.service = talloc_size(tctx, *r.out.bytes_needed);
		
		status = dcerpc_svcctl_EnumServicesStatusW(p, tctx, &r);

		torture_assert_ntstatus_ok(tctx, status, "EnumServicesStatus failed!");
		torture_assert_werr_ok(tctx, r.out.result, "EnumServicesStatus failed");

		service = (struct ENUM_SERVICE_STATUS *)r.out.service;
	}

	for(i = 0; i < *r.out.services_returned; i++) {
		printf("Type: %d, State: %d\n", service[i].status.type, service[i].status.state);
	}
	
	if (!test_CloseServiceHandle(p, tctx, &h))
		return false;

	return true;
}

static bool test_SCManager(struct torture_context *tctx, 
						   struct dcerpc_pipe *p)
{
	struct policy_handle h;

	if (!test_OpenSCManager(p, tctx, &h))
		return false;

	if (!test_CloseServiceHandle(p, tctx, &h))
		return false;

	return true;
}

struct torture_suite *torture_rpc_svcctl(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "SVCCTL");
	struct torture_tcase *tcase;

	tcase = torture_suite_add_rpc_iface_tcase(suite, "svcctl", 
											  &ndr_table_svcctl);
	
	torture_rpc_tcase_add_test(tcase, "SCManager", 
							   test_SCManager);
	torture_rpc_tcase_add_test(tcase, "EnumServicesStatus", 
							   test_EnumServicesStatus);

	return suite;
}
