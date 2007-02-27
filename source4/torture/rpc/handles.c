/* 
   Unix SMB/CIFS implementation.

   test suite for behaviour of rpc policy handles

   Copyright (C) Andrew Tridgell 2007
   
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
#include "librpc/gen_ndr/ndr_samr_c.h"
#include "librpc/gen_ndr/ndr_lsa_c.h"
#include "librpc/gen_ndr/ndr_drsuapi_c.h"
#include "torture/rpc/rpc.h"

/*
  this tests the use of policy handles between connections
*/

static bool test_handles_lsa(struct torture_context *torture)
{
	NTSTATUS status;
	struct dcerpc_pipe *p1, *p2;
	struct policy_handle handle;
	struct policy_handle handle2;
	struct lsa_ObjectAttribute attr;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy r;
	struct lsa_Close c;
	uint16_t system_name = '\\';
	TALLOC_CTX *mem_ctx = talloc_new(torture);

	status = torture_rpc_connection(mem_ctx, &p1, &dcerpc_table_lsarpc);
	torture_assert_ntstatus_ok(torture, status, "opening lsa pipe1");

	status = torture_rpc_connection(mem_ctx, &p2, &dcerpc_table_lsarpc);
	torture_assert_ntstatus_ok(torture, status, "opening lsa pipe1");

	qos.len = 0;
	qos.impersonation_level = 2;
	qos.context_mode = 1;
	qos.effective_only = 0;

	attr.len = 0;
	attr.root_dir = NULL;
	attr.object_name = NULL;
	attr.attributes = 0;
	attr.sec_desc = NULL;
	attr.sec_qos = &qos;

	r.in.system_name = &system_name;
	r.in.attr = &attr;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.handle = &handle;

	status = dcerpc_lsa_OpenPolicy(p1, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(torture, "lsa_OpenPolicy not supported - skipping\n");
		talloc_free(mem_ctx);
		return true;
	}

	c.in.handle = &handle;
	c.out.handle = &handle2;

	status = dcerpc_lsa_Close(p2, mem_ctx, &c);
	torture_assert_ntstatus_equal(torture, status, NT_STATUS_NET_WRITE_FAULT, 
				      "closing policy handle on p2");
	torture_assert_int_equal(torture, p2->last_fault_code, DCERPC_FAULT_CONTEXT_MISMATCH, 
				      "closing policy handle on p2");

	status = dcerpc_lsa_Close(p1, mem_ctx, &c);
	torture_assert_ntstatus_ok(torture, status, "closing policy handle on p1");

	status = dcerpc_lsa_Close(p1, mem_ctx, &c);
	torture_assert_ntstatus_equal(torture, status, NT_STATUS_NET_WRITE_FAULT, 
				      "closing policy handle on p1 again");
	torture_assert_int_equal(torture, p1->last_fault_code, DCERPC_FAULT_CONTEXT_MISMATCH, 
				      "closing policy handle on p1 again");
	
	talloc_free(mem_ctx);

	return true;
}


static bool test_handles_samr(struct torture_context *torture)
{
	NTSTATUS status;
	struct dcerpc_pipe *p1, *p2;
	struct policy_handle handle;
	struct policy_handle handle2;
	struct samr_Connect r;
	struct samr_Close c;
	TALLOC_CTX *mem_ctx = talloc_new(torture);

	status = torture_rpc_connection(mem_ctx, &p1, &dcerpc_table_samr);
	torture_assert_ntstatus_ok(torture, status, "opening samr pipe1");

	status = torture_rpc_connection(mem_ctx, &p2, &dcerpc_table_samr);
	torture_assert_ntstatus_ok(torture, status, "opening samr pipe1");

	r.in.system_name = 0;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.connect_handle = &handle;

	status = dcerpc_samr_Connect(p1, mem_ctx, &r);
	torture_assert_ntstatus_ok(torture, status, "opening policy handle on p1");

	c.in.handle = &handle;
	c.out.handle = &handle2;

	status = dcerpc_samr_Close(p2, mem_ctx, &c);
	torture_assert_ntstatus_equal(torture, status, NT_STATUS_NET_WRITE_FAULT, 
				      "closing policy handle on p2");
	torture_assert_int_equal(torture, p2->last_fault_code, DCERPC_FAULT_CONTEXT_MISMATCH, 
				      "closing policy handle on p2");

	status = dcerpc_samr_Close(p1, mem_ctx, &c);
	torture_assert_ntstatus_ok(torture, status, "closing policy handle on p1");

	status = dcerpc_samr_Close(p1, mem_ctx, &c);
	torture_assert_ntstatus_equal(torture, status, NT_STATUS_NET_WRITE_FAULT, 
				      "closing policy handle on p1 again");
	torture_assert_int_equal(torture, p1->last_fault_code, DCERPC_FAULT_CONTEXT_MISMATCH, 
				      "closing policy handle on p1 again");
	
	talloc_free(mem_ctx);

	return true;
}


static bool test_handles_drsuapi(struct torture_context *torture)
{
	NTSTATUS status;
	struct dcerpc_pipe *p1, *p2;
	struct policy_handle handle;
	struct policy_handle handle2;
	struct GUID bind_guid;
	struct drsuapi_DsBind r;
	struct drsuapi_DsUnbind c;
	TALLOC_CTX *mem_ctx = talloc_new(torture);

	status = torture_rpc_connection(mem_ctx, &p1, &dcerpc_table_drsuapi);
	torture_assert_ntstatus_ok(torture, status, "opening drsuapi pipe1");

	status = torture_rpc_connection(mem_ctx, &p2, &dcerpc_table_drsuapi);
	torture_assert_ntstatus_ok(torture, status, "opening drsuapi pipe1");

	GUID_from_string(DRSUAPI_DS_BIND_GUID, &bind_guid);

	r.in.bind_guid = &bind_guid;
	r.in.bind_info = NULL;
	r.out.bind_handle = &handle;

	status = dcerpc_drsuapi_DsBind(p1, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(torture, "drsuapi_DsBind not supported - skipping\n");
		talloc_free(mem_ctx);
		return true;
	}

	c.in.bind_handle = &handle;
	c.out.bind_handle = &handle2;

	status = dcerpc_drsuapi_DsUnbind(p2, mem_ctx, &c);
	torture_assert_ntstatus_equal(torture, status, NT_STATUS_NET_WRITE_FAULT, 
				      "closing policy handle on p2");
	torture_assert_int_equal(torture, p2->last_fault_code, DCERPC_FAULT_CONTEXT_MISMATCH, 
				      "closing policy handle on p2");

	status = dcerpc_drsuapi_DsUnbind(p1, mem_ctx, &c);
	torture_assert_ntstatus_ok(torture, status, "closing policy handle on p1");

	status = dcerpc_drsuapi_DsUnbind(p1, mem_ctx, &c);
	torture_assert_ntstatus_equal(torture, status, NT_STATUS_NET_WRITE_FAULT, 
				      "closing policy handle on p1 again");
	torture_assert_int_equal(torture, p1->last_fault_code, DCERPC_FAULT_CONTEXT_MISMATCH, 
				      "closing policy handle on p1 again");
	
	talloc_free(mem_ctx);

	return true;
}


struct torture_suite *torture_rpc_handles(void)
{
	struct torture_suite *suite;

	suite = torture_suite_create(talloc_autofree_context(), "HANDLES");
	torture_suite_add_simple_test(suite, "lsarpc", test_handles_lsa);
	torture_suite_add_simple_test(suite, "samr", test_handles_samr);
	torture_suite_add_simple_test(suite, "drsuapi", test_handles_drsuapi);
	return suite;
}
