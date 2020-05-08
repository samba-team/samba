/*
   Unix SMB/CIFS implementation.

   test suite for handle types on the SAMR pipe

   Copyright (C) Samuel Cabrero <scabrero@samba.org> 2020

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
#include "librpc/gen_ndr/ndr_samr_c.h"
#include "torture/rpc/torture_rpc.h"
#include "param/param.h"
#include "libcli/security/security.h"

enum samr_handle {
	SAMR_HANDLE_CONNECT,
	SAMR_HANDLE_DOMAIN,
	SAMR_HANDLE_USER,
	SAMR_HANDLE_GROUP,
	SAMR_HANDLE_ALIAS
};

static NTSTATUS torture_samr_Close(struct torture_context *tctx,
				   struct dcerpc_binding_handle *b,
				   struct policy_handle *h)
{
	NTSTATUS status;
	struct samr_Close cl;

	cl.in.handle  = h;
	cl.out.handle = h;
	status = dcerpc_samr_Close_r(b, tctx, &cl);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return cl.out.result;
}

static NTSTATUS torture_samr_Connect5(struct torture_context *tctx,
				      struct dcerpc_binding_handle *b,
				      uint32_t mask, struct policy_handle *h)
{
	NTSTATUS status;
	struct samr_Connect5 r5;
	union samr_ConnectInfo info;
	uint32_t level_out = 0;

	info.info1.client_version = 0;
	info.info1.unknown2 = 0;
	r5.in.system_name = "";
	r5.in.level_in = 1;
	r5.in.info_in = &info;
	r5.out.info_out = &info;
	r5.out.level_out = &level_out;
	r5.out.connect_handle = h;
	r5.in.access_mask = mask;

	status = dcerpc_samr_Connect5_r(b, tctx, &r5);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return r5.out.result;
}

static bool test_samr_handletype_OpenDomain(struct torture_context *tctx,
					    struct dcerpc_pipe *p)
{
	NTSTATUS status;
	struct samr_LookupDomain ld;
	struct dom_sid2 *sid = NULL;
	struct samr_OpenDomain od;
	struct samr_OpenUser ou;
	struct samr_OpenGroup og;
	struct policy_handle ch;
	struct policy_handle bad;
	struct policy_handle dh;
	struct policy_handle oh;
	struct lsa_String dn;
	struct dcerpc_binding_handle *b = p->binding_handle;

	/* first we must grab the sid of the domain */
	status = torture_samr_Connect5(tctx, b, SEC_FLAG_MAXIMUM_ALLOWED, &ch);
	torture_assert_ntstatus_ok(tctx, status, "Connect5 failed");

	ld.in.connect_handle = &ch;
	ld.in.domain_name    = &dn;
	ld.out.sid           = &sid;
	dn.string            = lpcfg_workgroup(tctx->lp_ctx);
	status = dcerpc_samr_LookupDomain_r(b, tctx, &ld);
	torture_assert_ntstatus_ok(tctx, status, "LookupDomain failed");
	torture_assert_ntstatus_ok(tctx, ld.out.result, "LookupDomain failed");

	status = torture_samr_Connect5(tctx, b, 1, &ch);
	torture_assert_ntstatus_ok(tctx, status, "Connect5 failed");

	od.in.connect_handle = &bad;
	od.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	od.in.sid = sid;
	od.out.domain_handle = &dh;

	/* Open domain, wrong handle GUID */
	bad = ch;
	bad.uuid = GUID_random();

	status = dcerpc_samr_OpenDomain_r(b, tctx, &od);
	torture_assert_ntstatus_equal(tctx,
				      status,
				      NT_STATUS_RPC_SS_CONTEXT_MISMATCH,
				      "OpenDomain succeeded with random GUID");

	/* Open domain, wrong handle type */
	bad = ch;
	bad.handle_type = SAMR_HANDLE_USER;

	status = dcerpc_samr_OpenDomain_r(b, tctx, &od);
	torture_assert_ntstatus_equal(tctx,
				      status,
				      NT_STATUS_RPC_SS_CONTEXT_MISMATCH,
				      "OpenDomain succeeded with wrong type");

	/* Open domain */
	bad = ch;

	status = dcerpc_samr_OpenDomain_r(b, tctx, &od);
	torture_assert_ntstatus_ok(tctx, status, "OpenDomain failed");
	torture_assert_ntstatus_ok(tctx, od.out.result, "OpenDomain failed");

	bad = dh;

	/* Open user, wrong handle type */
	ou.in.domain_handle = &bad;
	ou.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	ou.in.rid = 501;
	ou.out.user_handle = &oh;

	bad.handle_type = SAMR_HANDLE_ALIAS;

	status = dcerpc_samr_OpenUser_r(b, tctx, &ou);
	torture_assert_ntstatus_equal(tctx,
				      status,
				      NT_STATUS_RPC_SS_CONTEXT_MISMATCH,
				      "OpenUser succeeded with wrong type");

	/* Open user */
	bad.handle_type = SAMR_HANDLE_DOMAIN;

	status = dcerpc_samr_OpenUser_r(b, tctx, &ou);
	torture_assert_ntstatus_ok(tctx, status, "OpenUser failed");
	torture_assert_ntstatus_ok(tctx, ou.out.result, "OpenUser failed");

	/* Close user */
	status = torture_samr_Close(tctx, b, &oh);
	torture_assert_ntstatus_ok(tctx, status, "Close failed");

	bad = dh;

	/* Open group, wrong type */
	og.in.domain_handle = &bad;
	og.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	og.in.rid = 513;
	og.out.group_handle = &oh;

	bad.handle_type = SAMR_HANDLE_GROUP;

	status = dcerpc_samr_OpenGroup_r(b, tctx, &og);
	torture_assert_ntstatus_equal(tctx,
				      status,
				      NT_STATUS_RPC_SS_CONTEXT_MISMATCH,
				      "OpenGroup succeeded with wrong type");

	/* Open group */
	bad.handle_type = SAMR_HANDLE_DOMAIN;

	status = dcerpc_samr_OpenGroup_r(b, tctx, &og);
	torture_assert_ntstatus_ok(tctx, status, "OpenGroup failed");
	torture_assert_ntstatus_ok(tctx, ou.out.result, "OpenGroup failed");

	/* Close group */
	status = torture_samr_Close(tctx, b, &oh);
	torture_assert_ntstatus_ok(tctx, status, "Close failed");

	/* Close connect */
	status = torture_samr_Close(tctx, b, &ch);
	torture_assert_ntstatus_ok(tctx, status, "Close failed");

	return true;
}

struct torture_suite *torture_rpc_samr_handletype(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = NULL;
	struct torture_rpc_tcase *tcase = NULL;

	suite = torture_suite_create(mem_ctx, "samr.handletype");
	tcase = torture_suite_add_rpc_iface_tcase(suite, "samr",
						  &ndr_table_samr);

	torture_rpc_tcase_add_test(tcase, "OpenDomainHandleType",
				   test_samr_handletype_OpenDomain);

	return suite;
}
