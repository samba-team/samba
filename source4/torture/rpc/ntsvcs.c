/*
   Unix SMB/CIFS implementation.
   test suite for rpc ntsvcs operations

   Copyright (C) Guenther Deschner 2008

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
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
#include "torture/rpc/rpc.h"
#include "librpc/gen_ndr/ndr_ntsvcs_c.h"
#include "torture/util.h"
#include "param/param.h"

static bool test_PNP_GetVersion(struct torture_context *tctx,
				struct dcerpc_pipe *p)
{
	NTSTATUS status;
	struct PNP_GetVersion r;
	uint16_t version = 0;

	r.out.version = &version;

	status = dcerpc_PNP_GetVersion(p, tctx, &r);

	torture_assert_ntstatus_ok(tctx, status, "PNP_GetVersion");
	torture_assert_werr_ok(tctx, r.out.result, "PNP_GetVersion");
	torture_assert_int_equal(tctx, version, 0x400, "invalid version");

	return true;
}

static bool test_PNP_GetDeviceListSize(struct torture_context *tctx,
				       struct dcerpc_pipe *p)
{
	NTSTATUS status;
	struct PNP_GetDeviceListSize r;
	uint32_t size = 0;

	r.in.devicename = NULL;
	r.in.flags = 0;
	r.out.size = &size;

	status = dcerpc_PNP_GetDeviceListSize(p, tctx, &r);

	torture_assert_ntstatus_ok(tctx, status, "PNP_GetDeviceListSize");
	torture_assert_werr_ok(tctx, r.out.result, "PNP_GetDeviceListSize");

	return true;
}

static bool test_PNP_GetDeviceList(struct torture_context *tctx,
				   struct dcerpc_pipe *p)
{
	NTSTATUS status;
	struct PNP_GetDeviceList r;
	uint16_t *buffer = NULL;
	uint32_t length = 0;

	buffer = talloc_array(tctx, uint16_t, 0);

	r.in.filter = NULL;
	r.in.flags = 0;
	r.in.length = &length;
	r.out.length = &length;
	r.out.buffer = buffer;

	status = dcerpc_PNP_GetDeviceList(p, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status, "PNP_GetDeviceList");

	if (W_ERROR_EQUAL(r.out.result, WERR_CM_BUFFER_SMALL)) {
		struct PNP_GetDeviceListSize s;

		s.in.devicename = NULL;
		s.in.flags = 0;
		s.out.size = &length;

		status = dcerpc_PNP_GetDeviceListSize(p, tctx, &s);

		torture_assert_ntstatus_ok(tctx, status, "PNP_GetDeviceListSize");
		torture_assert_werr_ok(tctx, s.out.result, "PNP_GetDeviceListSize");
	}

	buffer = talloc_array(tctx, uint16_t, length);

	r.in.length = &length;
	r.out.length = &length;
	r.out.buffer = buffer;

	status = dcerpc_PNP_GetDeviceList(p, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status, "PNP_GetDeviceList");
	torture_assert_werr_ok(tctx, r.out.result, "PNP_GetDeviceList");

	return true;
}


struct torture_suite *torture_rpc_ntsvcs(TALLOC_CTX *mem_ctx)
{
	struct torture_rpc_tcase *tcase;
	struct torture_suite *suite = torture_suite_create(mem_ctx, "NTSVCS");
	struct torture_test *test;

	tcase = torture_suite_add_rpc_iface_tcase(suite, "ntsvcs",
						  &ndr_table_ntsvcs);

	test = torture_rpc_tcase_add_test(tcase, "PNP_GetDeviceList",
					  test_PNP_GetDeviceList);
	test = torture_rpc_tcase_add_test(tcase, "PNP_GetDeviceListSize",
					  test_PNP_GetDeviceListSize);
	test = torture_rpc_tcase_add_test(tcase, "PNP_GetVersion",
					  test_PNP_GetVersion);

	return suite;
}
