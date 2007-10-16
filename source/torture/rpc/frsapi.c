/*
   Unix SMB/CIFS implementation.
   test suite for rpc frsapi operations

   Copyright (C) Guenther Deschner 2007

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
#include "torture/rpc/rpc.h"
#include "librpc/gen_ndr/ndr_frsapi_c.h"
#include "torture/util.h"

static bool test_GetDsPollingIntervalW(struct torture_context *tctx,
				       struct dcerpc_pipe *p,
				       uint32_t *CurrentInterval,
				       uint32_t *DsPollingLongInterval,
				       uint32_t *DsPollingShortInterval)
{
	struct frsapi_GetDsPollingIntervalW r;

	ZERO_STRUCT(r);

	r.out.CurrentInterval = CurrentInterval;
	r.out.DsPollingLongInterval = DsPollingLongInterval;
	r.out.DsPollingShortInterval = DsPollingShortInterval;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_frsapi_GetDsPollingIntervalW(p, tctx, &r),
		"GetDsPollingIntervalW failed");

	torture_assert_werr_ok(tctx, r.out.result,
			       "GetDsPollingIntervalW failed");

	return true;
}

static bool test_SetDsPollingIntervalW(struct torture_context *tctx,
				       struct dcerpc_pipe *p,
				       uint32_t CurrentInterval,
				       uint32_t DsPollingLongInterval,
				       uint32_t DsPollingShortInterval)
{
	struct frsapi_SetDsPollingIntervalW r;

	ZERO_STRUCT(r);

	r.in.CurrentInterval = CurrentInterval;
	r.in.DsPollingLongInterval = DsPollingLongInterval;
	r.in.DsPollingShortInterval = DsPollingShortInterval;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_frsapi_SetDsPollingIntervalW(p, tctx, &r),
		"SetDsPollingIntervalW failed");

	torture_assert_werr_ok(tctx, r.out.result,
			       "SetDsPollingIntervalW failed");

	return true;
}

static bool test_DsPollingIntervalW(struct torture_context *tctx,
				    struct dcerpc_pipe *p)
{
	uint32_t i1, i2, i3;
	uint32_t k1, k2, k3;

	if (!test_GetDsPollingIntervalW(tctx, p, &i1, &i2, &i3)) {
		return false;
	}

	if (!test_SetDsPollingIntervalW(tctx, p, i1, i2, i3)) {
		return false;
	}

	k1 = i1;
	k2 = k3 = 0;

	if (!test_SetDsPollingIntervalW(tctx, p, k1, k2, k3)) {
		return false;
	}

	if (!test_GetDsPollingIntervalW(tctx, p, &k1, &k2, &k3)) {
		return false;
	}

	if ((i1 != k1) || (i2 != k2) || (i3 != k3)) {
		return false;
	}

	return true;
}

struct torture_suite *torture_rpc_frsapi(TALLOC_CTX *mem_ctx)
{
	struct torture_rpc_tcase *tcase;
	struct torture_suite *suite = torture_suite_create(mem_ctx, "FRSAPI");
	struct torture_test *test;

	tcase = torture_suite_add_rpc_iface_tcase(suite, "frsapi",
						  &ndr_table_frsapi);

	test = torture_rpc_tcase_add_test(tcase, "DsPollingIntervalW",
					  test_DsPollingIntervalW);

	return suite;
}
