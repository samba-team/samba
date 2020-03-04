/*
   Unix SMB/CIFS implementation.
   test suite for svcctl ndr operations

   Copyright (C) Guenther Deschner 2020

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
#include "torture/ndr/ndr.h"
#include "librpc/gen_ndr/ndr_svcctl.h"
#include "torture/ndr/proto.h"
#include "param/param.h"

static const uint8_t svcctl_ChangeServiceConfigW_req_data[] = {
	0x00, 0x00, 0x00, 0x00, 0xcd, 0x94, 0x05, 0x40, 0x30, 0x28, 0x00, 0x49,
	0x8d, 0xe4, 0x8e, 0x85, 0xb7, 0x19, 0x5c, 0x83, 0x10, 0x01, 0x00, 0x00,
	0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static bool svcctl_ChangeServiceConfigW_req_check(struct torture_context *tctx,
						  struct svcctl_ChangeServiceConfigW *r)
{
	struct policy_handle handle = { 0 };
	GUID_from_string("400594cd-2830-4900-8de4-8e85b7195c83", &handle.uuid);

	torture_assert_guid_equal(tctx, r->in.handle->uuid, handle.uuid, "handle");
	torture_assert_u32_equal(tctx, r->in.type, 0x00000110, "type");
	torture_assert_u32_equal(tctx, r->in.start_type, SVCCTL_AUTO_START, "start_type");
	torture_assert_u32_equal(tctx, r->in.error_control, SVCCTL_SVC_ERROR_NORMAL, "error_control");
	torture_assert_str_equal(tctx, r->in.binary_path, NULL, "binary_path");
	torture_assert_str_equal(tctx, r->in.load_order_group, NULL, "load_order_group");
	torture_assert(tctx, r->in.tag_id == NULL, "tag_id");
	torture_assert_str_equal(tctx, r->in.dependencies, NULL, "dependencies");
	torture_assert_u32_equal(tctx, r->in.dwDependSize, 0, "dwDependSize");
	torture_assert_str_equal(tctx, r->in.service_start_name, NULL, "service_start_name");
	torture_assert_str_equal(tctx, r->in.password, NULL, "password");
	torture_assert_u32_equal(tctx, r->in.dwPwSize, 0, "dwPwSize");
	torture_assert_str_equal(tctx, r->in.display_name, NULL, "display_name");

	return true;
}

static const uint8_t svcctl_ChangeServiceConfigW_rep_data[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static bool svcctl_ChangeServiceConfigW_rep_check(struct torture_context *tctx,
						  struct svcctl_ChangeServiceConfigW *r)
{
	torture_assert(tctx, r->out.tag_id == NULL, "tag_id");
	torture_assert_werr_ok(tctx, r->out.result, "result");

	return true;
}

struct torture_suite *ndr_svcctl_suite(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "svcctl");

	torture_suite_add_ndr_pull_fn_test(suite,
					   svcctl_ChangeServiceConfigW,
					   svcctl_ChangeServiceConfigW_req_data,
					   NDR_IN,
					   svcctl_ChangeServiceConfigW_req_check);

	torture_suite_add_ndr_pull_fn_test(suite,
					   svcctl_ChangeServiceConfigW,
					   svcctl_ChangeServiceConfigW_rep_data,
					   NDR_OUT,
					   svcctl_ChangeServiceConfigW_rep_check);
	return suite;
}
