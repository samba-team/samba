/*
   Unix SMB/CIFS implementation.
   test suite for wkssvc rpc operations

   Copyright (C) Andrew Tridgell 2003

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
#include "librpc/gen_ndr/ndr_wkssvc_c.h"
#include "torture/rpc/rpc.h"
#include "lib/cmdline/popt_common.h"
#include "param/param.h"

static bool test_NetWkstaGetInfo(struct torture_context *tctx,
				 struct dcerpc_pipe *p)
{
	NTSTATUS status;
	struct wkssvc_NetWkstaGetInfo r;
	union wkssvc_NetWkstaInfo info;
	uint16_t levels[] = {100, 101, 102, 502};
	int i;

	r.in.server_name = dcerpc_server_name(p);
	r.out.info = &info;

	for (i=0;i<ARRAY_SIZE(levels);i++) {
		r.in.level = levels[i];
		torture_comment(tctx, "testing NetWkstaGetInfo level %u\n", r.in.level);
		status = dcerpc_wkssvc_NetWkstaGetInfo(p, tctx, &r);
		torture_assert_ntstatus_ok(tctx, status,
			talloc_asprintf(tctx, "NetWkstaGetInfo level %u failed", r.in.level));
		torture_assert_werr_ok(tctx, r.out.result,
			talloc_asprintf(tctx, "NetWkstaGetInfo level %u failed", r.in.level));
	}

	return true;
}


static bool test_NetWkstaTransportEnum(struct torture_context *tctx,
				       struct dcerpc_pipe *p)
{
	NTSTATUS status;
	struct wkssvc_NetWkstaTransportEnum r;
	uint32_t resume_handle = 0;
	union wkssvc_NetWkstaTransportCtr ctr;
	struct wkssvc_NetWkstaTransportCtr0 ctr0;

	ZERO_STRUCT(ctr0);
	ctr.ctr0 = &ctr0;

	r.in.server_name = dcerpc_server_name(p);
	r.in.level = 0;
	r.in.ctr = &ctr;
	r.in.max_buffer = (uint32_t)-1;
	r.in.resume_handle = &resume_handle;
	r.out.ctr = &ctr;
	r.out.resume_handle = &resume_handle;

	status = dcerpc_wkssvc_NetWkstaTransportEnum(p, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status, "NetWkstaTransportEnum failed");
	torture_assert_werr_ok(tctx, r.out.result, talloc_asprintf(tctx,
		"NetWkstaTransportEnum level %u failed", r.in.level));

	return true;
}

static bool test_NetWkstaEnumUsers(struct torture_context *tctx,
				   struct dcerpc_pipe *p)
{
	NTSTATUS status;
	struct wkssvc_NetWkstaEnumUsers r;
	uint32_t handle = 0;
	uint32_t entries_read = 0;
	struct wkssvc_NetWkstaEnumUsersInfo info;
	struct wkssvc_NetWkstaEnumUsersCtr0 *user0;
	struct wkssvc_NetWkstaEnumUsersCtr1 *user1;
	uint32_t levels[] = { 0, 1 };
	int i;

	for (i=0; i<ARRAY_SIZE(levels); i++) {

		ZERO_STRUCT(info);

		info.level = levels[i];
		switch (info.level) {
		case 0:
			user0 = talloc_zero(tctx,
					    struct wkssvc_NetWkstaEnumUsersCtr0);
			info.ctr.user0 = user0;
			break;
		case 1:
			user1 = talloc_zero(tctx,
					    struct wkssvc_NetWkstaEnumUsersCtr1);
			info.ctr.user1 = user1;
			break;
		default:
			break;
		}

		r.in.server_name = dcerpc_server_name(p);
		r.in.prefmaxlen = (uint32_t)-1;
		r.in.info = r.out.info = &info;
		r.in.resume_handle = r.out.resume_handle = &handle;

		r.out.entries_read = &entries_read;

		torture_comment(tctx, "testing NetWkstaEnumUsers level %u\n",
				levels[i]);

		status = dcerpc_wkssvc_NetWkstaEnumUsers(p, tctx, &r);
		torture_assert_ntstatus_ok(tctx, status,
					   "NetWkstaEnumUsers failed");
		torture_assert_werr_ok(tctx, r.out.result,
				       "NetWkstaEnumUsers failed");
	}

	return true;
}

static bool test_NetrWkstaUserGetInfo(struct torture_context *tctx,
				      struct dcerpc_pipe *p)
{
	NTSTATUS status;
	struct wkssvc_NetrWkstaUserGetInfo r;
	union wkssvc_NetrWkstaUserInfo info;
	const char *dom = lp_workgroup(global_loadparm);
	struct cli_credentials *creds = cmdline_credentials;
	const char *user = cli_credentials_get_username(creds);
	int i;

	const struct {
		const char *unknown;
		uint32_t level;
		WERROR result;
	} tests[] = {
		{ NULL, 0, WERR_NO_SUCH_LOGON_SESSION },
		{ NULL, 1, WERR_NO_SUCH_LOGON_SESSION },
		{ NULL, 1101, WERR_OK },
		{ dom, 0, WERR_INVALID_PARAM },
		{ dom, 1, WERR_INVALID_PARAM },
		{ dom, 1101, WERR_INVALID_PARAM },
		{ user, 0, WERR_INVALID_PARAM },
		{ user, 1, WERR_INVALID_PARAM },
		{ user, 1101, WERR_INVALID_PARAM },
	};

	for (i=0; i<ARRAY_SIZE(tests); i++) {
		r.in.unknown = tests[i].unknown;
		r.in.level = tests[i].level;
		r.out.info = &info;

		torture_comment(tctx, "testing NetrWkstaUserGetInfo level %u\n",
				r.in.level);

		status = dcerpc_wkssvc_NetrWkstaUserGetInfo(p, tctx, &r);
		torture_assert_ntstatus_ok(tctx, status,
					   "NetrWkstaUserGetInfo failed");
		torture_assert_werr_equal(tctx, r.out.result,
					  tests[i].result,
					  "NetrWkstaUserGetInfo failed");
	}

	return true;
}

struct torture_suite *torture_rpc_wkssvc(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite;
	struct torture_rpc_tcase *tcase;

	suite = torture_suite_create(mem_ctx, "WKSSVC");
	tcase = torture_suite_add_rpc_iface_tcase(suite, "wkssvc",
						  &ndr_table_wkssvc);

	torture_rpc_tcase_add_test(tcase, "NetWkstaGetInfo",
				   test_NetWkstaGetInfo);
	torture_rpc_tcase_add_test(tcase, "NetWkstaTransportEnum",
				   test_NetWkstaTransportEnum);
	torture_rpc_tcase_add_test(tcase, "NetWkstaEnumUsers",
				   test_NetWkstaEnumUsers);
	torture_rpc_tcase_add_test(tcase, "NetrWkstaUserGetInfo",
				   test_NetrWkstaUserGetInfo);

	return suite;
}
