/* 
   Unix SMB/CIFS implementation.

   local testing of share code

   Copyright (C) Jelmer Vernooij 2007
   
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
#include "param/share.h"
#include "torture/torture.h"

static bool test_list_empty(struct torture_context *tctx, 
							void *tcase_data, 
							void *test_data)
{
	struct share_context *ctx = tcase_data;
	int count;
	const char **names;

	torture_assert_ntstatus_ok(tctx, share_list_all(tctx, ctx, &count, &names),
							   "share_list_all failed");

	return true;
}

static void tcase_add_share_tests(struct torture_tcase *tcase)
{
	torture_tcase_add_test(tcase, "list_empty", test_list_empty, NULL);
}

static BOOL setup_ldb(struct torture_context *tctx, void **data)
{
	return NT_STATUS_IS_OK(share_get_context_by_name(tctx, "ldb", data));
}

static BOOL setup_classic(struct torture_context *tctx, void **data)
{
	return NT_STATUS_IS_OK(share_get_context_by_name(tctx, "classic", data));
}

static BOOL teardown(struct torture_context *tctx, void *data)
{
	talloc_free(data);
	return true;
}

struct torture_suite *torture_local_share(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, 
													   "SHARE");
	struct torture_tcase *tcase;

	share_init();

	tcase = torture_suite_add_tcase(suite, "ldb");
	torture_tcase_set_fixture(tcase, setup_ldb, teardown);
	tcase_add_share_tests(tcase);

	tcase = torture_suite_add_tcase(suite, "classic");
	torture_tcase_set_fixture(tcase, setup_classic, teardown);
	tcase_add_share_tests(tcase);

	return suite;
}
