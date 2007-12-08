/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
   
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
#include "param/share.h"
#include "param/param.h"
#include "torture/torture.h"

static bool test_create(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert(tctx, lp_ctx != NULL, "lp_ctx");
	return true;
}

static bool test_set_option(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert(tctx, lp_set_option(lp_ctx, "workgroup=werkgroep"), "lp_set_option failed");
	torture_assert_str_equal(tctx, "WERKGROEP", lp_workgroup(lp_ctx), "workgroup");
	return true;
}

static bool test_set_option_invalid(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert(tctx, !lp_set_option(lp_ctx, "workgroup"), "lp_set_option succeeded");
	return true;
}

static bool test_set_option_parametric(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert(tctx, lp_set_option(lp_ctx, "some:thing=blaat"), "lp_set_option failed");
	torture_assert_str_equal(tctx, lp_parm_string(lp_ctx, NULL, "some", "thing"), "blaat", 
				 "invalid parametric option");
	return true;
}

struct torture_suite *torture_local_loadparm(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "LOADPARM");

	torture_suite_add_simple_test(suite, "create", test_create);
	torture_suite_add_simple_test(suite, "set_option", test_set_option);
	torture_suite_add_simple_test(suite, "set_option_invalid", test_set_option_invalid);
	torture_suite_add_simple_test(suite, "set_option_parametric", test_set_option_parametric);

	return suite;
}
