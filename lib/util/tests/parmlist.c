/* 
   Unix SMB/CIFS implementation.

   parmlist testing

   Copyright (C) Jelmer Vernooij 2009
   
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
#include "../lib/util/parmlist.h"

static bool test_get_int(struct torture_context *tctx)
{
	struct parmlist *pctx = talloc_zero(tctx, struct parmlist);
	parmlist_set_string(pctx, "bar", "3");
	parmlist_set_string(pctx, "notint", "bla");
	torture_assert_int_equal(3, parmlist_get_int(pctx, "bar", 42));
	torture_assert_int_equal(42, parmlist_get_int(pctx, "foo", 42),
							 "default");
	torture_assert_int_equal(0, parmlist_get_int(pctx, "notint", 42)
							 "Not an integer");
	return true;
}

struct torture_suite *torture_local_util_parmlist(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "PARMLIST");

	torture_suite_add_simple_test(suite, "get_int", test_get_int);

	return suite;
}
