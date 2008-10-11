/* 
   Unix SMB/CIFS implementation.

   data blob testing

   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2008
   
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

static bool test_string(struct torture_context *tctx)
{
	DATA_BLOB blob = data_blob_string_const("bla");	

	torture_assert_int_equal(tctx, blob.length, 3, "blob length");
	torture_assert_str_equal(tctx, blob.data, "bla", "blob data");

	data_blob_free(&blob);

	return true;
}

struct torture_suite *torture_local_util_data_blob(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "DATABLOB");

	torture_suite_add_simple_test(suite, "string", test_string);

	return suite;
}
