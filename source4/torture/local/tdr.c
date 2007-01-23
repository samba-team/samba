/* 
   Unix SMB/CIFS implementation.
   test suite for basic tdr functions

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
#include "torture/torture.h"
#include "lib/tdr/tdr.h"

static bool test_push_uint8(struct torture_context *tctx)
{
	uint8_t v = 4;
	struct tdr_push *tdr = talloc_zero(tctx, struct tdr_push);

	torture_assert_ntstatus_ok(tctx, tdr_push_uint8(tdr, &v), "push failed");
	torture_assert_int_equal(tctx, tdr->data.length, 1, "length incorrect");
	torture_assert_int_equal(tctx, tdr->data.data[0], 4, "data incorrect");
	return true;
}

static bool test_pull_uint8(struct torture_context *tctx)
{
	uint8_t d = 2;
	uint8_t l;
	struct tdr_pull tdr;
	tdr.data.data = &d;
	tdr.data.length = 1;
	tdr.offset = 0;
	tdr.flags = 0;
	torture_assert_ntstatus_ok(tctx, tdr_pull_uint8(&tdr, tctx, &l), 
							   "pull failed");
	torture_assert_int_equal(tctx, 1, tdr.offset, 
							 "offset invalid");
	return true;
}

struct torture_suite *torture_local_tdr(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "TDR");

	torture_suite_add_simple_test(suite, "pull_uint8", test_pull_uint8);
	torture_suite_add_simple_test(suite, "push_uint8", test_push_uint8);

	return suite;
}
