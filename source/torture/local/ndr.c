/* 
   Unix SMB/CIFS implementation.
   test suite for basic ndr functions

   Copyright (C) Jelmer Vernooij 2005
   
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
#include "librpc/ndr/libndr.h"

static bool test_check_string_terminator(struct torture_context *tctx)
{
	struct ndr_pull *ndr;
	DATA_BLOB blob;
	TALLOC_CTX *mem_ctx = tctx;

	/* Simple test */
	blob = strhex_to_data_blob("0000");
	
	ndr = ndr_pull_init_blob(&blob, mem_ctx);

	torture_assert_ntstatus_ok(tctx, ndr_check_string_terminator(ndr, 1, 2),
							   "simple check_string_terminator test failed");

	torture_assert(tctx, ndr->offset == 0,
		"check_string_terminator did not reset offset");

	if (NT_STATUS_IS_OK(ndr_check_string_terminator(ndr, 1, 3))) {
		torture_fail(tctx, "check_string_terminator checked beyond string boundaries");
	}

	torture_assert(tctx, ndr->offset == 0, 
		"check_string_terminator did not reset offset");

	talloc_free(ndr);

	blob = strhex_to_data_blob("11220000");
	ndr = ndr_pull_init_blob(&blob, mem_ctx);

	torture_assert_ntstatus_ok(tctx, 
		ndr_check_string_terminator(ndr, 4, 1),
		"check_string_terminator failed to recognize terminator");

	torture_assert_ntstatus_ok(tctx, 
		ndr_check_string_terminator(ndr, 3, 1),
		"check_string_terminator failed to recognize terminator");

	if (NT_STATUS_IS_OK(ndr_check_string_terminator(ndr, 2, 1))) {
		torture_fail(tctx, 
					 "check_string_terminator erroneously reported terminator");
	}

	torture_assert(tctx, ndr->offset == 0,
		"check_string_terminator did not reset offset");
	return true;
}

struct torture_suite *torture_local_ndr(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "NDR");

	torture_suite_add_simple_test(suite, "string terminator", 
								   test_check_string_terminator);

	return suite;
}
