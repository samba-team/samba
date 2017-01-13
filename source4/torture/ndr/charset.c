/*
   Unix SMB/CIFS implementation.
   test suite for charset ndr operations

   Copyright (C) Guenther Deschner 2017

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
#include "torture/ndr/proto.h"

static bool test_ndr_push_charset(struct torture_context *tctx)
{
	const char *strs[] = {
		NULL,
		"",
		"test"
	};
	int i;

	struct ndr_push *ndr;

	ndr = talloc_zero(tctx, struct ndr_push);

	for (i = 0; i < ARRAY_SIZE(strs); i++) {

		enum ndr_err_code expected_ndr_err = NDR_ERR_SUCCESS;

		if (strs[i] == NULL) {
			expected_ndr_err = NDR_ERR_INVALID_POINTER;
		}

		torture_assert_ndr_err_equal(tctx,
			ndr_push_charset(ndr, NDR_SCALARS, strs[i], 256, 2, CH_UTF16LE),
			expected_ndr_err,
			"failed to push charset");
	}

	return true;
}

static bool test_ndr_push_charset_to_null(struct torture_context *tctx)
{
	const char *strs[] = {
		NULL,
		"",
		"test"
	};
	int i;

	struct ndr_push *ndr;

	ndr = talloc_zero(tctx, struct ndr_push);


	for (i = 0; i < ARRAY_SIZE(strs); i++) {

		torture_assert_ndr_success(tctx,
			ndr_push_charset_to_null(ndr, NDR_SCALARS, strs[i], 256, 2, CH_UTF16LE),
			"failed to push charset to null");
	}

	return true;
}


struct torture_suite *ndr_charset_suite(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "charset");

	suite->description = talloc_strdup(suite, "NDR - charset focused push/pull tests");

	torture_suite_add_simple_test(suite, "push", test_ndr_push_charset);
	torture_suite_add_simple_test(suite, "push_to_null", test_ndr_push_charset_to_null);

	return suite;
}

