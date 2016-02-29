/*
 * Tests for strv_util
 *
 * Copyright Martin Schwenke <martin@meltin.net> 2016
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <talloc.h>

#include "replace.h"

#include "libcli/util/ntstatus.h"
#include "torture/torture.h"
#include "lib/util/data_blob.h"
#include "torture/local/proto.h"

#include "lib/util/strv.h"
#include "lib/util/strv_util.h"

static bool test_strv_split_none(struct torture_context *tctx)
{
	char *strv = NULL;
	int ret;

	/* NULL has 0 entries */
	ret = strv_split(tctx, &strv, NULL, " ");
	torture_assert(tctx, ret == 0, "strv_split() on NULL failed");
	torture_assert_int_equal(tctx,
				 strv_count(strv),
				 0,
				 "strv_split() on NULL failed");
	TALLOC_FREE(strv);

	/* Empty string has 0 entries */
	ret = strv_split(tctx, &strv, "", " ");
	torture_assert(tctx, ret == 0, "strv_split() on NULL failed");
	torture_assert_int_equal(tctx,
				 strv_count(strv),
				 0,
				 "strv_split() on \"\" failed");
	TALLOC_FREE(strv);

	/* String containing only separators has 0 entries */
	ret = strv_split(tctx, &strv, "abcabcabc", "cba ");
	torture_assert(tctx, ret == 0, "strv_split() on NULL failed");
	torture_assert_int_equal(tctx,
				 strv_count(strv),
				 0,
				 "strv_split() on seps-only failed");
	TALLOC_FREE(strv);

	return true;
}

struct test_str_split_data {
	const char *in;
	const char *sep;
	const char *out[10]; /* Hardcoded maximum! */
};

static bool test_strv_split_some(struct torture_context *tctx)
{
	const struct test_str_split_data data[] = {
		{
			/* Single string */
			.in = "foo",
			.sep = " \t",
			.out = { "foo" }
		},
		{
			/* Single string, single leading separator */
			.in = " foo",
			.sep = " \t",
			.out = { "foo" }
		},
		{
			/* Single string, single trailing separator */
			.in = " foo",
			.sep = " \t",
			.out = { "foo" }
		},
		{
			/* Single string, lots of separators */
			.in = " \t foo\t ",
			.sep = " \t",
			.out = { "foo" }
		},
		{
			/* Multiple strings, many separators */
			.in = " \t foo   bar\t\tx\t        samba\t ",
			.sep = " \t",
			.out = { "foo", "bar", "x", "samba" }
		},
	};
	const char *t;
	char *strv = NULL;
	int j;

	for (j = 0; j < ARRAY_SIZE(data); j++) {
		int i, num, ret;
		const struct test_str_split_data *d = &data[j];

		num = 0;
		while (num < ARRAY_SIZE(d->out) && d->out[num] != NULL) {
			num++;
		}
		ret = strv_split(tctx, &strv, d->in, d->sep);
		torture_assert(tctx, ret == 0, "strv_split() on NULL failed");
		torture_assert_int_equal(tctx,
					 strv_count(strv),
					 num,
					 "strv_split() failed");
		t = NULL;
		for (i = 0; i < num; i++) {
			t = strv_next(strv, t);
			torture_assert(tctx,
				       strcmp(t, d->out[i]) == 0,
				       "strv_split() failed");
		}
		TALLOC_FREE(strv);
	}
	return true;
}

struct torture_suite *torture_local_util_strv_util(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite =
		torture_suite_create(mem_ctx, "strv_util");

	torture_suite_add_simple_test(suite,
				      "strv_split_none",
				      test_strv_split_none);
	torture_suite_add_simple_test(suite,
				      "strv_split_some",
				      test_strv_split_some);
	return suite;
}
