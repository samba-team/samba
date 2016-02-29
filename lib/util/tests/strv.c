/*
 * Tests for strv
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

static bool test_strv_empty(struct torture_context *tctx)
{
	/* NULL strv contains 0 entries */
	torture_assert_int_equal(tctx,
				 strv_count(NULL),
				 0,
				 "strv_count() on NULL failed");

	/* NULL strv has no next entry */
	torture_assert(tctx,
		       strv_next(NULL, NULL) == NULL,
		       "strv_next() on NULL failed");

	return true;
}

static bool test_strv_single(struct torture_context *tctx)
{
	const char *data = "foo";
	char *strv = NULL;
	char *t;
	int ret;

	/* Add an item */
	ret = strv_add(tctx, &strv, data);
	torture_assert(tctx, ret == 0, "strv_add() failed");

	/* Is there 1 item? */
	torture_assert_int_equal(tctx,
				 strv_count(strv), 1,
				 "strv_count() failed");

	/* Is the expected item the first one? */
	t = strv_next(strv, NULL);
	torture_assert(tctx,
		       strcmp(t, data) == 0,
		       "strv_next() failed");

	/* Can the expected item be found? */
	t = strv_find(strv, data);
	torture_assert(tctx,
		       strcmp(t, data) == 0,
		       "strv_next() failed");

	/* Delete it */
	strv_delete(&strv, t);

	/* Should have no items */
	torture_assert_int_equal(tctx,
				 strv_count(strv), 0,
				 "strv_count() failed");
	return true;
}

static bool test_strv_multi(struct torture_context *tctx)
{
	const char *data[] = { "foo", "bar", "", "samba", "x"};
	char *strv = NULL;
	char *t;
	int i, ret;
	const int num = ARRAY_SIZE(data);

	/* Add items */
	for (i = 0; i < num; i++) {
		ret = strv_add(tctx, &strv, data[i]);
		torture_assert(tctx, ret == 0, "strv_add() failed");
	}

	torture_assert_int_equal(tctx,
				 strv_count(strv), num,
				 "strv_count() failed");

	/* Check that strv_next() finds the expected values */
	t = NULL;
	for (i = 0; i < num; i++) {
		t = strv_next(strv, t);
		torture_assert(tctx,
			       strcmp(t, data[i]) == 0,
			       "strv_next() failed");
	}


	/* Check that strv_next() finds the expected values */
	t = NULL;
	for (i = 0; i < num; i++) {
		t = strv_next(strv, t);
		torture_assert(tctx,
			       strcmp(t, data[i]) == 0,
			       "strv_next() failed");
	}

	/* Find each item, delete it, check count */
	for (i = 0; i < num; i++) {
		t = strv_find(strv, data[i]);
		torture_assert(tctx,
			       strcmp(t, data[i]) == 0,
			       "strv_next() failed");
		strv_delete(&strv, t);
		torture_assert_int_equal(tctx,
					 strv_count(strv), num - i - 1,
					 "strv_delete() failed");
	}

	/* Add items */
	for (i = 0; i < num; i++) {
		ret = strv_add(tctx, &strv, data[i]);
		torture_assert(tctx, ret == 0, "strv_add() failed");
	}

	torture_assert_int_equal(tctx,
				 strv_count(strv), num,
				 "strv_count() failed");

	/* Find items in reverse, delete, check count */
	for (i = num - 1; i >= 0; i--) {
		t = strv_find(strv, data[i]);
		torture_assert(tctx,
			       strcmp(t, data[i]) == 0,
			       "strv_next() failed");
		strv_delete(&strv, t);
		torture_assert_int_equal(tctx,
					 strv_count(strv), i,
					 "strv_delete() failed");
	}

	return true;
}

/* Similar to above but only add/check first 2 chars of each string */
static bool test_strv_addn(struct torture_context *tctx)
{
	const char *data[] = { "foo", "bar", "samba" };
	char *strv = NULL;
	char *t;
	int i, ret;
	const int num = ARRAY_SIZE(data);

	/* Add first 2 chars of each item */
	for (i = 0; i < num; i++) {
		ret = strv_addn(tctx, &strv, data[i], 2);
		torture_assert(tctx, ret == 0, "strv_add() failed");
	}

	torture_assert_int_equal(tctx,
				 strv_count(strv), num,
				 "strv_count() failed");

	/* Check that strv_next() finds the expected values */
	t = NULL;
	for (i = 0; i < num; i++) {
		t = strv_next(strv, t);
		torture_assert(tctx,
			       strncmp(t, data[i], 2) == 0,
			       "strv_next() failed");
	}

	return true;
}

struct torture_suite *torture_local_util_strv(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "strv");

	torture_suite_add_simple_test(suite, "strv_empty",  test_strv_empty);
	torture_suite_add_simple_test(suite, "strv_single", test_strv_single);
	torture_suite_add_simple_test(suite, "strv_multi",  test_strv_multi);
	torture_suite_add_simple_test(suite, "strv_addn",   test_strv_addn);

	return suite;
}
