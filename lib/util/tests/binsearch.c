/*
   Unix SMB/CIFS implementation.

   Tests for binsearch.h macros.

   Copyright Catalyst IT 2016.

   Written by Douglas Bagnall <douglas.bagnall@catalyst.net.nz>

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
#include "lib/util/binsearch.h"
#include "torture/torture.h"
#include "torture/local/proto.h"

static int int_cmp(int a, int b)
{
	return a - b;
}

static int int_cmp_p(int a, int *b)
{
	return a - *b;
}

static bool test_binsearch_v(struct torture_context *tctx)
{
	int array[] = { -11, -7, 0, 1, 723, 1000000};
	int misses[] = { -121, 17, -10, 10, -1, -723, 1000002};
	int i;
	int *result = NULL;

	for (i = 0; i < ARRAY_SIZE(misses); i++) {
		BINARY_ARRAY_SEARCH_V(array, ARRAY_SIZE(array),
				      misses[i], int_cmp, result);
		torture_comment(tctx, "looking for misses[%d] == %d\n", i, misses[i]);
		torture_assert(tctx, result == NULL, "failed to miss");
	}

	for (i = 0; i < ARRAY_SIZE(array); i++) {
		BINARY_ARRAY_SEARCH_V(array, ARRAY_SIZE(array),
				      array[i], int_cmp, result);
		torture_comment(tctx, "looking for array[%d] == %d, %p; got %p\n",
				i, array[i], &array[i], result);
		torture_assert(tctx, result == &array[i],
			       "failed to find element");
	}
	return true;
}

static bool test_binsearch_gte(struct torture_context *tctx)
{
	int array[] = { -11, -7, -7, -7, -1, 0, 0, 1, 723, 723, 723,
			724, 724, 10000};
	size_t a_len = ARRAY_SIZE(array);
	int targets[] = { -121, -8, -7, -6, 17, -10, 10, -1, 723,
			  724, 725, 10002, 10000, 0, -11, 1, 11};
	int i, j, target;
	int *result = NULL, *next = NULL;

	for (i = 0; i < ARRAY_SIZE(targets); i++) {
		target = targets[i];
		torture_comment(tctx, "looking for targets[%d] %d\n",
				i, target);

		BINARY_ARRAY_SEARCH_GTE(array, a_len, target,
					int_cmp_p, result, next);

		if (result == NULL) {
			/* we think there is no exact match */
			for (j = 0; j < a_len; j++) {
				if (target == array[j]) {
					torture_comment(tctx,
							"failed to find %d\n",
							targets[i]);
					torture_fail(tctx,
						     "result is wrongly NULL");
				}
			}
			if (next != NULL) {
				torture_assert(tctx, (next >= array &&
						      next < array + a_len),
					       "next is out of bounds");

				torture_assert(tctx, *next > target,
					       "next <= target");
				if (target <= array[0]) {
					torture_assert(tctx, next == array,
						       "search before start failed");
				}
				if (next != array) {
					torture_assert(tctx, next[-1] < target,
						       "next[-1] >= target");
				}
			}
			else {
				torture_assert(tctx, array[a_len - 1] < target,
					       "next was not found\n");
			}
		} else {
			/* we think we found an exact match */
			torture_assert(tctx, *result == target,
				       "result has wrong value");

			torture_assert(tctx, (result >= array &&
					      result < array + a_len),
				       "result is out of bounds!");

			torture_assert(tctx, next == NULL,
				       "next should be NULL on exact match\n");
			if (result != array) {
				torture_assert(tctx, result[-1] != target,
					       "didn't find first target\n");
			}
		}
		if (target >= array[a_len - 1]) {
			torture_assert(tctx, next == NULL,
				       "next is not NULL at array end\n");
		}
	}

	/* try again, with result and next the same pointer */
	for (i = 0; i < ARRAY_SIZE(targets); i++) {
		target = targets[i];
		torture_comment(tctx, "looking for targets[%d] %d\n",
				i, target);

		BINARY_ARRAY_SEARCH_GTE(array, a_len, target,
					int_cmp_p, result, result);

		if (result == NULL) {
			/* we think the target is greater than all elements */
			torture_assert(tctx, array[a_len - 1] < target,
				       "element >= target not found\n");
		} else {
			/* we think an element is >= target */
			torture_assert(tctx, *result >= target,
				       "result has wrong value");

			torture_assert(tctx, (result >= array &&
					      result < array + a_len),
				       "result is out of bounds!");

			if (result != array) {
				torture_assert(tctx, result[-1] < target,
					       "didn't find first target\n");
			}
		}
	}

	return true;
}

struct torture_suite *torture_local_util_binsearch(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "binsearch");
	torture_suite_add_simple_test(suite, "binsearch_v", test_binsearch_v);
	torture_suite_add_simple_test(suite, "binsearch_gte", test_binsearch_gte);
	return suite;
}
