/*
 * Tests exercising the ldb match operations.
 *
 *
 * Copyright (C) Catalyst.NET Ltd 2017
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
 *
 */

/*
 * from cmocka.c:
 * These headers or their equivalents should be included prior to
 * including
 * this header file.
 *
 * #include <stdarg.h>
 * #include <stddef.h>
 * #include <setjmp.h>
 *
 * This allows test applications to use custom definitions of C standard
 * library functions and types.
 */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../common/ldb_match.c"

#include "../include/ldb.h"

struct ldbtest_ctx {
	struct tevent_context *ev;
	struct ldb_context *ldb;
};

static int ldb_test_canonicalise(
	struct ldb_context *ldb,
	void *mem_ctx,
	const struct ldb_val *in,
	struct ldb_val *out)
{
	out->length = in->length;
	out->data = in->data;
	return 0;
}

static int setup(void **state)
{
	struct ldbtest_ctx *test_ctx;
	struct ldb_schema_syntax *syntax = NULL;
	int ret;

	test_ctx = talloc_zero(NULL, struct ldbtest_ctx);
	assert_non_null(test_ctx);

	test_ctx->ev = tevent_context_init(test_ctx);
	assert_non_null(test_ctx->ev);

	test_ctx->ldb = ldb_init(test_ctx, test_ctx->ev);
	assert_non_null(test_ctx->ldb);

	syntax = talloc_zero(test_ctx, struct ldb_schema_syntax);
	assert_non_null(syntax);
	syntax->canonicalise_fn = ldb_test_canonicalise;

	ret = ldb_schema_attribute_add_with_syntax(
	    test_ctx->ldb, "a", LDB_ATTR_FLAG_FIXED, syntax);
	assert_int_equal(LDB_SUCCESS, ret);

	*state = test_ctx;
	return 0;
}

static int teardown(void **state)
{
	talloc_free(*state);
	return 0;
}


/*
 * The wild card pattern "attribute=*" is parsed as an LDB_OP_PRESENT operation
 * rather than a LDB_OP_????
 *
 * This test serves to document that behaviour, and to confirm that
 * ldb_wildcard_compare handles this case appropriately.
 */
static void test_wildcard_match_star(void **state)
{
	struct ldbtest_ctx *ctx = *state;
	bool matched = false;
	int ret;

	uint8_t value[] = "The value.......end";
	struct ldb_val val = {
		.data   = value,
		.length = (sizeof(value))
	};
	struct ldb_parse_tree *tree = ldb_parse_tree(ctx, "a=*");
	assert_non_null(tree);

	ret = ldb_wildcard_compare(ctx->ldb, tree, val, &matched);
	assert_false(matched);
	assert_int_equal(LDB_ERR_INAPPROPRIATE_MATCHING, ret);
}

/*
 * Test basic wild card matching
 *
 */
static void test_wildcard_match(void **state)
{
	struct ldbtest_ctx *ctx = *state;
	bool matched = false;

	uint8_t value[] = "The value.......end";
	struct ldb_val val = {
		.data   = value,
		.length = (sizeof(value))
	};
	struct ldb_parse_tree *tree = ldb_parse_tree(ctx, "objectClass=*end");
	assert_non_null(tree);

	ldb_wildcard_compare(ctx->ldb, tree, val, &matched);
	assert_true(matched);
}


/*
 * ldb_handler_copy and ldb_val_dup over allocate by one and add a trailing '\0'
 * to the data, to make them safe to use the C string functions on.
 *
 * However testing for the trailing '\0' is not the correct way to test for
 * the end of a value, the length should be checked instead.
 */
static void test_wildcard_match_end_condition(void **state)
{
	struct ldbtest_ctx *ctx = *state;
	bool matched = false;

	uint8_t value[] = "hellomynameisbobx";
	struct ldb_val val = {
		.data   = talloc_memdup(NULL, value, sizeof(value)),
		.length = (sizeof(value) - 2)
	};
	struct ldb_parse_tree *tree = ldb_parse_tree(ctx, "a=*hello*mynameis*bob");
	assert_non_null(tree);

	ldb_wildcard_compare(ctx->ldb, tree, val, &matched);
	assert_true(matched);
}

/*
 * Note: to run under valgrind use:
 *       valgrind \
 *           --suppressions=lib/ldb/tests/ldb_match_test.valgrind \
 *           bin/ldb_match_test
 */
int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(
			test_wildcard_match_star,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_wildcard_match,
			setup,
			teardown),
		cmocka_unit_test_setup_teardown(
			test_wildcard_match_end_condition,
			setup,
			teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
