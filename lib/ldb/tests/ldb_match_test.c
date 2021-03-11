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

static void escape_string(uint8_t *buf, size_t buflen,
			  const uint8_t *s, size_t len)
{
	size_t i;
	size_t j = 0;
	for (i = 0; i < len; i++) {
		if (j == buflen - 1) {
			goto fin;
		}
		if (s[i] >= 0x20) {
			buf[j] = s[i];
			j++;
		} else {
			if (j >= buflen - 4) {
				goto fin;
			}
			/* utf-8 control char representation */
			buf[j] = 0xE2;
			buf[j + 1] = 0x90;
			buf[j + 2] = 0x80 + s[i];
			j+= 3;
		}
	}
fin:
	buf[j] = 0;
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
struct wildcard_test {
	uint8_t *val;
	size_t val_size;
	const char *search;
	bool should_match;
	bool fold;
};

/*
 * Q: Why this macro rather than plain struct values?
 * A: So we can get the size of the const char[] value while it is still a
 * true array, not a pointer.
 *
 * Q: but why not just use strlen?
 * A: so values can contain '\0', which we supposedly allow.
 */

#define TEST_ENTRY(val, search, should_match, fold)	\
	{						\
		(uint8_t*)discard_const(val),		\
		sizeof(val) - 1,			\
		search,					\
		should_match,				\
		fold					\
	 }

static void test_wildcard_match(void **state)
{
	struct ldbtest_ctx *ctx = *state;
	size_t failed = 0;
	size_t i;
	struct wildcard_test tests[] = {
		TEST_ENTRY("                     1  0", "1*0*", true, true),
		TEST_ENTRY("                     1  0", "1 *0", true, true),
		TEST_ENTRY("The value.......end", "*end", true, true),
		TEST_ENTRY("The value.......end", "*fend", false, true),
		TEST_ENTRY("The value.......end", "*eel", false, true),
		TEST_ENTRY("The value.......end", "*d", true, true),
		TEST_ENTRY("The value.......end", "*D*", true, true),
		TEST_ENTRY("The value.......end", "*e*d*", true, true),
		TEST_ENTRY("end", "*e*d*", true, true),
		TEST_ENTRY("end", "  *e*d*", true, true),
		TEST_ENTRY("1.0..0.0.0.0.0.0.0aAaaaAAAAAAA", "*a", true,  true),
		TEST_ENTRY("1.0.0.0.0.0.0.0.0.0.0aaaa", "*aaaaa", false, true),
		TEST_ENTRY("1.0.0.0.0.0.0.0.0.0.0", "*0.0", true, true),
		TEST_ENTRY("1.0.0.0.0.0.0.0.0.0", "1*0*0*0*0*0*0*0*0*0", true,
			   true),
		TEST_ENTRY("1.0.0.0.0.0.0.0.0", "1*0*0*0*0*0*0*0*0*0", false,
			   true),
		TEST_ENTRY("1.0.0.0.000.0.0.0.0", "1*0*0*0*0*0*0*0*0*0", true,
			   true),
		TEST_ENTRY("1\n0\r0\t000.0.0.0.0", "1*0*0*0*0*0*0*0*0", true,
			   true),
		/*
		 *  We allow NUL bytes and redundant spaces in non-casefolding
		 *  syntaxes.
		 */
		TEST_ENTRY("                  1  0", "*1  0", true, false),
		TEST_ENTRY("                  1  0", "*1  0", true, false),
		TEST_ENTRY("1    0", "*1 0", false, false),
		TEST_ENTRY("1\x00 x", "1*x", true, false),
		TEST_ENTRY("1\x00 x", "*x", true, false),
		TEST_ENTRY("1\x00 x", "*x*", true, false),
		TEST_ENTRY("1\x00 x", "* *", true, false),
		TEST_ENTRY("1\x00 x", "1*", true, false),
		TEST_ENTRY("1\x00 b* x", "1*b*", true, false),
		TEST_ENTRY("1.0..0.0.0.0.0.0.0aAaaaAAAAAAA", "*a", false,  false),
	};

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		bool matched;
		int ret;
		struct ldb_val val = {
			.data   = (uint8_t *)tests[i].val,
			.length = tests[i].val_size
		};
		const char *attr = tests[i].fold ? "objectclass" : "birthLocation";
		const char *s = talloc_asprintf(ctx, "%s=%s",
						attr, tests[i].search);
		struct ldb_parse_tree *tree = ldb_parse_tree(ctx, s);
		assert_non_null(tree);
		ret = ldb_wildcard_compare(ctx->ldb, tree, val, &matched);
		if (ret != LDB_SUCCESS) {
			uint8_t buf[100];
			escape_string(buf, sizeof(buf),
				      tests[i].val, tests[i].val_size);
			print_error("%zu val: «%s», search «%s» FAILED with %d\n",
				    i, buf, tests[i].search, ret);
			failed++;
		}
		if (matched != tests[i].should_match) {
			uint8_t buf[100];
			escape_string(buf, sizeof(buf),
				      tests[i].val, tests[i].val_size);
			print_error("%zu val: «%s», search «%s» should %s\n",
				    i, buf, tests[i].search,
				    matched ? "not match" : "match");
			failed++;
		}
	}
	if (failed != 0) {
		fail_msg("wrong results for %zu/%zu wildcard searches\n",
			 failed, ARRAY_SIZE(tests));
	}
}

#undef TEST_ENTRY


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
