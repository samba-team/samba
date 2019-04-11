/*
 * Tests exercising the ldb parse operations.
 *
 * Copyright (C) Catalyst.NET Ltd 2017
 * Copyright (C) Michael Hanselmann 2019
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

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../include/ldb.h"

struct test_ctx
{
};

static int setup(void **state)
{
	struct test_ctx *ctx;

	ctx = talloc_zero(NULL, struct test_ctx);
	assert_non_null(ctx);

	*state = ctx;

	return 0;
}

static int teardown(void **state)
{
	struct test_ctx *ctx =
		talloc_get_type_abort(*state, struct test_ctx);

	talloc_free(ctx);

	return 0;
}

static void test_roundtrip(TALLOC_CTX *mem_ctx, const char *filter, const char *expected)
{
	struct ldb_parse_tree *tree;
	char *serialized;

	assert_non_null(filter);
	assert_non_null(expected);

	tree = ldb_parse_tree(mem_ctx, filter);
	assert_non_null(tree);

	serialized = ldb_filter_from_tree(mem_ctx, tree);
	assert_non_null(serialized);

	assert_string_equal(serialized, expected);
}

static void test_parse_filtertype(void **state)
{
	struct test_ctx *ctx =
		talloc_get_type_abort(*state, struct test_ctx);

	test_roundtrip(ctx, "", "(|(objectClass=*)(distinguishedName=*))");
	test_roundtrip(ctx, "a=value", "(a=value)");
	test_roundtrip(ctx, "(|(foo=bar)(baz=hello))", "(|(foo=bar)(baz=hello))");
	test_roundtrip(ctx, " ", "(|(objectClass=*)(distinguishedName=*))");
}

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_parse_filtertype, setup, teardown),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
