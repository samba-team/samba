/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) 2019      Michael Hanselmann <public@hansmi.ch>
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

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "includes.h"
#include "./lib.h"

struct test_ctx {
};

static int setup_context(void **state)
{
	struct test_ctx *test_ctx;

	test_ctx = talloc_zero(NULL, struct test_ctx);
	assert_non_null(test_ctx);

	*state = test_ctx;

	return 0;
}

static int teardown_context(void **state)
{
	struct test_ctx *test_ctx =
		talloc_get_type_abort(*state, struct test_ctx);

	talloc_free(test_ctx);

	return 0;
}

static struct schema_conv process_data_blob(void **state, DATA_BLOB input)
{
	struct test_ctx *test_ctx =
		talloc_get_type_abort(*state, struct test_ctx);
	struct conv_options opt;
	struct schema_conv ret;

	assert_non_null(test_ctx);
	assert_non_null(input.data);

	opt.in = fmemopen(input.data, input.length, "r");
	opt.out = fopen("/dev/null", "w");
	opt.ldb_ctx = ldb_init(test_ctx, NULL);

	assert_non_null(opt.in);
	assert_non_null(opt.out);
	assert_non_null(opt.ldb_ctx);

	opt.basedn = ldb_dn_new(test_ctx, opt.ldb_ctx, "");

	assert_non_null(opt.basedn);

	ret = process_file(test_ctx, &opt);

	fclose(opt.in);
	fclose(opt.out);

	return ret;
}

static void test_unknown_syntax_oid(void **state)
{
	struct schema_conv ret;

	ret = process_data_blob(state, data_blob_string_const(
		"attributetype ( 999.555.999.555.999\n"
		"NAME 'mailLocalAddress'\n"
		"DESC 'RFC822 email address of this recipient'\n"
		"EQUALITY caseIgnoreIA5Match\n"
		"SYNTAX 999.555.999.555.999{256} )\n"
	));

	assert_int_equal(ret.count, 1);
	assert_int_equal(ret.failures, 1);
}

static void test_unterminated_token_value(void **state)
{
	struct schema_conv ret;

	ret = process_data_blob(state, data_blob_string_const(
		"attributetype ( 2.16.840.1.113730.3.1.47\n"
		"\tNAME 'mailRoutingAX 1.3.6.1.4.1.1466.115.121.1.26{256}\n"
		"\tSI GLE-VALUE )\n"
	));

	assert_int_equal(ret.count, 1);
	assert_int_equal(ret.failures, 1);
}

static void test_unterminated_must_value(void **state)
{
	struct schema_conv ret;

	ret = process_data_blob(state, data_blob_string_const(
		"attributetype ( 1\n"
		"\tSYNTAX 1./)# MUST ( foobar $\n"
	));

	assert_int_equal(ret.count, 1);
	assert_int_equal(ret.failures, 1);
}

static void test_unterminated_may_value(void **state)
{
	struct schema_conv ret;

	ret = process_data_blob(state, data_blob_string_const(
		"attributetype ( 1\n"
		"\tSYNTAX 1.3.6.1.4.1.1466.115.121.1./)# MAY ( javaClassNames $\n"
	));

	assert_int_equal(ret.count, 1);
	assert_int_equal(ret.failures, 1);
}

static void test_unterminated_sup_value(void **state)
{
	struct schema_conv ret;

	ret = process_data_blob(state, data_blob_string_const(
		"attributetype ( 1\n"
		"\tSYNTAX 1./)# SUP ( foobar $\n"
	));

	assert_int_equal(ret.count, 1);
	assert_int_equal(ret.failures, 1);
}

static void test_unknown_token(void **state)
{
	struct schema_conv ret;

	ret = process_data_blob(state, data_blob_string_const(
		"attributetype ( 1\n"
		"\tFOOBAR 123\n"
		" )\n"
	));

	assert_int_equal(ret.count, 1);
	assert_int_equal(ret.failures, 1);
}

static void test_missing_name(void **state)
{
	struct schema_conv ret;

	ret = process_data_blob(state, data_blob_string_const(
		"objectclass ( 1.3.6.3.6.1.4.1.1466.115.121.1.26{256} )"
	));

	assert_int_equal(ret.count, 1);
	assert_int_equal(ret.failures, 1);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_unknown_syntax_oid,
						setup_context,
						teardown_context),
		cmocka_unit_test_setup_teardown(test_unterminated_token_value,
						setup_context,
						teardown_context),
		cmocka_unit_test_setup_teardown(test_unterminated_must_value,
						setup_context,
						teardown_context),
		cmocka_unit_test_setup_teardown(test_unterminated_may_value,
						setup_context,
						teardown_context),
		cmocka_unit_test_setup_teardown(test_unterminated_sup_value,
						setup_context,
						teardown_context),
		cmocka_unit_test_setup_teardown(test_unknown_token,
						setup_context,
						teardown_context),
		cmocka_unit_test_setup_teardown(test_missing_name,
						setup_context,
						teardown_context),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
