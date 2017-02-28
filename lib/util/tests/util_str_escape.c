/*

   util_str_escape testing

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2017

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
#include "torture/torture.h"
#include "torture/local/proto.h"
#include "lib/util/util_str_escape.h"

static bool test_log_escape_empty_string(struct torture_context *tctx)
{
	char *result = log_escape( tctx, "");
	torture_assert_str_equal(tctx, result, "", "Empty string handling");
	return true;
}

static bool test_log_escape_null_string(struct torture_context *tctx)
{
	char *result = log_escape( tctx, NULL);
	torture_assert(tctx, (result == NULL), "Empty string handling");
	return true;
}

static bool test_log_escape_plain_string(struct torture_context *tctx)
{
	const char *input    = "a plain string with no escapable characters";
	const char *expected = "a plain string with no escapable characters";

	char *result = log_escape( tctx, input);
	torture_assert_str_equal(tctx, result, expected,
				 "Plain string handling");
	return true;
}

static bool test_log_escape_string(struct torture_context *tctx)
{
	const char *input    = "\a\b\f\n\r\t\v\\\x01";
	const char *expected = "\\a\\b\\f\\n\\r\\t\\v\\\\\\x01";

	char *result = log_escape( tctx, input);
	torture_assert_str_equal(tctx, result, expected,
				 "Escapable characters in string");
	return true;
}

static bool test_log_escape_hex_string(struct torture_context *tctx)
{
	const char *input    = "\x01\x1F ";
	const char *expected = "\\x01\\x1F ";

	char *result = log_escape( tctx, input);
	torture_assert_str_equal(tctx, result, expected,
				 "hex escaping");
	return true;
}
struct torture_suite *torture_local_util_str_escape(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx,
							   "util_str_escape");

	torture_suite_add_simple_test(suite, "log_escape_empty_string",
				      test_log_escape_empty_string);
	torture_suite_add_simple_test(suite, "log_escape_null_string",
				      test_log_escape_null_string);
	torture_suite_add_simple_test(suite, "log_escape_plain_string",
				      test_log_escape_plain_string);
	torture_suite_add_simple_test(suite, "log_escape_string",
				      test_log_escape_string);
	torture_suite_add_simple_test(suite, "log_escape_hex_string",
				      test_log_escape_hex_string);


	return suite;
}
