/*
   Unix SMB/CIFS implementation.
   test suite for the util_unistr utility functions

   Copyright (C) Catalyst.Net Ltd. 2023

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

#undef strcasecmp
#undef strncasecmp

struct torture_suite *torture_local_util_unistr(TALLOC_CTX *mem_ctx);

static bool test_utf16_len(struct torture_context *tctx)
{
	static const uint16_t empty_string[] = {'\0'};
	static const uint16_t foo_bar[] = {
		'f', 'o', 'o', ' ', 'b', 'a', 'r', '\0'};
	static const uint16_t foo_bar_alternative[] = {0xd83c,
						       0xdd75,
						       0xd83c,
						       0xdd7e,
						       0xd83c,
						       0xdd7e,
						       ' ',
						       0xd83c,
						       0xdd31,
						       0xd83c,
						       0xdd30,
						       0xd83c,
						       0xdd41,
						       '\0'};

	torture_assert_size_equal(tctx,
				  utf16_len(empty_string),
				  0,
				  "length of empty string");
	torture_assert_size_equal(tctx,
				  utf16_null_terminated_len(empty_string),
				  2,
				  "null‐terminated length of empty string");
	torture_assert_size_equal(tctx,
				  utf16_len(foo_bar),
				  14,
				  "length of “foo bar”");
	torture_assert_size_equal(tctx,
				  utf16_null_terminated_len(foo_bar),
				  16,
				  "null‐terminated length of “foo bar”");
	torture_assert_size_equal(tctx,
				  utf16_len(foo_bar_alternative),
				  26,
				  "length of “🅵🅾🅾 🄱🄰🅁”");
	torture_assert_size_equal(tctx,
				  utf16_null_terminated_len(
					  foo_bar_alternative),
				  28,
				  "null‐terminated length of “🅵🅾🅾 🄱🄰🅁”");

	return true;
}

static bool test_utf16_len_n(struct torture_context *tctx)
{
	static const uint16_t empty_string[] = {'\0'};
	static const uint16_t foo_bar[] = {'f', 'o', 'o', ' ', 'b', 'a', 'r'};
	static const uint16_t null_terminated_foo_bar[] = {
		'f', 'o', 'o', ' ', 'b', 'a', 'r', '\0'};
	static const uint16_t twice_null_terminated_abc[] = {
		'a', 'b', 'c', '\0', '\0'};

	torture_assert_size_equal(tctx,
				  utf16_len_n(empty_string, 0),
				  0,
				  "length of empty string");
	torture_assert_size_equal(tctx,
				  utf16_null_terminated_len_n(empty_string, 0),
				  0,
				  "null‐terminated length of empty string");

	torture_assert_size_equal(tctx,
				  utf16_len_n(empty_string,
					      sizeof empty_string),
				  0,
				  "length of null‐terminated empty string");
	torture_assert_size_equal(
		tctx,
		utf16_null_terminated_len_n(empty_string, sizeof empty_string),
		2,
		"null‐terminated length of null‐terminated empty string");

	torture_assert_size_equal(tctx,
				  utf16_len_n(foo_bar, sizeof foo_bar),
				  14,
				  "length of “foo bar”");
	torture_assert_size_equal(tctx,
				  utf16_null_terminated_len_n(foo_bar,
							      sizeof foo_bar),
				  14,
				  "null‐terminated length of “foo bar”");

	torture_assert_size_equal(tctx,
				  utf16_len_n(null_terminated_foo_bar,
					      sizeof null_terminated_foo_bar),
				  14,
				  "length of null‐terminated “foo bar”");
	torture_assert_size_equal(
		tctx,
		utf16_null_terminated_len_n(null_terminated_foo_bar,
					    sizeof null_terminated_foo_bar),
		16,
		"null‐terminated length of null‐terminated “foo bar”");

	torture_assert_size_equal(tctx,
				  utf16_len_n(null_terminated_foo_bar,
					      sizeof null_terminated_foo_bar -
						      1),
				  14,
				  "length of “foo bar” minus one byte");
	torture_assert_size_equal(
		tctx,
		utf16_null_terminated_len_n(null_terminated_foo_bar,
					    sizeof null_terminated_foo_bar - 1),
		14,
		"null‐terminated length of “foo bar” minus one byte");

	torture_assert_size_equal(tctx,
				  utf16_len_n(twice_null_terminated_abc,
					      sizeof twice_null_terminated_abc),
				  6,
				  "length of twice–null‐terminated “abc”");
	torture_assert_size_equal(
		tctx,
		utf16_null_terminated_len_n(twice_null_terminated_abc,
					    sizeof twice_null_terminated_abc),
		8,
		"null‐terminated length of twice–null‐terminated “abc”");

	return true;
}

struct torture_suite *torture_local_util_unistr(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx,
							   "util_unistr");

	torture_suite_add_simple_test(suite, "utf16_len", test_utf16_len);
	torture_suite_add_simple_test(suite, "utf16_len_n", test_utf16_len_n);

	return suite;
}
