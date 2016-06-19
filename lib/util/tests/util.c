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

#include "lib/util/samba_util.h"

struct test_trim_string_data {
	const char *desc;
	const char *in;
	const char *front;
	const char *back;
	const char *out;
	bool ret;
};

static const struct test_trim_string_data test_trim_string_data[] = {
	{
		.desc  = "All NULL",
		.in    = NULL,
		.front = NULL,
		.back  = NULL,
		.out   = NULL,
		.ret   = false,
	},
	{
		.desc  = "Input NULL",
		.in    = NULL,
		.front = "abc",
		.back  = "123",
		.out   = NULL,
		.ret   = false,
	},
	{
		.desc  = "Trim NULL",
		.in    = "abc",
		.front = NULL,
		.back  = NULL,
		.out   = "abc",
		.ret   = false,
	},
	{
		.desc  = "Trim empty",
		.in    = "abc",
		.front = "",
		.back  = "",
		.out   = "abc",
		.ret   = false,
	},
	{
		.desc  = "Trim front, non-matching",
		.in    = "abc",
		.front = "x",
		.back  = "",
		.out   = "abc",
		.ret   = false,
	},
	{
		.desc  = "Trim front, matches back",
		.in    = "abc",
		.front = "c",
		.back  = "",
		.out   = "abc",
		.ret   = false,
	},
	{
		.desc  = "Trim front, partial-match",
		.in    = "abc",
		.front = "ac",
		.back  = "",
		.out   = "abc",
		.ret   = false,
	},
	{
		.desc  = "Trim front, too long",
		.in    = "aaa",
		.front = "aaaa",
		.back  = "",
		.out   = "aaa",
		.ret   = false,
	},
	{
		.desc  = "Trim front, 1 char, 1x",
		.in    = "abc",
		.front = "a",
		.back  = "",
		.out   = "bc",
		.ret   = true,
	},
	{
		.desc  = "Trim front, 1 char, 2x",
		.in    = "aabc",
		.front = "a",
		.back  = "",
		.out   = "bc",
		.ret   = true,
	},
	{
		.desc  = "Trim front, 1 char, 3x",
		.in    = "aaabc",
		.front = "a",
		.back  = "",
		.out   = "bc",
		.ret   = true,
	},
	{
		.desc  = "Trim front, 1 char, matches all",
		.in    = "aaa",
		.front = "a",
		.back  = "",
		.out   = "",
		.ret   = true,
	},
	{
		.desc  = "Trim front, 2 chars, 1x",
		.in    = "abc",
		.front = "ab",
		.back  = "",
		.out   = "c",
		.ret   = true,
	},
	{
		.desc  = "Trim front, 2 chars, 2x",
		.in    = "ababc",
		.front = "ab",
		.back  = "",
		.out   = "c",
		.ret   = true,
	},
	{
		.desc  = "Trim front, 3 chars, matches all",
		.in    = "abc",
		.front = "abc",
		.back  = "",
		.out   = "",
		.ret   = true,
	},
	{
		.desc  = "Trim back, non-matching",
		.in    = "abc",
		.front = "",
		.back  = "x",
		.out   = "abc",
		.ret   = false,
	},
	{
		.desc  = "Trim back, matches front",
		.in    = "abc",
		.front = "",
		.back  = "a",
		.out   = "abc",
		.ret   = false,
	},
	{
		.desc  = "Trim back, partial-match",
		.in    = "abc",
		.front = "",
		.back  = "xc",
		.out   = "abc",
		.ret   = false,
	},
	{
		.desc  = "Trim back, too long",
		.in    = "aaa",
		.front = "",
		.back  = "aaaa",
		.out   = "aaa",
		.ret   = false,
	},
	{
		.desc  = "Trim back, 1 char, 1x",
		.in    = "abc",
		.front = "",
		.back  = "c",
		.out   = "ab",
		.ret   = true,
	},
	{
		.desc  = "Trim back, 1 char, 2x",
		.in    = "abcc",
		.front = "",
		.back  = "c",
		.out   = "ab",
		.ret   = true,
	},
	{
		.desc  = "Trim back, 1 char, 3x",
		.in    = "abccc",
		.front = "",
		.back  = "c",
		.out   = "ab",
		.ret   = true,
	},
	{
		.desc  = "Trim back, 1 char, matches all",
		.in    = "aaa",
		.front = "",
		.back  = "a",
		.out   = "",
		.ret   = true,
	},
	{
		.desc  = "Trim back, 2 chars, 1x",
		.in    = "abc",
		.front = "",
		.back  = "bc",
		.out   = "a",
		.ret   = true,
	},
	{
		.desc  = "Trim back, 2 chars, 2x",
		.in    = "abcbc",
		.front = "",
		.back  = "bc",
		.out   = "a",
		.ret   = true,
	},
	{
		.desc  = "Trim back, 3 chars, matches all",
		.in    = "abc",
		.front = "",
		.back  = "abc",
		.out   = "",
		.ret   = true,
	},
	{
		.desc  = "Trim both, non-matching",
		.in    = "abc",
		.front = "x",
		.back  = "y",
		.out   = "abc",
		.ret   = false,
	},
	{
		.desc  = "Trim both, reversed",
		.in    = "abc",
		.front = "c",
		.back  = "a",
		.out   = "abc",
		.ret   = false,
	},
	{
		.desc  = "Trim both, 1 char, 1x",
		.in    = "abc",
		.front = "a",
		.back  = "c",
		.out   = "b",
		.ret   = true,
	},
	{
		.desc  = "Trim both, 1 char, 2x",
		.in    = "aabcc",
		.front = "a",
		.back  = "c",
		.out   = "b",
		.ret   = true,
	},
	{
		.desc  = "Trim both, 1 char, 3x",
		.in    = "aaabccc",
		.front = "a",
		.back  = "c",
		.out   = "b",
		.ret   = true,
	},
	{
		.desc  = "Trim both, 1 char, matches all",
		.in    = "aaabbb",
		.front = "a",
		.back  = "b",
		.out   = "",
		.ret   = true,
	},
	{
		.desc  = "Trim both, 2 chars, 1x",
		.in    = "abxbc",
		.front = "ab",
		.back  = "bc",
		.out   = "x",
		.ret   = true,
	},
	{
		.desc  = "Trim both, 2 chars, 2x",
		.in    = "ababxyzbcbc",
		.front = "ab",
		.back  = "bc",
		.out   = "xyz",
		.ret   = true,
	},
	{
		.desc  = "Trim both, 2 chars, front matches, back doesn't",
		.in    = "abcde",
		.front = "ab",
		.back  = "xy",
		.out   = "cde",
		.ret   = true,
	},
	{
		.desc  = "Trim both, 2 chars, back matches, front doesn't",
		.in    = "abcde",
		.front = "xy",
		.back  = "de",
		.out   = "abc",
		.ret   = true,
	},
	{
		.desc  = "Trim back, 3 chars, matches all",
		.in    = "abcxyz",
		.front = "abc",
		.back  = "xyz",
		.out   = "",
		.ret   = true,
	},
};

static bool test_trim_string(struct torture_context *tctx)
{
	int j;
	for (j = 0; j < ARRAY_SIZE(test_trim_string_data); j++) {
		bool ret;
		const struct test_trim_string_data *d =
			&test_trim_string_data[j];
		char *str = talloc_strdup(tctx, d->in);
		torture_assert(tctx, d->in == NULL || str != NULL,
			       "Out of memory");

		torture_comment(tctx, "%s\n", d->desc);
		ret = trim_string(str, d->front, d->back);
		torture_assert(tctx, ret == d->ret,
			       "Incorrect return from trim_string()");
		if (d->out == NULL) {
			torture_assert(tctx, str == NULL, "Expected NULL");
		} else {
			torture_assert(tctx, str != NULL, "Expected non-NULL");
			torture_assert_str_equal(tctx, str, d->out,
						 "Incorrect output");
		}
		TALLOC_FREE(str);
	}

	return true;
}

struct torture_suite *torture_local_util(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite =
		torture_suite_create(mem_ctx, "util");

	torture_suite_add_simple_test(suite,
				      "trim_string",
				      test_trim_string);
	return suite;
}
