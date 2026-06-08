/* 
   Unix SMB/CIFS implementation.

   util_str testing

   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
   
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

static bool test_string_sub_simple(struct torture_context *tctx)
{
	char tmp[100];
	strlcpy(tmp, "foobar", sizeof(tmp));
	string_sub(tmp, "foo", "bar", sizeof(tmp));
	torture_assert_str_equal(tctx, tmp, "barbar", "invalid sub");
	return true;
}

static bool test_string_sub_multiple(struct torture_context *tctx)
{
	char tmp[100];
	strlcpy(tmp, "fooblafoo", sizeof(tmp));
	string_sub(tmp, "foo", "bar", sizeof(tmp));
	torture_assert_str_equal(tctx, tmp, "barblabar", "invalid sub");
	return true;
}

static bool test_string_sub_longer(struct torture_context *tctx)
{
	char tmp[100];
	strlcpy(tmp, "foobla", sizeof(tmp));
	string_sub(tmp, "foo", "blie", sizeof(tmp));
	torture_assert_str_equal(tctx, tmp, "bliebla", "invalid sub");
	return true;
}

static bool test_string_sub_shorter(struct torture_context *tctx)
{
	char tmp[100];
	strlcpy(tmp, "foobla", sizeof(tmp));
	string_sub(tmp, "foo", "bl", sizeof(tmp));
	torture_assert_str_equal(tctx, tmp, "blbla", "invalid sub");
	return true;
}

static bool test_string_sub_special_char(struct torture_context *tctx)
{
	char tmp[100];
	strlcpy(tmp, "foobla", sizeof(tmp));
	string_sub(tmp, "foo", "%b;l", sizeof(tmp));
	torture_assert_str_equal(tctx, tmp, "_b_lbla", "invalid sub");
	return true;
}

static bool test_talloc_string_sub_simple(struct torture_context *tctx)
{
	char *t;
	
	t = talloc_string_sub(tctx, "foobla", "foo", "bl");

	torture_assert_str_equal(tctx, t, "blbla", "invalid sub");

	return true;
}

static bool test_talloc_string_sub_multiple(struct torture_context *tctx)
{
	char *t;
	
	t = talloc_string_sub(tctx, "fooblafoo", "foo", "aapnootmies");

	torture_assert_str_equal(tctx, t, "aapnootmiesblaaapnootmies", 
				 "invalid sub");

	return true;
}

/*
 * with these next three tests, the failure is that the pattern looks like
 * "+++" because the \x.. bytes encode a zero byte in UTF-8. If we are not
 * careful with these strings we will see crashes instead of failures.
 */

static bool test_talloc_string_sub_tricky_utf8_4(struct torture_context *tctx)
{
	const char string[] =  "++++--\xD8\xBB";
	const char pattern[] = "+++\xF0\x80\x80\x80++";
	const char replace[] = "...";

	char *t = talloc_string_sub(tctx, string, pattern, replace);
	torture_assert_str_equal(tctx, t, string,
				 "should reject 4 byte NUL char");
	talloc_free(t);
	return true;
}

static bool test_talloc_string_sub_tricky_utf8_3(struct torture_context *tctx)
{
	const char string[] =  "++++--\xD8\xBB";
	const char pattern[] = "+++\xE0\x80\x80++";
	const char replace[] = "...";

	char *t = talloc_string_sub(tctx, string, pattern, replace);
	torture_assert_str_equal(tctx, t, string,
				 "should reject 3 byte NUL char");
	talloc_free(t);
	return true;
}

static bool test_talloc_string_sub_tricky_utf8_2(struct torture_context *tctx)
{
	const char string[] =  "++++--\xD8\xBB";
	const char pattern[] = "+++\xC0\x80++";
	const char replace[] = "...";

	char *t = talloc_string_sub(tctx, string, pattern, replace);
	torture_assert_str_equal(tctx, t, string,
				 "should reject 2 byte NUL char");
	talloc_free(t);
	return true;
}

static const struct {
	const char *str;
	bool ok;
	uint64_t val;
} conv_str_size_tests[] = {
	/* plain integers, with and without a suffix */
	{ "0",			true,	0 },
	{ "1",			true,	1 },
	{ "16K",		true,	16384 },
	{ "2T",			true,	2199023255552ULL },
	{ "8P",			true,	9007199254740992ULL },
	{ "18446744073709551615", true,	UINT64_MAX },

	/* fractional values, truncated towards zero */
	{ "0.5K",		true,	512 },
	{ "1.5G",		true,	1610612736ULL },
	{ "14.5M",		true,	15204352ULL },
	{ "2.2T",		true,	2418925581107ULL },
	{ "1.0K",		true,	1024 },

	/* without a suffix a fraction is truncated away entirely */
	{ "1.5",		true,	1 },

	/*
	 * Only the first CONV_STR_SIZE_MAX_SCALE digits are looked at,
	 * the rest cannot influence the result.
	 */
	{ "3.999999999999999K",	true,	4095 },
	{ "1.0000000001K",	true,	1024 },

	/* a lower case suffix means the same thing */
	{ "1.5g",		true,	1610612736ULL },

	/* rejected input */
	{ "",			false,	0 },
	{ "M",			false,	0 },
	{ "-1",			false,	0 },
	{ ".",			false,	0 },
	{ "1.",			false,	0 },
	{ "1.0.0",		false,	0 },
	{ "1.5X",		false,	0 },

	/* a digit is required before the separator, as before */
	{ ".5K",		false,	0 },

	{ "0x10",		false,	0 },
	{ "nan",		false,	0 },
	{ "inf",		false,	0 },
	{ "16E",		false,	0 },
	{ "18446744073709551616", false, 0 },
	{ "16777216P",		false,	0 },

	/*
	 * A comma is not a decimal separator, no matter what
	 * LC_NUMERIC says.
	 */
	{ "1,5M",		false,	0 },
};

static bool test_conv_str_size_values(struct torture_context *tctx)
{
	uint64_t nullval = UINT64_MAX;
	size_t i;

	torture_assert(tctx, !conv_str_size_error(NULL, &nullval),
		       "NULL should not be accepted");

	for (i = 0; i < ARRAY_SIZE(conv_str_size_tests); i++) {
		const char *str = conv_str_size_tests[i].str;
		uint64_t val = UINT64_MAX;
		bool ok;

		ok = conv_str_size_error(str, &val);
		torture_assert_int_equal(tctx, ok, conv_str_size_tests[i].ok,
					 talloc_asprintf(tctx,
						"unexpected result for '%s'",
						str));
		if (!conv_str_size_tests[i].ok) {
			continue;
		}
		torture_assert_u64_equal(tctx, val, conv_str_size_tests[i].val,
					 talloc_asprintf(tctx,
						"unexpected value for '%s'",
						str));
	}

	return true;
}

/*
 * smbd runs setlocale(LC_ALL, "") via smb_init_locale(), so an smb.conf
 * must not parse differently depending on the locale smbd was started
 * in. Re-run the same table under a locale that uses a comma as its
 * decimal separator.
 */
static bool test_conv_str_size_locale(struct torture_context *tctx)
{
	static const char * const locales[] = {
		"de_DE.UTF-8", "de_DE.utf8", "de_DE", "fr_FR.UTF-8",
	};
	const char *old = NULL;
	char *saved = NULL;
	bool found = false;
	size_t i;
	bool ok;

	old = setlocale(LC_NUMERIC, NULL);
	saved = talloc_strdup(tctx, old != NULL ? old : "C");
	torture_assert(tctx, saved != NULL, "talloc_strdup failed");

	for (i = 0; i < ARRAY_SIZE(locales); i++) {
		if (setlocale(LC_NUMERIC, locales[i]) != NULL) {
			found = true;
			break;
		}
	}
	if (!found) {
		setlocale(LC_NUMERIC, saved);
		torture_skip(tctx, "no comma-decimal locale available");
	}

	ok = test_conv_str_size_values(tctx);

	setlocale(LC_NUMERIC, saved);

	return ok;
}




struct torture_suite *torture_local_util_str(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "str");

	torture_suite_add_simple_test(suite, "string_sub_simple", 
				      test_string_sub_simple);

	torture_suite_add_simple_test(suite, "string_sub_multiple", 
				      test_string_sub_multiple);

	torture_suite_add_simple_test(suite, "string_sub_shorter", 
				      test_string_sub_shorter);

	torture_suite_add_simple_test(suite, "string_sub_longer", 
				      test_string_sub_longer);

	torture_suite_add_simple_test(suite, "string_sub_special_chars", 
				      test_string_sub_special_char);

	torture_suite_add_simple_test(suite, "talloc_string_sub_simple",
				      test_talloc_string_sub_simple);

	torture_suite_add_simple_test(suite, "string_sub_talloc_multiple", 
				      test_talloc_string_sub_multiple);

	torture_suite_add_simple_test(suite,
				      "test_talloc_string_sub_tricky_utf8_4",
				      test_talloc_string_sub_tricky_utf8_4);

	torture_suite_add_simple_test(suite,
				      "test_talloc_string_sub_tricky_utf8_3",
				      test_talloc_string_sub_tricky_utf8_3);

	torture_suite_add_simple_test(suite,
				      "test_talloc_string_sub_tricky_utf8_2",
				      test_talloc_string_sub_tricky_utf8_2);

	torture_suite_add_simple_test(suite,
				      "conv_str_size",
				      test_conv_str_size_values);

	torture_suite_add_simple_test(suite,
				      "conv_str_size_locale",
				      test_conv_str_size_locale);

	return suite;
}
