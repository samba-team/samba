/*
 * Tests for strv_util
 *
 * Copyright Martin Schwenke <martin@meltin.net> 2016
 * Copyright Christof Schmitt <cs@samba.org> 2018
 * Copyright Swen Schillig <swen@linux.ibm.com> 2019
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
#include "system/filesys.h"

#include "libcli/util/ntstatus.h"
#include "torture/torture.h"
#include "lib/util/data_blob.h"
#include "torture/local/proto.h"

#include "lib/util/samba_util.h"

#include "limits.h"
#include "string.h"

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

static bool test_directory_create_or_exist(struct torture_context *tctx)
{
	char *path = NULL, *new_path = NULL, *file_path = NULL;
	bool ret = true, b = true;
	int fd;
	NTSTATUS status;
	const mode_t perms = 0741;

	status = torture_temp_dir(tctx, "util_dir", &path);;
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"Creating test directory failed.\n");

	b = directory_create_or_exist(path, perms);
	torture_assert_goto(tctx, b == true, ret, done,
			    "directory_create_or_exist on "
			    "existing directory failed.\n");

	new_path = talloc_asprintf(tctx, "%s/%s", path, "dir");
	torture_assert_goto(tctx, new_path != NULL, ret, done,
			    "Could not allocate memory for directory path\n");

	b = directory_exist(new_path);
	torture_assert_goto(tctx, b == false, ret, done,
			    "Check for non-existing directory failed.\n");

	b = directory_create_or_exist(new_path, perms);
	torture_assert_goto(tctx, b == true, ret, done,
			    "directory_create_or_exist for "
			    "new directory failed.\n");

	b = directory_exist(new_path);
	torture_assert_goto(tctx, b == true, ret, done,
			    "Check for existing directory failed.\n");

	b = file_check_permissions(new_path, geteuid(), perms, NULL);
	torture_assert_goto(tctx, b == true, ret, done,
			    "Permission check for directory failed.\n");

	file_path = talloc_asprintf(tctx, "%s/%s", path, "file");
	torture_assert_goto(tctx, file_path != NULL, ret, done,
			    "Could not allocate memory for file path\n");
	fd = creat(file_path, perms);
	torture_assert_goto(tctx, fd != -1, ret, done,
			    "Creating file failed.\n");
	close(fd);

	b = directory_create_or_exist(file_path, perms);
	torture_assert_goto(tctx, b == false, ret, done,
			    "directory_create_or_exist for "
			    "existing file failed.\n");

done:
	return ret;
}

static bool test_smb_strtoul_errno_check(struct torture_context *tctx)
{
	const char *number = "123";
	unsigned long int val = 0;
	unsigned long long int vall = 0;
	int err;

	/* select an error code which is not set by the smb_strtoul routines */
	errno = EAGAIN;
	err = EAGAIN;
	val = smb_strtoul(number, NULL, 0, &err, SMB_STR_STANDARD);
	torture_assert(tctx, errno == EAGAIN, "smb_strtoul: Expected EAGAIN");
	torture_assert(tctx, err == 0, "smb_strtoul: Expected err = 0");
	torture_assert(tctx, val == 123, "smb_strtoul: Expected value 123");

	/* set err to an impossible value again before continuing */
	err = EAGAIN;
	vall = smb_strtoull(number, NULL, 0, &err, SMB_STR_STANDARD);
	torture_assert(tctx, errno == EAGAIN, "smb_strtoull: Expected EAGAIN");
	torture_assert(tctx, err == 0, "smb_strtoul: Expected err = 0");
	torture_assert(tctx, vall == 123, "smb_strtoul: Expected value 123");

	return true;
}

static bool test_smb_strtoul_negative(struct torture_context *tctx)
{
	const char *number = "-132";
	const char *number2 = "132-";
	unsigned long int val = 0;
	unsigned long long int vall = 0;
	int err;

	err = 0;
	smb_strtoul(number, NULL, 0, &err, SMB_STR_STANDARD);
	torture_assert(tctx, err == EINVAL, "smb_strtoul: Expected EINVAL");

	err = 0;
	smb_strtoull(number, NULL, 0, &err, SMB_STR_STANDARD);
	torture_assert(tctx, err == EINVAL, "smb_strtoull: Expected EINVAL");

	/* it is allowed to have a "-" sign after a number,
	 * e.g. as part of a formular, however, it is not supposed to
	 * have an effect on the converted value.
	 */

	err = 0;
	val = smb_strtoul(number2, NULL, 0, &err, SMB_STR_STANDARD);
	torture_assert(tctx, err == 0, "smb_strtoul: Expected no error");
	torture_assert(tctx, val == 132, "smb_strtoul: Wrong value");

	err = 0;
	vall = smb_strtoull(number2, NULL, 0, &err, SMB_STR_STANDARD);
	torture_assert(tctx, err == 0, "smb_strtoull: Expected no error");
	torture_assert(tctx, vall == 132, "smb_strtoull: Wrong value");

	return true;
}

static bool test_smb_strtoul_no_number(struct torture_context *tctx)
{
	const char *number = "ghijk";
	const char *blank = "";
	int err;

	err = 0;
	smb_strtoul(number, NULL, 0, &err, SMB_STR_STANDARD);
	torture_assert(tctx, err == EINVAL, "smb_strtoul: Expected EINVAL");

	err = 0;
	smb_strtoull(number, NULL, 0, &err, SMB_STR_STANDARD);
	torture_assert(tctx, err == EINVAL, "smb_strtoull: Expected EINVAL");

	err = 0;
	smb_strtoul(blank, NULL, 0, &err, SMB_STR_STANDARD);
	torture_assert(tctx, err == EINVAL, "smb_strtoul: Expected EINVAL");

	err = 0;
	smb_strtoull(blank, NULL, 0, &err, SMB_STR_STANDARD);
	torture_assert(tctx, err == EINVAL, "smb_strtoull: Expected EINVAL");

	return true;
}

static bool test_smb_strtoul_allow_negative(struct torture_context *tctx)
{
	const char *number = "-1";
	const char *number2 = "-1-1";
	unsigned long res = 0;
	unsigned long long res2 = 0;
	char *end_ptr = NULL;
	int err;

	err = 0;
	res = smb_strtoul(number, NULL, 0, &err, SMB_STR_ALLOW_NEGATIVE);
	torture_assert(tctx, err == 0, "strtoul_err: Unexpected error");
	torture_assert(tctx, res == ULONG_MAX, "strtoul_err: Unexpected value");

	err = 0;
	res2 = smb_strtoull(number, NULL, 0, &err, SMB_STR_ALLOW_NEGATIVE);
	torture_assert(tctx, err == 0, "strtoull_err: Unexpected error");
	torture_assert(tctx, res2 == ULLONG_MAX, "strtoull_err: Unexpected value");

	err = 0;
	smb_strtoul(number2, &end_ptr, 0, &err, SMB_STR_ALLOW_NEGATIVE);
	torture_assert(tctx, err == 0, "strtoul_err: Unexpected error");
	torture_assert(tctx, end_ptr[0] == '-', "strtoul_err: Unexpected end pointer");

	err = 0;
	smb_strtoull(number2, &end_ptr, 0, &err, SMB_STR_ALLOW_NEGATIVE);
	torture_assert(tctx, err == 0, "strtoull_err: Unexpected error");
	torture_assert(tctx, end_ptr[0] == '-', "strtoull_err: Unexpected end pointer");

	return true;
}

static bool test_smb_strtoul_full_string(struct torture_context *tctx)
{
	const char *number = "123 ";
	const char *number2 = "123";
	int err;

	err = 0;
	smb_strtoul(number, NULL, 0, &err, SMB_STR_FULL_STR_CONV);
	torture_assert(tctx, err == EINVAL, "strtoul_err: Expected EINVAL");

	err = 0;
	smb_strtoull(number, NULL, 0, &err, SMB_STR_FULL_STR_CONV);
	torture_assert(tctx, err == EINVAL, "strtoull_err: Expected EINVAL");

	err = 0;
	smb_strtoul(number2, NULL, 0, &err, SMB_STR_FULL_STR_CONV);
	torture_assert(tctx, err == 0, "strtoul_err: Unexpected error");

	err = 0;
	smb_strtoull(number2, NULL, 0, &err, SMB_STR_FULL_STR_CONV);
	torture_assert(tctx, err == 0, "strtoull_err: Unexpected error");

	return true;
}

static bool test_smb_strtoul_allow_no_conversion(struct torture_context *tctx)
{
	const char *number = "";
	const char *number2 = "xyz";
	unsigned long int n1 = 0;
	unsigned long long int n2 = 0;
	int err;

	err = 0;
	smb_strtoul(number, NULL, 0, &err, SMB_STR_ALLOW_NO_CONVERSION);
	torture_assert(tctx, err == 0, "strtoul_err: Unexpected error");
	torture_assert(tctx, n1 == 0, "strtoul_err: Unexpected value");

	err = 0;
	smb_strtoull(number, NULL, 0, &err, SMB_STR_ALLOW_NO_CONVERSION);
	torture_assert(tctx, err == 0, "strtoull_err: Unexpected error");
	torture_assert(tctx, n2 == 0, "strtoull_err: Unexpected value");

	err = 0;
	smb_strtoul(number2, NULL, 0, &err, SMB_STR_ALLOW_NO_CONVERSION);
	torture_assert(tctx, err == 0, "strtoul_err: Unexpected error");
	torture_assert(tctx, n1 == 0, "strtoul_err: Unexpected value");

	err = 0;
	smb_strtoull(number2, NULL, 0, &err, SMB_STR_ALLOW_NO_CONVERSION);
	torture_assert(tctx, err == 0, "strtoull_err: Unexpected error");
	torture_assert(tctx, n2 == 0, "strtoull_err: Unexpected value");

	return true;
}
struct torture_suite *torture_local_util(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite =
		torture_suite_create(mem_ctx, "util");

	torture_suite_add_simple_test(suite,
				      "trim_string",
				      test_trim_string);
	torture_suite_add_simple_test(suite,
				      "directory_create_or_exist",
				      test_directory_create_or_exist);
	torture_suite_add_simple_test(suite,
				      "smb_strtoul(l) errno",
				      test_smb_strtoul_errno_check);
	torture_suite_add_simple_test(suite,
				      "smb_strtoul(l) negative",
				      test_smb_strtoul_negative);
	torture_suite_add_simple_test(suite,
				      "smb_strtoul(l) no number",
				      test_smb_strtoul_no_number);
	torture_suite_add_simple_test(suite,
				      "smb_strtoul(l) allow_negative",
				      test_smb_strtoul_allow_negative);
	torture_suite_add_simple_test(suite,
				      "smb_strtoul(l) full string conversion",
				      test_smb_strtoul_full_string);
	torture_suite_add_simple_test(suite,
				      "smb_strtoul(l) allow no conversion",
				      test_smb_strtoul_allow_no_conversion);
	return suite;
}
