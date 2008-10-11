/* 
   Unix SMB/CIFS implementation.

   util_strlist testing

   Copyright (C) Jelmer Vernooij 2005
   
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

static const char *test_lists_shell_strings[] = {
	"",
	"foo",
	"foo bar",
	"foo bar \"bla \"",
	"foo \"\" bla",
	"bla \"\"\"\" blie",
	NULL
};

static bool test_lists_shell(struct torture_context *tctx,
							 const void *test_data)
{
	const char *data = (const char *)test_data;
	const char **ret1, **ret2, *tmp;
	bool match = true;
	TALLOC_CTX *mem_ctx = tctx;

	ret1 = str_list_make_shell(mem_ctx, data, " ");
	tmp = str_list_join_shell(mem_ctx, ret1, ' ');
	ret2 = str_list_make_shell(mem_ctx, tmp, " ");

	if ((ret1 == NULL || ret2 == NULL) && ret2 != ret1) {
		match = false;
	} else {
		int j;
		for (j = 0; ret1[j] && ret2[j]; j++) {
			if (strcmp(ret1[j], ret2[j]) != 0) {
				match = false;
				break;
			}
		}

		if (ret1[j] || ret2[j])
			match = false;
	}

	torture_assert(tctx, match, talloc_asprintf(tctx, 
		"str_list_{make,join}_shell: Error double parsing, first run:\n%s\nSecond run: \n%s", data, tmp));
	return true;
}

static bool test_list_copy(struct torture_context *tctx)
{
	const char **result;
	const char *list[] = { "foo", "bar", NULL };
	const char *empty_list[] = { NULL };
	const char **null_list = NULL;

	result = (const char **)str_list_copy(tctx, list);
	torture_assert_int_equal(tctx, str_list_length(result), 2, "list length");
	torture_assert_str_equal(tctx, result[0], "foo", "element 0");
	torture_assert_str_equal(tctx, result[1], "bar", "element 1");
	torture_assert_str_equal(tctx, result[2], NULL, "element 2");

	result = (const char **)str_list_copy(tctx, empty_list);
	torture_assert_int_equal(tctx, str_list_length(result), 0, "list length");
	torture_assert_str_equal(tctx, result[0], NULL, "element 0");

	result = (const char **)str_list_copy(tctx, null_list);
	torture_assert(tctx, result == NULL, "result NULL");
	
	return true;
}

struct torture_suite *torture_local_util_strlist(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "STRLIST");
	int i;

	for (i = 0; test_lists_shell_strings[i]; i++) {
		torture_suite_add_simple_tcase_const(suite, "lists_shell",
				test_lists_shell, &test_lists_shell_strings[i]);
	}

	torture_suite_add_simple_test(suite, "list_copy", test_list_copy);

	return suite;
}
