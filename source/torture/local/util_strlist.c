/* 
   Unix SMB/CIFS implementation.

   util_strlist testing

   Copyright (C) Jelmer Vernooij 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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

static BOOL test_lists_shell(struct torture_context *test, const void *_data)
{
	const char *data = _data;
	const char **ret1, **ret2, *tmp;
	BOOL match = True;

	ret1 = str_list_make_shell(test, data, " ");
	tmp = str_list_join_shell(test, ret1, ' ');
	ret2 = str_list_make_shell(test, tmp, " ");

	if ((ret1 == NULL || ret2 == NULL) && ret2 != ret1) {
		match = False;
	} else {
		int j;
		for (j = 0; ret1[j] && ret2[j]; j++) {
			if (strcmp(ret1[j], ret2[j]) != 0) {
				match = False;
				break;
			}
		}

		if (ret1[j] || ret2[j])
			match = False;
	}

	if (!match) {
		torture_fail(test, "str_list_{make,join}_shell: Error double parsing, first run:\n%s\nSecond run: \n%s", data, tmp);
		return False;
	}

	return True;
}

struct torture_suite *torture_local_util_strlist(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "LOCAL-STRLIST");
	int i;

	for (i = 0; test_lists_shell_strings[i]; i++) {
		torture_suite_add_simple_tcase(suite, 
									   "lists_shell", test_lists_shell,
									   &test_lists_shell_strings[i]);
	}

	return suite;
}
