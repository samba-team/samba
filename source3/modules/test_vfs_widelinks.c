/*
 *  Unix SMB/CIFS implementation.
 *
 *  Unit test for widelinks path validator.
 *
 *  Copyright (C) Jeremy Allison 2020
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* Needed for static build to complete... */
#include "includes.h"
#include "smbd/smbd.h"
NTSTATUS vfs_widelinks_init(TALLOC_CTX *ctx);

#include "vfs_widelinks.c"
#include <cmocka.h>

struct str_test_values {
	const char *src_str;
	const char *dst_str;
} ;

/* As many nasty edge cases as I can think of.. */

static struct str_test_values examples[] = {
	{ "/", "/" },
	{ "/../../", "/" },
	{ "/foo/../", "/" },
	{ "/./././", "/" },
	{ "/./././.", "/" },
	{ "/.../././.", "/..." },
	{ "/./././.foo", "/.foo" },
	{ "/./././.foo.", "/.foo." },
	{ "/./././foo.", "/foo." },
	{ "/foo/bar/..", "/foo" },
	{ "/foo/bar/../baz/", "/foo/baz" },
	{ "////////////////", "/" },
	{ "/////////./././././.", "/" },
	{ "/./.././../.boo/../baz", "/baz" },
	{ "/a/component/path", "/a/component/path" },
	{ "/a/component/path/", "/a/component/path" },
	{ "/a/component/path/..", "/a/component" },
	{ "/a/component/../path/", "/a/path" },
	{ "///a/./././///component/../////path/", "/a/path" }
};

/*
 * Test our realpath resolution code.
 */
static void test_resolve_realpath_name(void **state)
{
	unsigned i;
	TALLOC_CTX *frame = talloc_stackframe();

	for (i = 0; i < ARRAY_SIZE(examples); i++) {
		char *test_dst = resolve_realpath_name(frame,
					examples[i].src_str);
		if (test_dst == NULL) {
			fail();
		}
		assert_string_equal(test_dst, examples[i].dst_str);
		TALLOC_FREE(test_dst);
	}
	TALLOC_FREE(frame);
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_resolve_realpath_name),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
