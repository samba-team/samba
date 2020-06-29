/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) 2020      Andreas Schneider <asn@samba.org>
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

#include "lib/replace/replace.h"
#include <talloc.h>

#include "lib/util/util_paths.c"

static int setup(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	assert_non_null(mem_ctx);
	*state = mem_ctx;

	return 0;
}

static int teardown(void **state)
{
	TALLOC_CTX *mem_ctx = *state;
	TALLOC_FREE(mem_ctx);

    return 0;
}

static void test_get_user_home_dir(void **state)
{
	TALLOC_CTX *mem_ctx = *state;
	struct passwd *pwd = getpwuid(getuid());
	char *user;

	user = get_user_home_dir(mem_ctx);
	assert_non_null(user);
	assert_string_equal(user, pwd->pw_dir);

	TALLOC_FREE(user);
}

static void test_path_expand_tilde(void **state)
{
	TALLOC_CTX *mem_ctx = *state;
	char h[256] = {0};
	char *d = NULL;
	const char *user = NULL;
	char *home = NULL;

	user = getenv("USER");
	if (user == NULL){
		user = getenv("LOGNAME");
	}

	/* In certain CIs there no such variables */
	if (user == NULL) {
		struct passwd *pw = getpwuid(getuid());
		if (pw){
			user = pw->pw_name;
		}
	}

	home = getenv("HOME");
	assert_non_null(home);
	snprintf(h, sizeof(h), "%s/.cache", home);

	d = path_expand_tilde(mem_ctx, "~/.cache");
	assert_non_null(d);
	assert_string_equal(d, h);
	TALLOC_FREE(d);

	snprintf(h, sizeof(h), "%s/.cache/X~", home);
	d = path_expand_tilde(mem_ctx, "~/.cache/X~");
	assert_string_equal(d, h);
	TALLOC_FREE(d);

	d = path_expand_tilde(mem_ctx, "/guru/meditation");
	assert_non_null(d);
	assert_string_equal(d, "/guru/meditation");
	TALLOC_FREE(d);

	snprintf(h, sizeof(h), "~%s/.cache", user);
	d = path_expand_tilde(mem_ctx, h);
	assert_non_null(d);

	snprintf(h, sizeof(h), "%s/.cache", home);
	assert_string_equal(d, h);
	TALLOC_FREE(d);
}

int main(int argc, char *argv[])
{
	int rc;
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_get_user_home_dir),
		cmocka_unit_test(test_path_expand_tilde),
	};

	if (argc == 2) {
		cmocka_set_test_filter(argv[1]);
	}
	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	rc = cmocka_run_group_tests(tests, setup, teardown);

	return rc;
}
