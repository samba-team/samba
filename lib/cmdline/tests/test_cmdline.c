/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) 2018-2019 Andreas Schneider <asn@samba.org>
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

#include "lib/cmdline/cmdline.h"

static void torture_cmdline_burn(void **state)
{
	char arg1[] = "-U Administrator%secret";
	char arg2[] = "--user=Administrator%secret";
	char arg3[] = "--user=Administrator%super%secret";
	char arg4[] = "--password=super%secret";

	char *argv[] = { arg1, arg2, arg3, arg4, NULL };
	int argc = 4;

	samba_cmdline_burn(argc, argv);

	assert_string_equal(arg1, "-U Administrator");
	assert_string_equal(arg2, "--user=Administrator");
	assert_string_equal(arg3, "--user=Administrator");
	assert_string_equal(arg4, "--password");
}

int main(int argc, char *argv[])
{
	int rc;
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(torture_cmdline_burn),
	};

	if (argc == 2) {
		cmocka_set_test_filter(argv[1]);
	}
	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	rc = cmocka_run_group_tests(tests, NULL, NULL);

	return rc;
}
