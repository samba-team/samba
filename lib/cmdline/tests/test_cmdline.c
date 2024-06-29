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
#include <time.h>
#include <sys/time.h>
#include "replace.h"

#include "lib/cmdline/cmdline.h"

static void torture_cmdline_sanity_check_good(void **state)
{
	bool ok;
	struct poptOption long_options_good[] = {
		POPT_AUTOHELP
		POPT_COMMON_SAMBA
		POPT_COMMON_CONNECTION
		POPT_COMMON_CREDENTIALS
		POPT_COMMON_VERSION
		POPT_LEGACY_S3
		POPT_TABLEEND
	};

	ok = samba_cmdline_sanity_check(long_options_good);
	assert_true(ok);
}

static void torture_cmdline_sanity_check_bad(void **state)
{
	bool ok;

	struct poptOption long_options_bad[] = {
		POPT_AUTOHELP
		POPT_COMMON_SAMBA
		POPT_COMMON_SAMBA
		POPT_TABLEEND
	};

	ok = samba_cmdline_sanity_check(long_options_bad);
	assert_false(ok);
}

static void torture_cmdline_burn(void **state)
{
	 /* arg1 would require -U' Administrator%secret' */
	char arg1[] = "-U Administrator%secret";
	char arg2[] = "--no-no-no-not-secret=not%secret";
	char arg3[] = "--user=Administrator%secret";
	char arg4[] = "--user=Administrator%super%secret";
	char arg5[] = "--password=super%secret";
	char arg6[] = "--no-no-no-not-secret=not%secret";
	char arg7[] = "-U";
	char arg8[] = "fish%chips";
	char arg9[] = "--password";
	char arg10[] = "fish%chips";
	char arg11[] = "--password2";
	char arg12[] = "fish%chips";
	char arg13[] = "--username=Admonisher % secretest";
	/*
	 * The next two are not used in samba (--client-password
	 * appears in a Heimdal script that won't use lib/cmdline even
	 * if built) and are burnt by virtue of not being in the allow
	 * list.
	 */
	char arg14[] = "--client-password=bean stew";
	char arg15[] = "--enpassant="; /* like --enpassant='', no effect on affect next arg */
	char arg16[] = "bean";
	char arg17[] = "--bean=password";
	char arg18[] = "--name";
	char arg19[] = "Compass Alompass";

	char *argv[] = { arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
		arg9, arg10, arg11, arg12, arg13, arg14, arg15, arg16, arg17,
		arg18, arg19, NULL };
	int argc = ARRAY_SIZE(argv) - 1;

	samba_cmdline_burn(argc, argv);

	assert_string_equal(arg1, "-U Administrator");
	assert_string_equal(arg2, "--no-no-no-not-secret=not%secret");
	assert_string_equal(arg3, "--user=Administrator");
	assert_string_equal(arg4, "--user=Administrator");
	assert_string_equal(arg5, "--password");
	assert_string_equal(arg6, "--no-no-no-not-secret=not%secret");
	assert_string_equal(arg7, "-U");
	assert_string_equal(arg8, "fish");
	assert_string_equal(arg9, "--password");
	assert_string_equal(arg10, "");
	assert_string_equal(arg11, "--password2");
	assert_string_equal(arg12, "");
	assert_string_equal(arg13, "--username=Admonisher ");
	assert_string_equal(arg14, "--client-password");
	assert_string_equal(arg15, "--enpassant");
	assert_string_equal(arg16, "bean");
	assert_string_equal(arg17, "--bean=password");
	assert_string_equal(arg18, "--name");
	assert_string_equal(arg19, "Compass Alompass");
}

int main(int argc, char *argv[])
{
	int rc;
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(torture_cmdline_sanity_check_good),
		cmocka_unit_test(torture_cmdline_sanity_check_bad),
		cmocka_unit_test(torture_cmdline_burn),
	};

	if (argc == 2) {
		cmocka_set_test_filter(argv[1]);
	}
	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	rc = cmocka_run_group_tests(tests, NULL, NULL);

	return rc;
}
