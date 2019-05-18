/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) 2018      David Disseldorp <ddiss@samba.org>
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

#include <errno.h>

#include "lib/replace/replace.h"
#include "lib/util/samba_util.h"
#include "libcli/smb/smb_constants.h"

static void test_ms_fn_match_protocol_no_wildcard(void **state)
{
	int cmp;

	/* no wildcards in pattern, a simple strcasecmp_m */
	cmp = ms_fnmatch_protocol("pattern", "string", PROTOCOL_COREPLUS,
				  true);	/* case sensitive */
	assert_int_equal(cmp, -3);
}

static void test_ms_fn_match_protocol_pattern_upgraded(void **state)
{
	int cmp;

	/* protocol < PROTOCOL_NT1 pattern is "upgraded" */
	cmp = ms_fnmatch_protocol("??????", "string", PROTOCOL_COREPLUS,
				  false);
	assert_int_equal(cmp, 0);
}

static void test_ms_fn_match_protocol_match_zero_or_more(void **state)
{
	int cmp;

	/* '*' matches zero or more characters. handled via recursive calls */
	cmp = ms_fnmatch_protocol("********", "string", PROTOCOL_COREPLUS,
				  true);
	assert_int_equal(cmp, 0);
}

static void test_ms_fn_match_protocol_mapped_char(void **state)
{
	int cmp;

	/* '?' is mapped to '>', which matches any char or a '\0' */
	cmp = ms_fnmatch_protocol("???????", "string", PROTOCOL_COREPLUS,
				    false);
	assert_int_equal(cmp, 0);
}

static void test_ms_fn_match_protocol_nt1_any_char(void **state)
{
	int cmp;

	/* PROTOCOL_NT1 '?' matches any char, '\0' is not included */
	cmp = ms_fnmatch_protocol("???????", "string", PROTOCOL_NT1,
				  false);
	assert_int_equal(cmp, -1);
}

static void test_ms_fn_match_protocol_nt1_case_sensitive(void **state)
{
	int cmp;

	cmp = ms_fnmatch_protocol("StRinG", "string", PROTOCOL_NT1,
				  true);	/* case sensitive */
	assert_int_equal(cmp, 0);

	cmp = ms_fnmatch_protocol("StRin?", "string", PROTOCOL_NT1,
				  true);	/* case sensitive */
	assert_int_equal(cmp, -1);

	cmp = ms_fnmatch_protocol("StRin?", "string", PROTOCOL_NT1,
				  false);
	assert_int_equal(cmp, 0);
	cmp = ms_fnmatch_protocol("strin?", "string", PROTOCOL_NT1,
				  true);	/* case sensitive */
	assert_int_equal(cmp, 0);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_ms_fn_match_protocol_no_wildcard),
		cmocka_unit_test(test_ms_fn_match_protocol_pattern_upgraded),
		cmocka_unit_test(test_ms_fn_match_protocol_match_zero_or_more),
		cmocka_unit_test(test_ms_fn_match_protocol_mapped_char),
		cmocka_unit_test(test_ms_fn_match_protocol_nt1_any_char),
		cmocka_unit_test(test_ms_fn_match_protocol_nt1_case_sensitive),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
