/*
 *  Unix SMB/CIFS implementation.
 *
 *  Unit test for sys_rw.c
 *
 *  Copyright (C) Ralph Böhme 2021
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

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "lib/replace/replace.h"
#include "system/dir.h"

#include "lib/util/sys_rw.c"

static void test_sys_io_ranges_overlap(void **state)
{
	bool overlap;

	/*
	 * sys_io_ranges_overlap() args are:
	 *
	 * src size, src offset, dst size, dst offset
	 */

	/* src and dst size 0 => no overlap */
	overlap = sys_io_ranges_overlap(0, 0, 0, 0);
	assert_false(overlap);

	/* dst size 0 => no overlap */
	overlap = sys_io_ranges_overlap(1, 0, 0, 0);
	assert_false(overlap);

	/* src size 0 => no overlap */
	overlap = sys_io_ranges_overlap(0, 0, 1, 0);
	assert_false(overlap);

	/* same range => overlap */
	overlap = sys_io_ranges_overlap(1, 0, 1, 0);
	assert_true(overlap);

	/*
	 * |.|
	 *   |.|
	 * src before dst => no overlap
	 */
	overlap = sys_io_ranges_overlap(1, 0, 1, 1);
	assert_false(overlap);

	/*
	 * |..|
	 *  |..|
	 * src into dst => overlap
	 */
	overlap = sys_io_ranges_overlap(2, 0, 2, 1);
	assert_true(overlap);

	/*
	 * |....|
	 *  |..|
	 * src encompasses dst => overlap
	 */
	overlap = sys_io_ranges_overlap(4, 0, 1, 2);
	assert_true(overlap);


	/*
	 *  |..|
	 * |..|
	 * dst into src => overlap
	 */
	overlap = sys_io_ranges_overlap(2, 1, 2, 0);
	assert_true(overlap);

	/*
	 *  |..|
	 * |....|
	 * dst encompasses src => overlap
	 */
	overlap = sys_io_ranges_overlap(2, 1, 4, 0);
	assert_true(overlap);
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_sys_io_ranges_overlap),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
