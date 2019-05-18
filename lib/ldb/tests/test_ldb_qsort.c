/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) 2018      Andreas Schneider <asn@samba.org>
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

#include <ldb.h>

static int cmp_integer(int *a, int *b, void *opaque)
{
	if (a == NULL || b == NULL) {
		return 0;
	}

	if (*a > *b) {
		return 1;
	}

	if (*a < *b) {
		return -1;
	}

	return 0;
}

static void test_ldb_qsort(void **state)
{
	int a[6] = { 6, 3, 2, 7, 9, 4 };

	ldb_qsort(a, 6, sizeof(int), NULL, (ldb_qsort_cmp_fn_t)cmp_integer);

	assert_int_equal(a[0], 2);
	assert_int_equal(a[1], 3);
	assert_int_equal(a[2], 4);
	assert_int_equal(a[3], 6);
	assert_int_equal(a[4], 7);
	assert_int_equal(a[5], 9);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_ldb_qsort),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
