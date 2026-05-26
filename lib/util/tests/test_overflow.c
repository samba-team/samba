/*
 * cmocka unit tests for the overflow macros
 *
 *  Copyright (C) Gary Lockyer 2026 <gary@catalyst.net.nz>
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
 *
 */

/*
 * from cmocka.c:
 * These headers or their equivalents should be included prior to
 * including
 * this header file.
 *
 * #include <stdarg.h>
 * #include <stddef.h>
 * #include <setjmp.h>
 *
 * This allows test applications to use custom definitions of C standard
 * library functions and types.
 *
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>


#include "lib/util/overflow.h"

static void test_ptr_overflow_true(void **state)
{
	char *ptr = (char *)INTPTR_MAX;
	assert_true(ptr_overflow(ptr, 1, char));
}

static void test_ptr_overflow_false(void **state)
{
	char *ptr = (char *)(INTPTR_MAX- 1);
	assert_false(ptr_overflow(ptr, 1, char));
}

static void test_outside_range_false(void **state)
{
	char base[] = "1234";
	char *end  = base + 5;
	assert_false(offset_outside_range(base, end, 5));
}

static void test_outside_range_true(void **state)
{
	char base[] = "1234";
	char *end  = base + 5;
	assert_true(offset_outside_range(base, end, 6));
}

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test( test_ptr_overflow_true),
		cmocka_unit_test( test_ptr_overflow_false),
		cmocka_unit_test( test_outside_range_false),
		cmocka_unit_test( test_outside_range_true),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);

}
