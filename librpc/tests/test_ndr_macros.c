/*
 * Tests for librpc ndr functions
 *
 * Copyright (C) Catalyst.NET Ltd 2020
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
#include "replace.h"
#include <setjmp.h>
#include <cmocka.h>

#include "librpc/ndr/libndr.h"

/*
 * Test NDR_RECURSION_CHECK.
 */
static enum ndr_err_code wrap_NDR_RECURSION_CHECK(
	struct ndr_pull *ndr,
	uint32_t bytes) {

	NDR_RECURSION_CHECK(ndr, bytes);
	return NDR_ERR_SUCCESS;
}

static void test_NDR_RECURSION_CHECK(void **state)
{
	struct ndr_pull ndr = {0};
	enum ndr_err_code err;


	ndr.global_max_recursion = 0;
	ndr.recursion_depth = 42;
	err = wrap_NDR_RECURSION_CHECK(&ndr, 43);
	assert_int_equal(NDR_ERR_SUCCESS, err);
	assert_int_equal(43, ndr.recursion_depth);

	ndr.global_max_recursion = 0;
	ndr.recursion_depth = 43;
	err = wrap_NDR_RECURSION_CHECK(&ndr, 43);
	assert_int_equal(NDR_ERR_MAX_RECURSION_EXCEEDED, err);
	assert_int_equal(44, ndr.recursion_depth);

	ndr.global_max_recursion = 0;
	ndr.recursion_depth = 44;
	err = wrap_NDR_RECURSION_CHECK(&ndr, 43);
	assert_int_equal(NDR_ERR_MAX_RECURSION_EXCEEDED, err);
	assert_int_equal(45, ndr.recursion_depth);

	ndr.global_max_recursion = 5;
	ndr.recursion_depth = 5;
	err = wrap_NDR_RECURSION_CHECK(&ndr, 20);
	assert_int_equal(NDR_ERR_MAX_RECURSION_EXCEEDED, err);
	assert_int_equal(6, ndr.recursion_depth);

	ndr.global_max_recursion = 5;
	ndr.recursion_depth = 4;
	err = wrap_NDR_RECURSION_CHECK(&ndr, 20);
	assert_int_equal(NDR_ERR_SUCCESS, err);
	assert_int_equal(5, ndr.recursion_depth);

	ndr.global_max_recursion = 20;
	ndr.recursion_depth = 5;
	err = wrap_NDR_RECURSION_CHECK(&ndr, 5);
	assert_int_equal(NDR_ERR_MAX_RECURSION_EXCEEDED, err);
	assert_int_equal(6, ndr.recursion_depth);

	ndr.global_max_recursion = 20;
	ndr.recursion_depth = 4;
	err = wrap_NDR_RECURSION_CHECK(&ndr, 5);
	assert_int_equal(NDR_ERR_SUCCESS, err);
	assert_int_equal(5, ndr.recursion_depth);
}

/*
 * Test NDR_RECURSION_RETURN.
 */
static enum ndr_err_code wrap_NDR_RECURSION_UNWIND(
	struct ndr_pull *ndr) {

	NDR_RECURSION_UNWIND(ndr);
	return NDR_ERR_SUCCESS;
}

static void test_NDR_RECURSION_UNWIND(void **state)
{
	struct ndr_pull ndr = {0};
	enum ndr_err_code err;

	ndr.recursion_depth = 5;
	err = wrap_NDR_RECURSION_UNWIND(&ndr);
	assert_int_equal(NDR_ERR_SUCCESS, err);
	assert_int_equal(4, ndr.recursion_depth);

	ndr.recursion_depth = 0;
	err = wrap_NDR_RECURSION_UNWIND(&ndr);
	assert_int_equal(NDR_ERR_UNDERFLOW, err);
	assert_int_equal(0, ndr.recursion_depth);

}
int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_NDR_RECURSION_CHECK),
		cmocka_unit_test(test_NDR_RECURSION_UNWIND),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
