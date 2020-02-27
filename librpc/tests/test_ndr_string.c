/*
 * Tests for librpc ndr_string.c
 *
 * Copyright (C) Catalyst.NET Ltd 2019
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

#include "librpc/ndr/ndr_string.c"

/*
 * Try and pull a null terminated string from a zero length buffer
 * Should fail for both 1 byte, and 2 byte character strings.
 */
static void test_pull_string_zero_len_nul_term(void **state)
{
	struct ndr_pull ndr = {0};
	enum ndr_err_code err;
	int flags = NDR_SCALARS;
	uint8_t data[] = {0x0, 0x0};
	const char *s = NULL;

	ndr.flags = LIBNDR_FLAG_STR_UTF8 | LIBNDR_FLAG_STR_NULLTERM;
	ndr.data = data;
	ndr.data_size = 0;
	err = ndr_pull_string(&ndr, flags, &s);
	assert_int_equal(err, NDR_ERR_BUFSIZE);
	assert_null(s);
	assert_int_equal(0, ndr.offset);

	ndr.flags = LIBNDR_FLAG_STR_NULLTERM;
	ndr.offset = 0;
	err = ndr_pull_string(&ndr, flags, &s);
	assert_int_equal(err, NDR_ERR_BUFSIZE);
	assert_null(s);
	assert_int_equal(0, ndr.offset);

}

/*
 * Try and pull a null terminated string from a 1 byte buffer
 * Should succeed for 1 byte character and
 *        fail    for 2 byte character strings.
 */
static void test_pull_string_len_1_nul_term(void **state)
{
	struct ndr_pull ndr = {0};
	enum ndr_err_code err;
	int flags = NDR_SCALARS;
	const char *s = NULL;
	uint8_t data[] = {0x0, 0x0};

	ndr.flags = LIBNDR_FLAG_STR_UTF8 | LIBNDR_FLAG_STR_NULLTERM;
	ndr.data = data;
	ndr.data_size = 1;
	err = ndr_pull_string(&ndr, flags, &s);
	assert_int_equal(err, NDR_ERR_SUCCESS);
	assert_non_null(s);
	assert_int_equal(1, ndr.offset);

	ndr.offset = 0;
	ndr.flags = LIBNDR_FLAG_STR_NULLTERM;
	err = ndr_pull_string(&ndr, flags, &s);
	assert_int_equal(err, NDR_ERR_BUFSIZE);
	assert_int_equal(0, ndr.offset);
}

/*
 * Try and pull a null terminated string from a 2 byte buffer
 * Should succeed for both 1 byte, and 2 byte character strings.
 */
static void test_pull_string_len_2_nul_term(void **state)
{
	struct ndr_pull ndr = {0};
	enum ndr_err_code err;
	int flags = NDR_SCALARS;
	const char *s;
	uint8_t data[] = {0x0, 0x0};

	ndr.flags = LIBNDR_FLAG_STR_UTF8 | LIBNDR_FLAG_STR_NULLTERM;
	ndr.data = data;
	ndr.data_size = 2;
	err = ndr_pull_string(&ndr, flags, &s);
	assert_int_equal(err, NDR_ERR_SUCCESS);
	assert_non_null(s);
	assert_int_equal(1, ndr.offset);

	ndr.offset = 0;
	ndr.flags = LIBNDR_FLAG_STR_NULLTERM;
	err = ndr_pull_string(&ndr, flags, &s);
	assert_int_equal(err, NDR_ERR_SUCCESS);
	assert_non_null(s);
	assert_int_equal(2, ndr.offset);


}

static void test_ndr_string_n_length(void **state)
{
	char test_str1[5] = "Test";
	char test_str2[5] = {0};
	char test_str3[32] = "This is a test too";
	uint8_t test_str_u16[64] = {
		0x5C, 0x00, 0x5C, 0x00, 0x4C, 0x00, 0x6F, 0x00,
		0x67, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x2D, 0x00,
		0x6D, 0x00, 0x75, 0x00, 0x63, 0x00, 0x5C, 0x00,
		0x6B, 0x00, 0x79, 0x00, 0x6F, 0x00, 0x63, 0x00,
		0x65, 0x00, 0x72, 0x00, 0x61, 0x00, 0x2D, 0x00,
		0x6D, 0x00, 0x75, 0x00, 0x63, 0x00, 0x2D, 0x00,
		0x6E, 0x00, 0x00, 0x00 };
	size_t len;

	len = ndr_string_n_length(test_str1, sizeof(test_str1), 1);
	assert_int_equal(len, 5);

	len = ndr_string_n_length(test_str1, sizeof(test_str1) - 1, 1);
	assert_int_equal(len, 4);

	len = ndr_string_n_length(test_str2, sizeof(test_str2), 1);
	assert_int_equal(len, 1);

	len = ndr_string_n_length(test_str3, sizeof(test_str3), 1);
	assert_int_equal(len, 19);

	len = ndr_string_n_length(test_str3, 0, 1);
	assert_int_equal(len, 0);

	len = ndr_string_n_length(test_str_u16, 32, 2);
	assert_int_equal(len, 26);
}

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_pull_string_zero_len_nul_term),
		cmocka_unit_test(test_pull_string_len_1_nul_term),
		cmocka_unit_test(test_pull_string_len_2_nul_term),
		cmocka_unit_test(test_ndr_string_n_length)
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
