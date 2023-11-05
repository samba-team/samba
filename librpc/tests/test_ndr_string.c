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
	ndr_flags_type flags = NDR_SCALARS;
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
	ndr_flags_type flags = NDR_SCALARS;
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
	ndr_flags_type flags = NDR_SCALARS;
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

static void test_pull_string_array(void **state)
{
	/* We try pulling long string arrays without long strings */
	const char **r = NULL;
	struct ndr_pull ndr = {0};
	enum ndr_err_code err;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	size_t len = 1 * 1024 * 1024;
	uint8_t *data = talloc_array(mem_ctx, uint8_t, len);
	size_t i;

	for (i = 0; i < len; i++) {
		data[i] = (i & 1) ? '\0' : 'X';
	}

	ndr.current_mem_ctx = mem_ctx;

	ndr.flags = (LIBNDR_FLAG_REF_ALLOC |
		     LIBNDR_FLAG_REMAINING |
		     LIBNDR_FLAG_STR_NULLTERM |
		     LIBNDR_FLAG_STR_RAW8);
	ndr.data = data;
	ndr.data_size = len;

	err = ndr_pull_string_array(&ndr, NDR_SCALARS, &r);
	assert_int_equal(err, NDR_ERR_SUCCESS);
	assert_string_equal(r[0], "X");
	assert_string_equal(r[len / 3], "X");
	assert_string_equal(r[len / 2 - 1], "X");
	assert_ptr_equal(r[len / 2], NULL);
	TALLOC_FREE(mem_ctx);
}

static void test_pull_string_zero_len_utf8_NOTERM_STR_NO_EMBEDDED_NUL(void **state)
{
	struct ndr_pull ndr = {0};
	enum ndr_err_code err;
	ndr_flags_type flags = NDR_SCALARS;
	const char *s = NULL;
	uint8_t data[] = { 0x0, 0x0 };

	ndr.flags = LIBNDR_FLAG_STR_UTF8 | LIBNDR_FLAG_STR_SIZE2 | LIBNDR_FLAG_STR_NOTERM | LIBNDR_FLAG_STR_NO_EMBEDDED_NUL;

	ndr.data = data;
	ndr.data_size = sizeof(data);
	err = ndr_pull_string(&ndr, flags, &s);
	assert_int_equal(err, NDR_ERR_SUCCESS);
	assert_non_null(s);
	assert_string_equal(s, "");
	assert_int_equal(sizeof(data), ndr.offset);

}

static void test_pull_string_utf8_nul_term_STR_NO_EMBEDDED_NUL(void **state)
{

	struct ndr_pull ndr = {0};
	enum ndr_err_code err;
	ndr_flags_type flags = NDR_SCALARS;
	const char *s = NULL;
	uint8_t data[] = { 0x2, 0x0, 'a', 0x0 };

	ndr.flags = LIBNDR_FLAG_STR_UTF8 | LIBNDR_FLAG_STR_SIZE2 | LIBNDR_FLAG_STR_NO_EMBEDDED_NUL;

	ndr.data = data;
	ndr.data_size = sizeof(data);
	err = ndr_pull_string(&ndr, flags, &s);
	assert_int_equal(err, NDR_ERR_SUCCESS);
	assert_non_null(s);
	assert_string_equal(s, "a");
	assert_int_equal(sizeof(data), ndr.offset);

}

static void test_pull_string_utf8_nul_term_NOTERM_STR_NO_EMBEDDED_NUL(void **state)
{

	struct ndr_pull ndr = {0};
	enum ndr_err_code err;
	ndr_flags_type flags = NDR_SCALARS;
	const char *s = NULL;
	uint8_t data[] = { 0x2, 0x0, 'a', 0x0 };

	ndr.flags = LIBNDR_FLAG_STR_UTF8 | LIBNDR_FLAG_STR_SIZE2 | LIBNDR_FLAG_STR_NOTERM | LIBNDR_FLAG_STR_NO_EMBEDDED_NUL;

	ndr.data = data;
	ndr.data_size = sizeof(data);
	err = ndr_pull_string(&ndr, flags, &s);
	assert_int_equal(err, NDR_ERR_CHARCNV);
	assert_int_equal(2, ndr.offset);

}

static void test_pull_string_utf8_nullterm_STR_NO_EMBEDDED_NUL(void **state)
{

	struct ndr_pull ndr = {0};
	enum ndr_err_code err;
	ndr_flags_type flags = NDR_SCALARS;
	const char *s = NULL;
	uint8_t data[] = { 0x4, 0x0, 'a', 'b', 'c', 0x0};

	ndr.flags = LIBNDR_FLAG_STR_UTF8 | LIBNDR_FLAG_STR_SIZE2 | LIBNDR_FLAG_STR_NO_EMBEDDED_NUL;

	ndr.data = data;
	ndr.data_size = sizeof(data);
	err = ndr_pull_string(&ndr, flags, &s);
	assert_int_equal(err, NDR_ERR_SUCCESS);
	assert_non_null(s);
	assert_string_equal(s, "abc");
	assert_int_equal(sizeof(data), ndr.offset);

}

static void test_pull_string_utf8_STR_NO_EMBEDDED_NUL(void **state)
{

	struct ndr_pull ndr = {0};
	enum ndr_err_code err;
	ndr_flags_type flags = NDR_SCALARS;
	const char *s = NULL;
	uint8_t data[] = { 0x3, 0x0, 'a', 'b', 'c'};

	ndr.flags = LIBNDR_FLAG_STR_UTF8 | LIBNDR_FLAG_STR_SIZE2 | LIBNDR_FLAG_STR_NO_EMBEDDED_NUL;

	ndr.data = data;
	ndr.data_size = sizeof(data);
	err = ndr_pull_string(&ndr, flags, &s);
	assert_int_equal(err, NDR_ERR_CHARCNV);
	assert_int_equal(2, ndr.offset);

}

static void test_pull_string_utf8_NOTERM_STR_NO_EMBEDDED_NUL(void **state)
{

	struct ndr_pull ndr = {0};
	enum ndr_err_code err;
	ndr_flags_type flags = NDR_SCALARS;
	const char *s = NULL;
	uint8_t data[] = { 0x3, 0x0, 'a', 'b', 'c'};

	ndr.flags = LIBNDR_FLAG_STR_UTF8 | LIBNDR_FLAG_STR_SIZE2 | LIBNDR_FLAG_STR_NOTERM | LIBNDR_FLAG_STR_NO_EMBEDDED_NUL;

	ndr.data = data;
	ndr.data_size = sizeof(data);
	err = ndr_pull_string(&ndr, flags, &s);
	assert_int_equal(err, NDR_ERR_SUCCESS);
	assert_non_null(s);
	assert_string_equal(s, "abc");
	assert_int_equal(sizeof(data), ndr.offset);

}

static void test_pull_string_utf8_nullterm_NOTERM_STR_NO_EMBEDDED_NUL(void **state)
{

	struct ndr_pull ndr = {0};
	enum ndr_err_code err;
	ndr_flags_type flags = NDR_SCALARS;
	const char *s = NULL;
	uint8_t data[] = { 0x4, 0x0, 'a', 'b', 'c', 0x0};

	ndr.flags = LIBNDR_FLAG_STR_UTF8 | LIBNDR_FLAG_STR_SIZE2 | LIBNDR_FLAG_STR_NOTERM | LIBNDR_FLAG_STR_NO_EMBEDDED_NUL;

	ndr.data = data;
	ndr.data_size = sizeof(data);
	err = ndr_pull_string(&ndr, flags, &s);
	assert_int_equal(err, NDR_ERR_CHARCNV);
	assert_int_equal(2, ndr.offset);

}

static void test_pull_string_utf8_LIBNDR_FLAG_STR_NOTERM_STR_NO_EMBEDDED_NUL_fail(void **state)
{

	struct ndr_pull ndr = {0};
	enum ndr_err_code err;
	ndr_flags_type flags = NDR_SCALARS;
	const char *s = NULL;
	uint8_t data[] = { 0x3, 0x0, 'a', 0x0, 'a'};

	ndr.flags = LIBNDR_FLAG_STR_UTF8 | LIBNDR_FLAG_STR_SIZE2 | LIBNDR_FLAG_STR_NOTERM | LIBNDR_FLAG_STR_NO_EMBEDDED_NUL;

	ndr.data = data;
	ndr.data_size = sizeof(data);
	err = ndr_pull_string(&ndr, flags, &s);
	assert_int_equal(err, NDR_ERR_CHARCNV);
	assert_int_equal(2, ndr.offset);

}

static void test_pull_string_utf16_LIBNDR_FLAG_STR_NOTERM_STR_NO_EMBEDDED_NUL(void **state)
{

	struct ndr_pull ndr = {0};
	enum ndr_err_code err;
	ndr_flags_type flags = NDR_SCALARS;
	const char *s = NULL;
	uint8_t data[] = { 0x3, 0x0, 'a', 0x0, 'b', 0x0, 'c', 0x0};

	ndr.flags = LIBNDR_FLAG_STR_SIZE2 | LIBNDR_FLAG_STR_NOTERM | LIBNDR_FLAG_STR_NO_EMBEDDED_NUL;

	ndr.data = data;
	ndr.data_size = sizeof(data);
	err = ndr_pull_string(&ndr, flags, &s);
	assert_int_equal(err, NDR_ERR_SUCCESS);
	assert_non_null(s);
	assert_string_equal(s, "abc");
	assert_int_equal(sizeof(data), ndr.offset);

}

static void test_pull_string_utf16_LIBNDR_FLAG_STR_NOTERM_STR_NO_EMBEDDED_NUL_fail(void **state)
{

	struct ndr_pull ndr = {0};
	enum ndr_err_code err;
	ndr_flags_type flags = NDR_SCALARS;
	const char *s = NULL;
	uint8_t data[] = { 0x3, 0x0, 'a', 0x0, 0x0, 0x0, 'c', 0x0};

	ndr.flags = LIBNDR_FLAG_STR_SIZE2 | LIBNDR_FLAG_STR_NOTERM | LIBNDR_FLAG_STR_NO_EMBEDDED_NUL;

	ndr.data = data;
	ndr.data_size = sizeof(data);
	err = ndr_pull_string(&ndr, flags, &s);
	assert_int_equal(err, NDR_ERR_CHARCNV);
	assert_int_equal(2, ndr.offset);

}

static void test_pull_string_zero_len_utf8_STR_NO_EMBEDDED_NUL(void **state)
{

	struct ndr_pull ndr = {0};
	enum ndr_err_code err;
	ndr_flags_type flags = NDR_SCALARS;
	const char *s = NULL;
	uint8_t data[] = { 0x0, 0x0 };

	ndr.flags = LIBNDR_FLAG_STR_UTF8 | LIBNDR_FLAG_STR_SIZE2 | LIBNDR_FLAG_STR_NO_EMBEDDED_NUL;

	ndr.data = data;
	ndr.data_size = sizeof(data);
	err = ndr_pull_string(&ndr, flags, &s);
	assert_int_equal(err, NDR_ERR_SUCCESS);
	assert_non_null(s);
	assert_string_equal(s, "");
	assert_int_equal(sizeof(data), ndr.offset);

}

static void test_pull_string_nul_only_utf8_STR_NO_EMBEDDED_NUL(void **state)
{

	struct ndr_pull ndr = {0};
	enum ndr_err_code err;
	ndr_flags_type flags = NDR_SCALARS;
	const char *s = NULL;
	uint8_t data[] = { 0x2, 0x0, 0x0, 0x0 };

	ndr.flags = LIBNDR_FLAG_STR_UTF8 | LIBNDR_FLAG_STR_SIZE2 | LIBNDR_FLAG_STR_NO_EMBEDDED_NUL;

	ndr.data = data;
	ndr.data_size = sizeof(data);
	err = ndr_pull_string(&ndr, flags, &s);
	assert_int_equal(err, NDR_ERR_CHARCNV);
	assert_int_equal(2, ndr.offset);

}

static void test_pull_string_nul_term_utf8_NOTERM_NDR_REMAINING_STR_NO_EMBEDDED_NUL(void **state)
{

	struct ndr_pull ndr = {0};
	enum ndr_err_code err;
	ndr_flags_type flags = NDR_SCALARS;
	const char *s = NULL;
	uint8_t data[] = {'a', 'b', 'c', 0x0 };

	ndr.flags = LIBNDR_FLAG_STR_UTF8 | LIBNDR_FLAG_STR_NOTERM | LIBNDR_FLAG_REMAINING | LIBNDR_FLAG_STR_NO_EMBEDDED_NUL;

	ndr.data = data;
	ndr.data_size = sizeof(data);
	err = ndr_pull_string(&ndr, flags, &s);
	assert_int_equal(err, NDR_ERR_CHARCNV);
	assert_int_equal(0, ndr.offset);

}

static void test_pull_string_utf8_NOTERM_NDR_REMAINING_STR_NO_EMBEDDED_NUL(void **state)
{

	struct ndr_pull ndr = {0};
	enum ndr_err_code err;
	ndr_flags_type flags = NDR_SCALARS;
	const char *s = NULL;
	uint8_t data[] = {'a', 'b', 'c' };

	ndr.flags = LIBNDR_FLAG_STR_UTF8 | LIBNDR_FLAG_STR_NOTERM | LIBNDR_FLAG_REMAINING | LIBNDR_FLAG_STR_NO_EMBEDDED_NUL;

	ndr.data = data;
	ndr.data_size = sizeof(data);
	err = ndr_pull_string(&ndr, flags, &s);
	assert_int_equal(err, NDR_ERR_SUCCESS);
	assert_non_null(s);
	assert_string_equal(s, "abc");
	assert_int_equal(sizeof(data), ndr.offset);

}

static void test_pull_string_nul_term_utf8_STR_NULLTERM_NDR_REMAINING_STR_NO_EMBEDDED_NUL(void **state)
{

	struct ndr_pull ndr = {0};
	enum ndr_err_code err;
	ndr_flags_type flags = NDR_SCALARS;
	const char *s = NULL;
	uint8_t data[] = {'a', 'b', 'c', 0x0 };

	ndr.flags = LIBNDR_FLAG_STR_UTF8 | LIBNDR_FLAG_STR_NULLTERM | LIBNDR_FLAG_REMAINING | LIBNDR_FLAG_STR_NO_EMBEDDED_NUL;

	ndr.data = data;
	ndr.data_size = sizeof(data);
	err = ndr_pull_string(&ndr, flags, &s);
	assert_int_equal(err, NDR_ERR_SUCCESS);
	assert_non_null(s);
	assert_string_equal(s, "abc");
	assert_int_equal(sizeof(data), ndr.offset);

}

static void test_pull_string_utf8_NDR_REMAINING_STR_NULLTERM_STR_NO_EMBEDDED_NUL(void **state)
{

	struct ndr_pull ndr = {0};
	enum ndr_err_code err;
	ndr_flags_type flags = NDR_SCALARS;
	const char *s = NULL;
	uint8_t data[] = {'a', 'b', 'c' };

	ndr.flags = LIBNDR_FLAG_STR_UTF8 | LIBNDR_FLAG_STR_NULLTERM | LIBNDR_FLAG_REMAINING | LIBNDR_FLAG_STR_NO_EMBEDDED_NUL;

	ndr.data = data;
	ndr.data_size = sizeof(data);
	err = ndr_pull_string(&ndr, flags, &s);
	assert_int_equal(err, NDR_ERR_CHARCNV);
	assert_int_equal(0, ndr.offset);

}

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_pull_string_zero_len_nul_term),
		cmocka_unit_test(test_pull_string_len_1_nul_term),
		cmocka_unit_test(test_pull_string_len_2_nul_term),
		cmocka_unit_test(test_ndr_string_n_length),
		cmocka_unit_test(test_pull_string_array),
		cmocka_unit_test(test_pull_string_zero_len_utf8_NOTERM_STR_NO_EMBEDDED_NUL),
		cmocka_unit_test(test_pull_string_utf8_nul_term_STR_NO_EMBEDDED_NUL),
		cmocka_unit_test(test_pull_string_utf8_nul_term_NOTERM_STR_NO_EMBEDDED_NUL),
		cmocka_unit_test(test_pull_string_utf8_nullterm_STR_NO_EMBEDDED_NUL),
		cmocka_unit_test(test_pull_string_utf8_STR_NO_EMBEDDED_NUL),
		cmocka_unit_test(test_pull_string_utf8_NOTERM_STR_NO_EMBEDDED_NUL),
		cmocka_unit_test(test_pull_string_utf8_nullterm_NOTERM_STR_NO_EMBEDDED_NUL),
		cmocka_unit_test(test_pull_string_utf8_LIBNDR_FLAG_STR_NOTERM_STR_NO_EMBEDDED_NUL_fail),
		cmocka_unit_test(test_pull_string_utf16_LIBNDR_FLAG_STR_NOTERM_STR_NO_EMBEDDED_NUL),
		cmocka_unit_test(test_pull_string_utf16_LIBNDR_FLAG_STR_NOTERM_STR_NO_EMBEDDED_NUL_fail),
		cmocka_unit_test(test_pull_string_zero_len_utf8_STR_NO_EMBEDDED_NUL),
		cmocka_unit_test(test_pull_string_nul_only_utf8_STR_NO_EMBEDDED_NUL),
		cmocka_unit_test(test_pull_string_nul_term_utf8_NOTERM_NDR_REMAINING_STR_NO_EMBEDDED_NUL),
		cmocka_unit_test(test_pull_string_utf8_NOTERM_NDR_REMAINING_STR_NO_EMBEDDED_NUL),
		cmocka_unit_test(test_pull_string_nul_term_utf8_STR_NULLTERM_NDR_REMAINING_STR_NO_EMBEDDED_NUL),
		cmocka_unit_test(test_pull_string_utf8_NDR_REMAINING_STR_NULLTERM_STR_NO_EMBEDDED_NUL)
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
