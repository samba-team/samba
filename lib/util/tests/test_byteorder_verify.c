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

#include "lib/replace/replace.h"
#include "lib/util/bytearray.h"
#include "lib/util/byteorder.h"

static void torture_le_u8(void **state)
{
	uint8_t data[2] = {0};
	uint8_t result;

	(void)state;

	/* Test CVAL and SCVAL */
	PUSH_LE_U8(data, 0, 23);
	PUSH_LE_U8(data, 1, 42);

	result = CVAL(data, 0);
	assert_int_equal(result, 23);

	result = CVAL(data, 1);
	assert_int_equal(result, 42);

	/* Test CVAL_NC and PVAL */
	PUSH_LE_U8(data, 0, 23);
	PUSH_LE_U8(data, 1, 42);

	result = CVAL_NC(data, 0);
	assert_int_equal(result, 23);

	result = PVAL(data, 1);
	assert_int_equal(result, 42);

	/* Test SCVAL */
	SCVAL(data, 0, 42);
	SCVAL(data, 1, 23);

	result = PULL_LE_U8(data, 0);
	assert_int_equal(result, 42);

	result = PULL_LE_U8(data, 1);
	assert_int_equal(result, 23);
}

static void torture_le_u16(void **state)
{
	uint8_t data[2] = {0};
	uint16_t result;

	(void)state;

	/* Test SVAL */
	PUSH_LE_U16(data, 0, 0xff00);
	result = SVAL(data, 0);
	assert_int_equal(result, 0xff00);

	/* Test SSVAL */
	SSVAL(data, 0, 0x00ff);
	result = PULL_LE_U16(data, 0);
	assert_int_equal(result, 0x00ff);

	/* Test SSVALX */
	SSVALX(data, 0, 0x00fa);
	result = PULL_LE_U16(data, 0);
	assert_int_equal(result, 0x00fa);

	/* Test SSVALS */
	SSVALS(data, 0, 0x00fb);
	result = PULL_LE_U16(data, 0);
	assert_int_equal(result, 0x00fb);
}

static void torture_le_u32(void **state)
{
	uint8_t data[4] = {0};
	uint32_t result;

	(void)state;

	/* Test IVAL */
	PUSH_LE_U32(data, 0, 0xff000000);
	result = IVAL(data, 0);
	assert_int_equal(result, 0xff000000);

	/* Test SIVAL */
	SIVAL(data, 0, 0xffaabbcc);
	result = PULL_LE_U32(data, 0);
	assert_int_equal(result, 0xffaabbcc);

	/* Test SIVALX */
	SIVALX(data, 0, 0xffbbccdd);
	result = PULL_LE_U32(data, 0);
	assert_int_equal(result, 0xffbbccdd);

	/* Test SIVALS */
	SIVALS(data, 0, 0xffccddee);
	result = PULL_LE_U32(data, 0);
	assert_int_equal(result, 0xffccddee);
}

static void torture_le_u64(void **state)
{
	uint8_t data[8] = {0};
	uint64_t result;

	(void)state;

	PUSH_LE_U64(data, 0, 0xfffefffefffefffeUL);
	result = BVAL(data, 0);
	assert_int_equal(result, 0xfffefffefffefffeUL);

	SBVAL(data, 0, 0xfffafffafffafffaUL);
	result = PULL_LE_U64(data, 0);
	assert_int_equal(result, 0xfffafffafffafffaUL);
}

static void torture_be_u8(void **state)
{
	uint8_t data[2] = {0};
	uint8_t result;

	(void)state;

	PUSH_BE_U8(data, 0, 23);
	PUSH_BE_U8(data, 1, 42);

	result = CVAL(data, 0);
	assert_int_equal(result, 23);

	result = CVAL(data, 1);
	assert_int_equal(result, 42);

	SCVAL(data, 0, 42);
	SCVAL(data, 1, 23);

	result = PULL_BE_U8(data, 0);
	assert_int_equal(result, 42);

	result = PULL_BE_U8(data, 1);
	assert_int_equal(result, 23);
}

static void torture_be_u16(void **state)
{
	uint8_t data[2] = {0};
	uint16_t result;

	(void)state;

	/* Test RSVAL */
	PUSH_BE_U16(data, 0, 0xff00);
	result = RSVAL(data, 0);
	assert_int_equal(result, 0xff00);

	/* Test RSVALS */
	PUSH_BE_U16(data, 0, 0xffaa);
	result = RSVALS(data, 0);
	assert_int_equal(result, 0xffaa);

	/* Test RSSVAL */
	RSSVAL(data, 0, 0x00ff);
	result = PULL_BE_U16(data, 0);
	assert_int_equal(result, 0x00ff);

	/* Test RSSVALS */
	RSSVALS(data, 0, 0x00fa);
	result = PULL_BE_U16(data, 0);
	assert_int_equal(result, 0x00fa);
}

static void torture_be_u32(void **state)
{
	uint8_t data[4] = {0};
	uint32_t result;

	(void)state;

	/* Test RIVAL */
	PUSH_BE_U32(data, 0, 0xff000000);
	result = RIVAL(data, 0);
	assert_int_equal(result, 0xff000000);

	/* Test RIVALS */
	PUSH_BE_U32(data, 0, 0xff0000aa);
	result = RIVALS(data, 0);
	assert_int_equal(result, 0xff0000aa);

	/* Test RSIVAL */
	RSIVAL(data, 0, 0xffeeddcc);
	result = PULL_BE_U32(data, 0);
	assert_int_equal(result, 0xffeeddcc);

	/* Test RSIVALS */
	RSIVALS(data, 0, 0xffaaddcc);
	result = PULL_BE_U32(data, 0);
	assert_int_equal(result, 0xffaaddcc);
}

static void torture_be_u64(void **state)
{
	uint8_t data[8] = {0};
	uint64_t result;

	(void)state;

	/* Test RBVAL */
	PUSH_BE_U64(data, 0, 0xfffefffefffefffeUL);
	result = RBVAL(data, 0);
	assert_int_equal(result, 0xfffefffefffefffeUL);

	/* Test RBVALS */
	PUSH_BE_U64(data, 0, 0xfffafffafffafffaUL);
	result = RBVALS(data, 0);
	assert_int_equal(result, 0xfffafffafffafffaUL);

	/* Test RSBVAL */
	RSBVAL(data, 0, 0xfffbfffbfffbfffbUL);
	result = PULL_BE_U64(data, 0);
	assert_int_equal(result, 0xfffbfffbfffbfffbUL);

	/* Test RSBVALS */
	RSBVALS(data, 0, 0xfffcfffcfffcfffcUL);
	result = PULL_BE_U64(data, 0);
	assert_int_equal(result, 0xfffcfffcfffcfffcUL);
}

int main(int argc, char *argv[])
{
	int rc;
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(torture_le_u8),
		cmocka_unit_test(torture_le_u16),
		cmocka_unit_test(torture_le_u32),
		cmocka_unit_test(torture_le_u64),

		cmocka_unit_test(torture_be_u8),
		cmocka_unit_test(torture_be_u16),
		cmocka_unit_test(torture_be_u32),
		cmocka_unit_test(torture_be_u64),
	};

	if (argc == 2) {
		cmocka_set_test_filter(argv[1]);
	}
	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	rc = cmocka_run_group_tests(tests, NULL, NULL);

	return rc;
}
