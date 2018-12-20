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

static void torture_pull_le_u8(void **state)
{
	uint8_t data[2] = {0};
	uint8_t result;

	(void)state;

	result = PULL_LE_U8(data, 0);
	assert_int_equal(result, 0);

	data[0] = 0x2a;
	result = PULL_LE_U8(data, 0);
	assert_int_equal(result, 42);


	data[0] = 0xf;
	result = PULL_LE_U8(data, 0);
	assert_int_equal(result, 0xf);

	data[0] = 0xff;
	result = PULL_LE_U8(data, 0);
	assert_int_equal(result, 0xff);

	data[1] = 0x2a;
	result = PULL_LE_U8(data, 1);
	assert_int_equal(result, 42);
}

static void torture_pull_le_u16(void **state)
{
	uint8_t data[2] = {0, 0};
	uint16_t result;

	(void)state;

	result = PULL_LE_U16(data, 0);
	assert_int_equal(result, 0);

	data[0] = 0x2a;
	data[1] = 0x00;
	result = PULL_LE_U16(data, 0);
	assert_int_equal(result, 42);

	data[0] = 0xff;
	data[1] = 0x00;
	result = PULL_LE_U16(data, 0);
	assert_int_equal(result, 0x00ff);

	data[0] = 0x00;
	data[1] = 0xff;
	result = PULL_LE_U16(data, 0);
	assert_int_equal(result, 0xff00);

	data[0] = 0xff;
	data[1] = 0xff;
	result = PULL_LE_U16(data, 0);
	assert_int_equal(result, 0xffff);
}

static void torture_pull_le_u32(void **state)
{
	uint8_t data[4] = {0, 0, 0, 0};
	uint32_t result;

	(void)state;

	result = PULL_LE_U32(data, 0);
	assert_int_equal(result, 0);

	data[0] = 0x2a;
	data[1] = 0x00;
	data[2] = 0x00;
	data[3] = 0x00;
	result = PULL_LE_U32(data, 0);
	assert_int_equal(result, 42);

	data[0] = 0xff;
	data[1] = 0x00;
	data[2] = 0x00;
	data[3] = 0x00;
	result = PULL_LE_U32(data, 0);
	assert_int_equal(result, 0x00ff);

	data[0] = 0x00;
	data[1] = 0xff;
	data[2] = 0x00;
	data[3] = 0x00;
	result = PULL_LE_U32(data, 0);
	assert_int_equal(result, 0xff00);

	data[0] = 0x00;
	data[1] = 0x00;
	data[2] = 0xff;
	data[3] = 0x00;
	result = PULL_LE_U32(data, 0);
	assert_int_equal(result, 0xff0000);

	data[0] = 0x00;
	data[1] = 0x00;
	data[2] = 0x00;
	data[3] = 0xff;
	result = PULL_LE_U32(data, 0);
	assert_int_equal(result, 0xff000000);

	data[0] = 0xff;
	data[1] = 0xff;
	data[2] = 0xff;
	data[3] = 0xff;
	result = PULL_LE_U32(data, 0);
	assert_int_equal(result, 0xffffffff);
}

static void torture_push_le_u8(void **state)
{
	uint8_t data[4] = {0, 0, 0, 0};
	uint8_t data2[4] = {42, 42, 42, 42};

	(void)state;

	PUSH_LE_U8(data, 0, 42);
	PUSH_LE_U8(data, 1, 42);
	PUSH_LE_U8(data, 2, 42);
	PUSH_LE_U8(data, 3, 42);
	assert_memory_equal(data, data2, sizeof(data));
}

static void torture_push_le_u16(void **state)
{
	uint8_t data[4] = {0, 0, 0, 0};
	uint8_t data2[4] = {0xa6, 0x7f, 0x2a, 0x00};
	uint16_t result;

	(void)state;

	PUSH_LE_U16(data, 0, 32678);
	PUSH_LE_U16(data, 2, 42);
	assert_memory_equal(data, data2, sizeof(data));

	result = PULL_LE_U16(data, 2);
	assert_int_equal(result, 42);

	result = PULL_LE_U16(data, 0);
	assert_int_equal(result, 32678);
}

static void torture_push_le_u32(void **state)
{
	uint8_t data[8] = {0};
	uint8_t data2[8] = {0xa6, 0x7f, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00};
	uint32_t result;

	(void)state;

	PUSH_LE_U32(data, 0, 32678);
	PUSH_LE_U32(data, 4, 42);
	assert_memory_equal(data, data2, sizeof(data));

	result = PULL_LE_U32(data, 4);
	assert_int_equal(result, 42);

	result = PULL_LE_U32(data, 0);
	assert_int_equal(result, 32678);

	PUSH_LE_U32(data, 0, 0xfffefffe);
	result = PULL_LE_U32(data, 0);
	assert_int_equal(result, 0xfffefffe);
}

static void torture_push_le_u64(void **state)
{
	uint8_t data[16] = {0};
	uint64_t result;

	(void)state;

	PUSH_LE_U64(data, 0, 32678);

	result = PULL_LE_U64(data, 0);
	assert_int_equal(result, 32678);

	PUSH_LE_U64(data, 0, 0xfffefffefffefffeUL);

	result = PULL_LE_U64(data, 0);
	assert_int_equal(result, 0xfffefffefffefffeUL);
}

/****************** BIG ENDIAN ********************/

static void torture_pull_be_u8(void **state)
{
	uint8_t data[2] = {0};
	uint8_t result;

	(void)state;

	result = PULL_BE_U8(data, 0);
	assert_int_equal(result, 0);

	data[0] = 0x2a;
	result = PULL_BE_U8(data, 0);
	assert_int_equal(result, 42);


	data[0] = 0xf;
	result = PULL_BE_U8(data, 0);
	assert_int_equal(result, 0xf);

	data[0] = 0xff;
	result = PULL_BE_U8(data, 0);
	assert_int_equal(result, 0xff);

	data[1] = 0x2a;
	result = PULL_BE_U8(data, 1);
	assert_int_equal(result, 42);
}

static void torture_pull_be_u16(void **state)
{
	uint8_t data[2] = {0, 0};
	uint16_t result;

	(void)state;

	result = PULL_BE_U16(data, 0);
	assert_int_equal(result, 0);

	data[0] = 0x00;
	data[1] = 0x2a;
	result = PULL_BE_U16(data, 0);
	assert_int_equal(result, 42);

	data[0] = 0x00;
	data[1] = 0xff;
	result = PULL_BE_U16(data, 0);
	assert_int_equal(result, 0x00ff);

	data[0] = 0xff;
	data[1] = 0x00;
	result = PULL_BE_U16(data, 0);
	assert_int_equal(result, 0xff00);

	data[0] = 0xff;
	data[1] = 0xff;
	result = PULL_BE_U16(data, 0);
	assert_int_equal(result, 0xffff);
}

static void torture_pull_be_u32(void **state)
{
	uint8_t data[4] = {0, 0, 0, 0};
	uint32_t result;

	(void)state;

	result = PULL_BE_U32(data, 0);
	assert_int_equal(result, 0);

	data[0] = 0x00;
	data[1] = 0x00;
	data[2] = 0x00;
	data[3] = 0x2a;
	result = PULL_BE_U32(data, 0);
	assert_int_equal(result, 42);

	data[0] = 0x00;
	data[1] = 0x00;
	data[2] = 0x00;
	data[3] = 0xff;
	result = PULL_BE_U32(data, 0);
	assert_int_equal(result, 0x00ff);

	data[0] = 0x00;
	data[1] = 0x00;
	data[2] = 0xff;
	data[3] = 0x00;
	result = PULL_BE_U32(data, 0);
	assert_int_equal(result, 0xff00);

	data[0] = 0x00;
	data[1] = 0xff;
	data[2] = 0x00;
	data[3] = 0x00;
	result = PULL_BE_U32(data, 0);
	assert_int_equal(result, 0xff0000);

	data[0] = 0xff;
	data[1] = 0x00;
	data[2] = 0x00;
	data[3] = 0x00;
	result = PULL_BE_U32(data, 0);
	assert_int_equal(result, 0xff000000);

	data[0] = 0xff;
	data[1] = 0xff;
	data[2] = 0xff;
	data[3] = 0xff;
	result = PULL_BE_U32(data, 0);
	assert_int_equal(result, 0xffffffff);
}

static void torture_push_be_u8(void **state)
{
	uint8_t data[4] = {0, 0, 0, 0};
	uint8_t data2[4] = {42, 42, 42, 42};

	(void)state;

	PUSH_BE_U8(data, 0, 42);
	PUSH_BE_U8(data, 1, 42);
	PUSH_BE_U8(data, 2, 42);
	PUSH_BE_U8(data, 3, 42);
	assert_memory_equal(data, data2, sizeof(data));
}

static void torture_push_be_u16(void **state)
{
	uint8_t data[4] = {0, 0, 0, 0};
	uint8_t data2[4] = {0x7f, 0xa6, 0x00, 0x2a};
	uint16_t result;

	(void)state;

	PUSH_BE_U16(data, 0, 32678);
	PUSH_BE_U16(data, 2, 42);
	assert_memory_equal(data, data2, sizeof(data));

	result = PULL_BE_U16(data, 2);
	assert_int_equal(result, 42);

	result = PULL_BE_U16(data, 0);
	assert_int_equal(result, 32678);
}

static void torture_push_be_u32(void **state)
{
	uint8_t data[8] = {0};
	uint8_t data2[8] = {0x00, 0x00, 0x7f, 0xa6, 0x00, 0x00, 0x00, 0x2a};
	uint32_t result;

	(void)state;

	PUSH_BE_U32(data, 0, 32678);
	PUSH_BE_U32(data, 4, 42);
	assert_memory_equal(data, data2, sizeof(data));

	result = PULL_BE_U32(data, 4);
	assert_int_equal(result, 42);

	result = PULL_BE_U32(data, 0);
	assert_int_equal(result, 32678);

	PUSH_BE_U32(data, 0, 0xfffefffe);
	result = PULL_BE_U32(data, 0);
	assert_int_equal(result, 0xfffefffe);
}

static void torture_push_be_u64(void **state)
{
	uint8_t data[16] = {0};
	uint64_t result;

	(void)state;

	PUSH_BE_U64(data, 0, 32678);

	result = PULL_BE_U64(data, 0);
	assert_int_equal(result, 32678);

	PUSH_LE_U64(data, 8, 0xfffefffe);

	result = PULL_LE_U64(data, 8);
	assert_int_equal(result, 0xfffefffe);
}

int main(int argc, char *argv[])
{
	int rc;
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(torture_pull_le_u8),
		cmocka_unit_test(torture_pull_le_u16),
		cmocka_unit_test(torture_pull_le_u32),

		cmocka_unit_test(torture_push_le_u8),
		cmocka_unit_test(torture_push_le_u16),
		cmocka_unit_test(torture_push_le_u32),
		cmocka_unit_test(torture_push_le_u64),

		/* BIG ENDIAN */
		cmocka_unit_test(torture_pull_be_u8),
		cmocka_unit_test(torture_pull_be_u16),
		cmocka_unit_test(torture_pull_be_u32),

		cmocka_unit_test(torture_push_be_u8),
		cmocka_unit_test(torture_push_be_u16),
		cmocka_unit_test(torture_push_be_u32),
		cmocka_unit_test(torture_push_be_u64),
	};

	if (argc == 2) {
		cmocka_set_test_filter(argv[1]);
	}
	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	rc = cmocka_run_group_tests(tests, NULL, NULL);

	return rc;
}
