/*
   protocol types tests

   Copyright (C) Amitay Isaacs  2015-2017

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include <assert.h>

#include "protocol/protocol_basic.c"
#include "protocol/protocol_types.c"

#include "tests/src/protocol_common.h"


PROTOCOL_TYPE1_TEST(uint8_t, ctdb_uint8);
PROTOCOL_TYPE1_TEST(uint16_t, ctdb_uint16);
PROTOCOL_TYPE1_TEST(int32_t, ctdb_int32);
PROTOCOL_TYPE1_TEST(uint32_t, ctdb_uint32);
PROTOCOL_TYPE1_TEST(uint64_t, ctdb_uint64);
PROTOCOL_TYPE1_TEST(double, ctdb_double);

static void test_ctdb_string(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	const char *p1, *p2;
	size_t buflen;
	int ret;

	fill_ctdb_string(mem_ctx, &p1);
	buflen = ctdb_string_len(p1);
	ctdb_string_push(p1, BUFFER);
	ret = ctdb_string_pull(BUFFER, buflen, mem_ctx, &p2);
	assert(ret == 0);
	verify_ctdb_string(p1, p2);
	talloc_free(mem_ctx);
}

static void test_ctdb_stringn(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	const char *p1, *p2;
	size_t buflen;
	int ret;

	fill_ctdb_string(mem_ctx, &p1);
	buflen = ctdb_stringn_len(p1);
	ctdb_stringn_push(p1, BUFFER);
	ret = ctdb_stringn_pull(BUFFER, buflen, mem_ctx, &p2);
	assert(ret == 0);
	verify_ctdb_string(p1, p2);
	talloc_free(mem_ctx);
}

static void test_ctdb_pid(void)
{
	pid_t p1, p2;
	size_t buflen;
	int ret;

	p1 = rand32();
	buflen = ctdb_pid_len(p1);
	ctdb_pid_push(p1, BUFFER);
	ret = ctdb_pid_pull(BUFFER, buflen, NULL, &p2);
	assert(ret == 0);
	assert(p1 == p2);
}

int main(int argc, char *argv[])
{
	if (argc == 2) {
		int seed = atoi(argv[1]);
		srandom(seed);
	}

	TEST_FUNC(ctdb_uint8)();
	TEST_FUNC(ctdb_uint16)();
	TEST_FUNC(ctdb_int32)();
	TEST_FUNC(ctdb_uint32)();
	TEST_FUNC(ctdb_uint64)();
	TEST_FUNC(ctdb_double)();

	test_ctdb_string();
	test_ctdb_stringn();

	test_ctdb_pid();

	return 0;
}
