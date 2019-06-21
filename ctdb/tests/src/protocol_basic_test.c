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

#include "tests/src/protocol_common_basic.h"

PROTOCOL_TYPE1_TEST(uint8_t, ctdb_uint8);
PROTOCOL_TYPE1_TEST(uint16_t, ctdb_uint16);
PROTOCOL_TYPE1_TEST(int32_t, ctdb_int32);
PROTOCOL_TYPE1_TEST(uint32_t, ctdb_uint32);
PROTOCOL_TYPE1_TEST(uint64_t, ctdb_uint64);
PROTOCOL_TYPE1_TEST(double, ctdb_double);
PROTOCOL_TYPE1_TEST(bool, ctdb_bool);

static void test_ctdb_chararray(void)
{
	size_t len = rand_int(1000) + 1;
	char p1[len], p2[len];
	size_t buflen, np = 0;
	size_t i;
	int ret;

	for (i=0; i<len-1; i++) {
		p1[i] = 'A' + rand_int(26);
	}
	p1[len-1] = '\0';
	buflen = ctdb_chararray_len(p1, len);
	assert(buflen < sizeof(BUFFER));
	ctdb_chararray_push(p1, len, BUFFER, &np);
	assert(np == buflen);
	np = 0;
	ret = ctdb_chararray_pull(BUFFER, buflen, p2, len, &np);
	assert(ret == 0);
	assert(np == buflen);
	assert(strncmp(p1, p2, len) == 0);
}

PROTOCOL_TYPE2_TEST(const char *, ctdb_string);
PROTOCOL_TYPE2_TEST(const char *, ctdb_stringn);

PROTOCOL_TYPE1_TEST(pid_t, ctdb_pid);
PROTOCOL_TYPE1_TEST(struct timeval, ctdb_timeval);

static void test_ctdb_padding(void)
{
	int padding;
	size_t buflen, np = 0;
	int ret;

	padding = rand_int(8);

	buflen = ctdb_padding_len(padding);
	assert(buflen < sizeof(BUFFER));
	ctdb_padding_push(padding, BUFFER, &np);
	assert(np == buflen);
	np = 0;
	ret = ctdb_padding_pull(BUFFER, buflen, padding, &np);
	assert(ret == 0);
	assert(np == buflen);
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
	TEST_FUNC(ctdb_bool)();

	test_ctdb_chararray();

	TEST_FUNC(ctdb_string)();
	TEST_FUNC(ctdb_stringn)();

	TEST_FUNC(ctdb_pid)();
	TEST_FUNC(ctdb_timeval)();

	test_ctdb_padding();

	return 0;
}
