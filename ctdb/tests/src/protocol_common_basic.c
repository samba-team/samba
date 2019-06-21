/*
   protocol tests - common functions - basic types

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

#include "replace.h"

#include <assert.h>

#include "tests/src/protocol_common_basic.h"

uint8_t BUFFER[1024*1024];

/*
 * Functions to generation random data
 */

int rand_int(int max)
{
	return random() % max;
}

uint8_t rand8(void)
{
	uint8_t val = rand_int(256) & 0xff;
	return val;
}

uint16_t rand16(void)
{
	uint16_t val = rand_int(0xffff) & 0xffff;
	return val;
}

int32_t rand32i(void)
{
	return INT_MIN + random();
}

uint32_t rand32(void)
{
	return random();
}

uint64_t rand64(void)
{
	uint64_t t = random();
	t = (t << 32) | random();
	return t;
}

double rand_double(void)
{
	return 1.0 / rand64();
}

void fill_buffer(void *p, size_t len)
{
	size_t i;
	uint8_t *ptr = p;

	for (i=0; i<len; i++) {
		ptr[i] = rand8();
	}
}

void verify_buffer(void *p1, void *p2, size_t len)
{
	if (len > 0) {
		assert(memcmp(p1, p2, len) == 0);
	}
}

void fill_string(char *p, size_t len)
{
	size_t i;

	for (i=0; i<len-1; i++) {
		p[i] = 'A' + rand_int(26);
	}
	p[len-1] = '\0';
}

void verify_string(const char *p1, const char *p2)
{
	assert(strlen(p1) == strlen(p2));
	assert(strcmp(p1, p2) == 0);
}

void fill_ctdb_uint8(uint8_t *p)
{
	*p = rand8();
}

void verify_ctdb_uint8(uint8_t *p1, uint8_t *p2)
{
	assert(*p1 == *p2);
}

void fill_ctdb_uint16(uint16_t *p)
{
	*p = rand16();
}

void verify_ctdb_uint16(uint16_t *p1, uint16_t *p2)
{
	assert(*p1 == *p2);
}

void fill_ctdb_int32(int32_t *p)
{
	*p = rand32i();
}

void verify_ctdb_int32(int32_t *p1, int32_t *p2)
{
	assert(*p1 == *p2);
}

void fill_ctdb_uint32(uint32_t *p)
{
	*p = rand32();
}

void verify_ctdb_uint32(uint32_t *p1, uint32_t *p2)
{
	assert(*p1 == *p2);
}

void fill_ctdb_uint64(uint64_t *p)
{
	*p = rand64();
}

void verify_ctdb_uint64(uint64_t *p1, uint64_t *p2)
{
	assert(*p1 == *p2);
}

void fill_ctdb_double(double *p)
{
	*p = rand_double();
}

void verify_ctdb_double(double *p1, double *p2)
{
	assert(*p1 == *p2);
}

void fill_ctdb_bool(bool *p)
{
	if (rand_int(2) == 0) {
		*p = true;
	} else {
		*p = false;
	}
}

void verify_ctdb_bool(bool *p1, bool *p2)
{
	assert(*p1 == *p2);
}

void fill_ctdb_string(TALLOC_CTX *mem_ctx, const char **p)
{
	char *str;
	int len;

	len = rand_int(1024) + 2;
	str = talloc_size(mem_ctx, len+1);
	assert(str != NULL);

	fill_string(str, len);
	*p = str;
}

void verify_ctdb_string(const char **p1, const char **p2)
{
	if (*p1 == NULL || *p2 == NULL) {
		assert(*p1 == *p2);
	} else {
		verify_string(*p1, *p2);
	}
}

void fill_ctdb_stringn(TALLOC_CTX *mem_ctx, const char **p)
{
	fill_ctdb_string(mem_ctx, p);
}

void verify_ctdb_stringn(const char **p1, const char **p2)
{
	verify_ctdb_string(p1, p2);
}

void fill_ctdb_pid(pid_t *p)
{
	*p = rand32();
}

void verify_ctdb_pid(pid_t *p1, pid_t *p2)
{
	assert(*p1 == *p2);
}

void fill_ctdb_timeval(struct timeval *p)
{
	p->tv_sec = rand32();
	p->tv_usec = rand_int(1000000);
}

void verify_ctdb_timeval(struct timeval *p1, struct timeval *p2)
{
	assert(p1->tv_sec == p2->tv_sec);
	assert(p1->tv_usec == p2->tv_usec);
}

