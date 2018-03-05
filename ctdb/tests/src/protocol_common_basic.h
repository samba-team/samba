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

#ifndef __CTDB_PROTOCOL_COMMON_BASIC_H__
#define __CTDB_PROTOCOL_COMMON_BASIC_H__

#include "replace.h"

#include <talloc.h>

/*
 * Generate test routines
 */

#define TEST_FUNC(NAME)		test_ ##NAME
#define FILL_FUNC(NAME)		fill_ ##NAME
#define VERIFY_FUNC(NAME)	verify_ ##NAME
#define LEN_FUNC(NAME)		NAME## _len
#define PUSH_FUNC(NAME)		NAME## _push
#define PULL_FUNC(NAME)		NAME## _pull

/*
 * Test for basic data types that do not need memory allocation
 * For example - int32_t, uint32_t, uint64_t
 */
#define PROTOCOL_TYPE1_TEST(TYPE, NAME)	\
static void TEST_FUNC(NAME)(void) \
{ \
	TYPE p1; \
	TYPE p2; \
	size_t buflen, np = 0; \
	int ret; \
\
	FILL_FUNC(NAME)(&p1); \
	buflen = LEN_FUNC(NAME)(&p1); \
	assert(buflen < sizeof(BUFFER)); \
	PUSH_FUNC(NAME)(&p1, BUFFER, &np); \
	assert(np == buflen); \
	np = 0; \
	ret = PULL_FUNC(NAME)(BUFFER, buflen, &p2, &np); \
	assert(ret == 0); \
	assert(np == buflen); \
	VERIFY_FUNC(NAME)(&p1, &p2); \
}

/*
 * Test for container data types that need memory allocation for sub-elements
 * For example - TDB_DATA
 */
#define PROTOCOL_TYPE2_TEST(TYPE, NAME)	\
static void TEST_FUNC(NAME)(void) \
{ \
	TALLOC_CTX *mem_ctx; \
	TYPE p1; \
	TYPE p2; \
	size_t buflen, np = 0; \
	int ret; \
\
	mem_ctx = talloc_new(NULL); \
	assert(mem_ctx != NULL); \
	FILL_FUNC(NAME)(mem_ctx, &p1); \
	buflen = LEN_FUNC(NAME)(&p1); \
	assert(buflen < sizeof(BUFFER)); \
	PUSH_FUNC(NAME)(&p1, BUFFER, &np); \
	assert(np == buflen); \
	np = 0; \
	ret = PULL_FUNC(NAME)(BUFFER, buflen, mem_ctx, &p2, &np); \
	assert(ret == 0); \
	assert(np == buflen); \
	VERIFY_FUNC(NAME)(&p1, &p2); \
	talloc_free(mem_ctx); \
}

/*
 * Test for derived data types that need memory allocation
 * For example - most ctdb structures
 */
#define PROTOCOL_TYPE3_TEST(TYPE, NAME)	\
static void TEST_FUNC(NAME)(void) \
{ \
	TALLOC_CTX *mem_ctx; \
	TYPE *p1, *p2; \
	size_t buflen, np = 0; \
	int ret; \
\
	mem_ctx = talloc_new(NULL); \
	assert(mem_ctx != NULL); \
	p1 = talloc_zero(mem_ctx, TYPE); \
	assert(p1 != NULL); \
	FILL_FUNC(NAME)(p1, p1); \
	buflen = LEN_FUNC(NAME)(p1); \
	assert(buflen < sizeof(BUFFER)); \
	PUSH_FUNC(NAME)(p1, BUFFER, &np); \
	assert(np == buflen); \
	np = 0; \
	ret = PULL_FUNC(NAME)(BUFFER, buflen, mem_ctx, &p2, &np); \
	assert(ret == 0); \
	assert(np == buflen); \
	VERIFY_FUNC(NAME)(p1, p2); \
	talloc_free(mem_ctx); \
}

extern uint8_t BUFFER[1024*1024];

int rand_int(int max);
uint8_t rand8(void);
uint16_t rand16(void);
int32_t rand32i(void);
uint32_t rand32(void);
uint64_t rand64(void);
double rand_double(void);

void fill_buffer(void *p, size_t len);
void verify_buffer(void *p1, void *p2, size_t len);

void fill_string(char *p, size_t len);
void verify_string(const char *p1, const char *p2);

void fill_ctdb_uint8(uint8_t *p);
void verify_ctdb_uint8(uint8_t *p1, uint8_t *p2);

void fill_ctdb_uint16(uint16_t *p);
void verify_ctdb_uint16(uint16_t *p1, uint16_t *p2);

void fill_ctdb_int32(int32_t *p);
void verify_ctdb_int32(int32_t *p1, int32_t *p2);

void fill_ctdb_uint32(uint32_t *p);
void verify_ctdb_uint32(uint32_t *p1, uint32_t *p2);

void fill_ctdb_uint64(uint64_t *p);
void verify_ctdb_uint64(uint64_t *p1, uint64_t *p2);

void fill_ctdb_double(double *p);
void verify_ctdb_double(double *p1, double *p2);

void fill_ctdb_bool(bool *p);
void verify_ctdb_bool(bool *p1, bool *p2);

void fill_ctdb_string(TALLOC_CTX *mem_ctx, const char **p);
void verify_ctdb_string(const char **p1, const char **p2);

void fill_ctdb_stringn(TALLOC_CTX *mem_ctx, const char **p);
void verify_ctdb_stringn(const char **p1, const char **p2);

void fill_ctdb_pid(pid_t *p);
void verify_ctdb_pid(pid_t *p1, pid_t *p2);

void fill_ctdb_timeval(struct timeval *p);
void verify_ctdb_timeval(struct timeval *p1, struct timeval *p2);

#endif /* __CTDB_PROTOCOL_COMMON_BASIC_H__ */


