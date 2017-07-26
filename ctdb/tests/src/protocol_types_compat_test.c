/*
   protocol types backward compatibility test

   Copyright (C) Amitay Isaacs  2015

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
#include "system/filesys.h"

#include <assert.h>

#include "protocol/protocol_basic.c"
#include "protocol/protocol_types.c"

#include "tests/src/protocol_common.h"

#define COMPAT_TEST_FUNC(NAME)		test_ ##NAME## _compat
#define OLD_LEN_FUNC(NAME)		NAME## _len_old
#define OLD_PUSH_FUNC(NAME)		NAME## _push_old
#define OLD_PULL_FUNC(NAME)		NAME## _pull_old

#define COMPAT_TYPE1_TEST(TYPE, NAME)	\
static void COMPAT_TEST_FUNC(NAME)(void) \
{ \
	TALLOC_CTX *mem_ctx; \
	uint8_t *buf1, *buf2; \
	TYPE p = { 0 }, p1, p2; \
	size_t buflen1, buflen2, np = 0; \
	int ret; \
\
	mem_ctx = talloc_new(NULL); \
	assert(mem_ctx != NULL); \
	FILL_FUNC(NAME)(&p); \
	buflen1 = LEN_FUNC(NAME)(&p); \
	buflen2 = OLD_LEN_FUNC(NAME)(&p); \
	assert(buflen1 == buflen2); \
	buf1 = talloc_zero_size(mem_ctx, buflen1); \
	assert(buf1 != NULL); \
	buf2 = talloc_zero_size(mem_ctx, buflen2); \
	assert(buf2 != NULL); \
	PUSH_FUNC(NAME)(&p, buf1, &np); \
	OLD_PUSH_FUNC(NAME)(&p, buf2); \
	assert(memcmp(buf1, buf2, buflen1) == 0); \
	ret = PULL_FUNC(NAME)(buf1, buflen1, &p1, &np); \
	assert(ret == 0); \
	ret = OLD_PULL_FUNC(NAME)(buf2, buflen2, &p2); \
	VERIFY_FUNC(NAME)(&p1, &p2); \
	talloc_free(mem_ctx); \
}

#define COMPAT_TYPE3_TEST(TYPE, NAME)	\
static void COMPAT_TEST_FUNC(NAME)(void) \
{ \
	TALLOC_CTX *mem_ctx; \
	uint8_t *buf1, *buf2; \
	TYPE *p, *p1, *p2; \
	size_t buflen1, buflen2, np = 0; \
	int ret; \
\
	mem_ctx = talloc_new(NULL); \
	assert(mem_ctx != NULL); \
	p = talloc_zero(mem_ctx, TYPE); \
	assert(p != NULL); \
	FILL_FUNC(NAME)(p, p); \
	buflen1 = LEN_FUNC(NAME)(p); \
	buflen2 = OLD_LEN_FUNC(NAME)(p); \
	assert(buflen1 == buflen2); \
	buf1 = talloc_zero_size(mem_ctx, buflen1); \
	assert(buf1 != NULL); \
	buf2 = talloc_zero_size(mem_ctx, buflen2); \
	assert(buf2 != NULL); \
	PUSH_FUNC(NAME)(p, buf1, &np); \
	OLD_PUSH_FUNC(NAME)(p, buf2); \
	assert(memcmp(buf1, buf2, buflen1) == 0); \
	ret = PULL_FUNC(NAME)(buf1, buflen1, mem_ctx, &p1, &np); \
	assert(ret == 0); \
	ret = OLD_PULL_FUNC(NAME)(buf2, buflen2, mem_ctx, &p2); \
	VERIFY_FUNC(NAME)(p1, p2); \
	talloc_free(mem_ctx); \
}


static size_t ctdb_statistics_len_old(struct ctdb_statistics *in)
{
	return sizeof(struct ctdb_statistics);
}

static void ctdb_statistics_push_old(struct ctdb_statistics *in, uint8_t *buf)
{
	memcpy(buf, in, sizeof(struct ctdb_statistics));
}

static int ctdb_statistics_pull_old(uint8_t *buf, size_t buflen,
				    TALLOC_CTX *mem_ctx,
				    struct ctdb_statistics **out)
{
	struct ctdb_statistics *val;

	if (buflen < sizeof(struct ctdb_statistics)) {
		return EMSGSIZE;
	}

	val = talloc(mem_ctx, struct ctdb_statistics);
	if (val == NULL) {
		return ENOMEM;
	}

	memcpy(val, buf, sizeof(struct ctdb_statistics));

	*out = val;
	return 0;
}


COMPAT_TYPE3_TEST(struct ctdb_statistics, ctdb_statistics);

int main(int argc, char *argv[])
{
	if (argc == 2) {
		int seed = atoi(argv[1]);
		srandom(seed);
	}

	COMPAT_TEST_FUNC(ctdb_statistics)();

	return 0;
}
