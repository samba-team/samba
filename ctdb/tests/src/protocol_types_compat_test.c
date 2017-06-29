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

struct ctdb_vnn_map_wire {
	uint32_t generation;
	uint32_t size;
	uint32_t map[1];
};

static size_t ctdb_vnn_map_len_old(struct ctdb_vnn_map *in)
{
	return offsetof(struct ctdb_vnn_map, map) +
	       in->size * sizeof(uint32_t);
}

static void ctdb_vnn_map_push_old(struct ctdb_vnn_map *in, uint8_t *buf)
{
	struct ctdb_vnn_map_wire *wire = (struct ctdb_vnn_map_wire *)buf;

	memcpy(wire, in, offsetof(struct ctdb_vnn_map, map));
	memcpy(wire->map, in->map, in->size * sizeof(uint32_t));
}

static int ctdb_vnn_map_pull_old(uint8_t *buf, size_t buflen,
				 TALLOC_CTX *mem_ctx,
				 struct ctdb_vnn_map **out)
{
	struct ctdb_vnn_map *val;
	struct ctdb_vnn_map_wire *wire = (struct ctdb_vnn_map_wire *)buf;

	if (buflen < offsetof(struct ctdb_vnn_map_wire, map)) {
		return EMSGSIZE;
	}
	if (wire->size > buflen / sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (offsetof(struct ctdb_vnn_map_wire, map) +
	    wire->size * sizeof(uint32_t) <
	    offsetof(struct ctdb_vnn_map_wire, map)) {
		    return EMSGSIZE;
	}
	if (buflen < offsetof(struct ctdb_vnn_map_wire, map) +
		     wire->size * sizeof(uint32_t)) {
		return EMSGSIZE;
	}

	val = talloc(mem_ctx, struct ctdb_vnn_map);
	if (val == NULL) {
		return ENOMEM;
	}

	memcpy(val, wire, offsetof(struct ctdb_vnn_map, map));

	val->map = talloc_memdup(val, wire->map,
				 wire->size * sizeof(uint32_t));
	if (val->map == NULL) {
		talloc_free(val);
		return ENOMEM;
	}

	*out = val;
	return 0;
}

struct ctdb_dbid_map_wire {
	uint32_t num;
	struct ctdb_dbid dbs[1];
};

static size_t ctdb_dbid_map_len_old(struct ctdb_dbid_map *in)
{
	return sizeof(uint32_t) + in->num * sizeof(struct ctdb_dbid);
}

static void ctdb_dbid_map_push_old(struct ctdb_dbid_map *in, uint8_t *buf)
{
	struct ctdb_dbid_map_wire *wire = (struct ctdb_dbid_map_wire *)buf;

	wire->num = in->num;
	memcpy(wire->dbs, in->dbs, in->num * sizeof(struct ctdb_dbid));
}

static int ctdb_dbid_map_pull_old(uint8_t *buf, size_t buflen,
				  TALLOC_CTX *mem_ctx,
				  struct ctdb_dbid_map **out)
{
	struct ctdb_dbid_map *val;
	struct ctdb_dbid_map_wire *wire = (struct ctdb_dbid_map_wire *)buf;

	if (buflen < sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (wire->num > buflen / sizeof(struct ctdb_dbid)) {
		return EMSGSIZE;
	}
	if (sizeof(uint32_t) + wire->num * sizeof(struct ctdb_dbid) <
	    sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (buflen < sizeof(uint32_t) + wire->num * sizeof(struct ctdb_dbid)) {
		return EMSGSIZE;
	}

	val = talloc(mem_ctx, struct ctdb_dbid_map);
	if (val == NULL) {
		return ENOMEM;
	}

	val->num = wire->num;

	val->dbs = talloc_memdup(val, wire->dbs,
				 wire->num * sizeof(struct ctdb_dbid));
	if (val->dbs == NULL) {
		talloc_free(val);
		return ENOMEM;
	}

	*out = val;
	return 0;
}

static size_t ctdb_pulldb_len_old(struct ctdb_pulldb *in)
{
	return sizeof(struct ctdb_pulldb);
}

static void ctdb_pulldb_push_old(struct ctdb_pulldb *in, uint8_t *buf)
{
	memcpy(buf, in, sizeof(struct ctdb_pulldb));
}

static int ctdb_pulldb_pull_old(uint8_t *buf, size_t buflen,
				TALLOC_CTX *mem_ctx, struct ctdb_pulldb **out)
{
	struct ctdb_pulldb *val;

	if (buflen < sizeof(struct ctdb_pulldb)) {
		return EMSGSIZE;
	}

	val = talloc_memdup(mem_ctx, buf, sizeof(struct ctdb_pulldb));
	if (val == NULL) {
		return ENOMEM;
	}

	*out = val;
	return 0;
}


COMPAT_TYPE3_TEST(struct ctdb_statistics, ctdb_statistics);
COMPAT_TYPE3_TEST(struct ctdb_vnn_map, ctdb_vnn_map);
COMPAT_TYPE3_TEST(struct ctdb_dbid_map, ctdb_dbid_map);
COMPAT_TYPE3_TEST(struct ctdb_pulldb, ctdb_pulldb);

int main(int argc, char *argv[])
{
	if (argc == 2) {
		int seed = atoi(argv[1]);
		srandom(seed);
	}

	COMPAT_TEST_FUNC(ctdb_statistics)();
	COMPAT_TEST_FUNC(ctdb_vnn_map)();
	COMPAT_TEST_FUNC(ctdb_dbid_map)();
	COMPAT_TEST_FUNC(ctdb_pulldb)();

	return 0;
}
