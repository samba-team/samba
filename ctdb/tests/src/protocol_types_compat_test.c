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

static size_t ctdb_pulldb_ext_len_old(struct ctdb_pulldb_ext *in)
{
	return sizeof(struct ctdb_pulldb_ext);
}

static void ctdb_pulldb_ext_push_old(struct ctdb_pulldb_ext *in, uint8_t *buf)
{
	memcpy(buf, in, sizeof(struct ctdb_pulldb_ext));
}

static int ctdb_pulldb_ext_pull_old(uint8_t *buf, size_t buflen,
				    TALLOC_CTX *mem_ctx,
				    struct ctdb_pulldb_ext **out)
{
	struct ctdb_pulldb_ext *val;

	if (buflen < sizeof(struct ctdb_pulldb_ext)) {
		return EMSGSIZE;
	}

	val = talloc_memdup(mem_ctx, buf, sizeof(struct ctdb_pulldb_ext));
	if (val == NULL) {
		return ENOMEM;
	}

	*out = val;
	return 0;
}

static size_t ctdb_ltdb_header_len_old(struct ctdb_ltdb_header *in)
{
	return sizeof(struct ctdb_ltdb_header);
}

static void ctdb_ltdb_header_push_old(struct ctdb_ltdb_header *in,
				      uint8_t *buf)
{
	memcpy(buf, in, sizeof(struct ctdb_ltdb_header));
}

static int ctdb_ltdb_header_pull_old(uint8_t *buf, size_t buflen,
				     struct ctdb_ltdb_header *out)
{
	if (buflen < sizeof(struct ctdb_ltdb_header)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(struct ctdb_ltdb_header));
	return 0;
}

struct ctdb_rec_data_wire {
	uint32_t length;
	uint32_t reqid;
	uint32_t keylen;
	uint32_t datalen;
	uint8_t data[1];
};

static size_t ctdb_rec_data_len_old(struct ctdb_rec_data *in)
{
	return offsetof(struct ctdb_rec_data_wire, data) +
	       in->key.dsize + in->data.dsize +
	       (in->header == NULL ? 0 : sizeof(struct ctdb_ltdb_header));
}

static void ctdb_rec_data_push_old(struct ctdb_rec_data *in, uint8_t *buf)
{
	struct ctdb_rec_data_wire *wire = (struct ctdb_rec_data_wire *)buf;
	size_t offset;

	wire->length = ctdb_rec_data_len(in);
	wire->reqid = in->reqid;
	wire->keylen = in->key.dsize;
	wire->datalen = in->data.dsize;
	if (in->header != NULL) {
		wire->datalen += sizeof(struct ctdb_ltdb_header);
	}

	memcpy(wire->data, in->key.dptr, in->key.dsize);
	offset = in->key.dsize;
	if (in->header != NULL) {
		memcpy(&wire->data[offset], in->header,
		       sizeof(struct ctdb_ltdb_header));
		offset += sizeof(struct ctdb_ltdb_header);
	}
	if (in->data.dsize > 0) {
		memcpy(&wire->data[offset], in->data.dptr, in->data.dsize);
	}
}

static int ctdb_rec_data_pull_data_old(uint8_t *buf, size_t buflen,
				       uint32_t *reqid,
				       struct ctdb_ltdb_header **header,
				       TDB_DATA *key, TDB_DATA *data,
				       size_t *reclen)
{
	struct ctdb_rec_data_wire *wire = (struct ctdb_rec_data_wire *)buf;
	size_t offset;

	if (buflen < offsetof(struct ctdb_rec_data_wire, data)) {
		return EMSGSIZE;
	}
	if (wire->keylen > buflen || wire->datalen > buflen) {
		return EMSGSIZE;
	}
	if (offsetof(struct ctdb_rec_data_wire, data) + wire->keylen <
	    offsetof(struct ctdb_rec_data_wire, data)) {
		return EMSGSIZE;
	}
	if (offsetof(struct ctdb_rec_data_wire, data) +
		wire->keylen + wire->datalen <
	    offsetof(struct ctdb_rec_data_wire, data)) {
		return EMSGSIZE;
	}
	if (buflen < offsetof(struct ctdb_rec_data_wire, data) +
			wire->keylen + wire->datalen) {
		return EMSGSIZE;
	}

	*reqid = wire->reqid;

	key->dsize = wire->keylen;
	key->dptr = wire->data;
	offset = wire->keylen;

	/* Always set header to NULL.  If it is required, exact it using
	 * ctdb_rec_data_extract_header()
	 */
	*header = NULL;

	data->dsize = wire->datalen;
	data->dptr = &wire->data[offset];

	*reclen = offsetof(struct ctdb_rec_data_wire, data) +
			wire->keylen + wire->datalen;

	return 0;
}

static int ctdb_rec_data_pull_elems_old(uint8_t *buf, size_t buflen,
					TALLOC_CTX *mem_ctx,
					struct ctdb_rec_data *out)
{
	uint32_t reqid;
	struct ctdb_ltdb_header *header;
	TDB_DATA key, data;
	size_t reclen;
	int ret;

	ret = ctdb_rec_data_pull_data_old(buf, buflen, &reqid, &header,
					  &key, &data, &reclen);
	if (ret != 0) {
		return ret;
	}

	out->reqid = reqid;
	out->header = NULL;

	out->key.dsize = key.dsize;
	if (key.dsize > 0) {
		out->key.dptr = talloc_memdup(mem_ctx, key.dptr, key.dsize);
		if (out->key.dptr == NULL) {
			return ENOMEM;
		}
	}

	out->data.dsize = data.dsize;
	if (data.dsize > 0) {
		out->data.dptr = talloc_memdup(mem_ctx, data.dptr, data.dsize);
		if (out->data.dptr == NULL) {
			return ENOMEM;
		}
	}

	return 0;
}

static int ctdb_rec_data_pull_old(uint8_t *buf, size_t buflen,
				  TALLOC_CTX *mem_ctx,
				  struct ctdb_rec_data **out)
{
	struct ctdb_rec_data *val;
	int ret;

	val = talloc(mem_ctx, struct ctdb_rec_data);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_rec_data_pull_elems_old(buf, buflen, val, val);
	if (ret != 0) {
		TALLOC_FREE(val);
		return ret;
	}

	*out = val;
	return ret;
}

struct ctdb_rec_buffer_wire {
	uint32_t db_id;
	uint32_t count;
	uint8_t data[1];
};

static size_t ctdb_rec_buffer_len_old(struct ctdb_rec_buffer *in)
{
	return offsetof(struct ctdb_rec_buffer_wire, data) + in->buflen;
}

static void ctdb_rec_buffer_push_old(struct ctdb_rec_buffer *in, uint8_t *buf)
{
	struct ctdb_rec_buffer_wire *wire = (struct ctdb_rec_buffer_wire *)buf;

	wire->db_id = in->db_id;
	wire->count = in->count;
	if (in->buflen > 0) {
		memcpy(wire->data, in->buf, in->buflen);
	}
}

static int ctdb_rec_buffer_pull_old(uint8_t *buf, size_t buflen,
				    TALLOC_CTX *mem_ctx,
				    struct ctdb_rec_buffer **out)
{
	struct ctdb_rec_buffer *val;
	struct ctdb_rec_buffer_wire *wire = (struct ctdb_rec_buffer_wire *)buf;
	size_t offset;

	if (buflen < offsetof(struct ctdb_rec_buffer_wire, data)) {
		return EMSGSIZE;
	}

	val = talloc(mem_ctx, struct ctdb_rec_buffer);
	if (val == NULL) {
		return ENOMEM;
	}

	val->db_id = wire->db_id;
	val->count = wire->count;

	offset = offsetof(struct ctdb_rec_buffer_wire, data);
	val->buflen = buflen - offset;
	val->buf = talloc_memdup(val, wire->data, val->buflen);
	if (val->buf == NULL) {
		talloc_free(val);
		return ENOMEM;
	}

	*out = val;
	return 0;
}

static size_t ctdb_traverse_start_len_old(struct ctdb_traverse_start *in)
{
	return sizeof(struct ctdb_traverse_start);
}

static void ctdb_traverse_start_push_old(struct ctdb_traverse_start *in,
					 uint8_t *buf)
{
	memcpy(buf, in, sizeof(struct ctdb_traverse_start));
}

static int ctdb_traverse_start_pull_old(uint8_t *buf, size_t buflen,
					TALLOC_CTX *mem_ctx,
					struct ctdb_traverse_start **out)
{
	struct ctdb_traverse_start *val;

	if (buflen < sizeof(struct ctdb_traverse_start)) {
		return EMSGSIZE;
	}

	val = talloc_memdup(mem_ctx, buf, sizeof(struct ctdb_traverse_start));
	if (val == NULL) {
		return ENOMEM;
	}

	*out = val;
	return 0;
}

static size_t ctdb_traverse_all_len_old(struct ctdb_traverse_all *in)
{
	return sizeof(struct ctdb_traverse_all);
}

static void ctdb_traverse_all_push_old(struct ctdb_traverse_all *in,
				       uint8_t *buf)
{
	memcpy(buf, in, sizeof(struct ctdb_traverse_all));
}

static int ctdb_traverse_all_pull_old(uint8_t *buf, size_t buflen,
				      TALLOC_CTX *mem_ctx,
				      struct ctdb_traverse_all **out)
{
	struct ctdb_traverse_all *val;

	if (buflen < sizeof(struct ctdb_traverse_all)) {
		return EMSGSIZE;
	}

	val = talloc_memdup(mem_ctx, buf, sizeof(struct ctdb_traverse_all));
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
COMPAT_TYPE3_TEST(struct ctdb_pulldb_ext, ctdb_pulldb_ext);

COMPAT_TYPE1_TEST(struct ctdb_ltdb_header, ctdb_ltdb_header);

COMPAT_TYPE3_TEST(struct ctdb_rec_data, ctdb_rec_data);
COMPAT_TYPE3_TEST(struct ctdb_rec_buffer, ctdb_rec_buffer);
COMPAT_TYPE3_TEST(struct ctdb_traverse_start, ctdb_traverse_start);
COMPAT_TYPE3_TEST(struct ctdb_traverse_all, ctdb_traverse_all);

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
	COMPAT_TEST_FUNC(ctdb_pulldb_ext)();
	COMPAT_TEST_FUNC(ctdb_ltdb_header)();
	COMPAT_TEST_FUNC(ctdb_rec_data)();
	COMPAT_TEST_FUNC(ctdb_rec_buffer)();
	COMPAT_TEST_FUNC(ctdb_traverse_start)();
	COMPAT_TEST_FUNC(ctdb_traverse_all)();

	return 0;
}
