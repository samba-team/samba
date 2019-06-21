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
	assert(ret == 0); \
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
	assert(ret == 0); \
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

static size_t ctdb_traverse_start_ext_len_old(
			struct ctdb_traverse_start_ext *in)
{
	return sizeof(struct ctdb_traverse_start_ext);
}

static void ctdb_traverse_start_ext_push_old(
			struct ctdb_traverse_start_ext *in, uint8_t *buf)
{
	memcpy(buf, in, sizeof(struct ctdb_traverse_start_ext));
}

static int ctdb_traverse_start_ext_pull_old(uint8_t *buf, size_t buflen,
					    TALLOC_CTX *mem_ctx,
					    struct ctdb_traverse_start_ext **out)
{
	struct ctdb_traverse_start_ext *val;

	if (buflen < sizeof(struct ctdb_traverse_start_ext)) {
		return EMSGSIZE;
	}

	val = talloc_memdup(mem_ctx, buf,
			    sizeof(struct ctdb_traverse_start_ext));
	if (val == NULL) {
		return ENOMEM;
	}

	*out = val;
	return 0;
}

static size_t ctdb_traverse_all_ext_len_old(struct ctdb_traverse_all_ext *in)
{
	return sizeof(struct ctdb_traverse_all_ext);
}

static void ctdb_traverse_all_ext_push_old(struct ctdb_traverse_all_ext *in,
					   uint8_t *buf)
{
	memcpy(buf, in, sizeof(struct ctdb_traverse_all_ext));
}

static int ctdb_traverse_all_ext_pull_old(uint8_t *buf, size_t buflen,
					  TALLOC_CTX *mem_ctx,
					  struct ctdb_traverse_all_ext **out)
{
	struct ctdb_traverse_all_ext *val;

	if (buflen < sizeof(struct ctdb_traverse_all_ext)) {
		return EMSGSIZE;
	}

	val = talloc_memdup(mem_ctx, buf,
			    sizeof(struct ctdb_traverse_all_ext));
	if (val == NULL) {
		return ENOMEM;
	}

	*out = val;
	return 0;
}

static size_t ctdb_sock_addr_len_old(ctdb_sock_addr *in)
{
	return sizeof(ctdb_sock_addr);
}

static void ctdb_sock_addr_push_old(ctdb_sock_addr *in, uint8_t *buf)
{
	memcpy(buf, in, sizeof(ctdb_sock_addr));
}

static int ctdb_sock_addr_pull_elems_old(uint8_t *buf, size_t buflen,
					 TALLOC_CTX *mem_ctx,
					 ctdb_sock_addr *out)
{
	if (buflen < sizeof(ctdb_sock_addr)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(ctdb_sock_addr));

	return 0;
}

static int ctdb_sock_addr_pull_old(uint8_t *buf, size_t buflen,
				   TALLOC_CTX *mem_ctx, ctdb_sock_addr **out)
{
	ctdb_sock_addr *val;
	int ret;

	val = talloc(mem_ctx, ctdb_sock_addr);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_sock_addr_pull_elems_old(buf, buflen, val, val);
	if (ret != 0) {
		TALLOC_FREE(val);
		return ret;
	}

	*out = val;
	return ret;
}

static size_t ctdb_connection_len_old(struct ctdb_connection *in)
{
	return sizeof(struct ctdb_connection);
}

static void ctdb_connection_push_old(struct ctdb_connection *in, uint8_t *buf)
{
	memcpy(buf, in, sizeof(struct ctdb_connection));
}

static int ctdb_connection_pull_elems_old(uint8_t *buf, size_t buflen,
					  TALLOC_CTX *mem_ctx,
					  struct ctdb_connection *out)
{
	if (buflen < sizeof(struct ctdb_connection)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(struct ctdb_connection));

	return 0;
}

static int ctdb_connection_pull_old(uint8_t *buf, size_t buflen,
				    TALLOC_CTX *mem_ctx,
				    struct ctdb_connection **out)
{
	struct ctdb_connection *val;
	int ret;

	val = talloc(mem_ctx, struct ctdb_connection);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_connection_pull_elems_old(buf, buflen, val, val);
	if (ret != 0) {
		TALLOC_FREE(val);
		return ret;
	}

	*out = val;
	return ret;
}

struct ctdb_tunable_wire {
	uint32_t value;
	uint32_t length;
	uint8_t name[1];
};

static size_t ctdb_tunable_len_old(struct ctdb_tunable *in)
{
	return offsetof(struct ctdb_tunable_wire, name) +
	       strlen(in->name) + 1;
}

static void ctdb_tunable_push_old(struct ctdb_tunable *in, uint8_t *buf)
{
	struct ctdb_tunable_wire *wire = (struct ctdb_tunable_wire *)buf;

	wire->value = in->value;
	wire->length = strlen(in->name) + 1;
	memcpy(wire->name, in->name, wire->length);
}

static int ctdb_tunable_pull_old(uint8_t *buf, size_t buflen,
				 TALLOC_CTX *mem_ctx,
				 struct ctdb_tunable **out)
{
	struct ctdb_tunable *val;
	struct ctdb_tunable_wire *wire = (struct ctdb_tunable_wire *)buf;

	if (buflen < offsetof(struct ctdb_tunable_wire, name)) {
		return EMSGSIZE;
	}
	if (wire->length > buflen) {
		return EMSGSIZE;
	}
	if (offsetof(struct ctdb_tunable_wire, name) + wire->length <
	    offsetof(struct ctdb_tunable_wire, name)) {
		return EMSGSIZE;
	}
	if (buflen < offsetof(struct ctdb_tunable_wire, name) + wire->length) {
		return EMSGSIZE;
	}

	val = talloc(mem_ctx, struct ctdb_tunable);
	if (val == NULL) {
		return ENOMEM;
	}

	val->value = wire->value;
	val->name = talloc_memdup(val, wire->name, wire->length);
	if (val->name == NULL) {
		talloc_free(val);
		return ENOMEM;
	}

	*out = val;
	return 0;
}

static size_t ctdb_node_flag_change_len_old(struct ctdb_node_flag_change *in)
{
	return sizeof(struct ctdb_node_flag_change);
}

static void ctdb_node_flag_change_push_old(struct ctdb_node_flag_change *in,
					   uint8_t *buf)
{
	memcpy(buf, in, sizeof(struct ctdb_node_flag_change));
}

static int ctdb_node_flag_change_pull_old(uint8_t *buf, size_t buflen,
					  TALLOC_CTX *mem_ctx,
					  struct ctdb_node_flag_change **out)
{
	struct ctdb_node_flag_change *val;

	if (buflen < sizeof(struct ctdb_node_flag_change)) {
		return EMSGSIZE;
	}

	val = talloc_memdup(mem_ctx, buf,
			    sizeof(struct ctdb_node_flag_change));
	if (val == NULL) {
		return ENOMEM;
	}

	*out = val;
	return 0;
}

struct ctdb_var_list_wire {
	uint32_t length;
	char list_str[1];
};

static size_t ctdb_var_list_len_old(struct ctdb_var_list *in)
{
	int i;
	size_t len = sizeof(uint32_t);

	for (i=0; i<in->count; i++) {
		assert(in->var[i] != NULL);
		len += strlen(in->var[i]) + 1;
	}
	return len;
}

static void ctdb_var_list_push_old(struct ctdb_var_list *in, uint8_t *buf)
{
	struct ctdb_var_list_wire *wire = (struct ctdb_var_list_wire *)buf;
	int i, n;
	size_t offset = 0;

	if (in->count > 0) {
		n = sprintf(wire->list_str, "%s", in->var[0]);
		offset += n;
	}
	for (i=1; i<in->count; i++) {
		n = sprintf(&wire->list_str[offset], ":%s", in->var[i]);
		offset += n;
	}
	wire->length = offset + 1;
}

static int ctdb_var_list_pull_old(uint8_t *buf, size_t buflen,
				  TALLOC_CTX *mem_ctx,
				  struct ctdb_var_list **out)
{
	struct ctdb_var_list *val = NULL;
	struct ctdb_var_list_wire *wire = (struct ctdb_var_list_wire *)buf;
	char *str, *s, *tok, *ptr;
	const char **list;

	if (buflen < sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (wire->length > buflen) {
		return EMSGSIZE;
	}
	if (sizeof(uint32_t) + wire->length < sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (buflen < sizeof(uint32_t) + wire->length) {
		return EMSGSIZE;
	}

	str = talloc_strndup(mem_ctx, (char *)wire->list_str, wire->length);
	if (str == NULL) {
		return ENOMEM;
	}

	val = talloc_zero(mem_ctx, struct ctdb_var_list);
	if (val == NULL) {
		goto fail;
	}

	s = str;
	while ((tok = strtok_r(s, ":", &ptr)) != NULL) {
		s = NULL;
		list = talloc_realloc(val, val->var, const char *,
				      val->count+1);
		if (list == NULL) {
			goto fail;
		}

		val->var = list;
		val->var[val->count] = talloc_strdup(val, tok);
		if (val->var[val->count] == NULL) {
			goto fail;
		}
		val->count++;
	}

	talloc_free(str);
	*out = val;
	return 0;

fail:
	talloc_free(str);
	talloc_free(val);
	return ENOMEM;
}

static size_t ctdb_tunable_list_len_old(struct ctdb_tunable_list *in)
{
	return sizeof(struct ctdb_tunable_list);
}

static void ctdb_tunable_list_push_old(struct ctdb_tunable_list *in,
				       uint8_t *buf)
{
	memcpy(buf, in, sizeof(struct ctdb_tunable_list));
}

static int ctdb_tunable_list_pull_old(uint8_t *buf, size_t buflen,
				      TALLOC_CTX *mem_ctx,
				      struct ctdb_tunable_list **out)
{
	struct ctdb_tunable_list *val;

	if (buflen < sizeof(struct ctdb_tunable_list)) {
		return EMSGSIZE;
	}

	val = talloc_memdup(mem_ctx, buf, sizeof(struct ctdb_tunable_list));
	if (val == NULL) {
		return ENOMEM;
	}

	*out = val;
	return 0;
}

struct ctdb_tickle_list_wire {
	ctdb_sock_addr addr;
	uint32_t num;
	struct ctdb_connection conn[1];
};

static size_t ctdb_tickle_list_len_old(struct ctdb_tickle_list *in)
{
	return offsetof(struct ctdb_tickle_list, conn) +
	       in->num * sizeof(struct ctdb_connection);
}

static void ctdb_tickle_list_push_old(struct ctdb_tickle_list *in,
				      uint8_t *buf)
{
	struct ctdb_tickle_list_wire *wire =
		(struct ctdb_tickle_list_wire *)buf;
	size_t offset;
	unsigned int i;

	memcpy(&wire->addr, &in->addr, sizeof(ctdb_sock_addr));
	wire->num = in->num;

	offset = offsetof(struct ctdb_tickle_list_wire, conn);
	for (i=0; i<in->num; i++) {
		ctdb_connection_push_old(&in->conn[i], &buf[offset]);
		offset += ctdb_connection_len_old(&in->conn[i]);
	}
}

static int ctdb_tickle_list_pull_old(uint8_t *buf, size_t buflen,
				     TALLOC_CTX *mem_ctx,
				     struct ctdb_tickle_list **out)
{
	struct ctdb_tickle_list *val;
	struct ctdb_tickle_list_wire *wire =
		(struct ctdb_tickle_list_wire *)buf;
	size_t offset;
	unsigned int i;
	int ret;

	if (buflen < offsetof(struct ctdb_tickle_list_wire, conn)) {
		return EMSGSIZE;
	}
	if (wire->num > buflen / sizeof(struct ctdb_connection)) {
		return EMSGSIZE;
	}
	if (offsetof(struct ctdb_tickle_list_wire, conn) +
	    wire->num * sizeof(struct ctdb_connection) <
	    offsetof(struct ctdb_tickle_list_wire, conn)) {
		return EMSGSIZE;
	}
	if (buflen < offsetof(struct ctdb_tickle_list_wire, conn) +
		     wire->num * sizeof(struct ctdb_connection)) {
		return EMSGSIZE;
	}

	val = talloc(mem_ctx, struct ctdb_tickle_list);
	if (val == NULL) {
		return ENOMEM;
	}

	offset = offsetof(struct ctdb_tickle_list, conn);
	memcpy(val, wire, offset);

	val->conn = talloc_array(val, struct ctdb_connection, wire->num);
	if (val->conn == NULL) {
		talloc_free(val);
		return ENOMEM;
	}

	for (i=0; i<wire->num; i++) {
		ret = ctdb_connection_pull_elems_old(&buf[offset],
						     buflen-offset,
						     val->conn,
						     &val->conn[i]);
		if (ret != 0) {
			talloc_free(val);
			return ret;
		}
		offset += ctdb_connection_len_old(&val->conn[i]);
	}

	*out = val;
	return 0;
}

struct ctdb_addr_info_wire {
	ctdb_sock_addr addr;
	uint32_t mask;
	uint32_t len;
	char iface[1];
};

static size_t ctdb_addr_info_len_old(struct ctdb_addr_info *in)
{
	uint32_t len;

	len = offsetof(struct ctdb_addr_info_wire, iface);
	if (in->iface != NULL) {
	       len += strlen(in->iface)+1;
	}

	return len;
}

static void ctdb_addr_info_push_old(struct ctdb_addr_info *in, uint8_t *buf)
{
	struct ctdb_addr_info_wire *wire = (struct ctdb_addr_info_wire *)buf;

	wire->addr = in->addr;
	wire->mask = in->mask;
	if (in->iface == NULL) {
		wire->len = 0;
	} else {
		wire->len = strlen(in->iface)+1;
		memcpy(wire->iface, in->iface, wire->len);
	}
}

static int ctdb_addr_info_pull_old(uint8_t *buf, size_t buflen,
				   TALLOC_CTX *mem_ctx,
				   struct ctdb_addr_info **out)
{
	struct ctdb_addr_info *val;
	struct ctdb_addr_info_wire *wire = (struct ctdb_addr_info_wire *)buf;

	if (buflen < offsetof(struct ctdb_addr_info_wire, iface)) {
		return EMSGSIZE;
	}
	if (wire->len > buflen) {
		return EMSGSIZE;
	}
	if (offsetof(struct ctdb_addr_info_wire, iface) + wire->len <
	    offsetof(struct ctdb_addr_info_wire, iface)) {
		return EMSGSIZE;
	}
	if (buflen < offsetof(struct ctdb_addr_info_wire, iface) + wire->len) {
		return EMSGSIZE;
	}

	val = talloc(mem_ctx, struct ctdb_addr_info);
	if (val == NULL) {
		return ENOMEM;
	}

	val->addr = wire->addr;
	val->mask = wire->mask;

	if (wire->len == 0) {
		val->iface = NULL;
	} else {
		val->iface = talloc_strndup(val, wire->iface, wire->len);
		if (val->iface == NULL) {
			talloc_free(val);
			return ENOMEM;
		}
	}

	*out = val;
	return 0;
}

static size_t ctdb_transdb_len_old(struct ctdb_transdb *in)
{
	return sizeof(struct ctdb_transdb);
}

static void ctdb_transdb_push_old(struct ctdb_transdb *in, uint8_t *buf)
{
	memcpy(buf, in, sizeof(struct ctdb_transdb));
}

static int ctdb_transdb_pull_old(uint8_t *buf, size_t buflen,
				 TALLOC_CTX *mem_ctx,
				 struct ctdb_transdb **out)
{
	struct ctdb_transdb *val;

	if (buflen < sizeof(struct ctdb_transdb)) {
		return EMSGSIZE;
	}

	val = talloc_memdup(mem_ctx, buf, sizeof(struct ctdb_transdb));
	if (val == NULL) {
		return ENOMEM;
	}

	*out = val;
	return 0;
}

static size_t ctdb_uptime_len_old(struct ctdb_uptime *in)
{
	return sizeof(struct ctdb_uptime);
}

static void ctdb_uptime_push_old(struct ctdb_uptime *in, uint8_t *buf)
{
	memcpy(buf, in, sizeof(struct ctdb_uptime));
}

static int ctdb_uptime_pull_old(uint8_t *buf, size_t buflen,
				TALLOC_CTX *mem_ctx, struct ctdb_uptime **out)
{
	struct ctdb_uptime *val;

	if (buflen < sizeof(struct ctdb_uptime)) {
		return EMSGSIZE;
	}

	val = talloc_memdup(mem_ctx, buf, sizeof(struct ctdb_uptime));
	if (val == NULL) {
		return ENOMEM;
	}

	*out = val;
	return 0;
}

static size_t ctdb_public_ip_len_old(struct ctdb_public_ip *in)
{
	return sizeof(struct ctdb_public_ip);
}

static void ctdb_public_ip_push_old(struct ctdb_public_ip *in, uint8_t *buf)
{
	memcpy(buf, in, sizeof(struct ctdb_public_ip));
}

static int ctdb_public_ip_pull_elems_old(uint8_t *buf, size_t buflen,
					 TALLOC_CTX *mem_ctx,
					 struct ctdb_public_ip *out)
{
	if (buflen < sizeof(struct ctdb_public_ip)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(struct ctdb_public_ip));

	return 0;
}

static int ctdb_public_ip_pull_old(uint8_t *buf, size_t buflen,
				   TALLOC_CTX *mem_ctx,
				   struct ctdb_public_ip **out)
{
	struct ctdb_public_ip *val;
	int ret;

	val = talloc(mem_ctx, struct ctdb_public_ip);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_public_ip_pull_elems_old(buf, buflen, val, val);
	if (ret != 0) {
		TALLOC_FREE(val);
		return ret;
	}

	*out = val;
	return ret;
}

struct ctdb_public_ip_list_wire {
	uint32_t num;
	struct ctdb_public_ip ip[1];
};

static size_t ctdb_public_ip_list_len_old(struct ctdb_public_ip_list *in)
{
	unsigned int i;
	size_t len;

	len = sizeof(uint32_t);
	for (i=0; i<in->num; i++) {
		len += ctdb_public_ip_len_old(&in->ip[i]);
	}
	return len;
}

static void ctdb_public_ip_list_push_old(struct ctdb_public_ip_list *in,
					 uint8_t *buf)
{
	struct ctdb_public_ip_list_wire *wire =
		(struct ctdb_public_ip_list_wire *)buf;
	size_t offset;
	unsigned int i;

	wire->num = in->num;

	offset = offsetof(struct ctdb_public_ip_list_wire, ip);
	for (i=0; i<in->num; i++) {
		ctdb_public_ip_push_old(&in->ip[i], &buf[offset]);
		offset += ctdb_public_ip_len_old(&in->ip[i]);
	}
}

static int ctdb_public_ip_list_pull_old(uint8_t *buf, size_t buflen,
					TALLOC_CTX *mem_ctx,
					struct ctdb_public_ip_list **out)
{
	struct ctdb_public_ip_list *val;
	struct ctdb_public_ip_list_wire *wire =
		(struct ctdb_public_ip_list_wire *)buf;
	size_t offset;
	unsigned int i;
	bool ret;

	if (buflen < sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (wire->num > buflen / sizeof(struct ctdb_public_ip)) {
		return EMSGSIZE;
	}
	if (sizeof(uint32_t) + wire->num * sizeof(struct ctdb_public_ip) <
	    sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (buflen < sizeof(uint32_t) +
		     wire->num * sizeof(struct ctdb_public_ip)) {
		return EMSGSIZE;
	}

	val = talloc(mem_ctx, struct ctdb_public_ip_list);
	if (val == NULL) {
		return ENOMEM;
	}

	val->num = wire->num;
	if (wire->num == 0) {
		val->ip = NULL;
		*out = val;
		return 0;
	}
	val->ip = talloc_array(val, struct ctdb_public_ip, wire->num);
	if (val->ip == NULL) {
		talloc_free(val);
		return ENOMEM;
	}

	offset = offsetof(struct ctdb_public_ip_list_wire, ip);
	for (i=0; i<wire->num; i++) {
		ret = ctdb_public_ip_pull_elems_old(&buf[offset],
						    buflen-offset,
						    val->ip,
						    &val->ip[i]);
		if (ret != 0) {
			talloc_free(val);
			return ret;
		}
		offset += ctdb_public_ip_len_old(&val->ip[i]);
	}

	*out = val;
	return 0;
}

static size_t ctdb_node_and_flags_len_old(struct ctdb_node_and_flags *in)
{
	return sizeof(struct ctdb_node_and_flags);
}

static void ctdb_node_and_flags_push_old(struct ctdb_node_and_flags *in,
					 uint8_t *buf)
{
	memcpy(buf, in, sizeof(struct ctdb_node_and_flags));
}

static int ctdb_node_and_flags_pull_elems_old(TALLOC_CTX *mem_ctx,
					      uint8_t *buf, size_t buflen,
					      struct ctdb_node_and_flags *out)
{
	if (buflen < sizeof(struct ctdb_node_and_flags)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(struct ctdb_node_and_flags));

	return 0;
}

static int ctdb_node_and_flags_pull_old(uint8_t *buf, size_t buflen,
					TALLOC_CTX *mem_ctx,
					struct ctdb_node_and_flags **out)
{
	struct ctdb_node_and_flags *val;
	int ret;

	val = talloc(mem_ctx, struct ctdb_node_and_flags);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_node_and_flags_pull_elems_old(val, buf, buflen, val);
	if (ret != 0) {
		TALLOC_FREE(val);
		return ret;
	}

	*out = val;
	return ret;
}

struct ctdb_node_map_wire {
	uint32_t num;
	struct ctdb_node_and_flags node[1];
};

static size_t ctdb_node_map_len_old(struct ctdb_node_map *in)
{
	return sizeof(uint32_t) +
	       in->num * sizeof(struct ctdb_node_and_flags);
}

static void ctdb_node_map_push_old(struct ctdb_node_map *in, uint8_t *buf)
{
	struct ctdb_node_map_wire *wire = (struct ctdb_node_map_wire *)buf;
	size_t offset;
	unsigned int i;

	wire->num = in->num;

	offset = offsetof(struct ctdb_node_map_wire, node);
	for (i=0; i<in->num; i++) {
		ctdb_node_and_flags_push_old(&in->node[i], &buf[offset]);
		offset += ctdb_node_and_flags_len_old(&in->node[i]);
	}
}

static int ctdb_node_map_pull_old(uint8_t *buf, size_t buflen,
				  TALLOC_CTX *mem_ctx,
				  struct ctdb_node_map **out)
{
	struct ctdb_node_map *val;
	struct ctdb_node_map_wire *wire = (struct ctdb_node_map_wire *)buf;
	size_t offset;
	unsigned int i;
	bool ret;

	if (buflen < sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (wire->num > buflen / sizeof(struct ctdb_node_and_flags)) {
		return EMSGSIZE;
	}
	if (sizeof(uint32_t) + wire->num * sizeof(struct ctdb_node_and_flags) <
	    sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (buflen < sizeof(uint32_t) +
		     wire->num * sizeof(struct ctdb_node_and_flags)) {
		return EMSGSIZE;
	}

	val = talloc(mem_ctx, struct ctdb_node_map);
	if (val == NULL) {
		return ENOMEM;
	}

	val->num = wire->num;
	val->node = talloc_array(val, struct ctdb_node_and_flags, wire->num);
	if (val->node == NULL) {
		talloc_free(val);
		return ENOMEM;
	}

	offset = offsetof(struct ctdb_node_map_wire, node);
	for (i=0; i<wire->num; i++) {
		ret = ctdb_node_and_flags_pull_elems_old(val->node,
							 &buf[offset],
							 buflen-offset,
							 &val->node[i]);
		if (ret != 0) {
			talloc_free(val);
			return ret;
		}
		offset += ctdb_node_and_flags_len_old(&val->node[i]);
	}

	*out = val;
	return 0;
}

static size_t ctdb_script_len_old(struct ctdb_script *in)
{
	return sizeof(struct ctdb_script);
}

static void ctdb_script_push_old(struct ctdb_script *in, uint8_t *buf)
{
	memcpy(buf, in, sizeof(struct ctdb_script));
}

static int ctdb_script_pull_elems_old(uint8_t *buf, size_t buflen,
				      TALLOC_CTX *mem_ctx,
				      struct ctdb_script *out)
{
	if (buflen < sizeof(struct ctdb_script)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(struct ctdb_script));

	return 0;
}

static int ctdb_script_pull_old(uint8_t *buf, size_t buflen,
				TALLOC_CTX *mem_ctx, struct ctdb_script **out)
{
	struct ctdb_script *val;
	int ret;

	val = talloc(mem_ctx, struct ctdb_script);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_script_pull_elems_old(buf, buflen, val, val);
	if (ret != 0) {
		TALLOC_FREE(val);
		return ret;
	}

	*out = val;
	return ret;
}

struct ctdb_script_list_wire {
	uint32_t num_scripts;
	struct ctdb_script script[1];
};

static size_t ctdb_script_list_len_old(struct ctdb_script_list *in)
{
	unsigned int i;
	size_t len;

	if (in == NULL) {
		return 0;
	}

	len = offsetof(struct ctdb_script_list_wire, script);
	for (i=0; i<in->num_scripts; i++) {
		len += ctdb_script_len_old(&in->script[i]);
	}
	return len;
}

static void ctdb_script_list_push_old(struct ctdb_script_list *in,
				      uint8_t *buf)
{
	struct ctdb_script_list_wire *wire =
		(struct ctdb_script_list_wire *)buf;
	size_t offset;
	unsigned int i;

	if (in == NULL) {
		return;
	}

	wire->num_scripts = in->num_scripts;

	offset = offsetof(struct ctdb_script_list_wire, script);
	for (i=0; i<in->num_scripts; i++) {
		ctdb_script_push_old(&in->script[i], &buf[offset]);
		offset += ctdb_script_len_old(&in->script[i]);
	}
}

static int ctdb_script_list_pull_old(uint8_t *buf, size_t buflen,
				     TALLOC_CTX *mem_ctx,
				     struct ctdb_script_list **out)
{
	struct ctdb_script_list *val;
	struct ctdb_script_list_wire *wire =
		(struct ctdb_script_list_wire *)buf;
	size_t offset;
	unsigned int i;
	bool ret;

	/* If event scripts have never been run, the result will be NULL */
	if (buflen == 0) {
		*out = NULL;
		return 0;
	}

	offset = offsetof(struct ctdb_script_list_wire, script);

	if (buflen < offset) {
		return EMSGSIZE;
	}
	if (wire->num_scripts > buflen / sizeof(struct ctdb_script)) {
		return EMSGSIZE;
	}
	if (offset + wire->num_scripts * sizeof(struct ctdb_script) < offset) {
		return EMSGSIZE;
	}
	if (buflen < offset + wire->num_scripts * sizeof(struct ctdb_script)) {
		return EMSGSIZE;
	}

	val = talloc(mem_ctx, struct ctdb_script_list);
	if (val == NULL) {
		return ENOMEM;

	}

	val->num_scripts = wire->num_scripts;
	val->script = talloc_array(val, struct ctdb_script, wire->num_scripts);
	if (val->script == NULL) {
		talloc_free(val);
		return ENOMEM;
	}

	for (i=0; i<wire->num_scripts; i++) {
		ret = ctdb_script_pull_elems_old(&buf[offset], buflen-offset,
						 val->script,
						 &val->script[i]);
		if (ret != 0) {
			talloc_free(val);
			return ret;
		}
		offset += ctdb_script_len_old(&val->script[i]);
	}

	*out = val;
	return 0;
}

static size_t ctdb_ban_state_len_old(struct ctdb_ban_state *in)
{
	return sizeof(struct ctdb_ban_state);
}

static void ctdb_ban_state_push_old(struct ctdb_ban_state *in, uint8_t *buf)
{
	memcpy(buf, in, sizeof(struct ctdb_ban_state));
}

static int ctdb_ban_state_pull_old(uint8_t *buf, size_t buflen,
				   TALLOC_CTX *mem_ctx,
				   struct ctdb_ban_state **out)
{
	struct ctdb_ban_state *val;

	if (buflen < sizeof(struct ctdb_ban_state)) {
		return EMSGSIZE;
	}

	val = talloc_memdup(mem_ctx, buf, sizeof(struct ctdb_ban_state));
	if (val == NULL) {
		return ENOMEM;
	}

	*out = val;
	return 0;
}

struct ctdb_notify_data_wire {
	uint64_t srvid;
	uint32_t len;
	uint8_t data[1];
};

static size_t ctdb_notify_data_len_old(struct ctdb_notify_data *in)
{
	return offsetof(struct ctdb_notify_data_wire, data) +
	       in->data.dsize;
}

static void ctdb_notify_data_push_old(struct ctdb_notify_data *in,
				      uint8_t *buf)
{
	struct ctdb_notify_data_wire *wire =
		(struct ctdb_notify_data_wire *)buf;

	wire->srvid = in->srvid;
	wire->len = in->data.dsize;
	memcpy(wire->data, in->data.dptr, in->data.dsize);
}

static int ctdb_notify_data_pull_old(uint8_t *buf, size_t buflen,
				     TALLOC_CTX *mem_ctx,
				     struct ctdb_notify_data **out)
{
	struct ctdb_notify_data *val;
	struct ctdb_notify_data_wire *wire =
		(struct ctdb_notify_data_wire *)buf;

	if (buflen < offsetof(struct ctdb_notify_data_wire, data)) {
		return EMSGSIZE;
	}
	if (wire->len > buflen) {
		return EMSGSIZE;
	}
	if (offsetof(struct ctdb_notify_data_wire, data) + wire->len <
	    offsetof(struct ctdb_notify_data_wire, data)) {
		return EMSGSIZE;
	}
	if (buflen < offsetof(struct ctdb_notify_data_wire, data) + wire->len) {
		return EMSGSIZE;
	}

	val = talloc(mem_ctx, struct ctdb_notify_data);
	if (val == NULL) {
		return ENOMEM;
	}

	val->srvid = wire->srvid;
	val->data.dsize = wire->len;
	val->data.dptr = talloc_memdup(val, wire->data, wire->len);
	if (val->data.dptr == NULL) {
		talloc_free(val);
		return ENOMEM;
	}

	*out = val;
	return 0;
}

static size_t ctdb_iface_len_old(struct ctdb_iface *in)
{
	return sizeof(struct ctdb_iface);
}

static void ctdb_iface_push_old(struct ctdb_iface *in, uint8_t *buf)
{
	memcpy(buf, in, sizeof(struct ctdb_iface));
}

static int ctdb_iface_pull_elems_old(uint8_t *buf, size_t buflen,
				     TALLOC_CTX *mem_ctx,
				     struct ctdb_iface *out)
{
	if (buflen < sizeof(struct ctdb_iface)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(struct ctdb_iface));

	return 0;
}

static int ctdb_iface_pull_old(uint8_t *buf, size_t buflen,
			       TALLOC_CTX *mem_ctx, struct ctdb_iface **out)
{
	struct ctdb_iface *val;
	int ret;

	val = talloc(mem_ctx, struct ctdb_iface);
	if (val == NULL) {
		return ENOMEM;
	}

	ret = ctdb_iface_pull_elems_old(buf, buflen, val, val);
	if (ret != 0) {
		TALLOC_FREE(val);
		return ret;
	}

	*out = val;
	return ret;
}

struct ctdb_iface_list_wire {
	uint32_t num;
	struct ctdb_iface iface[1];
};

static size_t ctdb_iface_list_len_old(struct ctdb_iface_list *in)
{
	return sizeof(uint32_t) +
	       in->num * sizeof(struct ctdb_iface);
}

static void ctdb_iface_list_push_old(struct ctdb_iface_list *in, uint8_t *buf)
{
	struct ctdb_iface_list_wire *wire =
		(struct ctdb_iface_list_wire *)buf;

	wire->num = in->num;
	memcpy(wire->iface, in->iface, in->num * sizeof(struct ctdb_iface));
}

static int ctdb_iface_list_pull_old(uint8_t *buf, size_t buflen,
				    TALLOC_CTX *mem_ctx,
				    struct ctdb_iface_list **out)
{
	struct ctdb_iface_list *val;
	struct ctdb_iface_list_wire *wire =
		(struct ctdb_iface_list_wire *)buf;

	if (buflen < sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (wire->num > buflen / sizeof(struct ctdb_iface)) {
		return EMSGSIZE;
	}
	if (sizeof(uint32_t) + wire->num * sizeof(struct ctdb_iface) <
	    sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (buflen < sizeof(uint32_t) + wire->num * sizeof(struct ctdb_iface)) {
		return EMSGSIZE;
	}

	val = talloc(mem_ctx, struct ctdb_iface_list);
	if (val == NULL) {
		return ENOMEM;
	}

	val->num = wire->num;
	val->iface = talloc_array(val, struct ctdb_iface, wire->num);
	if (val->iface == NULL) {
		talloc_free(val);
		return ENOMEM;
	}

	memcpy(val->iface, wire->iface, wire->num * sizeof(struct ctdb_iface));

	*out = val;
	return 0;
}

struct ctdb_public_ip_info_wire {
	struct ctdb_public_ip ip;
	uint32_t active_idx;
	uint32_t num;
	struct ctdb_iface ifaces[1];
};

static size_t ctdb_public_ip_info_len_old(struct ctdb_public_ip_info *in)
{
	return offsetof(struct ctdb_public_ip_info_wire, num) +
	       ctdb_iface_list_len_old(in->ifaces);
}

static void ctdb_public_ip_info_push_old(struct ctdb_public_ip_info *in,
					 uint8_t *buf)
{
	struct ctdb_public_ip_info_wire *wire =
		(struct ctdb_public_ip_info_wire *)buf;
	size_t offset;

	offset = offsetof(struct ctdb_public_ip_info_wire, num);
	memcpy(wire, in, offset);
	wire->num = in->ifaces->num;
	memcpy(wire->ifaces, in->ifaces->iface,
	       in->ifaces->num * sizeof(struct ctdb_iface));
}

static int ctdb_public_ip_info_pull_old(uint8_t *buf, size_t buflen,
					TALLOC_CTX *mem_ctx,
					struct ctdb_public_ip_info **out)
{
	struct ctdb_public_ip_info *val;
	struct ctdb_public_ip_info_wire *wire =
		(struct ctdb_public_ip_info_wire *)buf;

	if (buflen < offsetof(struct ctdb_public_ip_info_wire, ifaces)) {
		return EMSGSIZE;
	}
	if (wire->num > buflen / sizeof(struct ctdb_iface)) {
		return EMSGSIZE;
	}
	if (offsetof(struct ctdb_public_ip_info_wire, ifaces) +
	    wire->num * sizeof(struct ctdb_iface) <
	    offsetof(struct ctdb_public_ip_info_wire, ifaces)) {
		return EMSGSIZE;
	}
	if (buflen < offsetof(struct ctdb_public_ip_info_wire, ifaces) +
		     wire->num * sizeof(struct ctdb_iface)) {
		return EMSGSIZE;
	}

	val = talloc(mem_ctx, struct ctdb_public_ip_info);
	if (val == NULL) {
		return ENOMEM;
	}

	memcpy(val, wire, offsetof(struct ctdb_public_ip_info_wire, num));

	val->ifaces = talloc(val, struct ctdb_iface_list);
	if (val->ifaces == NULL) {
		talloc_free(val);
		return ENOMEM;
	}

	val->ifaces->num = wire->num;
	val->ifaces->iface = talloc_array(val->ifaces, struct ctdb_iface,
					  wire->num);
	if (val->ifaces->iface == NULL) {
		talloc_free(val);
		return ENOMEM;
	}

	memcpy(val->ifaces->iface, wire->ifaces,
	       wire->num * sizeof(struct ctdb_iface));

	*out = val;
	return 0;
}

struct ctdb_statistics_list_wire {
	uint32_t num;
	struct ctdb_statistics stats[1];
};

static size_t ctdb_statistics_list_len_old(struct ctdb_statistics_list *in)
{
	return offsetof(struct ctdb_statistics_list_wire, stats) +
	       in->num * sizeof(struct ctdb_statistics);
}

static void ctdb_statistics_list_push_old(struct ctdb_statistics_list *in,
					  uint8_t *buf)
{
	struct ctdb_statistics_list_wire *wire =
		(struct ctdb_statistics_list_wire *)buf;

	wire->num = in->num;
	memcpy(wire->stats, in->stats,
	       in->num * sizeof(struct ctdb_statistics));
}

static int ctdb_statistics_list_pull_old(uint8_t *buf, size_t buflen,
					 TALLOC_CTX *mem_ctx,
					 struct ctdb_statistics_list **out)
{
	struct ctdb_statistics_list *val;
	struct ctdb_statistics_list_wire *wire =
		(struct ctdb_statistics_list_wire *)buf;

	if (buflen < offsetof(struct ctdb_statistics_list_wire, stats)) {
		return EMSGSIZE;
	}
	if (wire->num > buflen / sizeof(struct ctdb_statistics)) {
		return EMSGSIZE;
	}
	if (offsetof(struct ctdb_statistics_list_wire, stats) +
	    wire->num * sizeof(struct ctdb_statistics) <
	    offsetof(struct ctdb_statistics_list_wire, stats)) {
		return EMSGSIZE;
	}
	if (buflen < offsetof(struct ctdb_statistics_list_wire, stats) +
		     wire->num * sizeof(struct ctdb_statistics)) {
		return EMSGSIZE;
	}

	val = talloc(mem_ctx, struct ctdb_statistics_list);
	if (val == NULL) {
		return ENOMEM;
	}

	val->num = wire->num;

	val->stats = talloc_array(val, struct ctdb_statistics, wire->num);
	if (val->stats == NULL) {
		talloc_free(val);
		return ENOMEM;
	}

	memcpy(val->stats, wire->stats,
	       wire->num * sizeof(struct ctdb_statistics));

	*out = val;
	return 0;
}

struct ctdb_key_data_wire {
	uint32_t db_id;
	struct ctdb_ltdb_header header;
	uint32_t keylen;
	uint8_t key[1];
};

static size_t ctdb_key_data_len_old(struct ctdb_key_data *in)
{
	return offsetof(struct ctdb_key_data_wire, key) + in->key.dsize;
}

static void ctdb_key_data_push_old(struct ctdb_key_data *in, uint8_t *buf)
{
	struct ctdb_key_data_wire *wire = (struct ctdb_key_data_wire *)buf;

	memcpy(wire, in, offsetof(struct ctdb_key_data, key));
	wire->keylen = in->key.dsize;
	memcpy(wire->key, in->key.dptr, in->key.dsize);
}

static int ctdb_key_data_pull_old(uint8_t *buf, size_t buflen,
				  TALLOC_CTX *mem_ctx,
				  struct ctdb_key_data **out)
{
	struct ctdb_key_data *val;
	struct ctdb_key_data_wire *wire = (struct ctdb_key_data_wire *)buf;

	if (buflen < offsetof(struct ctdb_key_data_wire, key)) {
		return EMSGSIZE;
	}
	if (wire->keylen > buflen) {
		return EMSGSIZE;
	}
	if (offsetof(struct ctdb_key_data_wire, key) + wire->keylen <
	    offsetof(struct ctdb_key_data_wire, key)) {
		return EMSGSIZE;
	}
	if (buflen < offsetof(struct ctdb_key_data_wire, key) + wire->keylen) {
		return EMSGSIZE;
	}

	val = talloc(mem_ctx, struct ctdb_key_data);
	if (val == NULL) {
		return ENOMEM;
	}

	memcpy(val, wire, offsetof(struct ctdb_key_data, key));

	val->key.dsize = wire->keylen;
	val->key.dptr = talloc_memdup(val, wire->key, wire->keylen);
	if (val->key.dptr == NULL) {
		talloc_free(val);
		return ENOMEM;
	}

	*out = val;
	return 0;
}

struct ctdb_db_statistics_wire {
	struct ctdb_db_statistics dbstats;
	char hot_keys_wire[1];
};

static size_t ctdb_db_statistics_len_old(struct ctdb_db_statistics *in)
{
	size_t len;
	int i;

	len = sizeof(struct ctdb_db_statistics);
	for (i=0; i<MAX_HOT_KEYS; i++) {
		len += in->hot_keys[i].key.dsize;
	}
	return len;
}

static void ctdb_db_statistics_push_old(struct ctdb_db_statistics *in,
					void *buf)
{
	struct ctdb_db_statistics_wire *wire =
		(struct ctdb_db_statistics_wire *)buf;
	size_t offset;
	int i;

	in->num_hot_keys = MAX_HOT_KEYS;
	memcpy(wire, in, sizeof(struct ctdb_db_statistics));

	offset = 0;
	for (i=0; i<MAX_HOT_KEYS; i++) {
		memcpy(&wire->hot_keys_wire[offset],
		       in->hot_keys[i].key.dptr,
		       in->hot_keys[i].key.dsize);
		offset += in->hot_keys[i].key.dsize;
	}
}

static int ctdb_db_statistics_pull_old(uint8_t *buf, size_t buflen,
				       TALLOC_CTX *mem_ctx,
				       struct ctdb_db_statistics **out)
{
	struct ctdb_db_statistics *val;
	struct ctdb_db_statistics_wire *wire =
		(struct ctdb_db_statistics_wire *)buf;
	size_t offset;
	unsigned int i;

	if (buflen < sizeof(struct ctdb_db_statistics)) {
		return EMSGSIZE;
	}

	offset = 0;
	for (i=0; i<wire->dbstats.num_hot_keys; i++) {
		if (wire->dbstats.hot_keys[i].key.dsize > buflen) {
			return EMSGSIZE;
		}
		if (offset + wire->dbstats.hot_keys[i].key.dsize < offset) {
			return EMSGSIZE;
		}
		offset += wire->dbstats.hot_keys[i].key.dsize;
		if (offset > buflen) {
			return EMSGSIZE;
		}
	}
	if (sizeof(struct ctdb_db_statistics) + offset <
	    sizeof(struct ctdb_db_statistics)) {
		return EMSGSIZE;
	}
	if (buflen < sizeof(struct ctdb_db_statistics) + offset) {
		return EMSGSIZE;
	}

	val = talloc(mem_ctx, struct ctdb_db_statistics);
	if (val == NULL) {
		return ENOMEM;
	}

	memcpy(val, wire, sizeof(struct ctdb_db_statistics));

	offset = 0;
	for (i=0; i<wire->dbstats.num_hot_keys; i++) {
		uint8_t *ptr;
		size_t key_size;

		key_size = val->hot_keys[i].key.dsize;
		ptr = talloc_memdup(mem_ctx, &wire->hot_keys_wire[offset],
				    key_size);
		if (ptr == NULL) {
			talloc_free(val);
			return ENOMEM;
		}
		val->hot_keys[i].key.dptr = ptr;
		offset += key_size;
	}

	*out = val;
	return 0;
}

static size_t ctdb_election_message_len_old(struct ctdb_election_message *in)
{
	return sizeof(struct ctdb_election_message);
}

static void ctdb_election_message_push_old(struct ctdb_election_message *in,
					   uint8_t *buf)
{
	memcpy(buf, in, sizeof(struct ctdb_election_message));
}

static int ctdb_election_message_pull_old(uint8_t *buf, size_t buflen,
					  TALLOC_CTX *mem_ctx,
					  struct ctdb_election_message **out)
{
	struct ctdb_election_message *val;

	if (buflen < sizeof(struct ctdb_election_message)) {
		return EMSGSIZE;
	}

	val = talloc_memdup(mem_ctx, buf,
			    sizeof(struct ctdb_election_message));
	if (val == NULL) {
		return ENOMEM;
	}

	*out = val;
	return 0;
}

static size_t ctdb_srvid_message_len_old(struct ctdb_srvid_message *in)
{
	return sizeof(struct ctdb_srvid_message);
}

static void ctdb_srvid_message_push_old(struct ctdb_srvid_message *in,
					uint8_t *buf)
{
	memcpy(buf, in, sizeof(struct ctdb_srvid_message));
}

static int ctdb_srvid_message_pull_old(uint8_t *buf, size_t buflen,
				       TALLOC_CTX *mem_ctx,
				       struct ctdb_srvid_message **out)
{
	struct ctdb_srvid_message *val;

	if (buflen < sizeof(struct ctdb_srvid_message)) {
		return EMSGSIZE;
	}

	val = talloc_memdup(mem_ctx, buf, sizeof(struct ctdb_srvid_message));
	if (val == NULL) {
		return ENOMEM;
	}

	*out = val;
	return 0;
}

static size_t ctdb_disable_message_len_old(struct ctdb_disable_message *in)
{
	return sizeof(struct ctdb_disable_message);
}

static void ctdb_disable_message_push_old(struct ctdb_disable_message *in,
					  uint8_t *buf)
{
	memcpy(buf, in, sizeof(struct ctdb_disable_message));
}

static int ctdb_disable_message_pull_old(uint8_t *buf, size_t buflen,
					 TALLOC_CTX *mem_ctx,
					 struct ctdb_disable_message **out)
{
	struct ctdb_disable_message *val;

	if (buflen < sizeof(struct ctdb_disable_message)) {
		return EMSGSIZE;
	}

	val = talloc_memdup(mem_ctx, buf, sizeof(struct ctdb_disable_message));
	if (val == NULL) {
		return ENOMEM;
	}

	*out = val;
	return 0;
}

static size_t ctdb_server_id_len_old(struct ctdb_server_id *in)
{
	return sizeof(struct ctdb_server_id);
}

static void ctdb_server_id_push_old(struct ctdb_server_id *in, uint8_t *buf)
{
	memcpy(buf, in, sizeof(struct ctdb_server_id));
}

static int ctdb_server_id_pull_old(uint8_t *buf, size_t buflen,
				   struct ctdb_server_id *out)
{
	if (buflen < sizeof(struct ctdb_server_id)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(struct ctdb_server_id));
	return 0;
}

static size_t ctdb_g_lock_len_old(struct ctdb_g_lock *in)
{
	return sizeof(struct ctdb_g_lock);
}

static void ctdb_g_lock_push_old(struct ctdb_g_lock *in, uint8_t *buf)
{
	memcpy(buf, in, sizeof(struct ctdb_g_lock));
}

static int ctdb_g_lock_pull_old(uint8_t *buf, size_t buflen,
				struct ctdb_g_lock *out)
{
	if (buflen < sizeof(struct ctdb_g_lock)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(struct ctdb_g_lock));
	return 0;
}

static size_t ctdb_g_lock_list_len_old(struct ctdb_g_lock_list *in)
{
	return in->num * sizeof(struct ctdb_g_lock);
}

static void ctdb_g_lock_list_push_old(struct ctdb_g_lock_list *in,
				      uint8_t *buf)
{
	size_t offset = 0;
	unsigned int i;

	for (i=0; i<in->num; i++) {
		ctdb_g_lock_push_old(&in->lock[i], &buf[offset]);
		offset += sizeof(struct ctdb_g_lock);
	}
}

static int ctdb_g_lock_list_pull_old(uint8_t *buf, size_t buflen,
				     TALLOC_CTX *mem_ctx,
				     struct ctdb_g_lock_list **out)
{
	struct ctdb_g_lock_list *val;
	unsigned count;
	size_t offset;
	unsigned int i;
	int ret;

	val = talloc_zero(mem_ctx, struct ctdb_g_lock_list);
	if (val == NULL) {
		return ENOMEM;
	}

	count = buflen / sizeof(struct ctdb_g_lock);
	val->lock = talloc_array(val, struct ctdb_g_lock, count);
	if (val->lock == NULL) {
		talloc_free(val);
		return ENOMEM;
	}

	offset = 0;
	for (i=0; i<count; i++) {
		ret = ctdb_g_lock_pull_old(&buf[offset], buflen-offset,
					   &val->lock[i]);
		if (ret != 0) {
			talloc_free(val);
			return ret;
		}
		offset += sizeof(struct ctdb_g_lock);
	}

	val->num = count;

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
COMPAT_TYPE3_TEST(struct ctdb_traverse_start_ext, ctdb_traverse_start_ext);
COMPAT_TYPE3_TEST(struct ctdb_traverse_all_ext, ctdb_traverse_all_ext);
COMPAT_TYPE3_TEST(ctdb_sock_addr, ctdb_sock_addr);
COMPAT_TYPE3_TEST(struct ctdb_connection, ctdb_connection);
COMPAT_TYPE3_TEST(struct ctdb_tunable, ctdb_tunable);
COMPAT_TYPE3_TEST(struct ctdb_node_flag_change, ctdb_node_flag_change);
COMPAT_TYPE3_TEST(struct ctdb_var_list, ctdb_var_list);
COMPAT_TYPE3_TEST(struct ctdb_tunable_list, ctdb_tunable_list);
COMPAT_TYPE3_TEST(struct ctdb_tickle_list, ctdb_tickle_list);
COMPAT_TYPE3_TEST(struct ctdb_addr_info, ctdb_addr_info);
COMPAT_TYPE3_TEST(struct ctdb_transdb, ctdb_transdb);
COMPAT_TYPE3_TEST(struct ctdb_uptime, ctdb_uptime);
COMPAT_TYPE3_TEST(struct ctdb_public_ip, ctdb_public_ip);
COMPAT_TYPE3_TEST(struct ctdb_public_ip_list, ctdb_public_ip_list);
COMPAT_TYPE3_TEST(struct ctdb_node_and_flags, ctdb_node_and_flags);
COMPAT_TYPE3_TEST(struct ctdb_node_map, ctdb_node_map);
COMPAT_TYPE3_TEST(struct ctdb_script, ctdb_script);
COMPAT_TYPE3_TEST(struct ctdb_script_list, ctdb_script_list);
COMPAT_TYPE3_TEST(struct ctdb_ban_state, ctdb_ban_state);
COMPAT_TYPE3_TEST(struct ctdb_notify_data, ctdb_notify_data);
COMPAT_TYPE3_TEST(struct ctdb_iface, ctdb_iface);
COMPAT_TYPE3_TEST(struct ctdb_iface_list, ctdb_iface_list);
COMPAT_TYPE3_TEST(struct ctdb_public_ip_info, ctdb_public_ip_info);
COMPAT_TYPE3_TEST(struct ctdb_statistics_list, ctdb_statistics_list);
COMPAT_TYPE3_TEST(struct ctdb_key_data, ctdb_key_data);
COMPAT_TYPE3_TEST(struct ctdb_db_statistics, ctdb_db_statistics);

COMPAT_TYPE3_TEST(struct ctdb_election_message, ctdb_election_message);
COMPAT_TYPE3_TEST(struct ctdb_srvid_message, ctdb_srvid_message);
COMPAT_TYPE3_TEST(struct ctdb_disable_message, ctdb_disable_message);

COMPAT_TYPE1_TEST(struct ctdb_server_id, ctdb_server_id);
COMPAT_TYPE1_TEST(struct ctdb_g_lock, ctdb_g_lock);

COMPAT_TYPE3_TEST(struct ctdb_g_lock_list, ctdb_g_lock_list);

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
	COMPAT_TEST_FUNC(ctdb_traverse_start_ext)();
	COMPAT_TEST_FUNC(ctdb_traverse_all_ext)();
	COMPAT_TEST_FUNC(ctdb_sock_addr)();
	COMPAT_TEST_FUNC(ctdb_connection)();
	COMPAT_TEST_FUNC(ctdb_tunable)();
	COMPAT_TEST_FUNC(ctdb_node_flag_change)();
	COMPAT_TEST_FUNC(ctdb_var_list)();
	COMPAT_TEST_FUNC(ctdb_tunable_list)();
	COMPAT_TEST_FUNC(ctdb_tickle_list)();
	COMPAT_TEST_FUNC(ctdb_addr_info)();
	COMPAT_TEST_FUNC(ctdb_transdb)();
	COMPAT_TEST_FUNC(ctdb_uptime)();
	COMPAT_TEST_FUNC(ctdb_public_ip)();
	COMPAT_TEST_FUNC(ctdb_public_ip_list)();
	COMPAT_TEST_FUNC(ctdb_node_and_flags)();
	COMPAT_TEST_FUNC(ctdb_node_map)();
	COMPAT_TEST_FUNC(ctdb_script)();
	COMPAT_TEST_FUNC(ctdb_script_list)();
	COMPAT_TEST_FUNC(ctdb_ban_state)();
	COMPAT_TEST_FUNC(ctdb_notify_data)();
	COMPAT_TEST_FUNC(ctdb_iface)();
	COMPAT_TEST_FUNC(ctdb_iface_list)();
	COMPAT_TEST_FUNC(ctdb_public_ip_info)();
	COMPAT_TEST_FUNC(ctdb_statistics_list)();
	COMPAT_TEST_FUNC(ctdb_key_data)();
	COMPAT_TEST_FUNC(ctdb_db_statistics)();

	COMPAT_TEST_FUNC(ctdb_election_message)();
	COMPAT_TEST_FUNC(ctdb_srvid_message)();
	COMPAT_TEST_FUNC(ctdb_disable_message)();
	COMPAT_TEST_FUNC(ctdb_server_id)();
	COMPAT_TEST_FUNC(ctdb_g_lock)();
	COMPAT_TEST_FUNC(ctdb_g_lock_list)();

	return 0;
}
