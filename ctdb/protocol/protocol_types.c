/*
   CTDB protocol marshalling

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
#include "system/network.h"

#include <talloc.h>
#include <tdb.h>

#include "protocol.h"
#include "protocol_private.h"
#include "protocol_api.h"

size_t ctdb_uint32_len(uint32_t val)
{
	return sizeof(uint32_t);
}

void ctdb_uint32_push(uint32_t val, uint8_t *buf)
{
	memcpy(buf, &val, sizeof(uint32_t));
}

int ctdb_uint32_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     uint32_t *out)
{
	if (buflen < sizeof(uint32_t)) {
		return EMSGSIZE;
	}

	*out = *(uint32_t *)buf;
	return 0;
}

size_t ctdb_uint64_len(uint64_t val)
{
	return sizeof(uint64_t);
}

void ctdb_uint64_push(uint64_t val, uint8_t *buf)
{
	memcpy(buf, &val, sizeof(uint64_t));
}

int ctdb_uint64_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     uint64_t *out)
{
	if (buflen < sizeof(uint64_t)) {
		return EMSGSIZE;
	}

	*out = *(uint64_t *)buf;
	return 0;
}

size_t ctdb_double_len(double val)
{
	return sizeof(double);
}

void ctdb_double_push(double val, uint8_t *buf)
{
	memcpy(buf, &val, sizeof(double));
}

int ctdb_double_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     double *out)
{
	if (buflen < sizeof(double)) {
		return EMSGSIZE;
	}

	*out = *(double *)buf;
	return 0;
}

size_t ctdb_uint8_array_len(struct ctdb_uint8_array *array)
{
	return array->num * sizeof(uint8_t);
}

void ctdb_uint8_array_push(struct ctdb_uint8_array *array, uint8_t *buf)
{
	memcpy(buf, array->val, array->num * sizeof(uint8_t));
}

int ctdb_uint8_array_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			  struct ctdb_uint8_array **out)
{
	struct ctdb_uint8_array *array;

	array = talloc(mem_ctx, struct ctdb_uint8_array);
	if (array == NULL) {
		return ENOMEM;
	}

	array->num = buflen / sizeof(uint8_t);

	array->val = talloc_array(array, uint8_t, array->num);
	if (array->val == NULL) {
		talloc_free(array);
		return ENOMEM;
	}
	memcpy(array->val, buf, buflen);

	*out = array;
	return 0;
}

size_t ctdb_uint64_array_len(struct ctdb_uint64_array *array)
{
	return array->num * sizeof(uint64_t);
}

void ctdb_uint64_array_push(struct ctdb_uint64_array *array, uint8_t *buf)
{
	memcpy(buf, array->val, array->num * sizeof(uint64_t));
}

int ctdb_uint64_array_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			   struct ctdb_uint64_array **out)
{
	struct ctdb_uint64_array *array;

	array = talloc(mem_ctx, struct ctdb_uint64_array);
	if (array == NULL) {
		return ENOMEM;
	}

	array->num = buflen / sizeof(uint64_t);

	array->val = talloc_array(array, uint64_t, array->num);
	if (array->val == NULL) {
		talloc_free(array);
		return ENOMEM;
	}
	memcpy(array->val, buf, buflen);

	*out = array;
	return 0;
}

size_t ctdb_pid_len(pid_t pid)
{
	return sizeof(pid_t);
}

void ctdb_pid_push(pid_t pid, uint8_t *buf)
{
	memcpy(buf, &pid, sizeof(pid_t));
}

int ctdb_pid_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		  pid_t *out)
{
	if (buflen < sizeof(pid_t)) {
		return EMSGSIZE;
	}

	*out = *(pid_t *)buf;
	return 0;
}

size_t ctdb_string_len(const char *str)
{
	if (str == NULL) {
		return 0;
	}
	return strlen(str) + 1;
}

void ctdb_string_push(const char *str, uint8_t *buf)
{
	if (str == NULL) {
		return;
	}
	memcpy(buf, str, strlen(str)+1);
}

int ctdb_string_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     const char **out)
{
	char *str;

	if (buflen == 0) {
		return 0;
	}

	str = talloc_strndup(mem_ctx, (char *)buf, buflen);
	if (str == NULL) {
		return ENOMEM;
	}

	*out = str;
	return 0;
}

struct stringn_wire {
	uint32_t length;
	uint8_t str[1];
};

size_t ctdb_stringn_len(const char *str)
{
	return sizeof(uint32_t) + strlen(str) + 1;
}

void ctdb_stringn_push(const char *str, uint8_t *buf)
{
	struct stringn_wire *wire = (struct stringn_wire *)buf;

	if (str == NULL) {
		wire->length = 0;
	} else {
		wire->length = strlen(str) + 1;
		memcpy(wire->str, str, wire->length);
	}
}

int ctdb_stringn_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		      const char **out)
{
	char *str;
	struct stringn_wire *wire = (struct stringn_wire *)buf;

	if (buflen < sizeof(uint32_t)) {
		return EMSGSIZE;
	}

	if (buflen < sizeof(uint32_t) + wire->length) {
		return EMSGSIZE;
	}

	str = talloc_strndup(mem_ctx, (char *)wire->str, wire->length);
	if (str == NULL) {
		return ENOMEM;
	}

	*out = str;
	return 0;
}

size_t ctdb_statistics_len(struct ctdb_statistics *stats)
{
	return sizeof(struct ctdb_statistics);
}

void ctdb_statistics_push(struct ctdb_statistics *stats, uint8_t *buf)
{
	memcpy(buf, stats, sizeof(struct ctdb_statistics));
}

int ctdb_statistics_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			 struct ctdb_statistics **out)
{
	struct ctdb_statistics *stats;
	struct ctdb_statistics *wire = (struct ctdb_statistics *)buf;

	if (buflen < sizeof(struct ctdb_statistics)) {
		return EMSGSIZE;
	}

	stats = talloc(mem_ctx, struct ctdb_statistics);
	if (stats == NULL) {
		return ENOMEM;
	}
	memcpy(stats, wire, sizeof(struct ctdb_statistics));

	*out = stats;
	return 0;
}

struct ctdb_statistics_list_wire {
	uint32_t num;
	struct ctdb_statistics stats[1];
};

size_t ctdb_statistics_list_len(struct ctdb_statistics_list *stats_list)
{
	return offsetof(struct ctdb_statistics_list_wire, stats) +
	       stats_list->num * sizeof(struct ctdb_statistics);
}

void ctdb_statistics_list_push(struct ctdb_statistics_list *stats_list,
			       uint8_t *buf)
{
	struct ctdb_statistics_list_wire *wire =
		(struct ctdb_statistics_list_wire *)buf;

	wire->num = stats_list->num;
	memcpy(wire->stats, stats_list->stats,
	       stats_list->num * sizeof(struct ctdb_statistics));
}

int ctdb_statistics_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			      struct ctdb_statistics_list **out)
{
	struct ctdb_statistics_list *stats_list;
	struct ctdb_statistics_list_wire *wire =
		(struct ctdb_statistics_list_wire *)buf;

	if (buflen < offsetof(struct ctdb_statistics_list_wire, stats)) {
		return EMSGSIZE;
	}
	if (buflen < offsetof(struct ctdb_statistics_list_wire, stats) +
		     wire->num * sizeof(struct ctdb_statistics)) {
		return EMSGSIZE;
	}

	stats_list = talloc(mem_ctx, struct ctdb_statistics_list);
	if (stats_list == NULL) {
		return ENOMEM;
	}

	stats_list->num = wire->num;

	stats_list->stats = talloc_array(stats_list, struct ctdb_statistics,
					 wire->num);
	if (stats_list->stats == NULL) {
		talloc_free(stats_list);
		return ENOMEM;
	}

	memcpy(stats_list->stats, wire->stats,
	       wire->num * sizeof(struct ctdb_statistics));

	*out = stats_list;
	return 0;
}

struct ctdb_vnn_map_wire {
	uint32_t generation;
	uint32_t size;
	uint32_t map[1];
};

size_t ctdb_vnn_map_len(struct ctdb_vnn_map *vnnmap)
{
	return offsetof(struct ctdb_vnn_map, map) +
	       vnnmap->size * sizeof(uint32_t);
}

void ctdb_vnn_map_push(struct ctdb_vnn_map *vnnmap, uint8_t *buf)
{
	struct ctdb_vnn_map_wire *wire = (struct ctdb_vnn_map_wire *)buf;

	memcpy(wire, vnnmap, offsetof(struct ctdb_vnn_map, map));
	memcpy(wire->map, vnnmap->map, vnnmap->size * sizeof(uint32_t));
}

int ctdb_vnn_map_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		      struct ctdb_vnn_map **out)
{
	struct ctdb_vnn_map *vnnmap;
	struct ctdb_vnn_map_wire *wire = (struct ctdb_vnn_map_wire *)buf;

	if (buflen < offsetof(struct ctdb_vnn_map_wire, map)) {
		return EMSGSIZE;
	}
	if (buflen < offsetof(struct ctdb_vnn_map_wire, map) +
		     wire->size * sizeof(uint32_t)) {
		return EMSGSIZE;
	}

	vnnmap = talloc(mem_ctx, struct ctdb_vnn_map);
	if (vnnmap == NULL) {
		return ENOMEM;
	}

	memcpy(vnnmap, wire, offsetof(struct ctdb_vnn_map, map));

	vnnmap->map = talloc_memdup(vnnmap, wire->map,
				    wire->size * sizeof(uint32_t));
	if (vnnmap->map == NULL) {
		talloc_free(vnnmap);
		return ENOMEM;
	}

	*out = vnnmap;
	return 0;
}

struct ctdb_dbid_map_wire {
	uint32_t num;
	struct ctdb_dbid dbs[1];
};

size_t ctdb_dbid_map_len(struct ctdb_dbid_map *dbmap)
{
	return sizeof(uint32_t) + dbmap->num * sizeof(struct ctdb_dbid);
}

void ctdb_dbid_map_push(struct ctdb_dbid_map *dbmap, uint8_t *buf)
{
	struct ctdb_dbid_map_wire *wire = (struct ctdb_dbid_map_wire *)buf;

	wire->num = dbmap->num;
	memcpy(wire->dbs, dbmap->dbs, dbmap->num * sizeof(struct ctdb_dbid));
}

int ctdb_dbid_map_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       struct ctdb_dbid_map **out)
{
	struct ctdb_dbid_map *dbmap;
	struct ctdb_dbid_map_wire *wire = (struct ctdb_dbid_map_wire *)buf;

	if (buflen < sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (buflen < sizeof(uint32_t) + wire->num * sizeof(struct ctdb_dbid)) {
		return EMSGSIZE;
	}

	dbmap = talloc(mem_ctx, struct ctdb_dbid_map);
	if (dbmap == NULL) {
		return ENOMEM;
	}

	dbmap->num = wire->num;

	dbmap->dbs = talloc_memdup(dbmap, wire->dbs,
				   wire->num * sizeof(struct ctdb_dbid));
	if (dbmap->dbs == NULL) {
		talloc_free(dbmap);
		return ENOMEM;
	}

	*out = dbmap;
	return 0;
}

size_t ctdb_pulldb_len(struct ctdb_pulldb *pulldb)
{
	return sizeof(struct ctdb_pulldb);
}

void ctdb_pulldb_push(struct ctdb_pulldb *pulldb, uint8_t *buf)
{
	memcpy(buf, pulldb, sizeof(struct ctdb_pulldb));
}

int ctdb_pulldb_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     struct ctdb_pulldb **out)
{
	struct ctdb_pulldb *pulldb;

	if (buflen < sizeof(struct ctdb_pulldb)) {
		return EMSGSIZE;
	}

	pulldb = talloc_memdup(mem_ctx, buf, sizeof(struct ctdb_pulldb));
	if (pulldb == NULL) {
		return ENOMEM;
	}

	*out = pulldb;
	return 0;
}

size_t ctdb_ltdb_header_len(struct ctdb_ltdb_header *header)
{
	return sizeof(struct ctdb_ltdb_header);
}

void ctdb_ltdb_header_push(struct ctdb_ltdb_header *header, uint8_t *buf)
{
	memcpy(buf, header, sizeof(struct ctdb_ltdb_header));
}

int ctdb_ltdb_header_pull(uint8_t *buf, size_t buflen,
			  struct ctdb_ltdb_header *header)
{
	if (buflen < sizeof(struct ctdb_ltdb_header)) {
		return EMSGSIZE;
	}

	memcpy(header, buf, sizeof(struct ctdb_ltdb_header));
	return 0;
}

int ctdb_ltdb_header_extract(TDB_DATA *data, struct ctdb_ltdb_header *header)
{
	int ret;

	ret = ctdb_ltdb_header_pull(data->dptr, data->dsize, header);
	if (ret != 0) {
		return ret;
	}

	data->dptr += sizeof(struct ctdb_ltdb_header);
	data->dsize -= sizeof(struct ctdb_ltdb_header);

	return 0;
}

struct ctdb_rec_data_wire {
	uint32_t length;
	uint32_t reqid;
	uint32_t keylen;
	uint32_t datalen;
	uint8_t data[1];
};

size_t ctdb_rec_data_len(struct ctdb_rec_data *rec)
{
	return offsetof(struct ctdb_rec_data_wire, data) +
	       rec->key.dsize + rec->data.dsize +
	       (rec->header == NULL ? 0 : sizeof(struct ctdb_ltdb_header));
}

void ctdb_rec_data_push(struct ctdb_rec_data *rec, uint8_t *buf)
{
	struct ctdb_rec_data_wire *wire = (struct ctdb_rec_data_wire *)buf;
	size_t offset;

	wire->length = ctdb_rec_data_len(rec);
	wire->reqid = rec->reqid;
	wire->keylen = rec->key.dsize;
	wire->datalen = rec->data.dsize;
	if (rec->header != NULL) {
		wire->datalen += sizeof(struct ctdb_ltdb_header);
	}

	memcpy(wire->data, rec->key.dptr, rec->key.dsize);
	offset = rec->key.dsize;
	if (rec->header != NULL) {
		memcpy(&wire->data[offset], rec->header,
		       sizeof(struct ctdb_ltdb_header));
		offset += sizeof(struct ctdb_ltdb_header);
	}
	if (rec->data.dsize > 0) {
		memcpy(&wire->data[offset], rec->data.dptr, rec->data.dsize);
	}
}

static int ctdb_rec_data_pull_data(uint8_t *buf, size_t buflen,
				   uint32_t *reqid,
				   struct ctdb_ltdb_header **header,
				   TDB_DATA *key, TDB_DATA *data,
				   size_t *reclen)
{
	struct ctdb_rec_data_wire *wire = (struct ctdb_rec_data_wire *)buf;
	size_t offset, n;

	if (buflen < offsetof(struct ctdb_rec_data_wire, data)) {
		return EMSGSIZE;
	}
	n = offsetof(struct ctdb_rec_data_wire, data) +
		wire->keylen + wire->datalen;
	if (buflen < n) {
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

	*reclen = n;

	return 0;
}

static int ctdb_rec_data_pull_elems(uint8_t *buf, size_t buflen,
				    TALLOC_CTX *mem_ctx,
				    struct ctdb_rec_data *out)
{
	uint32_t reqid;
	struct ctdb_ltdb_header *header;
	TDB_DATA key, data;
	size_t reclen;
	int ret;

	ret = ctdb_rec_data_pull_data(buf, buflen, &reqid, &header,
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

int ctdb_rec_data_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       struct ctdb_rec_data **out)
{
	struct ctdb_rec_data *rec;
	int ret;

	rec = talloc(mem_ctx, struct ctdb_rec_data);
	if (rec == NULL) {
		return ENOMEM;
	}

	ret = ctdb_rec_data_pull_elems(buf, buflen, rec, rec);
	if (ret != 0) {
		TALLOC_FREE(rec);
	}

	*out = rec;
	return ret;
}

struct ctdb_rec_buffer_wire {
	uint32_t db_id;
	uint32_t count;
	uint8_t data[1];
};

size_t ctdb_rec_buffer_len(struct ctdb_rec_buffer *recbuf)
{
	return offsetof(struct ctdb_rec_buffer_wire, data) + recbuf->buflen;
}

void ctdb_rec_buffer_push(struct ctdb_rec_buffer *recbuf, uint8_t *buf)
{
	struct ctdb_rec_buffer_wire *wire = (struct ctdb_rec_buffer_wire *)buf;

	wire->db_id = recbuf->db_id;
	wire->count = recbuf->count;
	if (recbuf->buflen > 0) {
		memcpy(wire->data, recbuf->buf, recbuf->buflen);
	}
}

int ctdb_rec_buffer_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			 struct ctdb_rec_buffer **out)
{
	struct ctdb_rec_buffer *recbuf;
	struct ctdb_rec_buffer_wire *wire = (struct ctdb_rec_buffer_wire *)buf;
	size_t offset;

	if (buflen < offsetof(struct ctdb_rec_buffer_wire, data)) {
		return EMSGSIZE;
	}

	recbuf = talloc(mem_ctx, struct ctdb_rec_buffer);
	if (recbuf == NULL) {
		return ENOMEM;
	}

	recbuf->db_id = wire->db_id;
	recbuf->count = wire->count;

	offset = offsetof(struct ctdb_rec_buffer_wire, data);
	recbuf->buflen = buflen - offset;
	recbuf->buf = talloc_memdup(recbuf, wire->data, recbuf->buflen);
	if (recbuf->buf == NULL) {
		talloc_free(recbuf);
		return ENOMEM;
	}

	*out = recbuf;
	return 0;
}

struct ctdb_rec_buffer *ctdb_rec_buffer_init(TALLOC_CTX *mem_ctx,
					     uint32_t db_id)
{
	struct ctdb_rec_buffer *recbuf;

	recbuf = talloc_zero(mem_ctx, struct ctdb_rec_buffer);
	if (recbuf == NULL) {
		return recbuf;
	}

	recbuf->db_id = db_id;

	return recbuf;
}

int ctdb_rec_buffer_add(TALLOC_CTX *mem_ctx, struct ctdb_rec_buffer *recbuf,
			uint32_t reqid, struct ctdb_ltdb_header *header,
			TDB_DATA key, TDB_DATA data)
{
	struct ctdb_rec_data recdata;
	size_t len;
	uint8_t *ptr;

	recdata.reqid = reqid;
	recdata.header = header;
	recdata.key = key;
	recdata.data = data;

	len = ctdb_rec_data_len(&recdata);

	ptr = talloc_realloc(mem_ctx, recbuf->buf, uint8_t,
			     recbuf->buflen + len);
	if (ptr == NULL) {
		return ENOMEM;
	}

	ctdb_rec_data_push(&recdata, &ptr[recbuf->buflen]);

	recbuf->count++;
	recbuf->buf = ptr;
	recbuf->buflen += len;
	return 0;
}

int ctdb_rec_buffer_traverse(struct ctdb_rec_buffer *recbuf,
			     ctdb_rec_parser_func_t func,
			     void *private_data)
{
	struct ctdb_ltdb_header *header;
	TDB_DATA key, data;
	uint32_t reqid;
	size_t offset, reclen;
	int ret = 0, i;

	offset = 0;
	for (i=0; i<recbuf->count; i++) {
		ret = ctdb_rec_data_pull_data(&recbuf->buf[offset],
					      recbuf->buflen - offset,
					      &reqid, &header,
					      &key, &data, &reclen);
		if (ret != 0) {
			return ret;
		}

		ret = func(reqid, header, key, data, private_data);
		if (ret != 0) {
			break;
		}

		offset += reclen;
	}

	return ret;
}

size_t ctdb_traverse_start_len(struct ctdb_traverse_start *traverse)
{
	return sizeof(struct ctdb_traverse_start);
}

void ctdb_traverse_start_push(struct ctdb_traverse_start *traverse,
			      uint8_t *buf)
{
	memcpy(buf, traverse, sizeof(struct ctdb_traverse_start));
}

int ctdb_traverse_start_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			     struct ctdb_traverse_start **out)
{
	struct ctdb_traverse_start *traverse;

	if (buflen < sizeof(struct ctdb_traverse_start)) {
		return EMSGSIZE;
	}

	traverse = talloc_memdup(mem_ctx, buf,
				 sizeof(struct ctdb_traverse_start));
	if (traverse == NULL) {
		return ENOMEM;
	}

	*out = traverse;
	return 0;
}

size_t ctdb_traverse_all_len(struct ctdb_traverse_all *traverse)
{
	return sizeof(struct ctdb_traverse_all);
}

void ctdb_traverse_all_push(struct ctdb_traverse_all *traverse, uint8_t *buf)
{
	memcpy(buf, traverse, sizeof(struct ctdb_traverse_all));
}

int ctdb_traverse_all_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			   struct ctdb_traverse_all **out)
{
	struct ctdb_traverse_all *traverse;

	if (buflen < sizeof(struct ctdb_traverse_all)) {
		return EMSGSIZE;
	}

	traverse = talloc_memdup(mem_ctx, buf,
				 sizeof(struct ctdb_traverse_all));
	if (traverse == NULL) {
		return ENOMEM;
	}

	*out = traverse;
	return 0;
}

size_t ctdb_traverse_start_ext_len(struct ctdb_traverse_start_ext *traverse)
{
	return sizeof(struct ctdb_traverse_start_ext);
}

void ctdb_traverse_start_ext_push(struct ctdb_traverse_start_ext *traverse,
				  uint8_t *buf)
{
	memcpy(buf, traverse, sizeof(struct ctdb_traverse_start_ext));
}

int ctdb_traverse_start_ext_pull(uint8_t *buf, size_t buflen,
				 TALLOC_CTX *mem_ctx,
				 struct ctdb_traverse_start_ext **out)
{
	struct ctdb_traverse_start_ext *traverse;

	if (buflen < sizeof(struct ctdb_traverse_start_ext)) {
		return EMSGSIZE;
	}

	traverse = talloc_memdup(mem_ctx, buf,
				 sizeof(struct ctdb_traverse_start_ext));
	if (traverse == NULL) {
		return ENOMEM;
	}

	*out = traverse;
	return 0;
}

size_t ctdb_traverse_all_ext_len(struct ctdb_traverse_all_ext *traverse)
{
	return sizeof(struct ctdb_traverse_all_ext);
}

void ctdb_traverse_all_ext_push(struct ctdb_traverse_all_ext *traverse,
				uint8_t *buf)
{
	memcpy(buf, traverse, sizeof(struct ctdb_traverse_all_ext));
}

int ctdb_traverse_all_ext_pull(uint8_t *buf, size_t buflen,
			       TALLOC_CTX *mem_ctx,
			       struct ctdb_traverse_all_ext **out)
{
	struct ctdb_traverse_all_ext *traverse;

	if (buflen < sizeof(struct ctdb_traverse_all_ext)) {
		return EMSGSIZE;
	}

	traverse = talloc_memdup(mem_ctx, buf,
				 sizeof(struct ctdb_traverse_all_ext));
	if (traverse == NULL) {
		return ENOMEM;
	}

	*out = traverse;
	return 0;
}

size_t ctdb_sock_addr_len(ctdb_sock_addr *addr)
{
	return sizeof(ctdb_sock_addr);
}

void ctdb_sock_addr_push(ctdb_sock_addr *addr, uint8_t *buf)
{
	memcpy(buf, addr, sizeof(ctdb_sock_addr));
}

static int ctdb_sock_addr_pull_elems(uint8_t *buf, size_t buflen,
				     TALLOC_CTX *mem_ctx, ctdb_sock_addr *out)
{
	if (buflen < sizeof(ctdb_sock_addr)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(ctdb_sock_addr));

	return 0;
}

int ctdb_sock_addr_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			ctdb_sock_addr **out)
{
	ctdb_sock_addr *addr;
	int ret;

	addr = talloc(mem_ctx, ctdb_sock_addr);
	if (addr == NULL) {
		return false;
	}

	ret = ctdb_sock_addr_pull_elems(buf, buflen, addr, addr);
	if (ret != 0) {
		TALLOC_FREE(addr);
	}

	*out = addr;
	return ret;
}

size_t ctdb_connection_len(struct ctdb_connection *conn)
{
	return sizeof(struct ctdb_connection);
}

void ctdb_connection_push(struct ctdb_connection *conn, uint8_t *buf)
{
	memcpy(buf, conn, sizeof(struct ctdb_connection));
}

static int ctdb_connection_pull_elems(uint8_t *buf, size_t buflen,
				      TALLOC_CTX *mem_ctx,
				      struct ctdb_connection *out)
{
	if (buflen < sizeof(struct ctdb_connection)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(struct ctdb_connection));

	return 0;
}

int ctdb_connection_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			 struct ctdb_connection **out)
{
	struct ctdb_connection *conn;
	int ret;

	conn = talloc(mem_ctx, struct ctdb_connection);
	if (conn == NULL) {
		return ENOMEM;
	}

	ret = ctdb_connection_pull_elems(buf, buflen, conn, conn);
	if (ret != 0) {
		TALLOC_FREE(conn);
	}

	*out = conn;
	return ret;
}

struct ctdb_tunable_wire {
	uint32_t value;
	uint32_t length;
	uint8_t name[1];
};

size_t ctdb_tunable_len(struct ctdb_tunable *tunable)
{
	return offsetof(struct ctdb_tunable_wire, name) +
	       strlen(tunable->name) + 1;
}

void ctdb_tunable_push(struct ctdb_tunable *tunable, uint8_t *buf)
{
	struct ctdb_tunable_wire *wire = (struct ctdb_tunable_wire *)buf;

	wire->value = tunable->value;
	wire->length = strlen(tunable->name) + 1;
	memcpy(wire->name, tunable->name, wire->length);
}

int ctdb_tunable_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		      struct ctdb_tunable **out)
{
	struct ctdb_tunable *tunable;
	struct ctdb_tunable_wire *wire = (struct ctdb_tunable_wire *)buf;

	if (buflen < offsetof(struct ctdb_tunable_wire, name)) {
		return EMSGSIZE;
	}
	if (buflen < offsetof(struct ctdb_tunable_wire, name) + wire->length) {
		return EMSGSIZE;
	}

	tunable = talloc(mem_ctx, struct ctdb_tunable);
	if (tunable == NULL) {
		return ENOMEM;
	}

	tunable->value = wire->value;
	tunable->name = talloc_memdup(tunable, wire->name, wire->length);
	if (tunable->name == NULL) {
		talloc_free(tunable);
		return ENOMEM;
	}

	*out = tunable;
	return 0;
}

size_t ctdb_node_flag_change_len(struct ctdb_node_flag_change *flag_change)
{
	return sizeof(struct ctdb_node_flag_change);
}

void ctdb_node_flag_change_push(struct ctdb_node_flag_change *flag_change,
				uint8_t *buf)
{
	memcpy(buf, flag_change, sizeof(struct ctdb_node_flag_change));
}

int ctdb_node_flag_change_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			       struct ctdb_node_flag_change **out)
{
	struct ctdb_node_flag_change *flag_change;

	if (buflen < sizeof(struct ctdb_node_flag_change)) {
		return EMSGSIZE;
	}

	flag_change = talloc_memdup(mem_ctx, buf,
				    sizeof(struct ctdb_node_flag_change));
	if (flag_change == NULL) {
		return ENOMEM;
	}

	*out = flag_change;
	return 0;
}

struct ctdb_var_list_wire {
	uint32_t length;
	char list_str[1];
};

size_t ctdb_var_list_len(struct ctdb_var_list *var_list)
{
	int i;
	size_t len = sizeof(uint32_t);

	for (i=0; i<var_list->count; i++) {
		len += strlen(var_list->var[i]) + 1;
	}
	return len;
}

void ctdb_var_list_push(struct ctdb_var_list *var_list, uint8_t *buf)
{
	struct ctdb_var_list_wire *wire = (struct ctdb_var_list_wire *)buf;
	int i, n;
	size_t offset = 0;

	if (var_list->count > 0) {
		n = sprintf(wire->list_str, "%s", var_list->var[0]);
		offset += n;
	}
	for (i=1; i<var_list->count; i++) {
		n = sprintf(&wire->list_str[offset], ":%s", var_list->var[i]);
		offset += n;
	}
	wire->length = offset + 1;
}

int ctdb_var_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       struct ctdb_var_list **out)
{
	struct ctdb_var_list *var_list = NULL;
	struct ctdb_var_list_wire *wire = (struct ctdb_var_list_wire *)buf;
	char *str, *s, *tok, *ptr;
	const char **list;

	if (buflen < sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (buflen < sizeof(uint32_t) + wire->length) {
		return EMSGSIZE;
	}

	str = talloc_strndup(mem_ctx, (char *)wire->list_str, wire->length);
	if (str == NULL) {
		return ENOMEM;
	}

	var_list = talloc_zero(mem_ctx, struct ctdb_var_list);
	if (var_list == NULL) {
		goto fail;
	}

	s = str;
	while ((tok = strtok_r(s, ":", &ptr)) != NULL) {
		s = NULL;
		list = talloc_realloc(var_list, var_list->var, const char *,
				      var_list->count+1);
		if (list == NULL) {
			goto fail;
		}

		var_list->var = list;
		var_list->var[var_list->count] = talloc_strdup(var_list, tok);
		if (var_list->var[var_list->count] == NULL) {
			goto fail;
		}
		var_list->count++;
	}

	talloc_free(str);
	*out = var_list;
	return 0;

fail:
	talloc_free(str);
	talloc_free(var_list);
	return ENOMEM;
}

size_t ctdb_tunable_list_len(struct ctdb_tunable_list *tun_list)
{
	return sizeof(struct ctdb_tunable_list);
}

void ctdb_tunable_list_push(struct ctdb_tunable_list *tun_list, uint8_t *buf)
{
	memcpy(buf, tun_list, sizeof(struct ctdb_tunable_list));
}

int ctdb_tunable_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			   struct ctdb_tunable_list **out)
{
	struct ctdb_tunable_list *tun_list;

	if (buflen < sizeof(struct ctdb_tunable_list)) {
		return EMSGSIZE;
	}

	tun_list = talloc_memdup(mem_ctx, buf, sizeof(struct ctdb_tunable_list));
	if (tun_list == NULL) {
		return ENOMEM;
	}

	*out = tun_list;
	return 0;
}

struct ctdb_tickle_list_wire {
	ctdb_sock_addr addr;
	uint32_t num;
	struct ctdb_connection conn[1];
};

size_t ctdb_tickle_list_len(struct ctdb_tickle_list *tickles)
{
	return offsetof(struct ctdb_tickle_list, conn) +
	       tickles->num * sizeof(struct ctdb_connection);
}

void ctdb_tickle_list_push(struct ctdb_tickle_list *tickles, uint8_t *buf)
{
	struct ctdb_tickle_list_wire *wire =
		(struct ctdb_tickle_list_wire *)buf;
	size_t offset;
	int i;

	memcpy(&wire->addr, &tickles->addr, sizeof(ctdb_sock_addr));
	wire->num = tickles->num;

	offset = offsetof(struct ctdb_tickle_list_wire, conn);
	for (i=0; i<tickles->num; i++) {
		ctdb_connection_push(&tickles->conn[i], &buf[offset]);
		offset += ctdb_connection_len(&tickles->conn[i]);
	}
}

int ctdb_tickle_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			   struct ctdb_tickle_list **out)
{
	struct ctdb_tickle_list *tickles;
	struct ctdb_tickle_list_wire *wire =
		(struct ctdb_tickle_list_wire *)buf;
	size_t offset;
	int i, ret;

	if (buflen < offsetof(struct ctdb_tickle_list_wire, conn)) {
		return EMSGSIZE;
	}
	if (buflen < offsetof(struct ctdb_tickle_list_wire, conn) +
		     wire->num * sizeof(struct ctdb_connection)) {
		return EMSGSIZE;
	}

	tickles = talloc(mem_ctx, struct ctdb_tickle_list);
	if (tickles == NULL) {
		return ENOMEM;
	}

	offset = offsetof(struct ctdb_tickle_list, conn);
	memcpy(tickles, wire, offset);

	tickles->conn = talloc_array(tickles, struct ctdb_connection,
				     wire->num);
	if (tickles->conn == NULL) {
		talloc_free(tickles);
		return ENOMEM;
	}

	for (i=0; i<wire->num; i++) {
		ret = ctdb_connection_pull_elems(&buf[offset], buflen-offset,
						 tickles->conn,
						 &tickles->conn[i]);
		if (ret != 0) {
			talloc_free(tickles);
			return ret;
		}
		offset += ctdb_connection_len(&tickles->conn[i]);
	}

	*out = tickles;
	return 0;
}

size_t ctdb_client_id_len(struct ctdb_client_id *cid)
{
	return sizeof(struct ctdb_client_id);
}

void ctdb_client_id_push(struct ctdb_client_id *cid, uint8_t *buf)
{
	memcpy(buf, cid, sizeof(struct ctdb_client_id));
}

static int ctdb_client_id_pull_elems(uint8_t *buf, size_t buflen,
				     TALLOC_CTX *mem_ctx,
				     struct ctdb_client_id *out)
{
	if (buflen < sizeof(struct ctdb_client_id)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(struct ctdb_client_id));

	return 0;
}

int ctdb_client_id_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			struct ctdb_client_id **out)
{
	struct ctdb_client_id *cid;
	int ret;

	cid = talloc(mem_ctx, struct ctdb_client_id);
	if (cid == NULL) {
		return ENOMEM;
	}

	ret = ctdb_client_id_pull_elems(buf, buflen, cid, cid);
	if (ret != 0) {
		TALLOC_FREE(cid);
	}

	*out = cid;
	return ret;
}

struct ctdb_client_id_list_wire {
	uint32_t num;
	struct ctdb_client_id cid[1];
};

size_t ctdb_client_id_list_len(struct ctdb_client_id_list *cid_list)
{
	return sizeof(uint32_t) +
	       cid_list->num * sizeof(struct ctdb_client_id);
}

void ctdb_client_id_list_push(struct ctdb_client_id_list *cid_list,
			      uint8_t *buf)
{
	struct ctdb_client_id_list_wire *wire =
		(struct ctdb_client_id_list_wire *)buf;
	size_t offset;
	int i;

	wire->num = cid_list->num;

	offset = offsetof(struct ctdb_client_id_list_wire, cid);
	for (i=0; i<cid_list->num; i++) {
		ctdb_client_id_push(&cid_list->cid[i], &buf[offset]);
		offset += ctdb_client_id_len(&cid_list->cid[i]);
	}
}

static int ctdb_client_id_list_pull_elems(uint8_t *buf, size_t buflen,
					  TALLOC_CTX *mem_ctx,
					  struct ctdb_client_id_list *out)
{
	struct ctdb_client_id_list_wire *wire =
		(struct ctdb_client_id_list_wire *)buf;
	size_t offset;
	int i;

	if (buflen < sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (buflen < sizeof(uint32_t) +
		     wire->num * sizeof(struct ctdb_client_id)) {
		return EMSGSIZE;
	}

	out->num = wire->num;
	out->cid = talloc_array(mem_ctx, struct ctdb_client_id,
				wire->num);
	if (out->cid == NULL) {
		return ENOMEM;
	}

	offset = offsetof(struct ctdb_client_id_list_wire, cid);
	for (i=0; i<wire->num; i++) {
		bool ret;
		ret = ctdb_client_id_pull_elems(&buf[offset], buflen-offset,
						out->cid, &out->cid[i]);
		if (ret != 0) {
			return ret;
		}
		offset += ctdb_client_id_len(&out->cid[i]);
	}

	return 0;
}

int ctdb_client_id_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			     struct ctdb_client_id_list **out)
{
	struct ctdb_client_id_list *cid_list;
	int ret;

	cid_list = talloc(mem_ctx, struct ctdb_client_id_list);
	if (cid_list == NULL) {
		return ENOMEM;
	}

	ret = ctdb_client_id_list_pull_elems(buf, buflen, cid_list, cid_list);
	if (ret != 0) {
		TALLOC_FREE(cid_list);
	}

	*out = cid_list;
	return ret;
}

struct ctdb_client_id_map_wire {
	int count;
	struct ctdb_client_id_list list[1];
};

size_t ctdb_client_id_map_len(struct ctdb_client_id_map *cid_map)
{
	int i;
	size_t len;

	len = sizeof(int);
	for (i=0; i<cid_map->count; i++) {
		len += ctdb_client_id_list_len(&cid_map->list[i]);
	}
	return len;
}

void ctdb_client_id_map_push(struct ctdb_client_id_map *cid_map, uint8_t *buf)
{
	struct ctdb_client_id_map_wire *wire =
		(struct ctdb_client_id_map_wire *)buf;
	size_t offset;
	int i;

	wire->count = cid_map->count;

	offset = sizeof(int);
	for (i=0; i<cid_map->count; i++) {
		ctdb_client_id_list_push(&cid_map->list[i], &buf[offset]);
		offset += ctdb_client_id_list_len(&cid_map->list[i]);
	}
}

int ctdb_client_id_map_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			    struct ctdb_client_id_map **out)
{
	struct ctdb_client_id_map *cid_map;
	struct ctdb_client_id_map_wire *wire =
		(struct ctdb_client_id_map_wire *)buf;
	size_t offset;
	int i;
	bool ret;

	if (buflen < sizeof(int)) {
		return EMSGSIZE;
	}
	if (buflen < sizeof(int) +
		     wire->count * sizeof(struct ctdb_client_id_list)) {
		return EMSGSIZE;
	}

	cid_map = talloc(mem_ctx, struct ctdb_client_id_map);
	if (cid_map == NULL) {
		return ENOMEM;
	}

	cid_map->count = wire->count;
	cid_map->list = talloc_array(cid_map, struct ctdb_client_id_list,
				     wire->count);
	if (cid_map->list == NULL) {
		return ENOMEM;
	}

	offset = sizeof(int);
	for (i=0; i<wire->count; i++) {
		ret = ctdb_client_id_list_pull_elems(&buf[offset],
						     buflen-offset,
						     cid_map->list,
						     &cid_map->list[i]);
		if (ret != 0) {
			talloc_free(cid_map);
			return ret;
		}
		offset += ctdb_client_id_list_len(&cid_map->list[i]);
	}

	*out = cid_map;
	return 0;
}

struct ctdb_addr_info_wire {
	ctdb_sock_addr addr;
	uint32_t mask;
	uint32_t len;
	char iface[1];
};

size_t ctdb_addr_info_len(struct ctdb_addr_info *arp)
{
	uint32_t len;

	len = offsetof(struct ctdb_addr_info_wire, iface);
	if (arp->iface != NULL) {
	       len += strlen(arp->iface)+1;
	}

	return len;
}

void ctdb_addr_info_push(struct ctdb_addr_info *addr_info, uint8_t *buf)
{
	struct ctdb_addr_info_wire *wire = (struct ctdb_addr_info_wire *)buf;

	wire->addr = addr_info->addr;
	wire->mask = addr_info->mask;
	if (addr_info->iface == NULL) {
		wire->len = 0;
	} else {
		wire->len = strlen(addr_info->iface)+1;
		memcpy(wire->iface, addr_info->iface, wire->len);
	}
}

int ctdb_addr_info_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			struct ctdb_addr_info **out)
{
	struct ctdb_addr_info *addr_info;
	struct ctdb_addr_info_wire *wire = (struct ctdb_addr_info_wire *)buf;

	if (buflen < offsetof(struct ctdb_addr_info_wire, iface)) {
		return EMSGSIZE;
	}
	if (buflen < offsetof(struct ctdb_addr_info_wire, iface) + wire->len) {
		return EMSGSIZE;
	}

	addr_info = talloc(mem_ctx, struct ctdb_addr_info);
	if (addr_info == NULL) {
		return ENOMEM;
	}

	addr_info->addr = wire->addr;
	addr_info->mask = wire->mask;

	if (wire->len == 0) {
		addr_info->iface = NULL;
	} else {
		addr_info->iface = talloc_strndup(addr_info, wire->iface,
						  wire->len);
		if (addr_info->iface == NULL) {
			talloc_free(addr_info);
			return ENOMEM;
		}
	}

	*out = addr_info;
	return 0;
}

size_t ctdb_transdb_len(struct ctdb_transdb *transdb)
{
	return sizeof(struct ctdb_transdb);
}

void ctdb_transdb_push(struct ctdb_transdb *transdb, uint8_t *buf)
{
	memcpy(buf, transdb, sizeof(struct ctdb_transdb));
}

int ctdb_transdb_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     struct ctdb_transdb **out)
{
	struct ctdb_transdb *transdb;

	if (buflen < sizeof(struct ctdb_transdb)) {
		return EMSGSIZE;
	}

	transdb = talloc_memdup(mem_ctx, buf, sizeof(struct ctdb_transdb));
	if (transdb == NULL) {
		return ENOMEM;
	}

	*out = transdb;
	return 0;
}

size_t ctdb_uptime_len(struct ctdb_uptime *uptime)
{
	return sizeof(struct ctdb_uptime);
}

void ctdb_uptime_push(struct ctdb_uptime *uptime, uint8_t *buf)
{
	memcpy(buf, uptime, sizeof(struct ctdb_uptime));
}

int ctdb_uptime_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     struct ctdb_uptime **out)
{
	struct ctdb_uptime *uptime;

	if (buflen < sizeof(struct ctdb_uptime)) {
		return EMSGSIZE;
	}

	uptime = talloc_memdup(mem_ctx, buf, sizeof(struct ctdb_uptime));
	if (uptime == NULL) {
		return ENOMEM;
	}

	*out = uptime;
	return 0;
}

size_t ctdb_public_ip_len(struct ctdb_public_ip *pubip)
{
	return sizeof(struct ctdb_public_ip);
}

void ctdb_public_ip_push(struct ctdb_public_ip *pubip, uint8_t *buf)
{
	memcpy(buf, pubip, sizeof(struct ctdb_public_ip));
}

static int ctdb_public_ip_pull_elems(uint8_t *buf, size_t buflen,
				     TALLOC_CTX *mem_ctx,
				     struct ctdb_public_ip *out)
{
	if (buflen < sizeof(struct ctdb_public_ip)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(struct ctdb_public_ip));

	return 0;
}

int ctdb_public_ip_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			struct ctdb_public_ip **out)
{
	struct ctdb_public_ip *pubip;
	int ret;

	pubip = talloc(mem_ctx, struct ctdb_public_ip);
	if (pubip == NULL) {
		return ENOMEM;
	}

	ret = ctdb_public_ip_pull_elems(buf, buflen, pubip, pubip);
	if (ret != 0) {
		TALLOC_FREE(pubip);
	}

	*out = pubip;
	return ret;
}

struct ctdb_public_ip_list_wire {
	uint32_t num;
	struct ctdb_public_ip ip[1];
};

size_t ctdb_public_ip_list_len(struct ctdb_public_ip_list *pubip_list)
{
	int i;
	size_t len;

	len = sizeof(uint32_t);
	for (i=0; i<pubip_list->num; i++) {
		len += ctdb_public_ip_len(&pubip_list->ip[i]);
	}
	return len;
}

void ctdb_public_ip_list_push(struct ctdb_public_ip_list *pubip_list,
			      uint8_t *buf)
{
	struct ctdb_public_ip_list_wire *wire =
		(struct ctdb_public_ip_list_wire *)buf;
	size_t offset;
	int i;

	wire->num = pubip_list->num;

	offset = offsetof(struct ctdb_public_ip_list_wire, ip);
	for (i=0; i<pubip_list->num; i++) {
		ctdb_public_ip_push(&pubip_list->ip[i], &buf[offset]);
		offset += ctdb_public_ip_len(&pubip_list->ip[i]);
	}
}

int ctdb_public_ip_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			     struct ctdb_public_ip_list **out)
{
	struct ctdb_public_ip_list *pubip_list;
	struct ctdb_public_ip_list_wire *wire =
		(struct ctdb_public_ip_list_wire *)buf;
	size_t offset;
	int i;
	bool ret;

	if (buflen < sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (buflen < sizeof(uint32_t) +
		     wire->num * sizeof(struct ctdb_public_ip)) {
		return EMSGSIZE;
	}

	pubip_list = talloc(mem_ctx, struct ctdb_public_ip_list);
	if (pubip_list == NULL) {
		return ENOMEM;
	}

	pubip_list->num = wire->num;
	if (wire->num == 0) {
		pubip_list->ip = NULL;
		*out = pubip_list;
		return 0;
	}
	pubip_list->ip = talloc_array(pubip_list, struct ctdb_public_ip,
				      wire->num);
	if (pubip_list->ip == NULL) {
		talloc_free(pubip_list);
		return ENOMEM;
	}

	offset = offsetof(struct ctdb_public_ip_list_wire, ip);
	for (i=0; i<wire->num; i++) {
		ret = ctdb_public_ip_pull_elems(&buf[offset], buflen-offset,
						pubip_list->ip,
						&pubip_list->ip[i]);
		if (ret != 0) {
			talloc_free(pubip_list);
			return ret;
		}
		offset += ctdb_public_ip_len(&pubip_list->ip[i]);
	}

	*out = pubip_list;
	return 0;
}

size_t ctdb_node_and_flags_len(struct ctdb_node_and_flags *node)
{
	return sizeof(struct ctdb_node_and_flags);
}

void ctdb_node_and_flags_push(struct ctdb_node_and_flags *node, uint8_t *buf)
{
	memcpy(buf, node, sizeof(struct ctdb_node_and_flags));
}

static int ctdb_node_and_flags_pull_elems(TALLOC_CTX *mem_ctx,
					  uint8_t *buf, size_t buflen,
					  struct ctdb_node_and_flags *out)
{
	if (buflen < sizeof(struct ctdb_node_and_flags)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(struct ctdb_node_and_flags));

	return 0;
}

int ctdb_node_and_flags_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			      struct ctdb_node_and_flags **out)
{
	struct ctdb_node_and_flags *node;
	int ret;

	node = talloc(mem_ctx, struct ctdb_node_and_flags);
	if (node == NULL) {
		return ENOMEM;
	}

	ret = ctdb_node_and_flags_pull_elems(node, buf, buflen, node);
	if (ret != 0) {
		TALLOC_FREE(node);
	}

	*out = node;
	return ret;
}

struct ctdb_node_map_wire {
	uint32_t num;
	struct ctdb_node_and_flags node[1];
};

size_t ctdb_node_map_len(struct ctdb_node_map *nodemap)
{
	return sizeof(uint32_t) +
	       nodemap->num * sizeof(struct ctdb_node_and_flags);
}

void ctdb_node_map_push(struct ctdb_node_map *nodemap, uint8_t *buf)
{
	struct ctdb_node_map_wire *wire = (struct ctdb_node_map_wire *)buf;
	size_t offset;
	int i;

	wire->num = nodemap->num;

	offset = offsetof(struct ctdb_node_map_wire, node);
	for (i=0; i<nodemap->num; i++) {
		ctdb_node_and_flags_push(&nodemap->node[i], &buf[offset]);
		offset += ctdb_node_and_flags_len(&nodemap->node[i]);
	}
}

int ctdb_node_map_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       struct ctdb_node_map **out)
{
	struct ctdb_node_map *nodemap;
	struct ctdb_node_map_wire *wire = (struct ctdb_node_map_wire *)buf;
	size_t offset;
	int i;
	bool ret;

	nodemap = talloc(mem_ctx, struct ctdb_node_map);
	if (nodemap == NULL) {
		return ENOMEM;
	}

	nodemap->num = wire->num;
	nodemap->node = talloc_array(nodemap, struct ctdb_node_and_flags,
				     wire->num);
	if (nodemap->node == NULL) {
		talloc_free(nodemap);
		return ENOMEM;
	}

	offset = offsetof(struct ctdb_node_map_wire, node);
	for (i=0; i<wire->num; i++) {
		ret = ctdb_node_and_flags_pull_elems(nodemap->node,
						     &buf[offset],
						     buflen-offset,
						     &nodemap->node[i]);
		if (ret != 0) {
			talloc_free(nodemap);
			return ret;
		}
		offset += ctdb_node_and_flags_len(&nodemap->node[i]);
	}

	*out = nodemap;
	return 0;
}

size_t ctdb_script_len(struct ctdb_script *script)
{
	return sizeof(struct ctdb_script);
}

void ctdb_script_push(struct ctdb_script *script, uint8_t *buf)
{
	memcpy(buf, script, sizeof(struct ctdb_script));
}

static int ctdb_script_pull_elems(uint8_t *buf, size_t buflen,
				  TALLOC_CTX *mem_ctx,
				  struct ctdb_script *out)
{
	if (buflen < sizeof(struct ctdb_script)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(struct ctdb_script));

	return 0;
}

int ctdb_script_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     struct ctdb_script **out)
{
	struct ctdb_script *script;
	int ret;

	script = talloc(mem_ctx, struct ctdb_script);
	if (script == NULL) {
		return ENOMEM;
	}

	ret = ctdb_script_pull_elems(buf, buflen, script, script);
	if (ret != 0) {
		TALLOC_FREE(script);
	}

	*out = script;
	return ret;
}

struct ctdb_script_list_wire {
	uint32_t num_scripts;
	struct ctdb_script script[1];
};

size_t ctdb_script_list_len(struct ctdb_script_list *script_list)
{
	int i;
	size_t len;

	if (script_list == NULL) {
		return 0;
	}

	len = offsetof(struct ctdb_script_list_wire, script);
	for (i=0; i<script_list->num_scripts; i++) {
		len += ctdb_script_len(&script_list->script[i]);
	}
	return len;
}

void ctdb_script_list_push(struct ctdb_script_list *script_list, uint8_t *buf)
{
	struct ctdb_script_list_wire *wire =
		(struct ctdb_script_list_wire *)buf;
	size_t offset;
	int i;

	if (script_list == NULL) {
		return;
	}

	wire->num_scripts = script_list->num_scripts;

	offset = offsetof(struct ctdb_script_list_wire, script);
	for (i=0; i<script_list->num_scripts; i++) {
		ctdb_script_push(&script_list->script[i], &buf[offset]);
		offset += ctdb_script_len(&script_list->script[i]);
	}
}

int ctdb_script_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			  struct ctdb_script_list **out)
{
	struct ctdb_script_list *script_list;
	struct ctdb_script_list_wire *wire =
		(struct ctdb_script_list_wire *)buf;
	size_t offset;
	int i;
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
	if (buflen < offset + wire->num_scripts * sizeof(struct ctdb_script)) {
		return EMSGSIZE;
	}

	script_list = talloc(mem_ctx, struct ctdb_script_list);
	if (script_list == NULL) {
		return ENOMEM;

	}

	script_list->num_scripts = wire->num_scripts;
	script_list->script = talloc_array(script_list, struct ctdb_script,
					   wire->num_scripts);
	if (script_list->script == NULL) {
		talloc_free(script_list);
		return ENOMEM;
	}

	for (i=0; i<wire->num_scripts; i++) {
		ret = ctdb_script_pull_elems(&buf[offset], buflen-offset,
					     script_list->script,
					     &script_list->script[i]);
		if (ret != 0) {
			talloc_free(script_list);
			return ret;
		}
		offset += ctdb_script_len(&script_list->script[i]);
	}

	*out = script_list;
	return 0;
}

size_t ctdb_ban_state_len(struct ctdb_ban_state *ban_state)
{
	return sizeof(struct ctdb_ban_state);
}

void ctdb_ban_state_push(struct ctdb_ban_state *ban_state, uint8_t *buf)
{
	memcpy(buf, ban_state, sizeof(struct ctdb_ban_state));
}

int ctdb_ban_state_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			struct ctdb_ban_state **out)
{
	struct ctdb_ban_state *ban_state;

	if (buflen < sizeof(struct ctdb_ban_state)) {
		return EMSGSIZE;
	}

	ban_state = talloc_memdup(mem_ctx, buf, sizeof(struct ctdb_ban_state));
	if (ban_state == NULL) {
		return ENOMEM;
	}

	*out = ban_state;
	return 0;
}

size_t ctdb_db_priority_len(struct ctdb_db_priority *db_prio)
{
	return sizeof(struct ctdb_db_priority);
}

void ctdb_db_priority_push(struct ctdb_db_priority *db_prio, uint8_t *buf)
{
	memcpy(buf, db_prio, sizeof(struct ctdb_db_priority));
}

int ctdb_db_priority_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			  struct ctdb_db_priority **out)
{
	struct ctdb_db_priority *db_prio;

	if (buflen < sizeof(struct ctdb_db_priority)) {
		return EMSGSIZE;
	}

	db_prio = talloc_memdup(mem_ctx, buf, sizeof(struct ctdb_db_priority));
	if (db_prio == NULL) {
		return ENOMEM;
	}

	*out = db_prio;
	return 0;
}

struct ctdb_notify_data_wire {
	uint64_t srvid;
	uint32_t len;
	uint8_t data[1];
};

size_t ctdb_notify_data_len(struct ctdb_notify_data *notify)
{
	return offsetof(struct ctdb_notify_data_wire, data) +
	       notify->data.dsize;
}

void ctdb_notify_data_push(struct ctdb_notify_data *notify, uint8_t *buf)
{
	struct ctdb_notify_data_wire *wire =
		(struct ctdb_notify_data_wire *)buf;

	wire->srvid = notify->srvid;
	wire->len = notify->data.dsize;
	memcpy(wire->data, notify->data.dptr, notify->data.dsize);
}

int ctdb_notify_data_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			  struct ctdb_notify_data **out)
{
	struct ctdb_notify_data *notify;
	struct ctdb_notify_data_wire *wire =
		(struct ctdb_notify_data_wire *)buf;

	if (buflen < offsetof(struct ctdb_notify_data_wire, data)) {
		return EMSGSIZE;
	}
	if (buflen < offsetof(struct ctdb_notify_data_wire, data) + wire->len) {
		return EMSGSIZE;
	}

	notify = talloc(mem_ctx, struct ctdb_notify_data);
	if (notify == NULL) {
		return ENOMEM;
	}

	notify->srvid = wire->srvid;
	notify->data.dsize = wire->len;
	notify->data.dptr = talloc_memdup(notify, wire->data, wire->len);
	if (notify->data.dptr == NULL) {
		talloc_free(notify);
		return ENOMEM;
	}

	*out = notify;
	return 0;
}

size_t ctdb_iface_len(struct ctdb_iface *iface)
{
	return sizeof(struct ctdb_iface);
}

void ctdb_iface_push(struct ctdb_iface *iface, uint8_t *buf)
{
	memcpy(buf, iface, sizeof(struct ctdb_iface));
}

static int ctdb_iface_pull_elems(uint8_t *buf, size_t buflen,
				 TALLOC_CTX *mem_ctx,
				 struct ctdb_iface *out)
{
	if (buflen < sizeof(struct ctdb_iface)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(struct ctdb_iface));

	return 0;
}

int ctdb_iface_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		    struct ctdb_iface **out)
{
	struct ctdb_iface *iface;
	int ret;

	iface = talloc(mem_ctx, struct ctdb_iface);
	if (iface == NULL) {
		return ENOMEM;
	}

	ret = ctdb_iface_pull_elems(buf, buflen, iface, iface);
	if (ret != 0) {
		TALLOC_FREE(iface);
	}

	*out = iface;
	return ret;
}

struct ctdb_iface_list_wire {
	uint32_t num;
	struct ctdb_iface iface[1];
};

size_t ctdb_iface_list_len(struct ctdb_iface_list *iface_list)
{
	return sizeof(uint32_t) +
	       iface_list->num * sizeof(struct ctdb_iface);
}

void ctdb_iface_list_push(struct ctdb_iface_list *iface_list, uint8_t *buf)
{
	struct ctdb_iface_list_wire *wire =
		(struct ctdb_iface_list_wire *)buf;

	wire->num = iface_list->num;
	memcpy(wire->iface, iface_list->iface,
	       iface_list->num * sizeof(struct ctdb_iface));
}

int ctdb_iface_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			 struct ctdb_iface_list **out)
{
	struct ctdb_iface_list *iface_list;
	struct ctdb_iface_list_wire *wire =
		(struct ctdb_iface_list_wire *)buf;

	if (buflen < sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (buflen < sizeof(uint32_t) + wire->num * sizeof(struct ctdb_iface)) {
		return EMSGSIZE;
	}

	iface_list = talloc(mem_ctx, struct ctdb_iface_list);
	if (iface_list == NULL) {
		return ENOMEM;
	}

	iface_list->num = wire->num;
	iface_list->iface = talloc_array(iface_list, struct ctdb_iface,
					 wire->num);
	if (iface_list->iface == NULL) {
		talloc_free(iface_list);
		return ENOMEM;
	}

	memcpy(iface_list->iface, wire->iface,
	       wire->num * sizeof(struct ctdb_iface));

	*out = iface_list;
	return 0;
}

struct ctdb_public_ip_info_wire {
	struct ctdb_public_ip ip;
	uint32_t active_idx;
	uint32_t num;
	struct ctdb_iface ifaces[1];
};

size_t ctdb_public_ip_info_len(struct ctdb_public_ip_info *ipinfo)
{
	return offsetof(struct ctdb_public_ip_info_wire, num) +
	       ctdb_iface_list_len(ipinfo->ifaces);
}

void ctdb_public_ip_info_push(struct ctdb_public_ip_info *ipinfo, uint8_t *buf)
{
	struct ctdb_public_ip_info_wire *wire =
		(struct ctdb_public_ip_info_wire *)buf;
	size_t offset;

	offset = offsetof(struct ctdb_public_ip_info_wire, num);
	memcpy(wire, ipinfo, offset);
	wire->num = ipinfo->ifaces->num;
	memcpy(wire->ifaces, ipinfo->ifaces->iface,
	       ipinfo->ifaces->num * sizeof(struct ctdb_iface));
}

int ctdb_public_ip_info_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			     struct ctdb_public_ip_info **out)
{
	struct ctdb_public_ip_info *ipinfo;
	struct ctdb_public_ip_info_wire *wire =
		(struct ctdb_public_ip_info_wire *)buf;

	if (buflen < offsetof(struct ctdb_public_ip_info_wire, ifaces)) {
		return EMSGSIZE;
	}

	ipinfo = talloc(mem_ctx, struct ctdb_public_ip_info);
	if (ipinfo == NULL) {
		return ENOMEM;
	}

	memcpy(ipinfo, wire, offsetof(struct ctdb_public_ip_info_wire, num));

	ipinfo->ifaces = talloc(ipinfo, struct ctdb_iface_list);
	if (ipinfo->ifaces == NULL) {
		talloc_free(ipinfo);
		return ENOMEM;
	}

	ipinfo->ifaces->num = wire->num;
	ipinfo->ifaces->iface = talloc_array(ipinfo->ifaces, struct ctdb_iface,
					     wire->num);
	if (ipinfo->ifaces->iface == NULL) {
		talloc_free(ipinfo);
		return ENOMEM;
	}

	memcpy(ipinfo->ifaces->iface, wire->ifaces,
	       wire->num * sizeof(struct ctdb_iface));

	*out = ipinfo;
	return 0;
}

struct ctdb_key_data_wire {
	uint32_t db_id;
	struct ctdb_ltdb_header header;
	uint32_t keylen;
	uint8_t key[1];
};

size_t ctdb_key_data_len(struct ctdb_key_data *key)
{
	return offsetof(struct ctdb_key_data_wire, key) + key->key.dsize;
}

void ctdb_key_data_push(struct ctdb_key_data *key, uint8_t *buf)
{
	struct ctdb_key_data_wire *wire = (struct ctdb_key_data_wire *)buf;

	memcpy(wire, key, offsetof(struct ctdb_key_data, key));
	wire->keylen = key->key.dsize;
	memcpy(wire->key, key->key.dptr, key->key.dsize);
}

int ctdb_key_data_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       struct ctdb_key_data **out)
{
	struct ctdb_key_data *key_data;
	struct ctdb_key_data_wire *wire = (struct ctdb_key_data_wire *)buf;

	if (buflen < offsetof(struct ctdb_key_data_wire, key)) {
		return EMSGSIZE;
	}
	if (buflen < offsetof(struct ctdb_key_data_wire, key) + wire->keylen) {
		return EMSGSIZE;
	}

	key_data = talloc(mem_ctx, struct ctdb_key_data);
	if (key_data == NULL) {
		return ENOMEM;
	}

	memcpy(key_data, wire, offsetof(struct ctdb_key_data, key));

	key_data->key.dsize = wire->keylen;
	key_data->key.dptr = talloc_memdup(key_data, wire->key, wire->keylen);
	if (key_data->key.dptr == NULL) {
		talloc_free(key_data);
		return ENOMEM;
	}

	*out = key_data;
	return 0;
}

struct ctdb_db_statistics_wire {
	struct ctdb_db_statistics dbstats;
	char hot_keys_wire[1];
};

size_t ctdb_db_statistics_len(struct ctdb_db_statistics *dbstats)
{
	size_t len;
	int i;

	len = sizeof(struct ctdb_db_statistics);
	for (i=0; i<MAX_HOT_KEYS; i++) {
		len += dbstats->hot_keys[i].key.dsize;
	}
	return len;
}

void ctdb_db_statistics_push(struct ctdb_db_statistics *dbstats, void *buf)
{
	struct ctdb_db_statistics_wire *wire =
		(struct ctdb_db_statistics_wire *)buf;
	size_t offset;
	int i;

	dbstats->num_hot_keys = MAX_HOT_KEYS;
	memcpy(wire, dbstats, sizeof(struct ctdb_db_statistics));

	offset = 0;
	for (i=0; i<MAX_HOT_KEYS; i++) {
		memcpy(&wire->hot_keys_wire[offset],
		       dbstats->hot_keys[i].key.dptr,
		       dbstats->hot_keys[i].key.dsize);
		offset += dbstats->hot_keys[i].key.dsize;
	}
}

int ctdb_db_statistics_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			    struct ctdb_db_statistics **out)
{
	struct ctdb_db_statistics *dbstats;
	struct ctdb_db_statistics_wire *wire =
		(struct ctdb_db_statistics_wire *)buf;
	size_t offset;
	int i;

	if (buflen < sizeof(struct ctdb_db_statistics)) {
		return EMSGSIZE;
	}
	offset = 0;
	for (i=0; i<wire->dbstats.num_hot_keys; i++) {
		offset += wire->dbstats.hot_keys[i].key.dsize;
	}
	if (buflen < sizeof(struct ctdb_db_statistics) + offset) {
		return EMSGSIZE;
	}

	dbstats = talloc(mem_ctx, struct ctdb_db_statistics);
	if (dbstats == NULL) {
		return ENOMEM;
	}

	memcpy(dbstats, wire, sizeof(struct ctdb_db_statistics));

	offset = 0;
	for (i=0; i<wire->dbstats.num_hot_keys; i++) {
		uint8_t *ptr;
		size_t key_size;

		key_size = dbstats->hot_keys[i].key.dsize;
		ptr = talloc_memdup(mem_ctx, &wire->hot_keys_wire[offset],
				    key_size);
		if (ptr == NULL) {
			talloc_free(dbstats);
			return ENOMEM;
		}
		dbstats->hot_keys[i].key.dptr = ptr;
		offset += key_size;
	}

	*out = dbstats;
	return 0;
}

size_t ctdb_election_message_len(struct ctdb_election_message *election)
{
	return sizeof(struct ctdb_election_message);
}

void ctdb_election_message_push(struct ctdb_election_message *election,
				uint8_t *buf)
{
	memcpy(buf, election, sizeof(struct ctdb_election_message));
}

int ctdb_election_message_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			       struct ctdb_election_message **out)
{
	struct ctdb_election_message *election;

	if (buflen < sizeof(struct ctdb_election_message)) {
		return EMSGSIZE;
	}

	election = talloc_memdup(mem_ctx, buf,
				 sizeof(struct ctdb_election_message));
	if (election == NULL) {
		return ENOMEM;
	}

	*out = election;
	return 0;
}

size_t ctdb_srvid_message_len(struct ctdb_srvid_message *msg)
{
	return sizeof(struct ctdb_srvid_message);
}

void ctdb_srvid_message_push(struct ctdb_srvid_message *msg, uint8_t *buf)
{
	memcpy(buf, msg, sizeof(struct ctdb_srvid_message));
}

int ctdb_srvid_message_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			    struct ctdb_srvid_message **out)
{
	struct ctdb_srvid_message *msg;

	if (buflen < sizeof(struct ctdb_srvid_message)) {
		return EMSGSIZE;
	}

	msg = talloc_memdup(mem_ctx, buf, sizeof(struct ctdb_srvid_message));
	if (msg == NULL) {
		return ENOMEM;
	}

	*out = msg;
	return 0;
}

size_t ctdb_disable_message_len(struct ctdb_disable_message *disable)
{
	return sizeof(struct ctdb_disable_message);
}

void ctdb_disable_message_push(struct ctdb_disable_message *disable,
			       uint8_t *buf)
{
	memcpy(buf, disable, sizeof(struct ctdb_disable_message));
}

int ctdb_disable_message_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			      struct ctdb_disable_message **out)
{
	struct ctdb_disable_message *disable;

	if (buflen < sizeof(struct ctdb_disable_message)) {
		return EMSGSIZE;
	}

	disable = talloc_memdup(mem_ctx, buf,
				sizeof(struct ctdb_disable_message));
	if (disable == NULL) {
		return ENOMEM;
	}

	*out = disable;
	return 0;
}

size_t ctdb_tdb_data_len(TDB_DATA data)
{
	return data.dsize;
}

void ctdb_tdb_data_push(TDB_DATA data, uint8_t *buf)
{
	memcpy(buf, data.dptr, data.dsize);
}

int ctdb_tdb_data_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		       TDB_DATA *out)
{
	TDB_DATA data;

	data.dsize = buflen;
	if (data.dsize > 0) {
		data.dptr = talloc_memdup(mem_ctx, buf, buflen);
		if (data.dptr == NULL) {
			return ENOMEM;
		}
	} else {
		data.dptr = NULL;
	}

	*out = data;
	return 0;
}

size_t ctdb_server_id_len(struct ctdb_server_id *sid)
{
	return sizeof(struct ctdb_server_id);
}

void ctdb_server_id_push(struct ctdb_server_id *sid, uint8_t *buf)
{
	memcpy(buf, sid, sizeof(struct ctdb_server_id));
}

int ctdb_server_id_pull(uint8_t *buf, size_t buflen,
			struct ctdb_server_id *sid)
{
	if (buflen < sizeof(struct ctdb_server_id)) {
		return EMSGSIZE;
	}

	memcpy(sid, buf, sizeof(struct ctdb_server_id));
	return 0;
}

size_t ctdb_g_lock_len(struct ctdb_g_lock *lock)
{
	return sizeof(struct ctdb_g_lock);
}

void ctdb_g_lock_push(struct ctdb_g_lock *lock, uint8_t *buf)
{
	memcpy(buf, lock, sizeof(struct ctdb_g_lock));
}

int ctdb_g_lock_pull(uint8_t *buf, size_t buflen, struct ctdb_g_lock *lock)
{
	if (buflen < sizeof(struct ctdb_g_lock)) {
		return EMSGSIZE;
	}

	memcpy(lock, buf, sizeof(struct ctdb_g_lock));
	return 0;
}

size_t ctdb_g_lock_list_len(struct ctdb_g_lock_list *lock_list)
{
	return lock_list->num * sizeof(struct ctdb_g_lock);
}

void ctdb_g_lock_list_push(struct ctdb_g_lock_list *lock_list, uint8_t *buf)
{
	size_t offset = 0;
	int i;

	for (i=0; i<lock_list->num; i++) {
		ctdb_g_lock_push(&lock_list->lock[i], &buf[offset]);
		offset += sizeof(struct ctdb_g_lock);
	}
}

int ctdb_g_lock_list_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
			  struct ctdb_g_lock_list **out)
{
	struct ctdb_g_lock_list *lock_list;
	unsigned count;
	size_t offset;
	int ret, i;

	lock_list = talloc_zero(mem_ctx, struct ctdb_g_lock_list);
	if (lock_list == NULL) {
		return ENOMEM;
	}

	count = buflen / sizeof(struct ctdb_g_lock);
	lock_list->lock = talloc_array(lock_list, struct ctdb_g_lock, count);
	if (lock_list->lock == NULL) {
		talloc_free(lock_list);
		return ENOMEM;
	}

	offset = 0;
	for (i=0; i<count; i++) {
		ret = ctdb_g_lock_pull(&buf[offset], buflen-offset,
				       &lock_list->lock[i]);
		if (ret != 0) {
			talloc_free(lock_list);
			return ret;
		}
		offset += sizeof(struct ctdb_g_lock);
	}

	lock_list->num = count;

	*out = lock_list;
	return 0;
}
