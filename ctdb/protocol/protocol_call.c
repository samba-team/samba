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
#include "protocol_api.h"
#include "protocol_private.h"

struct ctdb_req_dmaster_wire {
	struct ctdb_req_header hdr;
	uint32_t db_id;
	uint64_t rsn;
	uint32_t dmaster;
	uint32_t keylen;
	uint32_t datalen;
	uint8_t  data[1];
};

struct ctdb_reply_dmaster_wire {
	struct ctdb_req_header hdr;
	uint32_t db_id;
	uint64_t rsn;
	uint32_t keylen;
	uint32_t datalen;
	uint8_t  data[1];
};

size_t ctdb_req_call_len(struct ctdb_req_header *h, struct ctdb_req_call *c)
{
	return ctdb_req_header_len(h) +
		ctdb_uint32_len(&c->flags) +
		ctdb_uint32_len(&c->db_id) +
		ctdb_uint32_len(&c->callid) +
		ctdb_uint32_len(&c->hopcount) +
		ctdb_tdb_datan_len(&c->key) +
		ctdb_tdb_datan_len(&c->calldata);
}

int ctdb_req_call_push(struct ctdb_req_header *h, struct ctdb_req_call *c,
		       uint8_t *buf, size_t *buflen)
{
	size_t offset = 0;
	size_t length, np;
	uint32_t u32;

	if (c->key.dsize == 0) {
		return EINVAL;
	}

	length = ctdb_req_call_len(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push(h, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&c->flags, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&c->db_id, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&c->callid, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&c->hopcount, buf+offset, &np);
	offset += np;

	u32 = ctdb_tdb_data_len(&c->key);
	ctdb_uint32_push(&u32, buf+offset, &np);
	offset += np;

	u32 = ctdb_tdb_data_len(&c->calldata);
	ctdb_uint32_push(&u32, buf+offset, &np);
	offset += np;

	ctdb_tdb_data_push(&c->key, buf+offset, &np);
	offset += np;

	ctdb_tdb_data_push(&c->calldata, buf+offset, &np);
	offset += np;

	return 0;
}

int ctdb_req_call_pull(uint8_t *buf, size_t buflen,
		       struct ctdb_req_header *h,
		       TALLOC_CTX *mem_ctx,
		       struct ctdb_req_call *c)
{
	struct ctdb_req_header header;
	size_t offset = 0, np;
	uint32_t u32;
	int ret;

	ret = ctdb_req_header_pull(buf+offset, buflen-offset, &header, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	if (h != NULL) {
		*h = header;
	}

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &c->flags, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &c->db_id, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &c->callid, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &c->hopcount, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &u32, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;
	c->key.dsize = u32;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &u32, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;
	c->calldata.dsize = u32;

	if (buflen-offset < c->key.dsize) {
		return EMSGSIZE;
	}

	ret = ctdb_tdb_data_pull(buf+offset, c->key.dsize, mem_ctx, &c->key,
				 &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	if (buflen-offset < c->calldata.dsize) {
		return EMSGSIZE;
	}

	ret = ctdb_tdb_data_pull(buf+offset, c->calldata.dsize,
				 mem_ctx, &c->calldata, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	return 0;
}

size_t ctdb_reply_call_len(struct ctdb_req_header *h,
			   struct ctdb_reply_call *c)
{
	return ctdb_req_header_len(h) +
		ctdb_int32_len(&c->status) +
		ctdb_tdb_datan_len(&c->data);
}

int ctdb_reply_call_push(struct ctdb_req_header *h, struct ctdb_reply_call *c,
			 uint8_t *buf, size_t *buflen)
{
	size_t offset = 0, np;
	size_t length;

	length = ctdb_reply_call_len(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push(h, buf+offset, &np);
	offset += np;

	ctdb_int32_push(&c->status, buf+offset, &np);
	offset += np;

	ctdb_tdb_datan_push(&c->data, buf+offset, &np);
	offset += np;

	return 0;
}

int ctdb_reply_call_pull(uint8_t *buf, size_t buflen,
			 struct ctdb_req_header *h,
			 TALLOC_CTX *mem_ctx,
			 struct ctdb_reply_call *c)
{
	struct ctdb_req_header header;
	size_t offset = 0, np;
	int ret;

	ret = ctdb_req_header_pull(buf+offset, buflen-offset, &header, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	if (h != NULL) {
		*h = header;
	}

	ret = ctdb_int32_pull(buf+offset, buflen-offset, &c->status, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_tdb_datan_pull(buf+offset, buflen-offset,
				  mem_ctx, &c->data, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	return 0;
}

size_t ctdb_reply_error_len(struct ctdb_req_header *h,
			    struct ctdb_reply_error *c)
{
	return ctdb_req_header_len(h) +
		ctdb_int32_len(&c->status) +
		ctdb_tdb_datan_len(&c->msg);
}

int ctdb_reply_error_push(struct ctdb_req_header *h, struct ctdb_reply_error *c,
			  uint8_t *buf, size_t *buflen)
{
	size_t offset = 0, np;
	size_t length;

	length = ctdb_reply_error_len(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push(h, buf+offset, &np);
	offset += np;

	ctdb_int32_push(&c->status, buf+offset, &np);
	offset += np;

	ctdb_tdb_datan_push(&c->msg, buf+offset, &np);
	offset += np;

	return 0;
}

int ctdb_reply_error_pull(uint8_t *buf, size_t buflen,
			  struct ctdb_req_header *h,
			  TALLOC_CTX *mem_ctx,
			  struct ctdb_reply_error *c)
{
	struct ctdb_req_header header;
	size_t offset = 0, np;
	int ret;

	ret = ctdb_req_header_pull(buf+offset, buflen-offset, &header, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	if (h != NULL) {
		*h = header;
	}

	ret = ctdb_int32_pull(buf+offset, buflen-offset, &c->status, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_tdb_datan_pull(buf+offset, buflen-offset, mem_ctx, &c->msg,
				  &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	return 0;
}

size_t ctdb_req_dmaster_len(struct ctdb_req_header *h,
			    struct ctdb_req_dmaster *c)
{
	return offsetof(struct ctdb_req_dmaster_wire, data) +
		ctdb_tdb_data_len(&c->key) +
		ctdb_tdb_data_len(&c->data);
}

int ctdb_req_dmaster_push(struct ctdb_req_header *h, struct ctdb_req_dmaster *c,
			  uint8_t *buf, size_t *buflen)
{
	struct ctdb_req_dmaster_wire *wire =
		(struct ctdb_req_dmaster_wire *)buf;
	size_t length, np;

	length = ctdb_req_dmaster_len(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push(h, (uint8_t *)&wire->hdr, &np);

	wire->db_id = c->db_id;
	wire->rsn = c->rsn;
	wire->dmaster = c->dmaster;
	wire->keylen = ctdb_tdb_data_len(&c->key);
	wire->datalen = ctdb_tdb_data_len(&c->data);
	ctdb_tdb_data_push(&c->key, wire->data, &np);
	ctdb_tdb_data_push(&c->data, wire->data + wire->keylen, &np);

	return 0;
}

int ctdb_req_dmaster_pull(uint8_t *buf, size_t buflen,
			  struct ctdb_req_header *h,
			  TALLOC_CTX *mem_ctx,
			  struct ctdb_req_dmaster *c)
{
	struct ctdb_req_dmaster_wire *wire =
		(struct ctdb_req_dmaster_wire *)buf;
	size_t length, np;
	int ret;

	length = offsetof(struct ctdb_req_dmaster_wire, data);
	if (buflen < length) {
		return EMSGSIZE;
	}
	if (wire->keylen > buflen || wire->datalen > buflen) {
		return EMSGSIZE;
	}
	if (length + wire->keylen < length) {
		return EMSGSIZE;
	}
	if (length + wire->keylen + wire->datalen < length) {
		return EMSGSIZE;
	}
	if (buflen < length + wire->keylen + wire->datalen) {
		return EMSGSIZE;
	}

	if (h != NULL) {
		ret = ctdb_req_header_pull((uint8_t *)&wire->hdr, buflen, h,
					   &np);
		if (ret != 0) {
			return ret;
		}
	}

	c->db_id = wire->db_id;
	c->rsn = wire->rsn;
	c->dmaster = wire->dmaster;

	ret = ctdb_tdb_data_pull(wire->data, wire->keylen, mem_ctx, &c->key,
				 &np);
	if (ret != 0) {
		return ret;
	}

	ret = ctdb_tdb_data_pull(wire->data + wire->keylen, wire->datalen,
				 mem_ctx, &c->data, &np);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

size_t ctdb_reply_dmaster_len(struct ctdb_req_header *h,
			      struct ctdb_reply_dmaster *c)
{
	return offsetof(struct ctdb_reply_dmaster_wire, data) +
		ctdb_tdb_data_len(&c->key) +
		ctdb_tdb_data_len(&c->data);
}

int ctdb_reply_dmaster_push(struct ctdb_req_header *h,
			    struct ctdb_reply_dmaster *c,
			    uint8_t *buf, size_t *buflen)
{
	struct ctdb_reply_dmaster_wire *wire =
		(struct ctdb_reply_dmaster_wire *)buf;
	size_t length, np;

	length = ctdb_reply_dmaster_len(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push(h, (uint8_t *)&wire->hdr, &np);

	wire->db_id = c->db_id;
	wire->rsn = c->rsn;
	wire->keylen = ctdb_tdb_data_len(&c->key);
	wire->datalen = ctdb_tdb_data_len(&c->data);
	ctdb_tdb_data_push(&c->key, wire->data, &np);
	ctdb_tdb_data_push(&c->data, wire->data + wire->keylen, &np);

	return 0;
}

int ctdb_reply_dmaster_pull(uint8_t *buf, size_t buflen,
			    struct ctdb_req_header *h,
			    TALLOC_CTX *mem_ctx,
			    struct ctdb_reply_dmaster *c)
{
	struct ctdb_reply_dmaster_wire *wire =
		(struct ctdb_reply_dmaster_wire *)buf;
	size_t length, np;
	int ret;

	length = offsetof(struct ctdb_reply_dmaster_wire, data);
	if (buflen < length) {
		return EMSGSIZE;
	}
	if (wire->keylen > buflen || wire->datalen > buflen) {
		return EMSGSIZE;
	}
	if (length + wire->keylen < length) {
		return EMSGSIZE;
	}
	if (length + wire->keylen + wire->datalen < length) {
		return EMSGSIZE;
	}
	if (buflen < length + wire->keylen + wire->datalen) {
		return EMSGSIZE;
	}

	if (h != NULL) {
		ret = ctdb_req_header_pull((uint8_t *)&wire->hdr, buflen, h,
					   &np);
		if (ret != 0) {
			return ret;
		}
	}

	c->db_id = wire->db_id;
	c->rsn = wire->rsn;

	ret = ctdb_tdb_data_pull(wire->data, wire->keylen, mem_ctx, &c->key,
				 &np);
	if (ret != 0) {
		return ret;
	}

	ret = ctdb_tdb_data_pull(wire->data + wire->keylen, wire->datalen,
				 mem_ctx, &c->data, &np);
	if (ret != 0) {
		return ret;
	}

	return 0;
}
