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
	return ctdb_req_header_len(h) +
		ctdb_uint32_len(&c->db_id) +
		ctdb_padding_len(4) +
		ctdb_uint64_len(&c->rsn) +
		ctdb_uint32_len(&c->dmaster) +
		ctdb_tdb_datan_len(&c->key) +
		ctdb_tdb_datan_len(&c->data);
}

int ctdb_req_dmaster_push(struct ctdb_req_header *h, struct ctdb_req_dmaster *c,
			  uint8_t *buf, size_t *buflen)
{
	size_t offset = 0, np;
	size_t length;
	uint32_t u32;

	length = ctdb_req_dmaster_len(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push(h, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&c->db_id, buf+offset, &np);
	offset += np;

	ctdb_padding_push(4, buf+offset, &np);
	offset += np;

	ctdb_uint64_push(&c->rsn, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&c->dmaster, buf+offset, &np);
	offset += np;

	u32 = ctdb_tdb_data_len(&c->key);
	ctdb_uint32_push(&u32, buf+offset, &np);
	offset += np;

	u32 = ctdb_tdb_data_len(&c->data);
	ctdb_uint32_push(&u32, buf+offset, &np);
	offset += np;

	ctdb_tdb_data_push(&c->key, buf+offset, &np);
	offset += np;

	ctdb_tdb_data_push(&c->data, buf+offset, &np);
	offset += np;

	return 0;
}

int ctdb_req_dmaster_pull(uint8_t *buf, size_t buflen,
			  struct ctdb_req_header *h,
			  TALLOC_CTX *mem_ctx,
			  struct ctdb_req_dmaster *c)
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

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &c->db_id, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_padding_pull(buf+offset, buflen-offset, 4, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint64_pull(buf+offset, buflen-offset, &c->rsn, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &c->dmaster, &np);
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
	c->data.dsize = u32;

	if (buflen-offset < c->key.dsize) {
		return EMSGSIZE;
	}

	ret = ctdb_tdb_data_pull(buf+offset, c->key.dsize, mem_ctx, &c->key,
				 &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	if (buflen-offset < c->data.dsize) {
		return EMSGSIZE;
	}

	ret = ctdb_tdb_data_pull(buf+offset, c->data.dsize, mem_ctx, &c->data,
				 &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	return 0;
}

size_t ctdb_reply_dmaster_len(struct ctdb_req_header *h,
			      struct ctdb_reply_dmaster *c)
{
	return ctdb_req_header_len(h) +
		ctdb_uint32_len(&c->db_id) +
		ctdb_padding_len(4) +
		ctdb_uint64_len(&c->rsn) +
		ctdb_tdb_datan_len(&c->key) +
		ctdb_tdb_datan_len(&c->data);
}

int ctdb_reply_dmaster_push(struct ctdb_req_header *h,
			    struct ctdb_reply_dmaster *c,
			    uint8_t *buf, size_t *buflen)
{
	size_t offset = 0, np;
	size_t length;
	uint32_t u32;

	length = ctdb_reply_dmaster_len(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push(h, buf+offset, &np);
	offset += np;

	ctdb_uint32_push(&c->db_id, buf+offset, &np);
	offset += np;

	ctdb_padding_push(4, buf+offset, &np);
	offset += np;

	ctdb_uint64_push(&c->rsn, buf+offset, &np);
	offset += np;

	u32 = ctdb_tdb_data_len(&c->key);
	ctdb_uint32_push(&u32, buf+offset, &np);
	offset += np;

	u32 = ctdb_tdb_data_len(&c->data);
	ctdb_uint32_push(&u32, buf+offset, &np);
	offset += np;

	ctdb_tdb_data_push(&c->key, buf+offset, &np);
	offset += np;

	ctdb_tdb_data_push(&c->data, buf+offset, &np);
	offset += np;

	return 0;
}

int ctdb_reply_dmaster_pull(uint8_t *buf, size_t buflen,
			    struct ctdb_req_header *h,
			    TALLOC_CTX *mem_ctx,
			    struct ctdb_reply_dmaster *c)
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

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &c->db_id, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_padding_pull(buf+offset, buflen-offset, 4, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	ret = ctdb_uint64_pull(buf+offset, buflen-offset, &c->rsn, &np);
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
	c->data.dsize = u32;

	if (buflen-offset < c->key.dsize) {
		return EMSGSIZE;
	}

	ret = ctdb_tdb_data_pull(buf+offset, c->key.dsize, mem_ctx, &c->key,
				 &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	if (buflen-offset < c->data.dsize) {
		return EMSGSIZE;
	}

	ret = ctdb_tdb_data_pull(buf+offset, c->data.dsize, mem_ctx, &c->data,
				 &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	return 0;
}
