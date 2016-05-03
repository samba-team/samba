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

struct ctdb_req_call_wire {
	struct ctdb_req_header hdr;
	uint32_t flags;
	uint32_t db_id;
	uint32_t callid;
	uint32_t hopcount;
	uint32_t keylen;
	uint32_t calldatalen;
	uint8_t data[1]; /* key[] followed by calldata[] */
};

struct ctdb_reply_call_wire {
	struct ctdb_req_header hdr;
	uint32_t status;
	uint32_t datalen;
	uint8_t  data[1];
};

struct ctdb_reply_error_wire {
	struct ctdb_req_header hdr;
	uint32_t status;
	uint32_t msglen;
	uint8_t  msg[1];
};

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
	return offsetof(struct ctdb_req_call_wire, data) +
		ctdb_tdb_data_len(c->key) + ctdb_tdb_data_len(c->calldata);
}

int ctdb_req_call_push(struct ctdb_req_header *h, struct ctdb_req_call *c,
		       uint8_t *buf, size_t *buflen)
{
	struct ctdb_req_call_wire *wire =
		(struct ctdb_req_call_wire *)buf;
	size_t length;

	if (c->key.dsize == 0) {
		return EINVAL;
	}

	length = ctdb_req_call_len(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push(h, (uint8_t *)&wire->hdr);

	wire->flags = c->flags;
	wire->db_id = c->db_id;
	wire->callid = c->callid;
	wire->hopcount = c->hopcount;
	wire->keylen = ctdb_tdb_data_len(c->key);
	wire->calldatalen = ctdb_tdb_data_len(c->calldata);
	ctdb_tdb_data_push(c->key, wire->data);
	ctdb_tdb_data_push(c->calldata, wire->data + wire->keylen);

	return 0;
}

int ctdb_req_call_pull(uint8_t *buf, size_t buflen,
		       struct ctdb_req_header *h,
		       TALLOC_CTX *mem_ctx,
		       struct ctdb_req_call *c)
{
	struct ctdb_req_call_wire *wire =
		(struct ctdb_req_call_wire *)buf;
	size_t length;
	int ret;

	length = offsetof(struct ctdb_req_call_wire, data);
	if (buflen < length) {
		return EMSGSIZE;
	}
	if (wire->keylen > buflen || wire->calldatalen > buflen) {
		return EMSGSIZE;
	}
	if (length + wire->keylen < length) {
		return EMSGSIZE;
	}
	if (length + wire->keylen + wire->calldatalen < length) {
		return EMSGSIZE;
	}
	if (buflen < length + wire->keylen + wire->calldatalen) {
		return EMSGSIZE;
	}

	if (h != NULL) {
		ret = ctdb_req_header_pull((uint8_t *)&wire->hdr, buflen, h);
		if (ret != 0) {
			return ret;
		}
	}

	c->flags = wire->flags;
	c->db_id = wire->db_id;
	c->callid = wire->callid;
	c->hopcount = wire->hopcount;

	ret = ctdb_tdb_data_pull(wire->data, wire->keylen, mem_ctx, &c->key);
	if (ret != 0) {
		return ret;
	}

	ret = ctdb_tdb_data_pull(wire->data + wire->keylen, wire->calldatalen,
				 mem_ctx, &c->calldata);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

size_t ctdb_reply_call_len(struct ctdb_req_header *h,
			   struct ctdb_reply_call *c)
{
	return offsetof(struct ctdb_reply_call_wire, data) +
		ctdb_tdb_data_len(c->data);
}

int ctdb_reply_call_push(struct ctdb_req_header *h, struct ctdb_reply_call *c,
			 uint8_t *buf, size_t *buflen)
{
	struct ctdb_reply_call_wire *wire =
		(struct ctdb_reply_call_wire *)buf;
	size_t length;

	length = ctdb_reply_call_len(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push(h, (uint8_t *)&wire->hdr);

	wire->status = c->status;
	wire->datalen = ctdb_tdb_data_len(c->data);
	ctdb_tdb_data_push(c->data, wire->data);

	return 0;
}

int ctdb_reply_call_pull(uint8_t *buf, size_t buflen,
			 struct ctdb_req_header *h,
			 TALLOC_CTX *mem_ctx,
			 struct ctdb_reply_call *c)
{
	struct ctdb_reply_call_wire *wire =
		(struct ctdb_reply_call_wire *)buf;
	size_t length;
	int ret;

	length = offsetof(struct ctdb_reply_call_wire, data);
	if (buflen < length) {
		return EMSGSIZE;
	}
	if (wire->datalen > buflen) {
		return EMSGSIZE;
	}
	if (length + wire->datalen < length) {
		return EMSGSIZE;
	}
	if (buflen < length + wire->datalen) {
		return EMSGSIZE;
	}

	if (h != NULL) {
		ret = ctdb_req_header_pull((uint8_t *)&wire->hdr, buflen, h);
		if (ret != 0) {
			return ret;
		}
	}

	c->status = wire->status;

	ret = ctdb_tdb_data_pull(wire->data, wire->datalen, mem_ctx, &c->data);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

size_t ctdb_reply_error_len(struct ctdb_req_header *h,
			    struct ctdb_reply_error *c)
{
	return offsetof(struct ctdb_reply_error_wire, msg) +
		ctdb_tdb_data_len(c->msg);
}

int ctdb_reply_error_push(struct ctdb_req_header *h, struct ctdb_reply_error *c,
			  uint8_t *buf, size_t *buflen)
{
	struct ctdb_reply_error_wire *wire =
		(struct ctdb_reply_error_wire *)buf;
	size_t length;

	length = ctdb_reply_error_len(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push(h, (uint8_t *)&wire->hdr);

	wire->status = c->status;
	wire->msglen = ctdb_tdb_data_len(c->msg);
	ctdb_tdb_data_push(c->msg, wire->msg);

	return 0;
}

int ctdb_reply_error_pull(uint8_t *buf, size_t buflen,
			  struct ctdb_req_header *h,
			  TALLOC_CTX *mem_ctx,
			  struct ctdb_reply_error *c)
{
	struct ctdb_reply_error_wire *wire =
		(struct ctdb_reply_error_wire *)buf;
	size_t length;
	int ret;

	length = offsetof(struct ctdb_reply_error_wire, msg);
	if (buflen < length) {
		return EMSGSIZE;
	}
	if (wire->msglen > buflen) {
		return EMSGSIZE;
	}
	if (length + wire->msglen < length) {
		return EMSGSIZE;
	}
	if (buflen < length + wire->msglen) {
		return EMSGSIZE;
	}

	if (h != NULL) {
		ret = ctdb_req_header_pull((uint8_t *)&wire->hdr, buflen, h);
		if (ret != 0) {
			return ret;
		}
	}

	c->status = wire->status;

	ret = ctdb_tdb_data_pull(wire->msg, wire->msglen, mem_ctx, &c->msg);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

size_t ctdb_req_dmaster_len(struct ctdb_req_header *h,
			    struct ctdb_req_dmaster *c)
{
	return offsetof(struct ctdb_req_dmaster_wire, data) +
		ctdb_tdb_data_len(c->key) + ctdb_tdb_data_len(c->data);
}

int ctdb_req_dmaster_push(struct ctdb_req_header *h, struct ctdb_req_dmaster *c,
			  uint8_t *buf, size_t *buflen)
{
	struct ctdb_req_dmaster_wire *wire =
		(struct ctdb_req_dmaster_wire *)buf;
	size_t length;

	length = ctdb_req_dmaster_len(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push(h, (uint8_t *)&wire->hdr);

	wire->db_id = c->db_id;
	wire->rsn = c->rsn;
	wire->dmaster = c->dmaster;
	wire->keylen = ctdb_tdb_data_len(c->key);
	wire->datalen = ctdb_tdb_data_len(c->data);
	ctdb_tdb_data_push(c->key, wire->data);
	ctdb_tdb_data_push(c->data, wire->data + wire->keylen);

	return 0;
}

int ctdb_req_dmaster_pull(uint8_t *buf, size_t buflen,
			  struct ctdb_req_header *h,
			  TALLOC_CTX *mem_ctx,
			  struct ctdb_req_dmaster *c)
{
	struct ctdb_req_dmaster_wire *wire =
		(struct ctdb_req_dmaster_wire *)buf;
	size_t length;
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
		ret = ctdb_req_header_pull((uint8_t *)&wire->hdr, buflen, h);
		if (ret != 0) {
			return ret;
		}
	}

	c->db_id = wire->db_id;
	c->rsn = wire->rsn;
	c->dmaster = wire->dmaster;

	ret = ctdb_tdb_data_pull(wire->data, wire->keylen, mem_ctx, &c->key);
	if (ret != 0) {
		return ret;
	}

	ret = ctdb_tdb_data_pull(wire->data + wire->keylen, wire->datalen,
				 mem_ctx, &c->data);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

size_t ctdb_reply_dmaster_len(struct ctdb_req_header *h,
			      struct ctdb_reply_dmaster *c)
{
	return offsetof(struct ctdb_reply_dmaster_wire, data) +
		ctdb_tdb_data_len(c->key) + ctdb_tdb_data_len(c->data);
}

int ctdb_reply_dmaster_push(struct ctdb_req_header *h,
			    struct ctdb_reply_dmaster *c,
			    uint8_t *buf, size_t *buflen)
{
	struct ctdb_reply_dmaster_wire *wire =
		(struct ctdb_reply_dmaster_wire *)buf;
	size_t length;

	length = ctdb_reply_dmaster_len(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push(h, (uint8_t *)&wire->hdr);

	wire->db_id = c->db_id;
	wire->rsn = c->rsn;
	wire->keylen = ctdb_tdb_data_len(c->key);
	wire->datalen = ctdb_tdb_data_len(c->data);
	ctdb_tdb_data_push(c->key, wire->data);
	ctdb_tdb_data_push(c->data, wire->data + wire->keylen);

	return 0;
}

int ctdb_reply_dmaster_pull(uint8_t *buf, size_t buflen,
			    struct ctdb_req_header *h,
			    TALLOC_CTX *mem_ctx,
			    struct ctdb_reply_dmaster *c)
{
	struct ctdb_reply_dmaster_wire *wire =
		(struct ctdb_reply_dmaster_wire *)buf;
	size_t length;
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
		ret = ctdb_req_header_pull((uint8_t *)&wire->hdr, buflen, h);
		if (ret != 0) {
			return ret;
		}
	}

	c->db_id = wire->db_id;
	c->rsn = wire->rsn;

	ret = ctdb_tdb_data_pull(wire->data, wire->keylen, mem_ctx, &c->key);
	if (ret != 0) {
		return ret;
	}

	ret = ctdb_tdb_data_pull(wire->data + wire->keylen, wire->datalen,
				 mem_ctx, &c->data);
	if (ret != 0) {
		return ret;
	}

	return 0;
}
