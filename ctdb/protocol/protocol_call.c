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

int ctdb_req_call_push(struct ctdb_req_header *h, struct ctdb_req_call *c,
		       TALLOC_CTX *mem_ctx, uint8_t **pkt, size_t *pkt_len)
{
	struct ctdb_req_call_wire *wire;
	uint8_t *buf;
	size_t length, buflen;
	int ret;

	if (c->key.dsize == 0) {
		return EINVAL;
	}

	length = offsetof(struct ctdb_req_call_wire, data) +
		 c->key.dsize + c->calldata.dsize;

	ret = allocate_pkt(mem_ctx, length, &buf, &buflen);
	if (ret != 0) {
		return ret;
	}

	wire = (struct ctdb_req_call_wire *)buf;

	h->length = buflen;
	memcpy(&wire->hdr, h, sizeof(struct ctdb_req_header));

	wire->flags = c->flags;
	wire->db_id = c->db_id;
	wire->callid = c->callid;
	wire->hopcount = c->hopcount;
	wire->keylen = c->key.dsize;
	wire->calldatalen = c->calldata.dsize;
	memcpy(wire->data, c->key.dptr, c->key.dsize);
	if (c->calldata.dsize > 0) {
		memcpy(wire->data + c->key.dsize, c->calldata.dptr,
		       c->calldata.dsize);
	}

	*pkt = buf;
	*pkt_len = buflen;
	return 0;
}

int ctdb_req_call_pull(uint8_t *pkt, size_t pkt_len,
		       struct ctdb_req_header *h,
		       TALLOC_CTX *mem_ctx,
		       struct ctdb_req_call *c)
{
	struct ctdb_req_call_wire *wire;
	size_t length;

	length = offsetof(struct ctdb_req_call_wire, data);
	if (pkt_len < length) {
		return EMSGSIZE;
	}

	wire = (struct ctdb_req_call_wire *)pkt;

	if (pkt_len < length + wire->keylen + wire->calldatalen) {
		return EMSGSIZE;
	}

	memcpy(h, &wire->hdr, sizeof(struct ctdb_req_header));

	c->flags = wire->flags;
	c->db_id = wire->db_id;
	c->callid = wire->callid;
	c->hopcount = wire->hopcount;
	c->key.dsize = wire->keylen;
	c->key.dptr = talloc_memdup(mem_ctx, wire->data, wire->keylen);
	if (c->key.dptr == NULL) {
		return ENOMEM;
	}
	c->calldata.dsize = wire->calldatalen;
	if (wire->calldatalen > 0) {
		c->calldata.dptr = talloc_memdup(mem_ctx,
						 wire->data + wire->keylen,
						 wire->calldatalen);
		if (c->calldata.dptr == NULL) {
			talloc_free(c->key.dptr);
			return ENOMEM;
		}
	}

	return 0;
}

int ctdb_reply_call_push(struct ctdb_req_header *h, struct ctdb_reply_call *c,
			 TALLOC_CTX *mem_ctx, uint8_t **pkt, size_t *pkt_len)
{
	struct ctdb_reply_call_wire *wire;
	uint8_t *buf;
	size_t length, buflen;
	int ret;

	length = offsetof(struct ctdb_reply_call_wire, data) + c->data.dsize;

	ret = allocate_pkt(mem_ctx, length, &buf, &buflen);
	if (ret != 0) {
		return ret;
	}

	wire = (struct ctdb_reply_call_wire *)buf;

	h->length = buflen;
	memcpy(&wire->hdr, h, sizeof(struct ctdb_req_header));

	wire->status = c->status;
	wire->datalen = c->data.dsize;
	if (c->data.dsize > 0) {
		memcpy(wire->data, c->data.dptr, c->data.dsize);
	}

	*pkt = buf;
	*pkt_len = buflen;
	return 0;
}

int ctdb_reply_call_pull(uint8_t *pkt, size_t pkt_len,
			 struct ctdb_req_header *h,
			 TALLOC_CTX *mem_ctx,
			 struct ctdb_reply_call *c)
{
	struct ctdb_reply_call_wire *wire;
	size_t length;

	length = offsetof(struct ctdb_reply_call_wire, data);
	if (pkt_len < length) {
		return EMSGSIZE;
	}

	wire = (struct ctdb_reply_call_wire *)pkt;

	if (pkt_len < length + wire->datalen) {
		return EMSGSIZE;
	}

	memcpy(h, &wire->hdr, sizeof(struct ctdb_req_header));

	c->status = wire->status;
	c->data.dsize = wire->datalen;
	if (wire->datalen > 0) {
		c->data.dptr = talloc_memdup(mem_ctx, wire->data,
					     wire->datalen);
		if (c->data.dptr == NULL) {
			return ENOMEM;
		}
	}

	return 0;
}

int ctdb_reply_error_push(struct ctdb_req_header *h, struct ctdb_reply_error *c,
			  TALLOC_CTX *mem_ctx, uint8_t **pkt, size_t *pkt_len)
{
	struct ctdb_reply_error_wire *wire;
	uint8_t *buf;
	size_t length, buflen;
	int ret;

	length = offsetof(struct ctdb_reply_error_wire, msg) + c->msg.dsize;

	ret = allocate_pkt(mem_ctx, length, &buf, &buflen);
	if (ret != 0) {
		return ret;
	}

	wire = (struct ctdb_reply_error_wire *)buf;

	h->length = buflen;
	memcpy(&wire->hdr, h, sizeof(struct ctdb_req_header));

	wire->status = c->status;
	wire->msglen = c->msg.dsize;
	if (c->msg.dsize > 0) {
		memcpy(wire->msg, c->msg.dptr, c->msg.dsize);
	}

	*pkt = buf;
	*pkt_len = buflen;
	return 0;
}

int ctdb_reply_error_pull(uint8_t *pkt, size_t pkt_len,
			  struct ctdb_req_header *h,
			  TALLOC_CTX *mem_ctx,
			  struct ctdb_reply_error *c)
{
	struct ctdb_reply_error_wire *wire;
	size_t length;

	length = offsetof(struct ctdb_reply_error_wire, msg);
	if (pkt_len < length) {
		return EMSGSIZE;
	}

	wire = (struct ctdb_reply_error_wire *)pkt;

	if (pkt_len < length + wire->msglen) {
		return EMSGSIZE;
	}

	memcpy(h, &wire->hdr, sizeof(struct ctdb_req_header));

	c->status = wire->status;
	c->msg.dsize = wire->msglen;
	if (wire->msglen > 0) {
		c->msg.dptr = talloc_memdup(mem_ctx, wire->msg, wire->msglen);
		if (c->msg.dptr == NULL) {
			return ENOMEM;
		}
	}

	return 0;
}

int ctdb_req_dmaster_push(struct ctdb_req_header *h, struct ctdb_req_dmaster *c,
			  TALLOC_CTX *mem_ctx, uint8_t **pkt, size_t *pkt_len)
{
	struct ctdb_req_dmaster_wire *wire;
	uint8_t *buf;
	size_t length, buflen;
	int ret;

	length = offsetof(struct ctdb_req_dmaster_wire, data) +
		 c->key.dsize + c->data.dsize;

	ret = allocate_pkt(mem_ctx, length, &buf, &buflen);
	if (ret != 0) {
		return ret;
	}

	wire = (struct ctdb_req_dmaster_wire *)buf;

	h->length = buflen;
	memcpy(&wire->hdr, h, sizeof(struct ctdb_req_header));

	wire->db_id = c->db_id;
	wire->rsn = c->rsn;
	wire->dmaster = c->dmaster;
	wire->keylen = c->key.dsize;
	if (c->key.dsize > 0) {
		memcpy(wire->data, c->key.dptr, c->key.dsize);
	}
	wire->datalen = c->data.dsize;
	if (c->data.dsize > 0) {
		memcpy(wire->data + c->key.dsize, c->data.dptr, c->data.dsize);
	}

	*pkt = buf;
	*pkt_len = buflen;
	return 0;
}

int ctdb_req_dmaster_pull(uint8_t *pkt, size_t pkt_len,
			  struct ctdb_req_header *h,
			  TALLOC_CTX *mem_ctx,
			  struct ctdb_req_dmaster *c)
{
	struct ctdb_req_dmaster_wire *wire;
	size_t length;

	length = offsetof(struct ctdb_req_dmaster_wire, data);
	if (pkt_len < length) {
		return EMSGSIZE;
	}

	wire = (struct ctdb_req_dmaster_wire *)pkt;

	if (pkt_len < length + wire->keylen + wire->datalen) {
		return EMSGSIZE;
	}

	memcpy(h, &wire->hdr, sizeof(struct ctdb_req_header));

	c->db_id = wire->db_id;
	c->rsn = wire->rsn;
	c->dmaster = wire->dmaster;
	c->key.dsize = wire->keylen;
	c->key.dptr = talloc_memdup(mem_ctx, wire->data, wire->keylen);
	if (c->key.dptr == NULL) {
		return ENOMEM;
	}
	c->data.dsize = wire->datalen;
	if (wire->datalen > 0) {
		c->data.dptr = talloc_memdup(mem_ctx, wire->data + wire->keylen,
					     wire->datalen);
		if (c->data.dptr == NULL) {
			talloc_free(c->key.dptr);
			return ENOMEM;
		}
	}

	return 0;
}

int ctdb_reply_dmaster_push(struct ctdb_req_header *h,
			    struct ctdb_reply_dmaster *c,
			    TALLOC_CTX *mem_ctx, uint8_t **pkt, size_t *pkt_len)
{
	struct ctdb_reply_dmaster_wire *wire;
	uint8_t *buf;
	size_t length, buflen;
	int ret;

	length = offsetof(struct ctdb_reply_dmaster_wire, data) +
		 c->key.dsize + c->data.dsize;

	ret = allocate_pkt(mem_ctx, length, &buf, &buflen);
	if (ret != 0) {
		return ret;
	}

	wire = (struct ctdb_reply_dmaster_wire *)buf;

	h->length = buflen;
	memcpy(&wire->hdr, h, sizeof(struct ctdb_req_header));

	wire->db_id = c->db_id;
	wire->rsn = c->rsn;
	wire->keylen = c->key.dsize;
	if (c->key.dsize > 0) {
		memcpy(wire->data, c->key.dptr, c->key.dsize);
	}
	wire->datalen = c->data.dsize;
	if (c->data.dsize > 0) {
		memcpy(wire->data + c->key.dsize, c->data.dptr, c->data.dsize);
	}

	*pkt = buf;
	*pkt_len = buflen;
	return 0;
}

int ctdb_reply_dmaster_pull(uint8_t *pkt, size_t pkt_len,
			    struct ctdb_req_header *h,
			    TALLOC_CTX *mem_ctx,
			    struct ctdb_reply_dmaster *c)
{
	struct ctdb_reply_dmaster_wire *wire;
	size_t length;

	length = offsetof(struct ctdb_reply_dmaster_wire, data);
	if (pkt_len < length) {
		return EMSGSIZE;
	}

	wire = (struct ctdb_reply_dmaster_wire *)pkt;

	if (pkt_len < length + wire->keylen + wire->datalen) {
		return EMSGSIZE;
	}

	memcpy(h, &wire->hdr, sizeof(struct ctdb_req_header));

	c->db_id = wire->db_id;
	c->rsn = wire->rsn;
	c->key.dsize = wire->keylen;
	c->key.dptr = talloc_memdup(mem_ctx, wire->data, wire->keylen);
	if (c->key.dptr == NULL) {
		return ENOMEM;
	}
	c->data.dsize = wire->datalen;
	if (wire->datalen > 0) {
		c->data.dptr = talloc_memdup(mem_ctx, wire->data + wire->keylen,
					     wire->datalen);
		if (c->data.dptr == NULL) {
			talloc_free(c->key.dptr);
			return ENOMEM;
		}
	}

	return 0;
}
