/*
   ctdb protocol backward compatibility test

   Copyright (C) Amitay Isaacs  2017

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
#include "protocol/protocol_header.c"
#include "protocol/protocol_call.c"
#include "protocol/protocol_control.c"
#include "protocol/protocol_message.c"
#include "protocol/protocol_keepalive.c"
#include "protocol/protocol_tunnel.c"

#include "tests/src/protocol_common.h"
#include "tests/src/protocol_common_ctdb.h"

#define COMPAT_TEST_FUNC(NAME)		test_ ##NAME## _compat
#define OLD_LEN_FUNC(NAME)		NAME## _len_old
#define OLD_PUSH_FUNC(NAME)		NAME## _push_old
#define OLD_PULL_FUNC(NAME)		NAME## _pull_old

#define COMPAT_CTDB1_TEST(TYPE, NAME)	\
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

#define COMPAT_CTDB4_TEST(TYPE, NAME, OPER) \
static void COMPAT_TEST_FUNC(NAME)(void) \
{ \
	TALLOC_CTX *mem_ctx; \
	uint8_t *buf1, *buf2; \
	struct ctdb_req_header h, h1, h2; \
	TYPE p = { 0 }, p1, p2; \
	size_t buflen1, buflen2; \
	int ret; \
\
	mem_ctx = talloc_new(NULL); \
	assert(mem_ctx != NULL); \
	fill_ctdb_req_header(&h); \
	FILL_FUNC(NAME)(mem_ctx, &p); \
	buflen1 = LEN_FUNC(NAME)(&h, &p); \
	buflen2 = OLD_LEN_FUNC(NAME)(&h, &p); \
	assert(buflen1 == buflen2); \
	buf1 = talloc_zero_size(mem_ctx, buflen1); \
	assert(buf1 != NULL); \
	buf2 = talloc_zero_size(mem_ctx, buflen2); \
	assert(buf2 != NULL); \
	ret = PUSH_FUNC(NAME)(&h, &p, buf1, &buflen1); \
	assert(ret == 0); \
	ret = OLD_PUSH_FUNC(NAME)(&h, &p, buf2, &buflen2); \
	assert(ret == 0); \
	assert(memcmp(buf1, buf2, buflen1) == 0); \
	ret = PULL_FUNC(NAME)(buf1, buflen1, &h1, mem_ctx, &p1); \
	assert(ret == 0); \
	ret = OLD_PULL_FUNC(NAME)(buf2, buflen2, &h2, mem_ctx, &p2); \
	assert(ret == 0); \
	verify_ctdb_req_header(&h1, &h2); \
	VERIFY_FUNC(NAME)(&p1, &p2); \
	talloc_free(mem_ctx); \
}

#define COMPAT_CTDB5_TEST(TYPE, NAME, OPER) \
static void COMPAT_TEST_FUNC(NAME)(uint32_t opcode) \
{ \
	TALLOC_CTX *mem_ctx; \
	uint8_t *buf1, *buf2; \
	struct ctdb_req_header h, h1, h2; \
	TYPE p = { 0 }, p1, p2; \
	size_t buflen1, buflen2; \
	int ret; \
\
	mem_ctx = talloc_new(NULL); \
	assert(mem_ctx != NULL); \
	fill_ctdb_req_header(&h); \
	FILL_FUNC(NAME)(mem_ctx, &p, opcode); \
	buflen1 = LEN_FUNC(NAME)(&h, &p); \
	buflen2 = OLD_LEN_FUNC(NAME)(&h, &p); \
	assert(buflen1 == buflen2); \
	buf1 = talloc_zero_size(mem_ctx, buflen1); \
	assert(buf1 != NULL); \
	buf2 = talloc_zero_size(mem_ctx, buflen2); \
	assert(buf2 != NULL); \
	ret = PUSH_FUNC(NAME)(&h, &p, buf1, &buflen1); \
	assert(ret == 0); \
	ret = OLD_PUSH_FUNC(NAME)(&h, &p, buf2, &buflen2); \
	assert(ret == 0); \
	assert(memcmp(buf1, buf2, buflen1) == 0); \
	ret = PULL_FUNC(NAME)(buf1, buflen1, &h1, mem_ctx, &p1); \
	assert(ret == 0); \
	ret = OLD_PULL_FUNC(NAME)(buf2, buflen2, &h2, mem_ctx, &p2); \
	assert(ret == 0); \
	verify_ctdb_req_header(&h1, &h2); \
	VERIFY_FUNC(NAME)(&p1, &p2); \
	talloc_free(mem_ctx); \
}

#define COMPAT_CTDB6_TEST(TYPE, NAME, OPER) \
static void COMPAT_TEST_FUNC(NAME)(uint32_t opcode) \
{ \
	TALLOC_CTX *mem_ctx; \
	uint8_t *buf1, *buf2; \
	struct ctdb_req_header h, h1, h2; \
	TYPE p = { 0 }, p1, p2; \
	size_t buflen1, buflen2; \
	int ret; \
\
	mem_ctx = talloc_new(NULL); \
	assert(mem_ctx != NULL); \
	fill_ctdb_req_header(&h); \
	FILL_FUNC(NAME)(mem_ctx, &p, opcode); \
	buflen1 = LEN_FUNC(NAME)(&h, &p); \
	buflen2 = OLD_LEN_FUNC(NAME)(&h, &p); \
	assert(buflen1 == buflen2); \
	buf1 = talloc_zero_size(mem_ctx, buflen1); \
	assert(buf1 != NULL); \
	buf2 = talloc_zero_size(mem_ctx, buflen2); \
	assert(buf2 != NULL); \
	ret = PUSH_FUNC(NAME)(&h, &p, buf1, &buflen1); \
	assert(ret == 0); \
	ret = OLD_PUSH_FUNC(NAME)(&h, &p, buf2, &buflen2); \
	assert(ret == 0); \
	assert(memcmp(buf1, buf2, buflen1) == 0); \
	ret = PULL_FUNC(NAME)(buf1, buflen1, opcode, &h1, mem_ctx, &p1); \
	assert(ret == 0); \
	ret = OLD_PULL_FUNC(NAME)(buf2, buflen2, opcode, &h2, mem_ctx, &p2); \
	assert(ret == 0); \
	verify_ctdb_req_header(&h1, &h2); \
	VERIFY_FUNC(NAME)(&p1, &p2); \
	talloc_free(mem_ctx); \
}

#define COMPAT_CTDB7_TEST(TYPE, NAME, OPER) \
static void COMPAT_TEST_FUNC(NAME)(uint64_t srvid) \
{ \
	TALLOC_CTX *mem_ctx; \
	uint8_t *buf1, *buf2; \
	struct ctdb_req_header h, h1, h2; \
	TYPE p = { 0 }, p1, p2; \
	size_t buflen1, buflen2; \
	int ret; \
\
	mem_ctx = talloc_new(NULL); \
	assert(mem_ctx != NULL); \
	fill_ctdb_req_header(&h); \
	FILL_FUNC(NAME)(mem_ctx, &p, srvid); \
	buflen1 = LEN_FUNC(NAME)(&h, &p); \
	buflen2 = OLD_LEN_FUNC(NAME)(&h, &p); \
	assert(buflen1 == buflen2); \
	buf1 = talloc_zero_size(mem_ctx, buflen1); \
	assert(buf1 != NULL); \
	buf2 = talloc_zero_size(mem_ctx, buflen2); \
	assert(buf2 != NULL); \
	ret = PUSH_FUNC(NAME)(&h, &p, buf1, &buflen1); \
	assert(ret == 0); \
	ret = OLD_PUSH_FUNC(NAME)(&h, &p, buf2, &buflen2); \
	assert(ret == 0); \
	assert(memcmp(buf1, buf2, buflen1) == 0); \
	ret = PULL_FUNC(NAME)(buf1, buflen1, &h1, mem_ctx, &p1); \
	assert(ret == 0); \
	ret = OLD_PULL_FUNC(NAME)(buf2, buflen2, &h2, mem_ctx, &p2); \
	assert(ret == 0); \
	verify_ctdb_req_header(&h1, &h2); \
	VERIFY_FUNC(NAME)(&p1, &p2); \
	talloc_free(mem_ctx); \
}


static size_t ctdb_req_header_len_old(struct ctdb_req_header *in)
{
        return sizeof(struct ctdb_req_header);
}

static void ctdb_req_header_push_old(struct ctdb_req_header *in, uint8_t *buf)
{
        memcpy(buf, in, sizeof(struct ctdb_req_header));
}

static int ctdb_req_header_pull_old(uint8_t *buf, size_t buflen,
				    struct ctdb_req_header *out)
{
        if (buflen < sizeof(struct ctdb_req_header)) {
                return EMSGSIZE;
        }

        memcpy(out, buf, sizeof(struct ctdb_req_header));
        return 0;
}

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

static size_t ctdb_req_call_len_old(struct ctdb_req_header *h,
				    struct ctdb_req_call *c)
{
	return offsetof(struct ctdb_req_call_wire, data) +
		ctdb_tdb_data_len(&c->key) +
		ctdb_tdb_data_len(&c->calldata);
}

static int ctdb_req_call_push_old(struct ctdb_req_header *h,
				  struct ctdb_req_call *c,
				  uint8_t *buf, size_t *buflen)
{
	struct ctdb_req_call_wire *wire =
		(struct ctdb_req_call_wire *)buf;
	size_t length, np;

	if (c->key.dsize == 0) {
		return EINVAL;
	}

	length = ctdb_req_call_len_old(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push_old(h, (uint8_t *)&wire->hdr);

	wire->flags = c->flags;
	wire->db_id = c->db_id;
	wire->callid = c->callid;
	wire->hopcount = c->hopcount;
	wire->keylen = ctdb_tdb_data_len(&c->key);
	wire->calldatalen = ctdb_tdb_data_len(&c->calldata);
	ctdb_tdb_data_push(&c->key, wire->data, &np);
	ctdb_tdb_data_push(&c->calldata, wire->data + wire->keylen, &np);

	return 0;
}

static int ctdb_req_call_pull_old(uint8_t *buf, size_t buflen,
				  struct ctdb_req_header *h,
				  TALLOC_CTX *mem_ctx,
				  struct ctdb_req_call *c)
{
	struct ctdb_req_call_wire *wire =
		(struct ctdb_req_call_wire *)buf;
	size_t length, np;
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
		ret = ctdb_req_header_pull_old((uint8_t *)&wire->hdr, buflen,
					       h);
		if (ret != 0) {
			return ret;
		}
	}

	c->flags = wire->flags;
	c->db_id = wire->db_id;
	c->callid = wire->callid;
	c->hopcount = wire->hopcount;

	ret = ctdb_tdb_data_pull(wire->data, wire->keylen, mem_ctx, &c->key,
				 &np);
	if (ret != 0) {
		return ret;
	}

	ret = ctdb_tdb_data_pull(wire->data + wire->keylen, wire->calldatalen,
				 mem_ctx, &c->calldata, &np);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

struct ctdb_reply_call_wire {
	struct ctdb_req_header hdr;
	uint32_t status;
	uint32_t datalen;
	uint8_t  data[1];
};

static size_t ctdb_reply_call_len_old(struct ctdb_req_header *h,
				      struct ctdb_reply_call *c)
{
	return offsetof(struct ctdb_reply_call_wire, data) +
		ctdb_tdb_data_len(&c->data);
}

static int ctdb_reply_call_push_old(struct ctdb_req_header *h,
				    struct ctdb_reply_call *c,
				    uint8_t *buf, size_t *buflen)
{
	struct ctdb_reply_call_wire *wire =
		(struct ctdb_reply_call_wire *)buf;
	size_t length, np;

	length = ctdb_reply_call_len_old(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push_old(h, (uint8_t *)&wire->hdr);

	wire->status = c->status;
	wire->datalen = ctdb_tdb_data_len(&c->data);
	ctdb_tdb_data_push(&c->data, wire->data, &np);

	return 0;
}

static int ctdb_reply_call_pull_old(uint8_t *buf, size_t buflen,
				    struct ctdb_req_header *h,
				    TALLOC_CTX *mem_ctx,
				    struct ctdb_reply_call *c)
{
	struct ctdb_reply_call_wire *wire =
		(struct ctdb_reply_call_wire *)buf;
	size_t length, np;
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
		ret = ctdb_req_header_pull_old((uint8_t *)&wire->hdr, buflen,
					       h);
		if (ret != 0) {
			return ret;
		}
	}

	c->status = wire->status;

	ret = ctdb_tdb_data_pull(wire->data, wire->datalen, mem_ctx, &c->data,
				 &np);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

struct ctdb_reply_error_wire {
	struct ctdb_req_header hdr;
	uint32_t status;
	uint32_t msglen;
	uint8_t  msg[1];
};

static size_t ctdb_reply_error_len_old(struct ctdb_req_header *h,
				       struct ctdb_reply_error *c)
{
	return offsetof(struct ctdb_reply_error_wire, msg) +
		ctdb_tdb_data_len(&c->msg);
}

static int ctdb_reply_error_push_old(struct ctdb_req_header *h,
				     struct ctdb_reply_error *c,
				     uint8_t *buf, size_t *buflen)
{
	struct ctdb_reply_error_wire *wire =
		(struct ctdb_reply_error_wire *)buf;
	size_t length, np;

	length = ctdb_reply_error_len_old(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push_old(h, (uint8_t *)&wire->hdr);

	wire->status = c->status;
	wire->msglen = ctdb_tdb_data_len(&c->msg);
	ctdb_tdb_data_push(&c->msg, wire->msg, &np);

	return 0;
}

static int ctdb_reply_error_pull_old(uint8_t *buf, size_t buflen,
				     struct ctdb_req_header *h,
				     TALLOC_CTX *mem_ctx,
				     struct ctdb_reply_error *c)
{
	struct ctdb_reply_error_wire *wire =
		(struct ctdb_reply_error_wire *)buf;
	size_t length, np;
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
		ret = ctdb_req_header_pull_old((uint8_t *)&wire->hdr, buflen,
					       h);
		if (ret != 0) {
			return ret;
		}
	}

	c->status = wire->status;

	ret = ctdb_tdb_data_pull(wire->msg, wire->msglen, mem_ctx, &c->msg,
				 &np);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

struct ctdb_req_dmaster_wire {
	struct ctdb_req_header hdr;
	uint32_t db_id;
	uint64_t rsn;
	uint32_t dmaster;
	uint32_t keylen;
	uint32_t datalen;
	uint8_t  data[1];
};

static size_t ctdb_req_dmaster_len_old(struct ctdb_req_header *h,
				       struct ctdb_req_dmaster *c)
{
	return offsetof(struct ctdb_req_dmaster_wire, data) +
		ctdb_tdb_data_len(&c->key) + ctdb_tdb_data_len(&c->data);
}

static int ctdb_req_dmaster_push_old(struct ctdb_req_header *h,
				     struct ctdb_req_dmaster *c,
				     uint8_t *buf, size_t *buflen)
{
	struct ctdb_req_dmaster_wire *wire =
		(struct ctdb_req_dmaster_wire *)buf;
	size_t length, np;

	length = ctdb_req_dmaster_len_old(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push_old(h, (uint8_t *)&wire->hdr);

	wire->db_id = c->db_id;
	wire->rsn = c->rsn;
	wire->dmaster = c->dmaster;
	wire->keylen = ctdb_tdb_data_len(&c->key);
	wire->datalen = ctdb_tdb_data_len(&c->data);
	ctdb_tdb_data_push(&c->key, wire->data, &np);
	ctdb_tdb_data_push(&c->data, wire->data + wire->keylen, &np);

	return 0;
}

static int ctdb_req_dmaster_pull_old(uint8_t *buf, size_t buflen,
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
		ret = ctdb_req_header_pull_old((uint8_t *)&wire->hdr, buflen,
					       h);
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

struct ctdb_reply_dmaster_wire {
	struct ctdb_req_header hdr;
	uint32_t db_id;
	uint64_t rsn;
	uint32_t keylen;
	uint32_t datalen;
	uint8_t  data[1];
};

static size_t ctdb_reply_dmaster_len_old(struct ctdb_req_header *h,
					 struct ctdb_reply_dmaster *c)
{
	return offsetof(struct ctdb_reply_dmaster_wire, data) +
		ctdb_tdb_data_len(&c->key) + ctdb_tdb_data_len(&c->data);
}

static int ctdb_reply_dmaster_push_old(struct ctdb_req_header *h,
				       struct ctdb_reply_dmaster *c,
				       uint8_t *buf, size_t *buflen)
{
	struct ctdb_reply_dmaster_wire *wire =
		(struct ctdb_reply_dmaster_wire *)buf;
	size_t length, np;

	length = ctdb_reply_dmaster_len_old(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push_old(h, (uint8_t *)&wire->hdr);

	wire->db_id = c->db_id;
	wire->rsn = c->rsn;
	wire->keylen = ctdb_tdb_data_len(&c->key);
	wire->datalen = ctdb_tdb_data_len(&c->data);
	ctdb_tdb_data_push(&c->key, wire->data, &np);
	ctdb_tdb_data_push(&c->data, wire->data + wire->keylen, &np);

	return 0;
}

static int ctdb_reply_dmaster_pull_old(uint8_t *buf, size_t buflen,
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
		ret = ctdb_req_header_pull_old((uint8_t *)&wire->hdr, buflen,
					       h);
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

struct ctdb_req_control_wire {
	struct ctdb_req_header hdr;
	uint32_t opcode;
	uint32_t pad;
	uint64_t srvid;
	uint32_t client_id;
	uint32_t flags;
	uint32_t datalen;
	uint8_t data[1];
};

static size_t ctdb_req_control_len_old(struct ctdb_req_header *h,
				       struct ctdb_req_control *c)
{
	return offsetof(struct ctdb_req_control_wire, data) +
		ctdb_req_control_data_len(&c->rdata);
}

static int ctdb_req_control_push_old(struct ctdb_req_header *h,
				     struct ctdb_req_control *c,
				     uint8_t *buf, size_t *buflen)
{
	struct ctdb_req_control_wire *wire =
		(struct ctdb_req_control_wire *)buf;
	size_t length, np;

	length = ctdb_req_control_len_old(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push_old(h, (uint8_t *)&wire->hdr);

	wire->opcode = c->opcode;
	wire->pad = c->pad;
	wire->srvid = c->srvid;
	wire->client_id = c->client_id;
	wire->flags = c->flags;

	wire->datalen = ctdb_req_control_data_len(&c->rdata);
	ctdb_req_control_data_push(&c->rdata, wire->data, &np);

	return 0;
}

static int ctdb_req_control_pull_old(uint8_t *buf, size_t buflen,
				     struct ctdb_req_header *h,
				     TALLOC_CTX *mem_ctx,
				     struct ctdb_req_control *c)
{
	struct ctdb_req_control_wire *wire =
		(struct ctdb_req_control_wire *)buf;
	size_t length, np;
	int ret;

	length = offsetof(struct ctdb_req_control_wire, data);
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
		ret = ctdb_req_header_pull_old((uint8_t *)&wire->hdr, buflen,
					       h);
		if (ret != 0) {
			return ret;
		}
	}

	c->opcode = wire->opcode;
	c->pad = wire->pad;
	c->srvid = wire->srvid;
	c->client_id = wire->client_id;
	c->flags = wire->flags;

	ret = ctdb_req_control_data_pull(wire->data, wire->datalen,
					 c->opcode, mem_ctx, &c->rdata, &np);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

struct ctdb_reply_control_wire {
	struct ctdb_req_header hdr;
	int32_t status;
	uint32_t datalen;
	uint32_t errorlen;
	uint8_t data[1];
};

static size_t ctdb_reply_control_len_old(struct ctdb_req_header *h,
					 struct ctdb_reply_control *c)
{
	return offsetof(struct ctdb_reply_control_wire, data) +
		(c->status == 0 ?
			ctdb_reply_control_data_len(&c->rdata) :
			ctdb_string_len(&c->errmsg));
}

static int ctdb_reply_control_push_old(struct ctdb_req_header *h,
				       struct ctdb_reply_control *c,
				       uint8_t *buf, size_t *buflen)
{
	struct ctdb_reply_control_wire *wire =
		(struct ctdb_reply_control_wire *)buf;
	size_t length, np;

	length = ctdb_reply_control_len_old(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push_old(h, (uint8_t *)&wire->hdr);

	wire->status = c->status;

	if (c->status == 0) {
		wire->datalen = ctdb_reply_control_data_len(&c->rdata);
		wire->errorlen = 0;
		ctdb_reply_control_data_push(&c->rdata, wire->data, &np);
	} else {
		wire->datalen = 0;
		wire->errorlen = ctdb_string_len(&c->errmsg);
		ctdb_string_push(&c->errmsg, wire->data + wire->datalen, &np);
	}

	return 0;
}

static int ctdb_reply_control_pull_old(uint8_t *buf, size_t buflen,
				       uint32_t opcode,
				       struct ctdb_req_header *h,
				       TALLOC_CTX *mem_ctx,
				       struct ctdb_reply_control *c)
{
	struct ctdb_reply_control_wire *wire =
		(struct ctdb_reply_control_wire *)buf;
	size_t length, np;
	int ret;

	length = offsetof(struct ctdb_reply_control_wire, data);
	if (buflen < length) {
		return EMSGSIZE;
	}
	if (wire->datalen > buflen || wire->errorlen > buflen) {
		return EMSGSIZE;
	}
	if (length + wire->datalen < length) {
		return EMSGSIZE;
	}
	if (length + wire->datalen + wire->errorlen < length) {
		return EMSGSIZE;
	}
	if (buflen < length + wire->datalen + wire->errorlen) {
		return EMSGSIZE;
	}

	if (h != NULL) {
		ret = ctdb_req_header_pull_old((uint8_t *)&wire->hdr, buflen,
					       h);
		if (ret != 0) {
			return ret;
		}
	}

	c->status = wire->status;

	if (c->status != -1) {
		ret = ctdb_reply_control_data_pull(wire->data, wire->datalen,
						   opcode, mem_ctx,
						   &c->rdata, &np);
		if (ret != 0) {
			return ret;
		}
	}

	ret = ctdb_string_pull(wire->data + wire->datalen, wire->errorlen,
			       mem_ctx, &c->errmsg, &np);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

struct ctdb_req_message_wire {
	struct ctdb_req_header hdr;
	uint64_t srvid;
	uint32_t datalen;
	uint8_t data[1];
};

static size_t ctdb_req_message_len_old(struct ctdb_req_header *h,
				       struct ctdb_req_message *c)
{
	return offsetof(struct ctdb_req_message_wire, data) +
		ctdb_message_data_len(&c->data, c->srvid);
}

static int ctdb_req_message_push_old(struct ctdb_req_header *h,
				     struct ctdb_req_message *c,
				     uint8_t *buf, size_t *buflen)
{
	struct ctdb_req_message_wire *wire =
		(struct ctdb_req_message_wire *)buf;
	size_t length, np;

	length = ctdb_req_message_len_old(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push_old(h, (uint8_t *)&wire->hdr);

	wire->srvid = c->srvid;
	wire->datalen = ctdb_message_data_len(&c->data, c->srvid);
	ctdb_message_data_push(&c->data, c->srvid, wire->data, &np);

	return 0;
}

static int ctdb_req_message_pull_old(uint8_t *buf, size_t buflen,
				     struct ctdb_req_header *h,
				     TALLOC_CTX *mem_ctx,
				     struct ctdb_req_message *c)
{
	struct ctdb_req_message_wire *wire =
		(struct ctdb_req_message_wire *)buf;
	size_t length, np;
	int ret;

	length = offsetof(struct ctdb_req_message_wire, data);
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
		ret = ctdb_req_header_pull_old((uint8_t *)&wire->hdr, buflen,
					       h);
		if (ret != 0) {
			return ret;
		}
	}

	c->srvid = wire->srvid;
	ret = ctdb_message_data_pull(wire->data, wire->datalen, wire->srvid,
				     mem_ctx, &c->data, &np);
	return ret;
}

static size_t ctdb_req_message_data_len_old(struct ctdb_req_header *h,
					    struct ctdb_req_message_data *c)
{
	return offsetof(struct ctdb_req_message_wire, data) +
		ctdb_tdb_data_len(&c->data);
}

static int ctdb_req_message_data_push_old(struct ctdb_req_header *h,
					  struct ctdb_req_message_data *c,
					  uint8_t *buf, size_t *buflen)
{
	struct ctdb_req_message_wire *wire =
		(struct ctdb_req_message_wire *)buf;
	size_t length, np;

	length = ctdb_req_message_data_len_old(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push(h, (uint8_t *)&wire->hdr, &np);

	wire->srvid = c->srvid;
	wire->datalen = ctdb_tdb_data_len(&c->data);
	ctdb_tdb_data_push(&c->data, wire->data, &np);

	return 0;
}

static int ctdb_req_message_data_pull_old(uint8_t *buf, size_t buflen,
					  struct ctdb_req_header *h,
					  TALLOC_CTX *mem_ctx,
					  struct ctdb_req_message_data *c)
{
	struct ctdb_req_message_wire *wire =
		(struct ctdb_req_message_wire *)buf;
	size_t length, np;
	int ret;

	length = offsetof(struct ctdb_req_message_wire, data);
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
		ret = ctdb_req_header_pull_old((uint8_t *)&wire->hdr, buflen,
					       h);
		if (ret != 0) {
			return ret;
		}
	}

	c->srvid = wire->srvid;

	ret = ctdb_tdb_data_pull(wire->data, wire->datalen,
				 mem_ctx, &c->data, &np);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

struct ctdb_req_keepalive_wire {
	struct ctdb_req_header hdr;
	uint32_t version;
	uint32_t uptime;
};

static size_t ctdb_req_keepalive_len_old(struct ctdb_req_header *h,
					 struct ctdb_req_keepalive *c)
{
	return sizeof(struct ctdb_req_keepalive_wire);
}

static int ctdb_req_keepalive_push_old(struct ctdb_req_header *h,
				       struct ctdb_req_keepalive *c,
				       uint8_t *buf, size_t *buflen)
{
	struct ctdb_req_keepalive_wire *wire =
		(struct ctdb_req_keepalive_wire *)buf;
	size_t length;

	length = ctdb_req_keepalive_len_old(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push_old(h, (uint8_t *)&wire->hdr);

	wire->version = c->version;
	wire->uptime = c->uptime;

	return 0;
}

static int ctdb_req_keepalive_pull_old(uint8_t *buf, size_t buflen,
				       struct ctdb_req_header *h,
				       TALLOC_CTX *mem_ctx,
				       struct ctdb_req_keepalive *c)
{
	struct ctdb_req_keepalive_wire *wire =
		(struct ctdb_req_keepalive_wire *)buf;
	size_t length;
	int ret;

	length = sizeof(struct ctdb_req_keepalive_wire);
	if (buflen < length) {
		return EMSGSIZE;
	}

	if (h != NULL) {
		ret = ctdb_req_header_pull_old((uint8_t *)&wire->hdr, buflen,
					       h);
		if (ret != 0) {
			return ret;
		}
	}

	c->version = wire->version;
	c->uptime = wire->uptime;

	return 0;
}

struct ctdb_req_tunnel_wire {
	struct ctdb_req_header hdr;
	uint64_t tunnel_id;
	uint32_t flags;
	uint32_t datalen;
	uint8_t data[1];
};

static size_t ctdb_req_tunnel_len_old(struct ctdb_req_header *h,
				      struct ctdb_req_tunnel *c)
{
	return offsetof(struct ctdb_req_tunnel_wire, data) +
		ctdb_tdb_data_len(&c->data);
}

static int ctdb_req_tunnel_push_old(struct ctdb_req_header *h,
				    struct ctdb_req_tunnel *c,
				    uint8_t *buf, size_t *buflen)
{
	struct ctdb_req_tunnel_wire *wire =
		(struct ctdb_req_tunnel_wire *)buf;
	size_t length, np;

	length = ctdb_req_tunnel_len_old(h, c);
	if (*buflen < length) {
		*buflen = length;
		return EMSGSIZE;
	}

	h->length = *buflen;
	ctdb_req_header_push_old(h, (uint8_t *)&wire->hdr);

	wire->tunnel_id = c->tunnel_id;
	wire->flags = c->flags;
	wire->datalen = ctdb_tdb_data_len(&c->data);
	ctdb_tdb_data_push(&c->data, wire->data, &np);

	return 0;
}

static int ctdb_req_tunnel_pull_old(uint8_t *buf, size_t buflen,
				    struct ctdb_req_header *h,
				    TALLOC_CTX *mem_ctx,
				    struct ctdb_req_tunnel *c)
{
	struct ctdb_req_tunnel_wire *wire =
		(struct ctdb_req_tunnel_wire *)buf;
	size_t length, np;
	int ret;

	length = offsetof(struct ctdb_req_tunnel_wire, data);
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
		ret = ctdb_req_header_pull_old((uint8_t *)&wire->hdr, buflen,
					       h);
		if (ret != 0) {
			return ret;
		}
	}

	c->tunnel_id = wire->tunnel_id;
	c->flags = wire->flags;

	ret = ctdb_tdb_data_pull(wire->data, wire->datalen, mem_ctx, &c->data,
				 &np);
	if (ret != 0) {
		return ret;
	}

	return 0;
}


COMPAT_CTDB1_TEST(struct ctdb_req_header, ctdb_req_header);

COMPAT_CTDB4_TEST(struct ctdb_req_call, ctdb_req_call, CTDB_REQ_CALL);
COMPAT_CTDB4_TEST(struct ctdb_reply_call, ctdb_reply_call, CTDB_REPLY_CALL);
COMPAT_CTDB4_TEST(struct ctdb_reply_error, ctdb_reply_error, CTDB_REPLY_ERROR);
COMPAT_CTDB4_TEST(struct ctdb_req_dmaster, ctdb_req_dmaster, CTDB_REQ_DMASTER);
COMPAT_CTDB4_TEST(struct ctdb_reply_dmaster, ctdb_reply_dmaster, CTDB_REPLY_DMASTER);

COMPAT_CTDB5_TEST(struct ctdb_req_control, ctdb_req_control, CTDB_REQ_CONTROL);
COMPAT_CTDB6_TEST(struct ctdb_reply_control, ctdb_reply_control, CTDB_REPLY_CONTROL);

COMPAT_CTDB7_TEST(struct ctdb_req_message, ctdb_req_message, CTDB_REQ_MESSAGE);
COMPAT_CTDB4_TEST(struct ctdb_req_message_data, ctdb_req_message_data, CTDB_REQ_MESSAGE);

COMPAT_CTDB4_TEST(struct ctdb_req_keepalive, ctdb_req_keepalive, CTDB_REQ_KEEPALIVE);
COMPAT_CTDB4_TEST(struct ctdb_req_tunnel, ctdb_req_tunnel, CTDB_REQ_TUNNEL);

#define NUM_CONTROLS	151

int main(int argc, char *argv[])
{
	uint32_t opcode;
	uint64_t test_srvid[] = {
		CTDB_SRVID_BANNING,
		CTDB_SRVID_ELECTION,
		CTDB_SRVID_RECONFIGURE,
		CTDB_SRVID_RELEASE_IP,
		CTDB_SRVID_TAKE_IP,
		CTDB_SRVID_SET_NODE_FLAGS,
		CTDB_SRVID_RECD_UPDATE_IP,
		CTDB_SRVID_VACUUM_FETCH,
		CTDB_SRVID_DETACH_DATABASE,
		CTDB_SRVID_MEM_DUMP,
		CTDB_SRVID_GETLOG,
		CTDB_SRVID_CLEARLOG,
		CTDB_SRVID_PUSH_NODE_FLAGS,
		CTDB_SRVID_RELOAD_NODES,
		CTDB_SRVID_TAKEOVER_RUN,
		CTDB_SRVID_REBALANCE_NODE,
		CTDB_SRVID_DISABLE_TAKEOVER_RUNS,
		CTDB_SRVID_DISABLE_RECOVERIES,
		CTDB_SRVID_DISABLE_IP_CHECK,
	};
	unsigned int i;

	if (argc == 2) {
		int seed = atoi(argv[1]);
		srandom(seed);
	}

	COMPAT_TEST_FUNC(ctdb_req_header)();

	COMPAT_TEST_FUNC(ctdb_req_call)();
	COMPAT_TEST_FUNC(ctdb_reply_call)();
	COMPAT_TEST_FUNC(ctdb_reply_error)();
	COMPAT_TEST_FUNC(ctdb_req_dmaster)();
	COMPAT_TEST_FUNC(ctdb_reply_dmaster)();

	for (opcode=0; opcode<NUM_CONTROLS; opcode++) {
		COMPAT_TEST_FUNC(ctdb_req_control)(opcode);
	}
	for (opcode=0; opcode<NUM_CONTROLS; opcode++) {
		COMPAT_TEST_FUNC(ctdb_reply_control)(opcode);
	}

	for (i=0; i<ARRAY_SIZE(test_srvid); i++) {
		COMPAT_TEST_FUNC(ctdb_req_message)(test_srvid[i]);
	}
	COMPAT_TEST_FUNC(ctdb_req_message_data)();

	COMPAT_TEST_FUNC(ctdb_req_keepalive)();
	COMPAT_TEST_FUNC(ctdb_req_tunnel)();

	return 0;
}
