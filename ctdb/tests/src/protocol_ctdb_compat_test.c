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


COMPAT_CTDB1_TEST(struct ctdb_req_header, ctdb_req_header);

COMPAT_CTDB4_TEST(struct ctdb_req_call, ctdb_req_call, CTDB_REQ_CALL);
COMPAT_CTDB4_TEST(struct ctdb_reply_call, ctdb_reply_call, CTDB_REPLY_CALL);
COMPAT_CTDB4_TEST(struct ctdb_reply_error, ctdb_reply_error, CTDB_REPLY_ERROR);
COMPAT_CTDB4_TEST(struct ctdb_req_dmaster, ctdb_req_dmaster, CTDB_REQ_DMASTER);
COMPAT_CTDB4_TEST(struct ctdb_reply_dmaster, ctdb_reply_dmaster, CTDB_REPLY_DMASTER);

int main(int argc, char *argv[])
{
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

	return 0;
}
