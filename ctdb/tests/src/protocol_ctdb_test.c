/*
   protocol tests

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

#include <assert.h>

#include "protocol/protocol_basic.c"
#include "protocol/protocol_types.c"
#include "protocol/protocol_header.c"
#include "protocol/protocol_call.c"
#include "protocol/protocol_control.c"
#include "protocol/protocol_message.c"
#include "protocol/protocol_packet.c"

#include "tests/src/protocol_common.h"
#include "tests/src/protocol_common_ctdb.h"


#define GENERATION	0xabcdef12
#define OPERATION	CTDB_REQ_KEEPALIVE
#define REQID		0x34567890
#define SRCNODE		7
#define DESTNODE	13

/*
 * Functions to test marshalling
 */

/* for ctdb_req_header */
#define PROTOCOL_CTDB1_TEST(TYPE, NAME) \
static void TEST_FUNC(NAME)(void) \
{ \
	TALLOC_CTX *mem_ctx; \
	TYPE c1, c2; \
	uint8_t *pkt; \
	size_t pkt_len, buflen, np; \
	int ret; \
\
	printf("%s\n", #NAME); \
	fflush(stdout); \
	mem_ctx = talloc_new(NULL); \
	assert(mem_ctx != NULL); \
	FILL_FUNC(NAME)(&c1); \
	buflen = LEN_FUNC(NAME)(&c1); \
	ret = ctdb_allocate_pkt(mem_ctx, buflen, &pkt, &pkt_len); \
	assert(ret == 0); \
	assert(pkt != NULL); \
	assert(pkt_len >= buflen); \
	np = 0; \
	PUSH_FUNC(NAME)(&c1, pkt, &np); \
	assert(np == buflen); \
	np = 0; \
	ret = PULL_FUNC(NAME)(pkt, pkt_len, &c2, &np); \
	assert(ret == 0); \
	assert(np == buflen); \
	VERIFY_FUNC(NAME)(&c1, &c2); \
	talloc_free(mem_ctx); \
}

/* for ctdb_req_control_data, ctdb_reply_control_data */
#define PROTOCOL_CTDB2_TEST(TYPE, NAME) \
static void TEST_FUNC(NAME)(uint32_t opcode) \
{ \
	TALLOC_CTX *mem_ctx; \
	TYPE c1, c2; \
	uint8_t *pkt; \
	size_t pkt_len, buflen, np; \
	int ret; \
\
	printf("%s %u\n", #NAME, opcode); \
	fflush(stdout); \
	mem_ctx = talloc_new(NULL); \
	assert(mem_ctx != NULL); \
	FILL_FUNC(NAME)(mem_ctx, &c1, opcode); \
	buflen = LEN_FUNC(NAME)(&c1); \
	ret = ctdb_allocate_pkt(mem_ctx, buflen, &pkt, &pkt_len); \
	assert(ret == 0); \
	assert(pkt != NULL); \
	assert(pkt_len >= buflen); \
	np = 0; \
	PUSH_FUNC(NAME)(&c1, pkt, &np); \
	assert(np == buflen); \
	np = 0; \
	ret = PULL_FUNC(NAME)(pkt, pkt_len, opcode, mem_ctx, &c2, &np); \
	assert(ret == 0); \
	assert(np == buflen); \
	VERIFY_FUNC(NAME)(&c1, &c2); \
	talloc_free(mem_ctx); \
}

/* for ctdb_message_data */
#define PROTOCOL_CTDB3_TEST(TYPE, NAME) \
static void TEST_FUNC(NAME)(uint64_t srvid) \
{ \
	TALLOC_CTX *mem_ctx; \
	TYPE c1, c2; \
	uint8_t *pkt; \
	size_t pkt_len, buflen, np; \
	int ret; \
\
	printf("%s %"PRIx64"\n", #NAME, srvid); \
	fflush(stdout); \
	mem_ctx = talloc_new(NULL); \
	assert(mem_ctx != NULL); \
	FILL_FUNC(NAME)(mem_ctx, &c1, srvid); \
	buflen = LEN_FUNC(NAME)(&c1, srvid); \
	ret = ctdb_allocate_pkt(mem_ctx, buflen, &pkt, &pkt_len); \
	assert(ret == 0); \
	assert(pkt != NULL); \
	assert(pkt_len >= buflen); \
	np = 0; \
	PUSH_FUNC(NAME)(&c1, srvid, pkt, &np); \
	assert(np == buflen); \
	np = 0; \
	ret = PULL_FUNC(NAME)(pkt, pkt_len, srvid, mem_ctx, &c2, &np); \
	assert(ret == 0); \
	assert(np == buflen); \
	VERIFY_FUNC(NAME)(&c1, &c2, srvid); \
	talloc_free(mem_ctx); \
}

/* for ctdb_req_call, ctdb_reply_call, etc. */
#define PROTOCOL_CTDB4_TEST(TYPE, NAME, OPER) \
static void TEST_FUNC(NAME)(void) \
{ \
	TALLOC_CTX *mem_ctx; \
	struct ctdb_req_header h1, h2; \
	TYPE c1, c2; \
	uint8_t *pkt; \
	size_t pkt_len, buflen, len; \
	int ret; \
\
	printf("%s\n", #NAME); \
	fflush(stdout); \
	mem_ctx = talloc_new(NULL); \
	assert(mem_ctx != NULL); \
	fill_ctdb_req_header(&h1); \
	FILL_FUNC(NAME)(mem_ctx, &c1); \
	buflen = LEN_FUNC(NAME)(&h1, &c1); \
	ret = ctdb_allocate_pkt(mem_ctx, buflen, &pkt, &pkt_len); \
	assert(ret == 0); \
	assert(pkt != NULL); \
	assert(pkt_len >= buflen); \
	len = 0; \
	ret = PUSH_FUNC(NAME)(&h1, &c1, pkt, &len); \
	assert(ret == EMSGSIZE); \
	assert(len == buflen); \
	ret = PUSH_FUNC(NAME)(&h1, &c1, pkt, &pkt_len); \
	assert(ret == 0); \
	ret = PULL_FUNC(NAME)(pkt, pkt_len, &h2, mem_ctx, &c2); \
	assert(ret == 0); \
	verify_ctdb_req_header(&h1, &h2); \
	assert(h2.length == pkt_len); \
	VERIFY_FUNC(NAME)(&c1, &c2); \
	talloc_free(mem_ctx); \
}

/* for ctdb_req_control */
#define PROTOCOL_CTDB5_TEST(TYPE, NAME, OPER) \
static void TEST_FUNC(NAME)(uint32_t opcode) \
{ \
	TALLOC_CTX *mem_ctx; \
	struct ctdb_req_header h1, h2; \
	TYPE c1, c2; \
	uint8_t *pkt; \
	size_t pkt_len, buflen, len; \
	int ret; \
\
	printf("%s %u\n", #NAME, opcode); \
	fflush(stdout); \
	mem_ctx = talloc_new(NULL); \
	assert(mem_ctx != NULL); \
	fill_ctdb_req_header(&h1); \
	FILL_FUNC(NAME)(mem_ctx, &c1, opcode); \
	buflen = LEN_FUNC(NAME)(&h1, &c1); \
	ret = ctdb_allocate_pkt(mem_ctx, buflen, &pkt, &pkt_len); \
	assert(ret == 0); \
	assert(pkt != NULL); \
	assert(pkt_len >= buflen); \
	len = 0; \
	ret = PUSH_FUNC(NAME)(&h1, &c1, pkt, &len); \
	assert(ret == EMSGSIZE); \
	assert(len == buflen); \
	ret = PUSH_FUNC(NAME)(&h1, &c1, pkt, &pkt_len); \
	assert(ret == 0); \
	ret = PULL_FUNC(NAME)(pkt, pkt_len, &h2, mem_ctx, &c2); \
	assert(ret == 0); \
	verify_ctdb_req_header(&h1, &h2); \
	assert(h2.length == pkt_len); \
	VERIFY_FUNC(NAME)(&c1, &c2); \
	talloc_free(mem_ctx); \
}

/* for ctdb_reply_control */
#define PROTOCOL_CTDB6_TEST(TYPE, NAME, OPER) \
static void TEST_FUNC(NAME)(uint32_t opcode) \
{ \
	TALLOC_CTX *mem_ctx; \
	struct ctdb_req_header h1, h2; \
	TYPE c1, c2; \
	uint8_t *pkt; \
	size_t pkt_len, buflen, len; \
	int ret; \
\
	printf("%s %u\n", #NAME, opcode); \
	fflush(stdout); \
	mem_ctx = talloc_new(NULL); \
	assert(mem_ctx != NULL); \
	fill_ctdb_req_header(&h1); \
	FILL_FUNC(NAME)(mem_ctx, &c1, opcode); \
	buflen = LEN_FUNC(NAME)(&h1, &c1); \
	ret = ctdb_allocate_pkt(mem_ctx, buflen, &pkt, &pkt_len); \
	assert(ret == 0); \
	assert(pkt != NULL); \
	assert(pkt_len >= buflen); \
	len = 0; \
	ret = PUSH_FUNC(NAME)(&h1, &c1, pkt, &len); \
	assert(ret == EMSGSIZE); \
	assert(len == buflen); \
	ret = PUSH_FUNC(NAME)(&h1, &c1, pkt, &pkt_len); \
	assert(ret == 0); \
	ret = PULL_FUNC(NAME)(pkt, pkt_len, opcode, &h2, mem_ctx, &c2); \
	assert(ret == 0); \
	verify_ctdb_req_header(&h1, &h2); \
	assert(h2.length == pkt_len); \
	VERIFY_FUNC(NAME)(&c1, &c2); \
	talloc_free(mem_ctx); \
}

/* for ctdb_req_message */
#define PROTOCOL_CTDB7_TEST(TYPE, NAME, OPER) \
static void TEST_FUNC(NAME)(uint64_t srvid) \
{ \
	TALLOC_CTX *mem_ctx; \
	struct ctdb_req_header h1, h2; \
	TYPE c1, c2; \
	uint8_t *pkt; \
	size_t pkt_len, buflen, len; \
	int ret; \
\
	printf("%s %"PRIx64"\n", #NAME, srvid); \
	fflush(stdout); \
	mem_ctx = talloc_new(NULL); \
	assert(mem_ctx != NULL); \
	fill_ctdb_req_header(&h1); \
	FILL_FUNC(NAME)(mem_ctx, &c1, srvid); \
	buflen = LEN_FUNC(NAME)(&h1, &c1); \
	ret = ctdb_allocate_pkt(mem_ctx, buflen, &pkt, &pkt_len); \
	assert(ret == 0); \
	assert(pkt != NULL); \
	assert(pkt_len >= buflen); \
	len = 0; \
	ret = PUSH_FUNC(NAME)(&h1, &c1, pkt, &len); \
	assert(ret == EMSGSIZE); \
	assert(len == buflen); \
	ret = PUSH_FUNC(NAME)(&h1, &c1, pkt, &pkt_len); \
	assert(ret == 0); \
	ret = PULL_FUNC(NAME)(pkt, pkt_len, &h2, mem_ctx, &c2); \
	assert(ret == 0); \
	verify_ctdb_req_header(&h1, &h2); \
	assert(h2.length == pkt_len); \
	VERIFY_FUNC(NAME)(&c1, &c2); \
	talloc_free(mem_ctx); \
}

PROTOCOL_CTDB1_TEST(struct ctdb_req_header, ctdb_req_header);

PROTOCOL_CTDB4_TEST(struct ctdb_req_call, ctdb_req_call, CTDB_REQ_CALL);
PROTOCOL_CTDB4_TEST(struct ctdb_reply_call, ctdb_reply_call, CTDB_REPLY_CALL);
PROTOCOL_CTDB4_TEST(struct ctdb_reply_error, ctdb_reply_error,
			CTDB_REPLY_ERROR);
PROTOCOL_CTDB4_TEST(struct ctdb_req_dmaster, ctdb_req_dmaster,
			CTDB_REQ_DMASTER);
PROTOCOL_CTDB4_TEST(struct ctdb_reply_dmaster, ctdb_reply_dmaster,
			CTDB_REPLY_DMASTER);

#define NUM_CONTROLS	151

PROTOCOL_CTDB2_TEST(struct ctdb_req_control_data, ctdb_req_control_data);

static void test_ctdb_reply_control_data(void)
{
	TALLOC_CTX *mem_ctx;
	size_t buflen;
	int ret;
	struct ctdb_reply_control_data cd, cd2;
	uint32_t opcode;

	printf("ctdb_reply_control_data\n");
	fflush(stdout);

	for (opcode=0; opcode<NUM_CONTROLS; opcode++) {
		mem_ctx = talloc_new(NULL);
		assert(mem_ctx != NULL);

		printf("%u.. ", opcode);
		fflush(stdout);
		fill_ctdb_reply_control_data(mem_ctx, &cd, opcode);
		buflen = ctdb_reply_control_data_len(&cd);
		ctdb_reply_control_data_push(&cd, BUFFER);
		ret = ctdb_reply_control_data_pull(BUFFER, buflen, opcode, mem_ctx, &cd2);
		assert(ret == 0);
		verify_ctdb_reply_control_data(&cd, &cd2);
		talloc_free(mem_ctx);
	}

	printf("\n");
	fflush(stdout);
}

static void test_ctdb_req_control(void)
{
	TALLOC_CTX *mem_ctx;
	uint8_t *pkt;
	size_t datalen, pkt_len, len;
	int ret;
	struct ctdb_req_header h, h2;
	struct ctdb_req_control c, c2;
	uint32_t opcode;

	printf("ctdb_req_control\n");
	fflush(stdout);

	ctdb_req_header_fill(&h, GENERATION, CTDB_REQ_CONTROL,
			     DESTNODE, SRCNODE, REQID);

	for (opcode=0; opcode<NUM_CONTROLS; opcode++) {
		mem_ctx = talloc_new(NULL);
		assert(mem_ctx != NULL);

		printf("%u.. ", opcode);
		fflush(stdout);
		fill_ctdb_req_control(mem_ctx, &c, opcode);
		datalen = ctdb_req_control_len(&h, &c);
		ret = ctdb_allocate_pkt(mem_ctx, datalen, &pkt, &pkt_len);
		assert(ret == 0);
		assert(pkt != NULL);
		assert(pkt_len >= datalen);
		len = 0;
		ret = ctdb_req_control_push(&h, &c, pkt, &len);
		assert(ret == EMSGSIZE);
		assert(len == datalen);
		ret = ctdb_req_control_push(&h, &c, pkt, &pkt_len);
		assert(ret == 0);
		ret = ctdb_req_control_pull(pkt, pkt_len, &h2, mem_ctx, &c2);
		assert(ret == 0);
		verify_ctdb_req_header(&h, &h2);
		assert(h2.length == pkt_len);
		verify_ctdb_req_control(&c, &c2);

		talloc_free(mem_ctx);
	}

	printf("\n");
	fflush(stdout);
}

static void test_ctdb_reply_control(void)
{
	TALLOC_CTX *mem_ctx;
	uint8_t *pkt;
	size_t datalen, pkt_len, len;
	int ret;
	struct ctdb_req_header h, h2;
	struct ctdb_reply_control c, c2;
	uint32_t opcode;

	printf("ctdb_reply_control\n");
	fflush(stdout);

	ctdb_req_header_fill(&h, GENERATION, CTDB_REPLY_CONTROL,
			     DESTNODE, SRCNODE, REQID);

	for (opcode=0; opcode<NUM_CONTROLS; opcode++) {
		mem_ctx = talloc_new(NULL);
		assert(mem_ctx != NULL);

		printf("%u.. ", opcode);
		fflush(stdout);
		fill_ctdb_reply_control(mem_ctx, &c, opcode);
		datalen = ctdb_reply_control_len(&h, &c);
		ret = ctdb_allocate_pkt(mem_ctx, datalen, &pkt, &pkt_len);
		assert(ret == 0);
		assert(pkt != NULL);
		assert(pkt_len >= datalen);
		len = 0;
		ret = ctdb_reply_control_push(&h, &c, pkt, &len);
		assert(ret == EMSGSIZE);
		assert(len == datalen);
		ret = ctdb_reply_control_push(&h, &c, pkt, &pkt_len);
		assert(ret == 0);
		ret = ctdb_reply_control_pull(pkt, pkt_len, opcode, &h2, mem_ctx, &c2);
		assert(ret == 0);
		verify_ctdb_req_header(&h, &h2);
		assert(h2.length == pkt_len);
		verify_ctdb_reply_control(&c, &c2);

		talloc_free(mem_ctx);
	}

	printf("\n");
	fflush(stdout);
}

static void test_ctdb_req_message_data(void)
{
	TALLOC_CTX *mem_ctx;
	uint8_t *pkt;
	size_t datalen, pkt_len, len;
	int ret;
	struct ctdb_req_header h, h2;
	struct ctdb_req_message_data c, c2;

	printf("ctdb_req_message\n");
	fflush(stdout);

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ctdb_req_header_fill(&h, GENERATION, CTDB_REQ_MESSAGE,
			     DESTNODE, SRCNODE, REQID);

	fill_ctdb_req_message_data(mem_ctx, &c);
	datalen = ctdb_req_message_data_len(&h, &c);
	ret = ctdb_allocate_pkt(mem_ctx, datalen, &pkt, &pkt_len);
	assert(ret == 0);
	assert(pkt != NULL);
	assert(pkt_len >= datalen);
	len = 0;
	ret = ctdb_req_message_data_push(&h, &c, pkt, &len);
	assert(ret == EMSGSIZE);
	assert(len == datalen);
	ret = ctdb_req_message_data_push(&h, &c, pkt, &pkt_len);
	assert(ret == 0);
	ret = ctdb_req_message_data_pull(pkt, pkt_len, &h2, mem_ctx, &c2);
	assert(ret == 0);
	verify_ctdb_req_header(&h, &h2);
	assert(h2.length == pkt_len);
	verify_ctdb_req_message_data(&c, &c2);

	talloc_free(mem_ctx);
}

int main(int argc, char *argv[])
{
	uint32_t opcode;

	if (argc == 2) {
		int seed = atoi(argv[1]);
		srandom(seed);
	}

	TEST_FUNC(ctdb_req_header)();

	TEST_FUNC(ctdb_req_call)();
	TEST_FUNC(ctdb_reply_call)();
	TEST_FUNC(ctdb_reply_error)();
	TEST_FUNC(ctdb_req_dmaster)();
	TEST_FUNC(ctdb_reply_dmaster)();

	for (opcode=0; opcode<NUM_CONTROLS; opcode++) {
		TEST_FUNC(ctdb_req_control_data)(opcode);
	}
	test_ctdb_reply_control_data();

	test_ctdb_req_control();
	test_ctdb_reply_control();

	test_ctdb_req_message_data();

	return 0;
}
