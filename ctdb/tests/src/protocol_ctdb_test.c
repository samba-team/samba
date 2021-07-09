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
#include "protocol/protocol_keepalive.c"
#include "protocol/protocol_tunnel.c"
#include "protocol/protocol_packet.c"

#include "tests/src/protocol_common.h"
#include "tests/src/protocol_common_ctdb.h"

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

#define NUM_CONTROLS	159

PROTOCOL_CTDB2_TEST(struct ctdb_req_control_data, ctdb_req_control_data);
PROTOCOL_CTDB2_TEST(struct ctdb_reply_control_data, ctdb_reply_control_data);

PROTOCOL_CTDB5_TEST(struct ctdb_req_control, ctdb_req_control,
			CTDB_REQ_CONTROL);
PROTOCOL_CTDB6_TEST(struct ctdb_reply_control, ctdb_reply_control,
			CTDB_REPLY_CONTROL);

PROTOCOL_CTDB3_TEST(union ctdb_message_data, ctdb_message_data);
PROTOCOL_CTDB7_TEST(struct ctdb_req_message, ctdb_req_message,
			CTDB_REQ_MESSAGE);
PROTOCOL_CTDB4_TEST(struct ctdb_req_message_data, ctdb_req_message_data,
			CTDB_REQ_MESSAGE);

PROTOCOL_CTDB4_TEST(struct ctdb_req_keepalive, ctdb_req_keepalive,
			CTDB_REQ_KEEPALIVE);
PROTOCOL_CTDB4_TEST(struct ctdb_req_tunnel, ctdb_req_tunnel, CTDB_REQ_TUNNEL);

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
	size_t i;

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
	for (opcode=0; opcode<NUM_CONTROLS; opcode++) {
		TEST_FUNC(ctdb_reply_control_data)(opcode);
	}

	for (opcode=0; opcode<NUM_CONTROLS; opcode++) {
		TEST_FUNC(ctdb_req_control)(opcode);
	}
	for (opcode=0; opcode<NUM_CONTROLS; opcode++) {
		TEST_FUNC(ctdb_reply_control)(opcode);
	}

	for (i=0; i<ARRAY_SIZE(test_srvid); i++) {
		TEST_FUNC(ctdb_message_data)(test_srvid[i]);
	}
	for (i=0; i<ARRAY_SIZE(test_srvid); i++) {
		TEST_FUNC(ctdb_req_message)(test_srvid[i]);
	}
	TEST_FUNC(ctdb_req_message_data)();

	TEST_FUNC(ctdb_req_keepalive)();
	TEST_FUNC(ctdb_req_tunnel)();

	return 0;
}
