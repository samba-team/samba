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

static void test_ctdb_req_header(void)
{
	TALLOC_CTX *mem_ctx;
	uint8_t *pkt;
	size_t pkt_len;
	struct ctdb_req_header h, h2;
	int ret;

	printf("ctdb_req_header\n");
	fflush(stdout);

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ctdb_req_header_fill(&h, GENERATION, OPERATION, DESTNODE, SRCNODE,
			     REQID);

	ret = ctdb_allocate_pkt(mem_ctx, ctdb_req_header_len(&h),
				&pkt, &pkt_len);
	assert(ret == 0);
	assert(pkt != NULL);
	assert(pkt_len >= ctdb_req_header_len(&h));

	ctdb_req_header_push(&h, pkt);

	ret = ctdb_req_header_pull(pkt, pkt_len, &h2);
	assert(ret == 0);

	verify_ctdb_req_header(&h, &h2);

	talloc_free(mem_ctx);
}

static void test_ctdb_req_call(void)
{
	TALLOC_CTX *mem_ctx;
	uint8_t *pkt;
	size_t datalen, pkt_len, len;
	int ret;
	struct ctdb_req_header h, h2;
	struct ctdb_req_call c, c2;

	printf("ctdb_req_call\n");
	fflush(stdout);

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ctdb_req_header_fill(&h, GENERATION, CTDB_REQ_CALL,
			     DESTNODE, SRCNODE, REQID);

	fill_ctdb_req_call(mem_ctx, &c);
	datalen = ctdb_req_call_len(&h, &c);
	ret = ctdb_allocate_pkt(mem_ctx, datalen, &pkt, &pkt_len);
	assert(ret == 0);
	assert(pkt != NULL);
	assert(pkt_len >= datalen);
	len = 0;
	ret = ctdb_req_call_push(&h, &c, pkt, &len);
	assert(ret == EMSGSIZE);
	assert(len == datalen);
	ret = ctdb_req_call_push(&h, &c, pkt, &pkt_len);
	assert(ret == 0);
	ret = ctdb_req_call_pull(pkt, pkt_len, &h2, mem_ctx, &c2);
	assert(ret == 0);
	verify_ctdb_req_header(&h, &h2);
	assert(h2.length == pkt_len);
	verify_ctdb_req_call(&c, &c2);

	talloc_free(mem_ctx);
}

static void test_ctdb_reply_call(void)
{
	TALLOC_CTX *mem_ctx;
	uint8_t *pkt;
	size_t datalen, pkt_len, len;
	int ret;
	struct ctdb_req_header h, h2;
	struct ctdb_reply_call c, c2;

	printf("ctdb_reply_call\n");
	fflush(stdout);

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ctdb_req_header_fill(&h, GENERATION, CTDB_REPLY_CALL,
			     DESTNODE, SRCNODE, REQID);

	fill_ctdb_reply_call(mem_ctx, &c);
	datalen = ctdb_reply_call_len(&h, &c);
	ret = ctdb_allocate_pkt(mem_ctx, datalen, &pkt, &pkt_len);
	assert(ret == 0);
	assert(pkt != NULL);
	assert(pkt_len >= datalen);
	len = 0;
	ret = ctdb_reply_call_push(&h, &c, pkt, &len);
	assert(ret == EMSGSIZE);
	assert(len == datalen);
	ret = ctdb_reply_call_push(&h, &c, pkt, &pkt_len);
	assert(ret == 0);
	ret = ctdb_reply_call_pull(pkt, pkt_len, &h2, mem_ctx, &c2);
	assert(ret == 0);
	verify_ctdb_req_header(&h, &h2);
	assert(h2.length == pkt_len);
	verify_ctdb_reply_call(&c, &c2);

	talloc_free(mem_ctx);
}

static void test_ctdb_reply_error(void)
{
	TALLOC_CTX *mem_ctx;
	uint8_t *pkt;
	size_t datalen, pkt_len, len;
	int ret;
	struct ctdb_req_header h, h2;
	struct ctdb_reply_error c, c2;

	printf("ctdb_reply_error\n");
	fflush(stdout);

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ctdb_req_header_fill(&h, GENERATION, CTDB_REPLY_ERROR,
			     DESTNODE, SRCNODE, REQID);

	fill_ctdb_reply_error(mem_ctx, &c);
	datalen = ctdb_reply_error_len(&h, &c);
	ret = ctdb_allocate_pkt(mem_ctx, datalen, &pkt, &pkt_len);
	assert(ret == 0);
	assert(pkt != NULL);
	assert(pkt_len >= datalen);
	len = 0;
	ret = ctdb_reply_error_push(&h, &c, pkt, &len);
	assert(ret == EMSGSIZE);
	assert(len == datalen);
	ret = ctdb_reply_error_push(&h, &c, pkt, &pkt_len);
	assert(ret == 0);
	ret = ctdb_reply_error_pull(pkt, pkt_len, &h2, mem_ctx, &c2);
	assert(ret == 0);
	verify_ctdb_req_header(&h, &h2);
	assert(h2.length == pkt_len);
	verify_ctdb_reply_error(&c, &c2);

	talloc_free(mem_ctx);
}

static void test_ctdb_req_dmaster(void)
{
	TALLOC_CTX *mem_ctx;
	uint8_t *pkt;
	size_t datalen, pkt_len, len;
	int ret;
	struct ctdb_req_header h, h2;
	struct ctdb_req_dmaster c, c2;

	printf("ctdb_req_dmaster\n");
	fflush(stdout);

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ctdb_req_header_fill(&h, GENERATION, CTDB_REQ_DMASTER,
			     DESTNODE, SRCNODE, REQID);

	fill_ctdb_req_dmaster(mem_ctx, &c);
	datalen = ctdb_req_dmaster_len(&h, &c);
	ret = ctdb_allocate_pkt(mem_ctx, datalen, &pkt, &pkt_len);
	assert(ret == 0);
	assert(pkt != NULL);
	assert(pkt_len >= datalen);
	len = 0;
	ret = ctdb_req_dmaster_push(&h, &c, pkt, &len);
	assert(ret == EMSGSIZE);
	assert(len == datalen);
	ret = ctdb_req_dmaster_push(&h, &c, pkt, &pkt_len);
	assert(ret == 0);
	ret = ctdb_req_dmaster_pull(pkt, pkt_len, &h2, mem_ctx, &c2);
	assert(ret == 0);
	verify_ctdb_req_header(&h, &h2);
	assert(h2.length == pkt_len);
	verify_ctdb_req_dmaster(&c, &c2);

	talloc_free(mem_ctx);
}

static void test_ctdb_reply_dmaster(void)
{
	TALLOC_CTX *mem_ctx;
	uint8_t *pkt;
	size_t datalen, pkt_len, len;
	int ret;
	struct ctdb_req_header h, h2;
	struct ctdb_reply_dmaster c, c2;

	printf("ctdb_reply_dmaster\n");
	fflush(stdout);

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ctdb_req_header_fill(&h, GENERATION, CTDB_REPLY_DMASTER,
			     DESTNODE, SRCNODE, REQID);

	fill_ctdb_reply_dmaster(mem_ctx, &c);
	datalen = ctdb_reply_dmaster_len(&h, &c);
	ret = ctdb_allocate_pkt(mem_ctx, datalen, &pkt, &pkt_len);
	assert(ret == 0);
	assert(pkt != NULL);
	assert(pkt_len >= datalen);
	len = 0;
	ret = ctdb_reply_dmaster_push(&h, &c, pkt, &len);
	assert(ret == EMSGSIZE);
	assert(len == datalen);
	ret = ctdb_reply_dmaster_push(&h, &c, pkt, &pkt_len);
	assert(ret == 0);
	ret = ctdb_reply_dmaster_pull(pkt, pkt_len, &h2, mem_ctx, &c2);
	assert(ret == 0);
	verify_ctdb_req_header(&h, &h2);
	assert(h2.length == pkt_len);
	verify_ctdb_reply_dmaster(&c, &c2);

	talloc_free(mem_ctx);
}

#define NUM_CONTROLS	151

static void test_ctdb_req_control_data(void)
{
	TALLOC_CTX *mem_ctx;
	size_t buflen;
	int ret;
	struct ctdb_req_control_data cd, cd2;
	uint32_t opcode;

	printf("ctdb_req_control_data\n");
	fflush(stdout);

	for (opcode=0; opcode<NUM_CONTROLS; opcode++) {
		mem_ctx = talloc_new(NULL);
		assert(mem_ctx != NULL);

		printf("%u.. ", opcode);
		fflush(stdout);
		fill_ctdb_req_control_data(mem_ctx, &cd, opcode);
		buflen = ctdb_req_control_data_len(&cd);
		ctdb_req_control_data_push(&cd, BUFFER);
		ret = ctdb_req_control_data_pull(BUFFER, buflen, opcode, mem_ctx, &cd2);
		assert(ret == 0);
		verify_ctdb_req_control_data(&cd, &cd2);
		talloc_free(mem_ctx);
	}

	printf("\n");
	fflush(stdout);
}

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
	if (argc == 2) {
		int seed = atoi(argv[1]);
		srandom(seed);
	}

	test_ctdb_req_header();

	test_ctdb_req_call();
	test_ctdb_reply_call();
	test_ctdb_reply_error();
	test_ctdb_req_dmaster();
	test_ctdb_reply_dmaster();

	test_ctdb_req_control_data();
	test_ctdb_reply_control_data();

	test_ctdb_req_control();
	test_ctdb_reply_control();

	test_ctdb_req_message_data();

	return 0;
}
