/*
   protocol types tests

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
#include "protocol/protocol_event.c"
#include "protocol/protocol_packet.c"
#include "protocol/protocol_sock.c"

#include "tests/src/protocol_common.h"
#include "tests/src/protocol_common_event.h"

#define REQID		0x34567890


/*
 * Functions to test eventd protocol marshalling
 */

/* for ctdb_event_request_data, ctdb_event_reply_data */
#define PROTOCOL_EVENT1_TEST(TYPE, NAME) \
static void TEST_FUNC(NAME)(uint32_t command) \
{ \
	TALLOC_CTX *mem_ctx; \
	TYPE c1, c2; \
	uint8_t *buf; \
	size_t buflen, np; \
	int ret; \
\
	printf("%s %u\n", #NAME, command); \
	fflush(stdout); \
	mem_ctx = talloc_new(NULL); \
	assert(mem_ctx != NULL); \
	FILL_FUNC(NAME)(mem_ctx, &c1, command); \
	buflen = LEN_FUNC(NAME)(&c1); \
	buf = talloc_size(mem_ctx, buflen); \
	assert(buf != NULL); \
	np = 0; \
	PUSH_FUNC(NAME)(&c1, buf, &np); \
	assert(np == buflen); \
	np = 0; \
	ret = PULL_FUNC(NAME)(buf, buflen, mem_ctx, &c2, &np); \
	assert(ret == 0); \
	assert(np == buflen); \
	VERIFY_FUNC(NAME)(&c1, &c2); \
	talloc_free(mem_ctx); \
}

#define PROTOCOL_EVENT2_TEST(TYPE, NAME) \
static void TEST_FUNC(NAME)(uint32_t command) \
{ \
	TALLOC_CTX *mem_ctx; \
	TYPE c1, c2; \
	uint8_t *buf; \
	size_t buflen, len; \
	int ret; \
\
	printf("%s %u\n", #NAME, command); \
	fflush(stdout); \
	mem_ctx = talloc_new(NULL); \
	assert(mem_ctx != NULL); \
	FILL_FUNC(NAME)(mem_ctx, &c1, command); \
	buflen = LEN_FUNC(NAME)(&c1); \
	buf = talloc_size(mem_ctx, buflen); \
	assert(buf != NULL); \
	len = 0; \
	ret = PUSH_FUNC(NAME)(&c1, buf, &len); \
	assert(ret == EMSGSIZE); \
	assert(len == buflen); \
	ret = PUSH_FUNC(NAME)(&c1, buf, &buflen); \
	assert(ret == 0); \
	ret = PULL_FUNC(NAME)(buf, buflen, mem_ctx, &c2); \
	assert(ret == 0); \
	assert(c2.header.length == buflen); \
	VERIFY_FUNC(NAME)(&c1, &c2); \
	talloc_free(mem_ctx); \
}

#define NUM_COMMANDS	5

PROTOCOL_TYPE3_TEST(struct ctdb_event_request_run, ctdb_event_request_run);
PROTOCOL_TYPE3_TEST(struct ctdb_event_request_status,
				ctdb_event_request_status);
PROTOCOL_TYPE3_TEST(struct ctdb_event_request_script_enable,
				ctdb_event_request_script_enable);
PROTOCOL_TYPE3_TEST(struct ctdb_event_request_script_disable,
				ctdb_event_request_script_disable);
PROTOCOL_TYPE3_TEST(struct ctdb_event_reply_status, ctdb_event_reply_status);
PROTOCOL_TYPE3_TEST(struct ctdb_event_reply_script_list,
				ctdb_event_reply_script_list);

PROTOCOL_EVENT1_TEST(struct ctdb_event_request_data, ctdb_event_request_data);
PROTOCOL_EVENT1_TEST(struct ctdb_event_reply_data, ctdb_event_reply_data);
PROTOCOL_EVENT2_TEST(struct ctdb_event_request, ctdb_event_request);
PROTOCOL_EVENT2_TEST(struct ctdb_event_reply, ctdb_event_reply);

int main(int argc, char *argv[])
{
	uint32_t command;

	if (argc == 2) {
		int seed = atoi(argv[1]);
		srandom(seed);
	}

	TEST_FUNC(ctdb_event_request_run)();
	TEST_FUNC(ctdb_event_request_status)();
	TEST_FUNC(ctdb_event_request_script_enable)();
	TEST_FUNC(ctdb_event_request_script_disable)();
	TEST_FUNC(ctdb_event_reply_status)();
	TEST_FUNC(ctdb_event_reply_script_list)();

	for (command=1; command<=NUM_COMMANDS; command++) {
		TEST_FUNC(ctdb_event_request_data)(command);
	}
	for (command=1; command<=NUM_COMMANDS; command++) {
		TEST_FUNC(ctdb_event_reply_data)(command);
	}

	for (command=1; command<=NUM_COMMANDS; command++) {
		TEST_FUNC(ctdb_event_request)(command);
	}
	for (command=1; command<=NUM_COMMANDS; command++) {
		TEST_FUNC(ctdb_event_reply)(command);
	}

	return 0;
}
