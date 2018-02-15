/*
   CTDB event daemon - protocol test

   Copyright (C) Amitay Isaacs  2018

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

#include <talloc.h>
#include <assert.h>

#define EVENT_PROTOCOL_TEST
#include "event/event_protocol.c"

#include "tests/src/protocol_common_basic.h"

/*
 * Functions to fill and verify event protocol structures
 */

static void fill_ctdb_event_script(TALLOC_CTX *mem_ctx,
				   struct ctdb_event_script *p)
{
	fill_ctdb_stringn(mem_ctx, &p->name);
	fill_ctdb_timeval(&p->begin);
	fill_ctdb_timeval(&p->end);
	p->result = rand32i();
	fill_ctdb_stringn(mem_ctx, &p->output);
}

static void verify_ctdb_event_script(struct ctdb_event_script *p1,
				     struct ctdb_event_script *p2)
{
	verify_ctdb_stringn(&p1->name, &p2->name);
	verify_ctdb_timeval(&p1->begin, &p2->begin);
	verify_ctdb_timeval(&p1->end, &p2->end);
	assert(p1->result == p2->result);
	verify_ctdb_stringn(&p1->output, &p2->output);
}

static void fill_ctdb_event_script_list(TALLOC_CTX *mem_ctx,
					struct ctdb_event_script_list *p)
{
	int i;

	p->num_scripts = rand_int(32);
	if (p->num_scripts > 0) {
		p->script = talloc_array(mem_ctx,
					 struct ctdb_event_script,
					 p->num_scripts);
		assert(p->script != NULL);

		for (i=0; i<p->num_scripts; i++) {
			fill_ctdb_event_script(mem_ctx, &p->script[i]);
		}
	} else {
		p->script = NULL;
	}
}

static void verify_ctdb_event_script_list(struct ctdb_event_script_list *p1,
					  struct ctdb_event_script_list *p2)
{
	int i;

	assert(p1->num_scripts == p2->num_scripts);
	for (i=0; i<p1->num_scripts; i++) {
		verify_ctdb_event_script(&p1->script[i], &p2->script[i]);
	}
}

static void fill_ctdb_event_request_run(TALLOC_CTX *mem_ctx,
					struct ctdb_event_request_run *p)
{
	fill_ctdb_stringn(mem_ctx, &p->component);
	fill_ctdb_stringn(mem_ctx, &p->event);
	fill_ctdb_stringn(mem_ctx, &p->args);
	p->timeout = rand32();
	p->flags = rand32();
}

static void verify_ctdb_event_request_run(struct ctdb_event_request_run *p1,
					  struct ctdb_event_request_run *p2)
{
	verify_ctdb_stringn(&p1->component, &p2->component);
	verify_ctdb_stringn(&p1->event, &p2->event);
	verify_ctdb_stringn(&p1->args, &p2->args);
	assert(p1->timeout == p2->timeout);
	assert(p1->flags == p2->flags);
}

static void fill_ctdb_event_request_status(TALLOC_CTX *mem_ctx,
					   struct ctdb_event_request_status *p)
{
	fill_ctdb_stringn(mem_ctx, &p->component);
	fill_ctdb_stringn(mem_ctx, &p->event);
}

static void verify_ctdb_event_request_status(
					struct ctdb_event_request_status *p1,
					struct ctdb_event_request_status *p2)
{
	verify_ctdb_stringn(&p1->component, &p2->component);
	verify_ctdb_stringn(&p1->event, &p2->event);
}

static void fill_ctdb_event_request_script(TALLOC_CTX *mem_ctx,
					   struct ctdb_event_request_script *p)
{
	fill_ctdb_stringn(mem_ctx, &p->component);
	fill_ctdb_stringn(mem_ctx, &p->script);
	if (rand_int(1) == 0) {
		p->action = CTDB_EVENT_SCRIPT_DISABLE;
	} else {
		p->action = CTDB_EVENT_SCRIPT_ENABLE;
	}
}

static void fill_ctdb_event_reply_status(TALLOC_CTX *mem_ctx,
					 struct ctdb_event_reply_status *p)
{
	p->summary = rand32i();
	p->script_list = talloc(mem_ctx, struct ctdb_event_script_list);
	assert(p->script_list != NULL);

	fill_ctdb_event_script_list(mem_ctx, p->script_list);
}

static void verify_ctdb_event_reply_status(struct ctdb_event_reply_status *p1,
					   struct ctdb_event_reply_status *p2)
{
	assert(p1->summary == p2->summary);
	verify_ctdb_event_script_list(p1->script_list, p2->script_list);
}

static void verify_ctdb_event_request_script(
					struct ctdb_event_request_script *p1,
					struct ctdb_event_request_script *p2)
{
	verify_ctdb_stringn(&p1->component, &p2->component);
	verify_ctdb_stringn(&p1->script, &p2->script);
	assert(p1->action == p2->action);
}

static void fill_ctdb_event_request_data(TALLOC_CTX *mem_ctx,
					 struct ctdb_event_request *p,
					 uint32_t cmd)
{
	p->cmd = cmd;

	switch (cmd) {
	case CTDB_EVENT_CMD_RUN:
		p->data.run = talloc(mem_ctx, struct ctdb_event_request_run);
		assert(p->data.run != NULL);

		fill_ctdb_event_request_run(mem_ctx, p->data.run);
		break;

	case CTDB_EVENT_CMD_STATUS:
		p->data.status = talloc(mem_ctx,
					struct ctdb_event_request_status);
		assert(p->data.status != NULL);

		fill_ctdb_event_request_status(mem_ctx, p->data.status);
		break;

	case CTDB_EVENT_CMD_SCRIPT:
		p->data.script = talloc(mem_ctx,
					struct ctdb_event_request_script);
		assert(p->data.script != NULL);

		fill_ctdb_event_request_script(mem_ctx, p->data.script);
		break;

	default:
		assert(cmd > 0 && cmd < CTDB_EVENT_CMD_MAX);
	}
}

static void verify_ctdb_event_request_data(struct ctdb_event_request *p1,
					   struct ctdb_event_request *p2)
{
	assert(p1->cmd == p2->cmd);

	switch (p1->cmd) {
	case CTDB_EVENT_CMD_RUN:
		verify_ctdb_event_request_run(p1->data.run, p2->data.run);
		break;

	case CTDB_EVENT_CMD_STATUS:
		verify_ctdb_event_request_status(p1->data.status,
						 p2->data.status);
		break;

	case CTDB_EVENT_CMD_SCRIPT:
		verify_ctdb_event_request_script(p1->data.script,
						 p2->data.script);
		break;

	default:
		assert(p1->cmd > 0 && p1->cmd < CTDB_EVENT_CMD_MAX);
	}
}

static void fill_ctdb_event_reply_data(TALLOC_CTX *mem_ctx,
				       struct ctdb_event_reply *p,
				       uint32_t cmd)
{
	p->cmd = cmd;
	p->result = rand32i();

	if (p->result != 0) {
		return;
	}

	switch (cmd) {
	case CTDB_EVENT_CMD_STATUS:
		p->data.status = talloc(mem_ctx,
					struct ctdb_event_reply_status);
		assert(p->data.status != NULL);

		fill_ctdb_event_reply_status(mem_ctx, p->data.status);
		break;

	default:
		assert(cmd > 0 && cmd < CTDB_EVENT_CMD_MAX);
	}
}

static void verify_ctdb_event_reply_data(struct ctdb_event_reply *p1,
					 struct ctdb_event_reply *p2)
{
	assert(p1->cmd == p2->cmd);
	assert(p1->result == p2->result);

	if (p1->result != 0) {
		return;
	}

	switch (p1->cmd) {
	case CTDB_EVENT_CMD_STATUS:
		verify_ctdb_event_reply_status(p1->data.status,
					       p2->data.status);
		break;

	default:
		assert(p1->cmd > 0 && p1->cmd < CTDB_EVENT_CMD_MAX);
	}
}

static void fill_ctdb_event_header(struct ctdb_event_header *p)
{
	p->length = 0; /* updated by push functions */
	p->version = 0; /* updated by push functions */
	p->reqid = rand32();
}

static void verify_ctdb_event_header(struct ctdb_event_header *p1,
				     struct ctdb_event_header *p2)
{
	assert(p1->length == p2->length);
	assert(p1->version == p2->version);
	assert(p1->reqid == p2->reqid);
}

static void fill_ctdb_event_request(TALLOC_CTX *mem_ctx,
				    struct ctdb_event_request *p,
				    uint32_t cmd)
{
	fill_ctdb_event_request_data(mem_ctx, p, cmd);
}

static void verify_ctdb_event_request(struct ctdb_event_request *p1,
				      struct ctdb_event_request *p2)
{
	verify_ctdb_event_request_data(p1, p2);
}

static void fill_ctdb_event_reply(TALLOC_CTX *mem_ctx,
				  struct ctdb_event_reply *p,
				  uint32_t cmd)
{
	fill_ctdb_event_reply_data(mem_ctx, p, cmd);
}

static void verify_ctdb_event_reply(struct ctdb_event_reply *p1,
				    struct ctdb_event_reply *p2)
{
	verify_ctdb_event_reply_data(p1, p2);
}

#define EVENT_PROTOCOL1_TEST(TYPE, NAME) \
static void TEST_FUNC(NAME)(uint32_t cmd) \
{ \
	TALLOC_CTX *mem_ctx; \
	TYPE c1, *c2; \
	uint8_t *buf; \
	size_t buflen, np; \
	int ret; \
\
	printf("%s %u\n", #NAME, cmd); \
	fflush(stdout); \
	mem_ctx = talloc_new(NULL); \
	assert(mem_ctx != NULL); \
	FILL_FUNC(NAME)(mem_ctx, &c1, cmd); \
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
	VERIFY_FUNC(NAME)(&c1, c2); \
	talloc_free(mem_ctx); \
}

#define EVENT_PROTOCOL2_TEST(TYPE, NAME) \
static void TEST_FUNC(NAME)(uint32_t cmd) \
{ \
	TALLOC_CTX *mem_ctx; \
	struct ctdb_event_header h1, h2; \
	TYPE c1, *c2; \
	uint8_t *buf; \
	size_t buflen, len; \
	int ret; \
\
	printf("%s %u\n", #NAME, cmd); \
	fflush(stdout); \
	mem_ctx = talloc_new(NULL); \
	assert(mem_ctx != NULL); \
	fill_ctdb_event_header(&h1); \
	FILL_FUNC(NAME)(mem_ctx, &c1, cmd); \
	buflen = LEN_FUNC(NAME)(&h1, &c1); \
	buf = talloc_size(mem_ctx, buflen); \
	assert(buf != NULL); \
	len = 0; \
	ret = PUSH_FUNC(NAME)(&h1, &c1, buf, &len); \
	assert(ret == EMSGSIZE); \
	assert(len == buflen); \
	ret = PUSH_FUNC(NAME)(&h1, &c1, buf, &buflen); \
	assert(ret == 0); \
	ret = PULL_FUNC(NAME)(buf, buflen, &h2, mem_ctx, &c2); \
	assert(ret == 0); \
	verify_ctdb_event_header(&h1, &h2); \
	VERIFY_FUNC(NAME)(&c1, c2); \
	talloc_free(mem_ctx); \
}

PROTOCOL_TYPE3_TEST(struct ctdb_event_script, ctdb_event_script);
PROTOCOL_TYPE3_TEST(struct ctdb_event_script_list, ctdb_event_script_list);

PROTOCOL_TYPE3_TEST(struct ctdb_event_request_run, ctdb_event_request_run);
PROTOCOL_TYPE3_TEST(struct ctdb_event_request_status,
		    ctdb_event_request_status);
PROTOCOL_TYPE3_TEST(struct ctdb_event_request_script,
		    ctdb_event_request_script);

PROTOCOL_TYPE3_TEST(struct ctdb_event_reply_status, ctdb_event_reply_status);

EVENT_PROTOCOL1_TEST(struct ctdb_event_request, ctdb_event_request_data);
EVENT_PROTOCOL1_TEST(struct ctdb_event_reply, ctdb_event_reply_data);

EVENT_PROTOCOL2_TEST(struct ctdb_event_request, ctdb_event_request);
EVENT_PROTOCOL2_TEST(struct ctdb_event_reply, ctdb_event_reply);

int main(int argc, const char **argv)
{
	uint32_t cmd;

	if (argc == 2) {
		int seed = atoi(argv[1]);
		srandom(seed);
	}

	TEST_FUNC(ctdb_event_script)();
	TEST_FUNC(ctdb_event_script_list)();

	TEST_FUNC(ctdb_event_request_run)();
	TEST_FUNC(ctdb_event_request_status)();
	TEST_FUNC(ctdb_event_request_script)();

	TEST_FUNC(ctdb_event_reply_status)();

	for (cmd=1; cmd<CTDB_EVENT_CMD_MAX; cmd++) {
		TEST_FUNC(ctdb_event_request_data)(cmd);
	}
	for (cmd=1; cmd<CTDB_EVENT_CMD_MAX; cmd++) {
		TEST_FUNC(ctdb_event_reply_data)(cmd);
	}

	for (cmd=1; cmd<CTDB_EVENT_CMD_MAX; cmd++) {
		TEST_FUNC(ctdb_event_request)(cmd);
	}
	for (cmd=1; cmd<CTDB_EVENT_CMD_MAX; cmd++) {
		TEST_FUNC(ctdb_event_reply)(cmd);
	}

	return 0;
}
