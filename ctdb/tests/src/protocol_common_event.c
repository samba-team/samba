/*
   protocol tests - eventd protocol

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
#include "system/network.h"

#include <assert.h>

#include "tests/src/protocol_common.h"
#include "tests/src/protocol_common_event.h"

/*
 * Functions to fill and verify eventd protocol structures
 */

void fill_ctdb_event_request_run(TALLOC_CTX *mem_ctx,
				 struct ctdb_event_request_run *p)
{
	p->event = rand_int(CTDB_EVENT_MAX);
	p->timeout = rand();
	fill_ctdb_string(mem_ctx, &p->arg_str);
}

void verify_ctdb_event_request_run(struct ctdb_event_request_run *p1,
				   struct ctdb_event_request_run *p2)
{
	assert(p1->event == p2->event);
	assert(p1->timeout == p2->timeout);
	verify_ctdb_string(&p1->arg_str, &p2->arg_str);
}

void fill_ctdb_event_request_status(TALLOC_CTX *mem_ctx,
				    struct ctdb_event_request_status *p)
{
	p->event = rand_int(CTDB_EVENT_MAX);
	p->state = rand_int(3) + 1;
}

void verify_ctdb_event_request_status(struct ctdb_event_request_status *p1,
				      struct ctdb_event_request_status *p2)
{
	assert(p1->event == p2->event);
	assert(p1->state == p2->state);
}

void fill_ctdb_event_request_script_enable(TALLOC_CTX *mem_ctx,
				struct ctdb_event_request_script_enable *p)
{
	fill_ctdb_string(mem_ctx, &p->script_name);
}

void verify_ctdb_event_request_script_enable(
				struct ctdb_event_request_script_enable *p1,
				struct ctdb_event_request_script_enable *p2)
{
	verify_ctdb_string(&p1->script_name, &p2->script_name);
}

void fill_ctdb_event_request_script_disable(TALLOC_CTX *mem_ctx,
				struct ctdb_event_request_script_disable *p)
{
	fill_ctdb_string(mem_ctx, &p->script_name);
}

void verify_ctdb_event_request_script_disable(
				struct ctdb_event_request_script_disable *p1,
				struct ctdb_event_request_script_disable *p2)
{
	verify_ctdb_string(&p1->script_name, &p2->script_name);
}

void fill_ctdb_event_reply_status(TALLOC_CTX *mem_ctx,
				  struct ctdb_event_reply_status *p)
{
	if (rand_int(2) == 0) {
		p->status = 0;
		p->script_list = talloc(mem_ctx, struct ctdb_script_list);
		assert(p->script_list != NULL);
		fill_ctdb_script_list(mem_ctx, p->script_list);
	} else {
		p->status = rand32i();
		p->script_list = NULL;
	}
}

void verify_ctdb_event_reply_status(struct ctdb_event_reply_status *p1,
				    struct ctdb_event_reply_status *p2)
{
	assert(p1->status == p2->status);
	if (p1->script_list == NULL) {
		assert(p1->script_list == p2->script_list);
	} else {
		verify_ctdb_script_list(p1->script_list, p2->script_list);
	}
}

void fill_ctdb_event_reply_script_list(TALLOC_CTX *mem_ctx,
				       struct ctdb_event_reply_script_list *p)
{
	p->script_list = talloc(mem_ctx, struct ctdb_script_list);
	assert(p->script_list != NULL);

	fill_ctdb_script_list(mem_ctx, p->script_list);
}

void verify_ctdb_event_reply_script_list(
				struct ctdb_event_reply_script_list *p1,
				struct ctdb_event_reply_script_list *p2)
{
	verify_ctdb_script_list(p1->script_list, p2->script_list);
}

void fill_ctdb_event_request_data(TALLOC_CTX *mem_ctx,
				  struct ctdb_event_request_data *r,
				  uint32_t command)
{
	r->command = command;

	switch (command) {
	case CTDB_EVENT_COMMAND_RUN:
		r->data.run = talloc(mem_ctx, struct ctdb_event_request_run);
		assert(r->data.run != NULL);

		fill_ctdb_event_request_run(mem_ctx, r->data.run);
		break;

	case CTDB_EVENT_COMMAND_STATUS:
		r->data.status = talloc(mem_ctx,
					struct ctdb_event_request_status);
		assert(r->data.status != NULL);

		fill_ctdb_event_request_status(mem_ctx, r->data.status);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_LIST:
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_ENABLE:
		r->data.script_enable = talloc(mem_ctx,
				struct ctdb_event_request_script_enable);
		assert(r->data.script_enable != NULL);

		fill_ctdb_event_request_script_enable(mem_ctx,
						      r->data.script_enable);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_DISABLE:
		r->data.script_disable = talloc(mem_ctx,
				struct ctdb_event_request_script_disable);
		assert(r->data.script_disable != NULL);

		fill_ctdb_event_request_script_disable(mem_ctx,
						       r->data.script_disable);
		break;
	}
}

void verify_ctdb_event_request_data(struct ctdb_event_request_data *r,
				    struct ctdb_event_request_data *r2)
{
	assert(r->command == r2->command);

	switch (r->command) {
	case CTDB_EVENT_COMMAND_RUN:
		verify_ctdb_event_request_run(r->data.run, r2->data.run);
		break;

	case CTDB_EVENT_COMMAND_STATUS:
		verify_ctdb_event_request_status(r->data.status,
						 r2->data.status);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_LIST:
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_ENABLE:
		verify_ctdb_event_request_script_enable(r->data.script_enable,
							r2->data.script_enable);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_DISABLE:
		verify_ctdb_event_request_script_disable(r->data.script_disable,
							 r2->data.script_disable);
		break;
	}
}

void fill_ctdb_event_reply_data(TALLOC_CTX *mem_ctx,
				struct ctdb_event_reply_data *r,
				uint32_t command)
{
	r->command = command;
	r->result = rand32i();

	switch (command) {
	case CTDB_EVENT_COMMAND_STATUS:
		r->data.status = talloc(mem_ctx,
					struct ctdb_event_reply_status);
		assert(r->data.status != NULL);

		fill_ctdb_event_reply_status(mem_ctx, r->data.status);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_LIST:
		r->data.script_list = talloc(mem_ctx,
				struct ctdb_event_reply_script_list);
		assert(r->data.script_list != NULL);

		fill_ctdb_event_reply_script_list(mem_ctx,
						  r->data.script_list);
		break;
	}
}

void verify_ctdb_event_reply_data(struct ctdb_event_reply_data *r,
				  struct ctdb_event_reply_data *r2)
{
	assert(r->command == r2->command);
	assert(r->result == r2->result);

	switch (r->command) {
	case CTDB_EVENT_COMMAND_RUN:
		break;

	case CTDB_EVENT_COMMAND_STATUS:
		verify_ctdb_event_reply_status(r->data.status,
					       r2->data.status);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_LIST:
		verify_ctdb_event_reply_script_list(r->data.script_list,
						    r2->data.script_list);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_ENABLE:
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_DISABLE:
		break;
	}
}

void fill_ctdb_event_request(TALLOC_CTX *mem_ctx,
			     struct ctdb_event_request *r, uint32_t command)
{
	fill_sock_packet_header(&r->header);
	fill_ctdb_event_request_data(mem_ctx, &r->rdata, command);
}

void verify_ctdb_event_request(struct ctdb_event_request *r,
			       struct ctdb_event_request *r2)
{
	verify_sock_packet_header(&r->header, &r2->header);
	verify_ctdb_event_request_data(&r->rdata, &r2->rdata);
}

void fill_ctdb_event_reply(TALLOC_CTX *mem_ctx, struct ctdb_event_reply *r,
			   uint32_t command)
{
	fill_sock_packet_header(&r->header);
	fill_ctdb_event_reply_data(mem_ctx, &r->rdata, command);
}

void verify_ctdb_event_reply(struct ctdb_event_reply *r,
			     struct ctdb_event_reply *r2)
{
	verify_sock_packet_header(&r->header, &r2->header);
	verify_ctdb_event_reply_data(&r->rdata, &r2->rdata);
}
