/* 
   Unix SMB/CIFS implementation.

   local test for irpc code

   Copyright (C) Andrew Tridgell 2004
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "lib/events/events.h"
#include "lib/messaging/irpc.h"
#include "librpc/gen_ndr/ndr_echo.h"

const uint32_t MSG_ID1 = 1, MSG_ID2 = 2;

static BOOL test_debug;

/*
  serve up AddOne over the irpc system
*/
static NTSTATUS irpc_AddOne(struct irpc_message *irpc, struct echo_AddOne *r)
{
	*r->out.out_data = r->in.in_data + 1;
	if (test_debug) {
		printf("irpc_AddOne: in=%u in+1=%u out=%u\n", 
			r->in.in_data, r->in.in_data+1, *r->out.out_data);
	}
	return NT_STATUS_OK;
}

/*
  a deferred reply to echodata
*/
static void deferred_echodata(struct event_context *ev, struct timed_event *te, 
			      struct timeval t, void *private)
{
	struct irpc_message *irpc = talloc_get_type(private, struct irpc_message);
	struct echo_EchoData *r = irpc->data;
	r->out.out_data = talloc_memdup(r, r->in.in_data, r->in.len);
	if (r->out.out_data == NULL) {
		irpc_send_reply(irpc, NT_STATUS_NO_MEMORY);
	}
	printf("sending deferred reply\n");
	irpc_send_reply(irpc, NT_STATUS_OK);
}


/*
  serve up EchoData over the irpc system
*/
static NTSTATUS irpc_EchoData(struct irpc_message *irpc, struct echo_EchoData *r)
{
	irpc->defer_reply = True;
	event_add_timed(irpc->ev, irpc, timeval_zero(), deferred_echodata, irpc);
	return NT_STATUS_OK;
}


/*
  test a addone call over the internal messaging system
*/
static BOOL test_addone(TALLOC_CTX *mem_ctx, 
			struct messaging_context *msg_ctx1,
			struct messaging_context *msg_ctx2,
			uint32_t value)
{
	struct echo_AddOne r;
	NTSTATUS status;

	/* make the call */
	r.in.in_data = value;

	test_debug = True;
	status = IRPC_CALL(msg_ctx1, MSG_ID2, rpcecho, ECHO_ADDONE, &r, mem_ctx);
	test_debug = False;
	if (!NT_STATUS_IS_OK(status)) {
		printf("AddOne failed - %s\n", nt_errstr(status));
		return False;
	}

	/* check the answer */
	if (*r.out.out_data != r.in.in_data + 1) {
		printf("AddOne wrong answer - %u + 1 = %u should be %u\n", 
		       r.in.in_data, *r.out.out_data, r.in.in_data+1);
		return False;
	}

	printf("%u + 1 = %u\n", r.in.in_data, *r.out.out_data);

	return True;	
}

/*
  test a echodata call over the internal messaging system
*/
static BOOL test_echodata(TALLOC_CTX *mem_ctx, 
			  struct messaging_context *msg_ctx1,
			  struct messaging_context *msg_ctx2)
{
	struct echo_EchoData r;
	NTSTATUS status;

	/* make the call */
	r.in.in_data = (unsigned char *)talloc_strdup(mem_ctx, "0123456789");
	r.in.len = strlen((char *)r.in.in_data);

	status = IRPC_CALL(msg_ctx1, MSG_ID2, rpcecho, ECHO_ECHODATA, &r, mem_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EchoData failed - %s\n", nt_errstr(status));
		return False;
	}

	/* check the answer */
	if (memcmp(r.out.out_data, r.in.in_data, r.in.len) != 0) {
		printf("EchoData wrong answer\n");
		NDR_PRINT_OUT_DEBUG(echo_EchoData, &r);
		return False;
	}

	printf("Echo '%*.*s' -> '%*.*s'\n", 
	       r.in.len, r.in.len,
	       r.in.in_data,
	       r.in.len, r.in.len,
	       r.out.out_data);

	return True;	
}


static void irpc_callback(struct irpc_request *irpc)
{
	struct echo_AddOne *r = irpc->r;
	int *pong_count = (int *)irpc->async.private;
	NTSTATUS status = irpc_call_recv(irpc);
	if (!NT_STATUS_IS_OK(status)) {
		printf("irpc call failed - %s\n", nt_errstr(status));
	}
	if (*r->out.out_data != r->in.in_data + 1) {
		printf("AddOne wrong answer - %u + 1 = %u should be %u\n", 
		       r->in.in_data, *r->out.out_data, r->in.in_data+1);
	}
	(*pong_count)++;
}

/*
  test echo speed
*/
static BOOL test_speed(TALLOC_CTX *mem_ctx, 
		       struct messaging_context *msg_ctx1,
		       struct messaging_context *msg_ctx2,
		       struct event_context *ev)
{
	int ping_count = 0;
	int pong_count = 0;
	BOOL ret = True;
	struct timeval tv;
	struct echo_AddOne r;
	int timelimit = lp_parm_int(-1, "torture", "timelimit", 10);

	tv = timeval_current();

	r.in.in_data = 0;

	printf("Sending echo for %d seconds\n", timelimit);
	while (timeval_elapsed(&tv) < timelimit) {
		struct irpc_request *irpc;

		irpc = IRPC_CALL_SEND(msg_ctx1, MSG_ID2, rpcecho, ECHO_ADDONE, &r, mem_ctx);
		if (irpc == NULL) {
			printf("AddOne send failed\n");
			return False;
		}

		irpc->async.fn = irpc_callback;
		irpc->async.private = &pong_count;

		ping_count++;

		while (ping_count > pong_count + 20) {
			event_loop_once(ev);
		}
	}

	printf("waiting for %d remaining replies (done %d)\n", 
	       ping_count - pong_count, pong_count);
	while (timeval_elapsed(&tv) < 30 && pong_count < ping_count) {
		event_loop_once(ev);
	}

	if (ping_count != pong_count) {
		printf("ping test failed! received %d, sent %d\n", 
		       pong_count, ping_count);
		ret = False;
	}

	printf("echo rate of %.0f messages/sec\n", 
	       (ping_count+pong_count)/timeval_elapsed(&tv));

	return ret;
}


BOOL torture_local_irpc(void) 
{
	TALLOC_CTX *mem_ctx = talloc_init("torture_local_irpc");
	BOOL ret = True;
	struct messaging_context *msg_ctx1, *msg_ctx2;
	struct event_context *ev;

	lp_set_cmdline("lock dir", "lockdir.tmp");

	ev = event_context_init(mem_ctx);
	msg_ctx1 = messaging_init(mem_ctx, MSG_ID1, ev);
	if (!msg_ctx1) {
		printf("Failed to init first messaging context\n");
		talloc_free(mem_ctx);
		return False;
	}
	msg_ctx2 = messaging_init(mem_ctx, MSG_ID2, ev);
	if (!msg_ctx2) {
		printf("Failed to init second messaging context\n");
		talloc_free(mem_ctx);
		return False;
	}

	/* register the server side function */
	IRPC_REGISTER(msg_ctx1, rpcecho, ECHO_ADDONE, irpc_AddOne, NULL);
	IRPC_REGISTER(msg_ctx2, rpcecho, ECHO_ADDONE, irpc_AddOne, NULL);

	IRPC_REGISTER(msg_ctx1, rpcecho, ECHO_ECHODATA, irpc_EchoData, NULL);
	IRPC_REGISTER(msg_ctx2, rpcecho, ECHO_ECHODATA, irpc_EchoData, NULL);

	ret &= test_addone(mem_ctx, msg_ctx1, msg_ctx2, 0);
	ret &= test_addone(mem_ctx, msg_ctx1, msg_ctx2, 0x7FFFFFFE);
	ret &= test_addone(mem_ctx, msg_ctx1, msg_ctx2, 0xFFFFFFFE);
	ret &= test_addone(mem_ctx, msg_ctx1, msg_ctx2, 0xFFFFFFFF);
	ret &= test_addone(mem_ctx, msg_ctx1, msg_ctx2, random() & 0xFFFFFFFF);
	ret &= test_echodata(mem_ctx, msg_ctx1, msg_ctx2);
	ret &= test_speed(mem_ctx, msg_ctx1, msg_ctx2, ev);

	talloc_free(mem_ctx);

	return ret;
}
