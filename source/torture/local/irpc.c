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
#include "torture/torture.h"
#include "torture/ui.h"

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
static BOOL test_addone(struct torture_test *parent_test, 
			struct messaging_context *msg_ctx1,
			struct messaging_context *msg_ctx2,
			uint32_t value)
{
	struct echo_AddOne r;
	NTSTATUS status;

	struct torture_test *test = torture_subtest(parent_test, "test_addone",
												"test_addone");

	/* make the call */
	r.in.in_data = value;

	test_debug = True;
	status = IRPC_CALL(msg_ctx1, MSG_ID2, rpcecho, ECHO_ADDONE, &r, test);
	test_debug = False;
	torture_assert_ntstatus_ok(test, status, "AddOne failed");

	/* check the answer */
	torture_assert(test, 
				   *r.out.out_data == r.in.in_data + 1, 
				   "AddOne wrong answer");

	torture_comment(test, "%u + 1 = %u", r.in.in_data, *r.out.out_data);

	return True;	
}

/*
  test a echodata call over the internal messaging system
*/
static BOOL test_echodata(struct torture_test *parent_test, 
			  struct messaging_context *msg_ctx1,
			  struct messaging_context *msg_ctx2)
{
	struct echo_EchoData r;
	NTSTATUS status;

	struct torture_test *test = torture_subtest(parent_test, "test_echodata",
												"test_echodata");

	/* make the call */
	r.in.in_data = (unsigned char *)talloc_strdup(test, "0123456789");
	r.in.len = strlen((char *)r.in.in_data);

	status = IRPC_CALL(msg_ctx1, MSG_ID2, rpcecho, ECHO_ECHODATA, &r, test);
	torture_assert_ntstatus_ok(test, status, "EchoData failed");

	/* check the answer */
	if (memcmp(r.out.out_data, r.in.in_data, r.in.len) != 0) {
		torture_fail(test, "EchoData wrong answer");
		NDR_PRINT_OUT_DEBUG(echo_EchoData, &r);
		return False;
	}

	torture_comment(test, "Echo '%*.*s' -> '%*.*s'", 
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
static BOOL test_speed(struct torture_test *parent_test, 
		       struct messaging_context *msg_ctx1,
		       struct messaging_context *msg_ctx2,
		       struct event_context *ev)
{
	int ping_count = 0;
	int pong_count = 0;
	struct timeval tv;
	struct echo_AddOne r;
	int timelimit = lp_parm_int(-1, "torture", "timelimit", 10);

	struct torture_test *test = torture_subtest(parent_test, "test_speed",
												"test_speed");

	tv = timeval_current();

	r.in.in_data = 0;

	torture_comment(test, "Sending echo for %d seconds", timelimit);
	while (timeval_elapsed(&tv) < timelimit) {
		struct irpc_request *irpc;

		irpc = IRPC_CALL_SEND(msg_ctx1, MSG_ID2, rpcecho, ECHO_ADDONE, &r, test);
		torture_assert(test, irpc != NULL, "AddOne send failed");

		irpc->async.fn = irpc_callback;
		irpc->async.private = &pong_count;

		ping_count++;

		while (ping_count > pong_count + 20) {
			event_loop_once(ev);
		}
	}

	torture_comment(test, "waiting for %d remaining replies (done %d)", 
	       ping_count - pong_count, pong_count);
	while (timeval_elapsed(&tv) < 30 && pong_count < ping_count) {
		event_loop_once(ev);
	}

	if (ping_count != pong_count) {
		torture_fail(test, "ping test failed! received %d, sent %d", 
		       pong_count, ping_count);
	}

	torture_comment(test, "echo rate of %.0f messages/sec", 
	       (ping_count+pong_count)/timeval_elapsed(&tv));

	return True;
}


BOOL torture_local_irpc(struct torture_context *torture) 
{
	struct torture_test *test = torture_test(torture, "torture_local_irpc", "");
	struct messaging_context *msg_ctx1, *msg_ctx2;
	struct event_context *ev;

	lp_set_cmdline("lock dir", "lockdir.tmp");

	ev = event_context_init(test);
	torture_assert(test, 
				   msg_ctx1 = messaging_init(test, MSG_ID1, ev),
				   "Failed to init first messaging context");

	torture_assert(test,
				   msg_ctx2 = messaging_init(test, MSG_ID2, ev),
				   "Failed to init second messaging context");

	/* register the server side function */
	IRPC_REGISTER(msg_ctx1, rpcecho, ECHO_ADDONE, irpc_AddOne, NULL);
	IRPC_REGISTER(msg_ctx2, rpcecho, ECHO_ADDONE, irpc_AddOne, NULL);

	IRPC_REGISTER(msg_ctx1, rpcecho, ECHO_ECHODATA, irpc_EchoData, NULL);
	IRPC_REGISTER(msg_ctx2, rpcecho, ECHO_ECHODATA, irpc_EchoData, NULL);

	test_addone(test, msg_ctx1, msg_ctx2, 0);
	test_addone(test, msg_ctx1, msg_ctx2, 0x7FFFFFFE);
	test_addone(test, msg_ctx1, msg_ctx2, 0xFFFFFFFE);
	test_addone(test, msg_ctx1, msg_ctx2, 0xFFFFFFFF);
	test_addone(test, msg_ctx1, msg_ctx2, random() & 0xFFFFFFFF);
	test_echodata(test, msg_ctx1, msg_ctx2);
	test_speed(test, msg_ctx1, msg_ctx2, ev);

	talloc_free(test);

	return torture_result(torture);
}
