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

/*
  serve up AddOne over the irpc system
*/
static NTSTATUS irpc_AddOne(struct irpc_message *irpc, struct echo_AddOne *r)
{
	*r->out.out_data = r->in.in_data + 1;
	return NT_STATUS_OK;
}


/*
  test a addone call over the internal messaging system
*/
static BOOL test_addone(TALLOC_CTX *mem_ctx, 
			struct messaging_context *msg_ctx1,
			struct messaging_context *msg_ctx2)
{
	struct echo_AddOne r;
	NTSTATUS status;
	uint32_t res;

	/* make the call */
	r.in.in_data = random();
	r.out.out_data = &res;

	status = IRPC_CALL(msg_ctx1, MSG_ID2, rpcecho, ECHO_ADDONE, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("AddOne failed - %s\n", nt_errstr(status));
		return False;
	}

	/* check the answer */
	if (res != r.in.in_data + 1) {
		printf("AddOne wrong answer - %u should be %u\n", 
		       *r.out.out_data, r.in.in_data+1);
		return False;
	}

	printf("%u + 1 = %u\n", r.in.in_data, res);

	return True;	
}


static void irpc_callback(struct irpc_request *irpc)
{
	int *pong_count = (int *)irpc->async.private;
	NTSTATUS status = irpc_call_recv(irpc);
	if (!NT_STATUS_IS_OK(status)) {
		printf("irpc call failed - %s\n", nt_errstr(status));
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
	uint32_t res;

	tv = timeval_current();

	r.in.in_data = 0;
	r.out.out_data = &res;

	printf("Sending echo for 10 seconds\n");
	while (timeval_elapsed(&tv) < 10.0) {
		struct irpc_request *irpc;

		irpc = IRPC_CALL_SEND(msg_ctx1, MSG_ID2, rpcecho, ECHO_ADDONE, &r);
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
	msg_ctx2 = messaging_init(mem_ctx, MSG_ID2, ev);

	/* register the server side function */
	IRPC_REGISTER(msg_ctx1, rpcecho, ECHO_ADDONE, irpc_AddOne, NULL);
	IRPC_REGISTER(msg_ctx2, rpcecho, ECHO_ADDONE, irpc_AddOne, NULL);

	ret &= test_addone(mem_ctx, msg_ctx1, msg_ctx2);
	ret &= test_speed(mem_ctx, msg_ctx1, msg_ctx2, ev);

	talloc_free(mem_ctx);

	return True;
}
