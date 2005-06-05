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

const uint32_t MSG_ID = 1;

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
static BOOL test_addone(TALLOC_CTX *mem_ctx, struct messaging_context *msg_ctx)
{
	struct echo_AddOne r;
	NTSTATUS status;
	uint32_t res;

	/* register the server side function */
	IRPC_REGISTER(msg_ctx, rpcecho, ECHO_ADDONE, irpc_AddOne);

	/* make the call */
	r.in.in_data = random();
	r.out.out_data = &res;

	status = IRPC_CALL(msg_ctx, MSG_ID, rpcecho, ECHO_ADDONE, &r);
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

BOOL torture_local_irpc(void) 
{
	TALLOC_CTX *mem_ctx = talloc_init("torture_local_irpc");
	BOOL ret = True;
	struct messaging_context *msg_ctx;
	struct event_context *ev;

	lp_set_cmdline("lock dir", "lockdir.tmp");

	ev = event_context_init(mem_ctx);
	msg_ctx = messaging_init(mem_ctx, MSG_ID, ev);

	ret &= test_addone(mem_ctx, msg_ctx);

	talloc_free(mem_ctx);

	return True;
}
