/* 
   Unix SMB/CIFS implementation.

   endpoint server for the echo pipe

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Stefan (metze) Metzmacher 2005
   
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
#include "rpc_server/dcerpc_server.h"
#include "librpc/gen_ndr/ndr_echo.h"
#include "events.h"


static NTSTATUS echo_AddOne(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct echo_AddOne *r)
{
	*r->out.v = *r->in.v + 1;
	return NT_STATUS_OK;
}

static NTSTATUS echo_EchoData(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct echo_EchoData *r)
{
	if (!r->in.len) {
		return NT_STATUS_OK;
	}

	r->out.out_data = talloc_memdup(mem_ctx, r->in.in_data, r->in.len);
	if (!r->out.out_data) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

static NTSTATUS echo_SinkData(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct echo_SinkData *r)
{
	return NT_STATUS_OK;
}

static NTSTATUS echo_SourceData(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct echo_SourceData *r)
{
	int i;
	for (i=0;i<r->in.len;i++) {
		r->out.data[i] = i;
	}

	return NT_STATUS_OK;
}

static NTSTATUS echo_TestCall(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct echo_TestCall *r)
{
	r->out.s2 = "this is a test string";
	
	return NT_STATUS_OK;
}

static NTSTATUS echo_TestCall2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct echo_TestCall2 *r)
{
	r->out.info = talloc_p(mem_ctx, union echo_Info);
	if (!r->out.info) {
		return NT_STATUS_NO_MEMORY;
	}

	switch (r->in.level) {
	case 1:
		r->out.info->info1.v = 10;
		break;
	case 2:
		r->out.info->info2.v = 20;
		break;
	case 3:
		r->out.info->info3.v = 30;
		break;
	case 4:
		r->out.info->info4.v = 40;
		break;
	case 5:
		r->out.info->info5.v1 = 50;
		r->out.info->info5.v2 = 60;
		break;
	case 6:
		r->out.info->info6.v1 = 70;
		r->out.info->info6.info1.v= 80;
		break;
	case 7:
		r->out.info->info7.v1 = 80;
		r->out.info->info7.info4.v = 90;
		break;
	default:
		return NT_STATUS_INVALID_LEVEL;
	}

	return NT_STATUS_OK;
}

static NTSTATUS echo_TestEnum(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct echo_TestEnum *r)
{
	r->out.foo2->e1 = ECHO_ENUM2;
	return NT_STATUS_OK;
}

struct echo_TestSleep_private {
	struct dcesrv_call_state *dce_call;
	struct echo_TestSleep *r;
	struct timed_event *te;
};

static void echo_TestSleep_handler(struct event_context *ev, struct timed_event *te, struct timeval t)
{
	struct echo_TestSleep_private *p = te->private;
	struct echo_TestSleep *r = p->r;
	NTSTATUS status;

	r->out.result = r->in.seconds;

	status = dcesrv_reply(p->dce_call);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("echo_TestSleep_handler: dcesrv_reply() failed - %s\n",
			nt_errstr(status)));
	}
}

static int echo_TestSleep_destructor(void *ptr)
{
	struct echo_TestSleep_private *p = ptr;
	event_remove_timed(p->dce_call->event_ctx, p->te);
	return 0;
}

static long echo_TestSleep(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct echo_TestSleep *r)
{
	struct timed_event te;
	struct echo_TestSleep_private *p;

	if (!(dce_call->state_flags & DCESRV_CALL_STATE_FLAG_MAY_ASYNC)) {
		/* we're not allowed to reply async */
		sleep(r->in.seconds);
		return r->in.seconds;
	}

	/* we're allowed to reply async */
	p = talloc(mem_ctx, struct echo_TestSleep_private);
	if (!p) {
		return 0;
	}

	p->dce_call	= dce_call;
	p->r		= r;

	te.handler	= echo_TestSleep_handler;
	te.private	= p;
	te.next_event	= timeval_add(&dce_call->time, r->in.seconds, 0);

	p->te = event_add_timed(dce_call->event_ctx, &te);
	if (!p->te) {
		return 0;
	}

	talloc_set_destructor(p, echo_TestSleep_destructor);

	dce_call->state_flags |= DCESRV_CALL_STATE_FLAG_ASYNC;
	return 0;
}

/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_echo_s.c"
