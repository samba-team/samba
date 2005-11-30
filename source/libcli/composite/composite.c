/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Andrew Tridgell 2005
   
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
/*
  composite API helper functions
*/

#include "includes.h"
#include "lib/events/events.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"
#include "lib/messaging/irpc.h"
#include "libcli/nbt/libnbt.h"

/*
  block until a composite function has completed, then return the status
*/
NTSTATUS composite_wait(struct composite_context *c)
{
	if (c == NULL) return NT_STATUS_NO_MEMORY;

	while (c->state < COMPOSITE_STATE_DONE) {
		if (event_loop_once(c->event_ctx) != 0) {
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	return c->status;
}


/* 
   callback from composite_trigger_done() 
*/
static void composite_trigger(struct event_context *ev, struct timed_event *te,
			      struct timeval t, void *ptr)
{
	struct composite_context *c = talloc_get_type(ptr, struct composite_context);
	if (c->async.fn) {
		c->async.fn(c);
	}
}


/*
  trigger an immediate 'done' event on a composite context
  this is used when the composite code works out that the call
  can be completed without waiting for any external event
*/
void composite_trigger_done(struct composite_context *c)
{
	c->state = COMPOSITE_STATE_DONE;
	/* a zero timeout means immediate */
	event_add_timed(c->event_ctx, c, timeval_zero(), composite_trigger, c);
}

void composite_trigger_error(struct composite_context *c)
{
	c->state = COMPOSITE_STATE_ERROR;
	/* a zero timeout means immediate */
	event_add_timed(c->event_ctx, c, timeval_zero(), composite_trigger, c);
}


/*
 * Some composite helpers that are handy if you write larger composite
 * functions.
 */

BOOL composite_is_ok(struct composite_context *ctx)
{
	if (NT_STATUS_IS_OK(ctx->status)) {
		return True;
	}
	ctx->state = COMPOSITE_STATE_ERROR;
	if (ctx->async.fn != NULL) {
		ctx->async.fn(ctx);
	}
	return False;
}

void composite_error(struct composite_context *ctx, NTSTATUS status)
{
	ctx->status = status;
	SMB_ASSERT(!composite_is_ok(ctx));
}

BOOL composite_nomem(const void *p, struct composite_context *ctx)
{
	if (p != NULL) {
		return False;
	}
	composite_error(ctx, NT_STATUS_NO_MEMORY);
	return True;
}

void composite_done(struct composite_context *ctx)
{
	ctx->state = COMPOSITE_STATE_DONE;
	if (ctx->async.fn != NULL) {
		ctx->async.fn(ctx);
	}
}

void composite_continue(struct composite_context *ctx,
			struct composite_context *new_ctx,
			void (*continuation)(struct composite_context *),
			void *private_data)
{
	if (composite_nomem(new_ctx, ctx)) return;
	new_ctx->async.fn = continuation;
	new_ctx->async.private_data = private_data;
}

void composite_continue_rpc(struct composite_context *ctx,
			    struct rpc_request *new_req,
			    void (*continuation)(struct rpc_request *),
			    void *private_data)
{
	if (composite_nomem(new_req, ctx)) return;
	new_req->async.callback = continuation;
	new_req->async.private = private_data;
}

void composite_continue_irpc(struct composite_context *ctx,
			     struct irpc_request *new_req,
			     void (*continuation)(struct irpc_request *),
			     void *private_data)
{
	if (composite_nomem(new_req, ctx)) return;
	new_req->async.fn = continuation;
	new_req->async.private = private_data;
}

void composite_continue_smb(struct composite_context *ctx,
			    struct smbcli_request *new_req,
			    void (*continuation)(struct smbcli_request *),
			    void *private_data)
{
	if (composite_nomem(new_req, ctx)) return;
	new_req->async.fn = continuation;
	new_req->async.private = private_data;
}

void composite_continue_nbt(struct composite_context *ctx,
			    struct nbt_name_request *new_req,
			    void (*continuation)(struct nbt_name_request *),
			    void *private_data)
{
	if (composite_nomem(new_req, ctx)) return;
	new_req->async.fn = continuation;
	new_req->async.private = private_data;
}
