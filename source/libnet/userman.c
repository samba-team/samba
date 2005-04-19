/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Rafal Szczesniak 2005
   
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
  a composite functions for user management operations (add/del/chg)
*/

#include "includes.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"
#include "librpc/gen_ndr/ndr_samr.h"
#include "libnet/composite.h"

static void useradd_handler(struct rpc_request *req);

enum useradd_stage { USERADD_CREATE };

struct useradd_state {
	enum useradd_stage       stage;
	struct dcerpc_pipe       *pipe;
	struct rpc_request       *req;
	struct policy_handle     domain_handle;
	struct samr_CreateUser   createuser;
	struct policy_handle     user_handle;
	uint32_t                 user_rid;
};


/**
 * Stage 1 (and the only one for now): Create user account.
 */
static NTSTATUS useradd_create(struct composite_context *c,
			       struct useradd_state *s)
{
	c->status = dcerpc_ndr_request_recv(s->req);
	NT_STATUS_NOT_OK_RETURN(c->status);
	
	c->state = SMBCLI_REQUEST_DONE;
	return NT_STATUS_OK;
}


/**
 * Event handler for asynchronous request. Handles transition through
 * intermediate stages of the call.
 *
 * @param req rpc call context
 */
static void useradd_handler(struct rpc_request *req)
{
	struct composite_context *c = req->async.private;
	struct useradd_state *s = talloc_get_type(c->private, struct useradd_state);
	
	switch (s->stage) {
	case USERADD_CREATE:
		c->status = useradd_create(c, s);
		break;
	}

	if (!NT_STATUS_IS_OK(c->status)) {
		c->state = SMBCLI_REQUEST_ERROR;
	}

	if (c->state >= SMBCLI_REQUEST_DONE &&
	    c->async.fn) {
		c->async.fn(c);
	}
}


/**
 * Sends asynchronous useradd request
 *
 * @param p dce/rpc call pipe 
 * @param io arguments and results of the call
 */
struct composite_context *rpc_composite_useradd_send(struct dcerpc_pipe *p,
						     struct rpc_composite_useradd *io)
{
	struct composite_context *c;
	struct useradd_state *s;
	struct dom_sid *sid;
	
	c = talloc_zero(p, struct composite_context);
	if (c == NULL) goto failure;
	
	s = talloc_zero(c, struct useradd_state);
	if (s == NULL) goto failure;
	
	s->domain_handle = io->in.domain_handle;
	s->pipe          = p;
	
	c->state     = SMBCLI_REQUEST_SEND;
	c->private   = s;
	c->event_ctx = dcerpc_event_context(p);

	/* preparing parameters to send rpc request */
	s->createuser.in.domain_handle         = &io->in.domain_handle;
	s->createuser.in.account_name          = talloc_zero(c, struct samr_String);
	s->createuser.in.account_name->string  = talloc_strdup(c, io->in.username);
	s->createuser.out.user_handle          = &s->user_handle;
	s->createuser.out.rid                  = &s->user_rid;

	/* send request */
	s->req = dcerpc_samr_CreateUser_send(p, c, &s->createuser);

	/* callback handler */
	s->req->async.callback = useradd_handler;
	s->req->async.private  = c;
	s->stage = USERADD_CREATE;

	return c;
	
failure:
	talloc_free(c);
	return NULL;
}


/**
 * Waits for and receives result of asynchronous useradd call
 * 
 * @param c composite context returned by asynchronous userinfo call
 * @param mem_ctx memory context of the call
 * @param io pointer to results (and arguments) of the call
 * @return nt status code of execution
 */

NTSTATUS rpc_composite_useradd_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
				    struct rpc_composite_useradd *io)
{
	NTSTATUS status;
	struct useradd_state *s;
	
	status = composite_wait(c);
	
	if (NT_STATUS_IS_OK(status) && io) {
		/* get and return result of the call */
		s = talloc_get_type(c->private, struct useradd_state);
		io->out.user_handle = s->user_handle;
	}

	talloc_free(c);
	return status;
}


/**
 * Synchronous version of useradd call
 *
 * @param pipe dce/rpc call pipe
 * @param mem_ctx memory context for the call
 * @param io arguments and results of the call
 * @return nt status code of execution
 */

NTSTATUS rpc_composite_useradd(struct dcerpc_pipe *pipe,
			       TALLOC_CTX *mem_ctx,
			       struct rpc_composite_useradd *io)
{
	struct composite_context *c = rpc_composite_useradd_send(pipe, io);
	return rpc_composite_useradd_recv(c, mem_ctx, io);
}
