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
#include "libcli/composite/monitor.h"
#include "librpc/gen_ndr/ndr_samr.h"
#include "libnet/composite.h"

/*
 * Composite user add function
 */

static void useradd_handler(struct rpc_request*);

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
	struct monitor_msg msg;
	
	switch (s->stage) {
	case USERADD_CREATE:
		c->status = useradd_create(c, s);
		msg.type = rpc_create_user;
		msg.data.rpc_create_user.rid = *s->createuser.out.rid;
		break;
	}

	if (!NT_STATUS_IS_OK(c->status)) {
		c->state = SMBCLI_REQUEST_ERROR;
	}

	if (c->monitor_fn) {
		c->monitor_fn(&msg);
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
						     struct rpc_composite_useradd *io,
						     void (*monitor)(struct monitor_msg*))
{
	struct composite_context *c;
	struct useradd_state *s;
	
	c = talloc_zero(p, struct composite_context);
	if (c == NULL) goto failure;
	
	s = talloc_zero(c, struct useradd_state);
	if (s == NULL) goto failure;
	
	s->domain_handle = io->in.domain_handle;
	s->pipe          = p;
	
	c->state       = SMBCLI_REQUEST_SEND;
	c->private     = s;
	c->event_ctx   = dcerpc_event_context(p);
	c->monitor_fn  = monitor;

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
 * @param c composite context returned by asynchronous useradd call
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
	struct composite_context *c = rpc_composite_useradd_send(pipe, io, NULL);
	return rpc_composite_useradd_recv(c, mem_ctx, io);
}


/*
 * Composite user delete function
 */

static void userdel_handler(struct rpc_request*);

enum userdel_stage { USERDEL_LOOKUP, USERDEL_OPEN, USERDEL_DELETE };

struct userdel_state {
	enum userdel_stage        stage;
	struct dcerpc_pipe        *pipe;
	struct rpc_request        *req;
	struct policy_handle      domain_handle;
	struct policy_handle      user_handle;
	struct samr_LookupNames   lookupname;
	struct samr_OpenUser      openuser;
	struct samr_DeleteUser    deleteuser;
};


/**
 * Stage 1: Lookup the user name and resolve it to rid
 */
static NTSTATUS userdel_lookup(struct composite_context *c,
			       struct userdel_state *s)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	c->status = dcerpc_ndr_request_recv(s->req);
	NT_STATUS_NOT_OK_RETURN(c->status);
	
	if (!s->lookupname.out.rids.count) {
		/* TODO: no such user */
		status = NT_STATUS_NO_SUCH_USER;

	} else if (!s->lookupname.out.rids.count > 1) {
		/* TODO: ambiguous username */
		status = NT_STATUS_INVALID_ACCOUNT_NAME;
	}
	
	s->openuser.in.domain_handle = &s->domain_handle;
	s->openuser.in.rid           = s->lookupname.out.rids.ids[0];
	s->openuser.in.access_mask   = SEC_FLAG_MAXIMUM_ALLOWED;
	s->openuser.out.user_handle  = &s->user_handle;

	s->req = dcerpc_samr_OpenUser_send(s->pipe, c, &s->openuser);
	
	s->req->async.callback = userdel_handler;
	s->req->async.private  = c;
	s->stage = USERDEL_OPEN;
	
	return NT_STATUS_OK;
}


/**
 * Stage 2: Open user account.
 */
static NTSTATUS userdel_open(struct composite_context *c,
			     struct userdel_state *s)
{
	c->status = dcerpc_ndr_request_recv(s->req);
	NT_STATUS_NOT_OK_RETURN(c->status);
	
	s->deleteuser.in.user_handle   = &s->user_handle;
	s->deleteuser.out.user_handle  = &s->user_handle;
	
	s->req = dcerpc_samr_DeleteUser_send(s->pipe, c, &s->deleteuser);
	
	s->req->async.callback = userdel_handler;
	s->req->async.private  = c;
	s->stage = USERDEL_DELETE;
	
	return NT_STATUS_OK;
}


/**
 * Stage 3: Delete user account
 */
static NTSTATUS userdel_delete(struct composite_context *c,
			       struct userdel_state *s)
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
static void userdel_handler(struct rpc_request *req)
{
	struct composite_context *c = req->async.private;
	struct userdel_state *s = talloc_get_type(c->private, struct userdel_state);
	
	switch (s->stage) {
	case USERDEL_LOOKUP:
		c->status = userdel_lookup(c, s);
		break;
	case USERDEL_OPEN:
		c->status = userdel_open(c, s);
		break;
	case USERDEL_DELETE:
		c->status = userdel_delete(c, s);
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
 * Sends asynchronous userdel request
 *
 * @param p dce/rpc call pipe
 * @param io arguments and results of the call
 */

struct composite_context *rpc_composite_userdel_send(struct dcerpc_pipe *p,
						     struct rpc_composite_userdel *io)
{
	struct composite_context *c;
	struct userdel_state *s;
	
	c = talloc_zero(p, struct composite_context);
	if (c == NULL) goto failure;

	s = talloc_zero(c, struct userdel_state);
	if (s == NULL) goto failure;

	c->state      = SMBCLI_REQUEST_SEND;
	c->private    = s;
	c->event_ctx  = dcerpc_event_context(p);

	s->pipe          = p;
	s->domain_handle = io->in.domain_handle;
	
	/* preparing parameters to send rpc request */
	s->lookupname.in.domain_handle = &io->in.domain_handle;
	s->lookupname.in.num_names     = 1;
	s->lookupname.in.names         = talloc_zero(s, struct samr_String);
	s->lookupname.in.names->string = io->in.username;

	/* send the request */
	s->req = dcerpc_samr_LookupNames_send(p, c, &s->lookupname);

	/* callback handler */
	s->req->async.callback = userdel_handler;
	s->req->async.private  = c;
	s->stage = USERDEL_LOOKUP;

	return c;

failure:
	talloc_free(c);
	return NULL;
}


/**
 * Waits for and receives results of asynchronous userdel call
 *
 * @param c composite context returned by asynchronous userdel call
 * @param mem_ctx memory context of the call
 * @param io pointer to results (and arguments) of the call
 * @return nt status code of execution
 */

NTSTATUS rpc_composite_userdel_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
				    struct rpc_composite_userdel *io)
{
	NTSTATUS status;
	struct userdel_state *s;
	
	status = composite_wait(c);

	if (NT_STATUS_IS_OK(status) && io) {
		s  = talloc_get_type(c->private, struct userdel_state);
		io->out.user_handle = s->user_handle;
	}

	talloc_free(c);
	return status;
}


/**
 * Synchronous version of userdel call
 *
 * @param pipe dce/rpc call pipe
 * @param mem_ctx memory context for the call
 * @param io arguments and results of the call
 * @return nt status code of execution
 */

NTSTATUS rpc_composite_userdel(struct dcerpc_pipe *pipe,
			       TALLOC_CTX *mem_ctx,
			       struct rpc_composite_userdel *io)
{
	struct composite_context *c = rpc_composite_userdel_send(pipe, io);
	return rpc_composite_userdel_recv(c, mem_ctx, io);
}
