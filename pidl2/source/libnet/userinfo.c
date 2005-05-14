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
  a composite function for getting user information via samr pipe
*/

#include "includes.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"
#include "libcli/composite/monitor.h"
#include "librpc/gen_ndr/ndr_samr.h"
#include "libnet/composite.h"

static void userinfo_handler(struct rpc_request *req);

enum userinfo_stage { USERINFO_OPENUSER, USERINFO_GETUSER, USERINFO_CLOSEUSER };

struct userinfo_state {
	enum userinfo_stage       stage;
	struct dcerpc_pipe        *pipe;
	struct rpc_request        *req;
	struct policy_handle      user_handle;
	uint16_t                  level;
	struct samr_OpenUser      openuser;
	struct samr_QueryUserInfo queryuserinfo;
	struct samr_Close         samrclose;	
	union  samr_UserInfo      *info;
};


/**
 * Stage 1: Open user policy handle in SAM server.
 */
static NTSTATUS userinfo_openuser(struct composite_context *c,
				  struct userinfo_state *s)
{
	/* receive samr_OpenUser reply */
	c->status = dcerpc_ndr_request_recv(s->req);
	NT_STATUS_NOT_OK_RETURN(c->status);

	/* prepare parameters for QueryUserInfo call */
	s->queryuserinfo.in.user_handle = &s->user_handle;
	s->queryuserinfo.in.level       = s->level;
	
	/* queue rpc call, set event handling and new state */
	s->req = dcerpc_samr_QueryUserInfo_send(s->pipe, c, &s->queryuserinfo);
	if (s->req == NULL) goto failure;
	
	s->req->async.callback = userinfo_handler;
	s->req->async.private  = c;
	s->stage = USERINFO_GETUSER;
	
	return NT_STATUS_OK;

failure:
	return NT_STATUS_UNSUCCESSFUL;
}


/**
 * Stage 2: Get requested user information.
 */
static NTSTATUS userinfo_getuser(struct composite_context *c,
				 struct userinfo_state *s)
{
	/* receive samr_QueryUserInfo reply */
	c->status = dcerpc_ndr_request_recv(s->req);
	NT_STATUS_NOT_OK_RETURN(c->status);

	s->info = talloc_steal(s, s->queryuserinfo.out.info);
	
	/* prepare arguments for Close call */
	s->samrclose.in.handle  = &s->user_handle;
	s->samrclose.out.handle = &s->user_handle;
	
	/* queue rpc call, set event handling and new state */
	s->req = dcerpc_samr_Close_send(s->pipe, c, &s->samrclose);
	
	s->req->async.callback = userinfo_handler;
	s->req->async.private  = c;
	s->stage = USERINFO_CLOSEUSER;

	return NT_STATUS_OK;
}


/**
 * Stage3: Close policy handle associated with opened user.
 */
static NTSTATUS userinfo_closeuser(struct composite_context *c,
				   struct userinfo_state *s)
{
	/* receive samr_Close reply */
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
static void userinfo_handler(struct rpc_request *req)
{
	struct composite_context *c = req->async.private;
	struct userinfo_state *s = talloc_get_type(c->private, struct userinfo_state);
	struct monitor_msg msg;
	
	/* Stages of the call */
	switch (s->stage) {
	case USERINFO_OPENUSER:
		c->status = userinfo_openuser(c, s);
		msg.type = rpc_open_user;
		msg.data.rpc_open_user.rid = s->openuser.in.rid;
		msg.data.rpc_open_user.access_mask = s->openuser.in.access_mask;
		break;

	case USERINFO_GETUSER:
		c->status = userinfo_getuser(c, s);
		msg.type = rpc_query_user;
		msg.data.rpc_query_user.level = s->queryuserinfo.in.level;
		break;
		
	case USERINFO_CLOSEUSER:
		c->status = userinfo_closeuser(c, s);
		msg.type = rpc_close_user;
		msg.data.rpc_close_user.rid = s->openuser.in.rid;
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
 * Sends asynchronous userinfo request
 *
 * @param p dce/rpc call pipe 
 * @param io arguments and results of the call
 */
struct composite_context *rpc_composite_userinfo_send(struct dcerpc_pipe *p,
						      struct rpc_composite_userinfo *io,
						      void (*monitor)(struct monitor_msg*))
{
	struct composite_context *c;
	struct userinfo_state *s;
	struct dom_sid *sid;
	
	c = talloc_zero(p, struct composite_context);
	if (c == NULL) goto failure;
	
	s = talloc_zero(c, struct userinfo_state);
	if (s == NULL) goto failure;

	s->level = io->in.level;
	s->pipe  = p;
	
	sid = dom_sid_parse_talloc(s, io->in.sid);
	if (sid == NULL) goto failure;	
	c->state       = SMBCLI_REQUEST_SEND;
	c->private     = s;
	c->event_ctx   = dcerpc_event_context(p);
	c->monitor_fn  = monitor;

	/* preparing parameters to send rpc request */
	s->openuser.in.domain_handle  = &io->in.domain_handle;
	s->openuser.in.access_mask    = SEC_FLAG_MAXIMUM_ALLOWED;
	s->openuser.in.rid            = sid->sub_auths[sid->num_auths - 1];
	s->openuser.out.user_handle   = &s->user_handle;

	/* send request */
	s->req = dcerpc_samr_OpenUser_send(p, c, &s->openuser);

	/* callback handler */
	s->req->async.callback = userinfo_handler;
	s->req->async.private  = c;
	s->stage = USERINFO_OPENUSER;

	return c;
	
failure:
	talloc_free(c);
	return NULL;
}


/**
 * Waits for and receives result of asynchronous userinfo call
 * 
 * @param c composite context returned by asynchronous userinfo call
 * @param mem_ctx memory context of the call
 * @param io pointer to results (and arguments) of the call
 * @return nt status code of execution
 */

NTSTATUS rpc_composite_userinfo_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
				     struct rpc_composite_userinfo *io)
{
	NTSTATUS status;
	struct userinfo_state *s;
	
	/* wait for results of sending request */
	status = composite_wait(c);
	
	if (NT_STATUS_IS_OK(status) && io) {
		s = talloc_get_type(c->private, struct userinfo_state);
		talloc_steal(mem_ctx, s->info);
		io->out.info = *s->info;
	}
	
	/* memory context associated to composite context is no longer needed */
	talloc_free(c);
	return status;
}


/**
 * Synchronous version of userinfo call
 *
 * @param pipe dce/rpc call pipe
 * @param mem_ctx memory context for the call
 * @param io arguments and results of the call
 * @return nt status code of execution
 */

NTSTATUS rpc_composite_userinfo(struct dcerpc_pipe *pipe,
				TALLOC_CTX *mem_ctx,
				struct rpc_composite_userinfo *io)
{
	struct composite_context *c = rpc_composite_userinfo_send(pipe, io, NULL);
	return rpc_composite_userinfo_recv(c, mem_ctx, io);
}
