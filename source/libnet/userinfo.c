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
#include "libcli/composite/composite.h"
#include "libnet/composite.h"
#include "librpc/gen_ndr/security.h"
#include "libcli/security/security.h"
#include "libnet/userman.h"
#include "libnet/userinfo.h"
#include "librpc/gen_ndr/ndr_samr_c.h"

static void userinfo_handler(struct rpc_request *req);

enum userinfo_stage { USERINFO_LOOKUP, USERINFO_OPENUSER, USERINFO_GETUSER, USERINFO_CLOSEUSER };

struct userinfo_state {
	enum userinfo_stage       stage;
	struct dcerpc_pipe        *pipe;
	struct rpc_request        *req;
	struct policy_handle      domain_handle;
	struct policy_handle      user_handle;
	uint16_t                  level;
	struct samr_LookupNames   lookup;
	struct samr_OpenUser      openuser;
	struct samr_QueryUserInfo queryuserinfo;
	struct samr_Close         samrclose;	
	union  samr_UserInfo      *info;

	/* information about the progress */
	void (*monitor_fn)(struct monitor_msg *);
};


/**
 * Stage 1 (optional): Look for a username in SAM server.
 */
static NTSTATUS userinfo_lookup(struct composite_context *c,
				struct userinfo_state *s)
{
	/* receive samr_Lookup reply */
	c->status = dcerpc_ndr_request_recv(s->req);
	NT_STATUS_NOT_OK_RETURN(c->status);
	
	/* there could be a problem with name resolving itself */
	NT_STATUS_NOT_OK_RETURN(s->lookup.out.result);

	/* have we actually got name resolved
	   - we're looking for only one at the moment */
	if (s->lookup.out.rids.count == 0) {
		return NT_STATUS_NO_SUCH_USER;
	}

	/* TODO: find proper status code for more than one rid found */

	/* prepare parameters for LookupNames */
	s->openuser.in.domain_handle  = &s->domain_handle;
	s->openuser.in.access_mask    = SEC_FLAG_MAXIMUM_ALLOWED;
	s->openuser.in.rid            = s->lookup.out.rids.ids[0];
	s->openuser.out.user_handle   = &s->user_handle;

	/* send request */
	s->req = dcerpc_samr_OpenUser_send(s->pipe, c, &s->openuser);
	if (s->req == NULL) goto failure;

	s->req->async.callback = userinfo_handler;
	s->req->async.private  = c;
	s->stage = USERINFO_OPENUSER;

	return NT_STATUS_OK;

failure:
	return NT_STATUS_UNSUCCESSFUL;
}


/**
 * Stage 2: Open user policy handle.
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
 * Stage 3: Get requested user information.
 */
static NTSTATUS userinfo_getuser(struct composite_context *c,
				 struct userinfo_state *s)
{
	/* receive samr_QueryUserInfo reply */
	c->status = dcerpc_ndr_request_recv(s->req);
	NT_STATUS_NOT_OK_RETURN(c->status);

	/* check if queryuser itself went ok */
	NT_STATUS_NOT_OK_RETURN(s->queryuserinfo.out.result);

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
 * Stage 4: Close policy handle associated with opened user.
 */
static NTSTATUS userinfo_closeuser(struct composite_context *c,
				   struct userinfo_state *s)
{
	/* receive samr_Close reply */
	c->status = dcerpc_ndr_request_recv(s->req);
	NT_STATUS_NOT_OK_RETURN(c->status);

	c->state = COMPOSITE_STATE_DONE;

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
	struct userinfo_state *s = talloc_get_type(c->private_data, struct userinfo_state);
	struct monitor_msg msg;
	struct msg_rpc_lookup_name *msg_lookup;
	struct msg_rpc_open_user *msg_open;
	struct msg_rpc_query_user *msg_query;
	struct msg_rpc_close_user *msg_close;
	
	/* Stages of the call */
	switch (s->stage) {
	case USERINFO_LOOKUP:
		c->status = userinfo_lookup(c, s);

		msg.type = rpc_lookup_name;
		msg_lookup = talloc(s, struct msg_rpc_lookup_name);
		msg_lookup->rid = s->lookup.out.rids.ids;
		msg_lookup->count = s->lookup.out.rids.count;
		msg.data = (void*)msg_lookup;
		msg.data_size = sizeof(*msg_lookup);
		break;

	case USERINFO_OPENUSER:
		c->status = userinfo_openuser(c, s);

		msg.type = rpc_open_user;
		msg_open = talloc(s, struct msg_rpc_open_user);
		msg_open->rid = s->openuser.in.rid;
		msg_open->access_mask = s->openuser.in.access_mask;
		msg.data = (void*)msg_open;
		msg.data_size = sizeof(*msg_open);
		break;

	case USERINFO_GETUSER:
		c->status = userinfo_getuser(c, s);

		msg.type = rpc_query_user;
		msg_query = talloc(s, struct msg_rpc_query_user);
		msg_query->level = s->queryuserinfo.in.level;
		msg.data = (void*)msg_query;
		msg.data_size = sizeof(*msg_query);
		break;
		
	case USERINFO_CLOSEUSER:
		c->status = userinfo_closeuser(c, s);

		msg.type = rpc_close_user;
		msg_close = talloc(s, struct msg_rpc_close_user);
		msg_close->rid = s->openuser.in.rid;
		msg.data = (void*)msg_close;
		msg.data_size = sizeof(*msg_close);
		break;
	}

	if (!NT_STATUS_IS_OK(c->status)) {
		c->state = COMPOSITE_STATE_ERROR;
	}
	
	if (s->monitor_fn) {
		s->monitor_fn(&msg);
	}

	if (c->state >= COMPOSITE_STATE_DONE &&
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
struct composite_context *libnet_rpc_userinfo_send(struct dcerpc_pipe *p,
						   struct libnet_rpc_userinfo *io,
						   void (*monitor)(struct monitor_msg*))
{
	struct composite_context *c;
	struct userinfo_state *s;
	struct dom_sid *sid;

	if (!p || !io) return NULL;
	
	c = composite_create(p, dcerpc_event_context(p));
	if (c == NULL) return c;
	
	s = talloc_zero(c, struct userinfo_state);
	if (composite_nomem(s, c)) return c;

	c->private_data = s;

	s->level         = io->in.level;
	s->pipe          = p;
	s->domain_handle = io->in.domain_handle;
	s->monitor_fn    = monitor;

	if (io->in.sid) {
		sid = dom_sid_parse_talloc(s, io->in.sid);
		if (composite_nomem(sid, c)) return c;

		s->openuser.in.domain_handle  = &s->domain_handle;
		s->openuser.in.access_mask    = SEC_FLAG_MAXIMUM_ALLOWED;
		s->openuser.in.rid            = sid->sub_auths[sid->num_auths - 1];
		s->openuser.out.user_handle   = &s->user_handle;
		
		/* send request */
		s->req = dcerpc_samr_OpenUser_send(p, c, &s->openuser);
		if (composite_nomem(s->req, c)) return c;
		
		s->stage = USERINFO_OPENUSER;

	} else {
		/* preparing parameters to send rpc request */
		s->lookup.in.domain_handle    = &s->domain_handle;
		s->lookup.in.num_names        = 1;
		s->lookup.in.names            = talloc_array(s, struct lsa_String, 1);
		
		if (composite_nomem(s->lookup.in.names, c)) return c;
		s->lookup.in.names[0].string  = talloc_strdup(s, io->in.username);
		
		/* send request */
		s->req = dcerpc_samr_LookupNames_send(p, c, &s->lookup);
		if (composite_nomem(s->req, c)) return c;
		
		s->stage = USERINFO_LOOKUP;
	}

	/* callback handler */
	s->req->async.callback = userinfo_handler;
	s->req->async.private = c;

	return c;
}


/**
 * Waits for and receives result of asynchronous userinfo call
 * 
 * @param c composite context returned by asynchronous userinfo call
 * @param mem_ctx memory context of the call
 * @param io pointer to results (and arguments) of the call
 * @return nt status code of execution
 */

NTSTATUS libnet_rpc_userinfo_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
				  struct libnet_rpc_userinfo *io)
{
	NTSTATUS status;
	struct userinfo_state *s;
	
	/* wait for results of sending request */
	status = composite_wait(c);
	
	if (NT_STATUS_IS_OK(status) && io) {
		s = talloc_get_type(c->private_data, struct userinfo_state);
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

NTSTATUS libnet_rpc_userinfo(struct dcerpc_pipe *p,
			     TALLOC_CTX *mem_ctx,
			     struct libnet_rpc_userinfo *io)
{
	struct composite_context *c = libnet_rpc_userinfo_send(p, io, NULL);
	return libnet_rpc_userinfo_recv(c, mem_ctx, io);
}
