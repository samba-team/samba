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
#include "librpc/gen_ndr/ndr_samr.h"

enum userinfo_stage { USERINFO_OPENUSER, USERINFO_GETUSER, USERINFO_CLOSEUSER };

struct rpc_composite_userinfo {
	struct {
		struct policy_handle domain_handle;
		const char *sid;
		uint16_t level;
	} in;
	struct {
		union samr_UserInfo info;
	} out;
};

struct userinfo_state {
	enum userinfo_stage stage;
	struct dcerpc_pipe *pipe;
	struct rpc_request *req;
	struct rpc_composite_userinfo io;
};

static void userinfo_handler(struct rpc_request *req);


static NTSTATUS userinfo_openuser(struct composite_context *c,
				  struct rpc_composite_userinfo *io)
{
	struct userinfo_state *s = talloc_get_type(c->private, struct userinfo_state);
	struct rpc_request *req = s->req;
	struct samr_OpenUser *rep;
	struct samr_QueryUserInfo r;

	/* receive samr_OpenUser reply */
	c->status = dcerpc_ndr_request_recv(req);
	NT_STATUS_NOT_OK_RETURN(c->status);
	rep = (struct samr_OpenUser*)req->ndr.struct_ptr;

	/* prepare parameters for QueryUserInfo call */
	r.in.user_handle = rep->out.user_handle;
	r.in.level       = io->in.level;
	
	/* queue rpc call, set event handling and new state */
	s->req = dcerpc_samr_QueryUserInfo_send(s->pipe, c, &r);
	if (s->req == NULL) goto failure;
	
	s->req->async.callback = userinfo_handler;
	s->req->async.private  = c;
	s->stage = USERINFO_GETUSER;
	
	return rep->out.result;

failure:
	return NT_STATUS_UNSUCCESSFUL;
}


static NTSTATUS userinfo_getuser(struct composite_context *c,
				 struct rpc_composite_userinfo *io)
{
	struct userinfo_state *s = talloc_get_type(c->private, struct userinfo_state);
	struct rpc_request *req = s->pipe->conn->pending;
	struct samr_QueryUserInfo *rep;
	struct samr_Close r;
	
	/* receive samr_QueryUserInfo reply */
	c->status = dcerpc_ndr_request_recv(req);
	NT_STATUS_NOT_OK_RETURN(c->status);
	rep = (struct samr_QueryUserInfo*)req->ndr.struct_ptr;
	
	/* prepare arguments for Close call */
	r.in.handle = rep->in.user_handle;
	
	/* queue rpc call, set event handling and new state */
	s->req = dcerpc_samr_Close_send(s->pipe, c, &r);
	
	s->req->async.callback = userinfo_handler;
	s->req->async.private  = c;
	s->stage = USERINFO_CLOSEUSER;

	/* copying result of composite call */
	io->out.info = *rep->out.info;

	return rep->out.result;
}


static NTSTATUS userinfo_closeuser(struct composite_context *c,
				   struct rpc_composite_userinfo *io)
{
	struct userinfo_state *s = talloc_get_type(c->private, struct userinfo_state);
	struct rpc_request *req = s->pipe->conn->pending;
	struct samr_Close *rep;
	
	/* receive samr_Close reply */
	c->status = dcerpc_ndr_request_recv(req);
	NT_STATUS_NOT_OK_RETURN(c->status);
	rep = (struct samr_Close*)req->ndr.struct_ptr;

	/* return result */
	return rep->out.result;
}


static void userinfo_handler(struct rpc_request *req)
{
	struct composite_context *c = req->async.private;
	struct userinfo_state *s = talloc_get_type(c->private, struct userinfo_state);

	switch (s->stage) {
	case USERINFO_OPENUSER:
		c->status = userinfo_openuser(c, &s->io);
		break;

	case USERINFO_GETUSER:
		c->status = userinfo_getuser(c, &s->io);
		break;
		
	case USERINFO_CLOSEUSER:
		c->status = userinfo_closeuser(c, &s->io);
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


struct composite_context* rpc_composite_userinfo_send(struct dcerpc_pipe *p,
						      struct rpc_composite_userinfo *io)
{	

	struct composite_context *c;
	struct userinfo_state *s;
	struct samr_OpenUser *r;
	struct dom_sid *sid;
	
	c = talloc_zero(p, struct composite_context);
	if (c == NULL) goto failure;
	
	s = talloc_zero(c, struct userinfo_state);
	if (s == NULL) goto failure;
	
	/* copying input parameters */
	s->io.in.domain_handle  = io->in.domain_handle;
	s->io.in.sid            = talloc_strdup(p, io->in.sid);
	s->io.in.level          = io->in.level;
	sid                     = dom_sid_parse_talloc(c, s->io.in.sid);
	if (sid == NULL) goto failure;
	
	c->private = s;
	c->event_ctx = dcerpc_event_context(p);

	/* preparing parameters to send rpc request */
	r = talloc_zero(p, struct samr_OpenUser);
	r->in.domain_handle  = &s->io.in.domain_handle;
	r->in.access_mask    = 0;
	r->in.rid            = sid->sub_auths[sid->num_auths - 1];

	/* send request */
	s->req = dcerpc_samr_OpenUser_send(p, c, r);

	/* callback handler */
	s->req->async.callback = userinfo_handler;
	s->req->async.private  = c;
	s->stage = USERINFO_OPENUSER;

	return c;
	
failure:
	talloc_free(c);
}


NTSTATUS rpc_composite_userinfo_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
				     struct rpc_composite_userinfo *io)
{
	NTSTATUS status;
	struct userinfo_state *s;
	
	status = composite_wait(c);
	
	if (NT_STATUS_IS_OK(status) && io) {
		s = talloc_get_type(c->private, struct userinfo_state);
		talloc_steal(mem_ctx, &s->io.out.info);
		io->out.info = s->io.out.info;
	}

	talloc_free(c);
	return status;
}


NTSTATUS rpc_composite_userinfo(struct dcerpc_pipe *pipe,
				TALLOC_CTX *mem_ctx,
				struct rpc_composite_userinfo *io)
{
	struct composite_context *c = rpc_composite_userinfo_send(pipe, io);
	return rpc_composite_userinfo_recv(c, mem_ctx, io);
}
