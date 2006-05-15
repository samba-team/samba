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
  a composite function for domain handling on samr pipe
*/

#include "includes.h"
#include "libcli/composite/composite.h"
#include "libnet/libnet.h"
#include "librpc/gen_ndr/ndr_samr_c.h"

static void domain_open_handler(struct rpc_request*);

enum domain_open_stage { DOMOPEN_CONNECT, DOMOPEN_LOOKUP, DOMOPEN_OPEN,
			 DOMOPEN_CLOSE_EXISTING, DOMOPEN_RPC_CONNECT };

struct domain_open_state {
	enum domain_open_stage    stage;
	struct libnet_context     *ctx;
	struct dcerpc_pipe        *pipe;
	struct rpc_request        *req;
	struct composite_context  *rpcconn_req;
	struct samr_Connect       connect;
	struct samr_LookupDomain  lookup;
	struct samr_OpenDomain    open;
	struct samr_Close         close;
	struct libnet_RpcConnect  rpcconn;
	struct lsa_String         domain_name;
	uint32_t                  access_mask;
	struct policy_handle      connect_handle;
	struct policy_handle      domain_handle;
};


/**
 * Stage 0.5 (optional): Connect to samr rpc pipe
 */
static void domain_open_rpc_connect(struct composite_context *ctx)
{
	struct composite_context *c;
	struct domain_open_state *s;

	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct domain_open_state);

	c->status = libnet_RpcConnect_recv(ctx, s->ctx, c, &s->rpcconn);
	if (!composite_is_ok(c)) return;

	s->pipe = s->rpcconn.out.dcerpc_pipe;

	/* preparing parameters for samr_Connect rpc call */
	s->connect.in.system_name      = 0;
	s->connect.in.access_mask      = s->access_mask;
	s->connect.out.connect_handle  = &s->connect_handle;

	/* send request */
	s->req = dcerpc_samr_Connect_send(s->pipe, c, &s->connect);
	if (composite_nomem(s->req, c)) return;

	/* callback handler */
	s->req->async.callback = domain_open_handler;
	s->req->async.private  = c;
	s->stage = DOMOPEN_CONNECT;
}


/**
 * Stage 0.5 (optional): Close existing (in libnet context) domain
 * handle
 */
static NTSTATUS domain_open_close(struct composite_context *c,
				  struct domain_open_state *s)
{
	/* receive samr_Close reply */
	c->status = dcerpc_ndr_request_recv(s->req);
	NT_STATUS_NOT_OK_RETURN(c->status);

	/* reset domain handle and associated data in libnet_context */
	s->ctx->domain.name        = NULL;
	s->ctx->domain.access_mask = 0;
	ZERO_STRUCT(s->ctx->domain.handle);

	/* preparing parameters for samr_Connect rpc call */
	s->connect.in.system_name      = 0;
	s->connect.in.access_mask      = s->access_mask;
	s->connect.out.connect_handle  = &s->connect_handle;
	
	/* send request */
	s->req = dcerpc_samr_Connect_send(s->pipe, c, &s->connect);
	if (s->req == NULL) return NT_STATUS_NO_MEMORY;

	/* callback handler */
	s->req->async.callback = domain_open_handler;
	s->req->async.private  = c;
	s->stage = DOMOPEN_CONNECT;
	
	return NT_STATUS_OK;
}


/**
 * Stage 1: Connect to SAM server.
 */
static NTSTATUS domain_open_connect(struct composite_context *c,
				    struct domain_open_state *s)
{
	struct samr_LookupDomain *r = &s->lookup;

	/* receive samr_Connect reply */
	c->status = dcerpc_ndr_request_recv(s->req);
	NT_STATUS_NOT_OK_RETURN(c->status);

	/* prepare for samr_LookupDomain call */
	r->in.connect_handle = &s->connect_handle;
	r->in.domain_name    = &s->domain_name;

	s->req = dcerpc_samr_LookupDomain_send(s->pipe, c, r);
	if (s->req == NULL) goto failure;

	s->req->async.callback = domain_open_handler;
	s->req->async.private  = c;
	s->stage = DOMOPEN_LOOKUP;

	return NT_STATUS_OK;

failure:
	return NT_STATUS_UNSUCCESSFUL;
}


/**
 * Stage 2: Lookup domain by name.
 */
static NTSTATUS domain_open_lookup(struct composite_context *c,
				   struct domain_open_state *s)
{
	struct samr_OpenDomain *r = &s->open;

	/* receive samr_LookupDomain reply */
	c->status = dcerpc_ndr_request_recv(s->req);
	NT_STATUS_NOT_OK_RETURN(c->status);

	/* prepare for samr_OpenDomain call */
	r->in.connect_handle = &s->connect_handle;
	r->in.access_mask    = SEC_FLAG_MAXIMUM_ALLOWED;
	r->in.sid            = s->lookup.out.sid;
	r->out.domain_handle = &s->domain_handle;

	s->req = dcerpc_samr_OpenDomain_send(s->pipe, c, r);
	if (s->req == NULL) goto failure;

	s->req->async.callback = domain_open_handler;
	s->req->async.private  = c;
	s->stage = DOMOPEN_OPEN;

	return NT_STATUS_OK;

failure:
	return NT_STATUS_UNSUCCESSFUL;
}


/*
 * Stage 3: Open domain.
 */
static NTSTATUS domain_open_open(struct composite_context *c,
				 struct domain_open_state *s)
{
	/* receive samr_OpenDomain reply */
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
static void domain_open_handler(struct rpc_request *req)
{
	struct composite_context *c = req->async.private;
	struct domain_open_state *s = talloc_get_type(c->private_data, struct domain_open_state);

	/* Stages of the call */
	switch (s->stage) {
	case DOMOPEN_CONNECT:
		c->status = domain_open_connect(c, s);
		break;
	case DOMOPEN_LOOKUP:
		c->status = domain_open_lookup(c, s);
		break;
	case DOMOPEN_OPEN:
		c->status = domain_open_open(c, s);
		break;
	case DOMOPEN_CLOSE_EXISTING:
		c->status = domain_open_close(c, s);
		break;
	case DOMOPEN_RPC_CONNECT:
		/* this state shouldn't be handled here */
		c->status = NT_STATUS_UNSUCCESSFUL;
		break;
	}

	if (!NT_STATUS_IS_OK(c->status)) {
		c->state = COMPOSITE_STATE_ERROR;
	}

	if (c->state == COMPOSITE_STATE_DONE) {
		composite_done(c);
	}
}


/**
 * Sends asynchronous domain_open request
 *
 * @param ctx initialised libnet context
 * @param io arguments and results of the call
 * @param monitor pointer to monitor function that is passed monitor message
 */

struct composite_context *libnet_DomainOpen_send(struct libnet_context *ctx,
						 struct libnet_DomainOpen *io,
						 void (*monitor)(struct monitor_msg*))
{
	struct composite_context *c;
	struct domain_open_state *s;

	c = talloc_zero(ctx, struct composite_context);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct domain_open_state);
	if (composite_nomem(s, c)) return c;

	c->state        = COMPOSITE_STATE_IN_PROGRESS;
	c->private_data = s;
	c->event_ctx    = ctx->event_ctx;

	s->ctx                 = ctx;
	s->pipe                = ctx->samr_pipe;
	s->access_mask         = io->in.access_mask;
	s->domain_name.string  = io->in.domain_name;

	if (ctx->samr_pipe == NULL) {
		s->rpcconn.level           = LIBNET_RPC_CONNECT_DC;
		s->rpcconn.in.name         = io->in.domain_name;
		s->rpcconn.in.dcerpc_iface = &dcerpc_table_samr;

		s->rpcconn_req = libnet_RpcConnect_send(ctx, c, &s->rpcconn);
		if (composite_nomem(s->rpcconn_req, c)) return c;

		s->rpcconn_req->async.fn = domain_open_rpc_connect;
		s->rpcconn_req->async.private_data  = c;
		s->stage = DOMOPEN_RPC_CONNECT;

		return c;
	}

	/* libnet context's domain handle is not empty, so check out what
	   was opened first, before doing anything */
	if (!policy_handle_empty(&ctx->domain.handle)) {
		if (strequal(ctx->domain.name, io->in.domain_name) &&
		    ctx->domain.access_mask == io->in.access_mask) {

			/* this domain is already opened */
			composite_done(c);
			return c;

		} else {
			/* another domain or access rights have been
			   requested - close the existing handle first */
			s->close.in.handle = &ctx->domain.handle;

			/* send request to close domain handle */
			s->req = dcerpc_samr_Close_send(s->pipe, c, &s->close);
			if (composite_nomem(s->req, c)) return c;

			/* callback handler */
			s->req->async.callback = domain_open_handler;
			s->req->async.private  = c;
			s->stage = DOMOPEN_CLOSE_EXISTING;

			return c;
		}
	}

	/* preparing parameters for samr_Connect rpc call */
	s->connect.in.system_name      = 0;
	s->connect.in.access_mask      = s->access_mask;
	s->connect.out.connect_handle  = &s->connect_handle;
	
	/* send request */
	s->req = dcerpc_samr_Connect_send(s->pipe, c, &s->connect);
	if (composite_nomem(s->req, c)) return c;

	/* callback handler */
	s->req->async.callback = domain_open_handler;
	s->req->async.private  = c;
	s->stage = DOMOPEN_CONNECT;

	return c;
}


/**
 * Waits for and receives result of asynchronous domain_open call
 * 
 * @param c composite context returned by asynchronous domain_open call
 * @param ctx initialised libnet context
 * @param mem_ctx memory context of the call
 * @param io pointer to results (and arguments) of the call
 * @return nt status code of execution
 */

NTSTATUS libnet_DomainOpen_recv(struct composite_context *c, struct libnet_context *ctx,
				TALLOC_CTX *mem_ctx, struct libnet_DomainOpen *io)
{
	NTSTATUS status;
	struct domain_open_state *s;

	/* wait for results of sending request */
	status = composite_wait(c);
	
	if (NT_STATUS_IS_OK(status) && io) {
		s = talloc_get_type(c->private_data, struct domain_open_state);
		io->out.domain_handle = s->domain_handle;

		/* store the resulting handle and related data for use by other
		   libnet functions */
		ctx->domain.handle      = s->domain_handle;
		ctx->domain.name        = talloc_strdup(ctx, s->domain_name.string);
		ctx->domain.access_mask = s->access_mask;
	}

	talloc_free(c);
	return status;
}


/**
 * Synchronous version of domain_open call
 *
 * @param ctx initialised libnet context
 * @param mem_ctx memory context for the call
 * @param io arguments and results of the call
 * @return nt status code of execution
 */

NTSTATUS libnet_DomainOpen(struct libnet_context *ctx,
			   TALLOC_CTX *mem_ctx,
			   struct libnet_DomainOpen *io)
{
	struct composite_context *c = libnet_DomainOpen_send(ctx, io, NULL);
	return libnet_DomainOpen_recv(c, ctx, mem_ctx, io);
}
