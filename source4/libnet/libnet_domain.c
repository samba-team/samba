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
  a composite function for domain handling on samr and lsa pipes
*/

#include "includes.h"
#include "libcli/composite/composite.h"
#include "libnet/libnet.h"
#include "librpc/gen_ndr/ndr_samr_c.h"
#include "librpc/gen_ndr/ndr_lsa_c.h"

static void domain_open_handler(struct rpc_request*);

enum domain_open_stage { DOMOPEN_CONNECT, DOMOPEN_LOOKUP, DOMOPEN_OPEN,
			 DOMOPEN_CLOSE_EXISTING, DOMOPEN_RPC_CONNECT };

struct domain_open_samr_state {
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

	/* information about the progress */
	void (*monitor_fn)(struct monitor_msg*);
};


/**
 * Stage 0.5 (optional): Connect to samr rpc pipe
 */
static void domain_open_rpc_connect(struct composite_context *ctx)
{
	struct composite_context *c;
	struct domain_open_samr_state *s;

	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct domain_open_samr_state);

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
				  struct domain_open_samr_state *s)
{
	/* receive samr_Close reply */
	c->status = dcerpc_ndr_request_recv(s->req);
	NT_STATUS_NOT_OK_RETURN(c->status);

	/* reset domain handle and associated data in libnet_context */
	s->ctx->samr.name        = NULL;
	s->ctx->samr.access_mask = 0;
	ZERO_STRUCT(s->ctx->samr.handle);

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
				    struct domain_open_samr_state *s)
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
				   struct domain_open_samr_state *s)
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
				 struct domain_open_samr_state *s)
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
	struct domain_open_samr_state *s = talloc_get_type(c->private_data,
							   struct domain_open_samr_state);

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
 * Sends asynchronous DomainOpenSamr request
 *
 * @param ctx initialised libnet context
 * @param io arguments and results of the call
 * @param monitor pointer to monitor function that is passed monitor message
 */

struct composite_context *libnet_DomainOpenSamr_send(struct libnet_context *ctx,
						     struct libnet_DomainOpen *io,
						     void (*monitor)(struct monitor_msg*))
{
	struct composite_context *c;
	struct domain_open_samr_state *s;

	c = composite_create(ctx, ctx->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct domain_open_samr_state);
	if (composite_nomem(s, c)) return c;

	c->private_data = s;
	s->monitor_fn   = monitor;

	s->ctx                 = ctx;
	s->pipe                = ctx->samr.pipe;
	s->access_mask         = io->in.access_mask;
	s->domain_name.string  = talloc_strdup(c, io->in.domain_name);

	/* check, if there's samr pipe opened already, before opening a domain */
	if (ctx->samr.pipe == NULL) {

		/* attempting to connect a domain controller */
		s->rpcconn.level           = LIBNET_RPC_CONNECT_DC;
		s->rpcconn.in.name         = io->in.domain_name;
		s->rpcconn.in.dcerpc_iface = &dcerpc_table_samr;
		
		/* send rpc pipe connect request */
		s->rpcconn_req = libnet_RpcConnect_send(ctx, c, &s->rpcconn);
		if (composite_nomem(s->rpcconn_req, c)) return c;

		s->rpcconn_req->async.fn = domain_open_rpc_connect;
		s->rpcconn_req->async.private_data  = c;
		s->stage = DOMOPEN_RPC_CONNECT;

		return c;
	}

	/* libnet context's domain handle is not empty, so check out what
	   was opened first, before doing anything */
	if (!policy_handle_empty(&ctx->samr.handle)) {
		if (strequal(ctx->samr.name, io->in.domain_name) &&
		    ctx->samr.access_mask == io->in.access_mask) {

			/* this domain is already opened */
			composite_done(c);
			return c;

		} else {
			/* another domain or access rights have been
			   requested - close the existing handle first */
			s->close.in.handle = &ctx->samr.handle;

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
 * Waits for and receives result of asynchronous DomainOpenSamr call
 * 
 * @param c composite context returned by asynchronous DomainOpen call
 * @param ctx initialised libnet context
 * @param mem_ctx memory context of the call
 * @param io pointer to results (and arguments) of the call
 * @return nt status code of execution
 */

NTSTATUS libnet_DomainOpenSamr_recv(struct composite_context *c, struct libnet_context *ctx,
				    TALLOC_CTX *mem_ctx, struct libnet_DomainOpen *io)
{
	NTSTATUS status;
	struct domain_open_samr_state *s;

	/* wait for results of sending request */
	status = composite_wait(c);
	
	if (NT_STATUS_IS_OK(status) && io) {
		s = talloc_get_type(c->private_data, struct domain_open_samr_state);
		io->out.domain_handle = s->domain_handle;

		/* store the resulting handle and related data for use by other
		   libnet functions */
		ctx->samr.handle      = s->domain_handle;
		ctx->samr.name        = talloc_steal(ctx, s->domain_name.string);
		ctx->samr.access_mask = s->access_mask;
	}

	talloc_free(c);
	return status;
}


struct domain_open_lsa_state {
	const char *name;
	uint32_t access_mask;
	struct libnet_context *ctx;
	struct libnet_RpcConnect rpcconn;
	struct lsa_OpenPolicy2   openpol;
	struct policy_handle handle;
	struct dcerpc_pipe *pipe;

	/* information about the progress */
	void (*monitor_fn)(struct monitor_msg*);
};


static void continue_rpc_connect_lsa(struct composite_context *ctx);
static void continue_lsa_policy_open(struct rpc_request *req);


/**
 * Sends asynchronous DomainOpenLsa request
 *
 * @param ctx initialised libnet context
 * @param io arguments and results of the call
 * @param monitor pointer to monitor function that is passed monitor message
 */

struct composite_context* libnet_DomainOpenLsa_send(struct libnet_context *ctx,
						    struct libnet_DomainOpen *io,
						    void (*monitor)(struct monitor_msg*))
{
	struct composite_context *c;
	struct domain_open_lsa_state *s;
	struct composite_context *rpcconn_req;
	struct rpc_request *openpol_req;
	struct lsa_QosInfo *qos;

	/* create composite context and state */
	c = composite_create(ctx, ctx->event_ctx);
	if (c == NULL) return c;

	s = talloc_zero(c, struct domain_open_lsa_state);
	if (composite_nomem(s, c)) return c;

	c->private_data = s;

	/* store arguments in the state structure */
	s->name         = talloc_strdup(c, io->in.domain_name);
	s->access_mask  = io->in.access_mask;
	s->ctx          = ctx;

	/* check, if there's lsa pipe opened already, before opening a handle */
	if (ctx->lsa.pipe == NULL) {

		/* attempting to connect a domain controller */
		s->rpcconn.level           = LIBNET_RPC_CONNECT_DC;
		s->rpcconn.in.name         = talloc_strdup(c, io->in.domain_name);
		s->rpcconn.in.dcerpc_iface = &dcerpc_table_lsarpc;
		
		/* send rpc pipe connect request */
		rpcconn_req = libnet_RpcConnect_send(ctx, c, &s->rpcconn);
		if (composite_nomem(rpcconn_req, c)) return c;

		composite_continue(c, rpcconn_req, continue_rpc_connect_lsa, c);
		return c;
	}

	s->pipe = ctx->lsa.pipe;

	/* preparing parameters for lsa_OpenPolicy2 rpc call */
	s->openpol.in.system_name = s->name;
	s->openpol.in.access_mask = s->access_mask;
	s->openpol.in.attr        = talloc_zero(c, struct lsa_ObjectAttribute);

	qos = talloc_zero(c, struct lsa_QosInfo);
	qos->len                 = 0;
	qos->impersonation_level = 2;
	qos->context_mode        = 1;
	qos->effective_only      = 0;

	s->openpol.in.attr->sec_qos = qos;
	s->openpol.out.handle       = &s->handle;
	
	/* send rpc request */
	openpol_req = dcerpc_lsa_OpenPolicy2_send(s->pipe, c, &s->openpol);
	if (composite_nomem(openpol_req, c)) return c;

	composite_continue_rpc(c, openpol_req, continue_lsa_policy_open, c);
	return c;
}


/*
  Stage 0.5 (optional): Rpc pipe connected, send lsa open policy request
 */
static void continue_rpc_connect_lsa(struct composite_context *ctx)
{
	struct composite_context *c;
	struct domain_open_lsa_state *s;
	struct lsa_QosInfo *qos;
	struct rpc_request *openpol_req;

	c = talloc_get_type(ctx->async.private_data, struct composite_context);
	s = talloc_get_type(c->private_data, struct domain_open_lsa_state);

	/* receive rpc connection */
	c->status = libnet_RpcConnect_recv(ctx, s->ctx, c, &s->rpcconn);
	if (!composite_is_ok(c)) return;

	/* RpcConnect function leaves the pipe in libnet context,
	   so get it from there */
	s->pipe = s->ctx->lsa.pipe;

	/* prepare lsa_OpenPolicy2 call */
	s->openpol.in.system_name = s->name;
	s->openpol.in.access_mask = s->access_mask;
	s->openpol.in.attr        = talloc_zero(c, struct lsa_ObjectAttribute);

	qos = talloc_zero(c, struct lsa_QosInfo);
	qos->len                 = 0;
	qos->impersonation_level = 2;
	qos->context_mode        = 1;
	qos->effective_only      = 0;

	s->openpol.in.attr->sec_qos = qos;
	s->openpol.out.handle       = &s->handle;

	/* send rpc request */
	openpol_req = dcerpc_lsa_OpenPolicy2_send(s->pipe, c, &s->openpol);
	if (composite_nomem(openpol_req, c)) return;

	composite_continue_rpc(c, openpol_req, continue_lsa_policy_open, c);
}


/*
  Stage 1: Lsa policy opened - we're done, if successfully
 */
static void continue_lsa_policy_open(struct rpc_request *req)
{
	struct composite_context *c;
	struct domain_open_lsa_state *s;

	c = talloc_get_type(req->async.private, struct composite_context);
	s = talloc_get_type(c->private_data, struct domain_open_lsa_state);

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;

	composite_done(c);
}


/**
 * Receives result of asynchronous DomainOpenLsa call
 *
 * @param c composite context returned by asynchronous DomainOpenLsa call
 * @param ctx initialised libnet context
 * @param mem_ctx memory context of the call
 * @param io pointer to results (and arguments) of the call
 * @return nt status code of execution
 */

NTSTATUS libnet_DomainOpenLsa_recv(struct composite_context *c, struct libnet_context *ctx,
				   TALLOC_CTX *mem_ctx, struct libnet_DomainOpen *io)
{
	NTSTATUS status;
	struct domain_open_lsa_state *s;

	status = composite_wait(c);

	if (NT_STATUS_IS_OK(status) && io) {
		/* everything went fine - get the results and
		   return the error string */
		s = talloc_get_type(c->private_data, struct domain_open_lsa_state);
		io->out.domain_handle = s->handle;

		ctx->lsa.handle      = s->handle;
		ctx->lsa.name        = talloc_steal(ctx, s->name);
		ctx->lsa.access_mask = s->access_mask;
		
		io->out.error_string = talloc_strdup(mem_ctx, "Success");

	} else if (!NT_STATUS_IS_OK(status)) {
		/* there was an error, so provide nt status code description */
		io->out.error_string = talloc_asprintf(mem_ctx,
						       "Failed to open domain: %s",
						       nt_errstr(status));
	}

	talloc_free(c);
	return status;
}


/**
 * Sends a request to open a domain in desired service
 *
 * @param ctx initalised libnet context
 * @param io arguments and results of the call
 * @param monitor pointer to monitor function that is passed monitor message
 */

struct composite_context* libnet_DomainOpen_send(struct libnet_context *ctx,
						 struct libnet_DomainOpen *io,
						 void (*monitor)(struct monitor_msg*))
{
	struct composite_context *c;

	switch (io->in.type) {
	case DOMAIN_LSA:
		/* reques to open a policy handle on \pipe\lsarpc */
		c = libnet_DomainOpenLsa_send(ctx, io, monitor);
		break;

	case DOMAIN_SAMR:
	default:
		/* request to open a domain policy handle on \pipe\samr */
		c = libnet_DomainOpenSamr_send(ctx, io, monitor);
		break;
	}

	return c;
}


/**
 * Receive result of domain open request
 *
 * @param c composite context returned by DomainOpen_send function
 * @param ctx initialised libnet context
 * @param mem_ctx memory context of the call
 * @param io results and arguments of the call
 */

NTSTATUS libnet_DomainOpen_recv(struct composite_context *c, struct libnet_context *ctx,
				TALLOC_CTX *mem_ctx, struct libnet_DomainOpen *io)
{
	NTSTATUS status;

	switch (io->in.type) {
	case DOMAIN_LSA:
		status = libnet_DomainOpenLsa_recv(c, ctx, mem_ctx, io);
		break;

	case DOMAIN_SAMR:
	default:
		status = libnet_DomainOpenSamr_recv(c, ctx, mem_ctx, io);
		break;
	}
	
	return status;
}


/**
 * Synchronous version of DomainOpen call
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


struct domain_close_lsa_state {
	struct dcerpc_pipe *pipe;
	struct lsa_Close close;
	struct policy_handle handle;

	void (*monitor_fn)(struct monitor_msg*);
};


static void continue_lsa_close(struct rpc_request *req);


struct composite_context* libnet_DomainCloseLsa_send(struct libnet_context *ctx,
						     struct libnet_DomainClose *io,
						     void (*monitor)(struct monitor_msg*))
{
	struct composite_context *c;
	struct domain_close_lsa_state *s;
	struct rpc_request *close_req;

	/* composite context and state structure allocation */
	c = composite_create(ctx, ctx->event_ctx);
	if (c == NULL) return c;

	s = talloc_zero(c, struct domain_close_lsa_state);
	if (composite_nomem(s, c)) return c;

	c->private_data = s;
	s->monitor_fn   = monitor;

	/* TODO: check if lsa pipe pointer is non-null */

	if (!strequal(ctx->lsa.name, io->in.domain_name)) {
		composite_error(c, NT_STATUS_INVALID_PARAMETER);
		return c;
	}

	/* get opened lsarpc pipe pointer */
	s->pipe = ctx->lsa.pipe;
	
	/* prepare close handle call arguments */
	s->close.in.handle  = &ctx->lsa.handle;
	s->close.out.handle = &s->handle;

	/* send the request */
	close_req = dcerpc_lsa_Close_send(s->pipe, c, &s->close);
	if (composite_nomem(close_req, c)) return c;

	composite_continue_rpc(c, close_req, continue_lsa_close, c);
	return c;
}


/*
  Stage 1: Receive result of lsa close call
*/
static void continue_lsa_close(struct rpc_request *req)
{
	struct composite_context *c;
	struct domain_close_lsa_state *s;
	
	c = talloc_get_type(req->async.private, struct composite_context);
	s = talloc_get_type(c->private_data, struct domain_close_lsa_state);

	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;

	composite_done(c);
}


NTSTATUS libnet_DomainCloseLsa_recv(struct composite_context *c, struct libnet_context *ctx,
				    TALLOC_CTX *mem_ctx, struct libnet_DomainClose *io)
{
	NTSTATUS status;

	status = composite_wait(c);

	if (NT_STATUS_IS_OK(status) && io) {
		/* policy handle closed successfully */

		ctx->lsa.name = NULL;
		ZERO_STRUCT(ctx->lsa.handle);

		io->out.error_string = talloc_asprintf(mem_ctx, "Success");

	} else if (!NT_STATUS_IS_OK(status)) {
		/* there was an error, so return description of the status code */
		io->out.error_string = talloc_asprintf(mem_ctx, "Error: %s", nt_errstr(status));
	}

	talloc_free(c);
	return status;
}


struct domain_close_samr_state {
	struct samr_Close close;
	struct policy_handle handle;
	
	void (*monitor_fn)(struct monitor_msg*);
};


static void continue_samr_close(struct rpc_request *req);


struct composite_context* libnet_DomainCloseSamr_send(struct libnet_context *ctx,
						      struct libnet_DomainClose *io,
						      void (*monitor)(struct monitor_msg*))
{
	struct composite_context *c;
	struct domain_close_samr_state *s;
	struct rpc_request *close_req;

	/* composite context and state structure allocation */
	c = composite_create(ctx, ctx->event_ctx);
	if (c == NULL) return c;

	s = talloc_zero(c, struct domain_close_samr_state);
	if (composite_nomem(s, c)) return c;

	c->private_data = s;
	s->monitor_fn   = monitor;

	/* TODO: check if samr pipe pointer is non-null */

	if (!strequal(ctx->samr.name, io->in.domain_name)) {
		composite_error(c, NT_STATUS_INVALID_PARAMETER);
		return c;
	}

	/* prepare close domain handle call arguments */
	ZERO_STRUCT(s->close);
	s->close.in.handle  = &ctx->samr.handle;
	s->close.out.handle = &s->handle;

	/* send the request */
	close_req = dcerpc_samr_Close_send(ctx->samr.pipe, ctx, &s->close);
	if (composite_nomem(close_req, c)) return c;

	composite_continue_rpc(c, close_req, continue_samr_close, c);
	return c;
}


/*
  Stage 1: Receive result of samr close call
*/
static void continue_samr_close(struct rpc_request *req)
{
	struct composite_context *c;
	struct domain_close_samr_state *s;

	c = talloc_get_type(req->async.private, struct composite_context);
	s = talloc_get_type(c->private_data, struct domain_close_samr_state);
	
	c->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(c)) return;
	
	composite_done(c);
}


NTSTATUS libnet_DomainCloseSamr_recv(struct composite_context *c, struct libnet_context *ctx,
				     TALLOC_CTX *mem_ctx, struct libnet_DomainClose *io)
{
	NTSTATUS status;

	status = composite_wait(c);

	if (NT_STATUS_IS_OK(status) && io) {
		/* domain policy handle closed successfully */

		ZERO_STRUCT(ctx->samr.handle);
		ctx->samr.name = NULL;

		io->out.error_string = talloc_asprintf(mem_ctx, "Success");

	} else if (!NT_STATUS_IS_OK(status)) {
		/* there was an error, so return description of the status code */
		io->out.error_string = talloc_asprintf(mem_ctx, "Error: %s", nt_errstr(status));
	}

	talloc_free(c);
	return status;
}


struct composite_context* libnet_DomainClose_send(struct libnet_context *ctx,
						  struct libnet_DomainClose *io,
						  void (*monitor)(struct monitor_msg*))
{
	struct composite_context *c;

	switch (io->in.type) {
	case DOMAIN_LSA:
		/* request to close policy handle on \pipe\lsarpc */
		c = libnet_DomainCloseLsa_send(ctx, io, monitor);
		break;

	case DOMAIN_SAMR:
	default:
		/* request to close domain policy handle on \pipe\samr */
		c = libnet_DomainCloseSamr_send(ctx, io, monitor);
		break;
	}
	
	return c;
}


NTSTATUS libnet_DomainClose_recv(struct composite_context *c, struct libnet_context *ctx,
				 TALLOC_CTX *mem_ctx, struct libnet_DomainClose *io)
{
	NTSTATUS status;

	switch (io->in.type) {
	case DOMAIN_LSA:
		/* receive result of closing lsa policy handle */
		status = libnet_DomainCloseLsa_recv(c, ctx, mem_ctx, io);
		break;

	case DOMAIN_SAMR:
	default:
		/* receive result of closing samr domain policy handle */
		status = libnet_DomainCloseSamr_recv(c, ctx, mem_ctx, io);
		break;
	}
	
	return status;
}


NTSTATUS libnet_DomainClose(struct libnet_context *ctx, TALLOC_CTX *mem_ctx,
			    struct libnet_DomainClose *io)
{
	struct composite_context *c;
	
	c = libnet_DomainClose_send(ctx, io, NULL);
	return libnet_DomainClose_recv(c, ctx, mem_ctx, io);
}
