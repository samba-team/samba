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
  a composite function for domain handling
*/

#include "includes.h"
#include "libcli/composite/composite.h"
#include "libnet/composite.h"

static void domain_open_handler(struct rpc_request*);

enum domain_open_stage { DOMOPEN_CONNECT, DOMOPEN_LOOKUP, DOMOPEN_OPEN };

struct domain_open_state {
	enum domain_open_stage    stage;
	struct dcerpc_pipe        *pipe;
	struct rpc_request        *req;
	struct samr_Connect       connect;
	struct samr_LookupDomain  lookup;
	struct samr_OpenDomain    open;
	struct lsa_String         domain_name;
	uint32_t                  access_mask;
	struct policy_handle      connect_handle;
	struct policy_handle      domain_handle;
};


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
	}

	if (!NT_STATUS_IS_OK(c->status)) {
		c->state = COMPOSITE_STATE_ERROR;
	}
}


/**
 * Sends asynchronous domain_open request
 *
 * @param p dce/rpc call pipe 
 * @param io arguments and results of the call
 */
struct composite_context *libnet_rpc_domain_open_send(struct dcerpc_pipe *p,
						      struct libnet_rpc_domain_open *io,
						      void (*monitor)(struct monitor_msg*))
{
	struct composite_context *c;
	struct domain_open_state *s;

	c = talloc_zero(p, struct composite_context);
	if (c == NULL) goto failure;

	s = talloc_zero(c, struct domain_open_state);
	if (s == NULL) goto failure;

	c->state       = COMPOSITE_STATE_IN_PROGRESS;
	c->private_data= s;
	c->event_ctx   = dcerpc_event_context(p);

	s->pipe                = p;
	s->access_mask         = io->in.access_mask;
	s->domain_name.string  = io->in.domain_name;

	/* preparing parameters to send rpc request */
	s->connect.in.system_name      = 0;
	s->connect.in.access_mask      = s->access_mask;
	s->connect.out.connect_handle  = &s->connect_handle;
	
	/* send request */
	s->req = dcerpc_samr_Connect_send(p, c, &s->connect);

	/* callback handler */
	s->req->async.callback = domain_open_handler;
	s->req->async.private  = c;
	s->stage = DOMOPEN_CONNECT;

	return c;

failure:
	talloc_free(c);
	return NULL;
}


/**
 * Waits for and receives result of asynchronous domain_open call
 * 
 * @param c composite context returned by asynchronous domain_open call
 * @param mem_ctx memory context of the call
 * @param io pointer to results (and arguments) of the call
 * @return nt status code of execution
 */
NTSTATUS libnet_rpc_domain_open_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
				     struct libnet_rpc_domain_open *io)
{
	NTSTATUS status;
	struct domain_open_state *s;

	/* wait for results of sending request */
	status = composite_wait(c);
	
	if (NT_STATUS_IS_OK(status) && io) {
		s = talloc_get_type(c->private_data, struct domain_open_state);
		io->out.domain_handle = s->domain_handle;
	}

	talloc_free(c);
	return status;
}


/**
 * Synchronous version of domain_open call
 *
 * @param pipe dce/rpc call pipe
 * @param mem_ctx memory context for the call
 * @param io arguments and results of the call
 * @return nt status code of execution
 */
NTSTATUS libnet_rpc_domain_open(struct dcerpc_pipe *p,
				TALLOC_CTX *mem_ctx,
				struct libnet_rpc_domain_open *io)
{
	struct composite_context *c = libnet_rpc_domain_open_send(p, io, NULL);
	return libnet_rpc_domain_open_recv(c, mem_ctx, io);
}
