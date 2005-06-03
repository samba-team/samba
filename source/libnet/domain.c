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

static void domain_open_handler(struct rpc_request*);

enum domain_open_stage { DOMOPEN_CONNECT, DOMOPEN_LOOKUP, DOMOPEN_OPEN };

struct domain_open_state {
	enum domain_open_stage    stage;
	struct dcerpc_pipe        *pipe;
	struct rpc_request        *req;
	struct samr_Connect       connect;
	struct samr_LookupDomain  lookup;
	struct samr_OpenDomain    open;
	uint32_t                  access_mask;
	struct policy_handle      domain_handle;
};


static void domain_open_handler(struct rpc_request *req)
{
	struct composite_context *c = req->async.private;
	struct domain_open_state *s = talloc_get_type(c->private, struct domain_open_state);
	struct monitor_msg msg;

	/* Stages of the call */
	switch (s->stage) {
	case DOMOPEN_CONNECT:
		break;
	case DOMOPEN_LOOKUP:
		break;
	case DOMOPEN_OPEN:
		break;
	}

	if (!NT_STATUS_IS_OK(c->status)) {
		c->state = SMBCLI_REQUEST_ERROR;
	}

	if (c->monitor_fn) {
		c->monitor_fn(&msg);
	}
}


struct composite_context *rpc_composite_domain_open_send(struct dcerpc_pipe *p,
							 struct rpc_composite_domain_open *io,
							 void (*monitor)(struct monitor_msg*))
{
	struct composite_context *c;
	struct domain_open_state *s;

	c = talloc_zero(p, struct composite_context);
	if (c == NULL) goto failure;

	s = talloc_zero(c, struct domain_open_state);
	if (c == NULL) goto failure;

	s->access_mask = io->in.access_mask;

	c->state       = SMBCLI_REQUEST_SEND;
	c->private     = s;
	c->event_ctx   = dcerpc_event_context(p);
	c->monitor_fn  = monitor;

	/* preparing parameters to send rpc request */
	s->connect.in.system_name = 0;
	s->connect.in.access_mask = s->access_mask;
	
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
