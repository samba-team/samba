/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Volker Lendecke 2005
   
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
  a composite API for finding a DC and its name
*/

#include "includes.h"
#include "libcli/composite/composite.h"
#include "winbind/wb_async_helpers.h"

#include "librpc/gen_ndr/nbt.h"
#include "librpc/gen_ndr/samr.h"
#include "lib/messaging/irpc.h"
#include "librpc/gen_ndr/irpc.h"
#include "librpc/gen_ndr/ndr_irpc.h"

struct finddcs_state {
	struct wb_finddcs *io;
	struct composite_context *creq;

	struct nbtd_getdcname *r;
	struct irpc_request *ireq;
};

static void finddcs_getdc(struct irpc_request *ireq)
{
	struct composite_context *c = talloc_get_type(ireq->async.private,
						      struct composite_context);
	struct finddcs_state *state = talloc_get_type(c->private_data,
						      struct finddcs_state);

	c->status = irpc_call_recv(ireq);
	if (!NT_STATUS_IS_OK(c->status)) {
		goto done;
	}

	state->io->out.dcs[0].name = talloc_steal(state->io->out.dcs,
						  state->r->out.dcname);

	c->status = NT_STATUS_OK;
	c->state = COMPOSITE_STATE_DONE;

 done:
	if (!NT_STATUS_IS_OK(c->status)) {
		c->state = COMPOSITE_STATE_ERROR;
	}
		
	if (c->state >= COMPOSITE_STATE_DONE &&
	    c->async.fn) {
		c->async.fn(c);
	}
	talloc_free(ireq);
}

/*
  called when name resolution is finished
*/
static void finddcs_resolve(struct composite_context *res_ctx)
{
	struct composite_context *c = talloc_get_type(res_ctx->async.private_data,
						      struct composite_context);
	struct finddcs_state *state = talloc_get_type(c->private_data,
						      struct finddcs_state);
	uint32_t *nbt_servers;

	state->io->out.num_dcs = 1;
	state->io->out.dcs = talloc_array(state, struct nbt_dc_name,
					  state->io->out.num_dcs);
	if (state->io->out.dcs == NULL) {
		c->status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	c->status = resolve_name_recv(res_ctx, state->io->out.dcs,
				      &state->io->out.dcs[0].address);
	if (!NT_STATUS_IS_OK(c->status)) {
		goto done;
	}

	nbt_servers = irpc_servers_byname(state->io->in.msg_ctx, "nbt_server");
	if ((nbt_servers == NULL) || (nbt_servers[0] == 0)) {
		c->status = NT_STATUS_NO_LOGON_SERVERS;
		goto done;
	}

	state->r = talloc(state, struct nbtd_getdcname);
	if (state->r == NULL) {
		c->status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	state->r->in.domainname = talloc_strdup(state->r, lp_workgroup());
	state->r->in.ip_address = state->io->out.dcs[0].address;
	state->r->in.my_computername = lp_netbios_name();
	state->r->in.my_accountname = talloc_asprintf(state->r, "%s$",
						      lp_netbios_name());
	state->r->in.account_control = ACB_WSTRUST;
	state->r->in.domain_sid = secrets_get_domain_sid(state->r,
							 lp_workgroup());

	if ((state->r->in.domainname == NULL) ||
	    (state->r->in.my_accountname == NULL)) {
		DEBUG(0, ("talloc failed\n"));
		c->status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	if (state->r->in.domain_sid == NULL) {
		c->status = NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		goto done;
	}

	state->ireq = irpc_call_send(state->io->in.msg_ctx, nbt_servers[0],
				     &dcerpc_table_irpc, DCERPC_NBTD_GETDCNAME,
				     state->r, state);
	
	if (state->ireq == NULL) {
		c->status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	c->status = NT_STATUS_OK;
	state->ireq->async.fn = finddcs_getdc;
	state->ireq->async.private = c;

 done:
	if (!NT_STATUS_IS_OK(c->status)) {
		c->state = COMPOSITE_STATE_ERROR;
	}
		
	if (c->state >= COMPOSITE_STATE_DONE &&
	    c->async.fn) {
		c->async.fn(c);
	}
}

struct composite_context *wb_finddcs_send(struct wb_finddcs *io,
					  struct event_context *event_ctx)
{
	struct composite_context *c;
	struct finddcs_state *state;
	struct nbt_name name;

	c = talloc_zero(NULL, struct composite_context);
	if (c == NULL) goto failed;
	c->state = COMPOSITE_STATE_IN_PROGRESS;
	c->event_ctx = event_ctx;

	state = talloc(c, struct finddcs_state);
	if (state == NULL) goto failed;

	state->io = io;

	make_nbt_name(&name, io->in.domain, 0x1c);
	state->creq = resolve_name_send(&name, c->event_ctx,
					lp_name_resolve_order());

	if (state->creq == NULL) goto failed;
	state->creq->async.private_data = c;
	state->creq->async.fn = finddcs_resolve;
	c->private_data = state;

	return c;
failed:
	talloc_free(c);
	return NULL;
}

NTSTATUS wb_finddcs_recv(struct composite_context *c, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;

	status = composite_wait(c);

	if (NT_STATUS_IS_OK(status)) {
		struct finddcs_state *state = talloc_get_type(c->private_data,
							      struct finddcs_state);
		talloc_steal(mem_ctx, state->io->out.dcs);
	}

	talloc_free(c);
	return status;
}

NTSTATUS wb_finddcs(struct wb_finddcs *io, TALLOC_CTX *mem_ctx,
		    struct event_context *ev)
{
	struct composite_context *c = wb_finddcs_send(io, ev);
	return wb_finddcs_recv(c, mem_ctx);
}
