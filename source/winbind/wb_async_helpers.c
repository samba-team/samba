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
#include "libcli/raw/libcliraw.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "libcli/auth/credentials.h"

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

struct get_schannel_creds_state {
	struct composite_context *ctx;
	struct dcerpc_pipe *p;
	struct wb_get_schannel_creds *io;
	struct netr_ServerReqChallenge *r;

	struct creds_CredentialState creds_state;
	struct netr_Credential netr_cred;
	uint32_t negotiate_flags;
	struct netr_ServerAuthenticate2 *a;
};

static void get_schannel_creds_recv_auth(struct rpc_request *req);
static void get_schannel_creds_recv_chal(struct rpc_request *req);
static void get_schannel_creds_recv_pipe(struct composite_context *ctx);

struct composite_context *wb_get_schannel_creds_send(struct wb_get_schannel_creds *io,
						     struct event_context *ev)
{
	struct composite_context *result, *ctx;
	struct get_schannel_creds_state *state;

	result = talloc_zero(NULL, struct composite_context);
	if (result == NULL) goto failed;
	result->state = COMPOSITE_STATE_IN_PROGRESS;
	result->event_ctx = ev;

	state = talloc(result, struct get_schannel_creds_state);
	if (state == NULL) goto failed;
	result->private_data = state;

	state->io = io;

	state->p = dcerpc_pipe_init(state, ev);
	if (state->p == NULL) goto failed;

	ctx = dcerpc_pipe_open_smb_send(state->p->conn, state->io->in.tree,
					"\\netlogon");
	if (ctx == NULL) goto failed;

	ctx->async.fn = get_schannel_creds_recv_pipe;
	ctx->async.private_data = state;
	state->ctx = result;
	return result;

 failed:
	talloc_free(result);
	return NULL;
}

static void get_schannel_creds_recv_pipe(struct composite_context *ctx)
{
	struct get_schannel_creds_state *state =
		talloc_get_type(ctx->async.private_data,
				struct get_schannel_creds_state);
	struct rpc_request *req;

	state->ctx->status = dcerpc_pipe_open_smb_recv(ctx);
	if (!NT_STATUS_IS_OK(state->ctx->status)) goto done;

	state->ctx->status = dcerpc_bind_auth_none(state->p,
						   DCERPC_NETLOGON_UUID,
						   DCERPC_NETLOGON_VERSION);
	if (!NT_STATUS_IS_OK(state->ctx->status)) goto done;

	state->r = talloc(state, struct netr_ServerReqChallenge);
	if (state->r == NULL) {
		state->ctx->status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	state->r->in.computer_name =
		cli_credentials_get_workstation(state->io->in.creds);
	state->r->in.server_name =
		talloc_asprintf(state->r, "\\\\%s",
				dcerpc_server_name(state->p));
	state->r->in.credentials = talloc(state->r, struct netr_Credential);
	state->r->out.credentials = talloc(state->r, struct netr_Credential);

	if ((state->r->in.server_name == NULL) ||
	    (state->r->in.credentials == NULL) ||
	    (state->r->out.credentials == NULL)) {
		state->ctx->status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	generate_random_buffer(state->r->in.credentials->data,
			       sizeof(state->r->in.credentials->data));

	req = dcerpc_netr_ServerReqChallenge_send(state->p, state, state->r);
	if (req == NULL) {
		state->ctx->status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	req->async.callback = get_schannel_creds_recv_chal;
	req->async.private = state;
	return;

 done:
	if (!NT_STATUS_IS_OK(state->ctx->status)) {
		state->ctx->state = COMPOSITE_STATE_ERROR;
	}
	if ((state->ctx->state >= COMPOSITE_STATE_DONE) &&
	    (state->ctx->async.fn != NULL)) {
		state->ctx->async.fn(state->ctx);
	}
}

static void get_schannel_creds_recv_chal(struct rpc_request *req)
{
	struct get_schannel_creds_state *state =
		talloc_get_type(req->async.private,
				struct get_schannel_creds_state);
	const struct samr_Password *mach_pwd;

	state->ctx->status = dcerpc_ndr_request_recv(req);
	if (!NT_STATUS_IS_OK(state->ctx->status)) goto done;
	state->ctx->status = state->r->out.result;
	if (!NT_STATUS_IS_OK(state->ctx->status)) goto done;

	mach_pwd = cli_credentials_get_nt_hash(state->io->in.creds, state);
	if (mach_pwd == NULL) {
		state->ctx->status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	state->negotiate_flags = NETLOGON_NEG_AUTH2_FLAGS;

	creds_client_init(&state->creds_state, state->r->in.credentials,
			  state->r->out.credentials, mach_pwd,
			  &state->netr_cred, state->negotiate_flags);

	state->a = talloc(state, struct netr_ServerAuthenticate2);
	if (state->a == NULL) {
		state->ctx->status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	state->a->in.server_name =
		talloc_reference(state->a, state->r->in.server_name);
	state->a->in.account_name =
		cli_credentials_get_username(state->io->in.creds);
	state->a->in.secure_channel_type =
		cli_credentials_get_secure_channel_type(state->io->in.creds);
	state->a->in.computer_name =
		cli_credentials_get_workstation(state->io->in.creds);
	state->a->in.negotiate_flags = &state->negotiate_flags;
	state->a->out.negotiate_flags = &state->negotiate_flags;
	state->a->in.credentials = &state->netr_cred;
	state->a->out.credentials = &state->netr_cred;

	req = dcerpc_netr_ServerAuthenticate2_send(state->p, state, state->a);
	if (req == NULL) {
		state->ctx->status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	req->async.callback = get_schannel_creds_recv_auth;
	req->async.private = state;
	return;

	state->io->out.netlogon = state->p;
	state->ctx->state = COMPOSITE_STATE_DONE;

 done:
	if (!NT_STATUS_IS_OK(state->ctx->status)) {
		state->ctx->state = COMPOSITE_STATE_ERROR;
	}
	if ((state->ctx->state >= COMPOSITE_STATE_DONE) &&
	    (state->ctx->async.fn != NULL)) {
		state->ctx->async.fn(state->ctx);
	}
}

static void get_schannel_creds_recv_auth(struct rpc_request *req)
{
	struct get_schannel_creds_state *state =
		talloc_get_type(req->async.private,
				struct get_schannel_creds_state);

	state->ctx->status = dcerpc_ndr_request_recv(req);
	DEBUG(5, ("result: %s\n", nt_errstr(state->ctx->status)));
	if (!NT_STATUS_IS_OK(state->ctx->status)) goto done;
	state->ctx->status = state->a->out.result;
	DEBUG(5, ("result: %s\n", nt_errstr(state->ctx->status)));
	if (!NT_STATUS_IS_OK(state->ctx->status)) goto done;

	state->ctx->state = COMPOSITE_STATE_DONE;

 done:
	if (!NT_STATUS_IS_OK(state->ctx->status)) {
		state->ctx->state = COMPOSITE_STATE_ERROR;
	}
	if ((state->ctx->state >= COMPOSITE_STATE_DONE) &&
	    (state->ctx->async.fn != NULL)) {
		state->ctx->async.fn(state->ctx);
	}
}

NTSTATUS wb_get_schannel_creds_recv(struct composite_context *c,
				    TALLOC_CTX *mem_ctx)
{
	NTSTATUS status = composite_wait(c);
	struct get_schannel_creds_state *state =
		talloc_get_type(c->private_data,
				struct get_schannel_creds_state);
	state->io->out.netlogon = talloc_steal(mem_ctx, state->p);
	talloc_free(c);
	return status;
}

NTSTATUS wb_get_schannel_creds(struct wb_get_schannel_creds *io,
			       TALLOC_CTX *mem_ctx,
			       struct event_context *ev)
{
	struct composite_context *c = wb_get_schannel_creds_send(io, ev);
	return wb_get_schannel_creds_recv(c, mem_ctx);
}
