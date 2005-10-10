/* 
   Unix SMB/CIFS implementation.

   A composite API for initializing a domain

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

#include "includes.h"
#include "libcli/composite/composite.h"
#include "libcli/smb_composite/smb_composite.h"
#include "winbind/wb_async_helpers.h"
#include "winbind/wb_server.h"
#include "smbd/service_stream.h"

#include "librpc/gen_ndr/nbt.h"
#include "librpc/gen_ndr/samr.h"
#include "lib/messaging/irpc.h"
#include "librpc/gen_ndr/irpc.h"
#include "librpc/gen_ndr/ndr_irpc.h"
#include "libcli/raw/libcliraw.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "librpc/gen_ndr/ndr_lsa.h"
#include "libcli/auth/credentials.h"


/*
 * Initialize a domain:
 *
 * - With schannel credentials, try to open the SMB connection with the
 *   machine creds. This works against W2k3SP1 with an NTLMSSP session
 *   setup. Fall back to anonymous.
 *
 * - If we have schannel creds, do the auth2 and open the schannel'ed netlogon
 *   pipe.
 *
 * - Open LSA. If we have machine creds, try to open with ntlmssp. Fall back
 *   to schannel and then to anon bind.
 *
 * - With queryinfopolicy, verify that we're talking to the right domain
 *
 * A bit complex, but with all the combinations I think it's the best we can
 * get. NT4, W2k3 and W2k all have different combinations, but in the end we
 * have a signed&sealed lsa connection on all of them.
 *
 * Not sure if it is overkill, but it seems to work.
 */

struct init_domain_state {
	struct composite_context *ctx;
	struct wbsrv_domain *domain;

	int num_dcs;
	struct nbt_dc_name *dcs;

	struct smb_composite_connect conn;

	struct dcerpc_pipe *auth2_pipe;
	struct dcerpc_pipe *netlogon_pipe;

	struct dcerpc_pipe *lsa_pipe;
	struct policy_handle *lsa_policy;

	struct lsa_QueryInfoPolicy queryinfo;
};

static void init_domain_recv_dcs(struct composite_context *ctx);
static void init_domain_recv_tree(struct composite_context *ctx);
static void init_domain_recv_netlogoncreds(struct composite_context *ctx);
static void init_domain_recv_netlogonpipe(struct composite_context *ctx);
static void init_domain_recv_lsa(struct composite_context *ctx);
static void init_domain_recv_queryinfo(struct rpc_request *req);

struct composite_context *wb_init_domain_send(struct wbsrv_domain *domain,
					      struct event_context *event_ctx,
					      struct messaging_context *msg_ctx)
{
	struct composite_context *result, *ctx;
	struct init_domain_state *state;

	result = talloc(domain, struct composite_context);
	if (result == NULL) goto failed;
	result->state = COMPOSITE_STATE_IN_PROGRESS;
	result->async.fn = NULL;
	result->event_ctx = event_ctx;

	state = talloc_zero(result, struct init_domain_state);
	if (state == NULL) goto failed;
	state->ctx = result;
	result->private_data = state;

	state->domain = domain;

	if (state->domain->schannel_creds != NULL) {
		talloc_free(state->domain->schannel_creds);
	}

	state->domain->schannel_creds = cli_credentials_init(state->domain);
	if (state->domain->schannel_creds == NULL) goto failed;
	cli_credentials_set_conf(state->domain->schannel_creds);
	state->ctx->status =
		cli_credentials_set_machine_account(state->domain->
						    schannel_creds);
	if (!NT_STATUS_IS_OK(state->ctx->status)) goto failed;

	ctx = wb_finddcs_send(domain->name, domain->sid, event_ctx, msg_ctx);
	if (ctx == NULL) goto failed;

	ctx->async.fn = init_domain_recv_dcs;
	ctx->async.private_data = state;
	return result;

 failed:
	talloc_free(result);
	return NULL;
}

static void init_domain_recv_dcs(struct composite_context *ctx)
{
	struct init_domain_state *state =
		talloc_get_type(ctx->async.private_data,
				struct init_domain_state);

	state->ctx->status = wb_finddcs_recv(ctx, state, &state->num_dcs,
					     &state->dcs);
	if (!composite_is_ok(state->ctx)) return;

	if (state->num_dcs < 1) {
		composite_error(state->ctx, NT_STATUS_NO_LOGON_SERVERS);
		return;
	}

	state->conn.in.dest_host = state->dcs[0].address;
	state->conn.in.port = 0;
	state->conn.in.called_name = state->dcs[0].name;
	state->conn.in.service = "IPC$";
	state->conn.in.service_type = "IPC";
	state->conn.in.workgroup = state->domain->name;

	state->conn.in.credentials = state->domain->schannel_creds;

	if (state->conn.in.credentials == NULL) {
		state->conn.in.credentials = cli_credentials_init(state);
		if (composite_nomem(state->conn.in.credentials, state->ctx)) {
			return;
		}
		cli_credentials_set_conf(state->conn.in.credentials);
		cli_credentials_set_anonymous(state->conn.in.credentials);
	}
		
	state->conn.in.fallback_to_anonymous = True;

	ctx = smb_composite_connect_send(&state->conn, state,
					 state->ctx->event_ctx);
	composite_continue(state->ctx, ctx, init_domain_recv_tree, state);
}

static void init_domain_recv_tree(struct composite_context *ctx)
{
	struct init_domain_state *state =
		talloc_get_type(ctx->async.private_data,
				struct init_domain_state);

	state->ctx->status = smb_composite_connect_recv(ctx, state);
	if (!composite_is_ok(state->ctx)) return;

	if (state->domain->schannel_creds == NULL) {
		/* No chance to open netlogon */
		ctx = wb_connect_lsa_send(state->conn.out.tree, NULL);
		composite_continue(state->ctx, ctx,
				   init_domain_recv_lsa, state);
		return;
	}

	ctx = wb_get_schannel_creds_send(state->domain->schannel_creds,
					 state->conn.out.tree,
					 state->ctx->event_ctx);
	composite_continue(state->ctx, ctx,
			   init_domain_recv_netlogoncreds, state);
}

static void init_domain_recv_netlogoncreds(struct composite_context *ctx)
{
	struct init_domain_state *state =
		talloc_get_type(ctx->async.private_data,
				struct init_domain_state);
	struct smbcli_tree *tree = NULL;

	state->ctx->status = wb_get_schannel_creds_recv(ctx, state,
							&state->auth2_pipe);
	if (!composite_is_ok(state->ctx)) return;

	talloc_unlink(state, state->conn.out.tree); /* The pipe owns it now */

	state->netlogon_pipe = dcerpc_pipe_init(state, state->ctx->event_ctx);
	if (composite_nomem(state->netlogon_pipe, state->ctx)) return;

	if (state->auth2_pipe != NULL) {
		tree = dcerpc_smb_tree(state->auth2_pipe->conn);
	}

	if (tree == NULL) {
		composite_error(state->ctx, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	ctx = dcerpc_pipe_open_smb_send(state->netlogon_pipe->conn, tree,
					"\\netlogon");
	composite_continue(state->ctx, ctx,
			   init_domain_recv_netlogonpipe, state);
}

static void init_domain_recv_netlogonpipe(struct composite_context *ctx)
{
	struct init_domain_state *state =
		talloc_get_type(ctx->async.private_data,
				struct init_domain_state);

	state->ctx->status = dcerpc_pipe_open_smb_recv(ctx);
	if (!composite_is_ok(state->ctx)) return;

	state->netlogon_pipe->conn->flags |= (DCERPC_SIGN | DCERPC_SEAL);
	state->ctx->status =
		dcerpc_bind_auth_password(state->netlogon_pipe,
					  DCERPC_NETLOGON_UUID,
					  DCERPC_NETLOGON_VERSION, 
					  state->domain->schannel_creds,
					  DCERPC_AUTH_TYPE_SCHANNEL,
					  NULL);

	ctx = wb_connect_lsa_send(state->conn.out.tree,
				  state->domain->schannel_creds);
	composite_continue(state->ctx, ctx, init_domain_recv_lsa, state);
}

static void init_domain_recv_lsa(struct composite_context *ctx)
{
	struct init_domain_state *state =
		talloc_get_type(ctx->async.private_data,
				struct init_domain_state);

	struct rpc_request *req;
	uint8_t auth_type;

	state->ctx->status = wb_connect_lsa_recv(ctx, state, &auth_type,
						 &state->lsa_pipe,
						 &state->lsa_policy);
	if (!composite_is_ok(state->ctx)) return;

	if (state->auth2_pipe == NULL) {
		/* Give the tree to the LSA pipe. If auth2_pipe exists we have
		 * given it to that already */
		talloc_unlink(state, state->conn.out.tree);
		state->conn.out.tree = NULL;
	}

	state->queryinfo.in.handle = state->lsa_policy;
	state->queryinfo.in.level = LSA_POLICY_INFO_ACCOUNT_DOMAIN;

	req = dcerpc_lsa_QueryInfoPolicy_send(state->lsa_pipe, state,
					      &state->queryinfo);
	composite_continue_rpc(state->ctx, req,
			       init_domain_recv_queryinfo, state);
}

static void init_domain_recv_queryinfo(struct rpc_request *req)
{
	struct init_domain_state *state =
		talloc_get_type(req->async.private, struct init_domain_state);
	struct lsa_DomainInfo *dominfo;

	state->ctx->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(state->ctx)) return;
	state->ctx->status = state->queryinfo.out.result;
	if (!composite_is_ok(state->ctx)) return;

	dominfo = &state->queryinfo.out.info->account_domain;

	if (strcasecmp(state->domain->name, dominfo->name.string) != 0) {
		DEBUG(2, ("Expected domain name %s, DC %s said %s\n",
			  state->domain->name,
			  dcerpc_server_name(state->lsa_pipe),
			  dominfo->name.string));
		composite_error(state->ctx, NT_STATUS_INVALID_DOMAIN_STATE);
		return;
	}

	if (!dom_sid_equal(state->domain->sid, dominfo->sid)) {
		DEBUG(2, ("Expected domain sid %s, DC %s said %s\n",
			  dom_sid_string(state, state->domain->sid),
			  dcerpc_server_name(state->lsa_pipe),
			  dom_sid_string(state, dominfo->sid)));
		composite_error(state->ctx, NT_STATUS_INVALID_DOMAIN_STATE);
		return;
	}

	composite_done(state->ctx);
}

NTSTATUS wb_init_domain_recv(struct composite_context *c)
{
	NTSTATUS status = composite_wait(c);
	if (NT_STATUS_IS_OK(status)) {
		struct init_domain_state *state =
			talloc_get_type(c->private_data,
					struct init_domain_state);
		struct wbsrv_domain *domain = state->domain;

		talloc_free(domain->netlogon_auth2_pipe);
		domain->netlogon_auth2_pipe =
			talloc_steal(domain, state->auth2_pipe);

		talloc_free(domain->netlogon_pipe);
		domain->netlogon_pipe =
			talloc_steal(domain, state->netlogon_pipe);

		talloc_free(domain->lsa_pipe);
		domain->lsa_pipe =
			talloc_steal(domain, state->lsa_pipe);

		talloc_free(domain->lsa_policy);
		domain->lsa_policy =
			talloc_steal(domain, state->lsa_policy);

		domain->initialized = True;
	}
	talloc_free(c);
	return status;
}

NTSTATUS wb_init_domain(struct wbsrv_domain *domain,
			struct event_context *event_ctx,
			struct messaging_context *messaging_ctx)
{
	struct composite_context *c =
		wb_init_domain_send(domain, event_ctx, messaging_ctx);
	return wb_init_domain_recv(c);
}
