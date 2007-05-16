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
#include "winbind/wb_server.h"
#include "winbind/wb_async_helpers.h"
#include "winbind/wb_helper.h"
#include "smbd/service_task.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "librpc/gen_ndr/ndr_lsa_c.h"

#include "libcli/auth/credentials.h"
#include "libcli/security/security.h"

#include "libcli/ldap/ldap_client.h"

#include "auth/credentials/credentials.h"

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
	struct wbsrv_service *service;

	struct smb_composite_connect conn;

	struct lsa_QueryInfoPolicy queryinfo;
};

static void init_domain_recv_tree(struct composite_context *ctx);
static void init_domain_recv_netlogoncreds(struct composite_context *ctx);
static void init_domain_recv_netlogonpipe(struct composite_context *ctx);
static void init_domain_recv_schannel(struct composite_context *ctx);
static void init_domain_recv_lsa(struct composite_context *ctx);
static void init_domain_recv_queryinfo(struct rpc_request *req);
static void init_domain_recv_ldapconn(struct composite_context *ctx);
static void init_domain_recv_samr(struct composite_context *ctx);

struct composite_context *wb_init_domain_send(TALLOC_CTX *mem_ctx,
					      struct wbsrv_service *service,
					      struct wb_dom_info *dom_info)
{
	struct composite_context *result, *ctx;
	struct init_domain_state *state;

	result = composite_create(mem_ctx, service->task->event_ctx);
	if (result == NULL) goto failed;

	state = talloc_zero(result, struct init_domain_state);
	if (state == NULL) goto failed;
	state->ctx = result;
	result->private_data = state;

	state->service = service;

	state->domain = talloc(state, struct wbsrv_domain);
	if (state->domain == NULL) goto failed;

	state->domain->info = talloc_reference(state->domain, dom_info);
	if (state->domain->info == NULL) goto failed;

	state->domain->schannel_creds = cli_credentials_init(state->domain);
	if (state->domain->schannel_creds == NULL) goto failed;

	cli_credentials_set_conf(state->domain->schannel_creds);
	state->ctx->status =
		cli_credentials_set_machine_account(state->domain->
						    schannel_creds);
	if (!NT_STATUS_IS_OK(state->ctx->status)) goto failed;

	state->conn.in.dest_host = dom_info->dc_address;
	state->conn.in.port = 0;
	state->conn.in.called_name = dom_info->dc_name;
	state->conn.in.service = "IPC$";
	state->conn.in.service_type = "IPC";
	state->conn.in.workgroup = dom_info->name;
	state->conn.in.credentials = state->domain->schannel_creds;

	state->conn.in.fallback_to_anonymous = True;

	ctx = smb_composite_connect_send(&state->conn, state->domain,
					 result->event_ctx);
	if (ctx == NULL) goto failed;

	ctx->async.fn = init_domain_recv_tree;
	ctx->async.private_data = state;
	return result;

 failed:
	talloc_free(result);
	return NULL;
}

static void init_domain_recv_tree(struct composite_context *ctx)
{
	struct init_domain_state *state =
		talloc_get_type(ctx->async.private_data,
				struct init_domain_state);
	state->ctx->status = smb_composite_connect_recv(ctx, state);
	if (!composite_is_ok(state->ctx)) return;

	if ((state->domain->schannel_creds != NULL) &&
	    (!cli_credentials_is_anonymous(state->domain->schannel_creds)) &&
	    ((lp_server_role() == ROLE_DOMAIN_MEMBER) &&
	     (dom_sid_equal(state->domain->info->sid,
			    state->service->primary_sid)))) {
		ctx = wb_get_schannel_creds_send(state,
						 state->domain->schannel_creds,
						 state->conn.out.tree,
						 state->ctx->event_ctx);
		composite_continue(state->ctx, ctx,
				   init_domain_recv_netlogoncreds, state);
		return;
	}

	ctx = wb_connect_lsa_send(state, state->conn.out.tree, NULL);
	composite_continue(state->ctx, ctx, init_domain_recv_lsa, state);
}

static void init_domain_recv_netlogoncreds(struct composite_context *ctx)
{
	struct init_domain_state *state =
		talloc_get_type(ctx->async.private_data,
				struct init_domain_state);
	struct dcerpc_pipe *auth2_pipe;
	struct smbcli_tree *tree = NULL;

	state->ctx->status =
		wb_get_schannel_creds_recv(ctx, state, &auth2_pipe);
	if (!composite_is_ok(state->ctx)) return;

	if (!lp_winbind_sealed_pipes()) {
		state->domain->netlogon_pipe = talloc_reference(state->domain,
								auth2_pipe);
		ctx = wb_connect_lsa_send(state, state->conn.out.tree, NULL);
		composite_continue(state->ctx, ctx, init_domain_recv_lsa,
				   state);
		return;
	}

	state->domain->netlogon_pipe =
		dcerpc_pipe_init(state->domain, state->ctx->event_ctx);
	if (composite_nomem(state->domain->netlogon_pipe, state->ctx)) return;

	tree = dcerpc_smb_tree(auth2_pipe->conn);
	if (tree == NULL) {
		composite_error(state->ctx, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	ctx = dcerpc_pipe_open_smb_send(state->domain->netlogon_pipe,
					tree, "\\netlogon");
	composite_continue(state->ctx, ctx, init_domain_recv_netlogonpipe,
			   state);
}

static void init_domain_recv_netlogonpipe(struct composite_context *ctx)
{
	struct init_domain_state *state =
		talloc_get_type(ctx->async.private_data,
				struct init_domain_state);

	state->ctx->status = dcerpc_pipe_open_smb_recv(ctx);
	if (!composite_is_ok(state->ctx)) return;

	state->domain->netlogon_pipe->conn->flags |=
		(DCERPC_SIGN | DCERPC_SEAL);
	ctx = dcerpc_bind_auth_send(state, state->domain->netlogon_pipe,
				    &dcerpc_table_netlogon,
				    state->domain->schannel_creds,
				    DCERPC_AUTH_TYPE_SCHANNEL,
				    DCERPC_AUTH_LEVEL_PRIVACY,
				    NULL);
	composite_continue(state->ctx, ctx, init_domain_recv_schannel, state);
}

static void init_domain_recv_schannel(struct composite_context *ctx)
{
	struct init_domain_state *state =
		talloc_get_type(ctx->async.private_data,
				struct init_domain_state);

	state->ctx->status = dcerpc_bind_auth_recv(ctx);
	if (!composite_is_ok(state->ctx)) return;

	ctx = wb_connect_lsa_send(state, state->conn.out.tree,
				  state->domain->schannel_creds);
	composite_continue(state->ctx, ctx, init_domain_recv_lsa, state);
}

static void init_domain_recv_lsa(struct composite_context *ctx)
{
	struct init_domain_state *state =
		talloc_get_type(ctx->async.private_data,
				struct init_domain_state);

	struct rpc_request *req;

	state->ctx->status = wb_connect_lsa_recv(ctx, state->domain,
						 &state->domain->lsa_auth_type,
						 &state->domain->lsa_pipe,
						 &state->domain->lsa_policy);
	if (!composite_is_ok(state->ctx)) return;

	/* Give the tree to the pipes. */
	talloc_unlink(state, state->conn.out.tree);

	state->queryinfo.in.handle = state->domain->lsa_policy;
	state->queryinfo.in.level = LSA_POLICY_INFO_ACCOUNT_DOMAIN;

	req = dcerpc_lsa_QueryInfoPolicy_send(state->domain->lsa_pipe, state,
					      &state->queryinfo);
	composite_continue_rpc(state->ctx, req,
			       init_domain_recv_queryinfo, state);
}

static void init_domain_recv_queryinfo(struct rpc_request *req)
{
	struct init_domain_state *state =
		talloc_get_type(req->async.private_data, struct init_domain_state);
	struct lsa_DomainInfo *dominfo;
	struct composite_context *ctx;
	const char *ldap_url;

	state->ctx->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(state->ctx)) return;
	state->ctx->status = state->queryinfo.out.result;
	if (!composite_is_ok(state->ctx)) return;

	dominfo = &state->queryinfo.out.info->account_domain;

	if (strcasecmp(state->domain->info->name, dominfo->name.string) != 0) {
		DEBUG(2, ("Expected domain name %s, DC %s said %s\n",
			  state->domain->info->name,
			  dcerpc_server_name(state->domain->lsa_pipe),
			  dominfo->name.string));
		composite_error(state->ctx, NT_STATUS_INVALID_DOMAIN_STATE);
		return;
	}

	if (!dom_sid_equal(state->domain->info->sid, dominfo->sid)) {
		DEBUG(2, ("Expected domain sid %s, DC %s said %s\n",
			  dom_sid_string(state, state->domain->info->sid),
			  dcerpc_server_name(state->domain->lsa_pipe),
			  dom_sid_string(state, dominfo->sid)));
		composite_error(state->ctx, NT_STATUS_INVALID_DOMAIN_STATE);
		return;
	}

	state->domain->ldap_conn =
		ldap4_new_connection(state->domain, state->ctx->event_ctx);
	composite_nomem(state->domain->ldap_conn, state->ctx);

	ldap_url = talloc_asprintf(state, "ldap://%s/",
				   state->domain->info->dc_address);
	composite_nomem(ldap_url, state->ctx);

	ctx = ldap_connect_send(state->domain->ldap_conn, ldap_url);
	composite_continue(state->ctx, ctx, init_domain_recv_ldapconn, state);
}

static void init_domain_recv_ldapconn(struct composite_context *ctx)
{
	struct init_domain_state *state =
		talloc_get_type(ctx->async.private_data,
				struct init_domain_state);

	state->ctx->status = ldap_connect_recv(ctx);
	if (NT_STATUS_IS_OK(state->ctx->status)) {
		state->domain->ldap_conn->host =
			talloc_strdup(state->domain->ldap_conn,
				      state->domain->info->dc_name);
		state->ctx->status =
			ldap_bind_sasl(state->domain->ldap_conn,
				       state->domain->schannel_creds);
		DEBUG(0, ("ldap_bind returned %s\n",
			  nt_errstr(state->ctx->status)));
	}

	state->domain->samr_pipe =
		dcerpc_pipe_init(state->domain, state->ctx->event_ctx);
	if (composite_nomem(state->domain->samr_pipe, state->ctx)) return;

	ctx = wb_connect_sam_send(state, state->conn.out.tree,
				  state->domain->lsa_auth_type,
				  state->domain->schannel_creds,
				  state->domain->info->sid);
	composite_continue(state->ctx, ctx, init_domain_recv_samr, state);
}

static void init_domain_recv_samr(struct composite_context *ctx)
{
	struct init_domain_state *state =
		talloc_get_type(ctx->async.private_data,
				struct init_domain_state);

	state->ctx->status = wb_connect_sam_recv(
		ctx, state->domain, &state->domain->samr_pipe,
		&state->domain->samr_handle, &state->domain->domain_handle);
	if (!composite_is_ok(state->ctx)) return;

	composite_done(state->ctx);
}

NTSTATUS wb_init_domain_recv(struct composite_context *c,
			     TALLOC_CTX *mem_ctx,
			     struct wbsrv_domain **result)
{
	NTSTATUS status = composite_wait(c);
	if (NT_STATUS_IS_OK(status)) {
		struct init_domain_state *state =
			talloc_get_type(c->private_data,
					struct init_domain_state);
		*result = talloc_steal(mem_ctx, state->domain);
	}
	talloc_free(c);
	return status;
}

NTSTATUS wb_init_domain(TALLOC_CTX *mem_ctx, struct wbsrv_service *service,
			struct wb_dom_info *dom_info,
			struct wbsrv_domain **result)
{
	struct composite_context *c =
		wb_init_domain_send(mem_ctx, service, dom_info);
	return wb_init_domain_recv(c, mem_ctx, result);
}
