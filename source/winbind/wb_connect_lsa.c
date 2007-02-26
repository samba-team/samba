/* 
   Unix SMB/CIFS implementation.

   Connect to the LSA pipe, given an smbcli_tree and possibly some
   credentials. Try ntlmssp, schannel and anon in that order.

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

#include "libcli/raw/libcliraw.h"
#include "librpc/gen_ndr/ndr_lsa_c.h"

/* Helper to initialize LSA with a specific auth methods. Verify by opening
 * the LSA policy. */

struct init_lsa_state {
	struct composite_context *ctx;
	struct dcerpc_pipe *lsa_pipe;

	uint8_t auth_type;
	struct cli_credentials *creds;

	struct lsa_ObjectAttribute objectattr;
	struct lsa_OpenPolicy2 openpolicy;
	struct policy_handle *handle;
};

static void init_lsa_recv_pipe(struct composite_context *ctx);
static void init_lsa_recv_anon_bind(struct composite_context *ctx);
static void init_lsa_recv_auth_bind(struct composite_context *ctx);
static void init_lsa_recv_openpol(struct rpc_request *req);

struct composite_context *wb_init_lsa_send(TALLOC_CTX *mem_ctx,
					   struct smbcli_tree *tree,
					   uint8_t auth_type,
					   struct cli_credentials *creds)
{
	struct composite_context *result, *ctx;
	struct init_lsa_state *state;

	result = talloc(mem_ctx, struct composite_context);
	if (result == NULL) goto failed;
	result->state = COMPOSITE_STATE_IN_PROGRESS;
	result->async.fn = NULL;
	result->event_ctx = tree->session->transport->socket->event.ctx;

	state = talloc(result, struct init_lsa_state);
	if (state == NULL) goto failed;
	state->ctx = result;
	result->private_data = state;

	state->auth_type = auth_type;
	state->creds = creds;

	state->lsa_pipe = dcerpc_pipe_init(state, result->event_ctx);
	if (state->lsa_pipe == NULL) goto failed;

	ctx = dcerpc_pipe_open_smb_send(state->lsa_pipe, tree,
					"\\lsarpc");
	ctx->async.fn = init_lsa_recv_pipe;
	ctx->async.private_data = state;
	return result;
	
 failed:
	talloc_free(result);
	return NULL;
}

static void init_lsa_recv_pipe(struct composite_context *ctx)
{
	struct init_lsa_state *state =
		talloc_get_type(ctx->async.private_data,
				struct init_lsa_state);

	state->ctx->status = dcerpc_pipe_open_smb_recv(ctx);
	if (!composite_is_ok(state->ctx)) return;

	switch (state->auth_type) {
	case DCERPC_AUTH_TYPE_NONE:
		ctx = dcerpc_bind_auth_none_send(state, state->lsa_pipe,
						 &dcerpc_table_lsarpc);
		composite_continue(state->ctx, ctx, init_lsa_recv_anon_bind,
				   state);
		break;
	case DCERPC_AUTH_TYPE_NTLMSSP:
	case DCERPC_AUTH_TYPE_SCHANNEL:
	{
		uint8_t auth_type;
		if (lp_winbind_sealed_pipes()) {
			auth_type = DCERPC_AUTH_LEVEL_PRIVACY;
		} else {
			auth_type = DCERPC_AUTH_LEVEL_INTEGRITY;
		}
		if (state->creds == NULL) {
			composite_error(state->ctx, NT_STATUS_INTERNAL_ERROR);
			return;
		}
		ctx = dcerpc_bind_auth_send(state, state->lsa_pipe,
					    &dcerpc_table_lsarpc,
					    state->creds, state->auth_type,
					    auth_type,
					    NULL);
		composite_continue(state->ctx, ctx, init_lsa_recv_auth_bind,
				   state);
		break;
	}
	default:
		composite_error(state->ctx, NT_STATUS_INTERNAL_ERROR);
	}
}

static void init_lsa_recv_anon_bind(struct composite_context *ctx)
{
	struct init_lsa_state *state =
		talloc_get_type(ctx->async.private_data,
				struct init_lsa_state);
	struct rpc_request *req;

	state->ctx->status = dcerpc_bind_auth_none_recv(ctx);
	if (!composite_is_ok(state->ctx)) return;
			
	state->handle = talloc(state, struct policy_handle);
	if (composite_nomem(state->handle, state->ctx)) return;

	state->openpolicy.in.system_name =
		talloc_asprintf(state, "\\\\%s",
				dcerpc_server_name(state->lsa_pipe));
	ZERO_STRUCT(state->objectattr);
	state->openpolicy.in.attr = &state->objectattr;
	state->openpolicy.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	state->openpolicy.out.handle = state->handle;

	req = dcerpc_lsa_OpenPolicy2_send(state->lsa_pipe, state,
					  &state->openpolicy);
	composite_continue_rpc(state->ctx, req, init_lsa_recv_openpol, state);
}

static void init_lsa_recv_auth_bind(struct composite_context *ctx)
{
	struct init_lsa_state *state =
		talloc_get_type(ctx->async.private_data,
				struct init_lsa_state);
	struct rpc_request *req;

	state->ctx->status = dcerpc_bind_auth_recv(ctx);
	if (!composite_is_ok(state->ctx)) return;
			
	state->handle = talloc(state, struct policy_handle);
	if (composite_nomem(state->handle, state->ctx)) return;

	state->openpolicy.in.system_name =
		talloc_asprintf(state, "\\\\%s",
				dcerpc_server_name(state->lsa_pipe));
	ZERO_STRUCT(state->objectattr);
	state->openpolicy.in.attr = &state->objectattr;
	state->openpolicy.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	state->openpolicy.out.handle = state->handle;

	req = dcerpc_lsa_OpenPolicy2_send(state->lsa_pipe, state,
					  &state->openpolicy);
	composite_continue_rpc(state->ctx, req, init_lsa_recv_openpol, state);
}

static void init_lsa_recv_openpol(struct rpc_request *req)
{
	struct init_lsa_state *state =
		talloc_get_type(req->async.private,
				struct init_lsa_state);

	state->ctx->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(state->ctx)) return;
	state->ctx->status = state->openpolicy.out.result;
	if (!composite_is_ok(state->ctx)) return;

	composite_done(state->ctx);
}

NTSTATUS wb_init_lsa_recv(struct composite_context *c,
			  TALLOC_CTX *mem_ctx,
			  struct dcerpc_pipe **lsa_pipe,
			  struct policy_handle **lsa_policy)
{
	NTSTATUS status = composite_wait(c);
	if (NT_STATUS_IS_OK(status)) {
		struct init_lsa_state *state =
			talloc_get_type(c->private_data,
					struct init_lsa_state);
		*lsa_pipe = talloc_steal(mem_ctx, state->lsa_pipe);
		*lsa_policy = talloc_steal(mem_ctx, state->handle);
	}
	talloc_free(c);
	return status;
}


/*
 * Connect to LSA using the credentials, try NTLMSSP and SCHANNEL using the
 * given credentials. If both fail or no credentials are available, fall back
 * to an anonymous bind.
 */

struct connect_lsa_state {
	struct composite_context *ctx;
	struct smbcli_tree *tree;
	struct cli_credentials *credentials;

	uint8_t auth_type;
	struct dcerpc_pipe *lsa_pipe;
	struct policy_handle *lsa_policy;
};

static void connect_lsa_recv_ntlmssp(struct composite_context *ctx);
static void connect_lsa_recv_schannel(struct composite_context *ctx);
static void connect_lsa_recv_anon(struct composite_context *ctx);

struct composite_context *wb_connect_lsa_send(TALLOC_CTX *mem_ctx,
					      struct smbcli_tree *tree,
					      struct cli_credentials *credentials)
{
	struct composite_context *result, *ctx;
	struct connect_lsa_state *state;

	result = talloc(mem_ctx, struct composite_context);
	if (result == NULL) goto failed;
	result->state = COMPOSITE_STATE_IN_PROGRESS;
	result->async.fn = NULL;
	result->event_ctx = tree->session->transport->socket->event.ctx;

	state = talloc(result, struct connect_lsa_state);
	if (state == NULL) goto failed;
	state->ctx = result;
	result->private_data = state;

	state->tree = tree;
	state->credentials = credentials;

	if (credentials == NULL) {
		ctx = wb_init_lsa_send(state, tree, DCERPC_AUTH_TYPE_NONE,
				       NULL);
		if (ctx == NULL) goto failed;
		ctx->async.fn = connect_lsa_recv_anon;
		ctx->async.private_data = state;
		return result;
	}

	ctx = wb_init_lsa_send(state, tree, DCERPC_AUTH_TYPE_NTLMSSP,
			       credentials);
	if (ctx == NULL) goto failed;
	ctx->async.fn = connect_lsa_recv_ntlmssp;
	ctx->async.private_data = state;
	return result;

 failed:
	talloc_free(result);
	return NULL;
}

static void connect_lsa_recv_ntlmssp(struct composite_context *ctx)
{
	struct connect_lsa_state *state =
		talloc_get_type(ctx->async.private_data,
				struct connect_lsa_state);

	state->ctx->status = wb_init_lsa_recv(ctx, state, &state->lsa_pipe,
					      &state->lsa_policy);

	if (NT_STATUS_IS_OK(state->ctx->status)) {
		state->auth_type = DCERPC_AUTH_TYPE_NTLMSSP;
		composite_done(state->ctx);
		return;
	}

	ctx = wb_init_lsa_send(state, state->tree, DCERPC_AUTH_TYPE_SCHANNEL,
			       state->credentials);
	composite_continue(state->ctx, ctx,
			   connect_lsa_recv_schannel, state);
}

static void connect_lsa_recv_schannel(struct composite_context *ctx)
{
	struct connect_lsa_state *state =
		talloc_get_type(ctx->async.private_data,
				struct connect_lsa_state);

	state->ctx->status = wb_init_lsa_recv(ctx, state, &state->lsa_pipe,
					      &state->lsa_policy);

	if (NT_STATUS_IS_OK(state->ctx->status)) {
		state->auth_type = DCERPC_AUTH_TYPE_SCHANNEL;
		composite_done(state->ctx);
		return;
	}

	ctx = wb_init_lsa_send(state, state->tree, DCERPC_AUTH_TYPE_NONE,
			       state->credentials);
	composite_continue(state->ctx, ctx,
			   connect_lsa_recv_anon, state);
}

static void connect_lsa_recv_anon(struct composite_context *ctx)
{
	struct connect_lsa_state *state =
		talloc_get_type(ctx->async.private_data,
				struct connect_lsa_state);

	state->ctx->status = wb_init_lsa_recv(ctx, state, &state->lsa_pipe,
					      &state->lsa_policy);
	if (!composite_is_ok(state->ctx)) return;

	state->auth_type = DCERPC_AUTH_TYPE_NONE;
	composite_done(state->ctx);
}

NTSTATUS wb_connect_lsa_recv(struct composite_context *c,
			     TALLOC_CTX *mem_ctx,
			     uint8_t *auth_type,
			     struct dcerpc_pipe **lsa_pipe,
			     struct policy_handle **lsa_policy)
{
	NTSTATUS status = composite_wait(c);
	if (NT_STATUS_IS_OK(status)) {
		struct connect_lsa_state *state =
			talloc_get_type(c->private_data,
					struct connect_lsa_state);
		*auth_type = state->auth_type;
		*lsa_pipe = talloc_steal(mem_ctx, state->lsa_pipe);
		*lsa_policy = talloc_steal(mem_ctx, state->lsa_policy);
	}
	talloc_free(c);
	return status;
}

NTSTATUS wb_connect_lsa(TALLOC_CTX *mem_ctx,
			struct smbcli_tree *tree,
			struct cli_credentials *credentials,
			uint8_t *auth_type,
			struct dcerpc_pipe **lsa_pipe,
			struct policy_handle **lsa_policy)
{
	struct composite_context *c;
	c = wb_connect_lsa_send(mem_ctx, tree, credentials);
	return wb_connect_lsa_recv(c, mem_ctx, auth_type, lsa_pipe,
				   lsa_policy);
}
