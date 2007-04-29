/* 
   Unix SMB/CIFS implementation.

   Connect to the SAMR pipe, given an smbcli_tree and possibly some
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
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_samr_c.h"


/* Helper to initialize SAMR with a specific auth methods. Verify by opening
 * the SAM handle */

struct connect_samr_state {
	struct composite_context *ctx;
	uint8_t auth_type;
	struct cli_credentials *creds;
	struct dom_sid *sid;

	struct dcerpc_pipe *samr_pipe;
	struct policy_handle *connect_handle;
	struct policy_handle *domain_handle;

	struct samr_Connect2 c;
	struct samr_OpenDomain o;
};

static void connect_samr_recv_pipe(struct composite_context *ctx);
static void connect_samr_recv_anon_bind(struct composite_context *ctx);
static void connect_samr_recv_auth_bind(struct composite_context *ctx);
static void connect_samr_recv_conn(struct rpc_request *req);
static void connect_samr_recv_open(struct rpc_request *req);

struct composite_context *wb_connect_sam_send(TALLOC_CTX *mem_ctx,
					      struct smbcli_tree *tree,
					      uint8_t auth_type,
					      struct cli_credentials *creds,
					      const struct dom_sid *domain_sid)
{
	struct composite_context *result, *ctx;
	struct connect_samr_state *state;

	result = composite_create(mem_ctx, tree->session->transport->socket->event.ctx);
	if (result == NULL) goto failed;

	state = talloc(result, struct connect_samr_state);
	if (state == NULL) goto failed;
	state->ctx = result;
	result->private_data = state;

	state->auth_type = auth_type;
	state->creds = creds;
	state->sid = dom_sid_dup(state, domain_sid);
	if (state->sid == NULL) goto failed;

	state->samr_pipe = dcerpc_pipe_init(state, result->event_ctx);
	if (state->samr_pipe == NULL) goto failed;

	ctx = dcerpc_pipe_open_smb_send(state->samr_pipe, tree,
					"\\samr");
	ctx->async.fn = connect_samr_recv_pipe;
	ctx->async.private_data = state;
	return result;
	
 failed:
	talloc_free(result);
	return NULL;
}

static void connect_samr_recv_pipe(struct composite_context *ctx)
{
	struct connect_samr_state *state =
		talloc_get_type(ctx->async.private_data,
				struct connect_samr_state);

	state->ctx->status = dcerpc_pipe_open_smb_recv(ctx);
	if (!composite_is_ok(state->ctx)) return;

	switch (state->auth_type) {
	case DCERPC_AUTH_TYPE_NONE:
		ctx = dcerpc_bind_auth_none_send(state, state->samr_pipe,
						 &dcerpc_table_samr);
		composite_continue(state->ctx, ctx,
				   connect_samr_recv_anon_bind, state);
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
		ctx = dcerpc_bind_auth_send(state, state->samr_pipe,
					    &dcerpc_table_samr,
					    state->creds, state->auth_type,
					    auth_type,
					    NULL);
		composite_continue(state->ctx, ctx,
				   connect_samr_recv_auth_bind, state);
		break;
	}
	default:
		composite_error(state->ctx, NT_STATUS_INTERNAL_ERROR);
	}
}

static void connect_samr_recv_anon_bind(struct composite_context *ctx)
{
	struct connect_samr_state *state =
		talloc_get_type(ctx->async.private_data,
				struct connect_samr_state);
	struct rpc_request *req;

	state->ctx->status = dcerpc_bind_auth_none_recv(ctx);
	if (!composite_is_ok(state->ctx)) return;
			
	state->connect_handle = talloc(state, struct policy_handle);
	if (composite_nomem(state->connect_handle, state->ctx)) return;

	state->c.in.system_name =
		talloc_asprintf(state, "\\\\%s",
				dcerpc_server_name(state->samr_pipe));
	state->c.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	state->c.out.connect_handle = state->connect_handle;

	req = dcerpc_samr_Connect2_send(state->samr_pipe, state, &state->c);
	composite_continue_rpc(state->ctx, req, connect_samr_recv_conn, state);
}

static void connect_samr_recv_auth_bind(struct composite_context *ctx)
{
	struct connect_samr_state *state =
		talloc_get_type(ctx->async.private_data,
				struct connect_samr_state);
	struct rpc_request *req;

	state->ctx->status = dcerpc_bind_auth_recv(ctx);
	if (!composite_is_ok(state->ctx)) return;
			
	state->connect_handle = talloc(state, struct policy_handle);
	if (composite_nomem(state->connect_handle, state->ctx)) return;

	state->c.in.system_name =
		talloc_asprintf(state, "\\\\%s",
				dcerpc_server_name(state->samr_pipe));
	state->c.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	state->c.out.connect_handle = state->connect_handle;

	req = dcerpc_samr_Connect2_send(state->samr_pipe, state, &state->c);
	composite_continue_rpc(state->ctx, req, connect_samr_recv_conn, state);
}

static void connect_samr_recv_conn(struct rpc_request *req)
{
	struct connect_samr_state *state =
		talloc_get_type(req->async.private,
				struct connect_samr_state);

	state->ctx->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(state->ctx)) return;
	state->ctx->status = state->c.out.result;
	if (!composite_is_ok(state->ctx)) return;

	state->domain_handle = talloc(state, struct policy_handle);
	if (composite_nomem(state->domain_handle, state->ctx)) return;

	state->o.in.connect_handle = state->connect_handle;
	state->o.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	state->o.in.sid = state->sid;
	state->o.out.domain_handle = state->domain_handle;

	req = dcerpc_samr_OpenDomain_send(state->samr_pipe, state, &state->o);
	composite_continue_rpc(state->ctx, req,
			       connect_samr_recv_open, state);
}

static void connect_samr_recv_open(struct rpc_request *req)
{
	struct connect_samr_state *state =
		talloc_get_type(req->async.private,
				struct connect_samr_state);

	state->ctx->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(state->ctx)) return;
	state->ctx->status = state->o.out.result;
	if (!composite_is_ok(state->ctx)) return;

	composite_done(state->ctx);
}

NTSTATUS wb_connect_sam_recv(struct composite_context *c,
			     TALLOC_CTX *mem_ctx,
			     struct dcerpc_pipe **samr_pipe,
			     struct policy_handle **connect_handle,
			     struct policy_handle **domain_handle)
{
	NTSTATUS status = composite_wait(c);
	if (NT_STATUS_IS_OK(status)) {
		struct connect_samr_state *state =
			talloc_get_type(c->private_data,
					struct connect_samr_state);
		*samr_pipe = talloc_steal(mem_ctx, state->samr_pipe);
		*connect_handle = talloc_steal(mem_ctx, state->connect_handle);
		*domain_handle = talloc_steal(mem_ctx, state->domain_handle);
	}
	talloc_free(c);
	return status;
}

NTSTATUS wb_connect_sam(TALLOC_CTX *mem_ctx,
			struct smbcli_tree *tree,
			uint8_t auth_type,
			struct cli_credentials *creds,
			const struct dom_sid *domain_sid,
			struct dcerpc_pipe **samr_pipe,
			struct policy_handle **connect_handle,
			struct policy_handle **domain_handle)
{
	struct composite_context *c =
		wb_connect_sam_send(mem_ctx, tree, auth_type, creds,
				    domain_sid);
	return wb_connect_sam_recv(c, mem_ctx, samr_pipe, connect_handle,
				   domain_handle);
}
