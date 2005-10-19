/* 
   Unix SMB/CIFS implementation.

   Command backend for wbinfo -m

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
#include "winbind/wb_server.h"
#include "smbd/service_stream.h"
#include "smbd/service_task.h"

/* List trusted domains. To avoid the trouble with having to wait for other
 * conflicting requests waiting for the lsa pipe we're opening our own lsa
 * pipe here. */

struct cmd_list_trustdom_state {
	struct composite_context *ctx;
	struct dcerpc_pipe *lsa_pipe;
	struct policy_handle *lsa_policy;
	int num_domains;
	struct wb_dom_info *domains;

	uint32_t resume_handle;
	struct lsa_DomainList domains;
	struct lsa_EnumTrustDom r;
};

static void cmd_list_trustdoms_recv_domain(struct composite_context *ctx);
static void cmd_list_trustdoms_recv_lsa(struct composite_context *ctx);
static void cmd_list_trustdoms_recv_doms(struct rpc_request *req);

struct composite_context *wb_cmd_list_trustdoms_send(struct wbsrv_service *service)
{
	struct composite_context *result, *ctx;
	struct cmd_list_trustdom_state *state;

	result = talloc_zero(NULL, struct composite_context);
	if (result == NULL) goto failed;
	result->state = COMPOSITE_STATE_IN_PROGRESS;
	result->async.fn = NULL;
	result->event_ctx = service->task->event_ctx;

	state = talloc(result, struct cmd_list_trustdom_state);
	if (state == NULL) goto failed;
	state->ctx = result;
	result->private_data = state;

	state->service = service;

	ctx = wb_sid2domain_send(service, service->primary_sid);
	if (ctx == NULL) goto failed;
	ctx->async.fn = cmd_list_trustdoms_recv_domain;
	ctx->async.private_data = state;
	return result;

 failed:
	talloc_free(result);
	return NULL;
}

static void cmd_list_trustdoms_recv_domain(struct composite_context *ctx)
{
	struct cmd_list_trustdom_state *state =
		talloc_get_type(ctx->async.private_data,
				struct cmd_list_trustdom_state);
	struct wbsrv_domain *domain;
	struct smbcli_tree *tree;

	state->ctx->status = wb_sid2domain_recv(ctx, &domain);
	if (!composite_is_ok(state->ctx)) return;

	tree = dcerpc_smb_tree(domain->lsa_pipe);
	if (composite_nomem(tree, state->tree)) return;

	ctx = wb_init_lsa_send(tree, domain->lsa_auth_type,
			       domain->schannel_creds);
	composite_continue(state->ctx, ctx, cmd_list_trustdoms_recv_lsa,
			   state);
}

static void cmd_list_trustdoms_recv_lsa(struct composite_context *ctx)
{
	struct cmd_list_trustdom_state *state =
		talloc_get_type(ctx->async.private_data,
				struct cmd_list_trustdom_state);
	struct rpc_request *req;

	state->ctx->status = wb_init_lsa_recv(ctx, state,
					      &state->lsa_pipe,
					      &state->lsa_policy);
	if (!composite_is_ok(state->ctx)) return;

	state->resume_handle = 0;
	state->r.in.policy_handle = state->lsa_policy;
	state->r.in.resume_handle = &state->resume_handle;
	state->r.in.max_size = 1000;
	state->r.out.resume_handle = &state->resume_handle;

	req = dcerpc_lsa_EnumTrustDom_send(state->lsa_pipe, state, &state->r);
	composite_continue_rpc(state->ctx, req, cmd_list_trustdoms_recv_doms,
			       state);
}

static void cmd_list_trustdoms_recv_doms(struct rpc_request *req)
{
	
}
