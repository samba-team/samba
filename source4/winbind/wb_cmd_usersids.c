/* 
   Unix SMB/CIFS implementation.

   Command backend for wbinfo --user-sids

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
#include "lib/events/events.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/gen_ndr/ndr_samr.h"

/* Calculate the token in two steps: Go the user's originating domain, asking
 * for the user's domain groups. Then with the resulting list of sids go to
 * our own domain, expanding the aliases aka domain local groups. Two helpers
 * are needed: composite_samr_GetAliasMembership and wb_sidaliases. The core
 * function this file supplies is wb_cmd_usersids somewhere down. */


/* composite_context wrapper around dcerpc_samr_GetAliasMembership */

static void composite_samr_GetAliasMembership_recv_rpc(struct rpc_request *req);

static struct composite_context *composite_samr_GetAliasMembership_send(struct dcerpc_pipe *p,
									TALLOC_CTX *mem_ctx,
									struct samr_GetAliasMembership *r)
{
	struct composite_context *result;
	struct rpc_request *req;

	result = talloc(mem_ctx, struct composite_context);
	if (result == NULL) goto failed;
	result->state = COMPOSITE_STATE_IN_PROGRESS;
	result->async.fn = NULL;
	result->event_ctx = p->conn->event_ctx;

	req = dcerpc_samr_GetAliasMembership_send(p, mem_ctx, r);
	if (req == NULL) goto failed;
	req->async.callback = composite_samr_GetAliasMembership_recv_rpc;
	req->async.private = result;
	return result;

 failed:
	talloc_free(result);
	return NULL;
}

static void composite_samr_GetAliasMembership_recv_rpc(struct rpc_request *req)
{
	struct composite_context *ctx =
		talloc_get_type(req->async.private, struct composite_context);

	ctx->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(ctx)) return;
	composite_done(ctx);
}

static NTSTATUS composite_samr_GetAliasMembership_recv(struct composite_context *ctx)
{
	NTSTATUS status = composite_wait(ctx);
	talloc_free(ctx);
	return status;
}

/* Composite wrapper including domain selection and domain queueing around
 * GetAliasMemberships */

struct sidaliases_state {
	struct composite_context *ctx;
	int num_sids;
	const struct dom_sid *domain_sid;
	const struct dom_sid *sids;

	struct lsa_SidArray lsa_sids;
	struct samr_Ids rids;
	struct samr_GetAliasMembership r;
};

static struct composite_context *sidaliases_send_req(struct wbsrv_domain *domain,
						     void *p);
static NTSTATUS sidaliases_recv_req(struct composite_context *ctx, void *p);

static struct composite_context *wb_sidaliases_send(struct wbsrv_service *service,
						    int num_sids,
						    struct dom_sid **sids)
{
	struct sidaliases_state *state;
	int i;

	state = talloc(NULL, struct sidaliases_state);

	state->domain_sid = talloc_reference(state, service->primary_sid);
	if (state->domain_sid == NULL) goto failed;

	state->lsa_sids.num_sids = num_sids;
	state->lsa_sids.sids = talloc_array(state, struct lsa_SidPtr,
					    num_sids);
	if (state->lsa_sids.sids == NULL) goto failed;

	for (i=0; i<state->lsa_sids.num_sids; i++) {
		state->lsa_sids.sids[i].sid =
			talloc_reference(state->lsa_sids.sids, sids[i]);
		if (state->lsa_sids.sids[i].sid == NULL) goto failed;
	}

	state->rids.count = 0;
	state->rids.ids = NULL;

	state->ctx = wb_domain_request_send(state, service,
					    service->primary_sid,
					    sidaliases_send_req,
					    sidaliases_recv_req,
					    state);
	if (state->ctx == NULL) goto failed;
	state->ctx->private_data = state;
	return state->ctx;

 failed:
	talloc_free(state);
	return NULL;
}

static struct composite_context *sidaliases_send_req(struct wbsrv_domain *domain,
						     void *p)
{
	struct sidaliases_state *state =
		talloc_get_type(p, struct sidaliases_state);

	state->r.in.domain_handle = domain->domain_handle;
	state->r.in.sids = &state->lsa_sids;
	state->r.out.rids = &state->rids;

	return composite_samr_GetAliasMembership_send(domain->samr_pipe,
						      state, &state->r);
}

static NTSTATUS sidaliases_recv_req(struct composite_context *ctx, void *p)
{
	struct sidaliases_state *state =
		talloc_get_type(p, struct sidaliases_state);
	NTSTATUS status;

	status = composite_samr_GetAliasMembership_recv(ctx);
	NT_STATUS_NOT_OK_RETURN(status);
	return state->r.out.result;
}

static NTSTATUS wb_sidaliases_recv(struct composite_context *ctx,
				   TALLOC_CTX *mem_ctx,
				   int *num_sids,
				   struct dom_sid ***sids)
{
	struct sidaliases_state *state =
		talloc_get_type(ctx->private_data,
				struct sidaliases_state);
	NTSTATUS status;
	int i;

	status = composite_wait(ctx);
	if (!NT_STATUS_IS_OK(status)) goto done;

	*num_sids = state->r.out.rids->count;
	*sids = talloc_array(mem_ctx, struct dom_sid *, *num_sids);
	if (*sids == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	for (i=0; i<*num_sids; i++) {
		(*sids)[i] = dom_sid_add_rid((*sids), state->domain_sid,
					     state->r.out.rids->ids[i]);
		if ((*sids)[i] == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
	}

 done:
	talloc_free(state);
	return status;
}

/* Supplied a SID, go to the user's DC, ask it for the user's domain
 * groups. Then go to our DC, ask it for the domain local groups. */

struct cmd_usersids_state {
	struct composite_context *ctx;
	struct wbsrv_service *service;
	struct dom_sid *user_sid;
	int num_domgroups;
	struct dom_sid **domgroups;
	int num_sids;
	struct dom_sid **sids;
};

static void cmd_usersids_recv_domgroups(struct composite_context *ctx);
static void cmd_usersids_recv_aliases(struct composite_context *ctx);

struct composite_context *wb_cmd_usersids_send(struct wbsrv_service *service,
					       const struct dom_sid *sid)
{
	struct composite_context *result, *ctx;
	struct cmd_usersids_state *state;

	result = talloc_zero(NULL, struct composite_context);
	if (result == NULL) goto failed;
	result->state = COMPOSITE_STATE_IN_PROGRESS;
	result->async.fn = NULL;
	result->event_ctx = service->task->event_ctx;

	state = talloc(result, struct cmd_usersids_state);
	if (state == NULL) goto failed;
	state->ctx = result;
	result->private_data = state;

	state->service = service;
	state->user_sid = dom_sid_dup(state, sid);
	if (state->user_sid == NULL) goto failed;

	ctx = wb_cmd_userdomgroups_send(service, sid);
	if (ctx == NULL) goto failed;

	ctx->async.fn = cmd_usersids_recv_domgroups;
	ctx->async.private_data = state;
	return result;

 failed:
	talloc_free(result);
	return NULL;
}

static void cmd_usersids_recv_domgroups(struct composite_context *ctx)
{
	struct cmd_usersids_state *state =
		talloc_get_type(ctx->async.private_data,
				struct cmd_usersids_state);

	int i;
	struct dom_sid **sids;

	state->ctx->status = wb_cmd_userdomgroups_recv(ctx, state,
						       &state->num_domgroups,
						       &state->domgroups);
	if (!composite_is_ok(state->ctx)) return;

	sids = talloc_array(state, struct dom_sid *, state->num_domgroups+1);
	if (composite_nomem(sids, state->ctx)) return;

	sids[0] = state->user_sid;
	for (i=0; i<state->num_domgroups; i++) {
		sids[i+1] = state->domgroups[i];
	}

	ctx = wb_sidaliases_send(state->service, state->num_domgroups+1,
				 sids);
	composite_continue(state->ctx, ctx, cmd_usersids_recv_aliases, state);
}

static void cmd_usersids_recv_aliases(struct composite_context *ctx)
{
	struct cmd_usersids_state *state =
		talloc_get_type(ctx->async.private_data,
				struct cmd_usersids_state);
	int i, num_aliases;
	struct dom_sid **aliases;

	state->ctx->status = wb_sidaliases_recv(ctx, state, &num_aliases,
						&aliases);
	if (!composite_is_ok(state->ctx)) return;

	state->num_sids = 1 + state->num_domgroups + num_aliases;
	state->sids = talloc_array(state, struct dom_sid *, state->num_sids);
	if (composite_nomem(state->sids, state->ctx)) return;

	state->sids[0] = talloc_steal(state->sids, state->user_sid);

	for (i=0; i<state->num_domgroups; i++) {
		state->sids[1+i] =
			talloc_steal(state->sids, state->domgroups[i]);
	}

	for (i=0; i<num_aliases; i++) {
		state->sids[1+i+state->num_domgroups] =
			talloc_steal(state->sids, aliases[i]);
	}

	composite_done(state->ctx);
}

NTSTATUS wb_cmd_usersids_recv(struct composite_context *ctx,
			      TALLOC_CTX *mem_ctx,
			      int *num_sids, struct dom_sid ***sids)
{
	NTSTATUS status = composite_wait(ctx);
	if (NT_STATUS_IS_OK(status)) {
		struct cmd_usersids_state *state =
			talloc_get_type(ctx->private_data,
					struct cmd_usersids_state);
		*num_sids = state->num_sids;
		*sids = talloc_steal(mem_ctx, state->sids);
	}
	talloc_free(ctx);
	return status;
}

NTSTATUS wb_cmd_usersids(struct wbsrv_service *service,
			      const struct dom_sid *sid,
			      TALLOC_CTX *mem_ctx, int *num_sids,
			      struct dom_sid ***sids)
{
	struct composite_context *c =
		wb_cmd_usersids_send(service, sid);
	return wb_cmd_usersids_recv(c, mem_ctx, num_sids, sids);
}

