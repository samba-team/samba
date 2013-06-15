/* 
   Unix SMB/CIFS implementation.

   Find and init a domain struct for a SID

   Copyright (C) Volker Lendecke 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include <tevent.h>
#include "../lib/util/tevent_ntstatus.h"
#include "libcli/composite/composite.h"
#include "winbind/wb_server.h"
#include "smbd/service_task.h"
#include "libcli/security/security.h"
#include "../lib/util/dlinklist.h"
#include "param/param.h"

static struct wbsrv_domain *find_domain_from_sid(struct wbsrv_service *service,
						 const struct dom_sid *sid)
{
	struct wbsrv_domain *domain;

	for (domain = service->domains; domain!=NULL; domain = domain->next) {
		if (dom_sid_equal(domain->info->sid, sid)) {
			break;
		}
		if (dom_sid_in_domain(domain->info->sid, sid)) {
			break;
		}
	}
	return domain;
}

struct wb_sid2domain_state {
	struct wbsrv_service *service;
	struct dom_sid sid;

	struct wbsrv_domain *domain;
};

static void wb_sid2domain_recv_dom_info(struct composite_context *ctx);
static void wb_sid2domain_recv_name(struct composite_context *ctx);
static void wb_sid2domain_recv_trusted_dom_info(struct composite_context *ctx);
static void wb_sid2domain_recv_init(struct composite_context *ctx);

static struct tevent_req *_wb_sid2domain_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct wbsrv_service *service,
					      const struct dom_sid *sid)
{
	struct tevent_req *req;
	struct wb_sid2domain_state *state;
	struct composite_context *ctx;

	DEBUG(5, ("wb_sid2domain_send called\n"));

	req = tevent_req_create(mem_ctx, &state,
				struct wb_sid2domain_state);
	if (req == NULL) {
		return NULL;
	}

	state->service = service;
	state->sid = *sid;

	state->domain = find_domain_from_sid(service, sid);
	if (state->domain != NULL) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	if (dom_sid_equal(service->primary_sid, sid) ||
	    dom_sid_in_domain(service->primary_sid, sid)) {
		ctx = wb_get_dom_info_send(state, service,
					   lpcfg_workgroup(service->task->lp_ctx),
					   lpcfg_realm(service->task->lp_ctx),
					   service->primary_sid);
		if (tevent_req_nomem(ctx, req)) {
			return tevent_req_post(req, ev);
		}
		ctx->async.fn = wb_sid2domain_recv_dom_info;
		ctx->async.private_data = req;

		return req;
	}

	if (dom_sid_equal(&global_sid_Builtin, sid) ||
	    dom_sid_in_domain(&global_sid_Builtin, sid)) {
		ctx = wb_get_dom_info_send(state, service,
					   "BUILTIN", NULL,
					   &global_sid_Builtin);
		if (tevent_req_nomem(ctx, req)) {
			return tevent_req_post(req, ev);
		}
		ctx->async.fn = wb_sid2domain_recv_dom_info;
		ctx->async.private_data = req;

		return req;
	}

	ctx = wb_cmd_lookupsid_send(state, service, &state->sid);
	if (tevent_req_nomem(ctx, req)) {
		return tevent_req_post(req, ev);
	}
	ctx->async.fn = wb_sid2domain_recv_name;
	ctx->async.private_data = req;

	return req;
}

static void wb_sid2domain_recv_dom_info(struct composite_context *ctx)
{
	struct tevent_req *req =
		talloc_get_type_abort(ctx->async.private_data,
		struct tevent_req);
	struct wb_sid2domain_state *state =
		tevent_req_data(req,
		struct wb_sid2domain_state);
	struct wb_dom_info *info;
	NTSTATUS status;

	status = wb_get_dom_info_recv(ctx, state, &info);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	ctx = wb_init_domain_send(state, state->service, info);
	if (tevent_req_nomem(ctx, req)) {
		return;
	}
	ctx->async.fn = wb_sid2domain_recv_init;
	ctx->async.private_data = req;
}

static void wb_sid2domain_recv_name(struct composite_context *ctx)
{
	struct tevent_req *req =
		talloc_get_type_abort(ctx->async.private_data,
		struct tevent_req);
	struct wb_sid2domain_state *state =
		tevent_req_data(req,
		struct wb_sid2domain_state);
	struct wb_sid_object *name;
	NTSTATUS status;

	status = wb_cmd_lookupsid_recv(ctx, state, &name);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (name->type == SID_NAME_UNKNOWN) {
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_DOMAIN);
		return;
	}

	if (name->type != SID_NAME_DOMAIN) {
		state->sid.num_auths -= 1;
	}

	ctx = wb_trusted_dom_info_send(state, state->service, name->domain,
				       &state->sid);
	if (tevent_req_nomem(ctx, req)) {
		return;
	}
	ctx->async.fn = wb_sid2domain_recv_trusted_dom_info;
	ctx->async.private_data = req;
}

static void wb_sid2domain_recv_trusted_dom_info(struct composite_context *ctx)
{
	struct tevent_req *req =
		talloc_get_type_abort(ctx->async.private_data,
		struct tevent_req);
	struct wb_sid2domain_state *state =
		tevent_req_data(req,
		struct wb_sid2domain_state);
	struct wb_dom_info *info;
	NTSTATUS status;

	status = wb_trusted_dom_info_recv(ctx, state, &info);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	ctx = wb_init_domain_send(state, state->service, info);
	if (tevent_req_nomem(ctx, req)) {
		return;
	}
	ctx->async.fn = wb_sid2domain_recv_init;
	ctx->async.private_data = req;
}

static void wb_sid2domain_recv_init(struct composite_context *ctx)
{
	struct tevent_req *req =
		talloc_get_type_abort(ctx->async.private_data,
		struct tevent_req);
	struct wb_sid2domain_state *state =
		tevent_req_data(req,
		struct wb_sid2domain_state);
	struct wbsrv_domain *existing;
	NTSTATUS status;

	status = wb_init_domain_recv(ctx, state, &state->domain);
	if (tevent_req_nterror(req, status)) {
		DEBUG(10, ("Could not init domain\n"));
		return;
	}

	existing = find_domain_from_sid(state->service, &state->sid);
	if (existing != NULL) {
		DEBUG(5, ("Initialized domain twice, dropping second one\n"));
		talloc_free(state->domain);
		state->domain = existing;
	} else {
		talloc_steal(state->service, state->domain);
		DLIST_ADD(state->service->domains, state->domain);
	}

	tevent_req_done(req);
}

static NTSTATUS _wb_sid2domain_recv(struct tevent_req *req,
				    struct wbsrv_domain **result)
{
	struct wb_sid2domain_state *state =
		tevent_req_data(req,
		struct wb_sid2domain_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*result = state->domain;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct sid2domain_state {
	struct composite_context *ctx;
	struct wbsrv_domain *domain;
};

static void sid2domain_recv_domain(struct tevent_req *subreq);

struct composite_context *wb_sid2domain_send(TALLOC_CTX *mem_ctx,
					     struct wbsrv_service *service,
					     const struct dom_sid *sid)
{
	struct composite_context *result;
	struct sid2domain_state *state;
	struct tevent_req *subreq;

	DEBUG(5, ("wb_sid2domain_send called\n"));
	result = composite_create(mem_ctx, service->task->event_ctx);
	if (result == NULL) goto failed;

	state = talloc(result, struct sid2domain_state);
	if (state == NULL) goto failed;
	state->ctx = result;
	result->private_data = state;

	subreq = _wb_sid2domain_send(state,
				     result->event_ctx,
				     service, sid);
	if (subreq == NULL) goto failed;
	tevent_req_set_callback(subreq, sid2domain_recv_domain, state);

	return result;

 failed:
	talloc_free(result);
	return NULL;

}

static void sid2domain_recv_domain(struct tevent_req *subreq)
{
	struct sid2domain_state *state =
		tevent_req_callback_data(subreq,
				struct sid2domain_state);

	state->ctx->status = _wb_sid2domain_recv(subreq, &state->domain);
	TALLOC_FREE(subreq);
	if (!composite_is_ok(state->ctx)) return;

	composite_done(state->ctx);
}

NTSTATUS wb_sid2domain_recv(struct composite_context *ctx,
			    struct wbsrv_domain **result)
{
	NTSTATUS status = composite_wait(ctx);
	if (NT_STATUS_IS_OK(status)) {
		struct sid2domain_state *state =
			talloc_get_type(ctx->private_data,
					struct sid2domain_state);
		*result = state->domain;
	}
	talloc_free(ctx);
	return status;
}

NTSTATUS wb_sid2domain(TALLOC_CTX *mem_ctx, struct wbsrv_service *service,
		       const struct dom_sid *sid,
		       struct wbsrv_domain **result)
{
	struct composite_context *c = wb_sid2domain_send(mem_ctx, service,
							 sid);
	return wb_sid2domain_recv(c, result);
}
