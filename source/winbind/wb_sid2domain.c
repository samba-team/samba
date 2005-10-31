/* 
   Unix SMB/CIFS implementation.

   Find and init a domain struct for a SID

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
#include "librpc/gen_ndr/nbt.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "winbind/wb_async_helpers.h"
#include "include/dlinklist.h"

static const char *sam_name(void)
{
	if (lp_server_role() == ROLE_STANDALONE) {
		return lp_netbios_name();
	}
	return lp_workgroup();
}

static struct wbsrv_domain *find_primary_domain(struct wbsrv_service *service)
{
	const char *my_domain_name = sam_name();
	struct wbsrv_domain *domain;

	for (domain = service->domains; domain!=NULL; domain = domain->next) {
		if (strcasecmp(domain->name, my_domain_name) == 0) {
			break;
		}
	}
	return domain;
}

static struct wbsrv_domain *find_domain_from_sid(struct wbsrv_service *service,
						 const struct dom_sid *sid)
{
	struct wbsrv_domain *domain;

	for (domain = service->domains; domain!=NULL; domain = domain->next) {
		if (dom_sid_equal(domain->sid, sid)) {
			break;
		}
		if (dom_sid_in_domain(domain->sid, sid)) {
			break;
		}
	}
	return domain;
}

struct sid2domain_state {
	struct composite_context *ctx;
	struct wbsrv_service *service;
	const struct dom_sid *sid;

	const char *domain_name;
	const char *dc_name;
	struct dom_sid *domain_sid;

	struct wbsrv_domain *my_domain;
	struct wbsrv_domain *result;
};

static void sid2domain_recv_name(struct composite_context *ctx);
static void sid2domain_recv_dcname(struct composite_context *ctx);
static void sid2domain_recv_init(struct composite_context *ctx);

struct composite_context *wb_sid2domain_send(struct wbsrv_service *service,
					     const struct dom_sid *sid)
{
	struct composite_context *result, *ctx;
	struct sid2domain_state *state;

	result = talloc_zero(NULL, struct composite_context);
	if (result == NULL) goto failed;
	result->state = COMPOSITE_STATE_IN_PROGRESS;
	result->async.fn = NULL;
	result->event_ctx = service->task->event_ctx;

	state = talloc(result, struct sid2domain_state);
	if (state == NULL) goto failed;
	state->ctx = result;
	result->private_data = state;

	state->service = service;
	state->sid = dom_sid_dup(state, sid);
	if (state->sid == NULL) goto failed;

	state->result = find_domain_from_sid(service, sid);
	if (state->result != NULL) {
		result->status = NT_STATUS_OK;
		if (!state->result->initialized) {
			ctx = wb_init_domain_send(service, state->result);
			if (ctx == NULL) goto failed;
			ctx->async.fn = sid2domain_recv_init;
			ctx->async.private_data = state;
			return result;
		}
		composite_trigger_done(result);
		return result;
	}

	state->my_domain = find_primary_domain(service);
	if (state->my_domain == NULL) {
		result->status = NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		composite_trigger_error(result);
		return result;
	}

	ctx = wb_cmd_lookupsid_send(state, service, state->sid);
	if (ctx == NULL) goto failed;
	ctx->async.fn = sid2domain_recv_name;
	ctx->async.private_data = state;
	return result;

 failed:
	talloc_free(result);
	return NULL;
}

static void sid2domain_recv_name(struct composite_context *ctx)
{
	struct sid2domain_state *state =
		talloc_get_type(ctx->async.private_data,
				struct sid2domain_state);
	struct wb_sid_object *name;

	state->ctx->status = wb_cmd_lookupsid_recv(ctx, state, &name);
	if (!composite_is_ok(state->ctx)) return;

	if (name->type == SID_NAME_UNKNOWN) {
		composite_error(state->ctx, NT_STATUS_NO_SUCH_DOMAIN);
		return;
	}

	state->domain_name = name->domain;
	state->domain_sid = dom_sid_dup(state, state->sid);
	if (name->type != SID_NAME_DOMAIN) {
		state->domain_sid->num_auths -= 1;
	}
	
	ctx = wb_cmd_getdcname_send(state->service, state->my_domain,
				    state->domain_name);
	composite_continue(state->ctx, ctx, sid2domain_recv_dcname, state);
}

static void sid2domain_recv_dcname(struct composite_context *ctx)
{
	struct sid2domain_state *state =
		talloc_get_type(ctx->async.private_data,
				struct sid2domain_state);

	state->ctx->status = wb_cmd_getdcname_recv(ctx, state,
						   &state->dc_name);
	if (!composite_is_ok(state->ctx)) return;

	state->result = talloc_zero(state, struct wbsrv_domain);
	if (composite_nomem(state->result, state->ctx)) return;

	state->result->name = talloc_steal(state->result, state->domain_name);
	state->result->sid = talloc_steal(state->result, state->domain_sid);
	state->result->dcname = talloc_steal(state->result, state->dc_name);

	state->result->schannel_creds = cli_credentials_init(state->result);
	if (composite_nomem(state->result->schannel_creds, state->ctx)) return;
	cli_credentials_set_conf(state->result->schannel_creds);
	cli_credentials_set_machine_account(state->result->schannel_creds);

	talloc_steal(state->service, state->result);
	DLIST_ADD(state->service->domains, state->result);

	ctx = wb_init_domain_send(state->service, state->result);
	composite_continue(state->ctx, ctx, sid2domain_recv_init, state);
}

static void sid2domain_recv_init(struct composite_context *ctx)
{
	struct sid2domain_state *state =
		talloc_get_type(ctx->async.private_data,
				struct sid2domain_state);

	state->ctx->status = wb_init_domain_recv(ctx);
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
		*result = state->result;
	}
	talloc_free(ctx);
	return status;
}

NTSTATUS wb_sid2domain(struct wbsrv_service *service,
		       const struct dom_sid *sid,
		       struct wbsrv_domain **result)
{
	struct composite_context *c = wb_sid2domain_send(service, sid);
	return wb_sid2domain_recv(c, result);
}
