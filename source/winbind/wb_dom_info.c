/* 
   Unix SMB/CIFS implementation.

   Get a struct wb_dom_info for a domain using DNS, netbios, possibly cldap
   etc.

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
#include "libcli/resolve/resolve.h"
#include "libcli/security/security.h"
#include "winbind/wb_server.h"
#include "smbd/service_task.h"
#include "librpc/gen_ndr/ndr_irpc.h"
#include "librpc/gen_ndr/samr.h"
#include "lib/messaging/irpc.h"

struct get_dom_info_state {
	struct composite_context *ctx;
	struct wbsrv_service *service;
	struct nbtd_getdcname r;
	struct wb_dom_info *info;
};

static void get_dom_info_recv_addrs(struct composite_context *ctx);
static void get_dom_info_recv_dcname(struct irpc_request *ireq);

struct composite_context *wb_get_dom_info_send(TALLOC_CTX *mem_ctx,
					       struct wbsrv_service *service,
					       const char *domain_name,
					       const struct dom_sid *sid)
{
	struct composite_context *result, *ctx;
	struct get_dom_info_state *state;
	struct nbt_name name;

	result = composite_create(mem_ctx, service->task->event_ctx);
	if (result == NULL) goto failed;

	state = talloc(result, struct get_dom_info_state);
	if (state == NULL) goto failed;
	state->ctx = result;
	result->private_data = state;

	state->service = service;

	state->info = talloc_zero(state, struct wb_dom_info);
	if (state->info == NULL) goto failed;

	state->info->name = talloc_strdup(state->info, domain_name);
	if (state->info->name == NULL) goto failed;
	state->info->sid = dom_sid_dup(state->info, sid);
	if (state->info->sid == NULL) goto failed;

	make_nbt_name(&name, state->info->name, NBT_NAME_LOGON);

	ctx = resolve_name_send(&name, result->event_ctx,
				lp_name_resolve_order());
	if (ctx == NULL) goto failed;

	ctx->async.fn = get_dom_info_recv_addrs;
	ctx->async.private_data = state;
	return result;

 failed:
	talloc_free(result);
	return NULL;
}

static void get_dom_info_recv_addrs(struct composite_context *ctx)
{
	struct get_dom_info_state *state =
		talloc_get_type(ctx->async.private_data,
				struct get_dom_info_state);
	struct server_id *nbt_servers;
	struct irpc_request *ireq;

	state->ctx->status = resolve_name_recv(ctx, state->info,
					       &state->info->dc_address);
	if (!composite_is_ok(state->ctx)) return;

	nbt_servers = irpc_servers_byname(state->service->task->msg_ctx,
					  state, "nbt_server");
	if ((nbt_servers == NULL) || (nbt_servers[0].id == 0)) {
		composite_error(state->ctx, NT_STATUS_NO_LOGON_SERVERS);
		return;
	}

	state->r.in.domainname = state->info->name;
	state->r.in.ip_address = state->info->dc_address;
	state->r.in.my_computername = lp_netbios_name();
	state->r.in.my_accountname = talloc_asprintf(state, "%s$",
						     lp_netbios_name());
	if (composite_nomem(state->r.in.my_accountname, state->ctx)) return;
	state->r.in.account_control = ACB_WSTRUST;
	state->r.in.domain_sid = dom_sid_dup(state, state->info->sid);
	if (composite_nomem(state->r.in.domain_sid, state->ctx)) return;

	ireq = irpc_call_send(state->service->task->msg_ctx, nbt_servers[0],
			      &dcerpc_table_irpc, DCERPC_NBTD_GETDCNAME,
			      &state->r, state);
	composite_continue_irpc(state->ctx, ireq, get_dom_info_recv_dcname,
				state);
}

static void get_dom_info_recv_dcname(struct irpc_request *ireq)
{
	struct get_dom_info_state *state =
		talloc_get_type(ireq->async.private,
				struct get_dom_info_state);


	state->ctx->status = irpc_call_recv(ireq);
	if (!composite_is_ok(state->ctx)) return;

	state->info->dc_name = talloc_steal(state->info, state->r.out.dcname);
	composite_done(state->ctx);
}

NTSTATUS wb_get_dom_info_recv(struct composite_context *ctx,
			      TALLOC_CTX *mem_ctx,
			      struct wb_dom_info **result)
{
	NTSTATUS status = composite_wait(ctx);
	if (NT_STATUS_IS_OK(status)) {
		struct get_dom_info_state *state =
			talloc_get_type(ctx->private_data,
					struct get_dom_info_state);
		*result = talloc_steal(mem_ctx, state->info);
	}
	talloc_free(ctx);
	return status;
}

NTSTATUS wb_get_dom_info(TALLOC_CTX *mem_ctx,
			 struct wbsrv_service *service,
			 const char *domain_name,
			 const struct dom_sid *sid,
			 struct wb_dom_info **result)
{
	struct composite_context *ctx =
		wb_get_dom_info_send(mem_ctx, service, domain_name, sid);
	return wb_get_dom_info_recv(ctx, mem_ctx, result);
}
