/* 
   Unix SMB/CIFS implementation.

   Command backend for wbinfo -s

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

struct cmd_lookupsid_state {
	struct composite_context *ctx;
	const struct dom_sid *sid;
	struct wb_sid_object *result;
};

static struct composite_context *lookupsid_send_req(struct wbsrv_domain *domain, void *p);
static NTSTATUS lookupsid_recv_req(struct composite_context *ctx, void *p);

struct composite_context *wb_cmd_lookupsid_send(struct wbsrv_service *service,
						const struct dom_sid *sid)
{
	struct cmd_lookupsid_state *state;

	state = talloc(NULL, struct cmd_lookupsid_state);
	state->sid = dom_sid_dup(state, sid);
	if (state->sid == NULL) goto failed;
	state->ctx = wb_domain_request_send(state, service,
					    service->primary_sid,
					    lookupsid_send_req,
					    lookupsid_recv_req,
					    state);
	if (state->ctx == NULL) goto failed;
	state->ctx->private_data = state;
	return state->ctx;

 failed:
	talloc_free(state);
	return NULL;
}

static struct composite_context *lookupsid_send_req(struct wbsrv_domain *domain, void *p)
{
	struct cmd_lookupsid_state *state =
		talloc_get_type(p, struct cmd_lookupsid_state);

	return wb_lsa_lookupsids_send(domain->lsa_pipe,
				      domain->lsa_policy,
				      1, &state->sid);
}

static NTSTATUS lookupsid_recv_req(struct composite_context *ctx, void *p)
{
	struct cmd_lookupsid_state *state =
		talloc_get_type(p, struct cmd_lookupsid_state);
	struct wb_sid_object **names;
	NTSTATUS status;

	status = wb_lsa_lookupsids_recv(ctx, state, &names);
	if (NT_STATUS_IS_OK(status)) {
		state->result = names[0];
	}
	return status;
}

NTSTATUS wb_cmd_lookupsid_recv(struct composite_context *c,
			       TALLOC_CTX *mem_ctx,
			       struct wb_sid_object **sid)
{
	struct cmd_lookupsid_state *state =
		talloc_get_type(c->private_data, struct cmd_lookupsid_state);
	NTSTATUS status = composite_wait(c);
	if (NT_STATUS_IS_OK(status)) {
		*sid = talloc_steal(mem_ctx, state->result);
	}
	talloc_free(state);
	return status;
}

NTSTATUS wb_cmd_lookupsid(struct wbsrv_service *service,
			  const struct dom_sid *sid,
			  TALLOC_CTX *mem_ctx, struct wb_sid_object **name)
{
	struct composite_context *c =
		wb_cmd_lookupsid_send(service, sid);
	return wb_cmd_lookupsid_recv(c, mem_ctx, name);
}
