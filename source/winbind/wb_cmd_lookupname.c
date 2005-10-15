/* 
   Unix SMB/CIFS implementation.

   Command backend for wbinfo -n

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

struct cmd_lookupname_state {
	struct composite_context *ctx;
	struct wbsrv_call *call;
	struct wbsrv_domain *domain;
	const char *name;
	struct wb_sid_object *result;
};

static struct composite_context *lookupname_send_req(void *p);
static NTSTATUS lookupname_recv_req(struct composite_context *ctx, void *p);

struct composite_context *wb_cmd_lookupname_send(struct wbsrv_call *call,
						 const char *name)
{
	struct cmd_lookupname_state *state;
	struct wbsrv_service *service = call->wbconn->listen_socket->service;

	state = talloc(NULL, struct cmd_lookupname_state);
	state->domain = service->domains;
	state->call = call;
	state->name = talloc_strdup(state, name);
	state->ctx = wb_queue_domain_send(state, state->domain,
					  call->event_ctx,
					  call->wbconn->conn->msg_ctx,
					  lookupname_send_req,
					  lookupname_recv_req,
					  state);
	if (state->ctx == NULL) {
		talloc_free(state);
		return NULL;
	}
	state->ctx->private_data = state;
	return state->ctx;
}

static struct composite_context *lookupname_send_req(void *p)
{
	struct cmd_lookupname_state *state =
		talloc_get_type(p, struct cmd_lookupname_state);

	return wb_lsa_lookupnames_send(state->domain->lsa_pipe,
				       state->domain->lsa_policy,
				       1, &state->name);
}

static NTSTATUS lookupname_recv_req(struct composite_context *ctx, void *p)
{
	struct cmd_lookupname_state *state =
		talloc_get_type(p, struct cmd_lookupname_state);
	struct wb_sid_object **sids;
	NTSTATUS status;

	status = wb_lsa_lookupnames_recv(ctx, state, &sids);
	if (NT_STATUS_IS_OK(status)) {
		state->result = sids[0];
	}
	return status;
}

NTSTATUS wb_cmd_lookupname_recv(struct composite_context *c,
				TALLOC_CTX *mem_ctx,
				struct wb_sid_object **sid)
{
	struct cmd_lookupname_state *state =
		talloc_get_type(c->private_data, struct cmd_lookupname_state);
	NTSTATUS status = composite_wait(c);
	if (NT_STATUS_IS_OK(status)) {
		*sid = talloc_steal(mem_ctx, state->result);
	}
	talloc_free(state);
	return status;
}

NTSTATUS wb_cmd_lookupname(struct wbsrv_call *call, const char *name,
			   TALLOC_CTX *mem_ctx, struct wb_sid_object **sid)
{
	struct composite_context *c =
		wb_cmd_lookupname_send(call, name);
	return wb_cmd_lookupname_recv(c, mem_ctx, sid);
}
