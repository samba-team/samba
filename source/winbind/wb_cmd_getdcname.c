/* 
   Unix SMB/CIFS implementation.

   Command backend for wbinfo --getdcname

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

#include "librpc/gen_ndr/ndr_netlogon.h"

static void composite_netr_GetAnyDCName_recv_rpc(struct rpc_request *req);

static struct composite_context *composite_netr_GetAnyDCName_send(struct dcerpc_pipe *p,
								  TALLOC_CTX *mem_ctx,
								  struct netr_GetAnyDCName *r)
{
	struct composite_context *result;
	struct rpc_request *req;

	result = talloc(mem_ctx, struct composite_context);
	if (result == NULL) goto failed;
	result->state = COMPOSITE_STATE_IN_PROGRESS;
	result->async.fn = NULL;
	result->event_ctx = p->conn->event_ctx;

	req = dcerpc_netr_GetAnyDCName_send(p, mem_ctx, r);
	if (req == NULL) goto failed;
	req->async.callback = composite_netr_GetAnyDCName_recv_rpc;
	req->async.private = result;
	return result;

 failed:
	talloc_free(result);
	return NULL;
}

static void composite_netr_GetAnyDCName_recv_rpc(struct rpc_request *req)
{
	struct composite_context *ctx =
		talloc_get_type(req->async.private, struct composite_context);

	ctx->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(ctx)) return;
	composite_done(ctx);
}

NTSTATUS composite_netr_GetAnyDCName_recv(struct composite_context *ctx)
{
	NTSTATUS status = composite_wait(ctx);
	talloc_free(ctx);
	return status;
}

struct cmd_getdcname_state {
	struct composite_context *ctx;
	struct wbsrv_domain *domain;
	const char *domain_name;

	struct netr_GetAnyDCName g;
};

static struct composite_context *getdcname_send_req(void *p);
static NTSTATUS getdcname_recv_req(struct composite_context *ctx, void *p);

struct composite_context *wb_cmd_getdcname_send(struct wbsrv_call *call,
						const char *domain)
{
	struct cmd_getdcname_state *state;
	struct wbsrv_service *service = call->wbconn->listen_socket->service;

	state = talloc(NULL, struct cmd_getdcname_state);
	state->domain = service->domains;
	state->domain_name = talloc_strdup(state, domain);
	state->ctx = wb_queue_domain_send(state, state->domain,
					  call->event_ctx,
					  call->wbconn->conn->msg_ctx,
					  getdcname_send_req,
					  getdcname_recv_req,
					  state);
	if (state->ctx == NULL) {
		talloc_free(state);
		return NULL;
	}
	state->ctx->private_data = state;
	return state->ctx;
}

static struct composite_context *getdcname_send_req(void *p)
{
	struct cmd_getdcname_state *state =
		talloc_get_type(p, struct cmd_getdcname_state);

	state->g.in.logon_server = talloc_asprintf(
		state, "\\\\%s",
		dcerpc_server_name(state->domain->netlogon_pipe));
	state->g.in.domainname = state->domain_name;

	return composite_netr_GetAnyDCName_send(state->domain->netlogon_pipe,
						state, &state->g);
}

static NTSTATUS getdcname_recv_req(struct composite_context *ctx, void *p)
{
	struct cmd_getdcname_state *state =
		talloc_get_type(p, struct cmd_getdcname_state);
	NTSTATUS status;

	status = composite_netr_GetAnyDCName_recv(ctx);
	NT_STATUS_NOT_OK_RETURN(status);

	if (!W_ERROR_IS_OK(state->g.out.result)) {
		return werror_to_ntstatus(state->g.out.result);
	}

	return NT_STATUS_OK;
}

NTSTATUS wb_cmd_getdcname_recv(struct composite_context *c,
			       TALLOC_CTX *mem_ctx,
			       const char **dcname)
{
	struct cmd_getdcname_state *state =
		talloc_get_type(c->private_data, struct cmd_getdcname_state);
	NTSTATUS status = composite_wait(c);
	if (NT_STATUS_IS_OK(status)) {
		const char *p = state->g.out.dcname;
		if (*p == '\\') p += 1;
		if (*p == '\\') p += 1;
		*dcname = talloc_strdup(mem_ctx, p);
		if (*dcname == NULL) {
			status = NT_STATUS_NO_MEMORY;
		}
	}
	talloc_free(state);
	return status;
}
