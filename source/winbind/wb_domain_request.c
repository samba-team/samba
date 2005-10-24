/* 
   Unix SMB/CIFS implementation.

   A composite API for initializing a domain

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
#include "dlinklist.h"

struct domain_request_state {
	struct domain_request_state *prev, *next;
	struct composite_context *ctx;
	struct wbsrv_service *service;
	struct wbsrv_domain *domain;
	struct composite_context *(*send_fn)(struct wbsrv_domain *domain,
					     void *p);
	NTSTATUS (*recv_fn)(struct composite_context *c,
			    void *p);
	void *private_data;
};

static void domain_request_recv_domain(struct composite_context *ctx);
static void domain_request_recv_init(struct composite_context *ctx);
static void domain_request_recv_sub(struct composite_context *ctx);

struct composite_context *wb_domain_request_send(TALLOC_CTX *mem_ctx,
						 struct wbsrv_service *service,
						 const struct dom_sid *sid,
						 struct composite_context *(*send_fn)(struct wbsrv_domain *domain, void *p),
						 NTSTATUS (*recv_fn)(struct composite_context *c,
								     void *p),
						 void *private_data)
					      
{
	struct composite_context *result, *ctx;
	struct domain_request_state *state;

	result = talloc(mem_ctx, struct composite_context);
	if (result == NULL) goto failed;
	result->state = COMPOSITE_STATE_IN_PROGRESS;
	result->async.fn = NULL;
	result->event_ctx = service->task->event_ctx;

	state = talloc_zero(result, struct domain_request_state);
	if (state == NULL) goto failed;
	state->ctx = result;
	result->private_data = state;

	state->service = service;
	state->send_fn = send_fn;
	state->recv_fn = recv_fn;
	state->private_data = private_data;

	ctx = wb_sid2domain_send(service, sid);
	if (ctx == NULL) goto failed;

	ctx->async.fn = domain_request_recv_domain;
	ctx->async.private_data = state;
	return result;

 failed:
	talloc_free(result);
	return NULL;
}

static void domain_request_recv_domain(struct composite_context *ctx)
{
	struct domain_request_state *state =
		talloc_get_type(ctx->async.private_data,
				struct domain_request_state);

	state->ctx->status = wb_sid2domain_recv(ctx, &state->domain);
	if (!composite_is_ok(state->ctx)) return;

	if (state->domain->busy) {
		DEBUG(3, ("Domain %s busy\n", state->domain->name));
		DLIST_ADD_END(state->domain->request_queue, state,
			      struct domain_request_state *);
		return;
	}

	state->domain->busy = True;

	if (!state->domain->initialized) {
		ctx = wb_init_domain_send(state->service, state->domain);
		composite_continue(state->ctx, ctx, domain_request_recv_init,
				   state);
		return;
	}

	ctx = state->send_fn(state->domain, state->private_data);
	composite_continue(state->ctx, ctx, domain_request_recv_sub, state);
}

static void domain_request_recv_init(struct composite_context *ctx)
{
	struct domain_request_state *state =
		talloc_get_type(ctx->async.private_data,
				struct domain_request_state);

	state->ctx->status = wb_init_domain_recv(ctx);
	if (!composite_is_ok(state->ctx)) return;

	ctx = state->send_fn(state->domain, state->private_data);
	composite_continue(state->ctx, ctx, domain_request_recv_sub, state);
}

static void domain_request_recv_sub(struct composite_context *ctx)
{
	struct domain_request_state *state =
		talloc_get_type(ctx->async.private_data,
				struct domain_request_state);

	state->ctx->status = state->recv_fn(ctx, state->private_data);
	state->domain->busy = False;

	if (state->domain->request_queue != NULL) {
		struct domain_request_state *s2;
		s2 = state->domain->request_queue;
		DLIST_REMOVE(state->domain->request_queue, s2);
		ctx = s2->send_fn(state->domain, s2->private_data);
		composite_continue(s2->ctx, ctx, domain_request_recv_sub, s2);
		state->domain->busy = True;
	}

	if (!composite_is_ok(state->ctx)) return;
	composite_done(state->ctx);
}

NTSTATUS wb_domain_request_recv(struct composite_context *ctx)
{
	NTSTATUS status = composite_wait(ctx);
	talloc_free(ctx);
	return status;
}
