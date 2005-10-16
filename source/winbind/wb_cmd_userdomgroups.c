/* 
   Unix SMB/CIFS implementation.

   Command backend for wbinfo --user-domgroups

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
#include "lib/events/events.h"
#include "librpc/gen_ndr/ndr_security.h"

struct cmd_userdomgroups_state {
	struct composite_context *ctx;
	struct wbsrv_domain *domain;
	uint32_t user_rid;
	int num_rids;
	uint32_t *rids;
};

static void composite_trigger_now(struct event_context *ev,
				  struct timed_event *te,
				  struct timeval t, void *ptr)
{
	struct composite_context *c =
		talloc_get_type(ptr, struct composite_context);
	if (NT_STATUS_IS_OK(c->status)) {
		c->state = COMPOSITE_STATE_ERROR;
	} else {
		c->state = COMPOSITE_STATE_DONE;
	}
		
	if (c->async.fn) {
		c->async.fn(c);
	}
}


static struct composite_context *userdomgroups_send_req(void *p);
static NTSTATUS userdomgroups_recv_req(struct composite_context *ctx, void *p);

struct composite_context *wb_cmd_userdomgroups_send(struct wbsrv_call *call,
						    const struct dom_sid *sid)
{
	struct cmd_userdomgroups_state *state;
	struct wbsrv_service *service = call->wbconn->listen_socket->service;

	state = talloc(NULL, struct cmd_userdomgroups_state);
	state->domain = service->domains;

	if (dom_sid_in_domain(state->domain->sid, sid)) {
		state->user_rid = sid->sub_auths[sid->num_auths-1];
		state->ctx = wb_queue_domain_send(state, state->domain,
						  call->event_ctx,
						  call->wbconn->conn->msg_ctx,
						  userdomgroups_send_req,
						  userdomgroups_recv_req,
						  state);
		if (state->ctx == NULL) goto failed;
		state->ctx->private_data = state;
		return state->ctx;
	}

	state->ctx = talloc(state, struct composite_context);
	if (state->ctx == NULL) goto failed;
	state->ctx->state = COMPOSITE_STATE_IN_PROGRESS;
	state->ctx->async.fn = NULL;
	state->ctx->event_ctx = call->event_ctx;
	state->ctx->status = NT_STATUS_NO_SUCH_USER;
	state->ctx->private_data = state;

	/* Using composite_trigger_error here causes problems with the client
	 * socket. Linux 2.6.8 gives me a ECONNRESET on the next read after
	 * writing the reply when I don't wait the 100 milliseconds. */
	
	event_add_timed(state->ctx->event_ctx, state->ctx,
			timeval_current_ofs(0, 100000),
			composite_trigger_now, state->ctx);
	return state->ctx;

 failed:
	talloc_free(state);
	return NULL;
}

static struct composite_context *userdomgroups_send_req(void *p)
{
	struct cmd_userdomgroups_state *state =
		talloc_get_type(p, struct cmd_userdomgroups_state);

	return wb_samr_userdomgroups_send(state->domain->samr_pipe,
					  state->domain->domain_handle,
					  state->user_rid);
}

static NTSTATUS userdomgroups_recv_req(struct composite_context *ctx, void *p)
{
	struct cmd_userdomgroups_state *state =
		talloc_get_type(p, struct cmd_userdomgroups_state);

	return wb_samr_userdomgroups_recv(ctx, state, &state->num_rids,
					  &state->rids);
}

NTSTATUS wb_cmd_userdomgroups_recv(struct composite_context *c,
				   TALLOC_CTX *mem_ctx,
				   int *num_sids, struct dom_sid ***sids)
{
	struct cmd_userdomgroups_state *state =
		talloc_get_type(c->private_data,
				struct cmd_userdomgroups_state);
	int i;
	NTSTATUS status;

	status = composite_wait(c);
	if (!NT_STATUS_IS_OK(status)) goto done;

	*num_sids = state->num_rids;
	*sids = talloc_array(mem_ctx, struct dom_sid *, state->num_rids);
	if (*sids == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	for (i=0; i<state->num_rids; i++) {
		(*sids)[i] = dom_sid_add_rid((*sids), state->domain->sid,
					     state->rids[i]);
		if ((*sids)[i] == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
	}

done:
	talloc_free(state);
	return status;
}

NTSTATUS wb_cmd_userdomgroups(struct wbsrv_call *call,
			      const struct dom_sid *sid,
			      TALLOC_CTX *mem_ctx, int *num_sids,
			      struct dom_sid ***sids)
{
	struct composite_context *c =
		wb_cmd_userdomgroups_send(call, sid);
	return wb_cmd_userdomgroups_recv(c, mem_ctx, num_sids, sids);
}
