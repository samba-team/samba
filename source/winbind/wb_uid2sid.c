/*
   Unix SMB/CIFS implementation.

   Command backend for wbinfo -U

   Copyright (C) Kai Blin 2007

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
#include "libcli/composite/composite.h"
#include "winbind/wb_server.h"
#include "smbd/service_task.h"
#include "winbind/wb_helper.h"
#include "libcli/security/proto.h"

struct uid2sid_state {
	struct composite_context *ctx;
	struct wbsrv_service *service;
	struct dom_sid *sid;
};

struct composite_context *wb_uid2sid_send(TALLOC_CTX *mem_ctx,
		struct wbsrv_service *service, uid_t uid)
{
	struct composite_context *result;
	struct uid2sid_state *state;

	DEBUG(5, ("wb_uid2sid_send called\n"));

	result = composite_create(mem_ctx, service->task->event_ctx);
	if (!result) return NULL;

	state = talloc(mem_ctx, struct uid2sid_state);
	if (composite_nomem(state, result)) return result;

	state->ctx = result;
	result->private_data = state;
	state->service = service;

	/* FIXME: This is a stub so far.
	 * We cheat by just using the uid as RID with the domain SID.*/
	state->sid = dom_sid_add_rid(result, service->primary_sid, uid);
	if (composite_nomem(state->sid, state->ctx)) return result;

	composite_done(state->ctx);
	return result;
}

NTSTATUS wb_uid2sid_recv(struct composite_context *ctx, TALLOC_CTX *mem_ctx,
		struct dom_sid **sid)
{
	NTSTATUS status = composite_wait(ctx);

	DEBUG(5, ("wb_uid2sid_recv called.\n"));

	if (NT_STATUS_IS_OK(status)) {
		struct uid2sid_state *state =
			talloc_get_type(ctx->private_data,
				struct uid2sid_state);
		*sid = talloc_steal(mem_ctx, state->sid);
	}
	talloc_free(ctx);
	return status;
}

