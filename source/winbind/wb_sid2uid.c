/*
   Unix SMB/CIFS implementation.

   Map a SID to a uid

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

struct sid2uid_state {
	struct composite_context *ctx;
	struct wbsrv_service *service;
	uid_t uid;
};

struct composite_context *wb_sid2uid_send(TALLOC_CTX *mem_ctx,
		struct wbsrv_service *service, const struct dom_sid *sid)
{
	struct composite_context *result;
	struct sid2uid_state *state;

	DEBUG(5, ("wb_sid2uid_send called\n"));

	result = composite_create(mem_ctx, service->task->event_ctx);
	if (!result) return NULL;

	state = talloc(result, struct sid2uid_state);
	if(composite_nomem(state, result)) return result;

	state->ctx = result;
	result->private_data = state;
	state->service = service;

	/*FIXME: This is a stub so far. */
	state->ctx->status = dom_sid_split_rid(result, sid, NULL, &state->uid);
	if(!composite_is_ok(state->ctx)) return result;

	DEBUG(5, ("Rid is %d\n", state->uid));

	composite_done(state->ctx);
	return result;
}

NTSTATUS wb_sid2uid_recv(struct composite_context *ctx, uid_t *uid)
{
	NTSTATUS status = composite_wait(ctx);

	DEBUG(5, ("wb_sid2uid_recv called\n"));

	if (NT_STATUS_IS_OK(status)) {
		struct sid2uid_state *state =
			talloc_get_type(ctx->private_data,
				struct sid2uid_state);
		*uid = state->uid;
	}
	talloc_free(ctx);
	return status;
}

