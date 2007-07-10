/* 
   Unix SMB/CIFS implementation.
   Main winbindd irpc handlers

   Copyright (C) Stefan Metzmacher	2006
   
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
#include "winbind/wb_server.h"
#include "lib/messaging/irpc.h"
#include "libcli/composite/composite.h"
#include "librpc/gen_ndr/ndr_winbind.h"
#include "smbd/service_task.h"

struct wb_irpc_SamLogon_state {
	struct irpc_message *msg;
	struct winbind_SamLogon *req;
};

static void wb_irpc_SamLogon_callback(struct composite_context *ctx);

static NTSTATUS wb_irpc_SamLogon(struct irpc_message *msg, 
				 struct winbind_SamLogon *req)
{
	struct wbsrv_service *service = talloc_get_type(msg->private,
					struct wbsrv_service);
	struct wb_irpc_SamLogon_state *s;
	struct composite_context *ctx;

	DEBUG(5, ("wb_irpc_SamLogon called\n"));

	s = talloc(msg, struct wb_irpc_SamLogon_state);
	NT_STATUS_HAVE_NO_MEMORY(s);

	s->msg = msg;
	s->req = req;

	ctx = wb_sam_logon_send(msg, service, req);
	NT_STATUS_HAVE_NO_MEMORY(ctx);

	ctx->async.fn = wb_irpc_SamLogon_callback;
	ctx->async.private_data = s;

	msg->defer_reply = True;
	return NT_STATUS_OK;
}

static void wb_irpc_SamLogon_callback(struct composite_context *ctx)
{
	struct wb_irpc_SamLogon_state *s = talloc_get_type(ctx->async.private_data,
					   struct wb_irpc_SamLogon_state);
	NTSTATUS status;

	DEBUG(5, ("wb_irpc_SamLogon_callback called\n"));

	status = wb_sam_logon_recv(ctx, s, s->req);

	irpc_send_reply(s->msg, status);
}

NTSTATUS wbsrv_init_irpc(struct wbsrv_service *service)
{
	NTSTATUS status;

	irpc_add_name(service->task->msg_ctx, "winbind_server");

	status = IRPC_REGISTER(service->task->msg_ctx, winbind, WINBIND_SAMLOGON,
			       wb_irpc_SamLogon, service);
	NT_STATUS_NOT_OK_RETURN(status);

	return NT_STATUS_OK;
}
