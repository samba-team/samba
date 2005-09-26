/* 
   Unix SMB/CIFS implementation.
   Main winbindd samba3 server routines

   Copyright (C) Stefan Metzmacher	2005
   Copyright (C) Volker Lendecke	2005

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
#include "smbd/service_stream.h"
#include "nsswitch/winbind_nss_config.h"
#include "nsswitch/winbindd_nss.h"
#include "winbind/wb_server.h"
#include "winbind/wb_samba3_protocol.h"
#include "winbind/wb_async_helpers.h"
#include "librpc/gen_ndr/nbt.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"

NTSTATUS wbsrv_samba3_interface_version(struct wbsrv_samba3_call *s3call)
{
	s3call->response.result			= WINBINDD_OK;
	s3call->response.data.interface_version	= WINBIND_INTERFACE_VERSION;
	return NT_STATUS_OK;
}

NTSTATUS wbsrv_samba3_priv_pipe_dir(struct wbsrv_samba3_call *s3call)
{
	s3call->response.result			= WINBINDD_OK;
	s3call->response.extra_data		= smbd_tmp_path(s3call,
						  WINBINDD_SAMBA3_PRIVILEGED_SOCKET);
	NT_STATUS_HAVE_NO_MEMORY(s3call->response.extra_data);
	return NT_STATUS_OK;
}

NTSTATUS wbsrv_samba3_ping(struct wbsrv_samba3_call *s3call)
{
	s3call->response.result			= WINBINDD_OK;
	return NT_STATUS_OK;
}

struct check_machacc_state {
	struct wb_finddcs *io;
};

static void wbsrv_samba3_check_machacc_reply(struct composite_context *action)
{
	struct wbsrv_samba3_call *s3call =
		talloc_get_type(action->async.private_data,
				struct wbsrv_samba3_call);
	struct check_machacc_state *state =
		talloc_get_type(s3call->private_data,
				struct check_machacc_state);
	NTSTATUS status;

	status = wb_finddcs_recv(action, s3call);
	if (NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("Got name %s\n", state->io->out.dcs[0].name));
		s3call->response.result = WINBINDD_OK;
	} else {
		DEBUG(10, ("Got no addr: %s\n", nt_errstr(status)));
		s3call->response.result = WINBINDD_ERROR;
	}

	status = wbsrv_send_reply(s3call->call);
	if (!NT_STATUS_IS_OK(status)) {
		wbsrv_terminate_connection(s3call->call->wbconn,
					   "wbsrv_queue_reply() failed");
		return;
	}
}

NTSTATUS wbsrv_samba3_check_machacc(struct wbsrv_samba3_call *s3call)
{
	struct composite_context *resolve_req;
	struct check_machacc_state *state;

	DEBUG(5, ("check_machacc called\n"));

	state = talloc(s3call, struct check_machacc_state);
	NT_STATUS_HAVE_NO_MEMORY(state);

	state->io = talloc(s3call, struct wb_finddcs);
	NT_STATUS_HAVE_NO_MEMORY(state->io);
	s3call->private_data = state;

	state->io->in.msg_ctx = s3call->call->wbconn->conn->msg_ctx;
	state->io->in.domain = lp_workgroup();

	resolve_req = wb_finddcs_send(state->io, s3call->call->event_ctx);
	NT_STATUS_HAVE_NO_MEMORY(resolve_req);

	/* setup the callbacks */
	resolve_req->async.fn		= wbsrv_samba3_check_machacc_reply;
	resolve_req->async.private_data	= s3call;

	/* tell the caller we reply later */
	s3call->call->flags |= WBSRV_CALL_FLAGS_REPLY_ASYNC;
	return NT_STATUS_OK;
}
