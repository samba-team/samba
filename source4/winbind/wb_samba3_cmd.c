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
#include "libcli/smb_composite/smb_composite.h"
#include "include/version.h"
#include "lib/events/events.h"

NTSTATUS wbsrv_samba3_interface_version(struct wbsrv_samba3_call *s3call)
{
	s3call->response.result			= WINBINDD_OK;
	s3call->response.data.interface_version	= WINBIND_INTERFACE_VERSION;
	return NT_STATUS_OK;
}

NTSTATUS wbsrv_samba3_info(struct wbsrv_samba3_call *s3call)
{
	s3call->response.result			= WINBINDD_OK;
	s3call->response.data.info.winbind_separator = *lp_winbind_separator();
	WBSRV_SAMBA3_SET_STRING(s3call->response.data.info.samba_version, SAMBA_VERSION_STRING);
	return NT_STATUS_OK;
}

NTSTATUS wbsrv_samba3_domain_name(struct wbsrv_samba3_call *s3call)
{
	s3call->response.result			= WINBINDD_OK;
	WBSRV_SAMBA3_SET_STRING(s3call->response.data.domain_name, lp_workgroup());
	return NT_STATUS_OK;
}

NTSTATUS wbsrv_samba3_netbios_name(struct wbsrv_samba3_call *s3call)
{
	s3call->response.result			= WINBINDD_OK;
	WBSRV_SAMBA3_SET_STRING(s3call->response.data.netbios_name, lp_netbios_name());
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

static void checkmachacc_recv_creds(struct composite_context *ctx);

NTSTATUS wbsrv_samba3_check_machacc(struct wbsrv_samba3_call *s3call)
{
	struct composite_context *ctx;

	DEBUG(5, ("wbsrv_samba3_check_machacc called\n"));

	ctx = wb_get_netlogon_pipe_send(s3call->call);
	NT_STATUS_HAVE_NO_MEMORY(ctx);

	ctx->async.fn = checkmachacc_recv_creds;
	ctx->async.private_data = s3call;
	s3call->call->flags |= WBSRV_CALL_FLAGS_REPLY_ASYNC;
	return NT_STATUS_OK;
}
	
static void checkmachacc_recv_creds(struct composite_context *ctx)
{
	struct wbsrv_samba3_call *s3call =
		talloc_get_type(ctx->async.private_data,
				struct wbsrv_samba3_call);
	NTSTATUS status;

	status = wb_get_netlogon_pipe_recv(ctx);
	if (NT_STATUS_IS_OK(status)) {
		s3call->response.result = WINBINDD_OK;
	} else {
		struct winbindd_response *resp = &s3call->response;
		resp->result = WINBINDD_ERROR;
		WBSRV_SAMBA3_SET_STRING(resp->data.auth.nt_status_string,
					nt_errstr(status));
		WBSRV_SAMBA3_SET_STRING(resp->data.auth.error_string,
					nt_errstr(status));
		resp->data.auth.pam_error = nt_status_to_pam(status);
	}
	status = wbsrv_send_reply(s3call->call);
	if (!NT_STATUS_IS_OK(status)) {
		wbsrv_terminate_connection(s3call->call->wbconn,
					   "wbsrv_queue_reply() failed");
		return;
	}
}

static void lookupname_recv_sid(struct composite_context *ctx);

NTSTATUS wbsrv_samba3_lookupname(struct wbsrv_samba3_call *s3call)
{
	struct composite_context *ctx;

	DEBUG(5, ("wbsrv_samba3_lookupname called\n"));

	ctx = wb_cmd_lookupname_send(s3call->call,
				     s3call->request.data.name.name);
	NT_STATUS_HAVE_NO_MEMORY(ctx);

	/* setup the callbacks */
	ctx->async.fn = lookupname_recv_sid;
	ctx->async.private_data	= s3call;
	s3call->call->flags |= WBSRV_CALL_FLAGS_REPLY_ASYNC;
	return NT_STATUS_OK;
}

static void lookupname_recv_sid(struct composite_context *ctx)
{
	struct wbsrv_samba3_call *s3call =
		talloc_get_type(ctx->async.private_data,
				struct wbsrv_samba3_call);
	struct wb_sid_object *sid;
	NTSTATUS status;

	status = wb_cmd_lookupname_recv(ctx, s3call, &sid);
	if (!NT_STATUS_IS_OK(status)) goto done;

	s3call->response.result = WINBINDD_OK;
	s3call->response.data.sid.type = sid->type;
	WBSRV_SAMBA3_SET_STRING(s3call->response.data.sid.sid,
				dom_sid_string(s3call, sid->sid));

 done:
	if (!NT_STATUS_IS_OK(status)) {
		struct winbindd_response *resp = &s3call->response;
		resp->result = WINBINDD_ERROR;
		WBSRV_SAMBA3_SET_STRING(resp->data.auth.nt_status_string,
					nt_errstr(status));
		WBSRV_SAMBA3_SET_STRING(resp->data.auth.error_string,
					nt_errstr(status));
		resp->data.auth.pam_error = nt_status_to_pam(status);
	}

	status = wbsrv_send_reply(s3call->call);
	if (!NT_STATUS_IS_OK(status)) {
		wbsrv_terminate_connection(s3call->call->wbconn,
					   "wbsrv_queue_reply() failed");
		return;
	}
}
