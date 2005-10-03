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
#include "librpc/rpc/dcerpc_composite.h"
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

#define null_no_memory_done(x) do { \
	if ((x) == NULL) { status = NT_STATUS_NO_MEMORY; goto done; } \
	} while (0)

struct check_machacc_state {
	struct wb_finddcs *io;
	struct smb_composite_connect *conn;
	struct wb_get_schannel_creds *getcreds;
};

static void wbsrv_samba3_check_machacc_receive_creds(struct composite_context *action);
static void wbsrv_samba3_check_machacc_receive_tree(struct composite_context *action);
static void wbsrv_samba3_check_machacc_receive_dcs(struct composite_context *action);

NTSTATUS wbsrv_samba3_check_machacc(struct wbsrv_samba3_call *s3call)
{
	struct composite_context *resolve_req;
	struct check_machacc_state *state;
	struct wbsrv_service *service =
		s3call->call->wbconn->listen_socket->service;

	DEBUG(5, ("check_machacc called\n"));

	if (service->netlogon != NULL) {
		talloc_free(service->netlogon);
	}

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
	resolve_req->async.fn = wbsrv_samba3_check_machacc_receive_dcs;
	resolve_req->async.private_data	= s3call;

	/* tell the caller we reply later */
	s3call->call->flags |= WBSRV_CALL_FLAGS_REPLY_ASYNC;
	return NT_STATUS_OK;
}

static void wbsrv_samba3_check_machacc_receive_dcs(struct composite_context *action)
{
	struct wbsrv_samba3_call *s3call =
		talloc_get_type(action->async.private_data,
				struct wbsrv_samba3_call);
	struct check_machacc_state *state =
		talloc_get_type(s3call->private_data,
				struct check_machacc_state);
	struct composite_context *ctx;
	NTSTATUS status;

	status = wb_finddcs_recv(action, s3call);

	s3call->response.data.auth.nt_status = NT_STATUS_V(status);
	WBSRV_SAMBA3_SET_STRING(s3call->response.data.auth.nt_status_string,
				nt_errstr(status));
	WBSRV_SAMBA3_SET_STRING(s3call->response.data.auth.error_string,
				nt_errstr(status));
	s3call->response.data.auth.pam_error = nt_status_to_pam(status);

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	state->conn = talloc(state, struct smb_composite_connect);
	if (state->conn == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	state->conn->in.dest_host = state->io->out.dcs[0].address;
	state->conn->in.port = 0;
	state->conn->in.called_name = state->io->out.dcs[0].name;
	state->conn->in.service = "IPC$";
	state->conn->in.service_type = "IPC";
	state->conn->in.workgroup = lp_workgroup();

	state->conn->in.credentials = cli_credentials_init(state->conn);
	if (state->conn->in.credentials == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	cli_credentials_set_conf(state->conn->in.credentials);
	cli_credentials_set_anonymous(state->conn->in.credentials);

	ctx = smb_composite_connect_send(state->conn, state,
					 s3call->call->event_ctx);
	if (ctx == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	ctx->async.fn = wbsrv_samba3_check_machacc_receive_tree;
	ctx->async.private_data = s3call;
	return;

 done:
	if (!NT_STATUS_IS_OK(status)) {
		s3call->response.result = WINBINDD_ERROR;
	}

	status = wbsrv_send_reply(s3call->call);
	if (!NT_STATUS_IS_OK(status)) {
		wbsrv_terminate_connection(s3call->call->wbconn,
					   "wbsrv_queue_reply() failed");
		return;
	}
}

static void wbsrv_samba3_check_machacc_receive_tree(struct composite_context *action)
{
	struct wbsrv_samba3_call *s3call =
		talloc_get_type(action->async.private_data,
				struct wbsrv_samba3_call);
	struct check_machacc_state *state =
		talloc_get_type(s3call->private_data,
				struct check_machacc_state);
	struct composite_context *ctx;
	NTSTATUS status;
	struct cli_credentials *creds;

	status = smb_composite_connect_recv(action, state);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5, ("Connect failed: %s\n", nt_errstr(status)));
		goto done;
	}

	state->getcreds = talloc(state, struct wb_get_schannel_creds);
	null_no_memory_done(state->getcreds);

	creds = cli_credentials_init(state);
	null_no_memory_done(creds);
	cli_credentials_set_conf(creds);
	status = cli_credentials_set_machine_account(creds);
	if (!NT_STATUS_IS_OK(status)) goto done;

	state->getcreds->in.tree = state->conn->out.tree;
	state->getcreds->in.creds = creds;

	ctx = wb_get_schannel_creds_send(state->getcreds,
					 s3call->call->event_ctx);
	null_no_memory_done(ctx);

	ctx->async.fn = wbsrv_samba3_check_machacc_receive_creds;
	ctx->async.private_data = s3call;

	return;
	
 done:
	s3call->response.result = WINBINDD_OK;

	if (!NT_STATUS_IS_OK(status)) {
		s3call->response.result = WINBINDD_ERROR;
		WBSRV_SAMBA3_SET_STRING(s3call->response.data.auth.nt_status_string,
					nt_errstr(status));
		WBSRV_SAMBA3_SET_STRING(s3call->response.data.auth.error_string,
					nt_errstr(status));
		s3call->response.data.auth.pam_error = nt_status_to_pam(status);

	}

	status = wbsrv_send_reply(s3call->call);
	if (!NT_STATUS_IS_OK(status)) {
		wbsrv_terminate_connection(s3call->call->wbconn,
					   "wbsrv_queue_reply() failed");
		return;
	}
}

static void delete_pipe(struct event_context *ctx, struct timed_event *te,
			struct timeval tv, void *p)
{
	talloc_free(p);
}

static void wbsrv_samba3_check_machacc_receive_creds(struct composite_context *action)
{
	struct wbsrv_samba3_call *s3call =
		talloc_get_type(action->async.private_data,
				struct wbsrv_samba3_call);
	struct check_machacc_state *state =
		talloc_get_type(s3call->private_data,
				struct check_machacc_state);
	struct wbsrv_service *service =
		s3call->call->wbconn->listen_socket->service;
	
	NTSTATUS status;
	
	status = wb_get_schannel_creds_recv(action, service);

	talloc_unlink(state, state->conn->out.tree); /* The pipe owns it now */
	state->conn->out.tree = NULL;

	if (!NT_STATUS_IS_OK(status)) {
		/* Nasty hack awaiting a proper fix. So far we can not
		 * delete a pipe from an async rpc callback which where we are
		 * in right now, so delete the pipe in 5 seconds.... :-) */
		event_add_timed(s3call->call->event_ctx, service,
				timeval_current_ofs(5, 0),
				delete_pipe, state->getcreds->out.netlogon);
		service->netlogon = NULL;
		goto done;
	}

	service->netlogon = state->getcreds->out.netlogon;
	s3call->response.result = WINBINDD_OK;
 done:
	if (!NT_STATUS_IS_OK(status)) {
		s3call->response.result = WINBINDD_ERROR;
		WBSRV_SAMBA3_SET_STRING(s3call->response.data.auth.nt_status_string,
					nt_errstr(status));
		WBSRV_SAMBA3_SET_STRING(s3call->response.data.auth.error_string,
					nt_errstr(status));
		s3call->response.data.auth.pam_error = nt_status_to_pam(status);

	}

	status = wbsrv_send_reply(s3call->call);
	if (!NT_STATUS_IS_OK(status)) {
		wbsrv_terminate_connection(s3call->call->wbconn,
					   "wbsrv_queue_reply() failed");
		return;
	}
}
