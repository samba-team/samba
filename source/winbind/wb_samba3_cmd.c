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
#include "librpc/gen_ndr/ndr_netlogon.h"

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

	ctx = wb_cmd_checkmachacc_send(s3call->call);
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

	status = wb_cmd_checkmachacc_recv(ctx);
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

NTSTATUS wbsrv_samba3_pam_auth(struct wbsrv_samba3_call *s3call)
{
	struct wbsrv_service *service =
		s3call->call->wbconn->listen_socket->service;
	
	s3call->response.result			= WINBINDD_ERROR;
	return NT_STATUS_OK;
}

NTSTATUS wbsrv_samba3_pam_auth_crap(struct wbsrv_samba3_call *s3call)
{
	struct wbsrv_service *service =
		s3call->call->wbconn->listen_socket->service;
	struct creds_CredentialState *creds_state;
	struct netr_Authenticator auth, auth2;
	struct netr_NetworkInfo ninfo;
	struct netr_LogonSamLogon r;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(s3call);
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCT(auth2);
	creds_state = cli_credentials_get_netlogon_creds(service->domains->schannel_creds);
	
	creds_client_authenticator(creds_state, &auth);

	ninfo.identity_info.account_name.string = s3call->request.data.auth_crap.user;
	ninfo.identity_info.domain_name.string = s3call->request.data.auth_crap.domain;
	ninfo.identity_info.parameter_control = 0;
	ninfo.identity_info.logon_id_low = 0;
	ninfo.identity_info.logon_id_high = 0;
	ninfo.identity_info.workstation.string = s3call->request.data.auth_crap.workstation;
	memcpy(ninfo.challenge, s3call->request.data.auth_crap.chal,
	       sizeof(ninfo.challenge));
	ninfo.nt.length = s3call->request.data.auth_crap.nt_resp_len;
	ninfo.nt.data = s3call->request.data.auth_crap.nt_resp;
	ninfo.lm.length = s3call->request.data.auth_crap.lm_resp_len;
	ninfo.lm.data = s3call->request.data.auth_crap.lm_resp;

	r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(service->domains->netlogon_pipe));
	r.in.workstation = cli_credentials_get_workstation(service->domains->schannel_creds);
	r.in.credential = &auth;
	r.in.return_authenticator = &auth2;
	r.in.logon_level = 2;
	r.in.validation_level = 3;
	r.in.logon.network = &ninfo;

	r.out.return_authenticator = NULL;
	status = dcerpc_netr_LogonSamLogon(service->domains->netlogon_pipe, mem_ctx, &r);
	if (!r.out.return_authenticator || 
	    !creds_client_check(creds_state, &r.out.return_authenticator->cred)) {
		DEBUG(0, ("Credentials check failed!\n"));
		status = NT_STATUS_ACCESS_DENIED;
	}
	if (NT_STATUS_IS_OK(status)) {
		struct netr_SamBaseInfo *base;
		switch (r.in.validation_level) {
		case 2:
			base = &r.out.validation.sam2->base;
			break;
		case 3:
			base = &r.out.validation.sam3->base;
			break;
		case 6:
			base = &r.out.validation.sam6->base;
			break;
		}

		creds_decrypt_samlogon(creds_state, 
				       r.in.validation_level, 
				       &r.out.validation);

		if ((s3call->request.flags & WBFLAG_PAM_INFO3_NDR) 
		    && (r.in.validation_level == 3)) {
			DATA_BLOB tmp_blob, tmp_blob2;
			status = ndr_push_struct_blob(&tmp_blob, mem_ctx, r.out.validation.sam3,
						      (ndr_push_flags_fn_t)ndr_push_netr_SamInfo3);
			if (NT_STATUS_IS_OK(status)) {
				tmp_blob2 = data_blob_talloc(mem_ctx, NULL, tmp_blob.length + 4);
				if (!tmp_blob2.data) {
					status = NT_STATUS_NO_MEMORY;
				}
			}
			/* Ugly Samba3 winbind pipe compatability */
			if (NT_STATUS_IS_OK(status)) {
				SIVAL(tmp_blob2.data, 0, 1);
				memcpy(tmp_blob2.data + 4, tmp_blob.data, tmp_blob.length); 
			}
			s3call->response.extra_data = talloc_steal(s3call, tmp_blob2.data);
			s3call->response.length += tmp_blob2.length;
		}
		if (s3call->request.flags & WBFLAG_PAM_USER_SESSION_KEY) {
			memcpy(s3call->response.data.auth.user_session_key, 
			       base->key.key, sizeof(s3call->response.data.auth.user_session_key) /* 16 */);
		}
		if (s3call->request.flags & WBFLAG_PAM_LMKEY) {
			memcpy(s3call->response.data.auth.first_8_lm_hash, 
			       base->LMSessKey.key, sizeof(s3call->response.data.auth.first_8_lm_hash) /* 8 */);
		}
	}
		
	if (!NT_STATUS_IS_OK(status)) {
		struct winbindd_response *resp = &s3call->response;
		resp->result = WINBINDD_ERROR;
	} else {
		struct winbindd_response *resp = &s3call->response;
		resp->result = WINBINDD_OK;
	}
		
	WBSRV_SAMBA3_SET_STRING(s3call->response.data.auth.nt_status_string,
				nt_errstr(status));
	WBSRV_SAMBA3_SET_STRING(s3call->response.data.auth.error_string,
				nt_errstr(status));
	s3call->response.data.auth.pam_error = nt_status_to_pam(status);
	return NT_STATUS_OK;
}
