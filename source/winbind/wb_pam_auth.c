/* 
   Unix SMB/CIFS implementation.

   Authenticate a user

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
#include "winbind/wb_async_helpers.h"
#include "winbind/wb_server.h"
#include "smbd/service_stream.h"
#include "libcli/auth/credentials.h"

struct pam_auth_crap_state {
	struct composite_context *ctx;
	struct wbsrv_domain *domain;
	const char *domain_name;
	const char *user_name;
	const char *workstation;
	DATA_BLOB chal, nt_resp, lm_resp;

        struct creds_CredentialState *creds_state;
        struct netr_Authenticator auth, auth2;
        struct netr_NetworkInfo ninfo;
        struct netr_LogonSamLogon r;

	struct netr_UserSessionKey user_session_key;
	struct netr_LMSessionKey lm_key;
	DATA_BLOB info3;
};

static struct rpc_request *send_samlogon(struct pam_auth_crap_state *state);
static void pam_auth_crap_recv_init(struct composite_context *ctx);
static void pam_auth_crap_recv_samlogon(struct rpc_request *req);

struct composite_context *wb_pam_auth_crap_send(struct wbsrv_call *call,
						const char *domain,
						const char *user,
						const char *workstation,
						DATA_BLOB chal,
						DATA_BLOB nt_resp,
						DATA_BLOB lm_resp)
{
	struct composite_context *result, *ctx;
	struct pam_auth_crap_state *state;
	struct wbsrv_service *service = call->wbconn->listen_socket->service;

	result = talloc(NULL, struct composite_context);
	if (result == NULL) goto failed;
	result->state = COMPOSITE_STATE_IN_PROGRESS;
	result->event_ctx = call->event_ctx;
	result->async.fn = NULL;

	state = talloc(result, struct pam_auth_crap_state);
	if (state == NULL) goto failed;
	state->ctx = result;
	result->private_data = state;

	state->domain = service->domains;

	state->domain_name = talloc_strdup(state, domain);
	if (state->domain_name == NULL) goto failed;

	state->user_name = talloc_strdup(state, user);
	if (state->user_name == NULL) goto failed;

	state->workstation = talloc_strdup(state, workstation);
	if (state->workstation == NULL) goto failed;

	state->chal = data_blob_talloc(state, chal.data, chal.length);
	if ((chal.data != NULL) && (state->chal.data == NULL)) goto failed;

	state->nt_resp = data_blob_talloc(state, nt_resp.data, nt_resp.length);
	if ((nt_resp.data != NULL) &&
	    (state->nt_resp.data == NULL)) goto failed;

	state->lm_resp = data_blob_talloc(state, lm_resp.data, lm_resp.length);
	if ((lm_resp.data != NULL) &&
	    (state->lm_resp.data == NULL)) goto failed;

	if (state->domain->initialized) {
		struct rpc_request *req = send_samlogon(state);
		if (req == NULL) goto failed;
		req->async.callback = pam_auth_crap_recv_samlogon;
		req->async.private = state;
		return result;
	}

	ctx = wb_init_domain_send(state->domain, result->event_ctx,
				  call->wbconn->conn->msg_ctx);
	if (ctx == NULL) goto failed;
	ctx->async.fn = pam_auth_crap_recv_init;
	ctx->async.private_data = state;
	return result;

 failed:
	talloc_free(result);
	return NULL;
}

static void pam_auth_crap_recv_init(struct composite_context *ctx)
{
	struct pam_auth_crap_state *state =
		talloc_get_type(ctx->async.private_data,
				struct pam_auth_crap_state);
	struct rpc_request *req;

	state->ctx->status = wb_init_domain_recv(ctx);
	if (!composite_is_ok(state->ctx)) return;

	req = send_samlogon(state);
	composite_continue_rpc(state->ctx, req,
			       pam_auth_crap_recv_samlogon, state);
}

static struct rpc_request *send_samlogon(struct pam_auth_crap_state *state)
{
	state->creds_state = cli_credentials_get_netlogon_creds(
		state->domain->schannel_creds);
	creds_client_authenticator(state->creds_state, &state->auth);

	state->ninfo.identity_info.account_name.string = state->user_name;
	state->ninfo.identity_info.domain_name.string =  state->domain_name;
	state->ninfo.identity_info.parameter_control = 0;
	state->ninfo.identity_info.logon_id_low = 0;
	state->ninfo.identity_info.logon_id_high = 0;
	state->ninfo.identity_info.workstation.string = state->workstation;

	SMB_ASSERT(state->chal.length == sizeof(state->ninfo.challenge));
	memcpy(state->ninfo.challenge, state->chal.data,
	       sizeof(state->ninfo.challenge));

	state->ninfo.nt.length = state->nt_resp.length;
	state->ninfo.nt.data = state->nt_resp.data;
	state->ninfo.lm.length = state->lm_resp.length;
	state->ninfo.lm.data = state->lm_resp.data;

	state->r.in.server_name = talloc_asprintf(
		state, "\\\\%s",
		dcerpc_server_name(state->domain->netlogon_pipe));
	if (state->r.in.server_name == NULL) return NULL;

	state->r.in.workstation = cli_credentials_get_workstation(
		state->domain->schannel_creds);
	state->r.in.credential = &state->auth;
	state->r.in.return_authenticator = &state->auth2;
	state->r.in.logon_level = 2;
	state->r.in.validation_level = 3;
	state->r.in.logon.network = &state->ninfo;
	state->r.out.return_authenticator = NULL;

	return dcerpc_netr_LogonSamLogon_send(state->domain->netlogon_pipe,
					      state, &state->r);
}

static void pam_auth_crap_recv_samlogon(struct rpc_request *req)
{
	struct pam_auth_crap_state *state =
		talloc_get_type(req->async.private,
				struct pam_auth_crap_state);
	struct netr_SamBaseInfo *base;
	DATA_BLOB tmp_blob;

	state->ctx->status = dcerpc_ndr_request_recv(req);
	if (!composite_is_ok(state->ctx)) return;
	state->ctx->status = state->r.out.result;
	if (!composite_is_ok(state->ctx)) return;

	if ((state->r.out.return_authenticator == NULL) ||
	    (!creds_client_check(state->creds_state,
				 &state->r.out.return_authenticator->cred))) {
		DEBUG(0, ("Credentials check failed!\n"));
		composite_error(state->ctx, NT_STATUS_ACCESS_DENIED);
		return;
	}

	creds_decrypt_samlogon(state->creds_state,
			       state->r.in.validation_level,
			       &state->r.out.validation);

	state->ctx->status = ndr_push_struct_blob(
		&tmp_blob, state, state->r.out.validation.sam3,
		(ndr_push_flags_fn_t)ndr_push_netr_SamInfo3);
	if (!composite_is_ok(state->ctx)) return;

	state->info3 = data_blob_talloc(state, NULL, tmp_blob.length+4);
	if (composite_nomem(state->info3.data, state->ctx)) return;

	SIVAL(state->info3.data, 0, 1);
	memcpy(state->info3.data+4, tmp_blob.data, tmp_blob.length);

	base = NULL;
	switch(state->r.in.validation_level) {
	case 2:
		base = &state->r.out.validation.sam2->base;
		break;
	case 3:
		base = &state->r.out.validation.sam3->base;
		break;
	case 6:
		base = &state->r.out.validation.sam6->base;
		break;
	}
	if (base == NULL) {
		composite_error(state->ctx, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	state->user_session_key = base->key;
	state->lm_key = base->LMSessKey;

	composite_done(state->ctx);
}

NTSTATUS wb_pam_auth_crap_recv(struct composite_context *c,
			       TALLOC_CTX *mem_ctx,
			       DATA_BLOB *info3,
			       struct netr_UserSessionKey *user_session_key,
			       struct netr_LMSessionKey *lm_key)
{
	NTSTATUS status = composite_wait(c);
	if (NT_STATUS_IS_OK(status)) {
		struct pam_auth_crap_state *state =
			talloc_get_type(c->private_data,
					struct pam_auth_crap_state);
		info3->length = state->info3.length;
		info3->data = talloc_steal(mem_ctx, state->info3.data);
		*user_session_key = state->user_session_key;
		*lm_key = state->lm_key;
	}
	talloc_free(c);
	return status;
}

NTSTATUS wb_pam_auth_crap(struct wbsrv_call *call,
			  const char *domain, const char *user,
			  const char *workstation,
			  DATA_BLOB chal, DATA_BLOB nt_resp,
			  DATA_BLOB lm_resp, TALLOC_CTX *mem_ctx,
			  DATA_BLOB *info3,
			  struct netr_UserSessionKey *user_session_key,
			  struct netr_LMSessionKey *lm_key)
{
	struct composite_context *c =
		wb_pam_auth_crap_send(call, domain, user, workstation,
				      chal, nt_resp, lm_resp);
	return wb_pam_auth_crap_recv(c, mem_ctx, info3, user_session_key,
				     lm_key);
}
