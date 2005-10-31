/* 
   Unix SMB/CIFS implementation.

   Authenticate a user

   Copyright (C) Volker Lendecke 2005
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   
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

/* Oh, there is so much to keep an eye on when authenticating a user.  Oh my! */
struct pam_auth_crap_state {
	struct composite_context *ctx;
	struct event_context *event_ctx;
	uint32_t logon_parameters;
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

static struct composite_context *crap_samlogon_send_req(struct wbsrv_domain *domain,
							void *p);
static NTSTATUS crap_samlogon_recv_req(struct composite_context *ctx, void *p);

/* NTLM authentication.

  Fill parameters into a control block to pass to the next function.
  No application logic, this is done by the helper function paramters
  to wb_domain_request_send()

*/

struct composite_context *wb_cmd_pam_auth_crap_send(struct wbsrv_call *call,
						    uint32_t logon_parameters,
						    const char *domain,
						    const char *user,
						    const char *workstation,
						    DATA_BLOB chal,
						    DATA_BLOB nt_resp,
						    DATA_BLOB lm_resp)
{
	struct pam_auth_crap_state *state;
	struct wbsrv_service *service = call->wbconn->listen_socket->service;

	state = talloc(NULL, struct pam_auth_crap_state);
	if (state == NULL) goto failed;

	state->event_ctx = call->event_ctx;

	state->logon_parameters = logon_parameters;

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

	state->ctx = wb_domain_request_send(state, service,
					    service->primary_sid,
					    crap_samlogon_send_req,
					    crap_samlogon_recv_req,
					    state);
	if (state->ctx == NULL) goto failed;
	state->ctx->private_data = state;
	return state->ctx;

 failed:
	talloc_free(state);
	return NULL;
}

/*  
    NTLM Authentication

    Send of a SamLogon request to authenticate a user.
*/
static struct composite_context *crap_samlogon_send_req(struct wbsrv_domain *domain,
							void *p)
{
	struct pam_auth_crap_state *state =
		talloc_get_type(p, struct pam_auth_crap_state);
	state->creds_state =
		cli_credentials_get_netlogon_creds(domain->schannel_creds);

	creds_client_authenticator(state->creds_state, &state->auth);

	state->ninfo.identity_info.account_name.string = state->user_name;
	state->ninfo.identity_info.domain_name.string =  state->domain_name;
	state->ninfo.identity_info.parameter_control = state->logon_parameters;
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
		state, "\\\\%s", dcerpc_server_name(domain->netlogon_pipe));
	if (state->r.in.server_name == NULL) return NULL;

	ZERO_STRUCT(state->auth2);

	state->r.in.workstation =
		cli_credentials_get_workstation(domain->schannel_creds);
	state->r.in.credential = &state->auth;
	state->r.in.return_authenticator = &state->auth2;
	state->r.in.logon_level = 2;
	state->r.in.validation_level = 3;
	state->r.in.logon.network = &state->ninfo;
	state->r.out.return_authenticator = NULL;

	return composite_netr_LogonSamLogon_send(domain->netlogon_pipe,
						 state, &state->r);
}

/* 
   NTLM Authentication 
   
   Check the SamLogon reply, decrypt and parse out the session keys and the info3 structure
*/
static NTSTATUS crap_samlogon_recv_req(struct composite_context *ctx,
				   void *p)
{
	struct pam_auth_crap_state *state =
		talloc_get_type(p, struct pam_auth_crap_state);
	struct netr_SamBaseInfo *base;
	DATA_BLOB tmp_blob;
	NTSTATUS status;

	status = composite_netr_LogonSamLogon_recv(ctx);
	if (!NT_STATUS_IS_OK(status)) return status;

	if ((state->r.out.return_authenticator == NULL) ||
	    (!creds_client_check(state->creds_state,
				 &state->r.out.return_authenticator->cred))) {
		DEBUG(0, ("Credentials check failed!\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	status = state->r.out.result;
	if (!NT_STATUS_IS_OK(status)) return status;

	/* Decrypt the session keys before we reform the info3, so the
	 * person on the other end of winbindd pipe doesn't have to.
	 * They won't have the encryption key anyway */
	creds_decrypt_samlogon(state->creds_state,
			       state->r.in.validation_level,
			       &state->r.out.validation);

	status = ndr_push_struct_blob(
		&tmp_blob, state,
		state->r.out.validation.sam3,
		(ndr_push_flags_fn_t)ndr_push_netr_SamInfo3);
	NT_STATUS_NOT_OK_RETURN(status);

	/* The Samba3 protocol is a bit broken (due to non-IDL
	 * heritage, so for compatability we must add a non-zero 4
	 * bytes to the info3 */
	state->info3 = data_blob_talloc(state, NULL, tmp_blob.length+4);
	NT_STATUS_HAVE_NO_MEMORY(state->info3.data);

	SIVAL(state->info3.data, 0, 1);
	memcpy(state->info3.data+4, tmp_blob.data, tmp_blob.length);

	/* We actually only ask for level 3, and assume it above, but anyway... */
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
		return NT_STATUS_INTERNAL_ERROR;
	}

	state->user_session_key = base->key;
	state->lm_key = base->LMSessKey;

	/* Give the caller the most accurate username possible.
	 * Assists where case sensitive comparisons may be done by our
	 * ntlm_auth callers */
	if (base->account_name.string) {
		state->user_name = base->account_name.string;
		talloc_steal(state, base->account_name.string);
	}
	if (base->domain.string) {
		state->domain_name = base->domain.string;
		talloc_steal(state, base->domain.string);
	}

	return NT_STATUS_OK;
}

NTSTATUS wb_cmd_pam_auth_crap_recv(struct composite_context *c,
				   TALLOC_CTX *mem_ctx,
				   DATA_BLOB *info3,
				   struct netr_UserSessionKey *user_session_key,
				   struct netr_LMSessionKey *lm_key,
				   char **unix_username)
{
	struct pam_auth_crap_state *state =
		talloc_get_type(c->private_data, struct pam_auth_crap_state);
	NTSTATUS status = composite_wait(c);
	if (NT_STATUS_IS_OK(status)) {
		info3->length = state->info3.length;
		info3->data = talloc_steal(mem_ctx, state->info3.data);
		*user_session_key = state->user_session_key;
		*lm_key = state->lm_key;
		*unix_username = talloc_asprintf(mem_ctx, "%s%s%s", 
						 state->domain_name, lp_winbind_separator(),
						 state->user_name);
		if (!*unix_username) {
			status = NT_STATUS_NO_MEMORY;
		}
	}
	talloc_free(state);
	return status;
}

NTSTATUS wb_cmd_pam_auth_crap(struct wbsrv_call *call,
			      uint32_t logon_parameters,
			      const char *domain, const char *user,
			      const char *workstation,
			      DATA_BLOB chal, DATA_BLOB nt_resp,
			      DATA_BLOB lm_resp, TALLOC_CTX *mem_ctx,
			      DATA_BLOB *info3,
			      struct netr_UserSessionKey *user_session_key,
			      struct netr_LMSessionKey *lm_key,
			      char **unix_username)
{
	struct composite_context *c =
		wb_cmd_pam_auth_crap_send(call, logon_parameters, 
					  domain, user, workstation,
					  chal, nt_resp, lm_resp);
	return wb_cmd_pam_auth_crap_recv(c, mem_ctx, info3, user_session_key,
					 lm_key, unix_username);
}

struct composite_context *wb_cmd_pam_auth_send(struct wbsrv_call *call,
					       const char *domain,
					       const char *user,
					       const char *password)
{
	struct composite_context *c;
	struct cli_credentials *credentials;
	const char *workstation;
	NTSTATUS status;

	DATA_BLOB chal, nt_resp, lm_resp, names_blob;
	int flags = CLI_CRED_NTLM_AUTH;
	if (lp_client_lanman_auth()) {
		flags |= CLI_CRED_LANMAN_AUTH;
	}

	if (lp_client_ntlmv2_auth()) {
		flags |= CLI_CRED_NTLMv2_AUTH;
	}

	DEBUG(5, ("wbsrv_samba3_pam_auth_crap called\n"));

	credentials = cli_credentials_init(call);
	if (!credentials) {
		return NULL;
	}
	cli_credentials_set_conf(credentials);
	cli_credentials_set_domain(credentials, domain, CRED_SPECIFIED);
	cli_credentials_set_username(credentials, user, CRED_SPECIFIED);

	cli_credentials_set_password(credentials, password, CRED_SPECIFIED);

	chal = data_blob_talloc(call, NULL, 8);
	if (!chal.data) {
		return NULL;
	}
	generate_random_buffer(chal.data, chal.length);
	cli_credentials_get_ntlm_username_domain(credentials, call,
						 &user, &domain);
	/* for best compatability with multiple vitual netbios names
	 * on the host, this should be generated from the
	 * cli_credentials associated with the machine account */
	workstation = cli_credentials_get_workstation(credentials);

	names_blob = NTLMv2_generate_names_blob(call, cli_credentials_get_workstation(credentials), 
						cli_credentials_get_domain(credentials));

	status = cli_credentials_get_ntlm_response(credentials, call, 
						   &flags, 
						   chal,
						   names_blob,
						   &lm_resp, &nt_resp,
						   NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}
	c = wb_cmd_pam_auth_crap_send(call, 0 /* logon parameters */, 
				      domain, user, workstation,
				      chal, nt_resp, lm_resp);
	return c;
}

NTSTATUS wb_cmd_pam_auth_recv(struct composite_context *c)
{
	struct pam_auth_crap_state *state =
		talloc_get_type(c->private_data, struct pam_auth_crap_state);
	NTSTATUS status = composite_wait(c);
	talloc_free(state);
	return status;
}

NTSTATUS wb_cmd_pam_auth(struct wbsrv_call *call,
			 const char *domain, const char *user,
			 const char *password)
{
	struct composite_context *c =
		wb_cmd_pam_auth_send(call, domain, user, 
				     password);
	return wb_cmd_pam_auth_recv(c);
}
