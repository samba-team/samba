/* 
   Unix SMB/CIFS implementation.

   Do a netr_LogonSamLogon to a remote DC

   Copyright (C) Volker Lendecke 2005
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   Copyright (C) Stefan Metzmacher 2006
   
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
#include <tevent.h>
#include "../lib/util/tevent_ntstatus.h"
#include "libcli/composite/composite.h"
#include "winbind/wb_server.h"
#include "smbd/service_task.h"
#include "auth/credentials/credentials.h"
#include "libcli/auth/libcli_auth.h"
#include "librpc/gen_ndr/ndr_netlogon_c.h"
#include "librpc/gen_ndr/winbind.h"

struct wb_sam_logon_state {
	struct tevent_context *ev;

	struct winbind_SamLogon *req;

	struct wbsrv_domain *domain;
	struct tevent_queue_entry *queue_entry;
        struct netlogon_creds_CredentialState *creds_state;
        struct netr_Authenticator auth1, auth2;

	TALLOC_CTX *r_mem_ctx;
        struct netr_LogonSamLogon r;
};

static void wb_sam_logon_recv_domain(struct composite_context *ctx);
static void wb_sam_logon_queue_trigger(struct tevent_req *req, void *priv);
static void wb_sam_logon_recv_samlogon(struct tevent_req *subreq);

/*
    Find the connection to the DC (or find an existing connection)
*/
struct tevent_req *wb_sam_logon_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct wbsrv_service *service,
				     struct winbind_SamLogon *_req)
{
	struct tevent_req *req;
	struct wb_sam_logon_state *state;
	struct composite_context *csubreq;

	req = tevent_req_create(mem_ctx, &state,
				struct wb_sam_logon_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->req = _req;

	csubreq = wb_sid2domain_send(state, service, service->primary_sid);
	if (tevent_req_nomem(csubreq, req)) {
		return tevent_req_post(req, ev);
	}
	csubreq->async.fn = wb_sam_logon_recv_domain;
	csubreq->async.private_data = req;

	return req;
}

/*
    Having finished making the connection to the DC
    Send of a SamLogon request to authenticate a user.
*/
static void wb_sam_logon_recv_domain(struct composite_context *csubreq)
{
	struct tevent_req *req =
		talloc_get_type_abort(csubreq->async.private_data,
		struct tevent_req);
	struct wb_sam_logon_state *state =
		tevent_req_data(req,
		struct wb_sam_logon_state);
	NTSTATUS status;
	struct tevent_queue_entry *e;

	status = wb_sid2domain_recv(csubreq, &state->domain);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	/*
	 * Because of the netlogon_creds behavior we have to
	 * queue the netr_LogonSamLogon() calls
	 */
	e = tevent_queue_add_entry(state->domain->netlogon_queue,
				   state->ev,
				   req,
				   wb_sam_logon_queue_trigger,
				   NULL);
	state->queue_entry = e;
}

static void wb_sam_logon_queue_trigger(struct tevent_req *req, void *priv)
{
	struct wb_sam_logon_state *state =
		tevent_req_data(req,
		struct wb_sam_logon_state);
	struct wbsrv_domain *domain = state->domain;
	struct tevent_req *subreq;

	state->creds_state = cli_credentials_get_netlogon_creds(domain->libnet_ctx->cred);
	netlogon_creds_client_authenticator(state->creds_state, &state->auth1);

	state->r.in.server_name = talloc_asprintf(state, "\\\\%s",
			      dcerpc_server_name(domain->netlogon_pipe));
	if (tevent_req_nomem(state->r.in.server_name, req)) {
		return;
	}

	state->r.in.computer_name = cli_credentials_get_workstation(domain->libnet_ctx->cred);
	state->r.in.credential = &state->auth1;
	state->r.in.return_authenticator = &state->auth2;
	state->r.in.logon_level = state->req->in.logon_level;
	state->r.in.logon = &state->req->in.logon;
	state->r.in.validation_level = state->req->in.validation_level;
	state->r.out.return_authenticator = NULL;
	state->r.out.validation = talloc(state, union netr_Validation);
	if (tevent_req_nomem(state->r.out.validation, req)) {
		return;
	}
	state->r.out.authoritative = talloc(state, uint8_t);
	if (tevent_req_nomem(state->r.out.authoritative, req)) {
		return;
	}

	/*
	 * use a new talloc context for the LogonSamLogon call
	 * because then we can just to a talloc_steal on this context
	 * in the final _recv() function to give the caller all the content of
	 * the state->r.out.validation
	 */
	state->r_mem_ctx = talloc_new(state);
	if (tevent_req_nomem(state->r_mem_ctx, req)) {
		return;
	}

	subreq = dcerpc_netr_LogonSamLogon_r_send(state,
						  state->ev,
						  domain->netlogon_pipe->binding_handle,
						  &state->r);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_sam_logon_recv_samlogon, req);
}

/* 
   NTLM Authentication 
   
   Check the SamLogon reply and decrypt the session keys
*/
static void wb_sam_logon_recv_samlogon(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct wb_sam_logon_state *state =
		tevent_req_data(req,
		struct wb_sam_logon_state);
	NTSTATUS status;
	bool ok;

	status = dcerpc_netr_LogonSamLogon_r_recv(subreq, state->r_mem_ctx);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (tevent_req_nterror(req, state->r.out.result)) {
		return;
	}

	if (state->r.out.return_authenticator == NULL) {
		tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
		return;
	}

	ok = netlogon_creds_client_check(state->creds_state,
				&state->r.out.return_authenticator->cred);
	if (!ok) {
		DEBUG(0, ("Credentials check failed!\n"));
		tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
		return;
	}

	/* Decrypt the session keys before we reform the info3, so the
	 * person on the other end of winbindd pipe doesn't have to.
	 * They won't have the encryption key anyway */
	netlogon_creds_decrypt_samlogon(state->creds_state,
					state->r.in.validation_level,
					state->r.out.validation);

	/*
	 * we do not need the netlogon_creds lock anymore
	 */
	TALLOC_FREE(state->queue_entry);

	tevent_req_done(req);
}

NTSTATUS wb_sam_logon_recv(struct tevent_req *req,
			   TALLOC_CTX *mem_ctx,
			   struct winbind_SamLogon *_req)
{
	struct wb_sam_logon_state *state =
		tevent_req_data(req,
		struct wb_sam_logon_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	talloc_steal(mem_ctx, state->r_mem_ctx);
	_req->out.validation = *state->r.out.validation;
	_req->out.authoritative = 1;

	tevent_req_received(req);
	return NT_STATUS_OK;
}
