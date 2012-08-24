/*
   Unix SMB/CIFS implementation.

   Do a netr_DsrUpdateReadOnlyServerDnsRecords to a remote DC

   Copyright (C) Andrew Bartlett 2010
   Copyright (C) Andrew Tridgell 2010

   based heavily on wb_sam_logon.c which is copyright:

   Copyright (C) Volker Lendecke 2005
   Copyright (C) Andrew Bartlett 2005
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

struct wb_update_rodc_dns_state {
	struct tevent_context *ev;

	struct winbind_DsrUpdateReadOnlyServerDnsRecords *req;

	struct wbsrv_domain *domain;
	struct tevent_queue_entry *queue_entry;
        struct netlogon_creds_CredentialState *creds_state;
        struct netr_Authenticator auth1, auth2;

	TALLOC_CTX *r_mem_ctx;
        struct netr_DsrUpdateReadOnlyServerDnsRecords r;
};

static void wb_update_rodc_dns_recv_domain(struct composite_context *csubreq);
static void wb_sam_logon_queue_trigger(struct tevent_req *req, void *priv);
static void wb_update_rodc_dns_recv_response(struct tevent_req *subreq);

/*
    Find the connection to the DC (or find an existing connection)
*/
struct tevent_req *wb_update_rodc_dns_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct wbsrv_service *service,
					   struct winbind_DsrUpdateReadOnlyServerDnsRecords *_req)
{
	struct tevent_req *req;
	struct wb_update_rodc_dns_state *state;
	struct composite_context *csubreq;

	req = tevent_req_create(mem_ctx, &state,
				struct wb_update_rodc_dns_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->req = _req;

	csubreq = wb_sid2domain_send(state, service, service->primary_sid);
	if (tevent_req_nomem(csubreq, req)) {
		return tevent_req_post(req, ev);
	}
	csubreq->async.fn = wb_update_rodc_dns_recv_domain;
	csubreq->async.private_data = req;

	return req;
}

/*
    Having finished making the connection to the DC
    Send of a DsrUpdateReadOnlyServerDnsRecords request to authenticate a user.
*/
static void wb_update_rodc_dns_recv_domain(struct composite_context *csubreq)
{
	struct tevent_req *req =
		talloc_get_type_abort(csubreq->async.private_data,
		struct tevent_req);
	struct wb_update_rodc_dns_state *state =
		tevent_req_data(req,
		struct wb_update_rodc_dns_state);
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
	struct wb_update_rodc_dns_state *state =
		tevent_req_data(req,
		struct wb_update_rodc_dns_state);
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
	state->r.out.return_authenticator = &state->auth2;
	state->r.in.site_name = state->req->in.site_name;
	state->r.in.dns_ttl = state->req->in.dns_ttl;
	state->r.in.dns_names = state->req->in.dns_names;
	state->r.out.dns_names = state->req->in.dns_names;

	/*
	 * use a new talloc context for the DsrUpdateReadOnlyServerDnsRecords call
	 * because then we can just to a talloc_steal on this context
	 * in the final _recv() function to give the caller all the content of
	 * the s->r.out.dns_names
	 */
	state->r_mem_ctx = talloc_new(state);
	if (tevent_req_nomem(state->r_mem_ctx, req)) {
		return;
	}

	subreq = dcerpc_netr_DsrUpdateReadOnlyServerDnsRecords_r_send(state,
						state->ev,
						domain->netlogon_pipe->binding_handle,
						&state->r);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_update_rodc_dns_recv_response, req);
}

/*
   NTLM Authentication

   Check the DsrUpdateReadOnlyServerDnsRecords reply and decrypt the session keys
*/
static void wb_update_rodc_dns_recv_response(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct wb_update_rodc_dns_state *state =
		tevent_req_data(req,
		struct wb_update_rodc_dns_state);
	NTSTATUS status;
	bool ok;

	status = dcerpc_netr_DsrUpdateReadOnlyServerDnsRecords_r_recv(subreq,
								state->r_mem_ctx);
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

	/*
	 * we do not need the netlogon_creds lock anymore
	 */
	TALLOC_FREE(state->queue_entry);

	tevent_req_done(req);
}

NTSTATUS wb_update_rodc_dns_recv(struct tevent_req *req,
			TALLOC_CTX *mem_ctx,
			struct winbind_DsrUpdateReadOnlyServerDnsRecords *_req)
{
	struct wb_update_rodc_dns_state *state =
		tevent_req_data(req,
		struct wb_update_rodc_dns_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	talloc_steal(mem_ctx, state->r_mem_ctx);
	_req->out.dns_names = state->r.out.dns_names;

	tevent_req_received(req);
	return NT_STATUS_OK;
}
