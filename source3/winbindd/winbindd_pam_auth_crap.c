/*
   Unix SMB/CIFS implementation.
   async implementation of WINBINDD_PAM_AUTH_CRAP
   Copyright (C) Volker Lendecke 2010

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
#include "winbindd.h"
#include "rpc_client/util_netlogon.h"
#include "libcli/security/dom_sid.h"

struct winbindd_pam_auth_crap_state {
	struct winbindd_response *response;
	uint32_t flags;
};

static void winbindd_pam_auth_crap_done(struct tevent_req *subreq);

struct tevent_req *winbindd_pam_auth_crap_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct winbindd_cli_state *cli,
	struct winbindd_request *request)
{
	struct tevent_req *req, *subreq;
	struct winbindd_pam_auth_crap_state *state;
	struct winbindd_domain *domain;
	const char *auth_domain = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct winbindd_pam_auth_crap_state);
	if (req == NULL) {
		return NULL;
	}

	state->flags = request->flags;

	if (state->flags & WBFLAG_PAM_AUTH_PAC) {
		bool is_trusted = false;
		uint16_t validation_level;
		union netr_Validation *validation = NULL;
		NTSTATUS status;

		status = winbindd_pam_auth_pac_verify(cli,
						      &is_trusted,
						      &validation_level,
						      &validation);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}

		state->response = talloc_zero(state,
					      struct winbindd_response);
		if (tevent_req_nomem(state->response, req)) {
			return tevent_req_post(req, ev);
		}
		state->response->result = WINBINDD_PENDING;
		state->response->length = sizeof(struct winbindd_response);

		status = append_auth_data(state->response,
					  state->response,
					  state->flags,
					  validation_level,
					  validation,
					  NULL, NULL);
		TALLOC_FREE(validation);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}

		if (is_trusted && (state->flags & WBFLAG_PAM_INFO3_TEXT)) {
			bool ok;

			ok = add_trusted_domain_from_auth(
				state->response->data.auth.validation_level,
				&state->response->data.auth.info3,
				&state->response->data.auth.info6);
			if (!ok) {
				DBG_ERR("add_trusted_domain_from_auth failed\n");
				tevent_req_nterror(req, NT_STATUS_LOGON_FAILURE);
				return tevent_req_post(req, ev);
			}
		}

		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	/* Ensure null termination */
	request->data.auth_crap.user[
		sizeof(request->data.auth_crap.user)-1] = '\0';
	request->data.auth_crap.domain[
		sizeof(request->data.auth_crap.domain)-1] = '\0';
	request->data.auth_crap.workstation[
		sizeof(request->data.auth_crap.workstation)-1] = '\0';

	DEBUG(3, ("[%5lu]: pam auth crap domain: [%s] user: %s\n",
		  (unsigned long)cli->pid,
		  request->data.auth_crap.domain,
		  request->data.auth_crap.user));

	if (!check_request_flags(request->flags)) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		return tevent_req_post(req, ev);
	}

	auth_domain = request->data.auth_crap.domain;
	if (auth_domain[0] == '\0') {
		auth_domain = lp_workgroup();
	}

	domain = find_auth_domain(request->flags, auth_domain);
	if (domain == NULL) {
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_USER);
		return tevent_req_post(req, ev);
	}

	if (request->data.auth_crap.workstation[0] == '\0') {
		fstrcpy(request->data.auth_crap.workstation, lp_netbios_name());
	}

	subreq = wb_domain_request_send(state, global_event_context(), domain,
					request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, winbindd_pam_auth_crap_done, req);
	return req;
}

static void winbindd_pam_auth_crap_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winbindd_pam_auth_crap_state *state = tevent_req_data(
		req, struct winbindd_pam_auth_crap_state);
	int res, err;

	res = wb_domain_request_recv(subreq, state, &state->response, &err);
	TALLOC_FREE(subreq);
	if (res == -1) {
		tevent_req_nterror(req, map_nt_error_from_unix(err));
		return;
	}

	if (NT_STATUS_IS_OK(NT_STATUS(state->response->data.auth.nt_status)) &&
	    (state->flags & WBFLAG_PAM_INFO3_TEXT))
	{
		bool ok;

		ok = add_trusted_domain_from_auth(
			state->response->data.auth.validation_level,
			&state->response->data.auth.info3,
			&state->response->data.auth.info6);
		if (!ok) {
			DBG_ERR("add_trusted_domain_from_auth failed\n");
			tevent_req_nterror(req, NT_STATUS_LOGON_FAILURE);
			return;
		}
	}

	tevent_req_done(req);
}

NTSTATUS winbindd_pam_auth_crap_recv(struct tevent_req *req,
				     struct winbindd_response *response)
{
	struct winbindd_pam_auth_crap_state *state = tevent_req_data(
		req, struct winbindd_pam_auth_crap_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		set_auth_errors(response, status);
		return status;
	}

	*response = *state->response;
	response->result = WINBINDD_PENDING;
	state->response = talloc_move(response, &state->response);
	return NT_STATUS(response->data.auth.nt_status);
}
