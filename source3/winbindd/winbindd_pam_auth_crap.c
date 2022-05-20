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
#include "lib/util/string_wrappers.h"
#include "lib/global_contexts.h"
#include "librpc/gen_ndr/ndr_winbind_c.h"

struct winbindd_pam_auth_crap_state {
	uint8_t authoritative;
	uint32_t flags;
	bool pac_is_trusted;
	char *domain;
	char *user;
	struct wbint_PamAuthCrapValidation validation;
	NTSTATUS result;
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
	DATA_BLOB lm_resp = data_blob_null;
	DATA_BLOB nt_resp = data_blob_null;
	DATA_BLOB chal = data_blob_null;
	struct wbint_SidArray *require_membership_of_sid = NULL;
	NTSTATUS status;
	bool lmlength_ok = false;
	bool ntlength_ok = false;
	bool pwlength_ok = false;

	req = tevent_req_create(mem_ctx, &state,
				struct winbindd_pam_auth_crap_state);
	if (req == NULL) {
		return NULL;
	}
	state->authoritative = 1;
	state->flags = request->flags;

	if (state->flags & WBFLAG_PAM_AUTH_PAC) {
		state->result = winbindd_pam_auth_pac_verify(cli,
				state,
				&state->pac_is_trusted,
				&state->validation.level,
				&state->validation.validation);
		if (tevent_req_nterror(req, state->result)) {
			return tevent_req_post(req, ev);
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

	DBG_NOTICE("[%5lu]: pam auth crap domain: [%s] user: [%s] "
		   "workstation: [%s]\n",
		   (unsigned long)cli->pid,
		   request->data.auth_crap.domain,
		   request->data.auth_crap.user,
		   request->data.auth_crap.workstation);

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
		/*
		 * We don't know the domain so
		 * we're not authoritative
		 */
		state->authoritative = 0;
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_USER);
		return tevent_req_post(req, ev);
	}

	if (request->data.auth_crap.workstation[0] == '\0') {
		fstrcpy(request->data.auth_crap.workstation, lp_netbios_name());
	}

	lmlength_ok = (request->data.auth_crap.lm_resp_len <=
		       sizeof(request->data.auth_crap.lm_resp));

	ntlength_ok = (request->data.auth_crap.nt_resp_len <=
		       sizeof(request->data.auth_crap.nt_resp));

	ntlength_ok |=
		((request->flags & WBFLAG_BIG_NTLMV2_BLOB) &&
		 (request->extra_len == request->data.auth_crap.nt_resp_len));

	pwlength_ok = lmlength_ok && ntlength_ok;

	if (!pwlength_ok) {
		DBG_ERR("Invalid password length %u/%u\n",
			request->data.auth_crap.lm_resp_len,
			request->data.auth_crap.nt_resp_len);
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	state->domain = talloc_strdup(state, request->data.auth_crap.domain);
	if (tevent_req_nomem(state->domain, req)) {
		return tevent_req_post(req, ev);
	}

	state->user = talloc_strdup(state, request->data.auth_crap.user);
	if (tevent_req_nomem(state->user, req)) {
		return tevent_req_post(req, ev);
	}

	status = extra_data_to_sid_array(
			request->data.auth_crap.require_membership_of_sid,
			state,
			&require_membership_of_sid);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	lm_resp = data_blob_talloc(state,
				   request->data.auth_crap.lm_resp,
				   request->data.auth_crap.lm_resp_len);
	if (tevent_req_nomem(lm_resp.data, req)) {
		return tevent_req_post(req, ev);
	}

	if (request->flags & WBFLAG_BIG_NTLMV2_BLOB) {
		nt_resp = data_blob_talloc(state,
				request->extra_data.data,
				request->data.auth_crap.nt_resp_len);
	} else {
		nt_resp = data_blob_talloc(state,
				request->data.auth_crap.nt_resp,
				request->data.auth_crap.nt_resp_len);
	}
	if (tevent_req_nomem(nt_resp.data, req)) {
		return tevent_req_post(req, ev);
	}

	chal = data_blob_talloc(state,
				request->data.auth_crap.chal,
				8);
	if (tevent_req_nomem(chal.data, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = dcerpc_wbint_PamAuthCrap_send(state,
				global_event_context(),
				dom_child_handle(domain),
				request->client_name,
				request->pid,
				request->flags,
				request->data.auth_crap.user,
				request->data.auth_crap.domain,
				request->data.auth_crap.workstation,
				lm_resp,
				nt_resp,
				chal,
				request->data.auth_crap.logon_parameters,
				require_membership_of_sid,
				&state->authoritative,
				&state->validation);
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
	NTSTATUS status;

	status = dcerpc_wbint_PamAuthCrap_recv(subreq, state, &state->result);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
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
		goto out;
	}

	if (NT_STATUS_IS_ERR(state->result)) {
		status = state->result;
		goto out;
	}

	status = append_auth_data(response,
				  response,
				  state->flags,
				  state->validation.level,
				  state->validation.validation,
				  state->domain,
				  state->user);
	if (NT_STATUS_IS_ERR(status)) {
		goto out;
	}

	if (state->flags & WBFLAG_PAM_AUTH_PAC && !state->pac_is_trusted) {
		/*
		 * Clear the flag just in state to do no add the domain
		 * from auth below.
		 */
		state->flags &= ~WBFLAG_PAM_INFO3_TEXT;
	}

	if (state->flags & WBFLAG_PAM_INFO3_TEXT) {
		bool ok;

		ok = add_trusted_domain_from_auth(
			response->data.auth.validation_level,
			&response->data.auth.info3,
			&response->data.auth.info6);
		if (!ok) {
			status = NT_STATUS_LOGON_FAILURE;
			DBG_ERR("add_trusted_domain_from_auth failed\n");
			set_auth_errors(response, status);
			response->data.auth.authoritative =
				state->authoritative;
			return status;
		}
	}

	status = NT_STATUS_OK;

out:
	set_auth_errors(response, status);
	response->data.auth.authoritative = state->authoritative;
	response->result = WINBINDD_PENDING;
	return NT_STATUS(response->data.auth.nt_status);
}
