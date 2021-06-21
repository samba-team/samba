/*
   Unix SMB/CIFS implementation.
   async implementation of WINBINDD_PAM_CHNG_PSWD_AUTH_CRAP
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
#include "lib/global_contexts.h"
#include "librpc/gen_ndr/ndr_winbind_c.h"

struct winbindd_pam_chng_pswd_auth_crap_state {
	struct wbint_PamAuthCrapChangePassword r;
};

static void winbindd_pam_chng_pswd_auth_crap_done(struct tevent_req *subreq);

struct tevent_req *winbindd_pam_chng_pswd_auth_crap_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct winbindd_cli_state *cli,
	struct winbindd_request *request)
{
	struct tevent_req *req, *subreq;
	struct winbindd_pam_chng_pswd_auth_crap_state *state;
	struct winbindd_domain *domain;
	const char *domain_name;

	req = tevent_req_create(mem_ctx, &state,
				struct winbindd_pam_chng_pswd_auth_crap_state);
	if (req == NULL) {
		return NULL;
	}

	/* Ensure null termination */
	request->data.chng_pswd_auth_crap.user[
		sizeof(request->data.chng_pswd_auth_crap.user)-1]='\0';
	request->data.chng_pswd_auth_crap.domain[
		sizeof(request->data.chng_pswd_auth_crap.domain)-1]=0;

	DEBUG(3, ("[%5lu]: pam change pswd auth crap domain: %s user: %s\n",
		  (unsigned long)cli->pid,
		  request->data.chng_pswd_auth_crap.domain,
		  request->data.chng_pswd_auth_crap.user));

	domain_name = NULL;
	if (*request->data.chng_pswd_auth_crap.domain != '\0') {
		domain_name = request->data.chng_pswd_auth_crap.domain;
	} else if (lp_winbind_use_default_domain()) {
		domain_name = lp_workgroup();
	}

	domain = NULL;
	if (domain_name != NULL) {
		domain = find_domain_from_name(domain_name);
	}

	if (domain == NULL) {
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_USER);
		return tevent_req_post(req, ev);
	}

	state->r.in.client_pid = request->pid;
	state->r.in.client_name = talloc_strdup(state, request->client_name);
	if (tevent_req_nomem(state->r.in.client_name, req)) {
		return tevent_req_post(req, ev);
	}

	state->r.in.domain = talloc_strdup(state, domain_name);
	if (tevent_req_nomem(state->r.in.domain, req)) {
		return tevent_req_post(req, ev);
	}
	state->r.in.user = talloc_strdup(state,
		request->data.chng_pswd_auth_crap.user);
	if (tevent_req_nomem(state->r.in.user, req)) {
		return tevent_req_post(req, ev);
	}

	state->r.in.new_nt_pswd = data_blob_talloc(state,
		request->data.chng_pswd_auth_crap.new_nt_pswd,
		request->data.chng_pswd_auth_crap.new_nt_pswd_len);
	if (tevent_req_nomem(state->r.in.new_nt_pswd.data, req)) {
		return tevent_req_post(req, ev);
	}

	state->r.in.old_nt_hash_enc = data_blob_talloc(state,
		request->data.chng_pswd_auth_crap.old_nt_hash_enc,
		request->data.chng_pswd_auth_crap.old_nt_hash_enc_len);
	if (tevent_req_nomem(state->r.in.old_nt_hash_enc.data, req)) {
		return tevent_req_post(req, ev);
	}

	if (request->data.chng_pswd_auth_crap.new_lm_pswd_len > 0) {
		state->r.in.new_lm_pswd = data_blob_talloc(state,
			request->data.chng_pswd_auth_crap.new_lm_pswd,
			request->data.chng_pswd_auth_crap.new_lm_pswd_len);
		if (tevent_req_nomem(state->r.in.new_lm_pswd.data, req)) {
			return tevent_req_post(req, ev);
		}

		state->r.in.old_lm_hash_enc = data_blob_talloc(state,
			request->data.chng_pswd_auth_crap.old_lm_hash_enc,
			request->data.chng_pswd_auth_crap.old_lm_hash_enc_len);
		if (tevent_req_nomem(state->r.in.old_lm_hash_enc.data, req)) {
			return tevent_req_post(req, ev);
		}
	} else {
		state->r.in.new_lm_pswd = data_blob_null;
		state->r.in.old_lm_hash_enc = data_blob_null;
	}

	subreq = dcerpc_wbint_PamAuthCrapChangePassword_r_send(state,
						global_event_context(),
						dom_child_handle(domain),
						&state->r);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, winbindd_pam_chng_pswd_auth_crap_done,
				req);
	return req;
}

static void winbindd_pam_chng_pswd_auth_crap_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winbindd_pam_chng_pswd_auth_crap_state *state = tevent_req_data(
		req, struct winbindd_pam_chng_pswd_auth_crap_state);
	NTSTATUS status;

	status = dcerpc_wbint_PamAuthCrapChangePassword_r_recv(subreq, state);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS winbindd_pam_chng_pswd_auth_crap_recv(
	struct tevent_req *req,
	struct winbindd_response *response)
{
	struct winbindd_pam_chng_pswd_auth_crap_state *state = tevent_req_data(
		req, struct winbindd_pam_chng_pswd_auth_crap_state);
	NTSTATUS status = NT_STATUS_OK;

	if (tevent_req_is_nterror(req, &status)) {
		set_auth_errors(response, status);
		return status;
	}

	response->result = WINBINDD_PENDING;
	set_auth_errors(response, state->r.out.result);

	return NT_STATUS(response->data.auth.nt_status);
}
