/*
   Unix SMB/CIFS implementation.
   async implementation of WINBINDD_PAM_AUTH
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
#include "libcli/security/dom_sid.h"
#include "lib/util/string_wrappers.h"
#include "lib/global_contexts.h"
#include "librpc/gen_ndr/ndr_winbind_c.h"

static NTSTATUS fake_password_policy(struct winbindd_response *r,
				     uint16_t validation_level,
				     union netr_Validation  *validation)
{
	const struct netr_SamBaseInfo *bi = NULL;
	NTTIME min_password_age;
	NTTIME max_password_age;

	switch (validation_level) {
	case 3:
		bi = &validation->sam3->base;
		break;
	case 6:
		bi = &validation->sam6->base;
		break;
	default:
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (bi->allow_password_change > bi->last_password_change) {
		min_password_age = bi->allow_password_change -
				   bi->last_password_change;
	} else {
		min_password_age = 0;
	}

	if (bi->force_password_change > bi->last_password_change) {
		max_password_age = bi->force_password_change -
				   bi->last_password_change;
	} else {
		max_password_age = 0;
	}

	r->data.auth.policy.min_length_password = 0;
	r->data.auth.policy.password_history = 0;
	r->data.auth.policy.password_properties = 0;
	r->data.auth.policy.expire =
		nt_time_to_unix_abs(&max_password_age);
	r->data.auth.policy.min_passwordage =
		nt_time_to_unix_abs(&min_password_age);

	return NT_STATUS_OK;
}

struct winbindd_pam_auth_state {
	struct wbint_PamAuth *r;
	fstring name_namespace;
	fstring name_domain;
	fstring name_user;
};

static void winbindd_pam_auth_done(struct tevent_req *subreq);

struct tevent_req *winbindd_pam_auth_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct winbindd_cli_state *cli,
					  struct winbindd_request *request)
{
	struct tevent_req *req, *subreq;
	struct winbindd_pam_auth_state *state;
	struct winbindd_domain *domain;
	char *mapped = NULL;
	NTSTATUS status;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct winbindd_pam_auth_state);
	if (req == NULL) {
		return NULL;
	}

	D_NOTICE("[%s (%u)] Winbind external command PAM_AUTH start.\n"
		 "Authenticating user '%s'.\n",
		 cli->client_name,
		 (unsigned int)cli->pid,
		 request->data.auth.user);

	if (!check_request_flags(request->flags)) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		return tevent_req_post(req, ev);
	}

	/* Parse domain and username */

	status = normalize_name_unmap(state, request->data.auth.user, &mapped);

	/* If the name normalization changed something, copy it over the given
	   name */

	if (NT_STATUS_IS_OK(status)
	    || NT_STATUS_EQUAL(status, NT_STATUS_FILE_RENAMED)) {
		fstrcpy(request->data.auth.user, mapped);
	}

	ok = canonicalize_username(request->data.auth.user,
				   state->name_namespace,
				   state->name_domain,
				   state->name_user);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_USER);
		return tevent_req_post(req, ev);
	}

	domain = find_auth_domain(request->flags, state->name_namespace);
	if (domain == NULL) {
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_USER);
		return tevent_req_post(req, ev);
	}

	state->r = talloc_zero(state, struct wbint_PamAuth);
	if (tevent_req_nomem(state->r, req)) {
		return tevent_req_post(req, ev);
	}

	state->r->in.client_name = talloc_strdup(
			state->r, request->client_name);
	if (tevent_req_nomem(state->r, req)) {
		return tevent_req_post(req, ev);
	}

	state->r->in.client_pid = request->pid;
	state->r->in.flags = request->flags;

	state->r->in.info = talloc_zero(state->r, struct wbint_AuthUserInfo);
	if (tevent_req_nomem(state->r, req)) {
		return tevent_req_post(req, ev);
	}

	state->r->in.info->krb5_cc_type = talloc_strdup(
			state->r, request->data.auth.krb5_cc_type);
	if (tevent_req_nomem(state->r, req)) {
		return tevent_req_post(req, ev);
	}

	state->r->in.info->password = talloc_strdup(
			state->r, request->data.auth.pass);
	if (tevent_req_nomem(state->r, req)) {
		return tevent_req_post(req, ev);
	}

	state->r->in.info->username = talloc_strdup(
			state->r, request->data.auth.user);
	if (tevent_req_nomem(state->r, req)) {
		return tevent_req_post(req, ev);
	}

	state->r->in.info->uid = request->data.auth.uid;

	status = extra_data_to_sid_array(
				request->data.auth.require_membership_of_sid,
				state->r,
				&state->r->in.require_membership_of_sid);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	subreq = dcerpc_wbint_PamAuth_r_send(state,
					     global_event_context(),
					     dom_child_handle(domain),
					     state->r);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, winbindd_pam_auth_done, req);
	return req;
}

static void winbindd_pam_auth_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winbindd_pam_auth_state *state = tevent_req_data(
		req, struct winbindd_pam_auth_state);
	NTSTATUS status;

	status = dcerpc_wbint_PamAuth_r_recv(subreq, state);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (tevent_req_nterror(req, state->r->out.result)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS winbindd_pam_auth_recv(struct tevent_req *req,
				struct winbindd_response *response)
{
	struct winbindd_pam_auth_state *state = tevent_req_data(
		req, struct winbindd_pam_auth_state);
	NTSTATUS status;

	D_NOTICE("Winbind external command PAM_AUTH end.\n");
	if (tevent_req_is_nterror(req, &status)) {
		set_auth_errors(response, status);
		return status;
	}

	response->result = WINBINDD_PENDING;

	status = append_auth_data(response,
				  response,
				  state->r->in.flags,
				  state->r->out.validation->level,
				  state->r->out.validation->validation,
				  state->name_domain,
				  state->name_user);
	fstrcpy(response->data.auth.krb5ccname,
		state->r->out.validation->krb5ccname);

	if (state->r->in.flags & WBFLAG_PAM_INFO3_TEXT) {
		bool ok;

		ok = add_trusted_domain_from_auth(
			state->r->out.validation->level,
			&response->data.auth.info3,
			&response->data.auth.info6);
		if (!ok) {
			DBG_ERR("add_trusted_domain_from_auth failed\n");
			set_auth_errors(response, NT_STATUS_LOGON_FAILURE);
			return NT_STATUS_LOGON_FAILURE;
		}
	}

	if (state->r->in.flags & WBFLAG_PAM_CACHED_LOGIN) {

		/* Store in-memory creds for single-signon using ntlm_auth. */

		status = winbindd_add_memory_creds(
			state->r->in.info->username,
			state->r->in.info->uid,
			state->r->in.info->password);
		D_DEBUG("winbindd_add_memory_creds returned: %s\n",
			   nt_errstr(status));
	}

	if (state->r->in.flags & WBFLAG_PAM_GET_PWD_POLICY) {
		/*
		 * WBFLAG_PAM_GET_PWD_POLICY is not used within
		 * any Samba caller anymore.
		 *
		 * We just fake this based on the effective values
		 * for the user, for legacy callers.
		 */
		status = fake_password_policy(response,
				state->r->out.validation->level,
				state->r->out.validation->validation);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("Failed to fake password policy: %s\n",
				nt_errstr(status));
			set_auth_errors(response, status);
			return status;
		}
	}

	return NT_STATUS_OK;
}
