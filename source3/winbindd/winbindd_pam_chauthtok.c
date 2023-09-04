/*
   Unix SMB/CIFS implementation.
   async implementation of WINBINDD_PAM_CHAUTHTOK
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
#include "lib/util/string_wrappers.h"
#include "lib/global_contexts.h"
#include "librpc/gen_ndr/ndr_winbind_c.h"

static void fill_in_password_policy(struct winbindd_response *r,
				    const struct samr_DomInfo1 *p)
{
	r->data.auth.policy.min_length_password =
		p->min_password_length;
	r->data.auth.policy.password_history =
		p->password_history_length;
	r->data.auth.policy.password_properties =
		p->password_properties;
	r->data.auth.policy.expire	=
		nt_time_to_unix_abs((const NTTIME *)&(p->max_password_age));
	r->data.auth.policy.min_passwordage =
		nt_time_to_unix_abs((const NTTIME *)&(p->min_password_age));
}

struct winbindd_pam_chauthtok_state {
	struct wbint_PamAuthChangePassword r;
};

static void winbindd_pam_chauthtok_done(struct tevent_req *subreq);

struct tevent_req *winbindd_pam_chauthtok_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct winbindd_cli_state *cli,
	struct winbindd_request *request)
{
	struct tevent_req *req, *subreq;
	struct winbindd_pam_chauthtok_state *state;
	struct winbindd_domain *contact_domain;
	fstring namespace, domain, user;
	char *mapped_user;
	NTSTATUS status;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct winbindd_pam_chauthtok_state);
	if (req == NULL) {
		return NULL;
	}

	/* Ensure null termination */
	request->data.chauthtok.user[
		sizeof(request->data.chauthtok.user)-1]='\0';

	DEBUG(3, ("[%5lu]: pam chauthtok %s\n", (unsigned long)cli->pid,
		  request->data.chauthtok.user));

	status = normalize_name_unmap(state, request->data.chauthtok.user,
				      &mapped_user);

	if (NT_STATUS_IS_OK(status) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_FILE_RENAMED)) {
		fstrcpy(request->data.chauthtok.user, mapped_user);
	}

	ok = canonicalize_username(request->data.chauthtok.user,
				   namespace,
				   domain,
				   user);
	if (!ok) {
		DEBUG(10, ("winbindd_pam_chauthtok: canonicalize_username %s "
			   "failed with\n", request->data.chauthtok.user));
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_USER);
		return tevent_req_post(req, ev);
	}

	contact_domain = find_domain_from_name(namespace);
	if (contact_domain == NULL) {
		DEBUG(3, ("Cannot change password for [%s] -> [%s]\\[%s] "
			  "as %s is not a trusted domain\n",
			  request->data.chauthtok.user, domain, user, domain));
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_USER);
		return tevent_req_post(req, ev);
	}

	state->r.in.client_pid = request->pid;
	state->r.in.flags = request->flags;

	state->r.in.client_name = talloc_strdup(state, request->client_name);
	if (tevent_req_nomem(state->r.in.client_name, req)) {
		return tevent_req_post(req, ev);
	}

	state->r.in.user = talloc_strdup(state, request->data.chauthtok.user);
	if (tevent_req_nomem(state->r.in.user, req)) {
		return tevent_req_post(req, ev);
	}

	state->r.in.old_password = talloc_strdup(state,
			request->data.chauthtok.oldpass);
	if (tevent_req_nomem(state->r.in.old_password, req)) {
		return tevent_req_post(req, ev);
	}

	state->r.in.new_password = talloc_strdup(state,
			request->data.chauthtok.newpass);
	if (tevent_req_nomem(state->r.in.new_password, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = dcerpc_wbint_PamAuthChangePassword_r_send(state,
					global_event_context(),
					dom_child_handle(contact_domain),
					&state->r);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, winbindd_pam_chauthtok_done, req);
	return req;
}

static void winbindd_pam_chauthtok_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winbindd_pam_chauthtok_state *state = tevent_req_data(
		req, struct winbindd_pam_chauthtok_state);
	NTSTATUS status;

	status = dcerpc_wbint_PamAuthChangePassword_r_recv(subreq, state);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS winbindd_pam_chauthtok_recv(struct tevent_req *req,
				     struct winbindd_response *response)
{
	struct winbindd_pam_chauthtok_state *state = tevent_req_data(
		req, struct winbindd_pam_chauthtok_state);
	NTSTATUS status = NT_STATUS_OK;

	if (tevent_req_is_nterror(req, &status)) {
		set_auth_errors(response, status);
		return status;
	}

	response->result = WINBINDD_PENDING;

	set_auth_errors(response, state->r.out.result);
	if (*state->r.out.dominfo != NULL) {
		fill_in_password_policy(response, *state->r.out.dominfo);
	}
	response->data.auth.reject_reason = *state->r.out.reject_reason;

	if (state->r.in.flags & WBFLAG_PAM_CACHED_LOGIN) {

		/* Update the single sign-on memory creds. */
		status = winbindd_replace_memory_creds(
			state->r.in.user, state->r.in.new_password);

		DEBUG(10, ("winbindd_replace_memory_creds returned %s\n",
			   nt_errstr(status)));

		/*
		 * When we login from gdm or xdm and password expires,
		 * we change password, but there are no memory
		 * credentials. So, winbindd_replace_memory_creds()
		 * returns NT_STATUS_OBJECT_NAME_NOT_FOUND. This is
		 * not a failure.  --- BoYang
		 */
		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			status = NT_STATUS_OK;
		}
	}

	return NT_STATUS(response->data.auth.nt_status);
}
