/*
   Unix SMB/CIFS implementation.
   async implementation of WINBINDD_PAM_LOGOFF
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
#include "util/debug.h"
#include "winbindd.h"
#include "lib/global_contexts.h"
#include "librpc/gen_ndr/ndr_winbind_c.h"

struct winbindd_pam_logoff_state {
	struct wbint_PamLogOff r;
};

static void winbindd_pam_logoff_done(struct tevent_req *subreq);

struct tevent_req *winbindd_pam_logoff_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct winbindd_cli_state *cli,
					    struct winbindd_request *request)
{
	struct tevent_req *req, *subreq;
	struct winbindd_pam_logoff_state *state;
	struct winbindd_domain *domain;
	fstring name_namespace, name_domain, user;
	uid_t caller_uid;
	gid_t caller_gid;
	int res;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct winbindd_pam_logoff_state);
	if (req == NULL) {
		return NULL;
	}
	D_NOTICE("[%s (%u)] Winbind external command PAM_LOGOFF start.\n"
		 "Username '%s' is used during logoff.\n",
		 cli->client_name,
		 (unsigned int)cli->pid,
		 request->data.auth.user);
	/* Ensure null termination */
	/* Ensure null termination */
	request->data.logoff.user[sizeof(request->data.logoff.user)-1]='\0';
	request->data.logoff.krb5ccname[
		sizeof(request->data.logoff.krb5ccname)-1]='\0';

	if (request->data.logoff.uid == (uid_t)-1) {
		goto failed;
	}

	ok = canonicalize_username(request->data.logoff.user,
				   name_namespace,
				   name_domain,
				   user);
	if (!ok) {
		goto failed;
	}

	domain = find_auth_domain(request->flags, name_namespace);
	if (domain == NULL) {
		goto failed;
	}

	caller_uid = (uid_t)-1;

	res = getpeereid(cli->sock, &caller_uid, &caller_gid);
	if (res != 0) {
		D_WARNING("winbindd_pam_logoff: failed to check peerid: %s\n",
			strerror(errno));
		goto failed;
	}

	switch (caller_uid) {
	case -1:
		goto failed;
	case 0:
		/* root must be able to logoff any user - gd */
		break;
	default:
		if (caller_uid != request->data.logoff.uid) {
			D_WARNING("caller requested invalid uid\n");
			goto failed;
		}
		break;
	}

	state->r.in.client_name = talloc_strdup(state, request->client_name);
	if (tevent_req_nomem(state->r.in.client_name, req)) {
		return tevent_req_post(req, ev);
	}
	state->r.in.client_pid = request->pid;

	state->r.in.flags = request->flags;
	state->r.in.user = talloc_strdup(state, request->data.logoff.user);
	if (tevent_req_nomem(state->r.in.user, req)) {
		return tevent_req_post(req, ev);
	}
	state->r.in.uid = request->data.logoff.uid;
	state->r.in.krb5ccname = talloc_strdup(state,
					request->data.logoff.krb5ccname);
	if (tevent_req_nomem(state->r.in.krb5ccname, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = dcerpc_wbint_PamLogOff_r_send(state,
					       global_event_context(),
					       dom_child_handle(domain),
					       &state->r);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, winbindd_pam_logoff_done, req);
	return req;

failed:
	tevent_req_nterror(req, NT_STATUS_NO_SUCH_USER);
	return tevent_req_post(req, ev);
}

static void winbindd_pam_logoff_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winbindd_pam_logoff_state *state = tevent_req_data(
		req, struct winbindd_pam_logoff_state);
	NTSTATUS status;

	status = dcerpc_wbint_PamLogOff_r_recv(subreq, state);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS winbindd_pam_logoff_recv(struct tevent_req *req,
				  struct winbindd_response *response)
{
	struct winbindd_pam_logoff_state *state = tevent_req_data(
		req, struct winbindd_pam_logoff_state);
	NTSTATUS status = NT_STATUS_OK;

	D_NOTICE("Winbind external command PAM_LOGOFF end.\n");
	if (tevent_req_is_nterror(req, &status)) {
		set_auth_errors(response, status);
		return status;
	}

	response->result = WINBINDD_PENDING;
	set_auth_errors(response, state->r.out.result);

	if (NT_STATUS_IS_OK(state->r.out.result)) {
		winbindd_delete_memory_creds(state->r.in.user);
	}

	return NT_STATUS(response->data.auth.nt_status);
}
