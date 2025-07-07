/*
   Unix SMB/CIFS implementation.
   async implementation of WINBINDD_GETPWNAM
   Copyright (C) Volker Lendecke 2009

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
#include "passdb/lookup_sid.h" /* only for LOOKUP_NAME_NO_NSS flag */
#include "libcli/security/dom_sid.h"
#include "librpc/gen_ndr/ndr_winbind_c.h"

struct winbindd_getpwnam_state {
	struct tevent_context *ev;
	const char *request_name;
	const char *unmapped_name;
	char *namespace;
	char *domname;
	char *username;
	struct dom_sid sid;
	enum lsa_SidType type;
	struct winbindd_pw pw;
};

static void winbindd_getpwnam_lookupname_done(struct tevent_req *subreq);
static void winbindd_getpwnam_done(struct tevent_req *subreq);

static void winbindd_getpwnam_initialized(struct tevent_req *subreq);
struct tevent_req *winbindd_getpwnam_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct winbindd_cli_state *cli,
					  struct winbindd_request *request)
{
	struct tevent_req *req, *subreq;
	struct winbindd_getpwnam_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct winbindd_getpwnam_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;

	/* Ensure null termination */
	request->data.username[sizeof(request->data.username)-1]='\0';

	D_NOTICE("[%s (%u)] Winbind external command GETPWNAM start.\n"
		 "Query username '%s'.\n",
		 cli->client_name,
		 (unsigned int)cli->pid,
		 request->data.username);

	state->request_name = talloc_strdup(state, request->data.username);
	if (tevent_req_nomem(state->request_name, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = wb_parent_idmap_setup_send(state, ev);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, winbindd_getpwnam_initialized, req);
	return req;
}

static void winbindd_getpwnam_unmap_done(struct tevent_req *subreq);
static void winbindd_getpwnam_initialized(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct winbindd_getpwnam_state *state = tevent_req_data(
		req, struct winbindd_getpwnam_state);
	const struct wb_parent_idmap_config *cfg = NULL;
	NTSTATUS status;

	status = wb_parent_idmap_setup_recv(subreq, &cfg);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = dcerpc_wbint_NormalizeNameUnmap_send(state,
						      state->ev,
						      idmap_child_handle(),
						      state->request_name,
						      &state->unmapped_name);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, winbindd_getpwnam_unmap_done, req);
}

static void winbindd_getpwnam_unmap_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct winbindd_getpwnam_state *state = tevent_req_data(
		req, struct winbindd_getpwnam_state);
	NTSTATUS status;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	bool ok;

	status = dcerpc_wbint_NormalizeNameUnmap_recv(subreq, state, &result);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (NT_STATUS_IS_OK(result) ||
	    NT_STATUS_EQUAL(result, NT_STATUS_FILE_RENAMED))
	{
		/* dcerpc_wbint_NormalizeNameUnmap did something */
		state->request_name = state->unmapped_name;
	}

	ok = parse_domain_user(state,
			       state->request_name,
			       &state->namespace,
			       &state->domname,
			       &state->username);
	if (!ok) {
		D_WARNING("Could not parse domain user: %s\n",
			  state->request_name);
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	subreq = wb_lookupname_send(state,
				    state->ev,
				    state->namespace,
				    state->domname,
				    state->username,
				    LOOKUP_NAME_NO_NSS);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, winbindd_getpwnam_lookupname_done, req);
}

static void winbindd_getpwnam_lookupname_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winbindd_getpwnam_state *state = tevent_req_data(
		req, struct winbindd_getpwnam_state);
	NTSTATUS status;

	status = wb_lookupname_recv(subreq, &state->sid, &state->type);
	TALLOC_FREE(subreq);
	if (NT_STATUS_IS_OK(status) && state->type == SID_NAME_UNKNOWN) {
		status = NT_STATUS_NONE_MAPPED;
	}
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = wb_getpwsid_send(state, state->ev, &state->sid, &state->pw);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, winbindd_getpwnam_done, req);
}

static void winbindd_getpwnam_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = wb_getpwsid_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS winbindd_getpwnam_recv(struct tevent_req *req,
				struct winbindd_response *response)
{
	struct winbindd_getpwnam_state *state = tevent_req_data(
		req, struct winbindd_getpwnam_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		struct dom_sid_buf buf;
		D_WARNING("Could not convert sid %s: %s\n",
			  dom_sid_str_buf(&state->sid, &buf),
			  nt_errstr(status));
		return status;
	}
	response->data.pw = state->pw;

	D_NOTICE("Winbind external command GETPWNAM end.\n"
		 "(name:passwd:uid:gid:gecos:dir:shell)\n"
		 "%s:%s:%u:%u:%s:%s:%s\n",
		 state->pw.pw_name,
		 state->pw.pw_passwd,
		 (unsigned int)state->pw.pw_uid,
		 (unsigned int)state->pw.pw_gid,
		 state->pw.pw_gecos,
		 state->pw.pw_dir,
		 state->pw.pw_shell
		 );

	return NT_STATUS_OK;
}
