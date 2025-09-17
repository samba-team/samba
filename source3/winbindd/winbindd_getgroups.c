/*
   Unix SMB/CIFS implementation.
   async implementation of WINBINDD_GETGROUPS
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

struct winbindd_getgroups_state {
	struct tevent_context *ev;
	const char *request_name;
	const char *unmapped_name;
	char *namespace;
	char *domname;
	char *username;
	struct dom_sid sid;
	enum lsa_SidType type;
	uint32_t num_sids;
	struct dom_sid *sids;
	uint32_t num_gids;
	gid_t *gids;
};

static void winbindd_getgroups_idmap_initialized(struct tevent_req *subreq);
static void winbindd_getgroups_lookupname_done(struct tevent_req *subreq);
static void winbindd_getgroups_gettoken_done(struct tevent_req *subreq);
static void winbindd_getgroups_sid2gid_done(struct tevent_req *subreq);
static void winbindd_getgroups_unmap_done(struct tevent_req *subreq);

struct tevent_req *winbindd_getgroups_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct winbindd_cli_state *cli,
					   struct winbindd_request *request)
{
	struct tevent_req *req, *subreq;
	struct winbindd_getgroups_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct winbindd_getgroups_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;

	/* Ensure null termination */
	request->data.username[sizeof(request->data.username)-1]='\0';

	D_NOTICE("[%s (%u)] Winbind external command GETGROUPS start.\n"
		 "Searching groups for username '%s'.\n",
		 cli->client_name,
		 (unsigned int)cli->pid,
		 request->data.username);

	state->request_name = talloc_strdup(state, request->data.username);
	if (tevent_req_nomem(state->request_name, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = wb_parent_idmap_setup_send(state, state->ev);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq,
				winbindd_getgroups_idmap_initialized,
				req);
	return req;
}

static void winbindd_getgroups_idmap_initialized(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct winbindd_getgroups_state *state = tevent_req_data(
		req, struct winbindd_getgroups_state);
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
	tevent_req_set_callback(subreq, winbindd_getgroups_unmap_done, req);
}

static void winbindd_getgroups_unmap_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct winbindd_getgroups_state *state = tevent_req_data(
		req, struct winbindd_getgroups_state);
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
		D_WARNING("Could not parse domain user: %s\n", state->request_name);
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
	tevent_req_set_callback(subreq, winbindd_getgroups_lookupname_done,
				req);
}

static void winbindd_getgroups_lookupname_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winbindd_getgroups_state *state = tevent_req_data(
		req, struct winbindd_getgroups_state);
	NTSTATUS status;

	status = wb_lookupname_recv(subreq, &state->sid, &state->type);
	TALLOC_FREE(subreq);
	if (NT_STATUS_IS_OK(status) && state->type == SID_NAME_UNKNOWN) {
		status = NT_STATUS_NONE_MAPPED;
	}
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = wb_gettoken_send(state, state->ev, &state->sid, true);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, winbindd_getgroups_gettoken_done, req);
}

static void winbindd_getgroups_gettoken_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winbindd_getgroups_state *state = tevent_req_data(
		req, struct winbindd_getgroups_state);
	NTSTATUS status;

	status = wb_gettoken_recv(subreq, state, &state->num_sids,
				  &state->sids);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	/*
	 * Convert the group SIDs to gids. state->sids[0] contains the user
	 * sid. If the idmap backend uses ID_TYPE_BOTH, we might need the
	 * the id of the user sid in the list of group sids, so map the
	 * complete token.
	 */

	subreq = wb_sids2xids_send(state, state->ev,
				   state->sids, state->num_sids);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, winbindd_getgroups_sid2gid_done, req);
}

static void winbindd_getgroups_sid2gid_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winbindd_getgroups_state *state = tevent_req_data(
		req, struct winbindd_getgroups_state);
	NTSTATUS status;
	struct unixid *xids;
	uint32_t i;

	xids = talloc_array(state, struct unixid, state->num_sids);
	if (tevent_req_nomem(xids, req)) {
		return;
	}
	for (i=0; i < state->num_sids; i++) {
		xids[i].type = ID_TYPE_NOT_SPECIFIED;
		xids[i].id = UINT32_MAX;
	}

	status = wb_sids2xids_recv(subreq, xids, state->num_sids);
	TALLOC_FREE(subreq);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED) ||
	    NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED))
	{
		status = NT_STATUS_OK;
	}
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->gids = talloc_array(state, gid_t, state->num_sids);
	if (tevent_req_nomem(state->gids, req)) {
		return;
	}
	state->num_gids = 0;

	for (i=0; i < state->num_sids; i++) {
		bool include_gid = false;
		const char *debug_missing = NULL;

		switch (xids[i].type) {
		case ID_TYPE_NOT_SPECIFIED:
			debug_missing = "not specified";
			break;
		case ID_TYPE_UID:
			if (i != 0) {
				debug_missing = "uid";
			}
			break;
		case ID_TYPE_GID:
		case ID_TYPE_BOTH:
			include_gid = true;
			break;
		case ID_TYPE_WB_REQUIRE_TYPE:
			/*
			 * these are internal between winbindd
			 * parent and child.
			 */
			smb_panic(__location__);
			break;
		}

		if (!include_gid) {
			struct dom_sid_buf sidbuf;

			if (debug_missing == NULL) {
				continue;
			}

			D_WARNING("WARNING: skipping unix id (%"PRIu32") for sid %s "
				  "from group list because the idmap type "
				  "is %s. "
				  "This might be a security problem when ACLs "
				  "contain DENY ACEs!\n",
				  (unsigned)xids[i].id,
				  dom_sid_str_buf(&state->sids[i], &sidbuf),
				  debug_missing);
			continue;
		}

		state->gids[state->num_gids] = (gid_t)xids[i].id;
		state->num_gids += 1;
	}

	/*
	 * This should not fail, as it does not do any reallocation,
	 * just updating the talloc size.
	 */
	state->gids = talloc_realloc(state, state->gids, gid_t, state->num_gids);
	if (tevent_req_nomem(state->gids, req)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS winbindd_getgroups_recv(struct tevent_req *req,
				 struct winbindd_response *response)
{
	struct winbindd_getgroups_state *state = tevent_req_data(
		req, struct winbindd_getgroups_state);
	NTSTATUS status;
	uint32_t i;

	if (tevent_req_is_nterror(req, &status)) {
		struct dom_sid_buf buf;
		D_DEBUG("Could not convert sid %s: %s\n",
			  dom_sid_str_buf(&state->sid, &buf),
			  nt_errstr(status));
		return status;
	}

	response->data.num_entries = state->num_gids;

	D_NOTICE("Winbind external command GETGROUPS end.\n"
		 "Received %"PRIu32" entries.\n",
		 response->data.num_entries);
	if (CHECK_DEBUGLVL(DBGLVL_NOTICE)) {
		for (i = 0; i < state->num_gids; i++) {
			D_NOTICE("%"PRIu32": GID %u\n", i, state->gids[i]);
		}
	}

	if (state->num_gids > 0) {
		response->extra_data.data = talloc_move(response,
							&state->gids);
		response->length += state->num_gids * sizeof(gid_t);
	}

	return NT_STATUS_OK;
}
