/*
   Unix SMB/CIFS implementation.
   async implementation of WINBINDD_ALLOCATE_UID
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
#include "librpc/gen_ndr/ndr_winbind_c.h"

struct winbindd_allocate_uid_state {
	struct tevent_context *ev;
	uint64_t uid;
};

static void winbindd_allocate_uid_initialized(struct tevent_req *subreq);
static void winbindd_allocate_uid_done(struct tevent_req *subreq);

struct tevent_req *winbindd_allocate_uid_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct winbindd_cli_state *cli,
					      struct winbindd_request *request)
{
	struct tevent_req *req, *subreq;
	struct winbindd_allocate_uid_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct winbindd_allocate_uid_state);
	if (req == NULL) {
		return NULL;
	}
        state->ev = ev;

	DEBUG(3, ("allocate_uid\n"));

	subreq = wb_parent_idmap_setup_send(state, ev);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, winbindd_allocate_uid_initialized, req);
	return req;
}

static void winbindd_allocate_uid_initialized(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct dcerpc_binding_handle *child_binding_handle = NULL;
	struct winbindd_allocate_uid_state *state = tevent_req_data(
		req, struct winbindd_allocate_uid_state);
	const struct wb_parent_idmap_config *cfg = NULL;
	NTSTATUS status;

	status = wb_parent_idmap_setup_recv(subreq, &cfg);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	if (cfg->num_doms == 0) {
		/*
		 * idmap_tdb also returns UNSUCCESSFUL if a range is full
		 */
		tevent_req_nterror(req, NT_STATUS_UNSUCCESSFUL);
		return;
	}

        child_binding_handle = idmap_child_handle();

        subreq = dcerpc_wbint_AllocateUid_send(state,
					       state->ev,
                                               child_binding_handle,
					       &state->uid);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, winbindd_allocate_uid_done, req);
}

static void winbindd_allocate_uid_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winbindd_allocate_uid_state *state = tevent_req_data(
		req, struct winbindd_allocate_uid_state);
	NTSTATUS status, result;

	status = dcerpc_wbint_AllocateUid_recv(subreq, state, &result);
	TALLOC_FREE(subreq);
	if (any_nt_status_not_ok(status, result, &status)) {
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

NTSTATUS winbindd_allocate_uid_recv(struct tevent_req *req,
				    struct winbindd_response *response)
{
	struct winbindd_allocate_uid_state *state = tevent_req_data(
		req, struct winbindd_allocate_uid_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		DEBUG(5, ("Could not allocate uid: %s\n", nt_errstr(status)));
		return status;
	}
	response->data.uid = state->uid;
	return NT_STATUS_OK;
}
