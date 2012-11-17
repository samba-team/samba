/*
   Unix SMB/CIFS implementation.
   async implementation of WINBINDD_SIDS_TO_XIDS
   Copyright (C) Volker Lendecke 2011
   Copyright (C) Michael Adam 2012

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
#include "../libcli/security/security.h"


struct winbindd_sids_to_xids_state {
	struct tevent_context *ev;
	struct dom_sid *sids;
	uint32_t num_sids;
	struct unixid *xids;
};

static void winbindd_sids_to_xids_done(struct tevent_req *subreq);

struct tevent_req *winbindd_sids_to_xids_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct winbindd_cli_state *cli,
					      struct winbindd_request *request)
{
	struct tevent_req *req, *subreq;
	struct winbindd_sids_to_xids_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct winbindd_sids_to_xids_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;

	DEBUG(3, ("sids_to_xids\n"));

	if (request->extra_len == 0) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}
	if (request->extra_data.data[request->extra_len-1] != '\0') {
		DEBUG(10, ("Got invalid sids list\n"));
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}
	if (!parse_sidlist(state, request->extra_data.data,
			   &state->sids, &state->num_sids)) {
		DEBUG(10, ("parse_sidlist failed\n"));
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	DEBUG(10, ("num_sids: %d\n", (int)state->num_sids));

	subreq = wb_sids2xids_send(state, ev, state->sids, state->num_sids);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, winbindd_sids_to_xids_done, req);
	return req;
}

static void winbindd_sids_to_xids_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winbindd_sids_to_xids_state *state = tevent_req_data(
		req, struct winbindd_sids_to_xids_state);
	NTSTATUS status;

	state->xids = talloc_zero_array(state, struct unixid, state->num_sids);
	if (tevent_req_nomem(state->xids, req)) {
		return;
	}

	status = wb_sids2xids_recv(subreq, state->xids);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS winbindd_sids_to_xids_recv(struct tevent_req *req,
				    struct winbindd_response *response)
{
	struct winbindd_sids_to_xids_state *state = tevent_req_data(
		req, struct winbindd_sids_to_xids_state);
	NTSTATUS status;
	char *result = NULL;
	uint32_t i;

	if (tevent_req_is_nterror(req, &status)) {
		DEBUG(5, ("Could not convert sids: %s\n", nt_errstr(status)));
		return status;
	}

	result = talloc_strdup(response, "");
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i<state->num_sids; i++) {
		char type = '\0';
		bool found = true;
		struct unixid xid;

		xid = state->xids[i];

		switch (xid.type) {
		case ID_TYPE_UID:
			type = 'U';
			break;
		case ID_TYPE_GID:
			type = 'G';
			break;
		case ID_TYPE_BOTH:
			type = 'B';
			break;
		default:
			found = false;
			break;
		}

		if (xid.id == UINT32_MAX) {
			found = false;
		}

		if (found) {
			result = talloc_asprintf_append_buffer(
				result, "%c%lu\n", type,
				(unsigned long)xid.id);
		} else {
			result = talloc_asprintf_append_buffer(result, "\n");
		}
		if (result == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	response->extra_data.data = result;
	response->length += talloc_get_size(result);

	return NT_STATUS_OK;
}
