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


struct winbindd_xids_to_sids_state {
	struct tevent_context *ev;

	struct unixid *xids;
	uint32_t num_xids;

	struct dom_sid *sids;
};

static void winbindd_xids_to_sids_done(struct tevent_req *subreq);

struct tevent_req *winbindd_xids_to_sids_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct winbindd_cli_state *cli,
					      struct winbindd_request *request)
{
	struct tevent_req *req, *subreq;
	struct winbindd_xids_to_sids_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct winbindd_xids_to_sids_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;

	DEBUG(3, ("xids_to_sids\n"));

	if (request->extra_len == 0) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}
	if (request->extra_data.data[request->extra_len-1] != '\0') {
		DEBUG(10, ("Got invalid xids list\n"));
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}
	if (!parse_xidlist(state, request->extra_data.data,
			   &state->xids, &state->num_xids)) {
		DEBUG(10, ("parse_sidlist failed\n"));
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	DBG_DEBUG("num_xids: %"PRIu32"\n%s\n",
		  state->num_xids,
		  (char *)request->extra_data.data);

	subreq = wb_xids2sids_send(state, ev, state->xids, state->num_xids);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, winbindd_xids_to_sids_done, req);
	return req;
}

static void winbindd_xids_to_sids_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winbindd_xids_to_sids_state *state = tevent_req_data(
		req, struct winbindd_xids_to_sids_state);
	NTSTATUS status;

	status = wb_xids2sids_recv(subreq, state, &state->sids);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS winbindd_xids_to_sids_recv(struct tevent_req *req,
				    struct winbindd_response *response)
{
	struct winbindd_xids_to_sids_state *state = tevent_req_data(
		req, struct winbindd_xids_to_sids_state);
	NTSTATUS status;
	char *result = NULL;
	uint32_t i;

	if (tevent_req_is_nterror(req, &status)) {
		DBG_INFO("Could not convert xids: %s\n", nt_errstr(status));
		return status;
	}

	result = talloc_strdup(response, "");
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i<state->num_xids; i++) {
		struct dom_sid_buf sid_buf;
		const char *str = "-";

		if (!is_null_sid(&state->sids[i])) {
			dom_sid_str_buf(&state->sids[i], &sid_buf);
			str = sid_buf.buf;
		}

		result = talloc_asprintf_append_buffer(
			result, "%s\n", str);
		if (result == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	DBG_DEBUG("sids:\n%s\n", result);

	response->extra_data.data = result;
	response->length += talloc_get_size(result);

	return NT_STATUS_OK;
}
