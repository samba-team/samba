/*
 * Unix SMB/CIFS implementation.
 * async xids2sids
 * Copyright (C) Volker Lendecke 2015
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "winbindd.h"
#include "../libcli/security/security.h"
#include "idmap_cache.h"
#include "librpc/gen_ndr/ndr_winbind_c.h"

struct wb_xids2sids_state {
	struct dom_sid *sids;
};

static void wb_xids2sids_done(struct tevent_req *subreq);

struct tevent_req *wb_xids2sids_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct unixid *xids,
				     uint32_t num_xids)
{
	struct tevent_req *req, *subreq;
	struct wb_xids2sids_state *state;
	struct winbindd_child *child;

	req = tevent_req_create(mem_ctx, &state,
				struct wb_xids2sids_state);
	if (req == NULL) {
		return NULL;
	}

	state->sids = talloc_array(state, struct dom_sid, num_xids);
	if (tevent_req_nomem(state->sids, req)) {
		return tevent_req_post(req, ev);
	}

	child = idmap_child();

	subreq = dcerpc_wbint_UnixIDs2Sids_send(
		state, ev, child->binding_handle, num_xids, xids, state->sids);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wb_xids2sids_done, req);
	return req;
}

static void wb_xids2sids_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_xids2sids_state *state = tevent_req_data(
		req, struct wb_xids2sids_state);
	NTSTATUS status, result;

	status = dcerpc_wbint_UnixIDs2Sids_recv(subreq, state, &result);
	TALLOC_FREE(subreq);
	if (any_nt_status_not_ok(status, result, &status)) {
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

NTSTATUS wb_xids2sids_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			   struct dom_sid **sids)
{
	struct wb_xids2sids_state *state = tevent_req_data(
		req, struct wb_xids2sids_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		DEBUG(5, ("wb_sids_to_xids failed: %s\n", nt_errstr(status)));
		return status;
	}

	*sids = talloc_move(mem_ctx, &state->sids);
	return NT_STATUS_OK;
}
