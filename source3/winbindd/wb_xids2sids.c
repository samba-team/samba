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
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "passdb/lookup_sid.h"

struct wb_xids2sids_dom_state {
	struct tevent_context *ev;
	struct unixid *all_xids;
	const bool *cached;
	size_t num_all_xids;
	struct dom_sid *all_sids;
	const struct wb_parent_idmap_config_dom *dom_map;
	bool tried_dclookup;

	size_t num_dom_xids;
	struct unixid *dom_xids;
	struct dom_sid *dom_sids;
};

static void wb_xids2sids_dom_done(struct tevent_req *subreq);
static void wb_xids2sids_dom_gotdc(struct tevent_req *subreq);

static struct tevent_req *wb_xids2sids_dom_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	const struct wb_parent_idmap_config_dom *dom_map,
	struct unixid *xids,
	const bool *cached,
	size_t num_xids,
	struct dom_sid *sids)
{
	struct tevent_req *req, *subreq;
	struct wb_xids2sids_dom_state *state;
	struct dcerpc_binding_handle *child_binding_handle = NULL;
	size_t i;

	req = tevent_req_create(mem_ctx, &state,
				struct wb_xids2sids_dom_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->all_xids = xids;
	state->cached = cached;
	state->num_all_xids = num_xids;
	state->all_sids = sids;
	state->dom_map = dom_map;

	state->dom_xids = talloc_array(state, struct unixid, num_xids);
	if (tevent_req_nomem(state->dom_xids, req)) {
		return tevent_req_post(req, ev);
	}
	state->dom_sids = talloc_array(state, struct dom_sid, num_xids);
	if (tevent_req_nomem(state->dom_sids, req)) {
		return tevent_req_post(req, ev);
	}

	for (i=0; i<num_xids; i++) {
		struct unixid id = state->all_xids[i];

		if ((id.id < dom_map->low_id) || (id.id > dom_map->high_id)) {
			/* out of range */
			continue;
		}
		if (state->cached[i]) {
			/* already found in cache */
			continue;
		}
		if (!is_null_sid(&state->all_sids[i])) {
			/* already mapped in a previously asked domain */
			continue;
		}
		state->dom_xids[state->num_dom_xids++] = id;
	}

	if (state->num_dom_xids == 0) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	child_binding_handle = idmap_child_handle();
	subreq = dcerpc_wbint_UnixIDs2Sids_send(
		state, ev, child_binding_handle, dom_map->name, dom_map->sid,
		state->num_dom_xids, state->dom_xids, state->dom_sids);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wb_xids2sids_dom_done, req);
	return req;
}

static void wb_xids2sids_dom_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_xids2sids_dom_state *state = tevent_req_data(
		req, struct wb_xids2sids_dom_state);
	const struct wb_parent_idmap_config_dom *dom_map = state->dom_map;
	NTSTATUS status, result;
	size_t i;
	size_t dom_sid_idx;

	status = dcerpc_wbint_UnixIDs2Sids_recv(subreq, state, &result);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (NT_STATUS_EQUAL(result, NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND) &&
	    !state->tried_dclookup) {

		subreq = wb_dsgetdcname_send(
			state, state->ev, state->dom_map->name, NULL, NULL,
			DS_RETURN_DNS_NAME);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, wb_xids2sids_dom_gotdc, req);
		return;
	}

	if (!NT_STATUS_EQUAL(result, NT_STATUS_NONE_MAPPED) &&
	    tevent_req_nterror(req, result)) {
		return;
	}

	dom_sid_idx = 0;

	for (i=0; i<state->num_all_xids; i++) {
		struct unixid *id = &state->all_xids[i];

		if ((id->id < dom_map->low_id) || (id->id > dom_map->high_id)) {
			/* out of range */
			continue;
		}
		if (state->cached[i]) {
			/* already found in cache */
			continue;
		}
		if (!is_null_sid(&state->all_sids[i])) {
			/* already mapped in a previously asked domain */
			continue;
		}

		sid_copy(&state->all_sids[i], &state->dom_sids[dom_sid_idx]);
		*id = state->dom_xids[dom_sid_idx];

		dom_sid_idx += 1;
	}

	tevent_req_done(req);
}

static void wb_xids2sids_dom_gotdc(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_xids2sids_dom_state *state = tevent_req_data(
		req, struct wb_xids2sids_dom_state);
	struct dcerpc_binding_handle *child_binding_handle = NULL;
	struct netr_DsRGetDCNameInfo *dcinfo;
	NTSTATUS status;

	status = wb_dsgetdcname_recv(subreq, state, &dcinfo);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->tried_dclookup = true;

	status = wb_dsgetdcname_gencache_set(state->dom_map->name, dcinfo);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	child_binding_handle = idmap_child_handle();
	subreq = dcerpc_wbint_UnixIDs2Sids_send(
		state, state->ev, child_binding_handle, state->dom_map->name,
		state->dom_map->sid, state->num_dom_xids,
		state->dom_xids, state->dom_sids);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_xids2sids_dom_done, req);
}

static NTSTATUS wb_xids2sids_dom_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

struct wb_xids2sids_state {
	struct tevent_context *ev;
	struct unixid *xids;
	size_t num_xids;
	struct dom_sid *sids;
	bool *cached;

	size_t dom_idx;
	const struct wb_parent_idmap_config *cfg;
};

static void wb_xids2sids_idmap_setup_done(struct tevent_req *subreq);
static void wb_xids2sids_done(struct tevent_req *subreq);

struct tevent_req *wb_xids2sids_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     const struct unixid *xids,
				     uint32_t num_xids)
{
	struct tevent_req *req, *subreq;
	struct wb_xids2sids_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct wb_xids2sids_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->num_xids = num_xids;

	state->xids = talloc_array(state, struct unixid, num_xids);
	if (tevent_req_nomem(state->xids, req)) {
		return tevent_req_post(req, ev);
	}
	memcpy(state->xids, xids, num_xids * sizeof(struct unixid));

	state->sids = talloc_zero_array(state, struct dom_sid, num_xids);
	if (tevent_req_nomem(state->sids, req)) {
		return tevent_req_post(req, ev);
	}

	state->cached = talloc_zero_array(state, bool, num_xids);
	if (tevent_req_nomem(state->cached, req)) {
		return tevent_req_post(req, ev);
	}

	if (winbindd_use_idmap_cache()) {
		uint32_t i;

		for (i=0; i<num_xids; i++) {
			struct dom_sid sid = {0};
			bool ok, expired = true;

			ok = idmap_cache_find_xid2sid(
				&xids[i], &sid, &expired);
			if (ok && !expired) {
				struct dom_sid_buf buf;
				DBG_DEBUG("Found %cID in cache: %s\n",
					  xids[i].type == ID_TYPE_UID?'U':'G',
					  dom_sid_str_buf(&sid, &buf));

				sid_copy(&state->sids[i], &sid);
				state->cached[i] = true;
			}
		}
	}

	subreq = wb_parent_idmap_setup_send(state, state->ev);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wb_xids2sids_idmap_setup_done, req);
	return req;
}

static void wb_xids2sids_idmap_setup_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_xids2sids_state *state = tevent_req_data(
		req, struct wb_xids2sids_state);
	NTSTATUS status;

	status = wb_parent_idmap_setup_recv(subreq, &state->cfg);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	SMB_ASSERT(state->cfg->num_doms > 0);

	subreq = wb_xids2sids_dom_send(
		state, state->ev,
		&state->cfg->doms[state->dom_idx],
		state->xids, state->cached, state->num_xids, state->sids);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_xids2sids_done, req);
	return;
}

static void wb_xids2sids_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_xids2sids_state *state = tevent_req_data(
		req, struct wb_xids2sids_state);
	size_t i;
	NTSTATUS status;

	status = wb_xids2sids_dom_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->dom_idx += 1;

	if (state->dom_idx < state->cfg->num_doms) {
		const struct wb_parent_idmap_config_dom *dom_map =
			&state->cfg->doms[state->dom_idx];

		subreq = wb_xids2sids_dom_send(state,
					       state->ev,
					       dom_map,
					       state->xids,
					       state->cached,
					       state->num_xids,
					       state->sids);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, wb_xids2sids_done, req);
		return;
	}


	for (i = 0; i < state->num_xids; i++) {
		/*
		 * Prime the cache after an xid2sid call. It's important that we
		 * use the xid value returned from the backend for the xid value
		 * passed to idmap_cache_set_sid2unixid(), not the input to
		 * wb_xids2sids_send: the input carries what was asked for,
		 * e.g. a ID_TYPE_UID. The result from the backend something the
		 * idmap child possibly changed to ID_TYPE_BOTH.
		 *
		 * And of course If the value was from the cache don't update
		 * the cache.
		 */

		if (state->cached[i]) {
			continue;
		}

		idmap_cache_set_sid2unixid(&state->sids[i], &state->xids[i]);
	}

	tevent_req_done(req);
	return;
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
