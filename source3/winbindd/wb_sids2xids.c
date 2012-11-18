/*
   Unix SMB/CIFS implementation.
   async sids2xids
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
#include "idmap_cache.h"
#include "librpc/gen_ndr/ndr_wbint_c.h"

struct wb_sids2xids_state {
	struct tevent_context *ev;

	struct dom_sid *sids;
	uint32_t num_sids;

	struct id_map *cached;

	struct dom_sid *non_cached;
	uint32_t num_non_cached;

	struct lsa_RefDomainList *domains;
	struct lsa_TransNameArray *names;

	struct wbint_TransIDArray ids;
};


static bool wb_sids2xids_in_cache(struct dom_sid *sid, struct id_map *map);
static void wb_sids2xids_lookupsids_done(struct tevent_req *subreq);
static void wb_sids2xids_done(struct tevent_req *subreq);

struct tevent_req *wb_sids2xids_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     const struct dom_sid *sids,
				     const uint32_t num_sids)
{
	struct tevent_req *req, *subreq;
	struct wb_sids2xids_state *state;
	uint32_t i;

	req = tevent_req_create(mem_ctx, &state,
				struct wb_sids2xids_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;

	state->num_sids = num_sids;

	state->sids = talloc_zero_array(state, struct dom_sid, num_sids);
	if (tevent_req_nomem(state->sids, req)) {
		return tevent_req_post(req, ev);
	}

	for (i = 0; i < num_sids; i++) {
		sid_copy(&state->sids[i], &sids[i]);
	}

	state->cached = talloc_zero_array(state, struct id_map, num_sids);
	if (tevent_req_nomem(state->cached, req)) {
		return tevent_req_post(req, ev);
	}

	state->non_cached = talloc_array(state, struct dom_sid, num_sids);
	if (tevent_req_nomem(state->non_cached, req)) {
		return tevent_req_post(req, ev);
	}

	/*
	 * Extract those sids that can not be resolved from cache
	 * into a separate list to be handed to id mapping, keeping
	 * the same index.
	 */
	for (i=0; i<state->num_sids; i++) {

		DEBUG(10, ("SID %d: %s\n", (int)i,
			   sid_string_dbg(&state->sids[i])));

		if (wb_sids2xids_in_cache(&state->sids[i], &state->cached[i])) {
			continue;
		}
		sid_copy(&state->non_cached[state->num_non_cached],
			 &state->sids[i]);
		state->num_non_cached += 1;
	}

	if (state->num_non_cached == 0) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	subreq = wb_lookupsids_send(state, ev, state->non_cached,
				    state->num_non_cached);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wb_sids2xids_lookupsids_done, req);
	return req;
}

static bool wb_sids2xids_in_cache(struct dom_sid *sid, struct id_map *map)
{
	struct unixid id;
	bool expired;

	if (!winbindd_use_idmap_cache()) {
		return false;
	}
	if (idmap_cache_find_sid2unixid(sid, &id, &expired)) {
		if (expired && is_domain_online(find_our_domain())) {
			return false;
		}
		map->sid = sid;
		map->xid = id;
		map->status = ID_MAPPED;
		return true;
	}
	return false;
}

static enum id_type lsa_SidType_to_id_type(const enum lsa_SidType sid_type);

static void wb_sids2xids_lookupsids_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_sids2xids_state *state = tevent_req_data(
		req, struct wb_sids2xids_state);
	struct winbindd_child *child;
	NTSTATUS status;
	int i;

	status = wb_lookupsids_recv(subreq, state, &state->domains,
				    &state->names);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->ids.num_ids = state->num_non_cached;
	state->ids.ids = talloc_array(state, struct wbint_TransID,
				      state->num_non_cached);
	if (tevent_req_nomem(state->ids.ids, req)) {
		return;
	}

	for (i=0; i<state->num_non_cached; i++) {
		struct lsa_TranslatedName *n = &state->names->names[i];
		struct wbint_TransID *t = &state->ids.ids[i];

		t->type = lsa_SidType_to_id_type(n->sid_type);
		t->domain_index = n->sid_index;
		sid_peek_rid(&state->non_cached[i], &t->rid);
		t->xid.id = UINT32_MAX;
		t->xid.type = t->type;
	}

	child = idmap_child();

	subreq = dcerpc_wbint_Sids2UnixIDs_send(
		state, state->ev, child->binding_handle, state->domains,
		&state->ids);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_sids2xids_done, req);
}

static enum id_type lsa_SidType_to_id_type(const enum lsa_SidType sid_type)
{
	enum id_type type;

	switch(sid_type) {
	case SID_NAME_COMPUTER:
	case SID_NAME_USER:
		type = ID_TYPE_UID;
		break;
	case SID_NAME_DOM_GRP:
	case SID_NAME_ALIAS:
	case SID_NAME_WKN_GRP:
		type = ID_TYPE_GID;
		break;
	default:
		type = ID_TYPE_NOT_SPECIFIED;
		break;
	}

	return type;
}


static void wb_sids2xids_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_sids2xids_state *state = tevent_req_data(
		req, struct wb_sids2xids_state);
	NTSTATUS status, result;

	status = dcerpc_wbint_Sids2UnixIDs_recv(subreq, state, &result);
	TALLOC_FREE(subreq);
	if (any_nt_status_not_ok(status, result, &status)) {
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

NTSTATUS wb_sids2xids_recv(struct tevent_req *req,
			   struct unixid *xids)
{
	struct wb_sids2xids_state *state = tevent_req_data(
		req, struct wb_sids2xids_state);
	NTSTATUS status;
	uint32_t i, num_non_cached;

	if (tevent_req_is_nterror(req, &status)) {
		DEBUG(5, ("wb_sids_to_xids failed: %s\n", nt_errstr(status)));
		return status;
	}

	num_non_cached = 0;

	for (i=0; i<state->num_sids; i++) {
		struct unixid xid;

		xid.id = UINT32_MAX;

		if (state->cached[i].sid != NULL) {
			xid = state->cached[i].xid;
		} else {
			xid = state->ids.ids[num_non_cached].xid;

			idmap_cache_set_sid2unixid(
				&state->non_cached[num_non_cached],
				&xid);

			num_non_cached += 1;
		}

		xids[i] = xid;
	}

	return NT_STATUS_OK;
}
