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
#include "librpc/gen_ndr/ndr_winbind_c.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "lsa.h"

struct wb_sids2xids_state {
	struct tevent_context *ev;

	struct dom_sid *sids;
	uint32_t num_sids;

	struct id_map *cached;

	struct dom_sid *non_cached;
	uint32_t num_non_cached;

	/*
	 * Domain array to use for the idmap call. The output from
	 * lookupsids cannot be used directly since for migrated
	 * objects the returned domain SID can be different than the
	 * original one. The new domain SID cannot be combined with
	 * the RID from the previous domain.
	 *
	 * The proper way would be asking for the correct RID in the
	 * new domain, but this approach avoids id mappings for
	 * invalid SIDs.
	 */
	struct lsa_RefDomainList idmap_doms;

	uint32_t dom_index;
	struct wbint_TransIDArray *dom_ids;
	struct lsa_RefDomainList idmap_dom;
	bool tried_dclookup;

	struct wbint_TransIDArray ids;
};


static bool wb_sids2xids_in_cache(struct dom_sid *sid, struct id_map *map);
static void wb_sids2xids_lookupsids_done(struct tevent_req *subreq);
static void wb_sids2xids_done(struct tevent_req *subreq);
static void wb_sids2xids_gotdc(struct tevent_req *subreq);

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
		struct dom_sid_buf buf;

		DEBUG(10, ("SID %d: %s\n", (int)i,
			   dom_sid_str_buf(&state->sids[i], &buf)));

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
static struct wbint_TransIDArray *wb_sids2xids_extract_for_domain_index(
	TALLOC_CTX *mem_ctx, const struct wbint_TransIDArray *src,
	uint32_t domain_index);

static void wb_sids2xids_lookupsids_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_sids2xids_state *state = tevent_req_data(
		req, struct wb_sids2xids_state);
	struct lsa_RefDomainList *domains = NULL;
	struct lsa_TransNameArray *names = NULL;
	struct dcerpc_binding_handle *child_binding_handle = NULL;
	NTSTATUS status;
	uint32_t i;

	status = wb_lookupsids_recv(subreq, state, &domains, &names);
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
		const struct dom_sid *sid = &state->non_cached[i];
		struct dom_sid dom_sid;
		struct lsa_TranslatedName *n = &names->names[i];
		struct wbint_TransID *t = &state->ids.ids[i];
		int domain_index;
		const char *domain_name = NULL;

		if (n->sid_index != UINT32_MAX) {
			const struct lsa_DomainInfo *info;
			bool match;

			info = &domains->domains[n->sid_index];
			match = dom_sid_in_domain(info->sid, sid);
			if (match) {
				domain_name = info->name.string;
			}
		}
		if (domain_name == NULL) {
			struct winbindd_domain *wb_domain = NULL;

			/*
			 * This is needed to handle Samba DCs
			 * which always return sid_index == UINT32_MAX for
			 * unknown sids.
			 */
			wb_domain = find_domain_from_sid_noinit(sid);
			if (wb_domain != NULL) {
				domain_name = wb_domain->name;
			}
		}
		if (domain_name == NULL) {
			domain_name = "";
		}

		sid_copy(&dom_sid, sid);
		sid_split_rid(&dom_sid, &t->rid);
		t->type_hint = lsa_SidType_to_id_type(n->sid_type);
		domain_index = init_lsa_ref_domain_list(
			state, &state->idmap_doms, domain_name, &dom_sid);
		if (domain_index == -1) {
			tevent_req_oom(req);
			return;
		}
		t->domain_index = domain_index;

		t->xid.id = UINT32_MAX;
		t->xid.type = ID_TYPE_NOT_SPECIFIED;
	}

	TALLOC_FREE(names);
	TALLOC_FREE(domains);

	child_binding_handle = idmap_child_handle();

	state->dom_ids = wb_sids2xids_extract_for_domain_index(
		state, &state->ids, state->dom_index);
	if (tevent_req_nomem(state->dom_ids, req)) {
		return;
	}

	state->idmap_dom = (struct lsa_RefDomainList) {
		.count = 1,
		.domains = &state->idmap_doms.domains[state->dom_index],
		.max_size = 1
	};

	subreq = dcerpc_wbint_Sids2UnixIDs_send(
		state, state->ev, child_binding_handle, &state->idmap_dom,
		state->dom_ids);
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
	struct winbindd_child *child;

	struct wbint_TransIDArray *src, *dst;
	uint32_t i, src_idx;

	status = dcerpc_wbint_Sids2UnixIDs_recv(subreq, state, &result);
	TALLOC_FREE(subreq);

	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (NT_STATUS_EQUAL(result, NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND) &&
	    !state->tried_dclookup) {

		struct lsa_DomainInfo *d;

		d = &state->idmap_doms.domains[state->dom_index];

		subreq = wb_dsgetdcname_send(
			state, state->ev, d->name.string, NULL, NULL,
			DS_RETURN_DNS_NAME);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, wb_sids2xids_gotdc, req);
		return;
	}

	src = state->dom_ids;
	src_idx = 0;
	dst = &state->ids;

	if (any_nt_status_not_ok(status, result, &status)) {
		DBG_DEBUG("status=%s, result=%s\n", nt_errstr(status),
			  nt_errstr(result));

		/*
		 * All we can do here is to report "not mapped"
		 */
		for (i=0; i<src->num_ids; i++) {
			src->ids[i].xid.type = ID_TYPE_NOT_SPECIFIED;
		}
	}

	for (i=0; i<dst->num_ids; i++) {
		if (dst->ids[i].domain_index == state->dom_index) {
			dst->ids[i].xid  = src->ids[src_idx].xid;
			src_idx += 1;
		}
	}

	TALLOC_FREE(state->dom_ids);

	state->dom_index += 1;
	state->tried_dclookup = false;

	if (state->dom_index == state->idmap_doms.count) {
		tevent_req_done(req);
		return;
	}

	child = idmap_child();

	state->dom_ids = wb_sids2xids_extract_for_domain_index(
		state, &state->ids, state->dom_index);
	if (tevent_req_nomem(state->dom_ids, req)) {
		return;
	}

	state->idmap_dom = (struct lsa_RefDomainList) {
		.count = 1,
		.domains = &state->idmap_doms.domains[state->dom_index],
		.max_size = 1
	};

	subreq = dcerpc_wbint_Sids2UnixIDs_send(
		state, state->ev, child->binding_handle, &state->idmap_dom,
		state->dom_ids);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_sids2xids_done, req);
}

static void wb_sids2xids_gotdc(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_sids2xids_state *state = tevent_req_data(
		req, struct wb_sids2xids_state);
	struct winbindd_child *child = idmap_child();
	struct netr_DsRGetDCNameInfo *dcinfo;
	NTSTATUS status;

	status = wb_dsgetdcname_recv(subreq, state, &dcinfo);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->tried_dclookup = true;

	{
		struct lsa_DomainInfo *d =
			&state->idmap_doms.domains[state->dom_index];
		const char *dom_name = d->name.string;

		status = wb_dsgetdcname_gencache_set(dom_name, dcinfo);
		if (tevent_req_nterror(req, status)) {
			return;
		}
	}

	subreq = dcerpc_wbint_Sids2UnixIDs_send(
		state, state->ev, child->binding_handle, &state->idmap_dom,
		state->dom_ids);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_sids2xids_done, req);
}

NTSTATUS wb_sids2xids_recv(struct tevent_req *req,
			   struct unixid xids[], uint32_t num_xids)
{
	struct wb_sids2xids_state *state = tevent_req_data(
		req, struct wb_sids2xids_state);
	NTSTATUS status;
	uint32_t i, num_non_cached;

	if (tevent_req_is_nterror(req, &status)) {
		DEBUG(5, ("wb_sids_to_xids failed: %s\n", nt_errstr(status)));
		return status;
	}

	if (num_xids != state->num_sids) {
		DEBUG(1, ("%s: Have %u xids, caller wants %u\n", __func__,
			  (unsigned)state->num_sids, num_xids));
		return NT_STATUS_INTERNAL_ERROR;
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

static struct wbint_TransIDArray *wb_sids2xids_extract_for_domain_index(
	TALLOC_CTX *mem_ctx, const struct wbint_TransIDArray *src,
	uint32_t domain_index)
{
	struct wbint_TransIDArray *ret;
	uint32_t i;

	ret = talloc_zero(mem_ctx, struct wbint_TransIDArray);
	if (ret == NULL) {
		return NULL;
	}
	ret->ids = talloc_array(ret, struct wbint_TransID, src->num_ids);
	if (ret->ids == NULL) {
		TALLOC_FREE(ret);
		return NULL;
	}

	for (i=0; i<src->num_ids; i++) {
		if (src->ids[i].domain_index == domain_index) {
			ret->ids[ret->num_ids] = src->ids[i];
			ret->ids[ret->num_ids].domain_index = 0;
			ret->num_ids += 1;
		}
	}

	return ret;
}
