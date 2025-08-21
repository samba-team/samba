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

	const struct wb_parent_idmap_config *cfg;

	struct dom_sid *sids;
	uint32_t num_sids;

	struct wbint_TransIDArray all_ids;

	/* Used to translated the idx back into all_ids.ids[idx] */
	uint32_t *tmp_idx;

	uint32_t lookup_count;
	struct dom_sid *lookup_sids;

	struct wbint_TransIDArray map_ids_in;
	struct wbint_TransIDArray map_ids_out;

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
	struct lsa_RefDomainList idmap_dom;
	bool tried_dclookup;
};

static void wb_sids2xids_idmap_setup_done(struct tevent_req *subreq);
static bool wb_sids2xids_in_cache(struct dom_sid *sid, struct id_map *map);
static void wb_sids2xids_lookupsids_done(struct tevent_req *subreq);
static void wb_sids2xids_done(struct tevent_req *subreq);
static void wb_sids2xids_gotdc(struct tevent_req *subreq);
static void wb_sids2xids_next_sids2unix(struct tevent_req *req);
static enum id_type lsa_SidType_to_id_type(const enum lsa_SidType sid_type);

struct tevent_req *wb_sids2xids_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     const struct dom_sid *sids,
				     const uint32_t num_sids)
{
	struct tevent_req *req, *subreq;
	struct wb_sids2xids_state *state;
	uint32_t i;
	uint32_t num_valid = 0;

	req = tevent_req_create(mem_ctx, &state,
				struct wb_sids2xids_state);
	if (req == NULL) {
		return NULL;
	}

	D_INFO("WB command sids2xids start.\n"
	       "Resolving %"PRIu32" SID(s).\n", num_sids);

	state->ev = ev;

	state->num_sids = num_sids;

	state->sids = talloc_zero_array(state, struct dom_sid, num_sids);
	if (tevent_req_nomem(state->sids, req)) {
		return tevent_req_post(req, ev);
	}

	for (i = 0; i < num_sids; i++) {
		sid_copy(&state->sids[i], &sids[i]);
	}

	state->all_ids.num_ids = num_sids;
	state->all_ids.ids = talloc_zero_array(state, struct wbint_TransID, num_sids);
	if (tevent_req_nomem(state->all_ids.ids, req)) {
		return tevent_req_post(req, ev);
	}

	state->tmp_idx = talloc_zero_array(state, uint32_t, num_sids);
	if (tevent_req_nomem(state->tmp_idx, req)) {
		return tevent_req_post(req, ev);
	}

	state->lookup_sids = talloc_zero_array(state, struct dom_sid, num_sids);
	if (tevent_req_nomem(state->lookup_sids, req)) {
		return tevent_req_post(req, ev);
	}

	state->map_ids_in.ids = talloc_zero_array(state, struct wbint_TransID, num_sids);
	if (tevent_req_nomem(state->map_ids_in.ids, req)) {
		return tevent_req_post(req, ev);
	}

	/*
	 * Extract those sids that can not be resolved from cache
	 * into a separate list to be handed to id mapping, keeping
	 * the same index.
	 */
	for (i=0; i<state->num_sids; i++) {
		struct wbint_TransID *cur_id = &state->all_ids.ids[i];
		struct dom_sid domain_sid;
		struct dom_sid_buf buf;
		struct id_map map = { .status = ID_UNMAPPED, };
		uint32_t rid = 0;
		bool in_cache;

		sid_copy(&domain_sid, &state->sids[i]);
		sid_split_rid(&domain_sid, &rid);

		/*
		 * Start with an invalid entry.
		 */
		*cur_id = (struct wbint_TransID) {
			.type_hint = ID_TYPE_NOT_SPECIFIED,
			.domain_index = UINT32_MAX - 1, /* invalid */
			.rid = rid,
			.xid = {
				.id = UINT32_MAX,
				.type = ID_TYPE_NOT_SPECIFIED,
			},
		};

		D_DEBUG("%"PRIu32": SID %s\n",
			i, dom_sid_str_buf(&state->sids[i], &buf));

		in_cache = wb_sids2xids_in_cache(&state->sids[i], &map);
		if (in_cache) {
			/*
			 * We used to ignore map.status and just rely
			 * on map.xid.type.
			 *
			 * Lets keep this logic for now...
			 */

			cur_id->xid = map.xid;
			cur_id->domain_index = UINT32_MAX; /* this marks it as filled entry */
			num_valid += 1;
			continue;
		}
	}

	D_DEBUG("Found %"PRIu32" (out of %"PRIu32") SID(s) in cache.\n",
		num_valid, num_sids);
	if (num_valid == num_sids) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	subreq = wb_parent_idmap_setup_send(state, state->ev);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wb_sids2xids_idmap_setup_done, req);
	return req;
}

static void wb_sids2xids_idmap_setup_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_sids2xids_state *state = tevent_req_data(
		req, struct wb_sids2xids_state);
	NTSTATUS status;
	uint32_t i;

	status = wb_parent_idmap_setup_recv(subreq, &state->cfg);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		D_WARNING("Failed with %s.\n", nt_errstr(status));
		return;
	}
	SMB_ASSERT(state->cfg->num_doms > 0);
	D_DEBUG("We will loop over %"PRIu32" SID(s) (skipping those already resolved via cache) and over %"PRIu32" domain(s).\n",
		state->num_sids,
		state->cfg->num_doms);

	/*
	 * Now we build a list with all domain
	 * with non cached entries
	 */
	for (i=0; i<state->num_sids; i++) {
		struct wbint_TransID *t = &state->all_ids.ids[i];
		struct dom_sid domain_sid;
		const char *domain_name = NULL;
		int domain_index;
		uint32_t rid = 0;
		uint32_t di;
		struct dom_sid_buf buf0, buf1;

		D_DEBUG("%"PRIu32": Processing SID %s\n",
			i,
			dom_sid_str_buf(&state->sids[i], &buf0));
		if (t->domain_index == UINT32_MAX) {
			/* ignore already filled entries */
			D_DEBUG("%"PRIu32": Ignoring already resolved SID %s\n",
				i,
				dom_sid_str_buf(&state->sids[i], &buf0));
			continue;
		}

		sid_copy(&domain_sid, &state->sids[i]);
		sid_split_rid(&domain_sid, &rid);
		D_DEBUG("%"PRIu32": Split SID %s into domain SID %s and RID %"PRIu32"\n",
			i,
			dom_sid_str_buf(&state->sids[i], &buf0),
			dom_sid_str_buf(&domain_sid, &buf1),
			rid);

		if (t->type_hint == ID_TYPE_NOT_SPECIFIED) {
			const char *tmp_name = NULL;
			enum lsa_SidType sid_type = SID_NAME_USE_NONE;
			const struct dom_sid *tmp_authority_sid = NULL;
			const char *tmp_authority_name = NULL;

			/*
			 * Try to get a type hint from for predefined sids
			 */
			status = dom_sid_lookup_predefined_sid(&state->sids[i],
							       &tmp_name,
							       &sid_type,
							       &tmp_authority_sid,
							       &tmp_authority_name);
			if (NT_STATUS_IS_OK(status)) {
				t->type_hint = lsa_SidType_to_id_type(sid_type);
				D_DEBUG("Got a type hint: %d from predefined SID.\n",
					t->type_hint);
			}
		}

		D_DEBUG("Looping over %"PRIu32" domain(s) to find domain SID %s.\n",
			state->cfg->num_doms,
			dom_sid_str_buf(&domain_sid, &buf0));
		for (di = 0; di < state->cfg->num_doms; di++) {
			struct wb_parent_idmap_config_dom *dom =
				&state->cfg->doms[di];
			bool match;

			match = dom_sid_equal(&domain_sid, &dom->sid);
			if (!match) {
				continue;
			}

			domain_name = dom->name;
			D_DEBUG("Found domain '%s'.\n", domain_name);
			break;
		}
		if (domain_name == NULL) {
			struct winbindd_domain *wb_domain = NULL;

			D_DEBUG("Could not find a domain for domain SID %s. Trying to fill the domain name from list of known domains.\n",
				dom_sid_str_buf(&domain_sid, &buf0));
			/*
			 * Try to fill the name if we already know it
			 */
			wb_domain = find_domain_from_sid_noinit(&state->sids[i]);
			if (wb_domain != NULL) {
				domain_name = wb_domain->name;
				D_DEBUG("Found domain '%s' in list of known domains.\n", domain_name);
			}
		}
		if (domain_name == NULL) {
			domain_name = "";
			D_DEBUG("Not found domain in list of known domains, setting empty domain name.\n");
		}

		if (t->type_hint == ID_TYPE_NOT_SPECIFIED) {
			if (domain_name[0] != '\0') {
				/*
				 * We know the domain, we indicate this
				 * by passing ID_TYPE_BOTH as a hint
				 *
				 * Maybe that's already enough for the backend
				 */
				t->type_hint = ID_TYPE_BOTH;
				D_DEBUG("Setting type hint ID_TYPE_BOTH for domain '%s'.\n", domain_name);
			}
		}

		domain_index = init_lsa_ref_domain_list(state,
							&state->idmap_doms,
							domain_name,
							&domain_sid);
		if (domain_index == -1) {
			tevent_req_oom(req);
			return;
		}
		t->domain_index = domain_index;
	}

	/*
	 * We defer lookupsids because it requires domain controller
	 * interaction.
	 *
	 * First we ask the idmap child without explicit type hints.
	 * In most cases mappings already exist in the backend and
	 * a type_hint is not needed.
	 */
	wb_sids2xids_next_sids2unix(req);
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

static void wb_sids2xids_lookupsids_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_sids2xids_state *state = tevent_req_data(
		req, struct wb_sids2xids_state);
	struct lsa_RefDomainList *domains = NULL;
	struct lsa_TransNameArray *names = NULL;
	NTSTATUS status;
	uint32_t li;

	status = wb_lookupsids_recv(subreq, state, &domains, &names);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		D_WARNING("Failed with %s.\n", nt_errstr(status));
		return;
	}

	if (domains == NULL) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		D_WARNING("Failed with NT_STATUS_INTERNAL_ERROR.\n");
		return;
	}

	if (names == NULL) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		D_WARNING("Failed with NT_STATUS_INTERNAL_ERROR.\n");
		return;
	}

	for (li = 0; li < state->lookup_count; li++) {
		struct lsa_TranslatedName *n = &names->names[li];
		uint32_t ai = state->tmp_idx[li];
		struct wbint_TransID *t = &state->all_ids.ids[ai];
		enum id_type type_hint;

		type_hint = lsa_SidType_to_id_type(n->sid_type);
		if (type_hint != ID_TYPE_NOT_SPECIFIED) {
			/*
			 * We know it's a valid user or group.
			 */
			t->type_hint = type_hint;
			continue;
		}

		if (n->sid_index == UINT32_MAX) {
			/*
			 * The domain is not known, there's
			 * no point to try mapping again.
			 * mark is done and add a negative cache
			 * entry.
			 */
			t->domain_index = UINT32_MAX; /* mark as valid */
			idmap_cache_set_sid2unixid(&state->sids[ai], &t->xid);
			continue;
		}

		if (n->sid_index >= domains->count) {
			tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
			D_WARNING("Failed with NT_STATUS_INTERNAL_ERROR.\n");
			return;
		}

		if (domains->domains[n->sid_index].name.string == NULL) {
			tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
			D_WARNING("Failed with NT_STATUS_INTERNAL_ERROR.\n");
			return;
		}
		if (domains->domains[n->sid_index].sid == NULL) {
			tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
			D_WARNING("Failed with NT_STATUS_INTERNAL_ERROR.\n");
			return;
		}

		if (t->type_hint != ID_TYPE_NOT_SPECIFIED) {
			/*
			 * We already tried with a type hint there's
			 * no point to try mapping again with ID_TYPE_BOTH.
			 *
			 * Mark is done and add a negative cache entry.
			 */
			t->domain_index = UINT32_MAX; /* mark as valid */
			idmap_cache_set_sid2unixid(&state->sids[ai], &t->xid);
			continue;
		}

		/*
		 * We only know the domain exists, but the user doesn't
		 */
		t->type_hint = ID_TYPE_BOTH;
	}

	TALLOC_FREE(names);
	TALLOC_FREE(domains);

	/*
	 * Now that we have type_hints for the remaining sids,
	 * we need to restart with the first domain.
	 */
	state->dom_index = 0;
	wb_sids2xids_next_sids2unix(req);
}

static void wb_sids2xids_next_sids2unix(struct tevent_req *req)
{
	struct wb_sids2xids_state *state = tevent_req_data(
		req, struct wb_sids2xids_state);
	struct tevent_req *subreq = NULL;
	struct dcerpc_binding_handle *child_binding_handle = NULL;
	const struct wbint_TransIDArray *src = NULL;
	struct wbint_TransIDArray *dst = NULL;
	uint32_t si;

 next_domain:
	state->tried_dclookup = false;

	D_DEBUG("Processing next domain (dom_index=%"PRIu32", idmap_doms.count=%"PRIu32", lookup_count=%"PRIu32").\n",
		state->dom_index,
		state->idmap_doms.count,
		state->lookup_count);
	if (state->dom_index == state->idmap_doms.count) {
		if (state->lookup_count != 0) {
			/*
			 * We already called wb_lookupsids_send()
			 * before, so we're done.
			 */
			D_DEBUG("We already called wb_lookupsids_send() before, so we're done.\n");
			tevent_req_done(req);
			return;
		}

		for (si=0; si < state->num_sids; si++) {
			struct wbint_TransID *t = &state->all_ids.ids[si];

			if (t->domain_index == UINT32_MAX) {
				/* ignore already filled entries */
				continue;
			}

			state->tmp_idx[state->lookup_count] = si;
			sid_copy(&state->lookup_sids[state->lookup_count],
				 &state->sids[si]);
			state->lookup_count += 1;
		}

		D_DEBUG("Prepared %"PRIu32" SID(s) for lookup wb_lookupsids_send().\n",
			state->lookup_count);
		if (state->lookup_count == 0) {
			/*
			 * no wb_lookupsids_send() needed...
			 */
			tevent_req_done(req);
			return;
		}

		subreq = wb_lookupsids_send(state,
					    state->ev,
					    state->lookup_sids,
					    state->lookup_count);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, wb_sids2xids_lookupsids_done, req);
		return;
	}

	src = &state->all_ids;
	dst = &state->map_ids_in;
	dst->num_ids = 0;

	for (si=0; si < src->num_ids; si++) {
		if (src->ids[si].domain_index != state->dom_index) {
			continue;
		}

		state->tmp_idx[dst->num_ids] = si;
		dst->ids[dst->num_ids] = src->ids[si];
		dst->ids[dst->num_ids].domain_index = 0;
		dst->num_ids += 1;
	}

	if (dst->num_ids == 0) {
		state->dom_index += 1;
		D_DEBUG("Go to next domain.\n");
		goto next_domain;
	}

	state->idmap_dom = (struct lsa_RefDomainList) {
		.count = 1,
		.domains = &state->idmap_doms.domains[state->dom_index],
		.max_size = 1
	};

	/*
	 * dcerpc_wbint_Sids2UnixIDs_send/recv will
	 * allocate a new array for the response
	 * and overwrite _ids->ids pointer.
	 *
	 * So we better make a temporary copy
	 * of state->map_ids_in (which contains the request array)
	 * into state->map_ids_out.
	 *
	 * That makes it possible to reuse the pre-allocated
	 * state->map_ids_in.ids array.
	 */
	state->map_ids_out = state->map_ids_in;
	child_binding_handle = idmap_child_handle();
	subreq = dcerpc_wbint_Sids2UnixIDs_send(
		state, state->ev, child_binding_handle, &state->idmap_dom,
		&state->map_ids_out);
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
	const struct wbint_TransIDArray *src = NULL;
	struct wbint_TransIDArray *dst = NULL;
	uint32_t dsgetdcname_flags = DS_RETURN_DNS_NAME;
	uint32_t si;

	status = dcerpc_wbint_Sids2UnixIDs_recv(subreq, state, &result);
	TALLOC_FREE(subreq);

	if (tevent_req_nterror(req, status)) {
		D_WARNING("Failed with %s.\n", nt_errstr(status));
		return;
	}

	if (NT_STATUS_EQUAL(result, NT_STATUS_HOST_UNREACHABLE)) {
		struct lsa_DomainInfo *d =
			&state->idmap_doms.domains[state->dom_index];
		winbind_idmap_add_failed_connection_entry(d->name.string);
		/* Trigger DC lookup and reconnect below */
		result = NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
		dsgetdcname_flags |= DS_FORCE_REDISCOVERY;
	}

	if (NT_STATUS_EQUAL(result, NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND) &&
	    !state->tried_dclookup) {

		struct lsa_DomainInfo *d;
		const char *domain_name = NULL;

		d = &state->idmap_doms.domains[state->dom_index];

		domain_name = find_dns_domain_name(d->name.string);

		D_DEBUG("Domain controller not found. Calling "
			"wb_dsgetdcname_send(%s) to get it.\n",
			domain_name);

		subreq = wb_dsgetdcname_send(state,
					     state->ev,
					     domain_name,
					     NULL,
					     NULL,
					     dsgetdcname_flags);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, wb_sids2xids_gotdc, req);
		return;
	}

	src = &state->map_ids_out;
	dst = &state->all_ids;

	if (any_nt_status_not_ok(status, result, &status)) {
		D_DEBUG("Either status %s or result %s is not ok. Report SIDs as not mapped.\n",
			nt_errstr(status),
			nt_errstr(result));
		/*
		 * All we can do here is to report "not mapped"
		 */
		src = &state->map_ids_in;
		for (si=0; si < src->num_ids; si++) {
			src->ids[si].xid.type = ID_TYPE_NOT_SPECIFIED;
		}
	}

	if (src->num_ids != state->map_ids_in.num_ids) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		D_WARNING("Number of mapped SIDs does not match. Failing with NT_STATUS_INTERNAL_ERROR.\n");
		return;
	}

	for (si=0; si < src->num_ids; si++) {
		uint32_t di = state->tmp_idx[si];

		if (src->ids[si].xid.type == ID_TYPE_WB_REQUIRE_TYPE) {
			if (state->lookup_count == 0) {
				D_DEBUG("The backend asks for more information (a type_hint), we'll do a lookupsids later.\n");
				/*
				 * The backend asks for more information
				 * (a type_hint), we'll do a lookupsids
				 * later.
				 */
				continue;
			}

			/*
			 * lookupsids was not able to provide a type_hint that
			 * satisfied the backend.
			 *
			 * Make sure we don't expose ID_TYPE_WB_REQUIRE_TYPE
			 * outside of winbindd!
			 */
			D_DEBUG("lookupsids was not able to provide a type_hint that satisfied the backend. Make sure we don't expose ID_TYPE_WB_REQUIRE_TYPE outside of winbindd!\n");
			src->ids[si].xid.type = ID_TYPE_NOT_SPECIFIED;
		}

		if (src->ids[si].xid.type != ID_TYPE_NOT_SPECIFIED) {
			dst->ids[di].xid = src->ids[si].xid;
			D_DEBUG("%"PRIu32": Setting XID %"PRIu32"\n",
				si, src->ids[si].xid.id);
		}
		dst->ids[di].domain_index = UINT32_MAX; /* mark as valid */
		idmap_cache_set_sid2unixid(&state->sids[di], &dst->ids[di].xid);
	}

	state->map_ids_in.num_ids = 0;
	if (NT_STATUS_IS_OK(status)) {
		/*
		 * If we got a valid response, we expect
		 * state->map_ids_out.ids to be a new allocated
		 * array, which we want to free early.
		 */
		SMB_ASSERT(state->map_ids_out.ids != state->map_ids_in.ids);
		TALLOC_FREE(state->map_ids_out.ids);
	}
	state->map_ids_out = (struct wbint_TransIDArray) { .num_ids = 0, };

	state->dom_index += 1;

	wb_sids2xids_next_sids2unix(req);
}

static void wb_sids2xids_gotdc(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_sids2xids_state *state = tevent_req_data(
		req, struct wb_sids2xids_state);
	struct dcerpc_binding_handle *child_binding_handle = NULL;
	struct netr_DsRGetDCNameInfo *dcinfo;
	NTSTATUS status;

	status = wb_dsgetdcname_recv(subreq, state, &dcinfo);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		D_WARNING("Failed with %s.\n", nt_errstr(status));
		return;
	}

	state->tried_dclookup = true;

	{
		struct lsa_DomainInfo *d =
			&state->idmap_doms.domains[state->dom_index];
		const char *dom_name = d->name.string;

		status = wb_dsgetdcname_gencache_set(dom_name, dcinfo);
		if (tevent_req_nterror(req, status)) {
			D_WARNING("Failed with %s.\n", nt_errstr(status));
			return;
		}
	}

	/*
	 * dcerpc_wbint_Sids2UnixIDs_send/recv will
	 * allocate a new array for the response
	 * and overwrite _ids->ids pointer.
	 *
	 * So we better make a temporary copy
	 * of state->map_ids_in (which contains the request array)
	 * into state->map_ids_out.
	 *
	 * That makes it possible to reuse the pre-allocated
	 * state->map_ids_in.ids array.
	 */
	state->map_ids_out = state->map_ids_in;
	child_binding_handle = idmap_child_handle();
	subreq = dcerpc_wbint_Sids2UnixIDs_send(
		state, state->ev, child_binding_handle, &state->idmap_dom,
		&state->map_ids_out);
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
	uint32_t i;

	if (tevent_req_is_nterror(req, &status)) {
		D_WARNING("Failed with %s.\n", nt_errstr(status));
		return status;
	}

	if (num_xids != state->num_sids) {
		D_WARNING("Error. We have resolved only %"PRIu32" XID(s), but caller asked for %"PRIu32".\n",
			  state->num_sids, num_xids);
		return NT_STATUS_INTERNAL_ERROR;
	}

	D_INFO("WB command sids2xids end.\n");
	for (i=0; i<state->num_sids; i++) {
		struct dom_sid_buf buf;
		xids[i] = state->all_ids.ids[i].xid;
		D_INFO("%"PRIu32": Found XID %"PRIu32" for SID %s\n",
		       i,
		       xids[i].id,
		       dom_sid_str_buf(&state->sids[i], &buf));
	}

	return NT_STATUS_OK;
}
