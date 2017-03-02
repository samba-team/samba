/*
   Unix SMB/CIFS implementation.
   async gettoken
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
#include "../libcli/security/security.h"
#include "passdb/machine_sid.h"

struct wb_gettoken_state {
	struct tevent_context *ev;
	struct dom_sid usersid;
	bool expand_local_aliases;
	uint32_t num_sids;
	struct dom_sid *sids;
};

static NTSTATUS wb_add_rids_to_sids(TALLOC_CTX *mem_ctx,
				    uint32_t *pnum_sids,
				    struct dom_sid **psids,
				    const struct dom_sid *domain_sid,
				    int num_rids, uint32_t *rids);

static void wb_gettoken_gotuser(struct tevent_req *subreq);
static void wb_gettoken_gotgroups(struct tevent_req *subreq);
static void wb_gettoken_gotlocalgroups(struct tevent_req *subreq);
static void wb_gettoken_gotbuiltins(struct tevent_req *subreq);

struct tevent_req *wb_gettoken_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    const struct dom_sid *sid,
				    bool expand_local_aliases)
{
	struct tevent_req *req, *subreq;
	struct wb_gettoken_state *state;

	req = tevent_req_create(mem_ctx, &state, struct wb_gettoken_state);
	if (req == NULL) {
		return NULL;
	}
	sid_copy(&state->usersid, sid);
	state->ev = ev;
	state->expand_local_aliases = expand_local_aliases;

	subreq = wb_queryuser_send(state, ev, &state->usersid);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wb_gettoken_gotuser, req);
	return req;
}

static void wb_gettoken_gotuser(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_gettoken_state *state = tevent_req_data(
		req, struct wb_gettoken_state);
	struct wbint_userinfo *info;
	NTSTATUS status;

	status = wb_queryuser_recv(subreq, state, &info);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->sids = talloc_array(state, struct dom_sid, 2);
	if (tevent_req_nomem(state->sids, req)) {
		return;
	}
	state->num_sids = 2;

	sid_copy(&state->sids[0], &info->user_sid);
	sid_copy(&state->sids[1], &info->group_sid);

	subreq = wb_lookupusergroups_send(state, state->ev, &info->user_sid);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_gettoken_gotgroups, req);
}

static void wb_gettoken_gotgroups(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_gettoken_state *state = tevent_req_data(
		req, struct wb_gettoken_state);
	int i, num_groups;
	struct dom_sid *groups;
	struct winbindd_domain *domain;
	NTSTATUS status;

	status = wb_lookupusergroups_recv(subreq, state, &num_groups, &groups);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_done(req);
		return;
	}

	for (i=0; i<num_groups; i++) {
		status = add_sid_to_array_unique(
			state, &groups[i], &state->sids, &state->num_sids);

		if (tevent_req_nterror(req, status)) {
			return;
		}
	}

	if (!state->expand_local_aliases) {
		tevent_req_done(req);
		return;
	}

	/*
	 * Expand our domain's aliases
	 */
	domain = find_domain_from_sid_noinit(get_global_sam_sid());
	if (domain == NULL) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	subreq = wb_lookupuseraliases_send(state, state->ev, domain,
					   state->num_sids, state->sids);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_gettoken_gotlocalgroups, req);
}

static void wb_gettoken_gotlocalgroups(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_gettoken_state *state = tevent_req_data(
		req, struct wb_gettoken_state);
	uint32_t num_rids;
	uint32_t *rids;
	struct winbindd_domain *domain;
	NTSTATUS status;

	status = wb_lookupuseraliases_recv(subreq, state, &num_rids, &rids);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	status = wb_add_rids_to_sids(state, &state->num_sids, &state->sids,
				     get_global_sam_sid(), num_rids, rids);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	TALLOC_FREE(rids);

	/*
	 * Now expand the builtin groups
	 */

	domain = find_domain_from_sid(&global_sid_Builtin);
	if (domain == NULL) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	subreq = wb_lookupuseraliases_send(state, state->ev, domain,
					   state->num_sids, state->sids);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_gettoken_gotbuiltins, req);
}

static void wb_gettoken_gotbuiltins(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_gettoken_state *state = tevent_req_data(
		req, struct wb_gettoken_state);
	uint32_t num_rids;
        uint32_t *rids;
	NTSTATUS status;

	status = wb_lookupuseraliases_recv(subreq, state, &num_rids, &rids);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	status = wb_add_rids_to_sids(state, &state->num_sids, &state->sids,
				     &global_sid_Builtin, num_rids, rids);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS wb_gettoken_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			  int *num_sids, struct dom_sid **sids)
{
	struct wb_gettoken_state *state = tevent_req_data(
		req, struct wb_gettoken_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*num_sids = state->num_sids;
	*sids = talloc_move(mem_ctx, &state->sids);
	return NT_STATUS_OK;
}

static NTSTATUS wb_add_rids_to_sids(TALLOC_CTX *mem_ctx,
				    uint32_t *pnum_sids,
				    struct dom_sid **psids,
				    const struct dom_sid *domain_sid,
				    int num_rids, uint32_t *rids)
{
	int i;

	for (i=0; i<num_rids; i++) {
		NTSTATUS status;
		struct dom_sid sid;

		sid_compose(&sid, domain_sid, rids[i]);

		status = add_sid_to_array_unique(
			mem_ctx, &sid, psids, pnum_sids);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	return NT_STATUS_OK;
}
