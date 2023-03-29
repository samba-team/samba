/*
   Unix SMB/CIFS implementation.
   async alias_members
   Copyright (C) Pavel Filipenský 2023

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

struct wb_alias_members_state {
	struct tevent_context *ev;
	struct dom_sid sid;
	struct wbint_SidArray sids;
};

static void wb_alias_members_done(struct tevent_req *subreq);

struct tevent_req *wb_alias_members_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 const struct dom_sid *sid,
					 enum lsa_SidType type,
					 int max_nesting)
{
	struct tevent_req *req, *subreq;
	struct wb_alias_members_state *state;
	struct winbindd_domain *domain;
	NTSTATUS status;
	struct dom_sid_buf buf;

	req = tevent_req_create(mem_ctx, &state, struct wb_alias_members_state);
	if (req == NULL) {
		return NULL;
	}
	D_INFO("WB command alias_members start.\nLooking up SID %s.\n",
	       dom_sid_str_buf(sid, &buf));

	if (max_nesting <= 0) {
		D_DEBUG("Finished. The depth based on 'winbind expand groups' is %d.\n", max_nesting);
		state->sids.num_sids = 0;
		state->sids.sids = NULL;
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	sid_copy(&state->sid, sid);

	status = lookup_usergroups_cached(state,
					  &state->sid,
					  &state->sids.num_sids,
					  &state->sids.sids);
	if (NT_STATUS_IS_OK(status)) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	domain = find_domain_from_sid_noinit(&state->sid);
	if (domain == NULL) {
		DBG_WARNING("could not find domain entry for sid %s\n",
			    dom_sid_str_buf(&state->sid, &buf));
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_ALIAS);
		return tevent_req_post(req, ev);
	}

	subreq = dcerpc_wbint_LookupAliasMembers_send(state,
						      ev,
						      dom_child_handle(domain),
						      &state->sid,
						      type,
						      &state->sids);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wb_alias_members_done, req);
	return req;
}

static void wb_alias_members_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq, struct tevent_req);
	struct wb_alias_members_state *state =
		tevent_req_data(req, struct wb_alias_members_state);
	NTSTATUS status, result;

	status = dcerpc_wbint_LookupAliasMembers_recv(subreq, state, &result);
	TALLOC_FREE(subreq);
	if (any_nt_status_not_ok(status, result, &status)) {
		D_WARNING("Failed with %s.\n", nt_errstr(status));
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

NTSTATUS wb_alias_members_recv(struct tevent_req *req,
			       TALLOC_CTX *mem_ctx,
			       uint32_t *num_sids,
			       struct dom_sid **sids)
{
	struct wb_alias_members_state *state =
		tevent_req_data(req, struct wb_alias_members_state);
	NTSTATUS status;
	uint32_t i;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*num_sids = state->sids.num_sids;
	*sids = talloc_move(mem_ctx, &state->sids.sids);

	D_INFO("WB command alias_members end.\nReceived %" PRIu32 " SID(s).\n",
	       *num_sids);
	if (CHECK_DEBUGLVL(DBGLVL_INFO)) {
		for (i = 0; i < *num_sids; i++) {
			struct dom_sid_buf buf;
			D_INFO("%" PRIu32 ": %s\n",
			       i,
			       dom_sid_str_buf(&(*sids)[i], &buf));
		}
	}
	return NT_STATUS_OK;
}
