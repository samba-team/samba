/*
   Unix SMB/CIFS implementation.
   async query_user_list
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
#include "lib/util/strv.h"

struct wb_query_user_list_state {
	struct tevent_context *ev;
	struct winbindd_domain *domain;
	struct wbint_RidArray rids;
	const char *domain_name;
	struct wbint_Principals names;
	char *users;
};

static void wb_query_user_list_gotrids(struct tevent_req *subreq);
static void wb_query_user_list_done(struct tevent_req *subreq);

struct tevent_req *wb_query_user_list_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct winbindd_domain *domain)
{
	struct tevent_req *req, *subreq;
	struct wb_query_user_list_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct wb_query_user_list_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->domain = domain;

	subreq = dcerpc_wbint_QueryUserRidList_send(
		state, ev, dom_child_handle(domain), &state->rids);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wb_query_user_list_gotrids, req);
	return req;
}

static void wb_query_user_list_gotrids(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_query_user_list_state *state = tevent_req_data(
		req, struct wb_query_user_list_state);
	NTSTATUS status, result;

	status = dcerpc_wbint_QueryUserRidList_recv(subreq, state, &result);
	TALLOC_FREE(subreq);
	if (any_nt_status_not_ok(status, result, &status)) {
		tevent_req_nterror(req, status);
		return;
	}

	DEBUG(10, ("dcerpc_wbint_QueryUserList returned %d users\n",
		   state->rids.num_rids));

	subreq = dcerpc_wbint_LookupRids_send(
		state, state->ev, dom_child_handle(state->domain),
		&state->domain->sid, &state->rids,
		&state->domain_name, &state->names);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_query_user_list_done, req);
}

static void wb_query_user_list_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_query_user_list_state *state = tevent_req_data(
		req, struct wb_query_user_list_state);
	NTSTATUS status, result;
	uint32_t i;

	status = dcerpc_wbint_LookupRids_recv(subreq, state, &result);
	TALLOC_FREE(subreq);
	if (any_nt_status_not_ok(status, result, &status)) {
		tevent_req_nterror(req, status);
		return;
	}

	for (i=0; i<state->names.num_principals; i++) {
		struct wbint_Principal *p = &state->names.principals[i];
		const char *name;
		int ret;

		name = fill_domain_username_talloc(state, state->domain_name, p->name, true);
		if (name == NULL) {
			tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
			return;
		}
		ret = strv_add(state, &state->users, name);
		if (ret != 0) {
			tevent_req_nterror(req, map_nt_error_from_unix(ret));
			return;
		}
	}

	tevent_req_done(req);
}

NTSTATUS wb_query_user_list_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				 char **users)
{
	struct wb_query_user_list_state *state = tevent_req_data(
		req, struct wb_query_user_list_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	*users = talloc_move(mem_ctx, &state->users);

	return NT_STATUS_OK;
}
