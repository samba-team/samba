/*
   Unix SMB/CIFS implementation.
   async next_pwent
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
#include "libcli/security/dom_sid.h"
#include "passdb/machine_sid.h"

struct wb_next_pwent_state {
	struct tevent_context *ev;
	struct getpwent_state *gstate;
	struct dom_sid next_sid;
	struct winbindd_pw *pw;
};

static void wb_next_pwent_fetch_done(struct tevent_req *subreq);
static void wb_next_pwent_fill_done(struct tevent_req *subreq);

static void wb_next_pwent_send_do(struct tevent_req *req,
				  struct wb_next_pwent_state *state)
{
	struct tevent_req *subreq;
	struct dom_sid_buf buf, buf1;
	struct winbindd_domain *domain = NULL;
	bool valid;

	valid = winbindd_domain_ref_get(&state->gstate->domain,
					&domain);
	if (!valid) {
		/*
		 * winbindd_domain_ref_get() already generated
		 * a debug message for the stale domain!
		 */
		tevent_req_nterror(req, NT_STATUS_NO_MORE_ENTRIES);
		return;
	}

	if (state->gstate->next_user >= state->gstate->rids.num_rids) {

		TALLOC_FREE(state->gstate->rids.rids);
		state->gstate->rids.num_rids = 0;

		domain = wb_next_domain(domain);
		winbindd_domain_ref_set(&state->gstate->domain, domain);
		if (domain == NULL) {
			tevent_req_nterror(req, NT_STATUS_NO_MORE_ENTRIES);
			return;
		}

		D_DEBUG("Query user RID list for domain %s.\n",
			domain->name);
		subreq = dcerpc_wbint_QueryUserRidList_send(
			state, state->ev,
			dom_child_handle(domain),
			&state->gstate->rids);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}

		tevent_req_set_callback(subreq, wb_next_pwent_fetch_done, req);
		return;
	}

	sid_compose(&state->next_sid, &domain->sid,
		    state->gstate->rids.rids[state->gstate->next_user]);

	D_DEBUG("Get pw for SID %s composed from domain SID %s and RID %"PRIu32".\n",
		dom_sid_str_buf(&state->next_sid, &buf),
		dom_sid_str_buf(&domain->sid, &buf1),
		state->gstate->rids.rids[state->gstate->next_user]);
	subreq = wb_getpwsid_send(state, state->ev, &state->next_sid,
				  state->pw);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}

	tevent_req_set_callback(subreq, wb_next_pwent_fill_done, req);
}

struct tevent_req *wb_next_pwent_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct getpwent_state *gstate,
				      struct winbindd_pw *pw)
{
	struct tevent_req *req;
	struct wb_next_pwent_state *state;

	req = tevent_req_create(mem_ctx, &state, struct wb_next_pwent_state);
	if (req == NULL) {
		return NULL;
	}
	D_INFO("WB command next_pwent start.\n");
	state->ev = ev;
	state->gstate = gstate;
	state->pw = pw;

	wb_next_pwent_send_do(req, state);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void wb_next_pwent_fetch_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_next_pwent_state *state = tevent_req_data(
		req, struct wb_next_pwent_state);
	NTSTATUS status, result;

	status = dcerpc_wbint_QueryUserRidList_recv(subreq, state->gstate,
						    &result);
	TALLOC_FREE(subreq);
	if (any_nt_status_not_ok(status, result, &status)) {
		struct winbindd_domain *domain = NULL;
		bool valid;

		valid = winbindd_domain_ref_get(&state->gstate->domain,
						&domain);
		if (!valid) {
			/*
			 * winbindd_domain_ref_get() already generated
			 * a debug message for the stale domain!
			 */
			tevent_req_nterror(req, NT_STATUS_NO_MORE_ENTRIES);
			return;
		}

		/* Ignore errors here, just log it */
		D_DEBUG("query_user_list for domain %s returned %s\n",
			domain->name,
			nt_errstr(status));
		state->gstate->rids.num_rids = 0;
	}

	state->gstate->next_user = 0;

	wb_next_pwent_send_do(req, state);
}

static void wb_next_pwent_fill_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_next_pwent_state *state = tevent_req_data(
		req, struct wb_next_pwent_state);
	NTSTATUS status;

	status = wb_getpwsid_recv(subreq);
	TALLOC_FREE(subreq);
	/*
	 * When you try to enumerate users with 'getent passwd' and the user
	 * doesn't have a uid set we should just move on.
	 */
	if (NT_STATUS_EQUAL(status, NT_STATUS_NO_SUCH_USER)) {
		state->gstate->next_user += 1;

		wb_next_pwent_send_do(req, state);

		return;
	} else if (tevent_req_nterror(req, status)) {
		return;
	}
	state->gstate->next_user += 1;
	tevent_req_done(req);
}

NTSTATUS wb_next_pwent_recv(struct tevent_req *req)
{
	D_INFO("WB command next_pwent end.\n");
	return tevent_req_simple_recv_ntstatus(req);
}
