/*
   Unix SMB/CIFS implementation.
   async getpwsid
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

struct wb_getpwsid_state {
	struct tevent_context *ev;
	struct dom_sid sid;
	struct wbint_userinfo *userinfo;
	struct winbindd_pw *pw;
};

static void wb_getpwsid_queryuser_done(struct tevent_req *subreq);
static void wb_getpwsid_lookupsid_done(struct tevent_req *subreq);
static void wb_getpwsid_done(struct tevent_req *subreq);

struct tevent_req *wb_getpwsid_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    const struct dom_sid *user_sid,
				    struct winbindd_pw *pw)
{
	struct tevent_req *req, *subreq;
	struct wb_getpwsid_state *state;

	req = tevent_req_create(mem_ctx, &state, struct wb_getpwsid_state);
	if (req == NULL) {
		return NULL;
	}
	sid_copy(&state->sid, user_sid);
	state->ev = ev;
	state->pw = pw;

	subreq = wb_queryuser_send(state, ev, &state->sid);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wb_getpwsid_queryuser_done, req);
	return req;
}

static void wb_getpwsid_queryuser_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_getpwsid_state *state = tevent_req_data(
		req, struct wb_getpwsid_state);
	NTSTATUS status;

	status = wb_queryuser_recv(subreq, state, &state->userinfo);
	TALLOC_FREE(subreq);
	if (NT_STATUS_IS_OK(status)
	    && (state->userinfo->acct_name != NULL)
	    && (state->userinfo->acct_name[0] != '\0'))
	{
		/*
		 * QueryUser got us a name, let's go directly to the
		 * fill_pwent step
		 */
		subreq = wb_fill_pwent_send(state, state->ev, state->userinfo,
					    state->pw);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, wb_getpwsid_done, req);
		return;
	}

	/*
	 * Either query_user did not succeed, or it
	 * succeeded but did not return an acct_name.
	 * (TODO: Can this happen at all???)
	 * ==> Try lsa_lookupsids.
	 */
	if (state->userinfo == NULL) {
		state->userinfo = talloc_zero(state, struct wbint_userinfo);
		if (tevent_req_nomem(state->userinfo, req)) {
			return;
		}

		/* a successful query_user call would have filled these */
		sid_copy(&state->userinfo->user_sid, &state->sid);
		state->userinfo->homedir = NULL;
		state->userinfo->shell = NULL;
		state->userinfo->primary_gid = (gid_t)-1;
	}

	subreq = wb_lookupsid_send(state, state->ev, &state->sid);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_getpwsid_lookupsid_done, req);
}

static void wb_getpwsid_lookupsid_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_getpwsid_state *state = tevent_req_data(
		req, struct wb_getpwsid_state);
	NTSTATUS status;
	enum lsa_SidType type;
	const char *domain;

	status = wb_lookupsid_recv(subreq, state->userinfo, &type, &domain,
				   &state->userinfo->acct_name);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	switch (type) {
	case SID_NAME_USER:
	case SID_NAME_COMPUTER:
		/*
		 * user case: we only need the account name from lookup_sids
		 */
		break;
	case SID_NAME_DOM_GRP:
	case SID_NAME_ALIAS:
	case SID_NAME_WKN_GRP:
		/*
		 * also treat group-type SIDs (they might map to ID_TYPE_BOTH)
		 */
		sid_copy(&state->userinfo->group_sid, &state->sid);
		break;
	default:
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_USER);
		return;
	}

	subreq = wb_fill_pwent_send(state, state->ev, state->userinfo,
				    state->pw);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_getpwsid_done, req);
}

static void wb_getpwsid_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = wb_fill_pwent_recv(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS wb_getpwsid_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}
