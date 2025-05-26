/*
   Unix SMB/CIFS implementation.
   async next_grent
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
#include "passdb/machine_sid.h"

struct wb_next_grent_state {
	struct tevent_context *ev;
	int max_nesting;
	struct getgrent_state *gstate;
	struct winbindd_gr *gr;
	const char *domname;
	const char *name;
	const char *mapped_name;
	gid_t gid;
	struct db_context *members;
};

static void wb_next_grent_fetch_done(struct tevent_req *subreq);
static void wb_next_grent_getgrsid_done(struct tevent_req *subreq);

static void wb_next_grent_send_do(struct tevent_req *req,
				  struct wb_next_grent_state *state)
{
	struct tevent_req *subreq;
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

	if (state->gstate->next_group >= state->gstate->num_groups) {
		TALLOC_FREE(state->gstate->groups);

		domain = wb_next_domain(domain);
		winbindd_domain_ref_set(&state->gstate->domain, domain);
		if (domain == NULL) {
			tevent_req_nterror(req, NT_STATUS_NO_MORE_ENTRIES);
			return;
		}

		subreq = wb_query_group_list_send(state, state->ev,
						  domain);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, wb_next_grent_fetch_done, req);
		return;
	}

	subreq = wb_getgrsid_send(
		state, state->ev,
		&state->gstate->groups[state->gstate->next_group].sid,
		state->max_nesting);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_next_grent_getgrsid_done, req);
}

struct tevent_req *wb_next_grent_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      int max_nesting,
				      struct getgrent_state *gstate,
				      struct winbindd_gr *gr)
{
	struct tevent_req *req;
	struct wb_next_grent_state *state;

	req = tevent_req_create(mem_ctx, &state, struct wb_next_grent_state);
	if (req == NULL) {
		return NULL;
	}

	D_INFO("WB command next_grent start.\n");

	state->ev = ev;
	state->gstate = gstate;
	state->gr = gr;
	state->max_nesting = max_nesting;

	wb_next_grent_send_do(req, state);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void wb_next_grent_fetch_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_next_grent_state *state = tevent_req_data(
		req, struct wb_next_grent_state);
	NTSTATUS status;

	status = wb_query_group_list_recv(subreq, state->gstate,
					  &state->gstate->num_groups,
					  &state->gstate->groups);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
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
		D_DEBUG("query_group_list for domain %s returned %s\n",
			domain->name, nt_errstr(status));
		state->gstate->num_groups = 0;
	}

	state->gstate->next_group = 0;

	wb_next_grent_send_do(req, state);
}

static void wb_next_grent_normalize_done(struct tevent_req *subreq);
static void wb_next_grent_getgrsid_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_next_grent_state *state = tevent_req_data(
		req, struct wb_next_grent_state);
	NTSTATUS status;

	status = wb_getgrsid_recv(subreq,
				  state,
				  &state->domname,
				  &state->name,
				  &state->gid,
				  &state->members);
	TALLOC_FREE(subreq);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
		state->gstate->next_group += 1;

		wb_next_grent_send_do(req, state);

		return;
	} else if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = dcerpc_wbint_NormalizeNameMap_send(state,
						    state->ev,
						    idmap_child_handle(),
						    state->domname,
						    state->name,
						    &state->mapped_name);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_next_grent_normalize_done, req);
}

static void wb_next_grent_normalize_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_next_grent_state *state = tevent_req_data(
		req, struct wb_next_grent_state);
	struct winbindd_gr *gr = state->gr;
	const char *full_group_name = NULL;
	NTSTATUS status;
	NTSTATUS result;

	status = dcerpc_wbint_NormalizeNameMap_recv(subreq, state, &result);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		DBG_ERR("wbint_NormalizeNameMap(%s, %s) call failed: %s\n",
			state->domname,
			state->name,
			nt_errstr(status));
		return;
	} else if (NT_STATUS_IS_OK(result)) {
		full_group_name = fill_domain_username_talloc(
			state, state->domname, state->mapped_name, true);

	} else if (NT_STATUS_EQUAL(result, NT_STATUS_FILE_RENAMED)) {
		full_group_name = state->mapped_name;
	} else {
		full_group_name = fill_domain_username_talloc(state,
							      state->domname,
							      state->name,
							      True);
	}

	if (tevent_req_nomem(full_group_name, req)) {
		D_WARNING("Failed to fill full group name.\n");
		return;
	}

	gr->gr_gid = state->gid;

	strlcpy(gr->gr_name, full_group_name, sizeof(gr->gr_name));
	strlcpy(gr->gr_passwd, "x", sizeof(gr->gr_passwd));

	D_DEBUG("Full group name is '%s'.\n", gr->gr_name);

	state->gstate->next_group += 1;
	tevent_req_done(req);
}

NTSTATUS wb_next_grent_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			    struct db_context **members)
{
	struct wb_next_grent_state *state = tevent_req_data(
		req, struct wb_next_grent_state);
	NTSTATUS status;

	D_INFO("WB command next_grent end.\n");
	if (tevent_req_is_nterror(req, &status)) {
		D_WARNING("Failed with %s.\n", nt_errstr(status));
		return status;
	}
	*members = talloc_move(mem_ctx, &state->members);
	return NT_STATUS_OK;
}
