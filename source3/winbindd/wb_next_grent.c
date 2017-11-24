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
	struct db_context *members;
};

static void wb_next_grent_fetch_done(struct tevent_req *subreq);
static void wb_next_grent_getgrsid_done(struct tevent_req *subreq);

static void wb_next_grent_send_do(struct tevent_req *req,
				  struct wb_next_grent_state *state)
{
	struct tevent_req *subreq;

	if (state->gstate->next_group >= state->gstate->num_groups) {
		TALLOC_FREE(state->gstate->groups);

		state->gstate->domain = wb_next_domain(state->gstate->domain);
		if (state->gstate->domain == NULL) {
			tevent_req_nterror(req, NT_STATUS_NO_MORE_ENTRIES);
			return;
		}

		subreq = wb_query_group_list_send(state, state->ev,
						  state->gstate->domain);
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
		/* Ignore errors here, just log it */
		DEBUG(10, ("query_group_list for domain %s returned %s\n",
			   state->gstate->domain->name, nt_errstr(status)));
		state->gstate->num_groups = 0;
	}

	state->gstate->next_group = 0;

	wb_next_grent_send_do(req, state);
}

static void wb_next_grent_getgrsid_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_next_grent_state *state = tevent_req_data(
		req, struct wb_next_grent_state);
	const char *domname, *name;
	NTSTATUS status;

	status = wb_getgrsid_recv(subreq, talloc_tos(), &domname, &name,
				  &state->gr->gr_gid, &state->members);
	TALLOC_FREE(subreq);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
		state->gstate->next_group += 1;

		wb_next_grent_send_do(req, state);

		return;
	} else if (tevent_req_nterror(req, status)) {
		return;
	}

	if (!fill_grent(talloc_tos(), state->gr, domname, name,
			state->gr->gr_gid)) {
		DEBUG(5, ("fill_grent failed\n"));
		tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}
	state->gstate->next_group += 1;
	tevent_req_done(req);
}

NTSTATUS wb_next_grent_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			    struct db_context **members)
{
	struct wb_next_grent_state *state = tevent_req_data(
		req, struct wb_next_grent_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*members = talloc_move(mem_ctx, &state->members);
	return NT_STATUS_OK;
}
