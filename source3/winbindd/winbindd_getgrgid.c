/*
   Unix SMB/CIFS implementation.
   async implementation of WINBINDD_GETGRGID
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
#include "libcli/security/dom_sid.h"

struct winbindd_getgrgid_state {
	struct tevent_context *ev;
	struct unixid xid;
	struct dom_sid *sid;
	const char *domname;
	const char *name;
	gid_t gid;
	struct db_context *members;
};

static void winbindd_getgrgid_gid2sid_done(struct tevent_req *subreq);
static void winbindd_getgrgid_done(struct tevent_req *subreq);

struct tevent_req *winbindd_getgrgid_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct winbindd_cli_state *cli,
					  struct winbindd_request *request)
{
	struct tevent_req *req, *subreq;
	struct winbindd_getgrgid_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct winbindd_getgrgid_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;

	DBG_NOTICE("[%s (%u)] getgrgid %d\n",
		   cli->client_name,
		   (unsigned int)cli->pid,
		   (int)request->data.gid);

	state->xid = (struct unixid) {
		.id = request->data.uid, .type = ID_TYPE_GID };

	subreq = wb_xids2sids_send(state, ev, &state->xid, 1);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, winbindd_getgrgid_gid2sid_done,
				req);
	return req;
}

static void winbindd_getgrgid_gid2sid_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winbindd_getgrgid_state *state = tevent_req_data(
		req, struct winbindd_getgrgid_state);
	NTSTATUS status;

	status = wb_xids2sids_recv(subreq, state, &state->sid);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	if (is_null_sid(state->sid)) {
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_GROUP);
		return;
	}

	subreq = wb_getgrsid_send(state, state->ev, state->sid,
				  lp_winbind_expand_groups());
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, winbindd_getgrgid_done, req);
}

static void winbindd_getgrgid_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winbindd_getgrgid_state *state = tevent_req_data(
		req, struct winbindd_getgrgid_state);
	NTSTATUS status;

	status = wb_getgrsid_recv(subreq, state, &state->domname, &state->name,
				  &state->gid, &state->members);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS winbindd_getgrgid_recv(struct tevent_req *req,
				struct winbindd_response *response)
{
	struct winbindd_getgrgid_state *state = tevent_req_data(
		req, struct winbindd_getgrgid_state);
	NTSTATUS status;
	int num_members;
	char *buf;

	if (tevent_req_is_nterror(req, &status)) {
		struct dom_sid_buf sidbuf;
		DEBUG(5, ("Could not convert sid %s: %s\n",
			  dom_sid_str_buf(state->sid, &sidbuf),
			  nt_errstr(status)));
		return status;
	}

	if (!fill_grent(talloc_tos(), &response->data.gr, state->domname,
			state->name, state->gid)) {
		DEBUG(5, ("fill_grent failed\n"));
		return NT_STATUS_NO_MEMORY;
	}

	status = winbindd_print_groupmembers(state->members, response,
					     &num_members, &buf);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	response->data.gr.num_gr_mem = (uint32_t)num_members;

	/* Group membership lives at start of extra data */

	response->data.gr.gr_mem_ofs = 0;
	response->extra_data.data = buf;
	response->length += talloc_get_size(response->extra_data.data);

	return NT_STATUS_OK;
}
