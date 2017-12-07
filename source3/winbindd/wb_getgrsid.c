/*
   Unix SMB/CIFS implementation.
   async getgrsid
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
#include "lib/dbwrap/dbwrap_rbt.h"

struct wb_getgrsid_state {
	struct tevent_context *ev;
	struct dom_sid sid;
	int max_nesting;
	const char *domname;
	const char *name;
	enum lsa_SidType type;
	gid_t gid;
	struct db_context *members;
};

static void wb_getgrsid_lookupsid_done(struct tevent_req *subreq);
static void wb_getgrsid_sid2gid_done(struct tevent_req *subreq);
static void wb_getgrsid_got_members(struct tevent_req *subreq);

struct tevent_req *wb_getgrsid_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    const struct dom_sid *group_sid,
				    int max_nesting)
{
	struct tevent_req *req, *subreq;
	struct wb_getgrsid_state *state;

	req = tevent_req_create(mem_ctx, &state, struct wb_getgrsid_state);
	if (req == NULL) {
		return NULL;
	}
	sid_copy(&state->sid, group_sid);
	state->ev = ev;
	state->max_nesting = max_nesting;

	if (dom_sid_in_domain(&global_sid_Unix_Groups, group_sid)) {
		/* unmapped Unix groups must be resolved locally */
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	subreq = wb_lookupsid_send(state, ev, &state->sid);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wb_getgrsid_lookupsid_done, req);
	return req;
}

static void wb_getgrsid_lookupsid_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_getgrsid_state *state = tevent_req_data(
		req, struct wb_getgrsid_state);
	NTSTATUS status;

	status = wb_lookupsid_recv(subreq, state, &state->type,
				   &state->domname, &state->name);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	switch (state->type) {
	case SID_NAME_DOM_GRP:
	case SID_NAME_ALIAS:
	case SID_NAME_WKN_GRP:
	/*
	 * also treat user-type SIDS (they might map to ID_TYPE_BOTH)
	 */
	case SID_NAME_USER:
	case SID_NAME_COMPUTER:
		break;
	default:
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_GROUP);
		return;
	}

	subreq = wb_sids2xids_send(state, state->ev, &state->sid, 1);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_getgrsid_sid2gid_done, req);
}

static void wb_getgrsid_sid2gid_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_getgrsid_state *state = tevent_req_data(
		req, struct wb_getgrsid_state);
	NTSTATUS status;
	struct unixid xids[1];

	status = wb_sids2xids_recv(subreq, xids, ARRAY_SIZE(xids));
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	/*
	 * We are filtering further down in sids2xids, but that filtering
	 * depends on the actual type of the sid handed in (as determined
	 * by lookupsids). Here we need to filter for the type of object
	 * actually requested, in this case uid.
	 */
	if (!(xids[0].type == ID_TYPE_GID || xids[0].type == ID_TYPE_BOTH)) {
		tevent_req_nterror(req, NT_STATUS_NONE_MAPPED);
		return;
	}

	state->gid = (gid_t)xids[0].id;

	if (state->type == SID_NAME_USER || state->type == SID_NAME_COMPUTER) {
		/*
		 * special treatment for a user sid that is
		 * mapped to ID_TYPE_BOTH:
		 * create a group with the sid/xid as only member
		 */
		const char *name;

		if (xids[0].type != ID_TYPE_BOTH) {
			tevent_req_nterror(req, NT_STATUS_NO_SUCH_GROUP);
			return;
		}

		state->members = db_open_rbt(state);
		if (tevent_req_nomem(state->members, req)) {
			return;
		}

		name = fill_domain_username_talloc(talloc_tos(),
						   state->domname,
						   state->name,
						   true /* can_assume */);
		if (tevent_req_nomem(name, req)) {
			return;
		}

		status = add_member_to_db(state->members, &state->sid, name);
		if (!NT_STATUS_IS_OK(status)) {
			tevent_req_nterror(req, status);
			return;
		}

		tevent_req_done(req);
		return;
	}

	/*
	 * the "regular" case of a group type sid.
	 */

	subreq = wb_group_members_send(state, state->ev, &state->sid,
				       state->type, state->max_nesting);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_getgrsid_got_members, req);
}

static void wb_getgrsid_got_members(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_getgrsid_state *state = tevent_req_data(
		req, struct wb_getgrsid_state);
	NTSTATUS status;

	status = wb_group_members_recv(subreq, state, &state->members);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS wb_getgrsid_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			  const char **domname, const char **name, gid_t *gid,
			  struct db_context **members)
{
	struct wb_getgrsid_state *state = tevent_req_data(
		req, struct wb_getgrsid_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*domname = talloc_move(mem_ctx, &state->domname);
	*name = talloc_move(mem_ctx, &state->name);
	*gid = state->gid;
	*members = talloc_move(mem_ctx, &state->members);
	return NT_STATUS_OK;
}
