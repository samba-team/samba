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
#include "lib/dbwrap/dbwrap.h"

struct wb_getgrsid_state {
	struct tevent_context *ev;
	struct dom_sid sid;
	int max_nesting;
	const char *domname;
	const char *name;
	enum lsa_SidType type;
	gid_t gid;
	struct db_context *members;
	uint32_t num_sids;
	struct dom_sid *sids;
};

static void wb_getgrsid_lookupsid_done(struct tevent_req *subreq);
static void wb_getgrsid_sid2gid_done(struct tevent_req *subreq);
static void wb_getgrsid_got_members(struct tevent_req *subreq);
static void wb_getgrsid_got_alias_members(struct tevent_req *subreq);

struct tevent_req *wb_getgrsid_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    const struct dom_sid *group_sid,
				    int max_nesting)
{
	struct tevent_req *req, *subreq;
	struct wb_getgrsid_state *state;
	struct dom_sid_buf buf;

	req = tevent_req_create(mem_ctx, &state, struct wb_getgrsid_state);
	if (req == NULL) {
		return NULL;
	}

	D_INFO("WB command getgrsid start.\nLooking up group SID %s.\n", dom_sid_str_buf(group_sid, &buf));

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

	switch (state->type) {
	case SID_NAME_USER:
	case SID_NAME_COMPUTER: {
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
	case SID_NAME_ALIAS:
		subreq = wb_alias_members_send(state,
					       state->ev,
					       &state->sid,
					       state->type,
					       state->max_nesting);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		/* Decrement the depth based on 'winbind expand groups' */
		state->max_nesting--;
		tevent_req_set_callback(subreq,
					wb_getgrsid_got_alias_members,
					req);
		break;
	case SID_NAME_DOM_GRP:
		subreq = wb_group_members_send(state,
					       state->ev,
					       &state->sid,
					       1,
					       &state->type,
					       state->max_nesting);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, wb_getgrsid_got_members, req);
		break;
	case SID_NAME_WKN_GRP:
		state->members = db_open_rbt(state);
		if (tevent_req_nomem(state->members, req)) {
			return;
		}
		tevent_req_done(req);
		return;
	default:
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_GROUP);
		break;
	}
}

static void wb_getgrsid_got_alias_members_names(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq, struct tevent_req);
	struct wb_getgrsid_state *state =
		tevent_req_data(req, struct wb_getgrsid_state);
	struct lsa_RefDomainList *domains = NULL;
	struct lsa_TransNameArray *names = NULL;
	NTSTATUS status;
	uint32_t li;
	uint32_t num_sids = 0;
	struct dom_sid *sids = NULL;
	enum lsa_SidType *types = NULL;

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

	state->members = db_open_rbt(state);
	if (tevent_req_nomem(state->members, req)) {
		return;
	}

	for (li = 0; li < state->num_sids; li++) {
		struct lsa_TranslatedName *n = &names->names[li];

		if (n->sid_type == SID_NAME_USER ||
		    n->sid_type == SID_NAME_COMPUTER) {
			const char *name = fill_domain_username_talloc(
				talloc_tos(),
				domains->domains[n->sid_index].name.string,
				n->name.string,
				false /* can_assume */);
			if (tevent_req_nomem(name, req)) {
				return;
			}

			status = add_member_to_db(state->members,
						  &state->sids[li],
						  name);
			if (!NT_STATUS_IS_OK(status)) {
				tevent_req_nterror(req, status);
				return;
			}
		} else if (n->sid_type == SID_NAME_DOM_GRP) {
			sids = talloc_realloc(talloc_tos(),
					      sids,
					      struct dom_sid,
					      num_sids + 1);
			if (tevent_req_nomem(sids, req)) {
				return;
			}
			sids[num_sids] = state->sids[li];
			types = talloc_realloc(talloc_tos(),
					       types,
					       enum lsa_SidType,
					       num_sids + 1);
			if (tevent_req_nomem(types, req)) {
				return;
			}
			types[num_sids] = n->sid_type;
			num_sids++;
		} else {
			struct dom_sid_buf buf;
			D_DEBUG("SID %s with sid_type=%d is ignored!\n",
				dom_sid_str_buf(&state->sids[li], &buf),
				n->sid_type);
		}
	}

	TALLOC_FREE(names);
	TALLOC_FREE(domains);

	if (num_sids == 0) {
		tevent_req_done(req);
		return;
	}
	subreq = wb_group_members_send(state,
				       state->ev,
				       sids,
				       num_sids,
				       types,
				       state->max_nesting);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_getgrsid_got_members, req);
}

static void wb_getgrsid_got_alias_members(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq, struct tevent_req);
	struct wb_getgrsid_state *state =
		tevent_req_data(req, struct wb_getgrsid_state);
	NTSTATUS status;

	status = wb_alias_members_recv(subreq,
				       state,
				       &state->num_sids,
				       &state->sids);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = wb_lookupsids_send(state,
				    state->ev,
				    state->sids,
				    state->num_sids);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				wb_getgrsid_got_alias_members_names,
				req);
}

static void wb_getgrsid_got_members(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_getgrsid_state *state = tevent_req_data(
		req, struct wb_getgrsid_state);
	NTSTATUS status;
	struct db_context *members_prev = state->members;

	status = wb_group_members_recv(subreq, state, &state->members);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	/*
	 * If we have called wb_alias_members_send(), members_prev
	 * might already contain users that are direct members of alias,
	 * add to them the users from nested groups.
	 */
	if (members_prev != NULL) {
		status = dbwrap_merge_dbs(state->members,
					  members_prev,
					  TDB_REPLACE);
		if (tevent_req_nterror(req, status)) {
			return;
		}
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

	D_INFO("WB command getgrsid end.\n");
	if (tevent_req_is_nterror(req, &status)) {
		D_WARNING("Failed with %s.\n", nt_errstr(status));
		return status;
	}
	*domname = talloc_move(mem_ctx, &state->domname);
	*name = talloc_move(mem_ctx, &state->name);
	*gid = state->gid;
	*members = talloc_move(mem_ctx, &state->members);
	return NT_STATUS_OK;
}
