/*
   Unix SMB/CIFS implementation.
   async implementation of WINBINDD_GETGRNAM
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
#include "lib/util/string_wrappers.h"
#include "librpc/gen_ndr/ndr_winbind_c.h"

struct winbindd_getgrnam_state {
	struct tevent_context *ev;
	const char *request_name;
	const char *unmapped_name;
	char *name_namespace;
	char *name_domain;
	char *name_group;
	struct dom_sid sid;
	const char *domname;
	const char *name;
	const char *mapped_name;
	const char *full_group_name;
	gid_t gid;
	struct db_context *members;
};

static void winbindd_getgrnam_unmap_done(struct tevent_req *subreq);
struct tevent_req *winbindd_getgrnam_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct winbindd_cli_state *cli,
					  struct winbindd_request *request)
{
	struct tevent_req *req, *subreq;
	struct winbindd_getgrnam_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct winbindd_getgrnam_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;

	/* Ensure null termination */
	request->data.groupname[sizeof(request->data.groupname)-1]='\0';

	D_NOTICE("[%s (%u)] Winbind external command GETGRNAM start.\n"
		   "Searching group name '%s'.\n",
		   cli->client_name,
		   (unsigned int)cli->pid,
		   request->data.groupname);

	state->request_name = talloc_strdup(state, request->data.groupname);
	if (tevent_req_nomem(state->request_name, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = dcerpc_wbint_NormalizeNameUnmap_send(state,
						      state->ev,
						      idmap_child_handle(),
						      state->request_name,
						      &state->unmapped_name);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, winbindd_getgrnam_unmap_done, req);
	return req;
}

static void winbindd_getgrnam_lookupname_done(struct tevent_req *subreq);
static void winbindd_getgrnam_unmap_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct winbindd_getgrnam_state *state = tevent_req_data(
		req, struct winbindd_getgrnam_state);
	NTSTATUS status;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	bool ok;

	status = dcerpc_wbint_NormalizeNameUnmap_recv(subreq, state, &result);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	/* If we didn't map anything in the above call, use the original string */
	if (!NT_STATUS_IS_OK(result) &&
	    !NT_STATUS_EQUAL(result, NT_STATUS_FILE_RENAMED))
	{
		state->unmapped_name = state->request_name;
	}

	/* Parse domain and groupname */

	ok = parse_domain_user(state,
			       state->unmapped_name,
			       &state->name_namespace,
			       &state->name_domain,
			       &state->name_group);
	if (!ok) {
		DBG_INFO("Could not parse domain user: %s\n",
			 state->unmapped_name);
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	/* if no domain or our local domain and no local tdb group, default to
	 * our local domain for aliases */

	if ( !*(state->name_domain) || strequal(state->name_domain,
						get_global_sam_name()) ) {
		TALLOC_FREE(state->name_domain);
		state->name_domain = talloc_strdup(state,
						get_global_sam_name());
		if (tevent_req_nomem(state->name_domain, req)) {
			return;
		}
	}

	subreq = wb_lookupname_send(state,
				    state->ev,
				    state->name_namespace,
				    state->name_domain,
				    state->name_group,
				    0);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, winbindd_getgrnam_lookupname_done, req);
}

static void winbindd_getgrnam_getgrsid_done(struct tevent_req *subreq);
static void winbindd_getgrnam_lookupname_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winbindd_getgrnam_state *state = tevent_req_data(
		req, struct winbindd_getgrnam_state);
	enum lsa_SidType type;
	NTSTATUS status;

	status = wb_lookupname_recv(subreq, &state->sid, &type);
	TALLOC_FREE(subreq);
	if (NT_STATUS_IS_OK(status) && type == SID_NAME_UNKNOWN) {
		status = NT_STATUS_NONE_MAPPED;
	}
	if (tevent_req_nterror(req, status)) {
		return;
	}

	switch (type) {
	case SID_NAME_DOM_GRP:
	case SID_NAME_ALIAS:
	case SID_NAME_WKN_GRP:
	/*
	 * Also give user types a chance:
	 * These might be user sids mapped to the ID_TYPE_BOTH,
	 * and in that case we should construct a group struct.
	 */
	case SID_NAME_USER:
	case SID_NAME_COMPUTER:
		break;
	default:
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_GROUP);
		return;
	}

	subreq = wb_getgrsid_send(state, state->ev, &state->sid,
				  lp_winbind_expand_groups());
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, winbindd_getgrnam_getgrsid_done, req);
}

static void winbindd_getgrnam_normalize_done(struct tevent_req *subreq);
static void winbindd_getgrnam_getgrsid_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct winbindd_getgrnam_state *state = tevent_req_data(
		req, struct winbindd_getgrnam_state);
	NTSTATUS status;

	status = wb_getgrsid_recv(subreq,
				  state,
				  &state->domname,
				  &state->name,
				  &state->gid,
				  &state->members);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
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
	tevent_req_set_callback(subreq, winbindd_getgrnam_normalize_done, req);
}

static void winbindd_getgrnam_normalize_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winbindd_getgrnam_state *state = tevent_req_data(
		req, struct winbindd_getgrnam_state);
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
		state->full_group_name = fill_domain_username_talloc(
			state, state->domname, state->mapped_name, true);

	} else if (NT_STATUS_EQUAL(result, NT_STATUS_FILE_RENAMED)) {
		state->full_group_name = state->mapped_name;
	} else {
		state->full_group_name = fill_domain_username_talloc(
			state, state->domname, state->name, True);
	}

	if (tevent_req_nomem(state->full_group_name, req)) {
		D_WARNING("Failed to fill full group name.\n");
		return;
	}
	tevent_req_done(req);
}

NTSTATUS winbindd_getgrnam_recv(struct tevent_req *req,
				struct winbindd_response *response)
{
	struct winbindd_getgrnam_state *state = tevent_req_data(
		req, struct winbindd_getgrnam_state);
	struct winbindd_gr *gr = &response->data.gr;
	NTSTATUS status;
	int num_members;
	char *buf;

	if (tevent_req_is_nterror(req, &status)) {
		struct dom_sid_buf sidbuf;
		D_WARNING("Could not convert sid %s: %s\n",
			  dom_sid_str_buf(&state->sid, &sidbuf),
			  nt_errstr(status));
		return status;
	}

	gr->gr_gid = state->gid;

	strlcpy(gr->gr_name, state->full_group_name, sizeof(gr->gr_name));
	strlcpy(gr->gr_passwd, "x", sizeof(gr->gr_passwd));

	D_DEBUG("Full group name is '%s'.\n", gr->gr_name);

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

	D_NOTICE("Winbind external command GETGRNAM end.\n"
		 "Returning %"PRIu32" member(s).\n",
		 response->data.gr.num_gr_mem);

	return NT_STATUS_OK;
}
