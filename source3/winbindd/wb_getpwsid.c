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
#include "lib/util/string_wrappers.h"
#include "source3/lib/substitute.h"

struct wb_getpwsid_state {
	struct tevent_context *ev;
	struct dom_sid sid;
	struct wbint_userinfo *userinfo;
	struct winbindd_pw *pw;
	const char *mapped_name;
};

static void wb_getpwsid_queryuser_done(struct tevent_req *subreq);

struct tevent_req *wb_getpwsid_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    const struct dom_sid *user_sid,
				    struct winbindd_pw *pw)
{
	struct tevent_req *req, *subreq;
	struct wb_getpwsid_state *state;
	struct dom_sid_buf buf;

	req = tevent_req_create(mem_ctx, &state, struct wb_getpwsid_state);
	if (req == NULL) {
		return NULL;
	}
	D_INFO("WB command getpwsid start.\nQuery user SID %s.\n", dom_sid_str_buf(user_sid, &buf));
	sid_copy(&state->sid, user_sid);
	state->ev = ev;
	state->pw = pw;

	if (dom_sid_in_domain(&global_sid_Unix_Users, user_sid)) {
		/* unmapped Unix users must be resolved locally */
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	subreq = wb_queryuser_send(state, ev, &state->sid);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wb_getpwsid_queryuser_done, req);
	return req;
}

static void wb_getpwsid_normalize_done(struct tevent_req *subreq);
static void wb_getpwsid_queryuser_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_getpwsid_state *state = tevent_req_data(
		req, struct wb_getpwsid_state);
	const char *acct_name_lower = NULL;
	NTSTATUS status;

	status = wb_queryuser_recv(subreq, state, &state->userinfo);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	acct_name_lower = strlower_talloc(state, state->userinfo->acct_name);
	if (tevent_req_nomem(acct_name_lower, req)) {
		return;
	}
	state->userinfo->acct_name = talloc_move(state->userinfo, &acct_name_lower);

	subreq = dcerpc_wbint_NormalizeNameMap_send(
		state,
		state->ev,
		idmap_child_handle(),
		state->userinfo->domain_name,
		state->userinfo->acct_name,
		&state->mapped_name);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_getpwsid_normalize_done, req);
}

static void wb_getpwsid_normalize_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_getpwsid_state *state = tevent_req_data(
		req, struct wb_getpwsid_state);
	struct winbindd_pw *pw = state->pw;
	struct wbint_userinfo *info;
	const char *output_username = NULL;
	char *tmp;
	NTSTATUS status;
	NTSTATUS result;

	status = dcerpc_wbint_NormalizeNameMap_recv(subreq, state, &result);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		DBG_ERR("wbint_NormalizeAndMapToAlias(%s, %s) call failed: %s\n",
			state->userinfo->domain_name,
			state->userinfo->acct_name,
			nt_errstr(status));
		return;
	} else if (NT_STATUS_IS_OK(result) ||
		   NT_STATUS_EQUAL(result, NT_STATUS_FILE_RENAMED))
	{
		state->userinfo->acct_name = talloc_steal(state->userinfo,
							  state->mapped_name);
	}

	info = state->userinfo;

	output_username = fill_domain_username_talloc(state,
						      info->domain_name,
						      info->acct_name,
						      true);
	if (tevent_req_nomem(output_username, req)) {
		return;
	}

	pw->pw_uid = info->uid;
	pw->pw_gid = info->primary_gid;

	strlcpy(pw->pw_name, output_username, sizeof(pw->pw_name));

	strlcpy(pw->pw_gecos, info->full_name ? info->full_name : "",
		sizeof(pw->pw_gecos));

	tmp = talloc_sub_specified(state,
				   info->homedir,
				   info->acct_name,
				   info->primary_group_name,
				   info->domain_name,
				   pw->pw_uid,
				   pw->pw_gid);
	if (tevent_req_nomem(tmp, req)) {
		return;
	}
	strlcpy(pw->pw_dir, tmp, sizeof(pw->pw_dir));
	TALLOC_FREE(tmp);

	tmp = talloc_sub_specified(state,
				   info->shell,
				   info->acct_name,
				   info->primary_group_name,
				   info->domain_name,
				   pw->pw_uid,
				   pw->pw_gid);
	if (tevent_req_nomem(tmp, req)) {
		return;
	}
	strlcpy(pw->pw_shell, tmp, sizeof(pw->pw_shell));
	TALLOC_FREE(tmp);

	strlcpy(pw->pw_passwd, "*", sizeof(pw->pw_passwd));

	tevent_req_done(req);
}

NTSTATUS wb_getpwsid_recv(struct tevent_req *req)
{
	NTSTATUS status = tevent_req_simple_recv_ntstatus(req);
	D_INFO("WB command getpwsid end.\nReturn status %s.\n", nt_errstr(status));
	return status;
}
