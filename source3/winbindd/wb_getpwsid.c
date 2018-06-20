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

static void wb_getpwsid_queryuser_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_getpwsid_state *state = tevent_req_data(
		req, struct wb_getpwsid_state);
	struct winbindd_pw *pw = state->pw;
	struct wbint_userinfo *info;
	fstring acct_name;
	const char *output_username = NULL;
	char *mapped_name = NULL;
	char *tmp;
	NTSTATUS status;

	status = wb_queryuser_recv(subreq, state, &state->userinfo);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	info = state->userinfo;

	pw->pw_uid = info->uid;
	pw->pw_gid = info->primary_gid;

	fstrcpy(acct_name, info->acct_name);
	if (!strlower_m(acct_name)) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	/*
	 * TODO:
	 * This function should be called in 'idmap winbind child'. It shouldn't
	 * be a blocking call, but for this we need to add a new function for
	 * winbind.idl. This is a fix which can be backported for now.
	 */
	status = normalize_name_map(state,
				    info->domain_name,
				    acct_name,
				    &mapped_name);
	if (NT_STATUS_IS_OK(status) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_FILE_RENAMED)) {
		fstrcpy(acct_name, mapped_name);
	}
	output_username = fill_domain_username_talloc(state,
						      info->domain_name,
						      acct_name,
						      true);
	if (output_username == NULL) {
		tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}

	strlcpy(pw->pw_name, output_username, sizeof(pw->pw_name));

	strlcpy(pw->pw_gecos, info->full_name ? info->full_name : "",
		sizeof(pw->pw_gecos));

	tmp = talloc_sub_specified(
		state, info->homedir, acct_name,
		info->primary_group_name, info->domain_name,
		pw->pw_uid, pw->pw_gid);
	if (tevent_req_nomem(tmp, req)) {
		return;
	}
	strlcpy(pw->pw_dir, tmp, sizeof(pw->pw_dir));
	TALLOC_FREE(tmp);

	tmp = talloc_sub_specified(
		state, info->shell, acct_name,
		info->primary_group_name, info->domain_name,
		pw->pw_uid, pw->pw_gid);
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
	return tevent_req_simple_recv_ntstatus(req);
}
