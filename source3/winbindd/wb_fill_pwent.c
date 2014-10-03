/*
   Unix SMB/CIFS implementation.
   async fill_pwent
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

struct wb_fill_pwent_state {
	struct tevent_context *ev;
	struct wbint_userinfo *info;
	struct winbindd_pw *pw;
};

static bool fillup_pw_field(const char *lp_template,
			    const char *username,
			    const char *grpname,
			    const char *domname,
			    uid_t uid,
			    gid_t gid,
			    const char *in,
			    fstring out);

static void wb_fill_pwent_sid2uid_done(struct tevent_req *subreq);
static void wb_fill_pwent_getgrsid_done(struct tevent_req *subreq);

struct tevent_req *wb_fill_pwent_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct wbint_userinfo *info,
				      struct winbindd_pw *pw)
{
	struct tevent_req *req, *subreq;
	struct wb_fill_pwent_state *state;

	req = tevent_req_create(mem_ctx, &state, struct wb_fill_pwent_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->info = info;
	state->pw = pw;

	subreq = wb_sids2xids_send(state, state->ev, &state->info->user_sid, 1);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wb_fill_pwent_sid2uid_done, req);
	return req;
}

static void wb_fill_pwent_sid2uid_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_fill_pwent_state *state = tevent_req_data(
		req, struct wb_fill_pwent_state);
	NTSTATUS status;
	struct unixid xid;

	status = wb_sids2xids_recv(subreq, &xid);
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
	if (!(xid.type == ID_TYPE_UID || xid.type == ID_TYPE_BOTH)) {
		tevent_req_nterror(req, NT_STATUS_NONE_MAPPED);
		return;
	}

	state->pw->pw_uid = (uid_t)xid.id;

	subreq = wb_getgrsid_send(state, state->ev, &state->info->group_sid, 0);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_fill_pwent_getgrsid_done, req);
}

static void wb_fill_pwent_getgrsid_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_fill_pwent_state *state = tevent_req_data(
		req, struct wb_fill_pwent_state);
	struct winbindd_domain *domain;
	const char *dom_name;
	const char *grp_name;
	fstring user_name, output_username;
	char *mapped_name = NULL;
	struct talloc_dict *members;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	NTSTATUS status;
	bool ok;

	/* xid handling is done in getgrsid() */
	status = wb_getgrsid_recv(subreq,
				  tmp_ctx,
				  &dom_name,
				  &grp_name,
				  &state->pw->pw_gid,
				  &members);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		talloc_free(tmp_ctx);
		return;
	}

	domain = find_domain_from_sid_noinit(&state->info->user_sid);
	if (domain == NULL) {
		talloc_free(tmp_ctx);
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_USER);
		return;
	}
	dom_name = domain->name;

	/* Username */

	fstrcpy(user_name, state->info->acct_name);
	if (!strlower_m(user_name)) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}
	status = normalize_name_map(state, domain, user_name, &mapped_name);

	/* Basic removal of whitespace */
	if (NT_STATUS_IS_OK(status)) {
		fill_domain_username(output_username, dom_name, mapped_name,
				     true);
	}
	/* Complete name replacement */
	else if (NT_STATUS_EQUAL(status, NT_STATUS_FILE_RENAMED)) {
		fstrcpy(output_username, mapped_name);
	}
	/* No change at all */
	else {
		fill_domain_username(output_username, dom_name, user_name,
				     true);
	}

	strlcpy(state->pw->pw_name,
		output_username,
		sizeof(state->pw->pw_name));
	/* FIXME The full_name can be longer than 255 chars */
	strlcpy(state->pw->pw_gecos,
		state->info->full_name != NULL ? state->info->full_name : "",
		sizeof(state->pw->pw_gecos));

	/* Home directory and shell */
	ok = fillup_pw_field(lp_template_homedir(),
			     user_name,
			     grp_name,
			     dom_name,
			     state->pw->pw_uid,
			     state->pw->pw_gid,
			     state->info->homedir,
			     state->pw->pw_dir);
	if (!ok) {
		talloc_free(tmp_ctx);
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_USER);
		return;
	}

	ok = fillup_pw_field(lp_template_shell(),
			     user_name,
			     grp_name,
			     dom_name,
			     state->pw->pw_uid,
			     state->pw->pw_gid,
			     state->info->shell,
			     state->pw->pw_shell);
	talloc_free(tmp_ctx);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_USER);
		return;
	}

	/* Password - set to "*" as we can't generate anything useful here.
	   Authentication can be done using the pam_winbind module. */

	fstrcpy(state->pw->pw_passwd, "*");
	tevent_req_done(req);
}

NTSTATUS wb_fill_pwent_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static bool fillup_pw_field(const char *lp_template,
			    const char *username,
			    const char *grpname,
			    const char *domname,
			    uid_t uid,
			    gid_t gid,
			    const char *in,
			    fstring out)
{
	const char *templ;
	char *result;

	if (out == NULL)
		return False;

	templ = lp_template;

	if ((in != NULL) && (in[0] != '\0') && (lp_security() == SEC_ADS)) {
		/*
		 * The backend has already filled in the required value. Use
		 * that instead of the template.
		 */
		templ = in;
	}

	result = talloc_sub_specified(talloc_tos(), templ,
				      username, grpname, domname,
				      uid, gid);
	if (result == NULL) {
		return False;
	}

	fstrcpy(out, result);
	TALLOC_FREE(result);

	return True;

}
