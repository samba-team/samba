/*
   Unix SMB/CIFS implementation.
   async queryuser
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
#include "util/debug.h"
#include "winbindd.h"
#include "librpc/gen_ndr/ndr_winbind_c.h"
#include "../libcli/security/security.h"
#include "libsmb/samlogon_cache.h"
#include "librpc/gen_ndr/ndr_winbind.h"

struct wb_queryuser_state {
	struct tevent_context *ev;
        struct wbint_userinfo *info;
	const struct wb_parent_idmap_config *idmap_cfg;
	bool tried_dclookup;
};

static void wb_queryuser_idmap_setup_done(struct tevent_req *subreq);
static void wb_queryuser_got_uid(struct tevent_req *subreq);
static void wb_queryuser_got_domain(struct tevent_req *subreq);
static void wb_queryuser_got_dc(struct tevent_req *subreq);
static void wb_queryuser_got_gid(struct tevent_req *subreq);
static void wb_queryuser_got_group_name(struct tevent_req *subreq);
static void wb_queryuser_done(struct tevent_req *subreq);

struct tevent_req *wb_queryuser_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     const struct dom_sid *user_sid)
{
	struct tevent_req *req, *subreq;
	struct wb_queryuser_state *state;
	struct wbint_userinfo *info;
	struct dom_sid_buf buf;

	req = tevent_req_create(mem_ctx, &state, struct wb_queryuser_state);
	if (req == NULL) {
		return NULL;
	}
	D_INFO("WB command queryuser start.\nQuery user sid %s\n",
	       dom_sid_str_buf(user_sid, &buf));
	state->ev = ev;

	state->info = talloc_zero(state, struct wbint_userinfo);
	if (tevent_req_nomem(state->info, req)) {
		return tevent_req_post(req, ev);
	}
	info = state->info;

	info->primary_gid = (gid_t)-1;

	sid_copy(&info->user_sid, user_sid);

	subreq = wb_parent_idmap_setup_send(state, state->ev);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wb_queryuser_idmap_setup_done, req);
        return req;
}

static void wb_queryuser_idmap_setup_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_queryuser_state *state = tevent_req_data(
		req, struct wb_queryuser_state);
	NTSTATUS status;
	struct dom_sid_buf buf;

	status = wb_parent_idmap_setup_recv(subreq, &state->idmap_cfg);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		D_WARNING("wb_parent_idmap_setup_recv() failed with %s.\n",
			  nt_errstr(status));
		return;
	}

	D_DEBUG("Convert the user SID %s to XID.\n",
		dom_sid_str_buf(&state->info->user_sid, &buf));
	subreq = wb_sids2xids_send(
		state, state->ev, &state->info->user_sid, 1);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_queryuser_got_uid, req);
	return;
}

static void wb_queryuser_got_uid(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_queryuser_state *state = tevent_req_data(
		req, struct wb_queryuser_state);
	struct wbint_userinfo *info = state->info;
	struct netr_SamInfo3 *info3;
	struct dcerpc_binding_handle *child_binding_handle = NULL;
	struct unixid xid;
	uint32_t user_rid = 0;
	NTSTATUS status;
	struct dom_sid_buf buf, buf1;

	status = wb_sids2xids_recv(subreq, &xid, 1);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		D_WARNING("wb_sids2xids_recv() failed with %s.\n",
			  nt_errstr(status));
		return;
	}

	if ((xid.type != ID_TYPE_UID) && (xid.type != ID_TYPE_BOTH)) {
		D_WARNING("XID type is %d, should be ID_TYPE_UID or ID_TYPE_BOTH.\n",
			  xid.type);
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_USER);
		return;
	}

	D_DEBUG("Received XID %"PRIu32" for SID %s.\n",
		xid.id,
		dom_sid_str_buf(&info->user_sid, &buf1));
	info->uid = xid.id;

	/*
	 * Default the group sid to "Domain Users" in the user's
	 * domain. The samlogon cache or the query_user call later on
	 * can override this.
	 * TODO: There is still missing functionality to set the correct group
	 * sid using samlogon cache (needs to use S4USelf).
	 * Once this is done, remove the workaround in test_membership_user() in
	 * source4/torture/local/nss_tests.c
	 */
	sid_copy(&info->group_sid, &info->user_sid);
	sid_split_rid(&info->group_sid, &user_rid);
	sid_append_rid(&info->group_sid,
		       user_rid == DOMAIN_RID_GUEST ? DOMAIN_RID_GUESTS
						    : DOMAIN_RID_USERS);

	D_DEBUG("Preconfigured 'Domain Users' RID %u was used to create group SID %s from user SID %s.\n",
		DOMAIN_RID_USERS,
		dom_sid_str_buf(&info->group_sid, &buf),
		dom_sid_str_buf(&info->user_sid, &buf1));

	info->homedir = talloc_strdup(info, lp_template_homedir());
	D_DEBUG("Setting 'homedir' to the template '%s'.\n", info->homedir);
	if (tevent_req_nomem(info->homedir, req)) {
		return;
	}

	info->shell = talloc_strdup(info, lp_template_shell());
	D_DEBUG("Setting 'shell' to the template '%s'.\n", info->shell);
	if (tevent_req_nomem(info->shell, req)) {
		return;
	}

	info3 = netsamlogon_cache_get(state, &info->user_sid);
	if (info3 != NULL) {
		D_DEBUG("Filling data received from netsamlogon_cache\n");
		sid_compose(&info->group_sid, info3->base.domain_sid,
			    info3->base.primary_gid);
		info->acct_name = talloc_move(
			info, &info3->base.account_name.string);
		info->full_name = talloc_move(
			info, &info3->base.full_name.string);

		info->domain_name = talloc_move(
			state, &info3->base.logon_domain.string);

		TALLOC_FREE(info3);
	}

	NDR_PRINT_DEBUG_LEVEL(DBGLVL_DEBUG, wbint_userinfo, state->info);
	if (info->domain_name == NULL) {
		D_DEBUG("Domain name is empty, calling wb_lookupsid_send() to get it.\n");
		subreq = wb_lookupsid_send(state, state->ev, &info->user_sid);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, wb_queryuser_got_domain, req);
		return;
	}

	/*
	 * Note wb_sids2xids_send/recv was called before,
	 * so we're sure that wb_parent_idmap_setup_send/recv
	 * was already called.
	 */
	child_binding_handle = idmap_child_handle();
	D_DEBUG("Domain name is set, calling dcerpc_wbint_GetNssInfo_send()\n");
	subreq = dcerpc_wbint_GetNssInfo_send(
		state, state->ev, child_binding_handle, info);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_queryuser_done, req);
}

static void wb_queryuser_got_domain(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_queryuser_state *state = tevent_req_data(
		req, struct wb_queryuser_state);
	struct wbint_userinfo *info = state->info;
	enum lsa_SidType type;
	struct dcerpc_binding_handle *child_binding_handle = NULL;
	NTSTATUS status;

	status = wb_lookupsid_recv(subreq, state, &type,
				   &info->domain_name, &info->acct_name);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		D_WARNING("wb_lookupsid_recv failed with %s.\n",
			  nt_errstr(status));
		return;
	}

	NDR_PRINT_DEBUG_LEVEL(DBGLVL_DEBUG, wbint_userinfo, state->info);
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
		sid_copy(&info->group_sid, &info->user_sid);
		break;
	default:
		D_WARNING("Unknown type:%d, return NT_STATUS_NO_SUCH_USER.\n",
			  type);
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_USER);
		return;
	}

	/*
	 * Note wb_sids2xids_send/recv was called before,
	 * so we're sure that wb_parent_idmap_setup_send/recv
	 * was already called.
	 */
	child_binding_handle = idmap_child_handle();
	D_DEBUG("About to call dcerpc_wbint_GetNssInfo_send()\n");
	subreq = dcerpc_wbint_GetNssInfo_send(
		state, state->ev, child_binding_handle, info);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_queryuser_done, req);
}

static void wb_queryuser_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_queryuser_state *state = tevent_req_data(
		req, struct wb_queryuser_state);
	struct wbint_userinfo *info = state->info;
	NTSTATUS status, result;
	bool need_group_name = false;
	const char *tmpl = NULL;
	uint32_t dsgetdcname_flags = DS_RETURN_DNS_NAME;

	status = dcerpc_wbint_GetNssInfo_recv(subreq, info, &result);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		D_WARNING("GetNssInfo failed with %s.\n", nt_errstr(status));
		return;
	}

	if (NT_STATUS_EQUAL(result, NT_STATUS_HOST_UNREACHABLE)) {
		winbind_idmap_add_failed_connection_entry(info->domain_name);
		/* Trigger DC lookup and reconnect below */
		result = NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
		dsgetdcname_flags |= DS_FORCE_REDISCOVERY;
	}

	if (NT_STATUS_EQUAL(result, NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND) &&
	    !state->tried_dclookup) {
		const char *domain_name = find_dns_domain_name(
			state->info->domain_name);

		D_DEBUG("GetNssInfo got DOMAIN_CONTROLLER_NOT_FOUND, calling "
			"wb_dsgetdcname_send(%s)\n",
			domain_name);

		subreq = wb_dsgetdcname_send(state,
					     state->ev,
					     domain_name,
					     NULL,
					     NULL,
					     dsgetdcname_flags);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, wb_queryuser_got_dc, req);
		return;
	}

	/*
	 * Ignore failure in "result" here. We'll try to fill in stuff
	 * that misses further down.
	 */

	if (state->info->primary_gid == (gid_t)-1) {
		D_DEBUG("Calling wb_sids2xids_send() to resolve primary gid.\n");
		subreq = wb_sids2xids_send(
			state, state->ev, &info->group_sid, 1);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, wb_queryuser_got_gid, req);
		return;
	}

	tmpl = lp_template_homedir();
	if(strstr_m(tmpl, "%g") || strstr_m(tmpl, "%G")) {
		need_group_name = true;
	}
	tmpl = lp_template_shell();
	if(strstr_m(tmpl, "%g") || strstr_m(tmpl, "%G")) {
		need_group_name = true;
	}

	if (need_group_name && state->info->primary_group_name == NULL) {
		D_DEBUG("Calling wb_lookupsid_send() to resolve primary group name.\n");
		subreq = wb_lookupsid_send(state, state->ev, &info->group_sid);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, wb_queryuser_got_group_name,
					req);
		return;
	}

	NDR_PRINT_DEBUG_LEVEL(DBGLVL_DEBUG, wbint_userinfo, state->info);
	tevent_req_done(req);
}

static void wb_queryuser_got_dc(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_queryuser_state *state = tevent_req_data(
		req, struct wb_queryuser_state);
	struct wbint_userinfo *info = state->info;
	struct netr_DsRGetDCNameInfo *dcinfo;
	struct dcerpc_binding_handle *child_binding_handle = NULL;
	NTSTATUS status;

	status = wb_dsgetdcname_recv(subreq, state, &dcinfo);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		D_WARNING("wb_dsgetdcname_recv() failed with %s.\n",
			  nt_errstr(status));
		return;
	}

	state->tried_dclookup = true;

	D_DEBUG("Got DC name, calling wb_dsgetdcname_gencache_set().\n");
	status = wb_dsgetdcname_gencache_set(info->domain_name, dcinfo);
	if (tevent_req_nterror(req, status)) {
		D_WARNING("wb_dsgetdcname_gencache_set() failed with %s.\n",
			  nt_errstr(status));
		return;
	}
	NDR_PRINT_DEBUG_LEVEL(DBGLVL_DEBUG, wbint_userinfo, state->info);

	/*
	 * Note wb_sids2xids_send/recv was called before,
	 * so we're sure that wb_parent_idmap_setup_send/recv
	 * was already called.
	 */
	child_binding_handle = idmap_child_handle();
	subreq = dcerpc_wbint_GetNssInfo_send(
		state, state->ev, child_binding_handle, info);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_queryuser_done, req);
}

static void wb_queryuser_got_gid(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_queryuser_state *state = tevent_req_data(
		req, struct wb_queryuser_state);
	struct unixid xid;
	NTSTATUS status;
	bool need_group_name = false;
	const char *tmpl = NULL;
	struct dom_sid_buf buf;

	status = wb_sids2xids_recv(subreq, &xid, 1);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		D_WARNING("wb_sids2xids_recv() failed with %s.\n",
			  nt_errstr(status));
		return;
	}

	D_DEBUG("Got XID %"PRIu32" with type %d.\n", xid.id, xid.type);
	if ((xid.type != ID_TYPE_GID) && (xid.type != ID_TYPE_BOTH)) {
		D_WARNING("Returning NT_STATUS_NO_SUCH_USER\n"
			  "xid.type must be ID_TYPE_UID or ID_TYPE_BOTH.\n");
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_USER);
		return;
	}

	state->info->primary_gid = xid.id;

	tmpl = lp_template_homedir();
	if(strstr_m(tmpl, "%g") || strstr_m(tmpl, "%G")) {
		need_group_name = true;
	}
	tmpl = lp_template_shell();
	if(strstr_m(tmpl, "%g") || strstr_m(tmpl, "%G")) {
		need_group_name = true;
	}

	NDR_PRINT_DEBUG_LEVEL(DBGLVL_DEBUG, wbint_userinfo, state->info);

	if (need_group_name && state->info->primary_group_name == NULL) {
		D_DEBUG("Calling wb_lookupsid_send for group SID %s.\n",
			  dom_sid_str_buf(&state->info->group_sid, &buf));
		subreq = wb_lookupsid_send(state, state->ev,
					   &state->info->group_sid);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, wb_queryuser_got_group_name,
					req);
		return;
	}

	D_DEBUG("No need to lookup primary group name. Request is done!\n");
	tevent_req_done(req);
}

static void wb_queryuser_got_group_name(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_queryuser_state *state = tevent_req_data(
		req, struct wb_queryuser_state);
	enum lsa_SidType type;
	NTSTATUS status;
	const char *domain_name;

	status = wb_lookupsid_recv(subreq, state->info, &type, &domain_name,
				   &state->info->primary_group_name);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		D_WARNING("wb_lookupsid_recv() failed with %s.\n",
			  nt_errstr(status));
		return;
	}
	tevent_req_done(req);
}

NTSTATUS wb_queryuser_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			   struct wbint_userinfo **pinfo)
{
	struct wb_queryuser_state *state = tevent_req_data(
		req, struct wb_queryuser_state);
	NTSTATUS status;

	D_INFO("WB command queryuser end.\n");
	NDR_PRINT_DEBUG_LEVEL(DBGLVL_INFO, wbint_userinfo, state->info);
	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*pinfo = talloc_move(mem_ctx, &state->info);
	return NT_STATUS_OK;
}
