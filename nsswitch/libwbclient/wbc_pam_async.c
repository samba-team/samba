/*
   Unix SMB/CIFS implementation.

   Winbind client API

   Copyright (C) 2009 Kai Blin  <kai@samba.org>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* Required Headers */

#include "replace.h"
#include "libwbclient.h"
#include "../winbind_client.h"
#include "wbc_async.h"

/* FIXME: Currently this is still a copy of the same function from wbc_pam.c */
static wbcErr wbc_create_auth_info(TALLOC_CTX *mem_ctx,
				   const struct winbindd_response *resp,
				   struct wbcAuthUserInfo **_i)
{
	wbcErr wbc_status = WBC_ERR_SUCCESS;
	struct wbcAuthUserInfo *i;
	struct wbcDomainSid domain_sid;
	char *p;
	uint32_t sn = 0;
	uint32_t j;

	i = talloc(mem_ctx, struct wbcAuthUserInfo);
	BAIL_ON_PTR_ERROR(i, wbc_status);

	i->user_flags	= resp->data.auth.info3.user_flgs;

	i->account_name	= talloc_strdup(i, resp->data.auth.info3.user_name);
	BAIL_ON_PTR_ERROR(i->account_name, wbc_status);
	i->user_principal= NULL;
	i->full_name	= talloc_strdup(i, resp->data.auth.info3.full_name);
	BAIL_ON_PTR_ERROR(i->full_name, wbc_status);
	i->domain_name	= talloc_strdup(i, resp->data.auth.info3.logon_dom);
	BAIL_ON_PTR_ERROR(i->domain_name, wbc_status);
	i->dns_domain_name= NULL;

	i->acct_flags	= resp->data.auth.info3.acct_flags;
	memcpy(i->user_session_key,
	       resp->data.auth.user_session_key,
	       sizeof(i->user_session_key));
	memcpy(i->lm_session_key,
	       resp->data.auth.first_8_lm_hash,
	       sizeof(i->lm_session_key));

	i->logon_count		= resp->data.auth.info3.logon_count;
	i->bad_password_count	= resp->data.auth.info3.bad_pw_count;

	i->logon_time		= resp->data.auth.info3.logon_time;
	i->logoff_time		= resp->data.auth.info3.logoff_time;
	i->kickoff_time		= resp->data.auth.info3.kickoff_time;
	i->pass_last_set_time	= resp->data.auth.info3.pass_last_set_time;
	i->pass_can_change_time	= resp->data.auth.info3.pass_can_change_time;
	i->pass_must_change_time= resp->data.auth.info3.pass_must_change_time;

	i->logon_server	= talloc_strdup(i, resp->data.auth.info3.logon_srv);
	BAIL_ON_PTR_ERROR(i->logon_server, wbc_status);
	i->logon_script	= talloc_strdup(i, resp->data.auth.info3.logon_script);
	BAIL_ON_PTR_ERROR(i->logon_script, wbc_status);
	i->profile_path	= talloc_strdup(i, resp->data.auth.info3.profile_path);
	BAIL_ON_PTR_ERROR(i->profile_path, wbc_status);
	i->home_directory= talloc_strdup(i, resp->data.auth.info3.home_dir);
	BAIL_ON_PTR_ERROR(i->home_directory, wbc_status);
	i->home_drive	= talloc_strdup(i, resp->data.auth.info3.dir_drive);
	BAIL_ON_PTR_ERROR(i->home_drive, wbc_status);

	i->num_sids	= 2;
	i->num_sids 	+= resp->data.auth.info3.num_groups;
	i->num_sids	+= resp->data.auth.info3.num_other_sids;

	i->sids	= talloc_array(i, struct wbcSidWithAttr, i->num_sids);
	BAIL_ON_PTR_ERROR(i->sids, wbc_status);

	wbc_status = wbcStringToSid(resp->data.auth.info3.dom_sid,
				    &domain_sid);
	BAIL_ON_WBC_ERROR(wbc_status);

#define _SID_COMPOSE(s, d, r, a) { \
	(s).sid = d; \
	if ((s).sid.num_auths < WBC_MAXSUBAUTHS) { \
		(s).sid.sub_auths[(s).sid.num_auths++] = r; \
	} else { \
		wbc_status = WBC_ERR_INVALID_SID; \
		BAIL_ON_WBC_ERROR(wbc_status); \
	} \
	(s).attributes = a; \
} while (0)

	sn = 0;
	_SID_COMPOSE(i->sids[sn], domain_sid,
		     resp->data.auth.info3.user_rid,
		     0);
	sn++;
	_SID_COMPOSE(i->sids[sn], domain_sid,
		     resp->data.auth.info3.group_rid,
		     0);
	sn++;

	p = (char *)resp->extra_data.data;
	if (!p) {
		wbc_status = WBC_ERR_INVALID_RESPONSE;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	for (j=0; j < resp->data.auth.info3.num_groups; j++) {
		uint32_t rid;
		uint32_t attrs;
		int ret;
		char *s = p;
		char *e = strchr(p, '\n');
		if (!e) {
			wbc_status = WBC_ERR_INVALID_RESPONSE;
			BAIL_ON_WBC_ERROR(wbc_status);
		}
		e[0] = '\0';
		p = &e[1];

		ret = sscanf(s, "0x%08X:0x%08X", &rid, &attrs);
		if (ret != 2) {
			wbc_status = WBC_ERR_INVALID_RESPONSE;
			BAIL_ON_WBC_ERROR(wbc_status);
		}

		_SID_COMPOSE(i->sids[sn], domain_sid,
			     rid, attrs);
		sn++;
	}

	for (j=0; j < resp->data.auth.info3.num_other_sids; j++) {
		uint32_t attrs;
		int ret;
		char *s = p;
		char *a;
		char *e = strchr(p, '\n');
		if (!e) {
			wbc_status = WBC_ERR_INVALID_RESPONSE;
			BAIL_ON_WBC_ERROR(wbc_status);
		}
		e[0] = '\0';
		p = &e[1];

		e = strchr(s, ':');
		if (!e) {
			wbc_status = WBC_ERR_INVALID_RESPONSE;
			BAIL_ON_WBC_ERROR(wbc_status);
		}
		e[0] = '\0';
		a = &e[1];

		ret = sscanf(a, "0x%08X",
			     &attrs);
		if (ret != 1) {
			wbc_status = WBC_ERR_INVALID_RESPONSE;
			BAIL_ON_WBC_ERROR(wbc_status);
		}

		wbc_status = wbcStringToSid(s, &i->sids[sn].sid);
		BAIL_ON_WBC_ERROR(wbc_status);

		i->sids[sn].attributes = attrs;
		sn++;
	}

	i->num_sids = sn;

	*_i = i;
	i = NULL;
done:
	talloc_free(i);
	return wbc_status;
}

/* FIXME: Currently this is still a copy of the same function from wbc_pam.c */
static wbcErr wbc_create_error_info(const struct winbindd_response *resp,
				    struct wbcAuthErrorInfo **_e)
{
	wbcErr wbc_status = WBC_ERR_SUCCESS;
	struct wbcAuthErrorInfo *e;

	e = talloc(NULL, struct wbcAuthErrorInfo);
	BAIL_ON_PTR_ERROR(e, wbc_status);

	e->nt_status = resp->data.auth.nt_status;
	e->pam_error = resp->data.auth.pam_error;
	e->nt_string = talloc_strdup(e, resp->data.auth.nt_status_string);
	BAIL_ON_PTR_ERROR(e->nt_string, wbc_status);

	e->display_string = talloc_strdup(e, resp->data.auth.error_string);
	BAIL_ON_PTR_ERROR(e->display_string, wbc_status);

	*_e = e;
	e = NULL;

done:
	talloc_free(e);
	return wbc_status;
}

struct wbc_authenticate_user_ex_state {
	struct winbindd_request req;
	struct tevent_context *ev;
	struct wb_context *wb_ctx;
	const struct wbcAuthUserParams *params;
	struct wbcAuthUserInfo *info;
	struct wbcAuthErrorInfo *error;
};

static void wbcAuthenticateUserEx_got_info(struct tevent_req *subreq);
static void wbcAuthenticateUserEx_done(struct tevent_req *subreq);

struct tevent_req *wbcAuthenticateUserEx_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct wb_context *wb_ctx,
					const struct wbcAuthUserParams *params)
{
	struct tevent_req *req, *subreq;
	struct wbc_authenticate_user_ex_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct wbc_authenticate_user_ex_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->wb_ctx = wb_ctx;
	state->params = params;

	if (!params) {
		tevent_req_error(req, WBC_ERR_INVALID_PARAM);
		return tevent_req_post(req, ev);
	}

	if (!params->account_name) {
		tevent_req_error(req, WBC_ERR_INVALID_PARAM);
		return tevent_req_post(req, ev);
	}

	ZERO_STRUCT(state->req);

	if (params->flags) {
		state->req.flags = params->flags;
	}

	switch (params->level) {
	case WBC_AUTH_USER_LEVEL_PLAIN:
		state->req.cmd = WINBINDD_PAM_AUTH;
		state->req.flags |= WBFLAG_PAM_INFO3_TEXT |
				    WBFLAG_PAM_USER_SESSION_KEY |
				    WBFLAG_PAM_LMKEY;

		if (!params->password.plaintext) {
			tevent_req_error(req, WBC_ERR_INVALID_PARAM);
			return tevent_req_post(req, ev);
		}

		strncpy(state->req.data.auth.pass,
			params->password.plaintext,
			sizeof(state->req.data.auth.pass)-1);

		if (params->domain_name && params->domain_name[0]) {
			/* We need to get the winbind separator :-( */
			subreq = wbcInfo_send(state, ev, wb_ctx);
			if (tevent_req_nomem(subreq, req)) {
				return tevent_req_post(req, ev);
			}

			tevent_req_set_callback(subreq,
						wbcAuthenticateUserEx_got_info,
						req);
			return req;
		} else {
			strncpy(state->req.data.auth.user,
				params->account_name,
				sizeof(state->req.data.auth.user)-1);
		}

		break;

	case WBC_AUTH_USER_LEVEL_HASH:
		tevent_req_error(req, WBC_ERR_NOT_IMPLEMENTED);
		return tevent_req_post(req, ev);
		/* Make some static code checkers happy */
		break;

	case WBC_AUTH_USER_LEVEL_RESPONSE:
		state->req.cmd = WINBINDD_PAM_AUTH_CRAP;
		state->req.flags |= WBFLAG_PAM_INFO3_TEXT |
				    WBFLAG_PAM_USER_SESSION_KEY |
				    WBFLAG_PAM_LMKEY;

		if (params->password.response.lm_length &&
		    !params->password.response.lm_data) {
			tevent_req_error(req, WBC_ERR_INVALID_PARAM);
			return tevent_req_post(req, ev);
		}
		if (params->password.response.lm_length == 0 &&
		    params->password.response.lm_data) {
			tevent_req_error(req, WBC_ERR_INVALID_PARAM);
			return tevent_req_post(req, ev);
		}

		if (params->password.response.nt_length &&
		    !params->password.response.nt_data) {
			tevent_req_error(req, WBC_ERR_INVALID_PARAM);
			return tevent_req_post(req, ev);
		}
		if (params->password.response.nt_length == 0&&
		    params->password.response.nt_data) {
			tevent_req_error(req, WBC_ERR_INVALID_PARAM);
			return tevent_req_post(req, ev);
		}

		strncpy(state->req.data.auth_crap.user,
			params->account_name,
			sizeof(state->req.data.auth_crap.user)-1);
		if (params->domain_name) {
			strncpy(state->req.data.auth_crap.domain,
				params->domain_name,
				sizeof(state->req.data.auth_crap.domain)-1);
		}
		if (params->workstation_name) {
			strncpy(state->req.data.auth_crap.workstation,
				params->workstation_name,
				sizeof(state->req.data.auth_crap.workstation)-1);
		}

		state->req.data.auth_crap.logon_parameters =
				params->parameter_control;

		memcpy(state->req.data.auth_crap.chal,
		       params->password.response.challenge,
		       sizeof(state->req.data.auth_crap.chal));

		state->req.data.auth_crap.lm_resp_len =
				MIN(params->password.response.lm_length,
				    sizeof(state->req.data.auth_crap.lm_resp));
		state->req.data.auth_crap.nt_resp_len =
				MIN(params->password.response.nt_length,
				    sizeof(state->req.data.auth_crap.nt_resp));
		if (params->password.response.lm_data) {
			memcpy(state->req.data.auth_crap.lm_resp,
			       params->password.response.lm_data,
			       state->req.data.auth_crap.lm_resp_len);
		}
		if (params->password.response.nt_data) {
			memcpy(state->req.data.auth_crap.nt_resp,
			       params->password.response.nt_data,
			       state->req.data.auth_crap.nt_resp_len);
		}
		break;
	default:
		tevent_req_error(req, WBC_ERR_INVALID_PARAM);
		return tevent_req_post(req, ev);
		break;
	}

	subreq = wb_trans_send(state, ev, wb_ctx, false, &state->req);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, wbcAuthenticateUserEx_done, req);
	return req;
}

static void wbcAuthenticateUserEx_got_info(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
			subreq, struct tevent_req);
	struct wbc_authenticate_user_ex_state *state = tevent_req_data(
			req, struct wbc_authenticate_user_ex_state);
	char *version_string;
	char separator;
	wbcErr wbc_status;

	wbc_status = wbcInfo_recv(subreq, state, &separator, &version_string);
	TALLOC_FREE(subreq);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		tevent_req_error(req, wbc_status);
		return;
	}

	snprintf(state->req.data.auth.user,
		 sizeof(state->req.data.auth.user)-1,
		 "%s%c%s",
		 state->params->domain_name,
		 separator,
		 state->params->account_name);

	subreq = wb_trans_send(state, state->ev, state->wb_ctx, false,
			       &state->req);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}

	tevent_req_set_callback(subreq, wbcAuthenticateUserEx_done, req);
	return;
}

static void wbcAuthenticateUserEx_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
			subreq, struct tevent_req);
	struct wbc_authenticate_user_ex_state *state = tevent_req_data(
			req, struct wbc_authenticate_user_ex_state);
	struct winbindd_response *resp;
	wbcErr wbc_status;

	ZERO_STRUCT(resp);

	wbc_status = wb_trans_recv(subreq, state, &resp);
	TALLOC_FREE(subreq);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		tevent_req_error(req, wbc_status);
		goto done;
	}

	if (resp->data.auth.nt_status != 0) {
		wbc_status = wbc_create_error_info(resp, &state->error);
		if (!WBC_ERROR_IS_OK(wbc_status)) {
			tevent_req_error(req, wbc_status);
			goto done;
		}

		tevent_req_error(req, WBC_ERR_AUTH_ERROR);
		goto done;
	}

	wbc_status = wbc_create_auth_info(state, resp, &state->info);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		tevent_req_error(req, wbc_status);
		goto done;
	}

done:
	TALLOC_FREE(resp);
}

wbcErr wbcAuthenticateUserEx_recv(struct tevent_req *req,
				  TALLOC_CTX *mem_ctx,
				  struct wbcAuthUserInfo **info,
				  struct wbcAuthErrorInfo **error)
{
	struct wbc_authenticate_user_ex_state *state = tevent_req_data(
			req, struct wbc_authenticate_user_ex_state);
	wbcErr wbc_status;

	if (error) {
		*error = NULL;
	}

	if (tevent_req_is_wbcerr(req, &wbc_status)) {
		tevent_req_received(req);
		if (error) {
			*error = talloc_steal(mem_ctx, state->error);
		}
		return wbc_status;
	}

	if (info) {
		*info = talloc_steal(mem_ctx, state->info);
	}

	tevent_req_received(req);
	return wbc_status;
}
