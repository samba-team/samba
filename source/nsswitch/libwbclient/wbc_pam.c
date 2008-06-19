/*
   Unix SMB/CIFS implementation.

   Winbind client API

   Copyright (C) Gerald (Jerry) Carter 2007

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

#include "libwbclient.h"

/** @brief Authenticate a username/password pair
 *
 * @param username     Name of user to authenticate
 * @param password     Clear text password os user
 *
 * @return #wbcErr
 **/

wbcErr wbcAuthenticateUser(const char *username,
			   const char *password)
{
	wbcErr wbc_status = WBC_ERR_SUCCESS;
	struct wbcAuthUserParams params;

	ZERO_STRUCT(params);

	params.account_name		= username;
	params.level			= WBC_AUTH_USER_LEVEL_PLAIN;
	params.password.plaintext	= password;

	wbc_status = wbcAuthenticateUserEx(&params, NULL, NULL);
	BAIL_ON_WBC_ERROR(wbc_status);

done:
	return wbc_status;
}

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

static wbcErr wbc_create_error_info(TALLOC_CTX *mem_ctx,
				  const struct winbindd_response *resp,
				  struct wbcAuthErrorInfo **_e)
{
	wbcErr wbc_status = WBC_ERR_SUCCESS;
	struct wbcAuthErrorInfo *e;

	e = talloc(mem_ctx, struct wbcAuthErrorInfo);
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

/** @brief Authenticate with more detailed information
 *
 * @param params       Input parameters, WBC_AUTH_USER_LEVEL_HASH
 *                     is not supported yet
 * @param info         Output details on WBC_ERR_SUCCESS
 * @param error        Output details on WBC_ERR_AUTH_ERROR
 *
 * @return #wbcErr
 **/

wbcErr wbcAuthenticateUserEx(const struct wbcAuthUserParams *params,
			     struct wbcAuthUserInfo **info,
			     struct wbcAuthErrorInfo **error)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	int cmd = 0;
	struct winbindd_request request;
	struct winbindd_response response;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	if (error) {
		*error = NULL;
	}

	if (!params) {
		wbc_status = WBC_ERR_INVALID_PARAM;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	if (!params->account_name) {
		wbc_status = WBC_ERR_INVALID_PARAM;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	/* Initialize request */

	switch (params->level) {
	case WBC_AUTH_USER_LEVEL_PLAIN:
		cmd = WINBINDD_PAM_AUTH;
		request.flags = WBFLAG_PAM_INFO3_TEXT |
				WBFLAG_PAM_USER_SESSION_KEY |
				WBFLAG_PAM_LMKEY;

		if (!params->password.plaintext) {
			wbc_status = WBC_ERR_INVALID_PARAM;
			BAIL_ON_WBC_ERROR(wbc_status);
		}

		if (params->domain_name && params->domain_name[0]) {
			/* We need to get the winbind separator :-( */
			struct winbindd_response sep_response;

			ZERO_STRUCT(sep_response);

			wbc_status = wbcRequestResponse(WINBINDD_INFO,
							NULL, &sep_response);
			BAIL_ON_WBC_ERROR(wbc_status);

			snprintf(request.data.auth.user,
				 sizeof(request.data.auth.user)-1,
				 "%s%c%s",
				 params->domain_name,
				 sep_response.data.info.winbind_separator,
				 params->account_name);
		} else {
			strncpy(request.data.auth.user,
				params->account_name,
				sizeof(request.data.auth.user)-1);
		}
		strncpy(request.data.auth.pass,
			params->password.plaintext,
			sizeof(request.data.auth.user)-1);
		break;

	case WBC_AUTH_USER_LEVEL_HASH:
		wbc_status = WBC_ERR_NOT_IMPLEMENTED;
		BAIL_ON_WBC_ERROR(wbc_status);
		break;

	case WBC_AUTH_USER_LEVEL_RESPONSE:
		cmd = WINBINDD_PAM_AUTH_CRAP;
		request.flags = WBFLAG_PAM_INFO3_TEXT |
				WBFLAG_PAM_USER_SESSION_KEY |
				WBFLAG_PAM_LMKEY;

		if (params->password.response.lm_length &&
		    !params->password.response.lm_data) {
			wbc_status = WBC_ERR_INVALID_PARAM;
			BAIL_ON_WBC_ERROR(wbc_status);
		}
		if (params->password.response.lm_length == 0 &&
		    params->password.response.lm_data) {
			wbc_status = WBC_ERR_INVALID_PARAM;
			BAIL_ON_WBC_ERROR(wbc_status);
		}

		if (params->password.response.nt_length &&
		    !params->password.response.nt_data) {
			wbc_status = WBC_ERR_INVALID_PARAM;
			BAIL_ON_WBC_ERROR(wbc_status);
		}
		if (params->password.response.nt_length == 0&&
		    params->password.response.nt_data) {
			wbc_status = WBC_ERR_INVALID_PARAM;
			BAIL_ON_WBC_ERROR(wbc_status);
		}

		strncpy(request.data.auth_crap.user,
			params->account_name,
			sizeof(request.data.auth_crap.user)-1);
		if (params->domain_name) {
			strncpy(request.data.auth_crap.domain,
				params->domain_name,
				sizeof(request.data.auth_crap.domain)-1);
		}
		if (params->workstation_name) {
			strncpy(request.data.auth_crap.workstation,
				params->workstation_name,
				sizeof(request.data.auth_crap.workstation)-1);
		}

		request.data.auth_crap.logon_parameters =
				params->parameter_control;

		memcpy(request.data.auth_crap.chal,
		       params->password.response.challenge,
		       sizeof(request.data.auth_crap.chal));

		request.data.auth_crap.lm_resp_len =
				MIN(params->password.response.lm_length,
				    sizeof(request.data.auth_crap.lm_resp));
		request.data.auth_crap.nt_resp_len =
				MIN(params->password.response.nt_length,
				    sizeof(request.data.auth_crap.nt_resp));
		if (params->password.response.lm_data) {
			memcpy(request.data.auth_crap.lm_resp,
			       params->password.response.lm_data,
			       request.data.auth_crap.lm_resp_len);
		}
		if (params->password.response.nt_data) {
			memcpy(request.data.auth_crap.nt_resp,
			       params->password.response.nt_data,
			       request.data.auth_crap.nt_resp_len);
		}
		break;
	default:
		break;
	}

	if (cmd == 0) {
		wbc_status = WBC_ERR_INVALID_PARAM;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	wbc_status = wbcRequestResponse(cmd,
					&request,
					&response);
	if (response.data.auth.nt_status != 0) {
		if (error) {
			wbc_status = wbc_create_error_info(NULL,
							   &response,
							   error);
			BAIL_ON_WBC_ERROR(wbc_status);
		}

		wbc_status = WBC_ERR_AUTH_ERROR;
		BAIL_ON_WBC_ERROR(wbc_status);
	}
	BAIL_ON_WBC_ERROR(wbc_status);

	if (info) {
		wbc_status = wbc_create_auth_info(NULL,
						  &response,
						  info);
		BAIL_ON_WBC_ERROR(wbc_status);
	}

done:
	if (response.extra_data.data)
		free(response.extra_data.data);

	return wbc_status;
}

/** @brief Trigger a verification of the trust credentials of a specific domain
 *
 * @param *domain      The name of the domain, only NULL for the default domain is
 *                     supported yet. Other values than NULL will result in
 *                     WBC_ERR_NOT_IMPLEMENTED.
 * @param error        Output details on WBC_ERR_AUTH_ERROR
 *
 * @return #wbcErr
 *
 **/
wbcErr wbcCheckTrustCredentials(const char *domain,
				struct wbcAuthErrorInfo **error)
{
	struct winbindd_request request;
	struct winbindd_response response;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;

	if (domain) {
		/*
		 * the current protocol doesn't support
		 * specifying a domain
		 */
		wbc_status = WBC_ERR_NOT_IMPLEMENTED;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Send request */

	wbc_status = wbcRequestResponse(WINBINDD_CHECK_MACHACC,
					&request,
					&response);
	if (response.data.auth.nt_status != 0) {
		if (error) {
			wbc_status = wbc_create_error_info(NULL,
							   &response,
							   error);
			BAIL_ON_WBC_ERROR(wbc_status);
		}

		wbc_status = WBC_ERR_AUTH_ERROR;
		BAIL_ON_WBC_ERROR(wbc_status);
	}
	BAIL_ON_WBC_ERROR(wbc_status);

 done:
	return wbc_status;
}
