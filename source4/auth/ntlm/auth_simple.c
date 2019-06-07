/* 
   Unix SMB/CIFS implementation.

   auth functions

   Copyright (C) Simo Sorce 2005
   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Andrew Bartlett 2005
   
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
#include <tevent.h>
#include "lib/util/tevent_ntstatus.h"
#include "auth/auth.h"
#include "dsdb/samdb/samdb.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

struct authenticate_ldap_simple_bind_state {
	bool using_tls;
	struct auth4_context *auth_context;
	struct auth_usersupplied_info *user_info;
	struct auth_session_info *session_info;
};

static void authenticate_ldap_simple_bind_done(struct tevent_req *subreq);

_PUBLIC_ struct tevent_req *authenticate_ldap_simple_bind_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct imessaging_context *msg,
					struct loadparm_context *lp_ctx,
					struct tsocket_address *remote_address,
					struct tsocket_address *local_address,
					bool using_tls,
					const char *dn,
					const char *password)
{
	struct tevent_req *req = NULL;
	struct authenticate_ldap_simple_bind_state *state = NULL;
	struct auth_usersupplied_info *user_info = NULL;
	const char *nt4_domain = NULL;
	const char *nt4_username = NULL;
	struct tevent_req *subreq = NULL;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct authenticate_ldap_simple_bind_state);
	if (req == NULL) {
		return NULL;
	}
	state->using_tls = using_tls;

	status = auth_context_create(state, ev, msg, lp_ctx,
				     &state->auth_context);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	user_info = talloc_zero(state, struct auth_usersupplied_info);
	if (tevent_req_nomem(user_info, req)) {
		return tevent_req_post(req, ev);
	}
	state->user_info = user_info;

	user_info->client.account_name = dn;
	/* No client.domain_name, use account_name instead */
	/* user_info->mapped.* will be filled below */

	user_info->workstation_name = NULL;

	user_info->remote_host = remote_address;
	user_info->local_host = local_address;

	user_info->service_description = "LDAP";

	if (using_tls) {
		user_info->auth_description = "simple bind";
	} else {
		user_info->auth_description = "simple bind/TLS";
	}

	user_info->password_state = AUTH_PASSWORD_PLAIN;
	user_info->password.plaintext = talloc_strdup(user_info, password);
	if (tevent_req_nomem(user_info->password.plaintext, req)) {
		return tevent_req_post(req, ev);
	}

	user_info->flags = USER_INFO_CASE_INSENSITIVE_USERNAME |
		USER_INFO_DONT_CHECK_UNIX_ACCOUNT;

	user_info->logon_parameters =
		MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT |
		MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT |
		MSV1_0_CLEARTEXT_PASSWORD_ALLOWED |
		MSV1_0_CLEARTEXT_PASSWORD_SUPPLIED;

	status = crack_auto_name_to_nt4_name(state, state->auth_context->sam_ctx,
					     dn, &nt4_domain, &nt4_username);
	if (!NT_STATUS_IS_OK(status)) {
		log_authentication_event(msg, lp_ctx,
					 &state->auth_context->start_time,
					 user_info, status,
					 NULL, NULL, NULL);
	}
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	user_info->mapped.account_name = nt4_username;
	user_info->mapped.domain_name = nt4_domain;
	user_info->mapped_state = true;

	subreq = auth_check_password_send(state, ev,
					  state->auth_context,
					  state->user_info);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, authenticate_ldap_simple_bind_done, req);

	return req;
}

static void authenticate_ldap_simple_bind_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct authenticate_ldap_simple_bind_state *state =
		tevent_req_data(req,
		struct authenticate_ldap_simple_bind_state);
	struct auth4_context *auth_context = state->auth_context;
	struct auth_usersupplied_info *user_info = state->user_info;
	const char *nt4_username = user_info->mapped.account_name;
	const struct tsocket_address *remote_address = user_info->remote_host;
	const struct tsocket_address *local_address = user_info->local_host;
	const char *transport_protection = AUTHZ_TRANSPORT_PROTECTION_NONE;
	struct auth_user_info_dc *user_info_dc = NULL;
	uint8_t authoritative = 0;
	uint32_t flags = 0;
	NTSTATUS nt_status;

	if (state->using_tls) {
		transport_protection = AUTHZ_TRANSPORT_PROTECTION_TLS;
	}

	nt_status = auth_check_password_recv(subreq, state,
					     &user_info_dc,
					     &authoritative);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, nt_status)) {
		return;
	}

	flags = AUTH_SESSION_INFO_DEFAULT_GROUPS;
	if (user_info_dc->info->authenticated) {
		flags |= AUTH_SESSION_INFO_AUTHENTICATED;
	}

	nt_status = auth_context->generate_session_info(auth_context,
							state,
							user_info_dc,
							nt4_username,
							flags,
							&state->session_info);
	if (tevent_req_nterror(req, nt_status)) {
		return;
	}

	log_successful_authz_event(auth_context->msg_ctx,
				   auth_context->lp_ctx,
				   remote_address,
				   local_address,
				   "LDAP",
				   "simple bind",
				   transport_protection,
				   state->session_info);

	tevent_req_done(req);
}

_PUBLIC_ NTSTATUS authenticate_ldap_simple_bind_recv(struct tevent_req *req,
					TALLOC_CTX *mem_ctx,
					struct auth_session_info **session_info)
{
	struct authenticate_ldap_simple_bind_state *state =
		tevent_req_data(req,
		struct authenticate_ldap_simple_bind_state);
	NTSTATUS status;

	*session_info = NULL;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*session_info = talloc_move(mem_ctx, &state->session_info);
	tevent_req_received(req);
	return NT_STATUS_OK;
}
