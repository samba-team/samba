/*
   Unix SMB/Netbios implementation.
   Version 3.0
   handle NLTMSSP, client server side parsing

   Copyright (C) Andrew Tridgell      2001
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2001-2005
   Copyright (C) Stefan Metzmacher 2005

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
#include "system/network.h"
#include "lib/tsocket/tsocket.h"
#include "auth/ntlmssp/ntlmssp.h"
#include "../librpc/gen_ndr/ndr_ntlmssp.h"
#include "auth/ntlmssp/ntlmssp_ndr.h"
#include "auth/ntlmssp/ntlmssp_private.h"
#include "../libcli/auth/libcli_auth.h"
#include "../lib/crypto/crypto.h"
#include "auth/gensec/gensec.h"
#include "auth/common_auth.h"
#include "param/param.h"


/**
 * Return the challenge as determined by the authentication subsystem
 * @return an 8 byte random challenge
 */

static NTSTATUS auth_ntlmssp_get_challenge(const struct ntlmssp_state *ntlmssp_state,
					   uint8_t chal[8])
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(ntlmssp_state->callback_private,
				      struct gensec_ntlmssp_context);
	struct auth4_context *auth_context = gensec_ntlmssp->gensec_security->auth_context;
	NTSTATUS status = NT_STATUS_NOT_IMPLEMENTED;

	if (auth_context->get_ntlm_challenge) {
		status = auth_context->get_ntlm_challenge(auth_context, chal);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("auth_ntlmssp_get_challenge: failed to get challenge: %s\n",
				  nt_errstr(status)));
			return status;
		}
	}

	return status;
}

/**
 * Some authentication methods 'fix' the challenge, so we may not be able to set it
 *
 * @return If the effective challenge used by the auth subsystem may be modified
 */
static bool auth_ntlmssp_may_set_challenge(const struct ntlmssp_state *ntlmssp_state)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(ntlmssp_state->callback_private,
				      struct gensec_ntlmssp_context);
	struct auth4_context *auth_context = gensec_ntlmssp->gensec_security->auth_context;

	if (auth_context->challenge_may_be_modified) {
		return auth_context->challenge_may_be_modified(auth_context);
	}
	return false;
}

/**
 * NTLM2 authentication modifies the effective challenge,
 * @param challenge The new challenge value
 */
static NTSTATUS auth_ntlmssp_set_challenge(struct ntlmssp_state *ntlmssp_state, DATA_BLOB *challenge)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(ntlmssp_state->callback_private,
				      struct gensec_ntlmssp_context);
	struct auth4_context *auth_context = gensec_ntlmssp->gensec_security->auth_context;
	NTSTATUS nt_status = NT_STATUS_NOT_IMPLEMENTED;
	const uint8_t *chal;

	if (challenge->length != 8) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	chal = challenge->data;

	if (auth_context->set_ntlm_challenge) {
		nt_status = auth_context->set_ntlm_challenge(auth_context,
							chal,
							"NTLMSSP callback (NTLM2)");
	}
	return nt_status;
}

/**
 * Check the password on an NTLMSSP login.
 *
 * Return the session keys used on the connection.
 */

static NTSTATUS auth_ntlmssp_check_password(struct ntlmssp_state *ntlmssp_state,
					    TALLOC_CTX *mem_ctx,
					    DATA_BLOB *user_session_key, DATA_BLOB *lm_session_key)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(ntlmssp_state->callback_private,
				      struct gensec_ntlmssp_context);
	struct auth4_context *auth_context = gensec_ntlmssp->gensec_security->auth_context;
	NTSTATUS nt_status = NT_STATUS_NOT_IMPLEMENTED;
	struct auth_usersupplied_info *user_info;

	user_info = talloc_zero(ntlmssp_state, struct auth_usersupplied_info);
	if (!user_info) {
		return NT_STATUS_NO_MEMORY;
	}

	user_info->logon_parameters = MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT | MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT;
	user_info->flags = 0;
	user_info->mapped_state = false;
	user_info->client.account_name = ntlmssp_state->user;
	user_info->client.domain_name = ntlmssp_state->domain;
	user_info->workstation_name = ntlmssp_state->client.netbios_name;
	user_info->remote_host = gensec_get_remote_address(gensec_ntlmssp->gensec_security);

	user_info->password_state = AUTH_PASSWORD_RESPONSE;
	user_info->password.response.lanman = ntlmssp_state->lm_resp;
	user_info->password.response.lanman.data = talloc_steal(user_info, ntlmssp_state->lm_resp.data);
	user_info->password.response.nt = ntlmssp_state->nt_resp;
	user_info->password.response.nt.data = talloc_steal(user_info, ntlmssp_state->nt_resp.data);

	if (auth_context->check_ntlm_password) {
		nt_status = auth_context->check_ntlm_password(auth_context,
							      gensec_ntlmssp,
							      user_info,
							      &gensec_ntlmssp->server_returned_info,
							      user_session_key, lm_session_key);
	}
	talloc_free(user_info);

	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(5,("%s: Checking NTLMSSP password for %s\\%s failed: %s\n",
			 __location__,
			 user_info->client.domain_name,
			 user_info->client.account_name,
			 nt_errstr(nt_status)));
	}

	NT_STATUS_NOT_OK_RETURN(nt_status);

	talloc_steal(mem_ctx, user_session_key->data);
	talloc_steal(mem_ctx, lm_session_key->data);

	return nt_status;
}

/**
 * Return the credentials of a logged on user, including session keys
 * etc.
 *
 * Only valid after a successful authentication
 *
 * May only be called once per authentication.
 *
 */

NTSTATUS gensec_ntlmssp_session_info(struct gensec_security *gensec_security,
				     TALLOC_CTX *mem_ctx,
				     struct auth_session_info **session_info)
{
	NTSTATUS nt_status;
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(gensec_security->private_data,
				      struct gensec_ntlmssp_context);
	uint32_t session_info_flags = 0;

	if (gensec_security->want_features & GENSEC_FEATURE_UNIX_TOKEN) {
		session_info_flags |= AUTH_SESSION_INFO_UNIX_TOKEN;
	}

	session_info_flags |= AUTH_SESSION_INFO_DEFAULT_GROUPS;

	if (gensec_security->auth_context && gensec_security->auth_context->generate_session_info) {
		nt_status = gensec_security->auth_context->generate_session_info(gensec_security->auth_context, mem_ctx, 
										 gensec_ntlmssp->server_returned_info,
										 gensec_ntlmssp->ntlmssp_state->user,
										 session_info_flags,
										 session_info);
	} else {
		DEBUG(0, ("Cannot generate a session_info without the auth_context\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	NT_STATUS_NOT_OK_RETURN(nt_status);

	nt_status = gensec_ntlmssp_session_key(gensec_security, *session_info,
					       &(*session_info)->session_key);
	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_USER_SESSION_KEY)) {
		(*session_info)->session_key = data_blob_null;
		nt_status = NT_STATUS_OK;
	}

	return nt_status;
}

/**
 * Start NTLMSSP on the server side
 *
 */
NTSTATUS gensec_ntlmssp_server_start(struct gensec_security *gensec_security)
{
	NTSTATUS nt_status;
	struct ntlmssp_state *ntlmssp_state;
	struct gensec_ntlmssp_context *gensec_ntlmssp;
	const char *netbios_name;
	const char *netbios_domain;
	const char *dns_name;
	const char *dns_domain;

	nt_status = gensec_ntlmssp_start(gensec_security);
	NT_STATUS_NOT_OK_RETURN(nt_status);

	gensec_ntlmssp =
		talloc_get_type_abort(gensec_security->private_data,
				      struct gensec_ntlmssp_context);

	ntlmssp_state = talloc_zero(gensec_ntlmssp,
				    struct ntlmssp_state);
	if (!ntlmssp_state) {
		return NT_STATUS_NO_MEMORY;
	}
	gensec_ntlmssp->ntlmssp_state = ntlmssp_state;

	ntlmssp_state->callback_private = gensec_ntlmssp;

	ntlmssp_state->role = NTLMSSP_SERVER;

	ntlmssp_state->expected_state = NTLMSSP_NEGOTIATE;

	if (lpcfg_lanman_auth(gensec_security->settings->lp_ctx) &&
	    gensec_setting_bool(gensec_security->settings,
				"ntlmssp_server", "allow_lm_key", false))
	{
		ntlmssp_state->allow_lm_key = true;
	}

	ntlmssp_state->neg_flags =
		NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_VERSION;

	if (gensec_setting_bool(gensec_security->settings, "ntlmssp_server", "128bit", true)) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_128;
	}

	if (gensec_setting_bool(gensec_security->settings, "ntlmssp_server", "56bit", true)) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_56;
	}

	if (gensec_setting_bool(gensec_security->settings, "ntlmssp_server", "keyexchange", true)) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_KEY_EXCH;
	}

	if (gensec_setting_bool(gensec_security->settings, "ntlmssp_server", "alwayssign", true)) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
	}

	if (gensec_setting_bool(gensec_security->settings, "ntlmssp_server", "ntlm2", true)) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_NTLM2;
	}

	if (gensec_security->want_features & GENSEC_FEATURE_SESSION_KEY) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
	}
	if (gensec_security->want_features & GENSEC_FEATURE_SIGN) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
	}
	if (gensec_security->want_features & GENSEC_FEATURE_SEAL) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SEAL;
	}

	ntlmssp_state->get_challenge = auth_ntlmssp_get_challenge;
	ntlmssp_state->may_set_challenge = auth_ntlmssp_may_set_challenge;
	ntlmssp_state->set_challenge = auth_ntlmssp_set_challenge;
	ntlmssp_state->check_password = auth_ntlmssp_check_password;

	if (lpcfg_server_role(gensec_security->settings->lp_ctx) == ROLE_STANDALONE) {
		ntlmssp_state->server.is_standalone = true;
	} else {
		ntlmssp_state->server.is_standalone = false;
	}

	if (gensec_security->settings->server_netbios_name) {
		netbios_name = gensec_security->settings->server_netbios_name;
	} else {
		netbios_name = lpcfg_netbios_name(gensec_security->settings->lp_ctx);
	}

	if (gensec_security->settings->server_netbios_domain) {
		netbios_domain = gensec_security->settings->server_netbios_domain;
	} else {
		netbios_domain = lpcfg_workgroup(gensec_security->settings->lp_ctx);
	}

	if (gensec_security->settings->server_dns_name) {
		dns_name = gensec_security->settings->server_dns_name;
	} else {
		const char *dnsdomain = lpcfg_dnsdomain(gensec_security->settings->lp_ctx);
		char *lower_netbiosname;

		lower_netbiosname = strlower_talloc(ntlmssp_state, netbios_name);
		NT_STATUS_HAVE_NO_MEMORY(lower_netbiosname);

		/* Find out the DNS host name */
		if (dnsdomain && dnsdomain[0] != '\0') {
			dns_name = talloc_asprintf(ntlmssp_state, "%s.%s",
						   lower_netbiosname,
						   dnsdomain);
			talloc_free(lower_netbiosname);
			NT_STATUS_HAVE_NO_MEMORY(dns_name);
		} else {
			dns_name = lower_netbiosname;
		}
	}

	if (gensec_security->settings->server_dns_domain) {
		dns_domain = gensec_security->settings->server_dns_domain;
	} else {
		dns_domain = lpcfg_dnsdomain(gensec_security->settings->lp_ctx);
	}

	ntlmssp_state->server.netbios_name = talloc_strdup(ntlmssp_state, netbios_name);
	NT_STATUS_HAVE_NO_MEMORY(ntlmssp_state->server.netbios_name);

	ntlmssp_state->server.netbios_domain = talloc_strdup(ntlmssp_state, netbios_domain);
	NT_STATUS_HAVE_NO_MEMORY(ntlmssp_state->server.netbios_domain);

	ntlmssp_state->server.dns_name = talloc_strdup(ntlmssp_state, dns_name);
	NT_STATUS_HAVE_NO_MEMORY(ntlmssp_state->server.dns_name);

	ntlmssp_state->server.dns_domain = talloc_strdup(ntlmssp_state, dns_domain);
	NT_STATUS_HAVE_NO_MEMORY(ntlmssp_state->server.dns_domain);

	return NT_STATUS_OK;
}

