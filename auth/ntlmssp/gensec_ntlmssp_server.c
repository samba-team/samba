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
#include "auth/gensec/gensec_internal.h"
#include "auth/common_auth.h"
#include "param/param.h"
#include "param/loadparm.h"
#include "libds/common/roles.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

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
	session_info_flags |= AUTH_SESSION_INFO_NTLM;

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
	enum server_role role;

	role = lpcfg_server_role(gensec_security->settings->lp_ctx);

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

	ntlmssp_state->role = NTLMSSP_SERVER;

	ntlmssp_state->expected_state = NTLMSSP_NEGOTIATE;

	ntlmssp_state->allow_lm_response =
		lpcfg_lanman_auth(gensec_security->settings->lp_ctx);

	if (ntlmssp_state->allow_lm_response &&
	    gensec_setting_bool(gensec_security->settings,
				"ntlmssp_server", "allow_lm_key", false))
	{
		ntlmssp_state->allow_lm_key = true;
	}

	ntlmssp_state->force_old_spnego = false;

	if (gensec_setting_bool(gensec_security->settings, "ntlmssp_server", "force_old_spnego", false)) {
		/*
		 * For testing Windows 2000 mode
		 */
		ntlmssp_state->force_old_spnego = true;
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

	if (ntlmssp_state->allow_lm_key) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_LM_KEY;
	}

	/*
	 * We always allow NTLMSSP_NEGOTIATE_SIGN and NTLMSSP_NEGOTIATE_SEAL.
	 *
	 * These will be removed if the client doesn't want them.
	 */
	ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
	ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SEAL;

	if (gensec_security->want_features & GENSEC_FEATURE_SESSION_KEY) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
	}
	if (gensec_security->want_features & GENSEC_FEATURE_SIGN) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;

		if (gensec_security->want_features & GENSEC_FEATURE_LDAP_STYLE) {
			/*
			 * We need to handle NTLMSSP_NEGOTIATE_SIGN as
			 * NTLMSSP_NEGOTIATE_SEAL if GENSEC_FEATURE_LDAP_STYLE
			 * is requested.
			 */
			ntlmssp_state->force_wrap_seal = true;
		}
	}
	if (gensec_security->want_features & GENSEC_FEATURE_SEAL) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SEAL;
	}

	if (role == ROLE_STANDALONE) {
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

	ntlmssp_state->neg_flags |= ntlmssp_state->required_flags;
	ntlmssp_state->conf_flags = ntlmssp_state->neg_flags;

	return NT_STATUS_OK;
}

