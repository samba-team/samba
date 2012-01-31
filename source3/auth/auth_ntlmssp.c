/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   handle NLTMSSP, server side

   Copyright (C) Andrew Tridgell      2001
   Copyright (C) Andrew Bartlett 2001-2005,2011
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
#include "auth.h"
#include "../auth/ntlmssp/ntlmssp.h"
#include "../auth/ntlmssp/ntlmssp_private.h"
#include "../librpc/gen_ndr/netlogon.h"
#include "../librpc/gen_ndr/dcerpc.h"
#include "../lib/tsocket/tsocket.h"
#include "auth/gensec/gensec.h"
#include "librpc/rpc/dcerpc.h"
#include "lib/param/param.h"

NTSTATUS auth3_generate_session_info(TALLOC_CTX *mem_ctx,
				     struct auth4_context *auth_context,
				     void *server_returned_info,
				     const char *original_user_name,
				     uint32_t session_info_flags,
				     struct auth_session_info **session_info)
{
	struct auth_serversupplied_info *server_info = talloc_get_type_abort(server_returned_info,
									     struct auth_serversupplied_info);
	NTSTATUS nt_status;

	nt_status = create_local_token(mem_ctx,
				       server_info,
				       NULL,
				       original_user_name,
				       session_info);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(10, ("create_local_token failed: %s\n",
			   nt_errstr(nt_status)));
		return nt_status;
	}

	return NT_STATUS_OK;
}

/**
 * Return the challenge as determined by the authentication subsystem 
 * @return an 8 byte random challenge
 */

NTSTATUS auth3_get_challenge(struct auth4_context *auth4_context,
					   uint8_t chal[8])
{
	struct auth_context *auth_context = talloc_get_type_abort(auth4_context->private_data,
								  struct auth_context);
	auth_context->get_ntlm_challenge(auth_context, chal);
	return NT_STATUS_OK;
}

/**
 * Some authentication methods 'fix' the challenge, so we may not be able to set it
 *
 * @return If the effective challenge used by the auth subsystem may be modified
 */
bool auth3_may_set_challenge(struct auth4_context *auth4_context)
{
	struct auth_context *auth_context = talloc_get_type_abort(auth4_context->private_data,
								  struct auth_context);
	return auth_context->challenge_may_be_modified;
}

/**
 * NTLM2 authentication modifies the effective challenge, 
 * @param challenge The new challenge value
 */
NTSTATUS auth3_set_challenge(struct auth4_context *auth4_context, const uint8_t *chal,
			     const char *challenge_set_by)
{
	struct auth_context *auth_context = talloc_get_type_abort(auth4_context->private_data,
								  struct auth_context);

	auth_context->challenge = data_blob_talloc(auth_context,
						   chal, 8);
	NT_STATUS_HAVE_NO_MEMORY(auth_context->challenge.data);

	auth_context->challenge_set_by = talloc_strdup(auth_context, challenge_set_by);
	NT_STATUS_HAVE_NO_MEMORY(auth_context->challenge_set_by);

	DEBUG(5, ("auth_context challenge set by %s\n", auth_context->challenge_set_by));
	DEBUG(5, ("challenge is: \n"));
	dump_data(5, auth_context->challenge.data, auth_context->challenge.length);
	return NT_STATUS_OK;
}

/**
 * Check the password on an NTLMSSP login.  
 *
 * Return the session keys used on the connection.
 */

NTSTATUS auth3_check_password(struct auth4_context *auth4_context,
			      TALLOC_CTX *mem_ctx,
			      const struct auth_usersupplied_info *user_info,
			      void **server_returned_info,
			      DATA_BLOB *session_key, DATA_BLOB *lm_session_key)
{
	struct auth_context *auth_context = talloc_get_type_abort(auth4_context->private_data,
								  struct auth_context);
	struct auth_usersupplied_info *mapped_user_info = NULL;
	struct auth_serversupplied_info *server_info;
	NTSTATUS nt_status;
	bool username_was_mapped;

	/* The client has given us its machine name (which we only get over NBT transport).
	   We need to possibly reload smb.conf if smb.conf includes depend on the machine name. */

	set_remote_machine_name(user_info->workstation_name, True);

	/* setup the string used by %U */
	/* sub_set_smb_name checks for weird internally */
	sub_set_smb_name(user_info->client.account_name);

	lp_load(get_dyn_CONFIGFILE(), false, false, true, true);

	nt_status = make_user_info_map(&mapped_user_info,
				       user_info->client.account_name,
				       user_info->client.domain_name,
				       user_info->workstation_name,
				       user_info->remote_host,
	                               user_info->password.response.lanman.data ? &user_info->password.response.lanman : NULL,
	                               user_info->password.response.nt.data ? &user_info->password.response.nt : NULL,
				       NULL, NULL, NULL,
				       AUTH_PASSWORD_RESPONSE);

	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	mapped_user_info->logon_parameters = user_info->logon_parameters;

	mapped_user_info->flags = user_info->flags;

	nt_status = auth_context->check_ntlm_password(auth_context,
						      mapped_user_info, &server_info);

	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(5,("Checking NTLMSSP password for %s\\%s failed: %s\n",
			 user_info->client.domain_name,
			 user_info->client.account_name,
			 nt_errstr(nt_status)));
	}

	username_was_mapped = mapped_user_info->was_mapped;

	free_user_info(&mapped_user_info);

	if (!NT_STATUS_IS_OK(nt_status)) {
		nt_status = do_map_to_guest_server_info(nt_status,
							&server_info,
							user_info->client.account_name,
							user_info->client.domain_name);
		*server_returned_info = talloc_steal(mem_ctx, server_info);
		return nt_status;
	}

	server_info->nss_token |= username_was_mapped;

	/* Clear out the session keys, and pass them to the caller.
	 * They will not be used in this form again - instead the
	 * NTLMSSP code will decide on the final correct session key,
	 * and supply it to create_local_token() */
	if (session_key) {
		DEBUG(10, ("Got NT session key of length %u\n",
			(unsigned int)server_info->session_key.length));
		*session_key = server_info->session_key;
		talloc_steal(mem_ctx, server_info->session_key.data);
		server_info->session_key = data_blob_null;
	}
	if (lm_session_key) {
		DEBUG(10, ("Got LM session key of length %u\n",
			(unsigned int)server_info->lm_session_key.length));
		*lm_session_key = server_info->lm_session_key;
		talloc_steal(mem_ctx, server_info->lm_session_key.data);
		server_info->lm_session_key = data_blob_null;
	}

	*server_returned_info = talloc_steal(mem_ctx, server_info);
	return nt_status;
}

static NTSTATUS gensec_ntlmssp3_server_start(struct gensec_security *gensec_security)
{
	NTSTATUS nt_status;
	bool is_standalone;
	const char *netbios_name;
	const char *netbios_domain;
	const char *dns_name;
	char *dns_domain;
	struct gensec_ntlmssp_context *gensec_ntlmssp;
	struct ntlmssp_state *ntlmssp_state;

	if ((enum server_role)lp_server_role() == ROLE_STANDALONE) {
		is_standalone = true;
	} else {
		is_standalone = false;
	}

	netbios_name = lp_netbios_name();
	netbios_domain = lp_workgroup();
	/* This should be a 'netbios domain -> DNS domain' mapping */
	dns_domain = get_mydnsdomname(talloc_tos());
	if (dns_domain) {
		strlower_m(dns_domain);
	}
	dns_name = get_mydnsfullname();

	nt_status = gensec_ntlmssp_start(gensec_security);
	NT_STATUS_NOT_OK_RETURN(nt_status);

	gensec_ntlmssp =
		talloc_get_type_abort(gensec_security->private_data,
				      struct gensec_ntlmssp_context);

	if (!netbios_name) {
		netbios_name = "";
	}

	if (!netbios_domain) {
		netbios_domain = "";
	}

	if (!dns_domain) {
		dns_domain = "";
	}

	if (!dns_name) {
		dns_name = "";
	}

	ntlmssp_state = talloc_zero(gensec_ntlmssp, struct ntlmssp_state);
	if (!ntlmssp_state) {
		return NT_STATUS_NO_MEMORY;
	}
	gensec_ntlmssp->ntlmssp_state = ntlmssp_state;

	ntlmssp_state->callback_private = gensec_ntlmssp;

	ntlmssp_state->role = NTLMSSP_SERVER;

	ntlmssp_state->server.is_standalone = is_standalone;

	ntlmssp_state->expected_state = NTLMSSP_NEGOTIATE;

	if (lpcfg_lanman_auth(gensec_security->settings->lp_ctx) &&
	    gensec_setting_bool(gensec_security->settings,
				"ntlmssp_server", "allow_lm_key", false))
	{
		ntlmssp_state->allow_lm_key = true;
	}

	ntlmssp_state->neg_flags =
		NTLMSSP_NEGOTIATE_128 |
		NTLMSSP_NEGOTIATE_56 |
		NTLMSSP_NEGOTIATE_VERSION |
		NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
		NTLMSSP_NEGOTIATE_NTLM |
		NTLMSSP_NEGOTIATE_NTLM2 |
		NTLMSSP_NEGOTIATE_KEY_EXCH;

	ntlmssp_state->server.netbios_name = talloc_strdup(ntlmssp_state, netbios_name);
	if (!ntlmssp_state->server.netbios_name) {
		talloc_free(ntlmssp_state);
		return NT_STATUS_NO_MEMORY;
	}
	ntlmssp_state->server.netbios_domain = talloc_strdup(ntlmssp_state, netbios_domain);
	if (!ntlmssp_state->server.netbios_domain) {
		talloc_free(ntlmssp_state);
		return NT_STATUS_NO_MEMORY;
	}
	ntlmssp_state->server.dns_name = talloc_strdup(ntlmssp_state, dns_name);
	if (!ntlmssp_state->server.dns_name) {
		return NT_STATUS_NO_MEMORY;
	}
	ntlmssp_state->server.dns_domain = talloc_strdup(ntlmssp_state, dns_domain);
	if (!ntlmssp_state->server.dns_domain) {
		return NT_STATUS_NO_MEMORY;
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

	return NT_STATUS_OK;
}

static const char *gensec_ntlmssp3_server_oids[] = {
	GENSEC_OID_NTLMSSP,
	NULL
};

const struct gensec_security_ops gensec_ntlmssp3_server_ops = {
	.name		= "ntlmssp3_server",
	.sasl_name	= GENSEC_SASL_NAME_NTLMSSP, /* "NTLM" */
	.auth_type	= DCERPC_AUTH_TYPE_NTLMSSP,
	.oid            = gensec_ntlmssp3_server_oids,
	.server_start   = gensec_ntlmssp3_server_start,
	.magic 	        = gensec_ntlmssp_magic,
	.update 	= gensec_ntlmssp_update,
	.sig_size	= gensec_ntlmssp_sig_size,
	.sign_packet	= gensec_ntlmssp_sign_packet,
	.check_packet	= gensec_ntlmssp_check_packet,
	.seal_packet	= gensec_ntlmssp_seal_packet,
	.unseal_packet	= gensec_ntlmssp_unseal_packet,
	.wrap           = gensec_ntlmssp_wrap,
	.unwrap         = gensec_ntlmssp_unwrap,
	.session_key	= gensec_ntlmssp_session_key,
	.session_info   = gensec_ntlmssp_session_info,
	.have_feature   = gensec_ntlmssp_have_feature,
	.enabled        = true,
	.priority       = GENSEC_NTLMSSP
};

