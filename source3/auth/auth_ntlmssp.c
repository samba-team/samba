/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   handle NLTMSSP, server side

   Copyright (C) Andrew Tridgell      2001
   Copyright (C) Andrew Bartlett 2001-2003,2011

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
#include "../librpc/gen_ndr/netlogon.h"
#include "../librpc/gen_ndr/dcerpc.h"
#include "../lib/tsocket/tsocket.h"
#include "auth/gensec/gensec.h"
#include "librpc/rpc/dcerpc.h"
#include "lib/param/param.h"

static NTSTATUS gensec_ntlmssp3_server_session_info(struct gensec_security *gensec_security,
					TALLOC_CTX *mem_ctx,
					struct auth_session_info **session_info)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(gensec_security->private_data,
				      struct gensec_ntlmssp_context);
	struct auth_serversupplied_info *server_info = talloc_get_type_abort(gensec_ntlmssp->server_returned_info, 
									     struct auth_serversupplied_info);
	NTSTATUS nt_status;

	nt_status = create_local_token(mem_ctx,
				       server_info,
				       &gensec_ntlmssp->ntlmssp_state->session_key,
				       gensec_ntlmssp->ntlmssp_state->user,
				       session_info);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(10, ("create_local_token failed: %s\n",
			   nt_errstr(nt_status)));
		return nt_status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS gensec_ntlmssp3_server_update(struct gensec_security *gensec_security,
					      TALLOC_CTX *out_mem_ctx,
					      struct tevent_context *ev,
					      const DATA_BLOB request,
					      DATA_BLOB *reply)
{
	NTSTATUS status;
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(gensec_security->private_data,
				      struct gensec_ntlmssp_context);

	status = ntlmssp_update(gensec_ntlmssp->ntlmssp_state, request, reply);
	if (NT_STATUS_IS_OK(status) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		talloc_steal(out_mem_ctx, reply->data);
	}

	return status;
}

/**
 * Return the challenge as determined by the authentication subsystem 
 * @return an 8 byte random challenge
 */

static NTSTATUS auth_ntlmssp_get_challenge(const struct ntlmssp_state *ntlmssp_state,
					   uint8_t chal[8])
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		(struct gensec_ntlmssp_context *)ntlmssp_state->callback_private;
	gensec_ntlmssp->auth_context->get_ntlm_challenge(
		gensec_ntlmssp->auth_context, chal);
	return NT_STATUS_OK;
}

/**
 * Some authentication methods 'fix' the challenge, so we may not be able to set it
 *
 * @return If the effective challenge used by the auth subsystem may be modified
 */
static bool auth_ntlmssp_may_set_challenge(const struct ntlmssp_state *ntlmssp_state)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		(struct gensec_ntlmssp_context *)ntlmssp_state->callback_private;
	struct auth_context *auth_context = gensec_ntlmssp->auth_context;

	return auth_context->challenge_may_be_modified;
}

/**
 * NTLM2 authentication modifies the effective challenge, 
 * @param challenge The new challenge value
 */
static NTSTATUS auth_ntlmssp_set_challenge(struct ntlmssp_state *ntlmssp_state, DATA_BLOB *challenge)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		(struct gensec_ntlmssp_context *)ntlmssp_state->callback_private;
	struct auth_context *auth_context = gensec_ntlmssp->auth_context;

	SMB_ASSERT(challenge->length == 8);

	auth_context->challenge = data_blob_talloc(auth_context,
						   challenge->data, challenge->length);

	auth_context->challenge_set_by = "NTLMSSP callback (NTLM2)";

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

static NTSTATUS auth_ntlmssp_check_password(struct ntlmssp_state *ntlmssp_state, TALLOC_CTX *mem_ctx,
					    DATA_BLOB *session_key, DATA_BLOB *lm_session_key)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		(struct gensec_ntlmssp_context *)ntlmssp_state->callback_private;
	struct auth_usersupplied_info *user_info = NULL;
	struct auth_serversupplied_info *server_info;
	NTSTATUS nt_status;
	bool username_was_mapped;

	/* The client has given us its machine name (which we only get over NBT transport).
	   We need to possibly reload smb.conf if smb.conf includes depend on the machine name. */

	set_remote_machine_name(gensec_ntlmssp->ntlmssp_state->client.netbios_name, True);

	/* setup the string used by %U */
	/* sub_set_smb_name checks for weird internally */
	sub_set_smb_name(gensec_ntlmssp->ntlmssp_state->user);

	lp_load(get_dyn_CONFIGFILE(), false, false, true, true);

	nt_status = make_user_info_map(&user_info,
				       gensec_ntlmssp->ntlmssp_state->user,
				       gensec_ntlmssp->ntlmssp_state->domain,
				       gensec_ntlmssp->ntlmssp_state->client.netbios_name,
				       gensec_get_remote_address(gensec_ntlmssp->gensec_security),
	                               gensec_ntlmssp->ntlmssp_state->lm_resp.data ? &gensec_ntlmssp->ntlmssp_state->lm_resp : NULL,
	                               gensec_ntlmssp->ntlmssp_state->nt_resp.data ? &gensec_ntlmssp->ntlmssp_state->nt_resp : NULL,
				       NULL, NULL, NULL,
				       AUTH_PASSWORD_RESPONSE);

	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	user_info->logon_parameters = MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT | MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT;

	nt_status = gensec_ntlmssp->auth_context->check_ntlm_password(gensec_ntlmssp->auth_context,
									  user_info, &server_info);

	username_was_mapped = user_info->was_mapped;

	free_user_info(&user_info);

	if (!NT_STATUS_IS_OK(nt_status)) {
		nt_status = do_map_to_guest_server_info(nt_status,
							&server_info,
							gensec_ntlmssp->ntlmssp_state->user,
							gensec_ntlmssp->ntlmssp_state->domain);
		gensec_ntlmssp->server_returned_info = server_info;
		return nt_status;
	}

	server_info->nss_token |= username_was_mapped;

	/* Clear out the session keys, and pass them to the caller.
	 * They will not be used in this form again - instead the
	 * NTLMSSP code will decide on the final correct session key,
	 * and supply it to create_local_token() */
	if (server_info->session_key.length) {
		DEBUG(10, ("Got NT session key of length %u\n",
			(unsigned int)server_info->session_key.length));
		*session_key = server_info->session_key;
		talloc_steal(mem_ctx, server_info->session_key.data);
		server_info->session_key = data_blob_null;
	}
	if (server_info->lm_session_key.length) {
		DEBUG(10, ("Got LM session key of length %u\n",
			(unsigned int)server_info->lm_session_key.length));
		*lm_session_key = server_info->lm_session_key;
		talloc_steal(mem_ctx, server_info->lm_session_key.data);
		server_info->lm_session_key = data_blob_null;
	}
	gensec_ntlmssp->server_returned_info = server_info;
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

	nt_status = make_auth_context_subsystem(gensec_ntlmssp, &gensec_ntlmssp->auth_context);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	nt_status = ntlmssp_server_start(gensec_ntlmssp,
					 is_standalone,
					 netbios_name,
					 netbios_domain,
					 dns_name,
					 dns_domain,
					 &gensec_ntlmssp->ntlmssp_state);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	gensec_ntlmssp->ntlmssp_state->callback_private = gensec_ntlmssp;

	gensec_ntlmssp->ntlmssp_state->get_challenge = auth_ntlmssp_get_challenge;
	gensec_ntlmssp->ntlmssp_state->may_set_challenge = auth_ntlmssp_may_set_challenge;
	gensec_ntlmssp->ntlmssp_state->set_challenge = auth_ntlmssp_set_challenge;
	gensec_ntlmssp->ntlmssp_state->check_password = auth_ntlmssp_check_password;

	if (gensec_ntlmssp->gensec_security->want_features & GENSEC_FEATURE_SESSION_KEY) {
		gensec_ntlmssp->ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
	}
	if (gensec_ntlmssp->gensec_security->want_features & GENSEC_FEATURE_SIGN) {
		gensec_ntlmssp->ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
	}
	if (gensec_ntlmssp->gensec_security->want_features & GENSEC_FEATURE_SEAL) {
		gensec_ntlmssp->ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
		gensec_ntlmssp->ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SEAL;
	}

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
	.update 	= gensec_ntlmssp3_server_update,
	.sig_size	= gensec_ntlmssp_sig_size,
	.sign_packet	= gensec_ntlmssp_sign_packet,
	.check_packet	= gensec_ntlmssp_check_packet,
	.seal_packet	= gensec_ntlmssp_seal_packet,
	.unseal_packet	= gensec_ntlmssp_unseal_packet,
	.wrap           = gensec_ntlmssp_wrap,
	.unwrap         = gensec_ntlmssp_unwrap,
	.session_key	= gensec_ntlmssp_session_key,
	.session_info   = gensec_ntlmssp3_server_session_info,
	.have_feature   = gensec_ntlmssp_have_feature,
	.enabled        = true,
	.priority       = GENSEC_NTLMSSP
};

