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
#include "libcli/security/security.h"

NTSTATUS auth3_generate_session_info(struct auth4_context *auth_context,
				     TALLOC_CTX *mem_ctx,
				     void *server_returned_info,
				     const char *original_user_name,
				     uint32_t session_info_flags,
				     struct auth_session_info **session_info)
{
	struct auth_user_info_dc *user_info = NULL;
	struct auth_serversupplied_info *server_info = NULL;
	NTSTATUS nt_status;

	/*
	 * This is a hack, some callers...
	 *
	 * Some callers pass auth_user_info_dc, the SCHANNEL and
	 * NCALRPC_AS_SYSTEM gensec modules.
	 *
	 * While the reset passes auth3_check_password() returned.
	 */
	user_info = talloc_get_type(server_returned_info,
				    struct auth_user_info_dc);
	if (user_info != NULL) {
		const struct dom_sid *sid;
		int cmp;

		/*
		 * This should only be called from SCHANNEL or NCALRPC_AS_SYSTEM
		 */
		if (user_info->num_sids != 1) {
			return NT_STATUS_INTERNAL_ERROR;
		}
		sid = &user_info->sids[PRIMARY_USER_SID_INDEX];

		cmp = dom_sid_compare(sid, &global_sid_System);
		if (cmp == 0) {
			return make_session_info_system(mem_ctx, session_info);
		}

		cmp = dom_sid_compare(sid, &global_sid_Anonymous);
		if (cmp == 0) {
			/*
			 * TODO: use auth_anonymous_session_info() here?
			 */
			return make_session_info_guest(mem_ctx, session_info);
		}

		return NT_STATUS_INTERNAL_ERROR;
	}

	server_info = talloc_get_type_abort(server_returned_info,
					    struct auth_serversupplied_info);
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
	auth_get_ntlm_challenge(auth_context, chal);
	return NT_STATUS_OK;
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

	nt_status = make_user_info_map(talloc_tos(),
                                       &mapped_user_info,
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

	nt_status = auth_check_ntlm_password(mem_ctx,
					     auth_context,
					     mapped_user_info,
					     &server_info);

	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(5,("Checking NTLMSSP password for %s\\%s failed: %s\n",
			 user_info->client.domain_name,
			 user_info->client.account_name,
			 nt_errstr(nt_status)));
	}

	username_was_mapped = mapped_user_info->was_mapped;

	TALLOC_FREE(mapped_user_info);

	if (!NT_STATUS_IS_OK(nt_status)) {
		nt_status = do_map_to_guest_server_info(mem_ctx,
							nt_status,
							user_info->client.account_name,
							user_info->client.domain_name,
							&server_info);
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
