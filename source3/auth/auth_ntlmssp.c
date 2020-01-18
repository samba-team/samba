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
#include "lib/util/tevent_ntstatus.h"

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
			return make_session_info_anonymous(mem_ctx, session_info);
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

struct auth3_check_password_state {
	uint8_t authoritative;
	void *server_info;
	DATA_BLOB nt_session_key;
	DATA_BLOB lm_session_key;
};

struct tevent_req *auth3_check_password_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct auth4_context *auth4_context,
	const struct auth_usersupplied_info *user_info)
{
	struct tevent_req *req = NULL;
	struct auth3_check_password_state *state = NULL;
	struct auth_context *auth_context = talloc_get_type_abort(
		auth4_context->private_data, struct auth_context);
	struct auth_usersupplied_info *mapped_user_info = NULL;
	struct auth_serversupplied_info *server_info = NULL;
	char *sanitized_username = NULL;
	NTSTATUS nt_status;
	bool username_was_mapped;

	req = tevent_req_create(
		mem_ctx, &state, struct auth3_check_password_state);
	if (req == NULL) {
		return NULL;
	}

	/*
	 * Be authoritative by default.
	 */
	state->authoritative = 1;

	/* The client has given us its machine name (which we only get over NBT transport).
	   We need to possibly reload smb.conf if smb.conf includes depend on the machine name. */

	set_remote_machine_name(user_info->workstation_name, True);

	nt_status = make_user_info_map(talloc_tos(),
                                       &mapped_user_info,
				       user_info->client.account_name,
				       user_info->client.domain_name,
				       user_info->workstation_name,
				       user_info->remote_host,
				       user_info->local_host,
				       user_info->service_description,
	                               user_info->password.response.lanman.data ? &user_info->password.response.lanman : NULL,
	                               user_info->password.response.nt.data ? &user_info->password.response.nt : NULL,
				       NULL, NULL, NULL,
				       AUTH_PASSWORD_RESPONSE);

	if (tevent_req_nterror(req, nt_status)) {
		return tevent_req_post(req, ev);
	}

	mapped_user_info->logon_parameters = user_info->logon_parameters;

	mapped_user_info->flags = user_info->flags;

	sanitized_username = talloc_alpha_strcpy(
		state,
		user_info->client.account_name,
		SAFE_NETBIOS_CHARS "$");
	if (sanitized_username == NULL) {
		tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
		return tevent_req_post(req, ev);
	}

	nt_status = auth_check_ntlm_password(state,
					     auth_context,
					     mapped_user_info,
					     &server_info,
					     &state->authoritative);

	if (!NT_STATUS_IS_OK(nt_status)) {
		DBG_INFO("Checking NTLMSSP password for %s\\%s failed: "
			 "%s, authoritative=%"PRIu8"\n",
			 user_info->client.domain_name,
			 user_info->client.account_name,
			 nt_errstr(nt_status),
			 state->authoritative);
	}

	username_was_mapped = mapped_user_info->was_mapped;

	TALLOC_FREE(mapped_user_info);

	if (!NT_STATUS_IS_OK(nt_status)) {
		nt_status = do_map_to_guest_server_info(
			state,
			nt_status,
			user_info->client.account_name,
			user_info->client.domain_name,
			&server_info);
		if (!tevent_req_nterror(req, nt_status)) {
			state->authoritative = 1;

			/* setup the string used by %U */
			set_current_user_info(
				sanitized_username,
				server_info->unix_name,
				server_info->info3->base.logon_domain.string);

			lp_load_with_shares(get_dyn_CONFIGFILE());

			tevent_req_done(req);
		}
		state->server_info = server_info;
		return tevent_req_post(req, ev);
	}

	server_info->nss_token |= username_was_mapped;

	/* setup the string used by %U */
	set_current_user_info(sanitized_username,
			      server_info->unix_name,
			      server_info->info3->base.logon_domain.string);

	lp_load_with_shares(get_dyn_CONFIGFILE());

	/* Clear out the session keys, and pass them to the caller.
	 * They will not be used in this form again - instead the
	 * NTLMSSP code will decide on the final correct session key,
	 * and supply it to create_local_token() */

	DBG_DEBUG("Got NT session key of length %zu\n",
		  server_info->session_key.length);
	state->nt_session_key = (DATA_BLOB) {
		.data = talloc_move(
			state, &server_info->session_key.data),
		.length = server_info->session_key.length,
	};
	server_info->session_key = data_blob_null;

	DBG_DEBUG("Got LM session key of length %zu\n",
		  server_info->lm_session_key.length);
	state->lm_session_key = (DATA_BLOB) {
		.data = talloc_move(
			state, &server_info->lm_session_key.data),
		.length = server_info->lm_session_key.length,
	};
	server_info->lm_session_key = data_blob_null;

	state->server_info = server_info;

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

NTSTATUS auth3_check_password_recv(struct tevent_req *req,
				   TALLOC_CTX *mem_ctx,
				   uint8_t *pauthoritative,
				   void **server_returned_info,
				   DATA_BLOB *nt_session_key,
				   DATA_BLOB *lm_session_key)
{
	struct auth3_check_password_state *state = tevent_req_data(
		req, struct auth3_check_password_state);
	NTSTATUS status;

	if (pauthoritative != NULL) {
		*pauthoritative = state->authoritative;
	}

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	if (server_returned_info != NULL) {
		*server_returned_info = talloc_move(
			mem_ctx, &state->server_info);
	}
	if (nt_session_key != NULL) {
		*nt_session_key = (DATA_BLOB) {
			.data = talloc_move(
				mem_ctx, &state->nt_session_key.data),
			.length = state->nt_session_key.length,
		};
	}
	if (lm_session_key != NULL) {
		*lm_session_key = (DATA_BLOB) {
			.data = talloc_move(
				mem_ctx, &state->lm_session_key.data),
			.length = state->lm_session_key.length,
		};
	}

	return NT_STATUS_OK;
}
