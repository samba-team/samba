/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   handle NLTMSSP, server side

   Copyright (C) Andrew Tridgell      2001
   Copyright (C) Andrew Bartlett 2001-2003

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

static const uint8 *auth_ntlmssp_get_challenge(struct ntlmssp_state *ntlmssp_state)
{
	AUTH_NTLMSSP_STATE *auth_ntlmssp_state = ntlmssp_state->auth_context;
	return auth_ntlmssp_state->auth_context->get_ntlm_challenge(auth_ntlmssp_state->auth_context);
}

static NTSTATUS auth_ntlmssp_check_password(struct ntlmssp_state *ntlmssp_state) 
{
	AUTH_NTLMSSP_STATE *auth_ntlmssp_state = ntlmssp_state->auth_context;
	uint32 auth_flags = AUTH_FLAG_NONE;
	auth_usersupplied_info *user_info = NULL;
	DATA_BLOB plaintext_password = data_blob(NULL, 0);
	NTSTATUS nt_status;

	if (auth_ntlmssp_state->ntlmssp_state->lm_resp.length) {
		auth_flags |= AUTH_FLAG_LM_RESP;
	}

	if (auth_ntlmssp_state->ntlmssp_state->nt_resp.length == 24) {
		auth_flags |= AUTH_FLAG_NTLM_RESP;
	} else 	if (auth_ntlmssp_state->ntlmssp_state->nt_resp.length > 24) {
		auth_flags |= AUTH_FLAG_NTLMv2_RESP;
	};

	/* the client has given us its machine name (which we otherwise would not get on port 445).
	   we need to possibly reload smb.conf if smb.conf includes depend on the machine name */

	set_remote_machine_name(auth_ntlmssp_state->ntlmssp_state->workstation);

	/* setup the string used by %U */
	/* sub_set_smb_name checks for weird internally */
	sub_set_smb_name(auth_ntlmssp_state->ntlmssp_state->user);

	reload_services(True);

	nt_status = make_user_info_map(&user_info, 
				       auth_ntlmssp_state->ntlmssp_state->user, 
				       auth_ntlmssp_state->ntlmssp_state->domain, 
				       auth_ntlmssp_state->ntlmssp_state->workstation, 
	                               auth_ntlmssp_state->ntlmssp_state->lm_resp, 
				       auth_ntlmssp_state->ntlmssp_state->nt_resp, 
				       plaintext_password, 
	                               auth_flags, True);

	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	nt_status = auth_ntlmssp_state->auth_context->check_ntlm_password(auth_ntlmssp_state->auth_context, user_info, &auth_ntlmssp_state->server_info); 
			
	free_user_info(&user_info);

	return nt_status;
}

NTSTATUS auth_ntlmssp_start(AUTH_NTLMSSP_STATE **auth_ntlmssp_state)
{
	NTSTATUS nt_status;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("AUTH NTLMSSP context");
	
	*auth_ntlmssp_state = talloc_zero(mem_ctx, sizeof(**auth_ntlmssp_state));
	if (!*auth_ntlmssp_state) {
		DEBUG(0,("auth_ntlmssp_start: talloc failed!\n"));
		talloc_destroy(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCTP(*auth_ntlmssp_state);

	(*auth_ntlmssp_state)->mem_ctx = mem_ctx;

	if (!NT_STATUS_IS_OK(nt_status = ntlmssp_server_start(&(*auth_ntlmssp_state)->ntlmssp_state))) {
		return nt_status;
	}

	if (!NT_STATUS_IS_OK(nt_status = make_auth_context_subsystem(&(*auth_ntlmssp_state)->auth_context))) {
		return nt_status;
	}

	(*auth_ntlmssp_state)->ntlmssp_state->auth_context = (*auth_ntlmssp_state);
	(*auth_ntlmssp_state)->ntlmssp_state->get_challenge = auth_ntlmssp_get_challenge;
	(*auth_ntlmssp_state)->ntlmssp_state->check_password = auth_ntlmssp_check_password;
	(*auth_ntlmssp_state)->ntlmssp_state->server_role = lp_server_role();

	return NT_STATUS_OK;
}

NTSTATUS auth_ntlmssp_end(AUTH_NTLMSSP_STATE **auth_ntlmssp_state)
{
	TALLOC_CTX *mem_ctx = (*auth_ntlmssp_state)->mem_ctx;

	if ((*auth_ntlmssp_state)->ntlmssp_state) {
		ntlmssp_server_end(&(*auth_ntlmssp_state)->ntlmssp_state);
	}
	if ((*auth_ntlmssp_state)->auth_context) {
		((*auth_ntlmssp_state)->auth_context->free)(&(*auth_ntlmssp_state)->auth_context);
	}
	if ((*auth_ntlmssp_state)->server_info) {
		free_server_info(&(*auth_ntlmssp_state)->server_info);
	}
	talloc_destroy(mem_ctx);
	*auth_ntlmssp_state = NULL;
	return NT_STATUS_OK;
}

NTSTATUS auth_ntlmssp_update(AUTH_NTLMSSP_STATE *auth_ntlmssp_state, 
			     const DATA_BLOB request, DATA_BLOB *reply) 
{
	return ntlmssp_server_update(auth_ntlmssp_state->ntlmssp_state, request, reply);
}

