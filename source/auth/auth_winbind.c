/* 
   Unix SMB/CIFS implementation.

   Winbind authentication mechnism

   Copyright (C) Tim Potter 2000
   Copyright (C) Andrew Bartlett 2001 - 2002
   Copyright (C) Stefan Metzmacher 2005
   
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
#include "auth/auth.h"
#include "nsswitch/winbind_client.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "librpc/gen_ndr/ndr_winbind.h"
#include "lib/messaging/irpc.h"

static NTSTATUS get_info3_from_ndr(TALLOC_CTX *mem_ctx, struct winbindd_response *response, struct netr_SamInfo3 *info3)
{
	size_t len = response->length - sizeof(struct winbindd_response);
	if (len > 4) {
		NTSTATUS status;
		DATA_BLOB blob;
		blob.length = len - 4;
		blob.data = (uint8_t *)(((char *)response->extra_data) + 4);

		status = ndr_pull_struct_blob(&blob, mem_ctx, info3,
					      (ndr_pull_flags_fn_t)ndr_pull_netr_SamInfo3);

		return status;
	} else {
		DEBUG(2, ("get_info3_from_ndr: No info3 struct found!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}
}

static NTSTATUS winbind_want_check(struct auth_method_context *ctx,
				   TALLOC_CTX *mem_ctx,
				   const struct auth_usersupplied_info *user_info)
{
	if (!user_info->mapped.account_name || !*user_info->mapped.account_name) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	/* TODO: maybe limit the user scope to remote users only */
	return NT_STATUS_OK;
}

/*
 Authenticate a user with a challenge/response
 using the samba3 winbind protocol
*/
static NTSTATUS winbind_check_password_samba3(struct auth_method_context *ctx,
					      TALLOC_CTX *mem_ctx,
					      const struct auth_usersupplied_info *user_info, 
					      struct auth_serversupplied_info **server_info)
{
	struct winbindd_request request;
	struct winbindd_response response;
        NSS_STATUS result;
	NTSTATUS nt_status;
	struct netr_SamInfo3 info3;		

	/* Send off request */
	const struct auth_usersupplied_info *user_info_temp;	
	nt_status = encrypt_user_info(mem_ctx, ctx->auth_ctx, 
				      AUTH_PASSWORD_RESPONSE, 
				      user_info, &user_info_temp);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}
	user_info = user_info_temp;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);
	request.flags = WBFLAG_PAM_INFO3_NDR;

	request.data.auth_crap.logon_parameters = user_info->logon_parameters;

	winbind_strcpy(request.data.auth_crap.user, 
		       user_info->client.account_name);
	winbind_strcpy(request.data.auth_crap.domain, 
		       user_info->client.domain_name);
	winbind_strcpy(request.data.auth_crap.workstation, 
		       user_info->workstation_name);

	memcpy(request.data.auth_crap.chal, ctx->auth_ctx->challenge.data.data, sizeof(request.data.auth_crap.chal));

	request.data.auth_crap.lm_resp_len = MIN(user_info->password.response.lanman.length,
						 sizeof(request.data.auth_crap.lm_resp));
	request.data.auth_crap.nt_resp_len = MIN(user_info->password.response.nt.length, 
						 sizeof(request.data.auth_crap.nt_resp));

	memcpy(request.data.auth_crap.lm_resp, user_info->password.response.lanman.data,
	       request.data.auth_crap.lm_resp_len);
	memcpy(request.data.auth_crap.nt_resp, user_info->password.response.nt.data,
	       request.data.auth_crap.nt_resp_len);

	result = winbindd_request(WINBINDD_PAM_AUTH_CRAP, &request, &response);

	nt_status = NT_STATUS(response.data.auth.nt_status);
	NT_STATUS_NOT_OK_RETURN(nt_status);

	if (result == NSS_STATUS_SUCCESS && response.extra_data) {
		union netr_Validation validation;

		nt_status = get_info3_from_ndr(mem_ctx, &response, &info3);
		SAFE_FREE(response.extra_data);
		NT_STATUS_NOT_OK_RETURN(nt_status); 

		validation.sam3 = &info3;
		nt_status = make_server_info_netlogon_validation(mem_ctx, 
								 user_info->client.account_name, 
								 3, &validation,
								 server_info);
		return nt_status;
	} else if (result == NSS_STATUS_SUCCESS && !response.extra_data) {
		DEBUG(0, ("Winbindd authenticated the user [%s]\\[%s], "
			  "but did not include the required info3 reply!\n", 
			  user_info->client.domain_name, user_info->client.account_name));
		return NT_STATUS_INSUFFICIENT_LOGON_INFO;
	} else if (NT_STATUS_IS_OK(nt_status)) {
		DEBUG(1, ("Winbindd authentication for [%s]\\[%s] failed, "
			  "but no error code is available!\n", 
			  user_info->client.domain_name, user_info->client.account_name));
		return NT_STATUS_NO_LOGON_SERVERS;
	}

        return nt_status;
}

struct winbind_check_password_state {
	struct winbind_SamLogon req;
};

/*
 Authenticate a user with a challenge/response
 using IRPC to the winbind task
*/
static NTSTATUS winbind_check_password(struct auth_method_context *ctx,
				       TALLOC_CTX *mem_ctx,
				       const struct auth_usersupplied_info *user_info, 
				       struct auth_serversupplied_info **server_info)
{
	NTSTATUS status;
	uint32_t *winbind_servers;
	struct winbind_check_password_state *s;
	const struct auth_usersupplied_info *user_info_new;
	struct netr_IdentityInfo *identity_info;

	winbind_servers = irpc_servers_byname(ctx->auth_ctx->msg_ctx, "winbind_server");
	if ((winbind_servers == NULL) || (winbind_servers[0] == 0)) {
		DEBUG(0, ("Winbind authentication for [%s]\\[%s] failed, " 
			  "no winbind_server running!\n",
			  user_info->client.domain_name, user_info->client.account_name));
		return NT_STATUS_NO_LOGON_SERVERS;
	}

	s = talloc(mem_ctx, struct winbind_check_password_state);
	NT_STATUS_HAVE_NO_MEMORY(s);

	if (user_info->flags & USER_INFO_INTERACTIVE_LOGON) {
		struct netr_PasswordInfo *password_info;

		status = encrypt_user_info(s, ctx->auth_ctx, AUTH_PASSWORD_HASH,
					   user_info, &user_info_new);
		NT_STATUS_NOT_OK_RETURN(status);
		user_info = user_info_new;

		password_info = talloc(s, struct netr_PasswordInfo);
		NT_STATUS_HAVE_NO_MEMORY(password_info);

		password_info->lmpassword = *user_info->password.hash.lanman;
		password_info->ntpassword = *user_info->password.hash.nt;

		identity_info = &password_info->identity_info;
		s->req.in.logon_level	= 1;
		s->req.in.logon.password= password_info;
	} else {
		struct netr_NetworkInfo *network_info;
		const uint8_t *challenge;

		status = encrypt_user_info(s, ctx->auth_ctx, AUTH_PASSWORD_RESPONSE,
					   user_info, &user_info_new);
		NT_STATUS_NOT_OK_RETURN(status);
		user_info = user_info_new;

		network_info = talloc(s, struct netr_NetworkInfo);
		NT_STATUS_HAVE_NO_MEMORY(network_info);

		status = auth_get_challenge(ctx->auth_ctx, &challenge);
		NT_STATUS_NOT_OK_RETURN(status);

		memcpy(network_info->challenge, challenge, sizeof(network_info->challenge));

		network_info->nt.length = user_info->password.response.nt.length;
		network_info->nt.data	= user_info->password.response.nt.data;

		network_info->nt.length = user_info->password.response.lanman.length;
		network_info->nt.data	= user_info->password.response.lanman.data;

		identity_info = &network_info->identity_info;
		s->req.in.logon_level	= 2;
		s->req.in.logon.network = network_info;
	}

	identity_info->domain_name.string	= user_info->client.domain_name;
	identity_info->parameter_control	= user_info->logon_parameters; /* see MSV1_0_* */
	identity_info->logon_id_low		= 0;
	identity_info->logon_id_high		= 0;
	identity_info->account_name.string	= user_info->client.account_name;
	identity_info->workstation.string	= user_info->workstation_name;

	s->req.in.validation_level	= 3;
	status = IRPC_CALL(ctx->auth_ctx->msg_ctx, winbind_servers[0],
			   winbind, WINBIND_SAMLOGON,
			   &s->req, s);
	NT_STATUS_NOT_OK_RETURN(status);

	status = make_server_info_netlogon_validation(mem_ctx,
						      user_info->client.account_name,
						      s->req.in.validation_level,
						      &s->req.out.validation,
						      server_info);
	NT_STATUS_NOT_OK_RETURN(status);

	return NT_STATUS_OK;
}

static const struct auth_operations winbind_samba3_ops = {
	.name		= "winbind_samba3",
	.get_challenge	= auth_get_challenge_not_implemented,
	.want_check	= winbind_want_check,
	.check_password	= winbind_check_password_samba3
};

static const struct auth_operations winbind_ops = {
	.name		= "winbind",
	.get_challenge	= auth_get_challenge_not_implemented,
	.want_check	= winbind_want_check,
	.check_password	= winbind_check_password
};

NTSTATUS auth_winbind_init(void)
{
	NTSTATUS ret;

	ret = auth_register(&winbind_samba3_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register 'winbind_samba3' auth backend!\n"));
		return ret;
	}

	ret = auth_register(&winbind_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register 'winbind' auth backend!\n"));
		return ret;
	}

	return NT_STATUS_OK;
}
