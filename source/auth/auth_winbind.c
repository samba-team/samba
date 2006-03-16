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

/* Authenticate a user with a challenge/response */
static NTSTATUS winbind_check_password(struct auth_method_context *ctx,
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

static const struct auth_operations winbind_ops = {
	.name		= "winbind",
	.get_challenge	= auth_get_challenge_not_implemented,
	.check_password	= winbind_check_password
};

NTSTATUS auth_winbind_init(void)
{
	NTSTATUS ret;

	ret = auth_register(&winbind_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register 'winbind' auth backend!\n"));
		return ret;
	}
	return ret;
}
