/* 
   Unix SMB/CIFS implementation.

   Winbind authentication mechnism

   Copyright (C) Tim Potter 2000
   Copyright (C) Andrew Bartlett 2001 - 2002
   
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
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "auth/auth.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

static NTSTATUS get_info3_from_ndr(TALLOC_CTX *mem_ctx, struct winbindd_response *response, struct netr_SamInfo3 *info3)
{
	size_t len = response->length - sizeof(struct winbindd_response);
	if (len > 4) {
		NTSTATUS status;
		DATA_BLOB blob;
		blob.length = len - 4;
		blob.data = ((char *)response->extra_data) + 4;
		
		status = ndr_pull_struct_blob(&blob, mem_ctx, info3,
					      (ndr_pull_flags_fn_t)ndr_pull_netr_SamInfo3);

		return status;
	} else {
		DEBUG(2, ("get_info3_from_ndr: No info3 struct found!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}
}

/* Authenticate a user with a challenge/response */

static NTSTATUS check_winbind_security(const struct auth_context *auth_context,
				     void *my_private_data, 
				     TALLOC_CTX *mem_ctx,
				     const struct auth_usersupplied_info *user_info, 
				     struct auth_serversupplied_info **server_info)
{
	struct winbindd_request request;
	struct winbindd_response response;
        NSS_STATUS result;
	NTSTATUS nt_status;
	struct netr_SamInfo3 info3;

	if (!user_info) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!auth_context) {
		DEBUG(3,("Password for user %s cannot be checked because we have no auth_info to get the challenge from.\n", 
			 user_info->internal_username.str));		
		return NT_STATUS_UNSUCCESSFUL;
	}		

	/* Send off request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);
	request.flags = WBFLAG_PAM_INFO3_NDR;
	fstrcpy(request.data.auth_crap.user, 
		user_info->smb_name.str);
	fstrcpy(request.data.auth_crap.domain, 
			  user_info->domain.str);
	fstrcpy(request.data.auth_crap.workstation, 
			  user_info->wksta_name.str);

	memcpy(request.data.auth_crap.chal, auth_context->challenge.data, sizeof(request.data.auth_crap.chal));
	
	request.data.auth_crap.lm_resp_len = MIN(user_info->lm_resp.length, 
						 sizeof(request.data.auth_crap.lm_resp));
	request.data.auth_crap.nt_resp_len = MIN(user_info->nt_resp.length, 
						 sizeof(request.data.auth_crap.nt_resp));
	
	memcpy(request.data.auth_crap.lm_resp, user_info->lm_resp.data, 
	       request.data.auth_crap.lm_resp_len);
	memcpy(request.data.auth_crap.nt_resp, user_info->nt_resp.data, 
	       request.data.auth_crap.nt_resp_len);
	
	result = winbindd_request(WINBINDD_PAM_AUTH_CRAP, &request, &response);

	nt_status = NT_STATUS(response.data.auth.nt_status);

	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	if (result == NSS_STATUS_SUCCESS && response.extra_data) {
		nt_status = get_info3_from_ndr(mem_ctx, &response, &info3);
		if (NT_STATUS_IS_OK(nt_status)) { 
			union netr_Validation validation;
			validation.sam3 = &info3;
			nt_status = 
				make_server_info_netlogon_validation(mem_ctx, 
								     user_info->internal_username.str, 
								     server_info,
								     3,
								     &validation); 
		}
		SAFE_FREE(response.extra_data);
	} else if (result == NSS_STATUS_SUCCESS && !response.extra_data) {
		DEBUG(0, ("Winbindd authenticated the user [%s]\\[%s], "
			  "but did not include the required info3 reply!\n", 
			  user_info->smb_name.str, user_info->domain.str));
		nt_status = NT_STATUS_INSUFFICIENT_LOGON_INFO;
	} else if (NT_STATUS_IS_OK(nt_status)) {
		DEBUG(1, ("Winbindd authentication for [%s]\\[%s] failed, "
			  "but no error code is available!\n", 
			  user_info->smb_name.str, user_info->domain.str));
		nt_status = NT_STATUS_NO_LOGON_SERVERS;
	}

        return nt_status;
}

/* module initialisation */
static NTSTATUS auth_init_winbind(struct auth_context *auth_context, 
					  const char *param, 
					  struct auth_methods **auth_method) 
{
	if (!make_auth_methods(auth_context, auth_method))
		return NT_STATUS_NO_MEMORY;

	(*auth_method)->name = "winbind";
	(*auth_method)->auth = check_winbind_security;
	return NT_STATUS_OK;
}

NTSTATUS auth_winbind_init(void)
{
	NTSTATUS ret;
	struct auth_operations ops;

	ops.name = "winbind";
	ops.init = auth_init_winbind;
	ret = auth_register(&ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' auth backend!\n",
			ops.name));
	}
	return ret;
}
