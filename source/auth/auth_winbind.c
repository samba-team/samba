/* 
   Unix SMB/Netbios implementation.
   Version 2.0

   Winbind authentication mechnism

   Copyright (C) Tim Potter 2000
   Copyright (C) Andrew Bartlett 2001
   
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

/* Prototypes from common.h */

NSS_STATUS winbindd_request(int req_type, 
			    struct winbindd_request *request,
			    struct winbindd_response *response);


/* Authenticate a user with a challenge/response */

static NTSTATUS check_winbind_security(const struct auth_context *auth_context,
				       void *my_private_data, 
				       TALLOC_CTX *mem_ctx,
				       const auth_usersupplied_info *user_info, 
				       auth_serversupplied_info **server_info)
{
	struct winbindd_request request;
	struct winbindd_response response;
        NSS_STATUS result;
        struct passwd *pw;
	NTSTATUS nt_status;

	if (!user_info) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!auth_context) {
		DEBUG(3,("Password for user %s cannot be checked because we have no auth_info to get the challenge from.\n", 
			 user_info->internal_username.str));		
		return NT_STATUS_UNSUCCESSFUL;
	}		

	/* Send off request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	snprintf(request.data.auth_crap.user, sizeof(request.data.auth_crap.user),
		 "%s\\%s", user_info->domain.str, user_info->smb_name.str);

	fstrcpy(request.data.auth_crap.user, user_info->smb_name.str);
	fstrcpy(request.data.auth_crap.domain, user_info->domain.str);

	memcpy(request.data.auth_crap.chal, auth_context->challenge.data, sizeof(request.data.auth_crap.chal));
	
	request.data.auth_crap.lm_resp_len = MIN(user_info->lm_resp.length, 
						 sizeof(request.data.auth_crap.lm_resp));
	request.data.auth_crap.nt_resp_len = MIN(user_info->nt_resp.length, 
						 sizeof(request.data.auth_crap.nt_resp));
	
	memcpy(request.data.auth_crap.lm_resp, user_info->lm_resp.data, 
	       sizeof(request.data.auth_crap.lm_resp_len));
	memcpy(request.data.auth_crap.nt_resp, user_info->nt_resp.data, 
	       request.data.auth_crap.lm_resp_len);
	
	result = winbindd_request(WINBINDD_PAM_AUTH_CRAP, &request, &response);

	if (result == NSS_STATUS_SUCCESS) {
		
		pw = Get_Pwnam(user_info->internal_username.str);
		
		if (pw) {			
			if (make_server_info_pw(server_info, pw)) {
				nt_status = NT_STATUS_OK;
			} else {
				nt_status = NT_STATUS_NO_MEMORY;
			}
		} else {
			nt_status = NT_STATUS_NO_SUCH_USER;
		}
	} else {
		nt_status = NT_STATUS_LOGON_FAILURE;
	}

        return nt_status;
}

/* module initialisation */
BOOL auth_init_winbind(struct auth_context *auth_context, auth_methods **auth_method) 
{
	if (!make_auth_methods(auth_context, auth_method)) {
		return False;
	}

	(*auth_method)->auth = check_winbind_security;
	return True;
}
