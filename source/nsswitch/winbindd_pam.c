/* 
   Unix SMB/CIFS implementation.

   Winbind daemon - pam auth funcions

   Copyright (C) Andrew Tridgell 2000
   Copyright (C) Tim Potter 2001
   Copyright (C) Andrew Bartlett 2001-2002
   
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

#include "winbindd.h"

/* Return a password structure from a username.  */

enum winbindd_result winbindd_pam_auth(struct winbindd_cli_state *state) 
{
	NTSTATUS result;
	fstring name_domain, name_user;
	int passlen;
	unsigned char trust_passwd[16];
	time_t last_change_time;
        uint32 smb_uid_low;
        NET_USER_INFO_3 info3;
        struct cli_state *cli = NULL;
	uchar chal[8];
	TALLOC_CTX *mem_ctx = NULL;
	DATA_BLOB lm_resp;
	DATA_BLOB nt_resp;

	extern pstring global_myname;

	DEBUG(3, ("[%5d]: pam auth %s\n", state->pid,
		  state->request.data.auth.user));

	if (!(mem_ctx = talloc_init_named("winbind pam auth for %s", state->request.data.auth.user))) {
		DEBUG(0, ("winbindd_pam_auth: could not talloc_init()!\n"));
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

	/* Parse domain and username */
	
	if (!parse_domain_user(state->request.data.auth.user, name_domain, 
			       name_user)) {
		DEBUG(5,("no domain separator (%s) in username (%s) - failing auth\n", lp_winbind_separator(), state->request.data.auth.user));
		result = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	passlen = strlen(state->request.data.auth.pass);
		
	{
		unsigned char local_lm_response[24];
		unsigned char local_nt_response[24];
		
		generate_random_buffer(chal, 8, False);
		SMBencrypt( (const uchar *)state->request.data.auth.pass, chal, local_lm_response);
		
		SMBNTencrypt((const uchar *)state->request.data.auth.pass, chal, local_nt_response);

		lm_resp = data_blob_talloc(mem_ctx, local_lm_response, sizeof(local_lm_response));
		nt_resp = data_blob_talloc(mem_ctx, local_nt_response, sizeof(local_nt_response));
	}
	
	/*
	 * Get the machine account password for our primary domain
	 */

	if (!secrets_fetch_trust_account_password(
                lp_workgroup(), trust_passwd, &last_change_time)) {
		DEBUG(0, ("winbindd_pam_auth: could not fetch trust account "
                          "password for domain %s\n", lp_workgroup()));
		result = NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		goto done;
	}

	/* We really don't care what LUID we give the user. */

	generate_random_buffer( (unsigned char *)&smb_uid_low, 4, False);

	ZERO_STRUCT(info3);
	
	/* Don't shut this down - it belongs to the connection cache code */
        result = cm_get_netlogon_cli(lp_workgroup(), trust_passwd, &cli);

        if (!NT_STATUS_IS_OK(result)) {
                DEBUG(3, ("could not open handle to NETLOGON pipe\n"));
                goto done;
        }

	result = cli_netlogon_sam_network_logon(cli, mem_ctx,
						name_user, name_domain, 
						global_myname, chal, 
						lm_resp, nt_resp, 
						&info3);
        
done:

	state->response.data.auth.nt_status = NT_STATUS_V(result);
	fstrcpy(state->response.data.auth.nt_status_string, nt_errstr(result));
	fstrcpy(state->response.data.auth.error_string, nt_errstr(result));
	state->response.data.auth.pam_error = nt_status_to_pam(result);

	DEBUG(NT_STATUS_IS_OK(result) ? 5 : 2, ("Plain-text authentication for user %s returned %s (PAM: %d)\n", 
	      state->request.data.auth.user, 
	      state->response.data.auth.nt_status_string,
	      state->response.data.auth.pam_error));	      

	if (mem_ctx) 
		talloc_destroy(mem_ctx);
	
	return NT_STATUS_IS_OK(result) ? WINBINDD_OK : WINBINDD_ERROR;
}
	
#ifdef WITH_WINBIND_AUTH_CRAP
/* Challenge Response Authentication Protocol */

enum winbindd_result winbindd_pam_auth_crap(struct winbindd_cli_state *state) 
{
	NTSTATUS result;
	unsigned char trust_passwd[16];
	time_t last_change_time;
        NET_USER_INFO_3 info3;
        struct cli_state *cli = NULL;
	TALLOC_CTX *mem_ctx = NULL;
	const char *domain = NULL;

	DATA_BLOB lm_resp, nt_resp;

	extern pstring global_myname;

	DEBUG(3, ("[%5d]: pam auth crap domain: %s user: %s\n", state->pid,
		  state->request.data.auth_crap.domain, state->request.data.auth_crap.user));

	if (!(mem_ctx = talloc_init_named("winbind pam auth crap for %s", state->request.data.auth_crap.user))) {
		DEBUG(0, ("winbindd_pam_auth_crap: could not talloc_init()!\n"));
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

	if (*state->request.data.auth_crap.domain) {
		domain = talloc_strdup(mem_ctx, state->request.data.auth_crap.domain);
	} else if (lp_winbind_use_default_domain()) {
		domain = talloc_strdup(mem_ctx, lp_workgroup());
	} else {
		DEBUG(5,("no domain specified with username (%s) - failing auth\n", state->request.data.auth_crap.user));
		result = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	if (!domain) {
		DEBUG(0,("winbindd_pam_auth_crap: talloc_strdup failed!\n"));
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

	lm_resp = data_blob_talloc(mem_ctx, state->request.data.auth_crap.lm_resp, state->request.data.auth_crap.lm_resp_len);
	nt_resp = data_blob_talloc(mem_ctx, state->request.data.auth_crap.nt_resp, state->request.data.auth_crap.nt_resp_len);
	
	/*
	 * Get the machine account password for our primary domain
	 */

	if (!secrets_fetch_trust_account_password(
                lp_workgroup(), trust_passwd, &last_change_time)) {
		DEBUG(0, ("winbindd_pam_auth: could not fetch trust account "
                          "password for domain %s\n", lp_workgroup()));
		result = NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		goto done;
	}

	ZERO_STRUCT(info3);

	/* Don't shut this down - it belongs to the connection cache code */
        result = cm_get_netlogon_cli(lp_workgroup(), trust_passwd, &cli);

        if (!NT_STATUS_IS_OK(result)) {
                DEBUG(3, ("could not open handle to NETLOGON pipe (%s)\n", nt_errstr(result)));
                goto done;
        }

	result = cli_netlogon_sam_network_logon(cli, mem_ctx,
						state->request.data.auth_crap.user, domain,
						global_myname, state->request.data.auth_crap.chal, 
						lm_resp, nt_resp, 
						&info3);
        
done:

	state->response.data.auth.nt_status = NT_STATUS_V(result);
	fstrcpy(state->response.data.auth.nt_status_string, nt_errstr(result));
	fstrcpy(state->response.data.auth.error_string, nt_errstr(result));
	state->response.data.auth.pam_error = nt_status_to_pam(result);

	DEBUG(NT_STATUS_IS_OK(result) ? 5 : 2, ("NTLM CRAP authentication for user [%s]\\[%s] returned %s (PAM: %d)\n", 
	      state->request.data.auth_crap.domain, 
	      state->request.data.auth_crap.user, 
	      state->response.data.auth.nt_status_string,
	      state->response.data.auth.pam_error));	      

	if (mem_ctx) 
		talloc_destroy(mem_ctx);
	
	return NT_STATUS_IS_OK(result) ? WINBINDD_OK : WINBINDD_ERROR;
}

#endif	/* WITH_WINBIND_AUTH_CRAP */

/* Change a user password */

enum winbindd_result winbindd_pam_chauthtok(struct winbindd_cli_state *state)
{
	NTSTATUS result;
	char *oldpass, *newpass;
	fstring domain, user;
	CLI_POLICY_HND *hnd;

	DEBUG(3, ("[%5d]: pam chauthtok %s\n", state->pid,
		state->request.data.chauthtok.user));

	/* Setup crap */

	if (state == NULL)
		return WINBINDD_ERROR;

	if (!parse_domain_user(state->request.data.chauthtok.user, domain, 
			       user)) {
		result = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	/* Change password */

	oldpass = state->request.data.chauthtok.oldpass;
	newpass = state->request.data.chauthtok.newpass;

	/* Get sam handle */

	if (!NT_STATUS_IS_OK(result = cm_get_sam_handle(domain, &hnd))) {
		DEBUG(1, ("could not get SAM handle on DC for %s\n", domain));
		goto done;
	}

	if (!cli_oem_change_password(hnd->cli, user, newpass, oldpass)) {
		DEBUG(1, ("password change failed for user %s/%s\n", domain, 
			  user));
		result = NT_STATUS_WRONG_PASSWORD;
	} else
		result = NT_STATUS_OK;

done:    
	state->response.data.auth.nt_status = NT_STATUS_V(result);
	fstrcpy(state->response.data.auth.nt_status_string, nt_errstr(result));
	fstrcpy(state->response.data.auth.error_string, nt_errstr(result));
	state->response.data.auth.pam_error = nt_status_to_pam(result);

	return NT_STATUS_IS_OK(result) ? WINBINDD_OK : WINBINDD_ERROR;
}
