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
#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND


static NTSTATUS append_info3_as_ndr(TALLOC_CTX *mem_ctx, 
				    struct winbindd_cli_state *state, 
				    NET_USER_INFO_3 *info3) 
{
	prs_struct ps;
	uint32 size;
	if (!prs_init(&ps, 256 /* Random, non-zero number */, mem_ctx, MARSHALL)) {
		return NT_STATUS_NO_MEMORY;
	}
	if (!net_io_user_info3("", info3, &ps, 1, 3)) {
		prs_mem_free(&ps);
		return NT_STATUS_UNSUCCESSFUL;
	}

	size = prs_data_size(&ps);
	state->response.extra_data = malloc(size);
	if (!state->response.extra_data) {
		prs_mem_free(&ps);
		return NT_STATUS_NO_MEMORY;
	}
	prs_copy_all_data_out(state->response.extra_data, &ps);
	state->response.length += size;
	prs_mem_free(&ps);
	return NT_STATUS_OK;
}

/**********************************************************************
 Authenticate a user with a clear test password
**********************************************************************/

enum winbindd_result winbindd_pam_auth(struct winbindd_cli_state *state) 
{
	NTSTATUS result;
	fstring name_domain, name_user;
	unsigned char trust_passwd[16];
	time_t last_change_time;
	uint32 sec_channel_type;
        NET_USER_INFO_3 info3;
        struct cli_state *cli = NULL;
	uchar chal[8];
	TALLOC_CTX *mem_ctx = NULL;
	DATA_BLOB lm_resp;
	DATA_BLOB nt_resp;
	DOM_CRED ret_creds;
	int attempts = 0;
	unsigned char local_lm_response[24];
	unsigned char local_nt_response[24];
	const char *contact_domain;

	/* Ensure null termination */
	state->request.data.auth.user[sizeof(state->request.data.auth.user)-1]='\0';

	/* Ensure null termination */
	state->request.data.auth.pass[sizeof(state->request.data.auth.pass)-1]='\0';

	DEBUG(3, ("[%5lu]: pam auth %s\n", (unsigned long)state->pid,
		  state->request.data.auth.user));

	if (!(mem_ctx = talloc_init("winbind pam auth for %s", state->request.data.auth.user))) {
		DEBUG(0, ("winbindd_pam_auth: could not talloc_init()!\n"));
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

	/* Parse domain and username */
	
	parse_domain_user(state->request.data.auth.user, name_domain, name_user);
	if ( !name_domain ) {
		DEBUG(5,("no domain separator (%s) in username (%s) - failing auth\n", lp_winbind_separator(), state->request.data.auth.user));
		result = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	/* do password magic */
	
	generate_random_buffer(chal, 8, False);
	SMBencrypt(state->request.data.auth.pass, chal, local_lm_response);
		
	SMBNTencrypt(state->request.data.auth.pass, chal, local_nt_response);

	lm_resp = data_blob_talloc(mem_ctx, local_lm_response, sizeof(local_lm_response));
	nt_resp = data_blob_talloc(mem_ctx, local_nt_response, sizeof(local_nt_response));
	
	if ( !get_trust_pw(name_domain, trust_passwd, &last_change_time, &sec_channel_type) ) {
		result = NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		goto done;
	}

	/* what domain should we contact? */
	
	if ( IS_DC )
		contact_domain = name_domain;
	else
		contact_domain = lp_workgroup();
		
	/* check authentication loop */

	do {
		ZERO_STRUCT(info3);
		ZERO_STRUCT(ret_creds);
	
		/* Don't shut this down - it belongs to the connection cache code */
		result = cm_get_netlogon_cli(contact_domain, trust_passwd, 
					     sec_channel_type, False, &cli);

		if (!NT_STATUS_IS_OK(result)) {
			DEBUG(3, ("could not open handle to NETLOGON pipe\n"));
			goto done;
		}

		result = cli_netlogon_sam_network_logon(cli, mem_ctx,
							&ret_creds,
							name_user, name_domain, 
							global_myname(), chal, 
							lm_resp, nt_resp,
							&info3);
		attempts += 1;
		
		/* if we get access denied, a possible cuase was that we had and open
		   connection to the DC, but someone changed our machine accoutn password
		   out from underneath us using 'net rpc changetrustpw' */
		   
		if ( NT_STATUS_V(result) == NT_STATUS_V(NT_STATUS_ACCESS_DENIED) ) {
			DEBUG(3,("winbindd_pam_auth: sam_logon returned ACCESS_DENIED.  Maybe the trust account "
				"password was changed and we didn't know it.  Killing connections to domain %s\n",
				name_domain));
			winbindd_cm_flush();
			cli->fd = -1;
		} 
		
		/* We have to try a second time as cm_get_netlogon_cli
		   might not yet have noticed that the DC has killed
		   our connection. */

	} while ( (attempts < 2) && (cli->fd == -1) );

        
	clnt_deal_with_creds(cli->sess_key, &(cli->clnt_cred), &ret_creds);
	
	if (NT_STATUS_IS_OK(result)) {
		netsamlogon_cache_store( cli->mem_ctx, &info3 );
		wcache_invalidate_samlogon(find_domain_from_name(name_domain), &info3);
	}
	
        
done:
	
	/* give us a more useful (more correct?) error code */
	if ((NT_STATUS_EQUAL(result, NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND) || (NT_STATUS_EQUAL(result, NT_STATUS_UNSUCCESSFUL)))) {
		result = NT_STATUS_NO_LOGON_SERVERS;
	}
	
	state->response.data.auth.nt_status = NT_STATUS_V(result);
	fstrcpy(state->response.data.auth.nt_status_string, nt_errstr(result));
	fstrcpy(state->response.data.auth.error_string, get_friendly_nt_error_msg(result));
	state->response.data.auth.pam_error = nt_status_to_pam(result);

	DEBUG(NT_STATUS_IS_OK(result) ? 5 : 2, ("Plain-text authentication for user %s returned %s (PAM: %d)\n", 
	      state->request.data.auth.user, 
	      state->response.data.auth.nt_status_string,
	      state->response.data.auth.pam_error));	      

	if (mem_ctx) 
		talloc_destroy(mem_ctx);
	
	return NT_STATUS_IS_OK(result) ? WINBINDD_OK : WINBINDD_ERROR;
}

/**********************************************************************
 Challenge Response Authentication Protocol 
**********************************************************************/

enum winbindd_result winbindd_pam_auth_crap(struct winbindd_cli_state *state) 
{
	NTSTATUS result;
	unsigned char trust_passwd[16];
	time_t last_change_time;
	uint32 sec_channel_type;
        NET_USER_INFO_3 info3;
        struct cli_state *cli = NULL;
	TALLOC_CTX *mem_ctx = NULL;
	char *user = NULL;
	const char *domain = NULL;
	const char *workstation;
	const char *contact_domain;
	DOM_CRED ret_creds;
	int attempts = 0;

	DATA_BLOB lm_resp, nt_resp;

	if (!state->privileged) {
		DEBUG(2, ("winbindd_pam_auth_crap: non-privileged access denied!\n"));
		/* send a better message than ACCESS_DENIED */
		push_utf8_fstring(state->response.data.auth.error_string, "winbind client not authorized to use winbindd_pam_auth_crap");
		result =  NT_STATUS_ACCESS_DENIED;
		goto done;
	}

	/* Ensure null termination */
	state->request.data.auth_crap.user[sizeof(state->request.data.auth_crap.user)-1]=0;
	state->request.data.auth_crap.domain[sizeof(state->request.data.auth_crap.domain)-1]=0;

	if (!(mem_ctx = talloc_init("winbind pam auth crap for (utf8) %s", state->request.data.auth_crap.user))) {
		DEBUG(0, ("winbindd_pam_auth_crap: could not talloc_init()!\n"));
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

        if (pull_utf8_talloc(mem_ctx, &user, state->request.data.auth_crap.user) == (size_t)-1) {
		DEBUG(0, ("winbindd_pam_auth_crap: pull_utf8_talloc failed!\n"));
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if (*state->request.data.auth_crap.domain) {
		char *dom = NULL;
		if (pull_utf8_talloc(mem_ctx, &dom, state->request.data.auth_crap.domain) == (size_t)-1) {
			DEBUG(0, ("winbindd_pam_auth_crap: pull_utf8_talloc failed!\n"));
			result = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}
		domain = dom;
	} else if (lp_winbind_use_default_domain()) {
		domain = lp_workgroup();
	} else {
		DEBUG(5,("no domain specified with username (%s) - failing auth\n", 
			 user));
		result = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	DEBUG(3, ("[%5lu]: pam auth crap domain: %s user: %s\n", (unsigned long)state->pid,
		  domain, user));
	   
	if ( !get_trust_pw(domain, trust_passwd, &last_change_time, &sec_channel_type) ) {
		result = NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		goto done;
	}

	if (*state->request.data.auth_crap.workstation) {
		char *wrk = NULL;
		if (pull_utf8_talloc(mem_ctx, &wrk, state->request.data.auth_crap.workstation) == (size_t)-1) {
			DEBUG(0, ("winbindd_pam_auth_crap: pull_utf8_talloc failed!\n"));
			result = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}
		workstation = wrk;
	} else {
		workstation = global_myname();
	}

	if (state->request.data.auth_crap.lm_resp_len > sizeof(state->request.data.auth_crap.lm_resp)
		|| state->request.data.auth_crap.nt_resp_len > sizeof(state->request.data.auth_crap.nt_resp)) {
		DEBUG(0, ("winbindd_pam_auth_crap: invalid password length %u/%u\n", 
			  state->request.data.auth_crap.lm_resp_len, 
			  state->request.data.auth_crap.nt_resp_len));
		result = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	lm_resp = data_blob_talloc(mem_ctx, state->request.data.auth_crap.lm_resp, state->request.data.auth_crap.lm_resp_len);
	nt_resp = data_blob_talloc(mem_ctx, state->request.data.auth_crap.nt_resp, state->request.data.auth_crap.nt_resp_len);
	
	/* what domain should we contact? */
	
	if ( IS_DC )
		contact_domain = domain;
	else
		contact_domain = lp_workgroup();
	
	do {
		ZERO_STRUCT(info3);
		ZERO_STRUCT(ret_creds);

		/* Don't shut this down - it belongs to the connection cache code */
		result = cm_get_netlogon_cli(contact_domain, trust_passwd, sec_channel_type, False, &cli);

		if (!NT_STATUS_IS_OK(result)) {
			DEBUG(3, ("could not open handle to NETLOGON pipe (error: %s)\n",
				  nt_errstr(result)));
			goto done;
		}

		result = cli_netlogon_sam_network_logon(cli, mem_ctx,
							&ret_creds,
							user, domain,
							workstation,
							state->request.data.auth_crap.chal, 
							lm_resp, nt_resp, 
							&info3);

		attempts += 1;

		/* if we get access denied, a possible cuase was that we had and open
		   connection to the DC, but someone changed our machine accoutn password
		   out from underneath us using 'net rpc changetrustpw' */
		   
		if ( NT_STATUS_V(result) == NT_STATUS_V(NT_STATUS_ACCESS_DENIED) ) {
			DEBUG(3,("winbindd_pam_auth_crap: sam_logon returned ACCESS_DENIED.  Maybe the trust account "
				"password was changed and we didn't know it.  Killing connections to domain %s\n",
				domain));
			winbindd_cm_flush();
			cli->fd = -1;
		} 
		
		/* We have to try a second time as cm_get_netlogon_cli
		   might not yet have noticed that the DC has killed
		   our connection. */

	} while ( (attempts < 2) && (cli->fd == -1) );

	clnt_deal_with_creds(cli->sess_key, &(cli->clnt_cred), &ret_creds);
        
	if (NT_STATUS_IS_OK(result)) {
		netsamlogon_cache_store( cli->mem_ctx, &info3 );
		wcache_invalidate_samlogon(find_domain_from_name(domain), &info3);
		
		if (state->request.flags & WBFLAG_PAM_INFO3_NDR) {
			result = append_info3_as_ndr(mem_ctx, state, &info3);
		}
		
		if (state->request.flags & WBFLAG_PAM_NTKEY) {
			memcpy(state->response.data.auth.nt_session_key, info3.user_sess_key, sizeof(state->response.data.auth.nt_session_key) /* 16 */);
		}
		if (state->request.flags & WBFLAG_PAM_LMKEY) {
			memcpy(state->response.data.auth.first_8_lm_hash, info3.padding, sizeof(state->response.data.auth.first_8_lm_hash) /* 8 */);
		}
	}

done:

	/* give us a more useful (more correct?) error code */
	if ((NT_STATUS_EQUAL(result, NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND) || (NT_STATUS_EQUAL(result, NT_STATUS_UNSUCCESSFUL)))) {
		result = NT_STATUS_NO_LOGON_SERVERS;
	}
	
	state->response.data.auth.nt_status = NT_STATUS_V(result);
	push_utf8_fstring(state->response.data.auth.nt_status_string, nt_errstr(result));
	if (!*state->response.data.auth.error_string) 
		push_utf8_fstring(state->response.data.auth.error_string, get_friendly_nt_error_msg(result));
	state->response.data.auth.pam_error = nt_status_to_pam(result);

	DEBUG(NT_STATUS_IS_OK(result) ? 5 : 2, 
	      ("NTLM CRAP authentication for user [%s]\\[%s] returned %s (PAM: %d)\n", 
	       domain,
	       user,
	       state->response.data.auth.nt_status_string,
	       state->response.data.auth.pam_error));	      

	if (mem_ctx) 
		talloc_destroy(mem_ctx);
	
	return NT_STATUS_IS_OK(result) ? WINBINDD_OK : WINBINDD_ERROR;
}

/* Change a user password */

enum winbindd_result winbindd_pam_chauthtok(struct winbindd_cli_state *state)
{
	NTSTATUS result;
	char *oldpass, *newpass;
	fstring domain, user;
	CLI_POLICY_HND *hnd;

	DEBUG(3, ("[%5lu]: pam chauthtok %s\n", (unsigned long)state->pid,
		state->request.data.chauthtok.user));

	/* Setup crap */

	if (state == NULL)
		return WINBINDD_ERROR;

	parse_domain_user(state->request.data.chauthtok.user, domain, user);
	if ( !*domain ) {
		result = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	/* Change password */

	oldpass = state->request.data.chauthtok.oldpass;
	newpass = state->request.data.chauthtok.newpass;

	/* Get sam handle */

	if ( NT_STATUS_IS_ERR(result = cm_get_sam_handle(domain, &hnd)) ) {
		DEBUG(1, ("could not get SAM handle on DC for %s\n", domain));
		goto done;
	}

	if (!cli_oem_change_password(hnd->cli, user, newpass, oldpass)) {
		DEBUG(1, ("password change failed for user %s/%s\n", domain, 
			  user));
		result = NT_STATUS_WRONG_PASSWORD;
	} else {
		result = NT_STATUS_OK;
	}

done:    
	state->response.data.auth.nt_status = NT_STATUS_V(result);
	fstrcpy(state->response.data.auth.nt_status_string, nt_errstr(result));
	fstrcpy(state->response.data.auth.error_string, nt_errstr(result));
	state->response.data.auth.pam_error = nt_status_to_pam(result);

	DEBUG(NT_STATUS_IS_OK(result) ? 5 : 2, 
	      ("Password change for user [%s]\\[%s] returned %s (PAM: %d)\n", 
	       domain,
	       user,
	       state->response.data.auth.nt_status_string,
	       state->response.data.auth.pam_error));	      

	return NT_STATUS_IS_OK(result) ? WINBINDD_OK : WINBINDD_ERROR;
}
