/* 
   Unix SMB/Netbios implementation.
   Version 3.0

   Winbind daemon - pam auth funcions

   Copyright (C) Andrew Tridgell 2000
   Copyright (C) Tim Potter 2001
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
        struct cli_state *cli;
	uchar chal[8];
	TALLOC_CTX *mem_ctx;
	DATA_BLOB lm_resp;
	DATA_BLOB nt_resp;

	extern pstring global_myname;

	DEBUG(3, ("[%5d]: pam auth %s\n", state->pid,
		  state->request.data.auth.user));

	if (!(mem_ctx = talloc_init_named("winbind pam auth for %s", state->request.data.auth.user))) {
		DEBUG(0, ("winbindd_pam_auth: could not talloc_init()!\n"));
		return WINBINDD_ERROR;
	}

	/* Parse domain and username */

	if (!parse_domain_user(state->request.data.auth.user, name_domain, 
                          name_user))
		return WINBINDD_ERROR;

	passlen = strlen(state->request.data.auth.pass);
		
	if (!*state->request.data.auth.pass) {
		return WINBINDD_ERROR;
	} else {
		unsigned char local_lm_response[24];
		unsigned char local_nt_response[24];
		
		generate_random_buffer(chal, 8, False);
		SMBencrypt( (const uchar *)state->request.data.auth.pass, chal, local_lm_response);
		
		SMBNTencrypt((const uchar *)state->request.data.auth.pass, chal, local_nt_response);

		lm_resp = data_blob(local_lm_response, sizeof(local_lm_response));
		nt_resp = data_blob(local_nt_response, sizeof(local_nt_response));
	}
	
	/*
	 * Get the machine account password for our primary domain
	 */

	if (!secrets_fetch_trust_account_password(
                lp_workgroup(), trust_passwd, &last_change_time)) {
		DEBUG(0, ("winbindd_pam_auth: could not fetch trust account "
                          "password for domain %s\n", lp_workgroup()));
		return WINBINDD_ERROR;
	}

	/* We really don't care what LUID we give the user. */

	generate_random_buffer( (unsigned char *)&smb_uid_low, 4, False);

	ZERO_STRUCT(info3);

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
	data_blob_free(&lm_resp);
	data_blob_free(&nt_resp);

	cli_shutdown(cli);

	talloc_destroy(mem_ctx);
	
	return NT_STATUS_IS_OK(result) ? WINBINDD_OK : WINBINDD_ERROR;
}

/* Challenge Response Authentication Protocol */

enum winbindd_result winbindd_pam_auth_crap(struct winbindd_cli_state *state) 
{
	NTSTATUS result;
	fstring name_domain, name_user;
	unsigned char trust_passwd[16];
	time_t last_change_time;
        NET_USER_INFO_3 info3;
        struct cli_state *cli;
	TALLOC_CTX *mem_ctx;

	DATA_BLOB lm_resp, nt_resp;

	extern pstring global_myname;

	DEBUG(3, ("[%5d]: pam auth crap %s\n", state->pid,
		  state->request.data.auth_crap.user));

	if (!(mem_ctx = talloc_init_named("winbind pam auth for %s", state->request.data.auth.user))) {
		DEBUG(0, ("winbindd_pam_auth_crap: could not talloc_init()!\n"));
		return WINBINDD_ERROR;
	}

	/* Parse domain and username */
	if (!parse_domain_user(state->request.data.auth_crap.user, name_domain, 
			       name_user))
		return WINBINDD_ERROR;
	
	
	
	lm_resp = data_blob(state->request.data.auth_crap.lm_resp, state->request.data.auth_crap.lm_resp_len);
	nt_resp = data_blob(state->request.data.auth_crap.nt_resp, state->request.data.auth_crap.nt_resp_len);
	
	/*
	 * Get the machine account password for our primary domain
	 */

	if (!secrets_fetch_trust_account_password(
                lp_workgroup(), trust_passwd, &last_change_time)) {
		DEBUG(0, ("winbindd_pam_auth: could not fetch trust account "
                          "password for domain %s\n", lp_workgroup()));
		return WINBINDD_ERROR;
	}

	ZERO_STRUCT(info3);

        result = cm_get_netlogon_cli(lp_workgroup(), trust_passwd, &cli);

        if (!NT_STATUS_IS_OK(result)) {
                DEBUG(3, ("could not open handle to NETLOGON pipe\n"));
                goto done;
        }

	result = cli_netlogon_sam_network_logon(cli, mem_ctx,
						name_user, name_domain, 
						global_myname, state->request.data.auth_crap.chal, 
						lm_resp, nt_resp, 
						&info3);
        
done:
	talloc_destroy(mem_ctx);

	cli_shutdown(cli);

	return NT_STATUS_IS_OK(result) ? WINBINDD_OK : WINBINDD_ERROR;
}

/* Change a user password */

enum winbindd_result winbindd_pam_chauthtok(struct winbindd_cli_state *state)
{
	char *oldpass, *newpass;
	fstring domain, user;
	uchar nt_oldhash[16];
	uchar lm_oldhash[16];

	DEBUG(3, ("[%5d]: pam chauthtok %s\n", state->pid,
		state->request.data.chauthtok.user));

	/* Setup crap */

	if (state == NULL)
		return WINBINDD_ERROR;

	if (!parse_domain_user(state->request.data.chauthtok.user, domain, user))
		return WINBINDD_ERROR;

	oldpass = state->request.data.chauthtok.oldpass;
	newpass = state->request.data.chauthtok.newpass;

	nt_lm_owf_gen(oldpass, nt_oldhash, lm_oldhash);

	/* Change password */

#if 0

	/* XXX */

	if (!msrpc_sam_ntchange_pwd(server_state.controller, domain, user,
		lm_oldhash, nt_oldhash, newpass)) {
		DEBUG(0, ("password change failed for user %s/%s\n", domain, user));
		return WINBINDD_ERROR;
	}
#endif
    
	return WINBINDD_OK;
}
