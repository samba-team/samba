/* 
   Unix SMB/Netbios implementation.
   Version 3.0

   Winbind daemon - pam auuth funcions

   Copyright (C) Andrew Tridgell 2000
   
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

/* Copy of parse_domain_user from winbindd_util.c.  Parse a string of the
   form DOMAIN\user into a domain and a user */

static BOOL wb_parse_domain_user(char *domuser, fstring domain, fstring user)
{
	char *p;
	char *sep = lp_winbind_separator();
 
	p = strchr(domuser,*sep);
 
	if (!p)
		return False;
 
	fstrcpy(user, p+1);
	fstrcpy(domain, domuser);
	domain[PTR_DIFF(p, domuser)] = 0;
	strupper(domain);
	return True;
}

/* Return a password structure from a username.  Specify whether cached data 
   can be returned. */

enum winbindd_result winbindd_pam_auth(struct winbindd_cli_state *state) 
{
	BOOL result, user_exists;
	fstring name_domain, name_user;
	int passlen;

	DEBUG(3, ("[%5d]: pam auth %s\n", state->pid,
		  state->request.data.auth.user));

	/* Parse domain and username */

	if (!wb_parse_domain_user(state->request.data.auth.user, name_domain, 
                          name_user))
		return WINBINDD_ERROR;

	passlen = strlen(state->request.data.auth.pass);

	/* So domain_client_validate() actually opens a new connection
	   for each authentication performed.  This can theoretically
	   be optimised to use an already open IPC$ connection. */

	result = domain_client_validate(name_user, name_domain,
					state->request.data.auth.pass,
					passlen,
					state->request.data.auth.pass,
					passlen, &user_exists, NULL);

	return result ? WINBINDD_OK : WINBINDD_ERROR;
}

/* Challenge Response Authentication Protocol */

#if ALLOW_WINBIND_AUTH_CRAP
enum winbindd_result winbindd_pam_auth_crap(struct winbindd_cli_state *state) 
{
	NTSTATUS result;
	fstring name_domain, name_user;
	unsigned char trust_passwd[16];
	time_t last_change_time;
        uint32 smb_uid_low;
        NET_USER_INFO_3 info3;
	NET_ID_INFO_CTR ctr;
        struct cli_state *cli;

	DEBUG(3, ("[%5d]: pam auth crap %s\n", state->pid,
		  state->request.data.auth_crap.user));

	/* Parse domain and username */

	if (!wb_parse_domain_user(state->request.data.auth_crap.user, name_domain, 
                          name_user))
		return WINBINDD_ERROR;

	/*
	 * Get the machine account password for our primary domain
	 */

	if (!secrets_fetch_trust_account_password(
                lp_workgroup(), trust_passwd, &last_change_time)) {
		DEBUG(0, ("winbindd_pam_auth_crap: could not fetch trust account "
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

	result = cli_nt_login_network(cli, name_domain, name_user, smb_uid_low,
			state->request.data.auth_crap.chal,
			state->request.data.auth_crap.lm_resp,
			state->request.data.auth_crap.nt_resp,
			&ctr, &info3);

        cli_shutdown(cli);

 done:
	return NT_STATUS_IS_OK(result) ? WINBINDD_OK : WINBINDD_ERROR;
}
#endif

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

	if (!wb_parse_domain_user(state->request.data.chauthtok.user, domain, user))
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
