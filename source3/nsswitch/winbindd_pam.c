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

extern pstring global_myname;

/* Copy of parse_domain_user from winbindd_util.c.  Parse a string of the
   form DOMAIN/user into a domain and a user */

static void parse_domain_user(char *domuser, fstring domain, fstring user)
{
        char *p;
        char *sep = lp_winbind_separator();
        if (!sep) sep = "\\";
        p = strchr(domuser,*sep);
        if (!p) p = strchr(domuser,'\\');
        if (!p) {
                fstrcpy(domain,"");
                fstrcpy(user, domuser);
                return;
        }
        
        fstrcpy(user, p+1);
        fstrcpy(domain, domuser);
        domain[PTR_DIFF(p, domuser)] = 0;
        strupper(domain);
}

/* Return a password structure from a username.  Specify whether cached data 
   can be returned. */

enum winbindd_result winbindd_pam_auth(struct winbindd_cli_state *state) 
{
	BOOL result;
	fstring name_domain, name_user;
	int passlen;
	unsigned char trust_passwd[16];
	time_t last_change_time;

	unsigned char local_lm_response[24];
	unsigned char local_nt_response[24];

	auth_usersupplied_info user_info;
	auth_serversupplied_info server_info;
	AUTH_STR theirdomain, smb_username, wksta_name;

	DEBUG(3, ("[%5d]: pam auth %s\n", state->pid,
		  state->request.data.auth.user));

	/* Parse domain and username */

	parse_domain_user(state->request.data.auth.user, name_domain, 
                          name_user);

	/* don't allow the null domain */

	if (strcmp(name_domain,"") == 0) 
		return WINBINDD_ERROR;

	passlen = strlen(state->request.data.auth.pass);
		
	ZERO_STRUCT(user_info);
	ZERO_STRUCT(theirdomain);
	ZERO_STRUCT(smb_username);
	ZERO_STRUCT(wksta_name);
	
	theirdomain.str = name_domain;
	theirdomain.len = strlen(theirdomain.str);

	user_info.requested_domain = theirdomain;
	user_info.domain = theirdomain;
	
	user_info.smb_username.str = name_user;
	user_info.smb_username.len = strlen(name_user);

	user_info.requested_username.str = name_user;
	user_info.requested_username.len = strlen(name_user);

	user_info.wksta_name.str = global_myname;
	user_info.wksta_name.len = strlen(user_info.wksta_name.str);

	user_info.wksta_name = wksta_name;

	generate_random_buffer( user_info.chal, 8, False);

	if (state->request.data.auth.pass) {
		SMBencrypt((uchar *)state->request.data.auth.pass, user_info.chal, local_lm_response);
		user_info.lm_resp.buffer = (uint8 *)local_lm_response;
		user_info.lm_resp.len = 24;
		SMBNTencrypt((uchar *)state->request.data.auth.pass, user_info.chal, local_nt_response);
		user_info.nt_resp.buffer = (uint8 *)local_nt_response;
		user_info.nt_resp.len = 24;
	} else {
		return WINBINDD_ERROR;
	}
	
	/*
	 * Get the machine account password for our primary domain
	 */

	if (!secrets_fetch_trust_account_password(lp_workgroup(), trust_passwd, &last_change_time))
	{
		DEBUG(0, ("winbindd_pam_auth: could not fetch trust account password for domain %s\n", lp_workgroup()));
		return WINBINDD_ERROR;
	}

	/* So domain_client_validate() actually opens a new connection
	   for each authentication performed.  This can theoretically
	   be optimised to use an already open IPC$ connection. */

	result = (domain_client_validate(&user_info, &server_info,
					 server_state.controller, trust_passwd,
					 last_change_time) == NT_STATUS_NOPROBLEMO);

	return result ? WINBINDD_OK : WINBINDD_ERROR;
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

    if (state == NULL) return WINBINDD_ERROR;

    parse_domain_user(state->request.data.chauthtok.user, domain, user);

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
