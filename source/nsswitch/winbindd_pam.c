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
   form DOMAIN/user into a domain and a user */

static BOOL parse_domain_user(char *domuser, fstring domain, fstring user)
{
        char *p = strchr(domuser,*lp_winbind_separator());

        if (!p)
		return False;
        
        fstrcpy(user, p+1);
        fstrcpy(domain, domuser);
        domain[PTR_DIFF(p, domuser)] = 0;
	unix_to_dos(domain, True);
	strupper(domain);
	dos_to_unix(domain, True);
	return True;
}

/* Authenticate a user from a plaintext password */

enum winbindd_result winbindd_pam_auth(struct winbindd_cli_state *state) 
{
	NET_USER_INFO_3 info3;
	uchar ntpw[16];
	uchar lmpw[16];
	uchar trust_passwd[16];
	uint32 status;
	fstring server;
	fstring name_domain, name_user;
	extern pstring global_myname;

	DEBUG(3, ("[%5d]: pam auth %s\n", state->pid,
		  state->request.data.auth.user));

	/* Parse domain and username */
	if (!parse_domain_user(state->request.data.auth.user, name_domain, 
                          name_user))
		return WINBINDD_ERROR;

	ZERO_STRUCT(info3);

	if (!_get_trust_account_password(lp_workgroup(), trust_passwd, NULL)) {
            DEBUG(1, ("could not get trust password for domain %s\n",
                      name_domain));
            return WINBINDD_ERROR;
        }

	nt_lm_owf_gen(state->request.data.auth.pass, ntpw, lmpw);

	slprintf(server, sizeof(server), "\\\\%s", server_state.controller);

	status = domain_client_validate_backend(server, 
						name_user, name_domain,
						global_myname, SEC_CHAN_WKSTA,
						trust_passwd,
						NULL,
						lmpw, sizeof(lmpw),
						ntpw, sizeof(ntpw), &info3);

	/* The group rids in the info3 structure are allocated dynamically
	   so make sure we free them. */

	if (info3.gids)
		free(info3.gid);

	if (status != NT_STATUS_NOPROBLEMO) {
                DEBUG(3, ("winbindd_pam_auth() failed with status 0x%08x\n",
                          status));
                return WINBINDD_ERROR;
        }

	return WINBINDD_OK;
}

/* Authenticate a user from a challenge/response */

enum winbindd_result winbindd_pam_auth_crap(struct winbindd_cli_state *state) 
{
	NET_USER_INFO_3 info3;
	uchar trust_passwd[16];
	uint32 status;
	fstring server;
	fstring name_domain, name_user;
	extern pstring global_myname;

	DEBUG(3, ("[%5d]: pam auth crap %s\n", state->pid,
		  state->request.data.auth_crap.user));

	/* Parse domain and username */
	if (!parse_domain_user(state->request.data.auth_crap.user, 
                          name_domain, name_user))
		return WINBINDD_ERROR;

	ZERO_STRUCT(info3);

	if (!_get_trust_account_password(lp_workgroup(), trust_passwd, NULL)) {
            DEBUG(1, ("could not get trust password for domain %s\n",
                      name_domain));
            return WINBINDD_ERROR;
        }

	slprintf(server, sizeof(server), "\\\\%s", server_state.controller);

	status = domain_client_validate_backend
          (server, name_user, name_domain, global_myname, SEC_CHAN_WKSTA,
           trust_passwd, state->request.data.auth_crap.chal,
           state->request.data.auth_crap.lm_resp, 
	   state->request.data.auth_crap.lm_resp_len,
           state->request.data.auth_crap.nt_resp, 
	   state->request.data.auth_crap.nt_resp_len,
           &info3);

	/* The group rids in the info3 structure are allocated dynamically
	   so make sure we free them. */

	if (info3.gids)
		free(info3.gid);

	if (status != NT_STATUS_NOPROBLEMO) {
                DEBUG(3, ("winbindd_pam_auth() failed with status 0x%08x\n",
                          status));
                return WINBINDD_ERROR;
        }

	return WINBINDD_OK;
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

    if (!parse_domain_user(state->request.data.chauthtok.user, domain, user))
        return WINBINDD_ERROR;

    oldpass = state->request.data.chauthtok.oldpass;
    newpass = state->request.data.chauthtok.newpass;

    nt_lm_owf_gen(oldpass, nt_oldhash, lm_oldhash);

    /* Change password */

    if (!msrpc_sam_ntchange_pwd(server_state.controller, domain, user,
                               lm_oldhash, nt_oldhash, newpass)) {
        DEBUG(0, ("password change failed for user %s/%s\n", domain, user));
        return WINBINDD_ERROR;
    }
    
    return WINBINDD_OK;
}
