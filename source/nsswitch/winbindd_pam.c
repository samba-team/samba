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

static uint32 check_any(fstring name_user, fstring name_domain, 
			uchar trust_passwd[16], const char *challenge,
			const char *smb_apasswd, int smb_apasslen,
			const char *smb_ntpasswd, int smb_ntpasslen,
			NET_USER_INFO_3 *info3)
{
	struct in_addr *ip_list = NULL;
	int count, i;
	uint32 result;
	BOOL try_local = True;

	if (!get_dc_list(False, lp_workgroup(), &ip_list, &count)) {
		DEBUG(0, ("could not find domain controller for "
			  "domain %s\n", lp_workgroup()));
		safe_free(ip_list);
		return NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
	}

	/* Try DC on local net */

retry:
	for (i = 0; i < count; i++) {
		fstring srv_name;

		if (try_local && !is_local_net(ip_list[i]))
			continue;

		if (!name_status_find(lp_workgroup(), 0x1c, 0x20,
				      ip_list[i], srv_name)) {
			DEBUG(3, ("IP %s not a dc for our domain\n",
				  inet_ntoa(ip_list[i])));
			continue;
		}

		result = domain_client_validate_backend(
			srv_name, name_user, name_domain, global_myname,
			SEC_CHAN_WKSTA, trust_passwd, challenge,
			smb_apasswd, smb_apasslen, smb_ntpasswd,
			smb_ntpasslen, info3);

		if (result == NT_STATUS_NOPROBLEMO ||
		    result == NT_STATUS_WRONG_PASSWORD)
			goto done;

		ip_list[i] = ipzero; /* Tried and failed */
	}

	/* OK try other DCs then */

	if (try_local) {
		try_local = False;
		goto retry;
	}

done:
	safe_free(ip_list);
	return result;
}

static uint32 check_passwordserver(fstring name_user, fstring name_domain,
				   uchar trust_passwd[16], 
				   const char *challenge,
				   const char *smb_apasswd, 
				   int smb_apasslen, 
				   const char *smb_ntpasswd, 
				   int smb_ntpasslen, 
				   NET_USER_INFO_3 *info3)
{
	fstring remote_machine;
	uint32 result = NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
	char *pserver;

	pserver = lp_passwordserver();

	while(next_token(&pserver, remote_machine, LIST_SEP, 
			 sizeof(remote_machine))) {
		fstring srv_name;

		/* Look up name of ip address */
		
		if (is_ipaddress(remote_machine)) {
			struct in_addr ip;

			inet_aton(remote_machine, &ip);

			if (!name_status_find(lp_workgroup(), 0x1c, 0x20, ip, srv_name)) {
				DEBUG(3, ("invalid server %s\n",
					  remote_machine));
				continue;
			}
		} else
			fstrcpy(srv_name, remote_machine);

		/* Return result of domain client validate */

		result = domain_client_validate_backend(
			srv_name, name_user, name_domain, global_myname,
			SEC_CHAN_WKSTA, trust_passwd, challenge,
			smb_apasswd, smb_apasslen, smb_ntpasswd,
			smb_ntpasslen, info3);

		if (result == NT_STATUS_NOPROBLEMO ||
		    result == NT_STATUS_WRONG_PASSWORD)
			break;
	}

	return result;	
}

/* Authenticate a user from a plaintext password */

enum winbindd_result winbindd_pam_auth(struct winbindd_cli_state *state) 
{
	NET_USER_INFO_3 info3;
	uchar ntpw[16];
	uchar lmpw[16];
	uchar trust_passwd[16];
	uint32 status;
	fstring name_domain, name_user;
	char *p;

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

	p = lp_passwordserver();
	if (strequal(p, ""))
		p = "*";

	if (strequal(p, "*"))
		status = check_any(
			name_user, name_domain, trust_passwd,
			NULL, lmpw, sizeof(lmpw), ntpw, sizeof(ntpw),
			&info3);
	else
		status = check_passwordserver(
			name_user, name_domain, trust_passwd,
			NULL, lmpw, sizeof(lmpw), ntpw, sizeof(ntpw),
			&info3);

	/* The group rids in the info3 structure are allocated dynamically
	   so make sure we free them. */

	if (info3.gids)
		free(info3.gids);

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
	fstring name_domain, name_user;
	char *p;

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

	p = lp_passwordserver();
	if (strequal(p, ""))
		p = "*";

	if (strequal(p, "*"))
		status = check_any(
			name_user, name_domain, trust_passwd,
			state->request.data.auth_crap.chal,
			state->request.data.auth_crap.lm_resp, 
			state->request.data.auth_crap.lm_resp_len,
			state->request.data.auth_crap.nt_resp, 
			state->request.data.auth_crap.nt_resp_len,
			&info3);
	else
		status = check_passwordserver(
			name_user, name_domain, trust_passwd,
			state->request.data.auth_crap.chal,
			state->request.data.auth_crap.lm_resp, 
			state->request.data.auth_crap.lm_resp_len,
			state->request.data.auth_crap.nt_resp, 
			state->request.data.auth_crap.nt_resp_len,
			&info3);

	/* The group rids in the info3 structure are allocated dynamically
	   so make sure we free them. */

	if (info3.gids)
		free(info3.gids);

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
