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
/************************************************************************
form a key for fetching a domain trust password
************************************************************************/
static char *trust_keystr(char *domain)
{
	static fstring keystr;
	slprintf(keystr,sizeof(keystr),"%s/%s", SECRETS_MACHINE_ACCT_PASS, domain);
	return keystr;
}

/************************************************************************
 Routine to get the trust account password for a domain.
 The user of this function must have locked the trust password file.
************************************************************************/
static BOOL _get_trust_account_password(char *domain, unsigned char *ret_pwd, time_t *pass_last_set_time)
{
	struct machine_acct_pass *pass;
	size_t size;

	if (!(pass = secrets_fetch(trust_keystr(domain), &size)) ||
	    size != sizeof(*pass)) return False;

	if (pass_last_set_time) *pass_last_set_time = pass->mod_time;
	memcpy(ret_pwd, pass->hash, 16);
	free(pass);
	return True;
}


/* Return a password structure from a username.  Specify whether cached data 
   can be returned. */

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

	DEBUG(1,("winbindd_pam_auth user=%s\n", 
		 state->request.data.auth.user));

	/* Parse domain and username */
	parse_domain_user(state->request.data.auth.user, name_domain, name_user);

	/* don't allow the null domain */
	if (strcmp(name_domain,"") == 0) return WINBINDD_ERROR;

	ZERO_STRUCT(info3);

	if (!_get_trust_account_password(lp_workgroup(), trust_passwd, NULL)) return WINBINDD_ERROR;

	nt_lm_owf_gen(state->request.data.auth.pass, ntpw, lmpw);

	slprintf(server, sizeof(server), "\\\\%s", server_state.controller);

	status = domain_client_validate_backend(server, 
						name_user, name_domain,
						global_myname, SEC_CHAN_WKSTA,
						trust_passwd,
						NULL,
						lmpw, sizeof(lmpw),
						ntpw, sizeof(ntpw), &info3);

	if (status != NT_STATUS_NOPROBLEMO) return WINBINDD_ERROR;

	return WINBINDD_OK;
}

