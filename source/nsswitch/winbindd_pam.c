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

/* Return a password structure from a username.  Specify whether cached data 
   can be returned. */

enum winbindd_result winbindd_pam_auth(struct winbindd_cli_state *state) 
{
	NET_USER_INFO_3 info3;
	uchar ntpw[16];
	uchar lmpw[16];
	uint32 status;
	fstring name_domain, name_user;
	extern pstring global_myname;

	DEBUG(1,("winbindd_pam_auth user=%s pass=%s\n", 
		 state->request.data.auth.user,
		 state->request.data.auth.pass));

	/* Parse domain and username */
	parse_domain_user(state->request.data.auth.user, name_domain, name_user);

	/* don't allow the null domain */
	if (strcmp(name_domain,"") == 0) return WINBINDD_ERROR;

	ZERO_STRUCT(info3);

	nt_lm_owf_gen(state->request.data.auth.pass, ntpw, lmpw);

	status = domain_client_validate(server_state.controller, 
					name_user, name_domain,
					global_myname, SEC_CHAN_WKSTA,
					NULL,
					lmpw, sizeof(lmpw),
					ntpw, sizeof(ntpw), &info3);

	if (status != NT_STATUS_NOPROBLEMO) return WINBINDD_ERROR;

	return WINBINDD_OK;
}

enum winbindd_result winbindd_pam_account(struct winbindd_cli_state *state) 
{
	/* say account exists if we can do a getpwnam */
	return winbindd_getpwnam_from_user(state);
}
