/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Authenticate against a remote domain
   Copyright (C) Andrew Tridgell 1992-1998
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

BOOL global_machine_password_needs_changing = False;

/****************************************************************************
 Check for a valid username and password in security=domain mode.
****************************************************************************/

static NTSTATUS check_ntdomain_security(void *my_private_data,
					const auth_usersupplied_info *user_info, 
					const auth_authsupplied_info *auth_info,
					auth_serversupplied_info **server_info)
{
	NTSTATUS nt_status = NT_STATUS_LOGON_FAILURE;
	char *p, *pserver;
	unsigned char trust_passwd[16];
	time_t last_change_time;

	become_root();

	/*
	 * Get the machine account password for our primary domain
	 */

	if (!secrets_fetch_trust_account_password(lp_workgroup(), trust_passwd, &last_change_time))
	{
		DEBUG(0, ("check_domain_security: could not fetch trust account password for domain %s\n", lp_workgroup()));
		unbecome_root();
		return NT_STATUS_LOGON_FAILURE;
	}

	unbecome_root();

	/* Test if machine password is expired and need to be changed */
	if (time(NULL) > last_change_time + lp_machine_password_timeout())
	{
		global_machine_password_needs_changing = True;
	}

	/*
	 * Treat each name in the 'password server =' line as a potential
	 * PDC/BDC. Contact each in turn and try and authenticate.
	 */

	pserver = lp_passwordserver();
	if (! *pserver) pserver = "*";
	p = pserver;

	nt_status = domain_client_validate(user_info, (uchar *)auth_info->challange.data,server_info, 
					   p, trust_passwd, last_change_time);

	return nt_status;
}

BOOL auth_init_ntdomain(auth_methods **auth_method) 
{
	if (!make_auth_methods(auth_method)) {
		return False;
	}

	(*auth_method)->auth = check_ntdomain_security;
	return True;
}
