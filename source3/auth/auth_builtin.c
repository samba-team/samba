/* 
   Unix SMB/Netbios implementation.
   Version 3.0.
   Generic authenticaion types
   Copyright (C) Andrew Bartlett              2001
   
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

/**
 * Return a guest logon for guest users (username = "")
 *
 * Typically used as the first module in the auth chain, this allows
 * guest logons to be delt with in one place.  Non-gust logons 'fail'
 * and pass onto the next module.
 **/

static NTSTATUS check_guest_security(void *my_private_data, 
				     TALLOC_CTX *mem_ctx,
				     const auth_usersupplied_info *user_info, 
				     const auth_authsupplied_info *auth_info,
				     auth_serversupplied_info **server_info)
{
	NTSTATUS nt_status = NT_STATUS_LOGON_FAILURE;

	if (!(user_info->internal_username.str 
	      && *user_info->internal_username.str)) { 
		if (make_server_info_guest(server_info)) {
			nt_status = NT_STATUS_OK;
		} else {
			nt_status = NT_STATUS_NO_SUCH_USER;
		}
	}

	return nt_status;
}

/* Guest modules initialisation */
BOOL auth_init_guest(auth_methods **auth_method) 
{
	if (!make_auth_methods(auth_method)) {
		return False;
	}

	(*auth_method)->auth = check_guest_security;
	return True;
}

/** 
 * Return an error based on username
 *
 * This function allows the testing of obsure errors, as well as the generation
 * of NT_STATUS -> DOS error mapping tables.
 *
 * This module is of no value to end-users.
 *
 * The password is ignored.
 *
 * @return An NTSTATUS value based on the username
 **/

static NTSTATUS check_name_to_ntstatus_security(void *my_private_data,
						TALLOC_CTX *mem_ctx,
						const auth_usersupplied_info *user_info, 
						const auth_authsupplied_info *auth_info,
						auth_serversupplied_info **server_info)
{
	NTSTATUS nt_status;
	fstring user;
	long error_num;
	fstrcpy(user, user_info->smb_name.str);
	
	if (strncasecmp("NT_STATUS", user, strlen("NT_STATUS")) == 0) {
		strupper(user);
		return nt_status_string_to_code(user);
	}

	strlower(user);
	error_num = strtoul(user, NULL, 16);
	
	DEBUG(5,("Error for user %s was %lx\n", user, error_num));

	nt_status = NT_STATUS(error_num);
	
	return nt_status;
}

/** Module initailisation function */
BOOL auth_init_name_to_ntstatus(auth_methods **auth_method) 
{
	if (!make_auth_methods(auth_method)) {
		return False;
	}

	(*auth_method)->auth = check_name_to_ntstatus_security;
	return True;
}




