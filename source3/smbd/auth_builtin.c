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

/****************************************************************************
 Check for a guest logon (username = "") and if so create the required 
 structure.
****************************************************************************/

static NTSTATUS check_guest_security(void *my_private_data, 
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

BOOL auth_init_guest(auth_methods **auth_method) 
{
	if (!make_auth_methods(auth_method)) {
		return False;
	}

	(*auth_method)->auth = check_guest_security;
	return True;
}

/****************************************************************************
 Check against either sam or unix, depending on encryption.
****************************************************************************/

static NTSTATUS check_local_security(void *my_private_data,
			      const auth_usersupplied_info *user_info, 
			      const auth_authsupplied_info *auth_info,
			      auth_serversupplied_info **server_info)
{
	NTSTATUS nt_status = NT_STATUS_LOGON_FAILURE;

	if (user_info->encrypted) {
		nt_status = check_sam_security(my_private_data, user_info, auth_info, server_info);
	} else {
		nt_status = check_unix_security(my_private_data, user_info, auth_info, server_info);
	}
	
	return nt_status;
}

BOOL auth_init_local(auth_methods **auth_method) 
{
	if (!make_auth_methods(auth_method)) {
		return False;
	}

	(*auth_method)->auth = check_local_security;
	return True;
}

