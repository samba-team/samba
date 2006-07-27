/* 
   Unix SMB/CIFS implementation.

   Anonymous Authentification

   Copyright (C) Stefan Metzmacher            2004-2005
   
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
#include "auth/auth.h"

/**
 * Return a anonymous logon for anonymous users (username = "")
 *
 * Typically used as the first module in the auth chain, this allows
 * anonymou logons to be dealt with in one place.  Non-anonymou logons 'fail'
 * and pass onto the next module.
 **/
static NTSTATUS anonymous_want_check(struct auth_method_context *ctx,
			      	     TALLOC_CTX *mem_ctx,
				     const struct auth_usersupplied_info *user_info)
{
	if (user_info->client.account_name && *user_info->client.account_name) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	return NT_STATUS_OK;
}

/**
 * Return a anonymous logon for anonymous users (username = "")
 *
 * Typically used as the first module in the auth chain, this allows
 * anonymou logons to be dealt with in one place.  Non-anonymou logons 'fail'
 * and pass onto the next module.
 **/
static NTSTATUS anonymous_check_password(struct auth_method_context *ctx,
			      		 TALLOC_CTX *mem_ctx,
					 const struct auth_usersupplied_info *user_info, 
					 struct auth_serversupplied_info **_server_info)
{
	return auth_anonymous_server_info(mem_ctx, _server_info);
}

static struct auth_operations anonymous_auth_ops = {
	.name		= "anonymous",
	.get_challenge	= auth_get_challenge_not_implemented,
	.want_check	= anonymous_want_check,
	.check_password	= anonymous_check_password
};

NTSTATUS auth_anonymous_init(void)
{
	NTSTATUS ret;

	ret = auth_register(&anonymous_auth_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register 'anonymous' auth backend!\n"));
		return ret;
	}

	return ret;
}
