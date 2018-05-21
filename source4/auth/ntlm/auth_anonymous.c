/* 
   Unix SMB/CIFS implementation.

   Anonymous Authentification

   Copyright (C) Stefan Metzmacher            2004-2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "auth/auth.h"
#include "auth/ntlm/auth_proto.h"
#include "param/param.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

_PUBLIC_ NTSTATUS auth4_anonymous_init(TALLOC_CTX *);

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

	switch (user_info->password_state) {
	case AUTH_PASSWORD_PLAIN:
		if (user_info->password.plaintext != NULL &&
		    strlen(user_info->password.plaintext) > 0)
		{
			return NT_STATUS_NOT_IMPLEMENTED;
		}
		break;
	case AUTH_PASSWORD_HASH:
		if (user_info->password.hash.lanman != NULL) {
			return NT_STATUS_NOT_IMPLEMENTED;
		}
		if (user_info->password.hash.nt != NULL) {
			return NT_STATUS_NOT_IMPLEMENTED;
		}
		break;
	case AUTH_PASSWORD_RESPONSE:
		if (user_info->password.response.lanman.length == 1) {
			if (user_info->password.response.lanman.data[0] != '\0') {
				return NT_STATUS_NOT_IMPLEMENTED;
			}
		} else if (user_info->password.response.lanman.length > 1) {
			return NT_STATUS_NOT_IMPLEMENTED;
		}
		if (user_info->password.response.nt.length > 0) {
			return NT_STATUS_NOT_IMPLEMENTED;
		}
		break;
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
					 struct auth_user_info_dc **_user_info_dc,
					 bool *authoritative)
{
	return auth_anonymous_user_info_dc(mem_ctx, lpcfg_netbios_name(ctx->auth_ctx->lp_ctx), _user_info_dc);
}

static const struct auth_operations anonymous_auth_ops = {
	.name		= "anonymous",
	.want_check	= anonymous_want_check,
	.check_password	= anonymous_check_password
};

_PUBLIC_ NTSTATUS auth4_anonymous_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret;

	ret = auth_register(ctx, &anonymous_auth_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register 'anonymous' auth backend!\n"));
		return ret;
	}

	return ret;
}
