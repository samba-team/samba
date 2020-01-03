/* 
   Unix SMB/CIFS implementation.
   Password and authentication handling
   Copyright (C) Andrew Bartlett              2001

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
#include "auth.h"
#include "system/passwd.h"
#include "../lib/tsocket/tsocket.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

/** Check a plaintext username/password
 *
 * Cannot deal with an encrupted password in any manner whatsoever,
 * unless the account has a null password.
 **/

static NTSTATUS check_unix_security(const struct auth_context *auth_context,
			     void *my_private_data, 
			     TALLOC_CTX *mem_ctx,
			     const struct auth_usersupplied_info *user_info,
			     struct auth_serversupplied_info **server_info)
{
	NTSTATUS nt_status;
	struct passwd *pass = NULL;
	const char *rhost;

	DEBUG(10, ("Check auth for: [%s]\n", user_info->mapped.account_name));

	if (tsocket_address_is_inet(user_info->remote_host, "ip")) {
		rhost = tsocket_address_inet_addr_string(user_info->remote_host,
							 talloc_tos());
		if (rhost == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		rhost = "127.0.0.1";
	}

	become_root();
	pass = Get_Pwnam_alloc(talloc_tos(), user_info->mapped.account_name);

	/** @todo This call assumes a ASCII password, no charset transformation is 
	    done.  We may need to revisit this **/
	nt_status = pass_check(pass,
				pass ? pass->pw_name : user_info->mapped.account_name,
				rhost,
				user_info->password.plaintext,
				true);

	unbecome_root();

	if (NT_STATUS_IS_OK(nt_status)) {
		if (pass != NULL) {
			nt_status = make_server_info_pw(mem_ctx,
							pass->pw_name,
							pass,
							server_info);
		} else {
			/* we need to do something more useful here */
			nt_status = NT_STATUS_NO_SUCH_USER;
		}
	}

	TALLOC_FREE(pass);
	return nt_status;
}

/* module initialisation */
static NTSTATUS auth_init_unix(
	struct auth_context *auth_context,
	const char* param,
	struct auth_methods **auth_method)
{
	struct auth_methods *result;

	result = talloc_zero(auth_context, struct auth_methods);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	result->name = "unix";
	result->auth = check_unix_security;

	*auth_method = result;
	return NT_STATUS_OK;
}

NTSTATUS auth_unix_init(TALLOC_CTX *mem_ctx)
{
	return smb_register_auth(AUTH_INTERFACE_VERSION, "unix", auth_init_unix);
}
