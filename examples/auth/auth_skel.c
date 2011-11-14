/* 
   Unix SMB/CIFS implementation.
   Password and authentication handling
   Copyright (C) Andrew Bartlett              2001
   Copyright (C) Jelmer Vernooij			  2003
   
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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

static NTSTATUS check_skel_security(const struct auth_context *auth_context,
					 void *my_private_data, 
					 TALLOC_CTX *mem_ctx,
					 const struct auth_usersupplied_info *user_info,
					 struct auth_serversupplied_info **server_info)
{
	if (!user_info || !auth_context) {
		return NT_STATUS_LOGON_FAILURE;
	}

	/* Insert your authentication checking code here, 
	 * and return NT_STATUS_OK if authentication succeeds */

	/* For now, just refuse all connections */
	return NT_STATUS_LOGON_FAILURE;
}

/* module initialisation */
static NTSTATUS auth_init_skel(struct auth_context *auth_context, const char *param, auth_methods **auth_method)
{
	struct auth_methods *result;

	result = talloc_zero(auth_context, struct auth_methods);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	result->name = "skel";
	result->auth = check_skel_security;

	if (param && *param) {
		/* we load the 'fallback' module - if skel isn't here, call this
		   module */
		auth_methods *priv;
		if (!load_auth_module(auth_context, param, &priv)) {
			return NT_STATUS_UNSUCCESSFUL;
		}
		result->private_data = (void *)priv;
	}

        *auth_method = result;
	return NT_STATUS_OK;
}

NTSTATUS auth_skel_init(void);
NTSTATUS auth_skel_init(void)
{
	return smb_register_auth(AUTH_INTERFACE_VERSION, "skel", auth_init_skel);
}
