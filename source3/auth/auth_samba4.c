/*
   Unix SMB/CIFS implementation.
   Authenticate against Samba4's auth subsystem
   Copyright (C) Volker Lendecke 2008
   Copyright (C) Andrew Bartlett 2010

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
#include "source3/include/auth.h"
#include "source4/auth/auth.h"
#include "auth/auth_sam_reply.h"
#include "param/param.h"
#include "source4/lib/events/events.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

static NTSTATUS check_samba4_security(const struct auth_context *auth_context,
				      void *my_private_data,
				      TALLOC_CTX *mem_ctx,
				      const struct auth_usersupplied_info *user_info,
				      struct auth_serversupplied_info **server_info)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct netr_SamInfo3 *info3 = NULL;
	NTSTATUS nt_status;
	struct auth_user_info_dc *user_info_dc;
	struct auth4_context *auth4_context;
	struct loadparm_context *lp_ctx;
	const char *config_file;

	lp_ctx = loadparm_init(frame);
	if (lp_ctx == NULL) {
		DEBUG(10, ("loadparm_init failed\n"));
		talloc_free(frame);
		return NT_STATUS_INVALID_SERVER_STATE;
	}

	if (lp_loaded()) {
		config_file = lp_configfile();
	}
	if (!config_file || !config_file[0]) {
		config_file = get_dyn_CONFIGFILE();
	}

	if (!lpcfg_load(lp_ctx, config_file)) {
		DEBUG(1, ("s4 lpcfg_load() of s3 config file %s failed", config_file));
		talloc_free(frame);
		return NT_STATUS_INVALID_SERVER_STATE;
	}

	/* We create a private tevent context here to avoid nested loops in
	 * the s3 one, as that may not be expected */
	nt_status = auth_context_create(mem_ctx,
					s4_event_context_init(frame), NULL, 
					lp_ctx,
					&auth4_context);
	NT_STATUS_NOT_OK_RETURN(nt_status);
		
	nt_status = auth_context_set_challenge(auth4_context, auth_context->challenge.data, "auth_samba4");
	NT_STATUS_NOT_OK_RETURN_AND_FREE(nt_status, auth4_context);

	nt_status = auth_check_password(auth4_context, auth4_context, user_info, &user_info_dc);
	NT_STATUS_NOT_OK_RETURN_AND_FREE(nt_status, auth4_context);
	
	nt_status = auth_convert_user_info_dc_saminfo3(mem_ctx,
						       user_info_dc,
						       &info3);
	if (NT_STATUS_IS_OK(nt_status)) {
		/* We need the strings from the server_info to be valid as long as the info3 is around */
		talloc_steal(info3, user_info_dc);
	}
	talloc_free(auth4_context);

	if (!NT_STATUS_IS_OK(nt_status)) {
		goto done;
	}

	nt_status = make_server_info_info3(mem_ctx, user_info->client.account_name,
					   user_info->mapped.domain_name, server_info,
					info3);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(10, ("make_server_info_info3 failed: %s\n",
			   nt_errstr(nt_status)));
		TALLOC_FREE(frame);
		return nt_status;
	}

	nt_status = NT_STATUS_OK;

 done:
	TALLOC_FREE(frame);
	return nt_status;
}

/* module initialisation */
static NTSTATUS auth_init_samba4(struct auth_context *auth_context,
				    const char *param,
				    auth_methods **auth_method)
{
	struct auth_methods *result;

	result = TALLOC_ZERO_P(auth_context, struct auth_methods);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	result->name = "samba4";
	result->auth = check_samba4_security;

        *auth_method = result;
	return NT_STATUS_OK;
}

NTSTATUS auth_samba4_init(void)
{
	smb_register_auth(AUTH_INTERFACE_VERSION, "samba4",
			  auth_init_samba4);
	return NT_STATUS_OK;
}
