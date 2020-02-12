/* 
   Unix SMB/CIFS implementation.
   Password and authentication handling
   Copyright (C) Andrew Tridgell              1992-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Andrew Bartlett              2001-2003
   Copyright (C) Gerald Carter                2003

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

static NTSTATUS auth_sam_ignoredomain_auth(const struct auth_context *auth_context,
					   void *my_private_data,
					   TALLOC_CTX *mem_ctx,
					   const struct auth_usersupplied_info *user_info,
					   struct auth_serversupplied_info **server_info)
{
	if (!user_info || !auth_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (user_info->mapped.account_name == NULL ||
	    user_info->mapped.account_name[0] == '\0')
	{
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	DBG_DEBUG("Check auth for: [%s]\\[%s]\n",
		  user_info->mapped.domain_name,
		  user_info->mapped.account_name);

	return check_sam_security(&auth_context->challenge, mem_ctx,
				  user_info, server_info);
}

/* module initialisation */
static NTSTATUS auth_init_sam_ignoredomain(
	struct auth_context *auth_context,
	const char *param,
	struct auth_methods **auth_method)
{
	struct auth_methods *result;

	result = talloc_zero(auth_context, struct auth_methods);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	result->auth = auth_sam_ignoredomain_auth;
	result->name = "sam_ignoredomain";

        *auth_method = result;
	return NT_STATUS_OK;
}


/****************************************************************************
Check SAM security (above) but with a few extra checks.
****************************************************************************/

static NTSTATUS auth_samstrict_auth(const struct auth_context *auth_context,
				    void *my_private_data,
				    TALLOC_CTX *mem_ctx,
				    const struct auth_usersupplied_info *user_info,
				    struct auth_serversupplied_info **server_info)
{
	const char *effective_domain = NULL;
	bool is_local_name, is_my_domain;

	if (!user_info || !auth_context) {
		return NT_STATUS_LOGON_FAILURE;
	}
	effective_domain = user_info->mapped.domain_name;

	if (user_info->mapped.account_name == NULL ||
	    user_info->mapped.account_name[0] == '\0')
	{
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (lp_server_role() == ROLE_DOMAIN_MEMBER) {
		const char *p = NULL;

		p = strchr_m(user_info->mapped.account_name, '@');
		if (p != NULL) {
			/*
			 * This needs to go to the DC,
			 * even if @ is the last character
			 */
			return NT_STATUS_NOT_IMPLEMENTED;
		}
	}

	if (effective_domain == NULL) {
		effective_domain = "";
	}

	DBG_DEBUG("Check auth for: [%s]\\[%s]\n",
		  effective_domain,
		  user_info->mapped.account_name);


	if (strequal(effective_domain, "") || strequal(effective_domain, ".")) {
		/*
		 * An empty domain name or '.' should be handled
		 * as the local SAM name.
		 */
		effective_domain = lp_netbios_name();
	}

	is_local_name = is_myname(effective_domain);
	is_my_domain  = strequal(effective_domain, lp_workgroup());

	/* check whether or not we service this domain/workgroup name */

	switch ( lp_server_role() ) {
		case ROLE_STANDALONE:
		case ROLE_DOMAIN_MEMBER:
			if ( !is_local_name ) {
				DEBUG(6,("check_samstrict_security: %s is not one of my local names (%s)\n",
					effective_domain, (lp_server_role() == ROLE_DOMAIN_MEMBER
					? "ROLE_DOMAIN_MEMBER" : "ROLE_STANDALONE") ));
				return NT_STATUS_NOT_IMPLEMENTED;
			}

			break;
		case ROLE_DOMAIN_PDC:
		case ROLE_DOMAIN_BDC:
			if ( !is_local_name && !is_my_domain ) {
				DEBUG(6,("check_samstrict_security: %s is not one of my local names or domain name (DC)\n",
					effective_domain));
				return NT_STATUS_NOT_IMPLEMENTED;
			}

			break;
		default: /* name is ok */
			break;
	}

	return check_sam_security(&auth_context->challenge, mem_ctx,
				  user_info, server_info);
}

/* module initialisation */
static NTSTATUS auth_init_sam(
	struct auth_context *auth_context,
	const char *param,
	struct auth_methods **auth_method)
{
	struct auth_methods *result;

	if (lp_server_role() == ROLE_ACTIVE_DIRECTORY_DC
	    && !lp_parm_bool(-1, "server role check", "inhibit", false)) {
		DEBUG(0, ("server role = 'active directory domain controller' not compatible with running the auth_sam module. \n"));
		DEBUGADD(0, ("You should not set 'auth methods' when running the AD DC.\n"));
		exit(1);
	}

	result = talloc_zero(auth_context, struct auth_methods);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	result->auth = auth_samstrict_auth;
	result->name = "sam";
	*auth_method = result;
	return NT_STATUS_OK;
}

static NTSTATUS auth_sam_netlogon3_auth(const struct auth_context *auth_context,
					void *my_private_data,
					TALLOC_CTX *mem_ctx,
					const struct auth_usersupplied_info *user_info,
					struct auth_serversupplied_info **server_info)
{
	const char *effective_domain = NULL;
	bool is_my_domain;

	if (!user_info || !auth_context) {
		return NT_STATUS_LOGON_FAILURE;
	}
	effective_domain = user_info->mapped.domain_name;

	if (user_info->mapped.account_name == NULL ||
	    user_info->mapped.account_name[0] == '\0')
	{
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (effective_domain == NULL) {
		effective_domain = "";
	}

	DBG_DEBUG("Check auth for: [%s]\\[%s]\n",
		  effective_domain,
		  user_info->mapped.account_name);

	/* check whether or not we service this domain/workgroup name */

	switch (lp_server_role()) {
	case ROLE_DOMAIN_PDC:
	case ROLE_DOMAIN_BDC:
		break;
	default:
		DBG_ERR("Invalid server role\n");
		return NT_STATUS_INVALID_SERVER_STATE;
	}

	if (strequal(effective_domain, "") || strequal(effective_domain, ".")) {
		/*
		 * An empty domain name or '.' should be handled
		 * as the local SAM name.
		 */
		effective_domain = lp_workgroup();
	}

	is_my_domain = strequal(user_info->mapped.domain_name, lp_workgroup());
	if (!is_my_domain) {
		DBG_INFO("%s is not our domain name (DC for %s)\n",
			 effective_domain, lp_workgroup());
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	return check_sam_security(&auth_context->challenge, mem_ctx,
				  user_info, server_info);
}

/* module initialisation */
static NTSTATUS auth_init_sam_netlogon3(
	struct auth_context *auth_context,
	const char *param,
	struct auth_methods **auth_method)
{
	struct auth_methods *result;

	if (lp_server_role() == ROLE_ACTIVE_DIRECTORY_DC
	    && !lp_parm_bool(-1, "server role check", "inhibit", false)) {
		DEBUG(0, ("server role = 'active directory domain controller' "
			  "not compatible with running the auth_sam module.\n"));
		DEBUGADD(0, ("You should not set 'auth methods' when "
			     "running the AD DC.\n"));
		exit(1);
	}

	result = talloc_zero(auth_context, struct auth_methods);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	result->auth = auth_sam_netlogon3_auth;
	result->name = "sam_netlogon3";
	*auth_method = result;
	return NT_STATUS_OK;
}

NTSTATUS auth_sam_init(TALLOC_CTX *mem_ctx)
{
	smb_register_auth(AUTH_INTERFACE_VERSION, "sam", auth_init_sam);
	smb_register_auth(AUTH_INTERFACE_VERSION, "sam_ignoredomain", auth_init_sam_ignoredomain);
	smb_register_auth(AUTH_INTERFACE_VERSION, "sam_netlogon3", auth_init_sam_netlogon3);
	return NT_STATUS_OK;
}
