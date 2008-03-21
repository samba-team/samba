/*
 * Unix SMB/CIFS implementation.
 * Registry helper routines
 * Copyright (C) Michael Adam 2007
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_REGISTRY

extern REGISTRY_OPS smbconf_reg_ops;

/*
 * create a fake token just with enough rights to
 * locally access the registry:
 *
 * - builtin administrators sid
 * - disk operators privilege
 */
NTSTATUS registry_create_admin_token(TALLOC_CTX *mem_ctx,
				     NT_USER_TOKEN **ptoken)
{
	NTSTATUS status;
	NT_USER_TOKEN *token = NULL;

	if (ptoken == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	token = TALLOC_ZERO_P(mem_ctx, NT_USER_TOKEN);
	if (token == NULL) {
		DEBUG(1, ("talloc failed\n"));
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	token->privileges = se_disk_operators;
	status = add_sid_to_array(token, &global_sid_Builtin_Administrators,
				  &token->user_sids, &token->num_sids);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Error adding builtin administrators sid "
			  "to fake token.\n"));
		goto done;
	}

	*ptoken = token;

done:
	return status;
}

/*
 * init the smbconf portion of the registry.
 * for use in places where not the whole registry is needed,
 * e.g. utils/net_conf.c and loadparm.c
 */
bool registry_init_smbconf(void)
{
	bool ret = false;
	int saved_errno = 0;
	static REGISTRY_HOOK smbconf_reg_hook = {KEY_SMBCONF, &smbconf_reg_ops};

	DEBUG(10, ("registry_init_smbconf called\n"));

	if (!regdb_init()) {
		saved_errno = errno;
		DEBUG(1, ("Can't open the registry"));
		if (saved_errno) {
			DEBUGADD(1, (": %s", strerror(saved_errno)));
		}
		DEBUGADD(1, (".\n"));
		goto done;
	}
	if (!init_registry_key(KEY_SMBCONF)) {
		DEBUG(1, ("Could not initialize registry key '%s'\n",
			  KEY_SMBCONF));
		goto done;
	}
	reghook_cache_init();
	if (!reghook_cache_add(&smbconf_reg_hook)) {
		DEBUG(1, ("Error adding smbconf reghooks to reghook cache.\n"));
		goto done;
	}

	regdb_close();

	ret = true;

done:
	return ret;
}
