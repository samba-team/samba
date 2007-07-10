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

extern REGISTRY_OPS smbconf_reg_ops;

/*
 * create a fake token just with enough rights to
 * locally access the registry.
 */
NT_USER_TOKEN *registry_create_admin_token(TALLOC_CTX *mem_ctx)
{
	NT_USER_TOKEN *token = NULL;

	/* fake a user token: builtin administrators sid and the
	 * disk operators privilege is all we need to access the 
	 * registry... */
	if (!(token = TALLOC_ZERO_P(mem_ctx, NT_USER_TOKEN))) {
		DEBUG(1, ("talloc failed\n"));
		goto done;
	}
	token->privileges = se_disk_operators;
	if (!add_sid_to_array(token, &global_sid_Builtin_Administrators,
			 &token->user_sids, &token->num_sids)) {
		DEBUG(1, ("Error adding builtin administrators sid "
			  "to fake token.\n"));
		goto done;
	}
done:
	return token;
}

/*
 * init the smbconf portion of the registry.
 * for use in places where not the whole registry is needed,
 * e.g. utils/net_conf.c and loadparm.c
 */
BOOL registry_init_regdb(void)
{
	BOOL ret = False;
	int saved_errno = 0;
	static REGISTRY_HOOK smbconf_reg_hook = {KEY_SMBCONF, &smbconf_reg_ops};

	DEBUG(10, ("registry_init_regdb called\n"));

	if (!regdb_init()) {
		saved_errno = errno;
		DEBUG(1, ("Can't open the registry"));
		if (saved_errno) {
			DEBUGADD(1, (": %s", strerror(saved_errno)));
		}
		DEBUGADD(1, (".\n"));
		goto done;
	}
	reghook_cache_init();
	if (!reghook_cache_add(&smbconf_reg_hook)) {
		DEBUG(1, ("Error adding smbconf reghooks to reghook cache.\n"));
		goto done;
	}

	ret = True;

done:
	return ret;
}
