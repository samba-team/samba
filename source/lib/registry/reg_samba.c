/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Jelmer Vernooij			2004.

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
#include "registry.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_REGISTRY

static WERROR reg_samba_get_hive (struct registry_context *ctx, uint32 hkey, struct registry_key **k)
{
	WERROR error;
	const char *conf;
	char *backend, *location;
	const char *hivename = reg_get_hkey_name(hkey);

	*k = NULL;

	conf = lp_parm_string(-1, "registry", hivename);
	
	if (!conf) {
		return WERR_NOT_SUPPORTED;
	}

	backend = talloc_strdup(NULL, conf);
	location = strchr(backend, ':');

	if (location) {
		*location = '\0';
		location++;
	}
	
	error = reg_open_hive(ctx, backend, location, NULL, k);

	talloc_destroy(backend);

	return error;
}

WERROR reg_open_local (struct registry_context **ctx)
{
	*ctx = talloc_p(NULL, struct registry_context);
	(*ctx)->get_hive = reg_samba_get_hive;
	
	return WERR_OK;
}
