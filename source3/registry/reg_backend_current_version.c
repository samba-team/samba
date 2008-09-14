/*
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Gerald Carter     2002-2005
 *  Copyright (C) Michael Adam      2008
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * CurrentVersion registry backend.
 *
 * This is a virtual overlay, dynamically presenting version information.
 */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_REGISTRY

extern REGISTRY_OPS regdb_ops;

#define KEY_CURRENT_VERSION_NORM "HKLM/SOFTWARE/MICROSOFT/WINDOWS NT/CURRENTVERSION"

static int current_version_fetch_values(const char *key, REGVAL_CTR *values)
{
	const char *sysroot_string = "c:\\Windows";
	fstring sysversion;
	fstring value;
	uint32 value_length;
	char *path = NULL;
	TALLOC_CTX *ctx = talloc_tos();

	path = talloc_strdup(ctx, key);
	if (path == NULL) {
		return -1;
	}
	path = normalize_reg_path(ctx, path);
	if (path == NULL) {
		return -1;
	}

	if (strncmp(path, KEY_CURRENT_VERSION_NORM, strlen(path)) != 0) {
		return regdb_ops.fetch_values(key, values);
	}

	value_length = push_ucs2(value, value, sysroot_string, sizeof(value),
				 STR_TERMINATE|STR_NOALIGN );
	regval_ctr_addvalue(values, "SystemRoot", REG_SZ, value, value_length);

	fstr_sprintf(sysversion, "%d.%d", lp_major_announce_version(),
		     lp_minor_announce_version());
	value_length = push_ucs2(value, value, sysversion, sizeof(value),
				 STR_TERMINATE|STR_NOALIGN);
	regval_ctr_addvalue(values, "CurrentVersion", REG_SZ, value,
			    value_length);

	return regval_ctr_numvals(values);
}

static int current_version_fetch_subkeys(const char *key,
					 REGSUBKEY_CTR *subkey_ctr)
{
	return regdb_ops.fetch_subkeys(key, subkey_ctr);
}

REGISTRY_OPS current_version_reg_ops = {
	.fetch_values = current_version_fetch_values,
	.fetch_subkeys = current_version_fetch_subkeys,
};
