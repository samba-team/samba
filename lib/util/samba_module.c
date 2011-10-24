/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Jelmer Vernooij 2002-2003,2005-2007
   Copyright (C) Stefan (metze) Metzmacher 2003
   Copyright (C) Andrew Bartlett 2011

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
#include "dynconfig/dynconfig.h"
#include "lib/util/internal_module.h"
#include "system/filesys.h"
#include "system/dir.h"

/**
 * Run the specified init functions.
 *
 * @return true if all functions ran successfully, false otherwise
 */
bool samba_module_init_fns_run(samba_module_init_fn *fns)
{
	int i;
	bool ret = true;

	if (fns == NULL)
		return true;

	for (i = 0; fns[i]; i++) { ret &= (bool)NT_STATUS_IS_OK(fns[i]()); }

	return ret;
}

/**
 * Load the initialization functions from DSO files for a specific subsystem.
 *
 * Will return an array of function pointers to initialization functions
 */

samba_module_init_fn *samba_modules_load(TALLOC_CTX *mem_ctx, const char *subsystem)
{
	char *path = modules_path(mem_ctx, subsystem);
	samba_module_init_fn *ret;

	ret = load_modules(mem_ctx, path);

	talloc_free(path);

	return ret;
}
