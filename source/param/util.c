/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 2001-2002
   Copyright (C) Simo Sorce 2001
   Copyright (C) Jim McDonough (jmcd@us.ibm.com)  2003.
   Copyright (C) James J Myers 2003
   
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
#include "dynconfig.h"
#include "system/network.h"
#include "system/filesys.h"

/**
 * @file
 * @brief Misc utility functions
 */


/**
  see if a string matches either our primary or one of our secondary 
  netbios aliases. do a case insensitive match
*/
_PUBLIC_ BOOL is_myname(const char *name)
{
	const char **aliases;
	int i;

	if (strcasecmp(name, lp_netbios_name()) == 0) {
		return True;
	}

	aliases = lp_netbios_aliases();
	for (i=0; aliases && aliases[i]; i++) {
		if (strcasecmp(name, aliases[i]) == 0) {
			return True;
		}
	}

	return False;
}


/**
 A useful function for returning a path in the Samba lock directory.
**/
_PUBLIC_ char *lock_path(TALLOC_CTX* mem_ctx, const char *name)
{
	char *fname, *dname;
	if (name == NULL) {
		return NULL;
	}
	if (name[0] == 0 || name[0] == '/' || strstr(name, ":/")) {
		return talloc_strdup(mem_ctx, name);
	}

	dname = talloc_strdup(mem_ctx, lp_lockdir());
	trim_string(dname,"","/");
	
	if (!directory_exist(dname)) {
		mkdir(dname,0755);
	}
	
	fname = talloc_asprintf(mem_ctx, "%s/%s", dname, name);

	talloc_free(dname);

	return fname;
}


/**
 A useful function for returning a path in the Samba piddir directory.
**/
static char *pid_path(TALLOC_CTX* mem_ctx, const char *name)
{
	char *fname, *dname;

	dname = talloc_strdup(mem_ctx, lp_piddir());
	trim_string(dname,"","/");
	
	if (!directory_exist(dname)) {
		mkdir(dname,0755);
	}
	
	fname = talloc_asprintf(mem_ctx, "%s/%s", dname, name);

	talloc_free(dname);

	return fname;
}


/**
 * @brief Returns an absolute path to a file in the Samba lib directory.
 *
 * @param name File to find, relative to DATADIR.
 *
 * @retval Pointer to a talloc'ed string containing the full path.
 **/

_PUBLIC_ char *data_path(TALLOC_CTX* mem_ctx, const char *name)
{
	char *fname;
	fname = talloc_asprintf(mem_ctx, "%s/%s", dyn_DATADIR, name);
	return fname;
}

/**
 * @brief Returns an absolute path to a file in the Samba private directory.
 *
 * @param name File to find, relative to PRIVATEDIR.
 * if name is not relative, then use it as-is
 *
 * @retval Pointer to a talloc'ed string containing the full path.
 **/
_PUBLIC_ char *private_path(TALLOC_CTX* mem_ctx, const char *name)
{
	char *fname;
	if (name == NULL) {
		return NULL;
	}
	if (name[0] == 0 || name[0] == '/' || strstr(name, ":/")) {
		return talloc_strdup(mem_ctx, name);
	}
	fname = talloc_asprintf(mem_ctx, "%s/%s", lp_private_dir(), name);
	return fname;
}

/**
  return a path in the smbd.tmp directory, where all temporary file
  for smbd go. If NULL is passed for name then return the directory 
  path itself
*/
_PUBLIC_ char *smbd_tmp_path(TALLOC_CTX *mem_ctx, const char *name)
{
	char *fname, *dname;

	dname = pid_path(mem_ctx, "smbd.tmp");
	if (!directory_exist(dname)) {
		mkdir(dname,0755);
	}

	if (name == NULL) {
		return dname;
	}

	fname = talloc_asprintf(mem_ctx, "%s/%s", dname, name);
	talloc_free(dname);

	return fname;
}

static char *modules_path(TALLOC_CTX* mem_ctx, const char *name)
{
	const char *env_moduledir = getenv("LD_SAMBA_MODULE_PATH");
	return talloc_asprintf(mem_ctx, "%s/%s", 
						   env_moduledir?env_moduledir:lp_modulesdir(), 
						   name);
}

/**
 * Load the initialization functions from DSO files for a specific subsystem.
 *
 * Will return an array of function pointers to initialization functions
 */

_PUBLIC_ init_module_fn *load_samba_modules(TALLOC_CTX *mem_ctx, const char *subsystem)
{
	char *path = modules_path(mem_ctx, subsystem);
	init_module_fn *ret;

	ret = load_modules(mem_ctx, path);

	talloc_free(path);

	return ret;
}


