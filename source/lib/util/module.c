/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Jelmer Vernooij 2005
   
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

/**
 * @file
 * @brief Module initialization function handling
 */

#include "includes.h"
#include "system/dir.h"

/**
 * Obtain the init function from a shared library file
 */
_PUBLIC_ init_module_fn load_module(TALLOC_CTX *mem_ctx, const char *path)
{
	void *handle;
	void *init_fn;

	handle = dlopen(path, RTLD_NOW);
	if (handle == NULL) {
		DEBUG(0, ("Unable to open %s: %s\n", path, dlerror()));
		return NULL;
	}

	init_fn = dlsym(handle, "init_module");

	if (init_fn == NULL) {
		DEBUG(0, ("Unable to find init_module() in %s: %s\n", path, dlerror()));
		DEBUG(1, ("Loading module '%s' failed\n", path));
		dlclose(handle);
		return NULL;
	}

	return (init_module_fn)init_fn;
}

/**
 * Obtain list of init functions from the modules in the specified
 * directory
 */
_PUBLIC_ init_module_fn *load_modules(TALLOC_CTX *mem_ctx, const char *path)
{
	DIR *dir;
	struct dirent *entry;
	char *filename;
	int success = 0;
	init_module_fn *ret = talloc_array(mem_ctx, init_module_fn, 2);

	ret[0] = NULL;
	
	dir = opendir(path);
	if (dir == NULL) {
		talloc_free(ret);
		return NULL;
	}

	while((entry = readdir(dir))) {
		if (ISDOT(entry->d_name) || ISDOTDOT(entry->d_name))
			continue;

		filename = talloc_asprintf(mem_ctx, "%s/%s", path, entry->d_name);

		ret[success] = load_module(mem_ctx, filename);
		if (ret[success]) {
			ret = talloc_realloc(mem_ctx, ret, init_module_fn, success+2);
			success++;
			ret[success] = NULL;
		}

		talloc_free(filename);
	}

	closedir(dir);

	return ret;
}

/**
 * Run the specified init functions.
 *
 * @return True if all functions ran successfully, False otherwise
 */
_PUBLIC_ BOOL run_init_functions(NTSTATUS (**fns) (void))
{
	int i;
	BOOL ret = True;
	
	if (fns == NULL)
		return True;
	
	for (i = 0; fns[i]; i++) { ret &= (BOOL)NT_STATUS_IS_OK(fns[i]()); }

	return ret;
}
