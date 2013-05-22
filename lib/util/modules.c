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
#include "lib/util/samba_modules.h"
#include "system/filesys.h"
#include "system/dir.h"

/**
 * Obtain the init function from a shared library file
 */
init_module_fn load_module(const char *path, bool is_probe, void **handle_out)
{
	void *handle;
	void *init_fn;
	char *error;

	/* This should be a WAF build, where modules should be built
	 * with no undefined symbols and are already linked against
	 * the libraries that they are loaded by */
	handle = dlopen(path, RTLD_NOW);

	/* This call should reset any possible non-fatal errors that
	   occured since last call to dl* functions */
	error = dlerror();

	if (handle == NULL) {
		int level = is_probe ? 5 : 0;
		DEBUG(level, ("Error loading module '%s': %s\n", path, error ? error : ""));
		return NULL;
	}

	init_fn = (init_module_fn)dlsym(handle, SAMBA_INIT_MODULE);

	/* we could check dlerror() to determine if it worked, because
           dlsym() can validly return NULL, but what would we do with
           a NULL pointer as a module init function? */

	if (init_fn == NULL) {
		DEBUG(0, ("Unable to find %s() in %s: %s\n",
			  SAMBA_INIT_MODULE, path, dlerror()));
		DEBUG(1, ("Loading module '%s' failed\n", path));
		dlclose(handle);
		return NULL;
	}

	if (handle_out) {
		*handle_out = handle;
	}

	return (init_module_fn)init_fn;
}

/**
 * Obtain list of init functions from the modules in the specified
 * directory
 */
static init_module_fn *load_modules(TALLOC_CTX *mem_ctx, const char *path)
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

		ret[success] = load_module(filename, true, NULL);
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
 * @return true if all functions ran successfully, false otherwise
 */
bool run_init_functions(init_module_fn *fns)
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

init_module_fn *load_samba_modules(TALLOC_CTX *mem_ctx, const char *subsystem)
{
	char *path = modules_path(mem_ctx, subsystem);
	init_module_fn *ret;

	ret = load_modules(mem_ctx, path);

	talloc_free(path);

	return ret;
}


/* Load a dynamic module.  Only log a level 0 error if we are not checking
   for the existence of a module (probling). */

static NTSTATUS do_smb_load_module(const char *subsystem,
				   const char *module_name, bool is_probe)
{
	void *handle;
	init_module_fn init;
	NTSTATUS status;

	char *full_path = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();

	/* Check for absolute path */

	DEBUG(5, ("%s module '%s'\n", is_probe ? "Probing" : "Loading", module_name));

	if (subsystem && module_name[0] != '/') {
		full_path = talloc_asprintf(ctx,
					    "%s/%s.%s",
					    modules_path(ctx, subsystem),
					    module_name,
					    shlib_ext());
		if (!full_path) {
			TALLOC_FREE(ctx);
			return NT_STATUS_NO_MEMORY;
		}

		DEBUG(5, ("%s module '%s': Trying to load from %s\n",
			  is_probe ? "Probing": "Loading", module_name, full_path));
		init = load_module(full_path, is_probe, &handle);
	} else {
		init = load_module(module_name, is_probe, &handle);
	}

	if (!init) {
		TALLOC_FREE(ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	DEBUG(2, ("Module '%s' loaded\n", module_name));

	status = init();
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Module '%s' initialization failed: %s\n",
			  module_name, get_friendly_nt_error_msg(status)));
		dlclose(handle);
	}
	TALLOC_FREE(ctx);
	return status;
}

/* Load all modules in list and return number of
 * modules that has been successfully loaded */
int smb_load_modules(const char **modules)
{
	int i;
	int success = 0;

	for(i = 0; modules[i]; i++){
		if(NT_STATUS_IS_OK(do_smb_load_module(NULL, modules[i], false))) {
			success++;
		}
	}

	DEBUG(2, ("%d modules successfully loaded\n", success));

	return success;
}

NTSTATUS smb_probe_module(const char *subsystem, const char *module)
{
	return do_smb_load_module(subsystem, module, true);
}

NTSTATUS smb_load_module(const char *subsystem, const char *module)
{
	return do_smb_load_module(subsystem, module, false);
}
