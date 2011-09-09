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
init_module_fn load_module(TALLOC_CTX *mem_ctx, const char *path)
{
	void *handle;
	void *init_fn;

	handle = dlopen(path, RTLD_NOW);
	if (handle == NULL) {
		DEBUG(0, ("Unable to open %s: %s\n", path, dlerror()));
		return NULL;
	}

	init_fn = dlsym(handle, SAMBA_INIT_MODULE);

	if (init_fn == NULL) {
		DEBUG(0, ("Unable to find %s() in %s: %s\n",
			  SAMBA_INIT_MODULE, path, dlerror()));
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
init_module_fn *load_modules(TALLOC_CTX *mem_ctx, const char *path)
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

static NTSTATUS do_smb_load_module(const char *module_name, bool is_probe)
{
	void *handle;
	init_module_function *init;
	NTSTATUS status;
	const char *error;

	/* Always try to use LAZY symbol resolving; if the plugin has
	 * backwards compatibility, there might be symbols in the
	 * plugin referencing to old (removed) functions
	 */
	handle = dlopen(module_name, RTLD_LAZY);

	/* This call should reset any possible non-fatal errors that
	   occured since last call to dl* functions */
	error = dlerror();

	if(!handle) {
		int level = is_probe ? 3 : 0;
		DEBUG(level, ("Error loading module '%s': %s\n", module_name, error ? error : ""));
		return NT_STATUS_UNSUCCESSFUL;
	}

	init = (init_module_function *)dlsym(handle, "init_samba_module");

	/* we must check dlerror() to determine if it worked, because
           dlsym() can validly return NULL */
	error = dlerror();
	if (error) {
		DEBUG(0, ("Error trying to resolve symbol 'init_samba_module' "
			  "in %s: %s\n", module_name, error));
		dlclose(handle);
		return NT_STATUS_UNSUCCESSFUL;
	}

	DEBUG(2, ("Module '%s' loaded\n", module_name));

	status = init();
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Module '%s' initialization failed: %s\n",
			    module_name, get_friendly_nt_error_msg(status)));
		dlclose(handle);
	}

	return status;
}

NTSTATUS smb_load_module(const char *module_name)
{
	return do_smb_load_module(module_name, false);
}

/* Load all modules in list and return number of
 * modules that has been successfully loaded */
int smb_load_modules(const char **modules)
{
	int i;
	int success = 0;

	for(i = 0; modules[i]; i++){
		if(NT_STATUS_IS_OK(smb_load_module(modules[i]))) {
			success++;
		}
	}

	DEBUG(2, ("%d modules successfully loaded\n", success));

	return success;
}

NTSTATUS smb_probe_module(const char *subsystem, const char *module)
{
	char *full_path = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	NTSTATUS status;

	/* Check for absolute path */

	/* if we make any 'samba multibyte string'
	   calls here, we break
	   for loading string modules */

	DEBUG(5, ("Probing module '%s'\n", module));

	if (module[0] == '/') {
		status = do_smb_load_module(module, true);
		TALLOC_FREE(ctx);
		return status;
	}

	full_path = talloc_asprintf(ctx,
				    "%s/%s.%s",
				    modules_path(ctx, subsystem),
				    module,
				    shlib_ext());
	if (!full_path) {
		TALLOC_FREE(ctx);
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(5, ("Probing module '%s': Trying to load from %s\n",
		module, full_path));

	status = do_smb_load_module(full_path, true);

	TALLOC_FREE(ctx);
	return status;
}
