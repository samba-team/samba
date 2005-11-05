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

#include "includes.h"
#include "system/dir.h"

static BOOL load_module(TALLOC_CTX *mem_ctx, const char *dir, const char *name)
{
	char *path;
	void *handle;
	BOOL (*init_module_fn) (void);
	BOOL ret;

	path = talloc_asprintf(mem_ctx, "%s/%s", dir, name);

	handle = dlopen(path, RTLD_NOW);
	if (handle == NULL) {
		DEBUG(0, ("Unable to open %s: %s\n", path, dlerror()));
		return False;
	}

	init_module_fn = dlsym(handle, "init_module");

	if (init_module_fn == NULL) {
		DEBUG(0, ("Unable to find init_module() in %s: %s\n", path, dlerror()));
		return False;
	}

	ret = init_module_fn();
	if (!ret) {
		DEBUG(1, ("Loading module '%s' failed\n", path));
	}

	dlclose(handle);

	talloc_free(path);

	return ret;
}

BOOL load_modules(const char *path)
{
	DIR *dir;
	struct dirent *entry;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;
	
	mem_ctx = talloc_init(NULL);

	dir = opendir(path);
	if (dir == NULL) {
		talloc_free(mem_ctx);
		return False;
	}

	while((entry = readdir(dir))) {
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
			continue;

		ret &= load_module(mem_ctx, path, entry->d_name);
	}

	closedir(dir);

	talloc_free(mem_ctx);

	return ret;
}
