/*
   Unix SMB/CIFS implementation.
   Grops and Users Management System initializations.
   Copyright (C) Simo Sorce 2002

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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_SAM

#define GMV_MAJOR 0
#define GMV_MINOR 1

static GUMS_FUNCTIONS *gums_backend = NULL;

static struct gums_init_function_entry *backends = NULL;

static void lazy_initialize_gums(void)
{
	static BOOL initialized = False;
	
	if (initialized)
		return;

	static_init_gums;
	initialized = True;
}

static struct gums_init_function_entry *gums_find_backend_entry(const char *name);

NTSTATUS gums_register_module(int version, const char *name, gums_init_function init_fn)
{
	struct gums_init_function_entry *entry = backends;

	if (version != GUMS_INTERFACE_VERSION) {
		DEBUG(0,("Can't register gums backend!\n"
			 "You tried to register a gums module with"
			 "GUMS_INTERFACE_VERSION %d, while this version"
			 "of samba uses version %d\n", version,
			 GUMS_INTERFACE_VERSION));

		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	if (!name || !init_fn) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	DEBUG(5,("Attempting to register gums backend %s\n", name));

	/* Check for duplicates */
	if (gums_find_backend_entry(name)) {
		DEBUG(0,("There already is a gums backend registered"
			 "with the name %s!\n", name));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	entry = smb_xmalloc(sizeof(struct gums_init_function_entry));
	entry->name = smb_xstrdup(name);
	entry->init_fn = init_fn;

	DLIST_ADD(backends, entry);
	DEBUG(5,("Successfully added gums backend '%s'\n", name));
	return NT_STATUS_OK;
}

static struct gums_init_function_entry *gums_find_backend_entry(const char *name)
{
	struct gums_init_function_entry *entry = backends;

	while (entry) {
		if (strcmp(entry->name, name) == 0)
			return entry;
		entry = entry->next;
	}

	return NULL;
}

NTSTATUS gums_setup_backend(const char *backend)
{

	TALLOC_CTX *mem_ctx;
	char *module_name = smb_xstrdup(backend);
	char *p, *module_data = NULL;
	struct gums_init_function_entry *entry;
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	lazy_initialize_gums();

	p = strchr(module_name, ':');
	if (p) {
		*p = 0;
		module_data = p+1;
		trim_string(module_data, " ", " ");
	}

	trim_string(module_name, " ", " ");

	DEBUG(5,("Attempting to find a gums backend to match %s (%s)\n", backend, module_name));

	entry = gums_find_backend_entry(module_name);

	/* Try to find a module that contains this module */
	if (!entry) {
		DEBUG(2,("No builtin backend found, trying to load plugin\n"));
		if(NT_STATUS_IS_OK(smb_probe_module("gums", module_name)) && !(entry = gums_find_backend_entry(module_name))) {
			DEBUG(0,("Plugin is available, but doesn't register gums backend %s\n", module_name));
			SAFE_FREE(module_name);
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	/* No such backend found */
	if(!entry) {
		DEBUG(0,("No builtin nor plugin backend for %s found\n", module_name));
		SAFE_FREE(module_name);
		return NT_STATUS_INVALID_PARAMETER;
	}

	DEBUG(5,("Found gums backend %s\n", module_name));

	/* free current functions structure if any */
	if (gums_backend) {
		gums_backend->free_private_data(gums_backend->private_data);
		talloc_destroy(gums_backend->mem_ctx);
		gums_backend = NULL;
	}

	/* allocate a new GUMS_FUNCTIONS structure and memory context */
	mem_ctx = talloc_init("gums_backend (%s)", module_name);
	if (!mem_ctx)
		return NT_STATUS_NO_MEMORY;
	gums_backend = talloc(mem_ctx, sizeof(GUMS_FUNCTIONS));
	if (!gums_backend)
		return NT_STATUS_NO_MEMORY;
	gums_backend->mem_ctx = mem_ctx;

	/* init the requested backend module */
	if (NT_STATUS_IS_OK(ret = entry->init_fn(gums_backend, module_data))) {
		DEBUG(5,("gums backend %s has a valid init\n", backend));
	} else {
		DEBUG(0,("gums backend %s did not correctly init (error was %s)\n", backend, nt_errstr(ret)));
	}
	SAFE_FREE(module_name);
	return ret;
}

NTSTATUS get_gums_fns(GUMS_FUNCTIONS **fns)
{
	if (gums_backend != NULL) {
		*fns = gums_backend;
		return NT_STATUS_OK;
	}

	DEBUG(2, ("get_gums_fns: unable to get gums functions! backend uninitialized?\n"));
	return NT_STATUS_UNSUCCESSFUL;
}
