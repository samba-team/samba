/* 
   Unix SMB/CIFS implementation.
   module loading system

   Copyright (C) Jelmer Vernooij 2002-2004
   
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

#ifdef HAVE_DLOPEN

/* Load module (or directory with modules) recursively. 
 * Includes running the init_module() function */
NTSTATUS smb_load_module(const char *module_name)
{
	void *handle;
	init_module_function init;
	NTSTATUS status;
	const char *error;
	struct stat st;
	DIR *dir;
	struct dirent *dirent;

	if(stat(module_name, &st) < 0) {
		DEBUG(0, ("Can't stat module '%s'\n", module_name));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* If the argument is a directory, recursively load all files / 
	 * directories in it */

	/* How about symlinks pointing to themselves - wouldn't we rather 
	 * want to use wildcards here? */
	if(S_ISDIR(st.st_mode)) {
		dir = opendir(module_name);
		while ((dirent = readdir(dir))) {
			smb_load_module(dirent->d_name);
		}
	}

	/* Always try to use LAZY symbol resolving; if the plugin has 
	 * backwards compatibility, there might be symbols in the 
	 * plugin referencing to old (removed) functions
	 */
	handle = sys_dlopen(module_name, RTLD_LAZY);

	if(!handle) {
		DEBUG(0, ("Error loading module '%s': %s\n", module_name, sys_dlerror()));
		return NT_STATUS_UNSUCCESSFUL;
	}

	init = (init_module_function)sys_dlsym(handle, "init_module");

	/* we must check sys_dlerror() to determine if it worked, because
           sys_dlsym() can validly return NULL */
	error = sys_dlerror();
	if (error) {
		DEBUG(0, ("Error trying to resolve symbol 'init_module' in %s: %s\n", module_name, error));
		return NT_STATUS_UNSUCCESSFUL;
	}

	status = init();

	DEBUG(2, ("Module '%s' loaded\n", module_name));

	return status;
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

#else /* HAVE_DLOPEN */

NTSTATUS smb_load_module(const char *module_name)
{
	DEBUG(0,("This samba executable has not been built with plugin support\n"));
	return NT_STATUS_NOT_SUPPORTED;
}

int smb_load_modules(const char **modules)
{
	DEBUG(0,("This samba executable has not been built with plugin support\n"));
	return -1;
}

#endif /* HAVE_DLOPEN */

void init_modules(void)
{
	if(lp_preload_modules()) 
		smb_load_modules(lp_preload_modules());
}

struct subsystem {
	char *name;
	register_backend_function callback;
	struct subsystem *prev, *next;
};

static struct subsystem *subsystems = NULL;

NTSTATUS register_subsystem(const char *name, register_backend_function callback) 
{
	struct subsystem *s;
	struct subsystem *t = subsystems;

	while(t) {
		if(!strcmp(name, t->name)) {
			/* its already registered! */
			DEBUG(0,("Subsystem '%s' already registered\n", name));
			return NT_STATUS_OBJECT_NAME_COLLISION;
		}
		t = t->next;
	}

	s = smb_xmalloc(sizeof(struct subsystem));

	s->name = smb_xstrdup(name);
	s->callback = callback;
	s->prev = s->next = NULL;

	DLIST_ADD(subsystems, s);

	return NT_STATUS_OK;
}

NTSTATUS register_backend(const char *subsystem, const void *args)
{
	/* Find the specified subsystem */
	struct subsystem *s = subsystems;

	while(s) {
		if(!strcmp(subsystem, s->name)) return s->callback(args);
		s = s->next;
	}
	
	DEBUG(0, ("Unable to register backend for subsystem '%s'\n", subsystem));

	return NT_STATUS_NOT_IMPLEMENTED;
}
