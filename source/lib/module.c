/* 
   Unix SMB/CIFS implementation.
   module loading system

   Copyright (C) Jelmer Vernooij 2002-2003
   Copyright (C) Stefan (metze) Metzmacher 2003
   
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
NTSTATUS smb_load_module(const char *module_name)
{
	void *handle;
	init_module_function *init;
	NTSTATUS status;
	const char *error;

	/* Always try to use LAZY symbol resolving; if the plugin has 
	 * backwards compatibility, there might be symbols in the 
	 * plugin referencing to old (removed) functions
	 */
	handle = sys_dlopen(module_name, RTLD_LAZY);

	if(!handle) {
		DEBUG(0, ("Error loading module '%s': %s\n", module_name, sys_dlerror()));
		return NT_STATUS_UNSUCCESSFUL;
	}

	init = sys_dlsym(handle, "init_module");

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

NTSTATUS smb_probe_module(const char *subsystem, const char *module)
{
	pstring full_path;
	
	/* Check for absolute path */
	if(module[0] == '/')return smb_load_module(module);
	
	pstrcpy(full_path, lib_path(subsystem));
	pstrcat(full_path, "/");
	pstrcat(full_path, module);
	pstrcat(full_path, ".");
	pstrcat(full_path, shlib_ext());

	DEBUG(5, ("Probing module %s: Trying to load from %s\n", module, full_path));
	
	return smb_load_module(full_path);
}

#else /* HAVE_DLOPEN */

NTSTATUS smb_load_module(const char *module_name)
{
	DEBUG(0,("This samba executable has not been built with plugin support"));
	return NT_STATUS_NOT_SUPPORTED;
}

int smb_load_modules(const char **modules)
{
	DEBUG(0,("This samba executable has not been built with plugin support"));
	return -1;
}

NTSTATUS smb_probe_module(const char *subsystem, const char *module)
{
	DEBUG(0,("This samba executable has not been built with plugin support, not probing")); 
	return NT_STATUS_NOT_SUPPORTED;
}

#endif /* HAVE_DLOPEN */

void init_modules(void)
{
	/* FIXME: This can cause undefined symbol errors :
	 *  smb_register_vfs() isn't available in nmbd, for example */
	if(lp_preload_modules()) 
		smb_load_modules(lp_preload_modules());
}


/*************************************************************************
 * This functions /path/to/foobar.so -> foobar
 ************************************************************************/
void module_path_get_name(const char *path, pstring name)
{
	char *s;

	/* First, make the path relative */
	s = strrchr(path, '/');
	if(s) pstrcpy(name, s+1);
	else pstrcpy(name, path);
	
	if (dyn_SHLIBEXT && *dyn_SHLIBEXT && strlen(dyn_SHLIBEXT) < strlen(name)) {
		int n = strlen(name) - strlen(dyn_SHLIBEXT);
		
		/* Remove extension if necessary */
		if (name[n-1] == '.' && !strcmp(name+n, dyn_SHLIBEXT)) {
			name[n-1] = '\0';
		}
	}
}


/***************************************************************************
 * This Function registers a idle event
 *
 * the registered funtions are run periodically
 * and maybe shutdown idle connections (e.g. to an LDAP server)
 ***************************************************************************/
static smb_idle_event_struct *smb_idle_event_list = NULL;
NTSTATUS smb_register_idle_event(smb_idle_event_struct *idle_event)
{
	if (!idle_event) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	idle_event->last_run = 0;

	DLIST_ADD(smb_idle_event_list,idle_event);

	return NT_STATUS_OK;
}

NTSTATUS smb_unregister_idle_event(smb_idle_event_struct *idle_event)
{
	if (!idle_event) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	DLIST_REMOVE(smb_idle_event_list,idle_event);

	return NT_STATUS_OK;
}

void smb_run_idle_events(time_t now)
{
	smb_idle_event_struct *tmp_event = smb_idle_event_list;

	while (tmp_event) {
		time_t interval;

		if (tmp_event->fn) {
			if (tmp_event->interval >= SMB_IDLE_EVENT_MIN_INTERVAL) {
				interval = tmp_event->interval;
			} else {
				interval = SMB_IDLE_EVENT_DEFAULT_INTERVAL;
			}
			if (now >(tmp_event->last_run+interval)) {
				tmp_event->fn(&tmp_event,now);
				tmp_event->last_run = now;
			}
		}

		tmp_event = tmp_event->next;
	}

	return;
}

/***************************************************************************
 * This Function registers a exit event
 *
 * the registered funtions are run on exit()
 * and maybe shutdown idle connections (e.g. to an LDAP server)
 ***************************************************************************/
static smb_exit_event_struct *smb_exit_event_list = NULL;
NTSTATUS smb_register_exit_event(smb_exit_event_struct *exit_event)
{
	if (!exit_event) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	DLIST_ADD(smb_exit_event_list,exit_event);

	return NT_STATUS_OK;
}

NTSTATUS smb_unregister_exit_event(smb_exit_event_struct *exit_event)
{
	if (!exit_event) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	DLIST_REMOVE(smb_exit_event_list,exit_event);

	return NT_STATUS_OK;
}

void smb_run_exit_events(void)
{
	smb_exit_event_struct *tmp_event = smb_exit_event_list;

	while (tmp_event) {
		if (tmp_event->fn) {
			tmp_event->fn(&tmp_event);
		}
		tmp_event = tmp_event->next;
	}

	/* run exit_events only once */
	smb_exit_event_list = NULL;

	return;
}

