/* 
   Unix SMB/CIFS implementation.
   module loading system

   Copyright (C) Jelmer Vernooij 2002
   
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
	NTSTATUS nt_status;
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

	nt_status = init();

	DEBUG(2, ("Module '%s' loaded\n", module_name));

	return nt_status;
}

#else /* HAVE_DLOPEN */

NTSTATUS smb_load_module(const char *module_name)
{
	DEBUG(0,("This samba executable has not been build with plugin support"));
	return NT_STATUS_NOT_SUPPORTED;
}

#endif /* HAVE_DLOPEN */
