/* 
   Unix SMB/CIFS implementation.
   Loadable passdb module interface.
   Copyright (C) Jelmer Vernooij 2002
   Copyright (C) Andrew Bartlett 2002
      
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

NTSTATUS pdb_init_plugin(PDB_CONTEXT *pdb_context, PDB_METHODS **pdb_method, const char *location)
{
	void * dl_handle;
	char *plugin_location, *plugin_name, *p;
	pdb_init_function plugin_init;

	if (location == NULL) {
		DEBUG(0, ("The plugin module needs an argument!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	plugin_name = smb_xstrdup(location);
	p = strchr(plugin_name, ':');
	if (p) {
		*p = 0;
		plugin_location = p+1;
		trim_string(plugin_location, " ", " ");
	} else plugin_location = NULL;
	trim_string(plugin_name, " ", " ");

	DEBUG(5, ("Trying to load sam plugin %s\n", plugin_name));
	dl_handle = sys_dlopen(plugin_name, RTLD_NOW | RTLD_GLOBAL );
	if (!dl_handle) {
		DEBUG(0, ("Failed to load sam plugin %s using sys_dlopen (%s)\n", plugin_name, sys_dlerror()));
		return NT_STATUS_UNSUCCESSFUL;
	}
    
	plugin_init = sys_dlsym(dl_handle, "pdb_init");
	if (!plugin_init){
		DEBUG(0, ("Failed to find function 'pdb_init' using sys_dlsym in sam plugin %s (%s)\n", plugin_name, sys_dlerror()));	    
		return NT_STATUS_UNSUCCESSFUL;
	}

	DEBUG(5, ("Starting sam plugin %s with location %s\n", plugin_name, plugin_location));
	return plugin_init(pdb_context, pdb_method, plugin_location);
}
