/* 
   Unix SMB/CIFS implementation.
   Configuration Modules Support
   Copyright (C) Simo Sorce 2003

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
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.*/

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_IDMAP

struct modconf_struct {
	char *name;
	struct config_functions *fns;
};

static struct modconf_struct module;

NTSTATUS smb_register_config(int version, const char *name, struct config_functions *fns)
{
	if ((version != SAMBA_CONFIG_INTERFACE_VERSION)) {
		DEBUG(0, ("smb_register_config: Failed to register config module.\n"
		          "The module has been compiled with a different interface version (%d).\n"
			  "The supported version is: %d\n",
			  version, SAMBA_CONFIG_INTERFACE_VERSION));
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	if (!name || !name[0]) {
		DEBUG(0,("smb_register_config: Name missing!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	module.name = smb_xstrdup(name);
	module.fns = fns;
	DEBUG(5, ("smb_register_config: Successfully registeres config backend '%s'\n", name));
	return NT_STATUS_OK;
}

/**********************************************************************
 * Init the configuration module
 *********************************************************************/

BOOL modconf_init(const char *config_backend)
{
	NTSTATUS ret;
	BOOL bret = False;
	char *name;
	char *params;

	/* nothing to do */
	if (!config_backend)
		return True;

	name = smb_xstrdup(config_backend);
	if ((params = strchr(name, ':')) != NULL ) {
		*params = '\0';
		params++;
	}

	ret = smb_probe_module("config", name);
	
	if (NT_STATUS_IS_OK(ret) && NT_STATUS_IS_OK(module.fns->init(params)))
		bret = True;

	SAFE_FREE(name);
	return bret;
}

BOOL modconf_load(BOOL (*sfunc)(const char *),BOOL (*pfunc)(const char *, const char *))
{
	if (module.fns) {
		if (NT_STATUS_IS_OK(module.fns->load(sfunc, pfunc))) {
			return True;
		}
	}
	return False;
}

NTSTATUS modconf_close(void)
{
	return module.fns->close();
}
