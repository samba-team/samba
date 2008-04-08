/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2008
   
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
#include "auth/auth.h"
#include "lib/ldb_wrap.h"
#include "torture/torture.h"
#include "libcli/raw/libcliraw.h"
#include "torture/util.h"
#include "librpc/ndr/libndr.h"

#include "param/param.h"
#include <Python.h>
#include "scripting/python/modules.h"

NTSTATUS provision_bare(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx,
			struct provision_settings *settings)
{
	PyObject *provision_mod, *provision_dict, *provision_fn, *result, *parameters;
	
	DEBUG(0,("Provision for Become-DC test using python\n"));

	py_load_samba_modules();
	Py_Initialize();
	py_update_path("bin"); /* FIXME: Can't assume this is always the case */

	provision_mod = PyImport_Import(PyString_FromString("samba.provision"));

	if (provision_mod == NULL) {
		PyErr_Print();
		DEBUG(0, ("Unable to import provision Python module.\n"));
	      	return NT_STATUS_UNSUCCESSFUL;
	}

	provision_dict = PyModule_GetDict(provision_mod);

	if (provision_dict == NULL) {
		DEBUG(0, ("Unable to get dictionary for provision module\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	provision_fn = PyDict_GetItemString(provision_dict, "provision_become_dc");
	if (provision_fn == NULL) {
		PyErr_Print();
		DEBUG(0, ("Unable to get provision_become_dc function\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	DEBUG(0,("New Server[%s] in Site[%s]\n", settings->dns_name, 
			 settings->site_name));

	DEBUG(0,("DSA Instance [%s]\n"
		"\tobjectGUID[%s]\n"
		"\tinvocationId[%s]\n",
		settings->ntds_dn_str,
		settings->ntds_guid == NULL?"None":GUID_string(mem_ctx, settings->ntds_guid),
		settings->invocation_id == NULL?"None":GUID_string(mem_ctx, settings->invocation_id)));

	DEBUG(0,("Pathes under targetdir[%s]\n",
		 settings->targetdir));
	parameters = PyDict_New();

	PyDict_SetItemString(parameters, "rootdn", 
						 PyString_FromString(settings->root_dn_str));
	if (settings->targetdir != NULL)
		PyDict_SetItemString(parameters, "targetdir", 
							 PyString_FromString(settings->targetdir));
	PyDict_SetItemString(parameters, "setup_dir", 
			     PyString_FromString("setup"));
	PyDict_SetItemString(parameters, "hostname", 
						 PyString_FromString(settings->netbios_name));
	PyDict_SetItemString(parameters, "domain", 
						 PyString_FromString(settings->domain));
	PyDict_SetItemString(parameters, "realm", 
						 PyString_FromString(settings->realm));
	if (settings->root_dn_str)
		PyDict_SetItemString(parameters, "rootdn", 
				     PyString_FromString(settings->root_dn_str));

	if (settings->domain_dn_str) 
		PyDict_SetItemString(parameters, "domaindn", 
				     PyString_FromString(settings->domain_dn_str));

	if (settings->schema_dn_str) 
		PyDict_SetItemString(parameters, "schemadn", 
				     PyString_FromString(settings->schema_dn_str));
	
	if (settings->config_dn_str) 
		PyDict_SetItemString(parameters, "configdn", 
				     PyString_FromString(settings->config_dn_str));
	
	if (settings->site_name) 
		PyDict_SetItemString(parameters, "sitename", 
				     PyString_FromString(settings->site_name));

	PyDict_SetItemString(parameters, "machinepass", 
			     PyString_FromString(settings->machine_password));

	result = PyEval_CallObjectWithKeywords(provision_fn, NULL, parameters);

	Py_DECREF(parameters);

	if (result == NULL) {
		PyErr_Print();
		PyErr_Clear();
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}
