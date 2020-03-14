/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2008-2009
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005

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

#include <Python.h>
#include "python/py3compat.h"
#include <ldb.h>
#include <pyldb.h>
#include "includes.h"
#include "librpc/ndr/libndr.h"
#include "param/provision.h"
#include "param/secrets.h"
#include <pytalloc.h>
#include "python/modules.h"
#include "param/pyparam.h"
#include "dynconfig/dynconfig.h"

static bool dict_insert(PyObject* dict,
			const char* key,
			PyObject* value)
{
	if (value == NULL) {
		return false;
	}
	if (PyDict_SetItemString(dict, key, value) == -1) {
		Py_XDECREF(value);
		return false;
	}
	Py_XDECREF(value);
	return true;
}

static PyObject *provision_module(void)
{
	PyObject *name = PyUnicode_FromString("samba.provision");
	PyObject *mod = NULL;
	if (name == NULL)
		return NULL;
	mod = PyImport_Import(name);
	Py_CLEAR(name);
	return mod;
}

static PyObject *schema_module(void)
{
	PyObject *name = PyUnicode_FromString("samba.schema");
	PyObject *mod = NULL;
	if (name == NULL)
		return NULL;
	mod = PyImport_Import(name);
	Py_CLEAR(name);
	return mod;
}

static PyObject *ldb_module(void)
{
	PyObject *name = PyUnicode_FromString("ldb");
	PyObject *mod = NULL;
	if (name == NULL)
		return NULL;
	mod = PyImport_Import(name);
	Py_CLEAR(name);
	return mod;
}

static PyObject *PyLdb_FromLdbContext(struct ldb_context *ldb_ctx)
{
	PyLdbObject *ret;
	PyObject *ldb_mod = ldb_module();
	PyTypeObject *ldb_ctx_type;
	if (ldb_mod == NULL)
		return NULL;

	ldb_ctx_type = (PyTypeObject *)PyObject_GetAttrString(ldb_mod, "Ldb");

	ret = (PyLdbObject *)ldb_ctx_type->tp_alloc(ldb_ctx_type, 0);
	if (ret == NULL) {
		PyErr_NoMemory();
		Py_XDECREF(ldb_ctx_type);
		return NULL;
	}
	ret->mem_ctx = talloc_new(NULL);
	ret->ldb_ctx = talloc_reference(ret->mem_ctx, ldb_ctx);
	Py_XDECREF(ldb_ctx_type);
	return (PyObject *)ret;
}

NTSTATUS provision_bare(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx,
			struct provision_settings *settings, 
			struct provision_result *result)
{
	const char *configfile;
	PyObject *provision_mod = NULL, *provision_dict = NULL;
	PyObject *provision_fn = NULL, *py_result = NULL;
	PyObject *parameters = NULL, *py_lp_ctx = NULL, *py_domaindn = NULL;

	struct ldb_context *samdb;
	NTSTATUS status = NT_STATUS_OK;
	
	DEBUG(0,("Provision for Become-DC test using python\n"));

	Py_Initialize();
	py_update_path(); /* Put the samba path at the start of sys.path */

	provision_mod = provision_module();

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
	
	DEBUG(0,("New Server in Site[%s]\n", 
		 settings->site_name));

	DEBUG(0,("DSA Instance [%s]\n"
		"\tinvocationId[%s]\n",
		settings->ntds_dn_str,
		settings->invocation_id == NULL?"None":GUID_string(mem_ctx, settings->invocation_id)));

	DEBUG(0,("Paths under targetdir[%s]\n",
		 settings->targetdir));
	parameters = PyDict_New();

	configfile = lpcfg_configfile(lp_ctx);
	if (configfile != NULL) {
		if (!dict_insert(parameters, "smbconf",
				 PyUnicode_FromString(configfile))) {
			status = NT_STATUS_UNSUCCESSFUL;
			goto out;
		}
	}

	if (!dict_insert(parameters,
			 "rootdn",
			 PyUnicode_FromString(settings->root_dn_str))) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}
	if (settings->targetdir != NULL) {
		if (!dict_insert(parameters,
				 "targetdir",
				 PyUnicode_FromString(settings->targetdir))) {
			status = NT_STATUS_UNSUCCESSFUL;
			goto out;
		}
	}
	if (!dict_insert(parameters,
			 "hostname",
			 PyUnicode_FromString(settings->netbios_name))) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}
	if (!dict_insert(parameters,
			 "domain",
			 PyUnicode_FromString(settings->domain))) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}
	if (!dict_insert(parameters,
			 "realm",
			 PyUnicode_FromString(settings->realm))) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}
	if (settings->root_dn_str) {
		if (!dict_insert(parameters,
				 "rootdn",
				 PyUnicode_FromString(settings->root_dn_str))) {
			status = NT_STATUS_UNSUCCESSFUL;
			goto out;
		}
	}

	if (settings->domain_dn_str) {
		if (!dict_insert(parameters,
				 "domaindn",
				 PyUnicode_FromString(settings->domain_dn_str))) {
			status = NT_STATUS_UNSUCCESSFUL;
			goto out;
		}
	}

	if (settings->schema_dn_str) {
		if (!dict_insert(parameters,
				 "schemadn",
				 PyUnicode_FromString(settings->schema_dn_str))) {
			status = NT_STATUS_UNSUCCESSFUL;
			goto out;
		}
	}
	if (settings->config_dn_str) {
		if (!dict_insert(parameters,
				 "configdn",
				 PyUnicode_FromString(settings->config_dn_str))) {
			status = NT_STATUS_UNSUCCESSFUL;
			goto out;
		}
	}
	if (settings->server_dn_str) {
		if (!dict_insert(parameters,
				 "serverdn",
				 PyUnicode_FromString(settings->server_dn_str))) {
			status = NT_STATUS_UNSUCCESSFUL;
			goto out;
		}
	}
	if (settings->site_name) {
		if (!dict_insert(parameters,
				 "sitename",
				  PyUnicode_FromString(settings->site_name))) {
			status = NT_STATUS_UNSUCCESSFUL;
			goto out;
		}
	}

	if (!dict_insert(parameters,
			 "machinepass",
			 PyUnicode_FromString(settings->machine_password))){
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	if (!dict_insert(parameters,
			 "debuglevel",
			 PyLong_FromLong(DEBUGLEVEL))) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	if (!dict_insert(parameters,
			 "use_ntvfs",
			 PyLong_FromLong(settings->use_ntvfs))) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	py_result = PyEval_CallObjectWithKeywords(provision_fn, NULL, parameters);

	if (py_result == NULL) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	py_domaindn = PyObject_GetAttrString(py_result, "domaindn");
	result->domaindn = talloc_strdup(mem_ctx, PyUnicode_AsUTF8(py_domaindn));

	/* FIXME paths */
	py_lp_ctx = PyObject_GetAttrString(py_result, "lp");
	if (py_lp_ctx == NULL) {
		DEBUG(0, ("Missing 'lp' attribute"));
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}
	result->lp_ctx = lpcfg_from_py_object(mem_ctx, py_lp_ctx);

	samdb = pyldb_Ldb_AsLdbContext(PyObject_GetAttrString(py_result, "samdb"));
	if (samdb == NULL) {
		DEBUG(0, ("Missing 'samdb' attribute"));
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}
	result->samdb = samdb;
	status = NT_STATUS_OK;
out:
	Py_CLEAR(parameters);
	Py_CLEAR(provision_mod);
	Py_CLEAR(provision_fn);
	Py_CLEAR(provision_dict);
	Py_CLEAR(py_result);
	Py_CLEAR(py_lp_ctx);
	Py_CLEAR(py_domaindn);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Print();
		PyErr_Clear();
	}
	return status;
}

static PyObject *py_dom_sid_FromSid(struct dom_sid *sid)
{
	PyObject *mod_security = NULL, *dom_sid_Type = NULL, *result = NULL;

	mod_security = PyImport_ImportModule("samba.dcerpc.security");
	if (mod_security == NULL) {
		return NULL;
	}

	dom_sid_Type = PyObject_GetAttrString(mod_security, "dom_sid");
	if (dom_sid_Type == NULL) {
		Py_DECREF(mod_security);
		return NULL;
	}

	result = pytalloc_reference((PyTypeObject *)dom_sid_Type, sid);
	Py_DECREF(mod_security);
	Py_DECREF(dom_sid_Type);
	return result;
}

NTSTATUS provision_store_self_join(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx,
				   struct tevent_context *event_ctx,
				   struct provision_store_self_join_settings *settings,
				   const char **error_string)
{
	int ret;
	PyObject *provision_mod = NULL, *provision_dict = NULL;
	PyObject *provision_fn = NULL, *py_result = NULL;
	PyObject *parameters = NULL;
	struct ldb_context *ldb = NULL;
	TALLOC_CTX *tmp_mem = talloc_new(mem_ctx);

	NTSTATUS status = NT_STATUS_OK;
	*error_string = NULL;

	if (!tmp_mem) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	/* Create/Open the secrets database */
	ldb = secrets_db_create(tmp_mem, lp_ctx);
	if (!ldb) {
		*error_string
			= talloc_asprintf(mem_ctx, 
					  "Could not open secrets database");
		status = NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		goto out;
	}

	ret = ldb_transaction_start(ldb);

	if (ret != LDB_SUCCESS) {
		*error_string
			= talloc_asprintf(mem_ctx, 
					  "Could not start transaction on secrets database: %s", ldb_errstring(ldb));
		status = NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		goto out;
	}

	Py_Initialize();
	py_update_path(); /* Put the samba path at the start of sys.path */
	provision_mod = provision_module();

	if (provision_mod == NULL) {
		*error_string
			= talloc_asprintf(mem_ctx, "Unable to import provision Python module.");
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	provision_dict = PyModule_GetDict(provision_mod);

	if (provision_dict == NULL) {
		*error_string
			= talloc_asprintf(mem_ctx, "Unable to get dictionary for provision module");
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	provision_fn = PyDict_GetItemString(provision_dict, "secretsdb_self_join");
	if (provision_fn == NULL) {
		*error_string
			= talloc_asprintf(mem_ctx, "Unable to get provision_become_dc function");
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	parameters = PyDict_New();

	if(!dict_insert(parameters,
			"secretsdb",
			PyLdb_FromLdbContext(ldb))){
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}
	if (!dict_insert(parameters,
			 "domain",
			 PyUnicode_FromString(settings->domain_name))) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}
	if (settings->realm != NULL) {
		if (!dict_insert(parameters,
				 "realm",
				 PyUnicode_FromString(settings->realm))) {
			status = NT_STATUS_UNSUCCESSFUL;
			goto out;
		}
	}
	if (!dict_insert(parameters,
			 "machinepass",
			 PyUnicode_FromString(settings->machine_password))) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}
	if (!dict_insert(parameters,
			 "netbiosname",
			 PyUnicode_FromString(settings->netbios_name))) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}


	if (!dict_insert(parameters,
			 "domainsid",
			 py_dom_sid_FromSid(settings->domain_sid))) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	if (!dict_insert(parameters,
			 "secure_channel_type",
			 PyLong_FromLong(settings->secure_channel_type))) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	if (!dict_insert(parameters,
			 "key_version_number",
			 PyLong_FromLong(settings->key_version_number))) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	py_result = PyEval_CallObjectWithKeywords(provision_fn, NULL, parameters);

	if (py_result == NULL) {
		ldb_transaction_cancel(ldb);
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	ret = ldb_transaction_commit(ldb);
	if (ret != LDB_SUCCESS) {
		*error_string
			= talloc_asprintf(mem_ctx, 
					  "Could not commit transaction on secrets database: %s", ldb_errstring(ldb));
		status = NT_STATUS_INTERNAL_DB_ERROR;
		goto out;
	}

	status = NT_STATUS_OK;
out:
	talloc_free(tmp_mem);
	Py_CLEAR(parameters);
	Py_CLEAR(provision_mod);
	Py_CLEAR(provision_dict);
	Py_CLEAR(py_result);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Print();
		PyErr_Clear();
	}
	return status;
}


struct ldb_context *provision_get_schema(TALLOC_CTX *mem_ctx,
					 struct loadparm_context *lp_ctx,
					 const char *schema_dn,
					 DATA_BLOB *override_prefixmap)
{
	PyObject *schema_mod, *schema_dict, *schema_fn, *py_result, *parameters;
	PyObject *py_ldb = NULL;
	struct ldb_context *ldb_result = NULL;
	Py_Initialize();
	py_update_path(); /* Put the samba path at the start of sys.path */

	schema_mod = schema_module();

	if (schema_mod == NULL) {
		PyErr_Print();
		DEBUG(0, ("Unable to import schema Python module.\n"));
	      	return NULL;
	}

	schema_dict = PyModule_GetDict(schema_mod);

	if (schema_dict == NULL) {
		DEBUG(0, ("Unable to get dictionary for schema module\n"));
		return NULL;
	}

	schema_fn = PyDict_GetItemString(schema_dict, "ldb_with_schema");
	if (schema_fn == NULL) {
		PyErr_Print();
		DEBUG(0, ("Unable to get schema_get_ldb function\n"));
		return NULL;
	}
	
	parameters = PyDict_New();

	if (schema_dn) {
		if (!dict_insert(parameters,
				 "schemadn",
				 PyUnicode_FromString(schema_dn))) {
			return NULL;
		}
	}

	if (override_prefixmap) {
		if (!dict_insert(parameters,
				 "override_prefixmap",
				 PyBytes_FromStringAndSize(
					(const char *)override_prefixmap->data,
					override_prefixmap->length))) {
			return NULL;
		}
	}

	py_result = PyEval_CallObjectWithKeywords(schema_fn, NULL, parameters);

	Py_DECREF(parameters);

	if (py_result == NULL) {
		PyErr_Print();
		PyErr_Clear();
		return NULL;
	}

	py_ldb = PyObject_GetAttrString(py_result, "ldb");
	Py_DECREF(py_result);
	ldb_result = pyldb_Ldb_AsLdbContext(py_ldb);
	if (talloc_reference(mem_ctx, ldb_result) == NULL) {
		ldb_result = NULL;
	}
	Py_DECREF(py_ldb);
	return ldb_result;
}
