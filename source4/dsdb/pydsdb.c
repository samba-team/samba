/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2010
   Copyright (C) Matthias Dieter Wallnöfer          2009
   
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
#include "includes.h"
#include "dsdb/samdb/samdb.h"
#include "lib/ldb/pyldb.h"
#include "libcli/security/security.h"
#include "librpc/ndr/libndr.h"

/* FIXME: These should be in a header file somewhere, once we finish moving
 * away from SWIG .. */
#define PyErr_LDB_OR_RAISE(py_ldb, ldb) \
/*	if (!PyLdb_Check(py_ldb)) { \
		PyErr_SetString(py_ldb_get_exception(), "Ldb connection object required"); \
		return NULL; \
	} */\
	ldb = PyLdb_AsLdbContext(py_ldb);

static PyObject *py_samdb_server_site_name(PyObject *self, PyObject *args)
{
	PyObject *py_ldb, *result;
	struct ldb_context *ldb;
	const char *site;
	TALLOC_CTX *mem_ctx;

	if (!PyArg_ParseTuple(args, "O", &py_ldb))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	mem_ctx = talloc_new(NULL);

	site = samdb_server_site_name(ldb, mem_ctx);
	if (site == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to find server site");
		talloc_free(mem_ctx);
		return NULL;
	}

	result = PyString_FromString(site);
	talloc_free(mem_ctx);
	return result;
}

static PyObject *py_dsdb_convert_schema_to_openldap(PyObject *self,
													PyObject *args)
{
	char *target_str, *mapping;
	PyObject *py_ldb;
	struct ldb_context *ldb;
	PyObject *ret;
	char *retstr;

	if (!PyArg_ParseTuple(args, "Oss", &py_ldb, &target_str, &mapping))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	retstr = dsdb_convert_schema_to_openldap(ldb, target_str, mapping);
	if (retstr == NULL) {
		PyErr_SetString(PyExc_RuntimeError,
						"dsdb_convert_schema_to_openldap failed");
		return NULL;
	} 

	ret = PyString_FromString(retstr);
	talloc_free(retstr);
	return ret;
}

static PyObject *py_samdb_set_domain_sid(PyLdbObject *self, PyObject *args)
{ 
	PyObject *py_ldb, *py_sid;
	struct ldb_context *ldb;
	struct dom_sid *sid;
	bool ret;

	if (!PyArg_ParseTuple(args, "OO", &py_ldb, &py_sid))
		return NULL;
	
	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	sid = dom_sid_parse_talloc(NULL, PyString_AsString(py_sid));

	ret = samdb_set_domain_sid(ldb, sid);
	if (!ret) {
		PyErr_SetString(PyExc_RuntimeError, "set_domain_sid failed");
		return NULL;
	} 
	Py_RETURN_NONE;
}

static PyObject *py_samdb_get_domain_sid(PyLdbObject *self, PyObject *args)
{ 
	PyObject *py_ldb;
	struct ldb_context *ldb;
	const struct dom_sid *sid;
	PyObject *ret;
	char *retstr;

	if (!PyArg_ParseTuple(args, "O", &py_ldb))
		return NULL;
	
	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	sid = samdb_domain_sid(ldb);
	if (!sid) {
		PyErr_SetString(PyExc_RuntimeError, "samdb_domain_sid failed");
		return NULL;
	} 
	retstr = dom_sid_string(NULL, sid);
	ret = PyString_FromString(retstr);
	talloc_free(retstr);
	return ret;
}

static PyObject *py_samdb_ntds_invocation_id(PyObject *self, PyObject *args)
{
	PyObject *py_ldb, *result;
	struct ldb_context *ldb;
	TALLOC_CTX *mem_ctx;
	const struct GUID *guid;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "O", &py_ldb)) {
		talloc_free(mem_ctx);
		return NULL;
	}

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	guid = samdb_ntds_invocation_id(ldb);
	if (guid == NULL) {
		PyErr_SetString(PyExc_RuntimeError,
						"Failed to find NTDS invocation ID");
		talloc_free(mem_ctx);
		return NULL;
	}

	result = PyString_FromString(GUID_string(mem_ctx, guid));
	talloc_free(mem_ctx);
	return result;
}

static PyObject *py_dsdb_set_ntds_invocation_id(PyObject *self, PyObject *args)
{
	PyObject *py_ldb, *py_guid;
	bool ret;
	struct GUID guid;
	struct ldb_context *ldb;
	if (!PyArg_ParseTuple(args, "OO", &py_ldb, &py_guid))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);
	GUID_from_string(PyString_AsString(py_guid), &guid);

	ret = samdb_set_ntds_invocation_id(ldb, &guid);
	if (!ret) {
		PyErr_SetString(PyExc_RuntimeError, "set_ntds_invocation_id failed");
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *py_samdb_ntds_objectGUID(PyObject *self, PyObject *args)
{
	PyObject *py_ldb, *result;
	struct ldb_context *ldb;
	TALLOC_CTX *mem_ctx;
	const struct GUID *guid;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "O", &py_ldb)) {
		talloc_free(mem_ctx);
		return NULL;
	}

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	guid = samdb_ntds_objectGUID(ldb);
	if (guid == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to find NTDS GUID");
		talloc_free(mem_ctx);
		return NULL;
	}

	result = PyString_FromString(GUID_string(mem_ctx, guid));
	talloc_free(mem_ctx);
	return result;
}


static PyMethodDef py_dsdb_methods[] = {
	{ "samdb_server_site_name", (PyCFunction)py_samdb_server_site_name,
		METH_VARARGS, "Get the server site name as a string"},
	{ "dsdb_convert_schema_to_openldap",
		(PyCFunction)py_dsdb_convert_schema_to_openldap, METH_VARARGS, 
		"dsdb_convert_schema_to_openldap(ldb, target_str, mapping) -> str\n"
		"Create an OpenLDAP schema from a schema." },
	{ "samdb_set_domain_sid", (PyCFunction)py_samdb_set_domain_sid,
		METH_VARARGS,
		"samdb_set_domain_sid(samdb, sid)\n"
		"Set SID of domain to use." },
	{ "samdb_get_domain_sid", (PyCFunction)py_samdb_get_domain_sid,
		METH_VARARGS,
		"samdb_get_domain_sid(samdb)\n"
		"Get SID of domain in use." },
	{ "samdb_ntds_invocation_id", (PyCFunction)py_samdb_ntds_invocation_id,
		METH_VARARGS, "get the NTDS invocation ID GUID as a string"},
	{ "dsdb_set_ntds_invocation_id", (PyCFunction)py_dsdb_set_ntds_invocation_id, METH_VARARGS,
		NULL },
	{ "samdb_ntds_objectGUID", (PyCFunction)py_samdb_ntds_objectGUID, METH_VARARGS,
		"get the NTDS objectGUID as a string"},
	{ NULL }
};

void initdsdb(void)
{
	PyObject *m;

	m = Py_InitModule3("dsdb", py_dsdb_methods, 
			   "Python bindings for the directory service databases.");
	if (m == NULL)
		return;

	/* "userAccountControl" flags */
	PyModule_AddObject(m, "UF_NORMAL_ACCOUNT", PyInt_FromLong(UF_NORMAL_ACCOUNT));
	PyModule_AddObject(m, "UF_TEMP_DUPLICATE_ACCOUNT", PyInt_FromLong(UF_TEMP_DUPLICATE_ACCOUNT));
	PyModule_AddObject(m, "UF_SERVER_TRUST_ACCOUNT", PyInt_FromLong(UF_SERVER_TRUST_ACCOUNT));
	PyModule_AddObject(m, "UF_WORKSTATION_TRUST_ACCOUNT", PyInt_FromLong(UF_WORKSTATION_TRUST_ACCOUNT));
	PyModule_AddObject(m, "UF_INTERDOMAIN_TRUST_ACCOUNT", PyInt_FromLong(UF_INTERDOMAIN_TRUST_ACCOUNT));
	PyModule_AddObject(m, "UF_PASSWD_NOTREQD", PyInt_FromLong(UF_PASSWD_NOTREQD));
	PyModule_AddObject(m, "UF_ACCOUNTDISABLE", PyInt_FromLong(UF_ACCOUNTDISABLE));

	/* "groupType" flags */
	PyModule_AddObject(m, "GTYPE_SECURITY_BUILTIN_LOCAL_GROUP", PyInt_FromLong(GTYPE_SECURITY_BUILTIN_LOCAL_GROUP));
	PyModule_AddObject(m, "GTYPE_SECURITY_GLOBAL_GROUP", PyInt_FromLong(GTYPE_SECURITY_GLOBAL_GROUP));
	PyModule_AddObject(m, "GTYPE_SECURITY_DOMAIN_LOCAL_GROUP", PyInt_FromLong(GTYPE_SECURITY_DOMAIN_LOCAL_GROUP));
	PyModule_AddObject(m, "GTYPE_SECURITY_UNIVERSAL_GROUP", PyInt_FromLong(GTYPE_SECURITY_UNIVERSAL_GROUP));
	PyModule_AddObject(m, "GTYPE_DISTRIBUTION_GLOBAL_GROUP", PyInt_FromLong(GTYPE_DISTRIBUTION_GLOBAL_GROUP));
	PyModule_AddObject(m, "GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP", PyInt_FromLong(GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP));
	PyModule_AddObject(m, "GTYPE_DISTRIBUTION_UNIVERSAL_GROUP", PyInt_FromLong(GTYPE_DISTRIBUTION_UNIVERSAL_GROUP));

	/* "sAMAccountType" flags */
	PyModule_AddObject(m, "ATYPE_NORMAL_ACCOUNT", PyInt_FromLong(ATYPE_NORMAL_ACCOUNT));
	PyModule_AddObject(m, "ATYPE_WORKSTATION_TRUST", PyInt_FromLong(ATYPE_WORKSTATION_TRUST));
	PyModule_AddObject(m, "ATYPE_INTERDOMAIN_TRUST", PyInt_FromLong(ATYPE_INTERDOMAIN_TRUST));
	PyModule_AddObject(m, "ATYPE_SECURITY_GLOBAL_GROUP", PyInt_FromLong(ATYPE_SECURITY_GLOBAL_GROUP));
	PyModule_AddObject(m, "ATYPE_SECURITY_LOCAL_GROUP", PyInt_FromLong(ATYPE_SECURITY_LOCAL_GROUP));
	PyModule_AddObject(m, "ATYPE_SECURITY_UNIVERSAL_GROUP", PyInt_FromLong(ATYPE_SECURITY_UNIVERSAL_GROUP));
	PyModule_AddObject(m, "ATYPE_DISTRIBUTION_GLOBAL_GROUP", PyInt_FromLong(ATYPE_DISTRIBUTION_GLOBAL_GROUP));
	PyModule_AddObject(m, "ATYPE_DISTRIBUTION_LOCAL_GROUP", PyInt_FromLong(ATYPE_DISTRIBUTION_LOCAL_GROUP));
	PyModule_AddObject(m, "ATYPE_DISTRIBUTION_UNIVERSAL_GROUP", PyInt_FromLong(ATYPE_DISTRIBUTION_UNIVERSAL_GROUP));

	/* "domainFunctionality", "forestFunctionality" flags in the rootDSE */
	PyModule_AddObject(m, "DS_DOMAIN_FUNCTION_2000", PyInt_FromLong(DS_DOMAIN_FUNCTION_2000));
	PyModule_AddObject(m, "DS_DOMAIN_FUNCTION_2003_MIXED", PyInt_FromLong(DS_DOMAIN_FUNCTION_2003_MIXED));
	PyModule_AddObject(m, "DS_DOMAIN_FUNCTION_2003", PyInt_FromLong(DS_DOMAIN_FUNCTION_2003));
	PyModule_AddObject(m, "DS_DOMAIN_FUNCTION_2008", PyInt_FromLong(DS_DOMAIN_FUNCTION_2008));
	PyModule_AddObject(m, "DS_DOMAIN_FUNCTION_2008_R2", PyInt_FromLong(DS_DOMAIN_FUNCTION_2008_R2));

	/* "domainControllerFunctionality" flags in the rootDSE */
	PyModule_AddObject(m, "DS_DC_FUNCTION_2000", PyInt_FromLong(DS_DC_FUNCTION_2000));
	PyModule_AddObject(m, "DS_DC_FUNCTION_2003", PyInt_FromLong(DS_DC_FUNCTION_2003));
	PyModule_AddObject(m, "DS_DC_FUNCTION_2008", PyInt_FromLong(DS_DC_FUNCTION_2008));
	PyModule_AddObject(m, "DS_DC_FUNCTION_2008_R2", PyInt_FromLong(DS_DC_FUNCTION_2008_R2));
}
