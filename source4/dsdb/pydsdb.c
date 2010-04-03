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
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	if (!PyArg_ParseTuple(args, "O", &py_ldb)) {
		talloc_free(mem_ctx);
		return NULL;
	}

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

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

static PyMethodDef py_dsdb_methods[] = {
	{ "server_site_name", (PyCFunction)py_samdb_server_site_name, METH_VARARGS,
		"get the server site name as a string"},
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
