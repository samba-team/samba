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

/* XXX: This function really should be in pyldb.c */
static PyObject *py_dsdb_set_opaque_integer(PyObject *self, PyObject *args)
{
	PyObject *py_ldb;
	int value;
	int *old_val, *new_val;
	char *py_opaque_name, *opaque_name_talloc;
	struct ldb_context *ldb;
	TALLOC_CTX *tmp_ctx;

	if (!PyArg_ParseTuple(args, "Osi", &py_ldb, &py_opaque_name, &value))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	/* see if we have a cached copy */
	old_val = (int *)ldb_get_opaque(ldb, py_opaque_name);
	/* XXX: We shouldn't just blindly assume that the value that is 
	 * already present has the size of an int and is not shared 
	 * with other code that may rely on it not changing. 
	 * JRV 20100403 */

	if (old_val) {
		*old_val = value;
		Py_RETURN_NONE;
	} 

	tmp_ctx = talloc_new(ldb);
	if (tmp_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	
	new_val = talloc(tmp_ctx, int);
	if (new_val == NULL) {
		talloc_free(tmp_ctx);
		PyErr_NoMemory();
		return NULL;
	}
	
	opaque_name_talloc = talloc_strdup(tmp_ctx, py_opaque_name);
	if (opaque_name_talloc == NULL) {
		talloc_free(tmp_ctx);
		PyErr_NoMemory();
		return NULL;
	}
	
	*new_val = value;

	/* cache the domain_sid in the ldb */
	if (ldb_set_opaque(ldb, opaque_name_talloc, new_val) != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		PyErr_SetString(PyExc_RuntimeError,
					"Failed to set opaque integer into the ldb");
		return NULL;
	}

	talloc_steal(ldb, new_val);
	talloc_steal(ldb, opaque_name_talloc);
	talloc_free(tmp_ctx);

	Py_RETURN_NONE;
}

static PyMethodDef py_dsdb_methods[] = {
	{ "samdb_server_site_name", (PyCFunction)py_samdb_server_site_name,
		METH_VARARGS, "Get the server site name as a string"},
	{ "dsdb_set_opaque_integer", (PyCFunction)py_dsdb_set_opaque_integer,
		METH_VARARGS, NULL },
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
