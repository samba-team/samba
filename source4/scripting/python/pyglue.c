/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
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
#include "ldb.h"
#include "ldb_errors.h"
#include "ldb_wrap.h"
#include "param/param.h"
#include "auth/credentials/credentials.h"
#include "dsdb/samdb/samdb.h"
#include "lib/ldb-samba/ldif_handlers.h"
#include "librpc/ndr/libndr.h"
#include "version.h"
#include "lib/ldb/pyldb.h"
#include "libcli/util/pyerrors.h"
#include "libcli/security/security.h"
#include "auth/pyauth.h"
#include "param/pyparam.h"
#include "auth/credentials/pycredentials.h"
#include "lib/socket/netif.h"
#include "lib/socket/netif_proto.h"

/* FIXME: These should be in a header file somewhere, once we finish moving
 * away from SWIG .. */
#define PyErr_LDB_OR_RAISE(py_ldb, ldb) \
/*	if (!PyLdb_Check(py_ldb)) { \
		PyErr_SetString(py_ldb_get_exception(), "Ldb connection object required"); \
		return NULL; \
	} */\
	ldb = PyLdb_AsLdbContext(py_ldb);

static void PyErr_SetLdbError(PyObject *error, int ret, struct ldb_context *ldb_ctx)
{
	if (ret == LDB_ERR_PYTHON_EXCEPTION)
		return; /* Python exception should already be set, just keep that */

	PyErr_SetObject(error, 
			Py_BuildValue(discard_const_p(char, "(i,s)"), ret,
			ldb_ctx == NULL?ldb_strerror(ret):ldb_errstring(ldb_ctx)));
}

static PyObject *py_ldb_get_exception(void)
{
	PyObject *mod = PyImport_ImportModule("ldb");
	if (mod == NULL)
		return NULL;

	return PyObject_GetAttrString(mod, "LdbError");
}

static PyObject *py_generate_random_str(PyObject *self, PyObject *args)
{
	int len;
	PyObject *ret;
	char *retstr;
	if (!PyArg_ParseTuple(args, "i", &len))
		return NULL;

	retstr = generate_random_str(NULL, len);
	ret = PyString_FromString(retstr);
	talloc_free(retstr);
	return ret;
}

static PyObject *py_generate_random_password(PyObject *self, PyObject *args)
{
	int min, max;
	PyObject *ret;
	char *retstr;
	if (!PyArg_ParseTuple(args, "ii", &min, &max))
		return NULL;

	retstr = generate_random_password(NULL, min, max);
	if (retstr == NULL) {
		return NULL;
	}
	ret = PyString_FromString(retstr);
	talloc_free(retstr);
	return ret;
}

static PyObject *py_unix2nttime(PyObject *self, PyObject *args)
{
	time_t t;
	NTTIME nt;
	if (!PyArg_ParseTuple(args, "I", &t))
		return NULL;

	unix_to_nt_time(&nt, t);

	return PyInt_FromLong((uint64_t)nt);
}

static PyObject *py_set_debug_level(PyObject *self, PyObject *args)
{
	unsigned level;
	if (!PyArg_ParseTuple(args, "I", &level))
		return NULL;
	(DEBUGLEVEL) = level;
	Py_RETURN_NONE;
}

static PyObject *py_dsdb_set_global_schema(PyObject *self, PyObject *args)
{
	PyObject *py_ldb;
	struct ldb_context *ldb;
	int ret;
	if (!PyArg_ParseTuple(args, "O", &py_ldb))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	ret = dsdb_set_global_schema(ldb);
	PyErr_LDB_ERROR_IS_ERR_RAISE(py_ldb_get_exception(), ret, ldb);

	Py_RETURN_NONE;
}

static PyObject *py_dsdb_set_schema_from_ldif(PyObject *self, PyObject *args)
{
	WERROR result;
	char *pf, *df;
	PyObject *py_ldb;
	struct ldb_context *ldb;

	if (!PyArg_ParseTuple(args, "Oss", &py_ldb, &pf, &df))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	result = dsdb_set_schema_from_ldif(ldb, pf, df);
	PyErr_WERROR_IS_ERR_RAISE(result);

	Py_RETURN_NONE;
}

static PyObject *py_dsdb_write_prefixes_from_schema_to_ldb(PyObject *self, PyObject *args)
{
	PyObject *py_ldb;
	struct ldb_context *ldb;
	WERROR result;
	struct dsdb_schema *schema;

	if (!PyArg_ParseTuple(args, "O", &py_ldb))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	schema = dsdb_get_schema(ldb, NULL);
	if (!schema) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to set find a schema on ldb!\n");
		return NULL;
	}

	result = dsdb_write_prefixes_from_schema_to_ldb(NULL, ldb, schema);
	PyErr_WERROR_IS_ERR_RAISE(result);

	Py_RETURN_NONE;
}

static PyObject *py_dsdb_set_schema_from_ldb(PyObject *self, PyObject *args)
{
	PyObject *py_ldb;
	struct ldb_context *ldb;
	PyObject *py_from_ldb;
	struct ldb_context *from_ldb;
	struct dsdb_schema *schema;
	int ret;
	if (!PyArg_ParseTuple(args, "OO", &py_ldb, &py_from_ldb))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	PyErr_LDB_OR_RAISE(py_from_ldb, from_ldb);

	schema = dsdb_get_schema(from_ldb, NULL);
	if (!schema) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to set find a schema on 'from' ldb!\n");
		return NULL;
	}

	ret = dsdb_reference_schema(ldb, schema, true);
	PyErr_LDB_ERROR_IS_ERR_RAISE(py_ldb_get_exception(), ret, ldb);

	Py_RETURN_NONE;
}

static PyObject *py_dsdb_load_partition_usn(PyObject *self, PyObject *args)
{
	PyObject *py_dn, *py_ldb, *result;
	struct ldb_dn *dn;
	uint64_t highest_uSN, urgent_uSN;
	struct ldb_context *ldb;
	TALLOC_CTX *mem_ctx;
	int ret;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
	   PyErr_NoMemory();
	   return NULL;
	}

	if (!PyArg_ParseTuple(args, "OO", &py_ldb, &py_dn)) {
	   talloc_free(mem_ctx);
	   return NULL;
	}

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	if (!PyObject_AsDn(mem_ctx, py_dn, ldb, &dn)) {
	   talloc_free(mem_ctx);
	   return NULL;
	}

	ret = dsdb_load_partition_usn(ldb, dn, &highest_uSN, &urgent_uSN);
	if (ret != LDB_SUCCESS) {
	   char *errstr = talloc_asprintf(mem_ctx, "Failed to load partition uSN - %s", ldb_errstring(ldb));
	   PyErr_SetString(PyExc_RuntimeError, errstr);
	   talloc_free(mem_ctx);
	   return NULL;
	}

	talloc_free(mem_ctx);

	result = PyDict_New();

	PyDict_SetItemString(result, "uSNHighest", PyInt_FromLong((uint64_t)highest_uSN));
	PyDict_SetItemString(result, "uSNUrgent", PyInt_FromLong((uint64_t)urgent_uSN));


	return result;
}

/*
  return the list of interface IPs we have configured
  takes an loadparm context, returns a list of IPs in string form

  Does not return addresses on 127.0.0.0/8
 */
static PyObject *py_interface_ips(PyObject *self, PyObject *args)
{
	PyObject *pylist;
	int count;
	TALLOC_CTX *tmp_ctx;
	PyObject *py_lp_ctx;
	struct loadparm_context *lp_ctx;
	struct interface *ifaces;
	int i, ifcount;
	int all_interfaces;

	if (!PyArg_ParseTuple(args, "Oi", &py_lp_ctx, &all_interfaces))
		return NULL;

	lp_ctx = lp_from_py_object(py_lp_ctx);
	if (lp_ctx == NULL) {
		PyErr_SetString(PyExc_TypeError, "Expected loadparm object");
		return NULL;
	}

	tmp_ctx = talloc_new(NULL);

	load_interfaces(tmp_ctx, lp_interfaces(lp_ctx), &ifaces);

	count = iface_count(ifaces);

	/* first count how many are not loopback addresses */
	for (ifcount = i = 0; i<count; i++) {
		const char *ip = iface_n_ip(ifaces, i);
		if (!(!all_interfaces && iface_same_net(ip, "127.0.0.1", "255.0.0.0"))) {
			ifcount++;
		}
	}

	pylist = PyList_New(ifcount);
	for (ifcount = i = 0; i<count; i++) {
		const char *ip = iface_n_ip(ifaces, i);
		if (!(!all_interfaces && iface_same_net(ip, "127.0.0.1", "255.0.0.0"))) {
			PyList_SetItem(pylist, ifcount, PyString_FromString(ip));
			ifcount++;
		}
	}
	talloc_free(tmp_ctx);
	return pylist;
}


static PyMethodDef py_misc_methods[] = {
	{ "generate_random_str", (PyCFunction)py_generate_random_str, METH_VARARGS,
		"generate_random_str(len) -> string\n"
		"Generate random string with specified length." },
	{ "generate_random_password", (PyCFunction)py_generate_random_password, METH_VARARGS,
		"generate_random_password(min, max) -> string\n"
		"Generate random password with a length >= min and <= max." },
	{ "unix2nttime", (PyCFunction)py_unix2nttime, METH_VARARGS,
		"unix2nttime(timestamp) -> nttime" },
	{ "dsdb_set_global_schema", (PyCFunction)py_dsdb_set_global_schema, METH_VARARGS,
		NULL },
	{ "dsdb_set_schema_from_ldif", (PyCFunction)py_dsdb_set_schema_from_ldif, METH_VARARGS,
		NULL },
	{ "dsdb_write_prefixes_from_schema_to_ldb", (PyCFunction)py_dsdb_write_prefixes_from_schema_to_ldb, METH_VARARGS,
		NULL },
	{ "dsdb_set_schema_from_ldb", (PyCFunction)py_dsdb_set_schema_from_ldb, METH_VARARGS,
		NULL },
	{ "set_debug_level", (PyCFunction)py_set_debug_level, METH_VARARGS,
		"set debug level" },
	{ "dsdb_load_partition_usn", (PyCFunction)py_dsdb_load_partition_usn, METH_VARARGS,
		"get uSNHighest and uSNUrgent from the partition @REPLCHANGED"},
	{ "interface_ips", (PyCFunction)py_interface_ips, METH_VARARGS,
		"get interface IP address list"},
	{ NULL }
};

void initglue(void)
{
	PyObject *m;

	debug_setup_talloc_log();

	m = Py_InitModule3("glue", py_misc_methods, 
			   "Python bindings for miscellaneous Samba functions.");
	if (m == NULL)
		return;

	PyModule_AddObject(m, "version", PyString_FromString(SAMBA_VERSION_STRING));

	/* one of the most annoying things about python scripts is
 	   that they don't die when you hit control-C. This fixes that
 	   sillyness. As we do all database operations using
 	   transactions, this is also safe. In fact, not dying
 	   immediately is unsafe as we could end up treating the
 	   control-C exception as a different error and try to modify
 	   as database incorrectly 
	*/
	signal(SIGINT, SIG_DFL);
}

