/*
   Unix SMB/CIFS implementation.

   Python interface to ldb, Samba-specific functions

   Copyright (C) 2007-2010 Jelmer Vernooij <jelmer@samba.org>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include <Python.h>
#include "includes.h"
#include <ldb.h>
#include "lib/ldb/pyldb.h"
#include "param/pyparam.h"
#include "auth/credentials/pycredentials.h"

static PyObject *pyldb_module;
staticforward PyTypeObject PySambaLdb;

static PyObject *py_ldb_set_loadparm(PyObject *self, PyObject *args)
{
	PyObject *py_lp_ctx;
	struct loadparm_context *lp_ctx;
	struct ldb_context *ldb;

	if (!PyArg_ParseTuple(args, "O", &py_lp_ctx))
		return NULL;

	lp_ctx = lp_from_py_object(py_lp_ctx);
	if (lp_ctx == NULL) {
		PyErr_SetString(PyExc_TypeError, "Expected loadparm object");
		return NULL;
	}

	ldb = PyLdb_AsLdbContext(self);

	ldb_set_opaque(ldb, "loadparm", lp_ctx);

	Py_RETURN_NONE;
}

static PyObject *py_ldb_set_credentials(PyObject *self, PyObject *args)
{
	PyObject *py_creds;
	struct cli_credentials *creds;
	struct ldb_context *ldb;

	if (!PyArg_ParseTuple(args, "O", &py_creds))
		return NULL;

	creds = cli_credentials_from_py_object(py_creds);
	if (creds == NULL) {
		PyErr_SetString(PyExc_TypeError, "Expected credentials object");
		return NULL;
	}

	ldb = PyLdb_AsLdbContext(self);

	ldb_set_opaque(ldb, "credentials", creds);

	Py_RETURN_NONE;
}

static PyMethodDef py_samba_ldb_methods[] = {
	{ "set_loadparm", (PyCFunction)py_ldb_set_loadparm, METH_VARARGS, 
		"ldb_set_loadparm(ldb, session_info)\n"
		"Set loadparm context to use when connecting." },
	{ "ldb_set_credentials", (PyCFunction)py_ldb_set_credentials, METH_VARARGS,
		"ldb_set_credentials(ldb, credentials)\n"
		"Set credentials to use when connecting." },
	{ NULL },
};

static PyTypeObject PySambaLdb = {
	.tp_name = "samba.Ldb",
	.tp_doc = "Connection to a LDB database.",
	.tp_methods = py_samba_ldb_methods,
	.tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
};


void init_ldb(void)
{
	PyObject *m;

	pyldb_module = PyImport_ImportModule("ldb");
	if (pyldb_module == NULL)
		return;

	PySambaLdb.tp_base = (PyTypeObject *)PyObject_GetAttrString(pyldb_module, "Ldb");
	if (PySambaLdb.tp_base == NULL)
		return;

	if (PyType_Ready(&PySambaLdb) < 0)
		return;

	m = Py_InitModule3("_ldb", NULL, "Samba-specific LDB python bindings");
	if (m == NULL)
		return;

	Py_INCREF(&PySambaLdb);
	PyModule_AddObject(m, "Ldb", (PyObject *)&PySambaLdb);
}
