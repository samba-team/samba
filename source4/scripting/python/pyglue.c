/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
   
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
#include "ldb.h"
#include "ldb_errors.h"
#include "param/param.h"
#include "auth/credentials/credentials.h"
#include "dsdb/samdb/samdb.h"
#include "lib/ldb-samba/ldif_handlers.h"
#include "librpc/ndr/libndr.h"
#include "version.h"
#include <Python.h>
#include "lib/ldb/pyldb.h"
#include "libcli/util/pyerrors.h"
#include "libcli/security/security.h"
#include "auth/pyauth.h"
#include "param/pyparam.h"

#ifndef Py_RETURN_NONE
#define Py_RETURN_NONE return Py_INCREF(Py_None), Py_None
#endif

/* FIXME: These should be in a header file somewhere, once we finish moving
 * away from SWIG .. */
extern struct cli_credentials *cli_credentials_from_py_object(PyObject *py_obj);

#define PyErr_LDB_OR_RAISE(py_ldb, ldb) \
	if (!PyLdb_Check(py_ldb)) { \
		/*PyErr_SetString(PyExc_TypeError, "Ldb connection object required"); \
		return NULL; \ */ \
	} \
	ldb = PyLdb_AsLdbContext(py_ldb);


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

static PyObject *py_unix2nttime(PyObject *self, PyObject *args)
{
	time_t t;
	NTTIME nt;
	if (!PyArg_ParseTuple(args, "I", &t))
		return NULL;

	unix_to_nt_time(&nt, t);

	return PyInt_FromLong((uint64_t)nt);
}

static PyObject *py_ldb_set_credentials(PyObject *self, PyObject *args)
{
	PyObject *py_creds, *py_ldb;
	struct cli_credentials *creds;
	struct ldb_context *ldb;
	if (!PyArg_ParseTuple(args, "OO", &py_ldb, &py_creds))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);
	
	creds = cli_credentials_from_py_object(py_creds);
	if (creds == NULL) {
		PyErr_SetString(PyExc_TypeError, "Expected credentials object");
		return NULL;
	}

    	ldb_set_opaque(ldb, "credentials", creds);

	Py_RETURN_NONE;
}

static PyObject *py_ldb_set_loadparm(PyObject *self, PyObject *args)
{
	PyObject *py_lp_ctx, *py_ldb;
	struct loadparm_context *lp_ctx;
	struct ldb_context *ldb;
	if (!PyArg_ParseTuple(args, "OO", &py_ldb, &py_lp_ctx))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	lp_ctx = lp_from_py_object(py_lp_ctx);
	if (lp_ctx == NULL) {
		PyErr_SetString(PyExc_TypeError, "Expected loadparm object");
		return NULL;
	}

    	ldb_set_opaque(ldb, "loadparm", lp_ctx);

	Py_RETURN_NONE;
}


static PyObject *py_ldb_set_session_info(PyObject *self, PyObject *args)
{
	PyObject *py_session_info, *py_ldb;
	struct auth_session_info *info;
	struct ldb_context *ldb;
	if (!PyArg_ParseTuple(args, "OO", &py_ldb, &py_session_info))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);
	/*if (!PyAuthSession_Check(py_session_info)) {
		PyErr_SetString(PyExc_TypeError, "Expected session info object");
		return NULL;
	}*/

	info = PyAuthSession_AsSession(py_session_info);

    	ldb_set_opaque(ldb, "sessionInfo", info);

	Py_RETURN_NONE;
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

static PyObject *py_ldb_register_samba_handlers(PyObject *self, PyObject *args)
{
	PyObject *py_ldb;
	struct ldb_context *ldb;
	int ret;

	if (!PyArg_ParseTuple(args, "O", &py_ldb))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);
	ret = ldb_register_samba_handlers(ldb);

	PyErr_LDB_ERROR_IS_ERR_RAISE(ret, ldb);
	Py_RETURN_NONE;
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

static PyObject *py_dsdb_set_global_schema(PyObject *self, PyObject *args)
{
	PyObject *py_ldb;
	struct ldb_context *ldb;
	int ret;
	if (!PyArg_ParseTuple(args, "O", &py_ldb))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	ret = dsdb_set_global_schema(ldb);
	PyErr_LDB_ERROR_IS_ERR_RAISE(ret, ldb);

	Py_RETURN_NONE;
}

static PyObject *py_dsdb_attach_schema_from_ldif_file(PyObject *self, PyObject *args)
{
	WERROR result;
	char *pf, *df;
	PyObject *py_ldb;
	struct ldb_context *ldb;

	if (!PyArg_ParseTuple(args, "Oss", &py_ldb, &pf, &df))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	result = dsdb_attach_schema_from_ldif_file(ldb, pf, df);
	PyErr_WERROR_IS_ERR_RAISE(result);

	Py_RETURN_NONE;
}

static PyMethodDef py_misc_methods[] = {
	{ "generate_random_str", (PyCFunction)py_generate_random_str, METH_VARARGS,
		"random_password(len) -> string\n"
		"Generate random password with specified length." },
	{ "unix2nttime", (PyCFunction)py_unix2nttime, METH_VARARGS,
		"unix2nttime(timestamp) -> nttime" },
	{ "ldb_set_credentials", (PyCFunction)py_ldb_set_credentials, METH_VARARGS, 
		"ldb_set_credentials(ldb, credentials) -> None\n"
		"Set credentials to use when connecting." },
	{ "ldb_set_session_info", (PyCFunction)py_ldb_set_session_info, METH_VARARGS,
		"ldb_set_session_info(ldb, session_info)\n"
		"Set session info to use when connecting." },
	{ "ldb_set_loadparm", (PyCFunction)py_ldb_set_loadparm, METH_VARARGS,
		"ldb_set_loadparm(ldb, session_info)\n"
		"Set loadparm context to use when connecting." },
	{ "samdb_set_domain_sid", (PyCFunction)py_samdb_set_domain_sid, METH_VARARGS,
		"samdb_set_domain_sid(samdb, sid)\n"
		"Set SID of domain to use." },
	{ "ldb_register_samba_handlers", (PyCFunction)py_ldb_register_samba_handlers, METH_VARARGS,
		"ldb_register_samba_handlers(ldb)\n"
		"Register Samba-specific LDB modules and schemas." },
	{ "dsdb_set_ntds_invocation_id", (PyCFunction)py_dsdb_set_ntds_invocation_id, METH_VARARGS,
		NULL },
	{ "dsdb_set_global_schema", (PyCFunction)py_dsdb_set_global_schema, METH_VARARGS,
		NULL },
	{ "dsdb_attach_schema_from_ldif_file", (PyCFunction)py_dsdb_attach_schema_from_ldif_file, METH_VARARGS,
		NULL },
	{ NULL }
};

void initglue(void)
{
	PyObject *m;

	m = Py_InitModule3("glue", py_misc_methods, 
			   "Python bindings for miscellaneous Samba functions.");
	if (m == NULL)
		return;

	PyModule_AddObject(m, "version", PyString_FromString(SAMBA_VERSION_STRING));
}

