/*
   Unix SMB/CIFS implementation.
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2008
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2011

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
#include "includes.h"
#include "python/modules.h"
#include "libcli/util/pyerrors.h"
#include "libcli/security/security.h"
#include "pytalloc.h"

static PyObject *py_se_access_check(PyObject *module, PyObject *args, PyObject *kwargs)
{
	NTSTATUS nt_status;
	const char * const kwnames[] = { "security_descriptor", "token", "access_desired", NULL };
	PyObject *py_sec_desc = Py_None;
	PyObject *py_security_token = Py_None;
	struct security_descriptor *security_descriptor;
	struct security_token *security_token;
	unsigned int access_desired; /* This is an unsigned int, not uint32_t,
				      * because that's what we need for the
				      * python PyArg_ParseTupleAndKeywords */
	uint32_t access_granted;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OOI",
					 discard_const_p(char *, kwnames),
					 &py_sec_desc, &py_security_token, &access_desired)) {
		return NULL;
	}

	security_descriptor = pytalloc_get_type(py_sec_desc, struct security_descriptor);
	if (!security_descriptor) {
		PyErr_Format(PyExc_TypeError,
			     "Expected dcerpc.security.descriptor for security_descriptor argument got  %s",
			     pytalloc_get_name(py_sec_desc));
		return NULL;
	}

	security_token = pytalloc_get_type(py_security_token, struct security_token);
	if (!security_token) {
		PyErr_Format(PyExc_TypeError,
			     "Expected dcerpc.security.token for token argument, got %s",
			     pytalloc_get_name(py_sec_desc));
		return NULL;
	}

	nt_status = se_access_check(security_descriptor, security_token, access_desired, &access_granted);
	if (!NT_STATUS_IS_OK(nt_status)) {
		PyErr_NTSTATUS_IS_ERR_RAISE(nt_status);
	}

	return PyLong_FromLong(access_granted);
}

static PyMethodDef py_security_methods[] = {
	{ "access_check", PY_DISCARD_FUNC_SIG(PyCFunction,
					      py_se_access_check),
	METH_VARARGS|METH_KEYWORDS,
	"access_check(security_descriptor, token, access_desired) -> access_granted.  Raises NT_STATUS on error, including on access check failure, returns access granted bitmask"},
	{0},
};

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	.m_name = "security",
	.m_doc = "Security support.",
	.m_size = -1,
	.m_methods = py_security_methods,
};

MODULE_INIT_FUNC(security)
{
	PyObject *m;

	m = PyModule_Create(&moduledef);
	if (m == NULL)
		return NULL;

	return m;
}
