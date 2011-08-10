/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2011
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
#include "includes.h"
#include "libcli/util/pyerrors.h"
#include "pyauth.h"
#include "auth/auth.h"
#include "auth/credentials/pycredentials.h"
#include "librpc/rpc/pyrpc_util.h"

#ifndef Py_RETURN_NONE
#define Py_RETURN_NONE return Py_INCREF(Py_None), Py_None
#endif

static void PyType_AddGetSet(PyTypeObject *type, PyGetSetDef *getset)
{
	PyObject *dict;
	int i;
	if (type->tp_dict == NULL)
		type->tp_dict = PyDict_New();
	dict = type->tp_dict;
	for (i = 0; getset[i].name; i++) {
		PyObject *descr;
		descr = PyDescr_NewGetSet(type, &getset[i]);
		PyDict_SetItemString(dict, getset[i].name, 
				     descr);
	}
}

static PyObject *py_auth_session_get_credentials(PyObject *self, void *closure)
{
	struct auth_session_info *session = pytalloc_get_type(self, struct auth_session_info);
	PyObject *py_credentials;
	/* This is evil, as the credentials are not IDL structures */
	py_credentials = py_return_ndr_struct("samba.credentials", "Credentials", session->credentials, session->credentials);
	return py_credentials;
}

static int py_auth_session_set_credentials(PyObject *self, PyObject *value, void *closure)
{
	struct auth_session_info *session = pytalloc_get_type(self, struct auth_session_info);
	session->credentials = talloc_reference(session, PyCredentials_AsCliCredentials(value));
	return 0;
}

static PyGetSetDef py_auth_session_extra_getset[] = {
	{ discard_const_p(char, "credentials"), (getter)py_auth_session_get_credentials, (setter)py_auth_session_set_credentials, NULL },
	{ NULL }
};

static void py_auth_session_info_patch(PyTypeObject *type)
{
	PyType_AddGetSet(type, py_auth_session_extra_getset);
}

#define PY_SESSION_INFO_PATCH py_auth_session_info_patch

