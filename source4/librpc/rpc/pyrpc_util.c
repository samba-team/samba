/*
   Unix SMB/CIFS implementation.

   Python interface to DCE/RPC library - utility functions.

   Copyright (C) 2010 Jelmer Vernooij <jelmer@samba.org>
   Copyright (C) 2010 Andrew Tridgell <tridge@samba.org>

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
#include "librpc/rpc/pyrpc_util.h"

#ifndef Py_TYPE /* Py_TYPE is only available on Python > 2.6 */
#define Py_TYPE(ob)             (((PyObject*)(ob))->ob_type)
#endif

bool py_check_dcerpc_type(PyObject *obj, const char *module, const char *typename)
{
	PyObject *mod;
        PyTypeObject *type;
	bool ret;

	mod = PyImport_ImportModule(module);

	if (mod == NULL) {
		PyErr_Format(PyExc_RuntimeError, "Unable to import %s to check type %s",
			module, typename);
		return NULL;
	}

	type = (PyTypeObject *)PyObject_GetAttrString(mod, typename);
	Py_DECREF(mod);
	if (type == NULL) {
		PyErr_Format(PyExc_RuntimeError, "Unable to find type %s in module %s",
			module, typename);
		return NULL;
	}

	ret = PyObject_TypeCheck(obj, type);
	Py_DECREF(type);

	if (!ret)
		PyErr_Format(PyExc_TypeError, "Expected type %s.%s, got %s",
			module, typename, Py_TYPE(obj)->tp_name);

	return ret;
}
