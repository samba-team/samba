/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
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

#include <Python.h>
#include "py3compat.h"
#include "includes.h"
#include "python/modules.h"
#include "dynconfig/dynconfig.h"

static bool PySys_PathPrepend(PyObject *list, const char *path)
{
	bool ok;
	PyObject *py_path = PyUnicode_FromString(path);
	if (py_path == NULL) {
		return false;
	}
	ok = PyList_Insert(list, 0, py_path) == 0;
	Py_XDECREF(py_path);
	return ok;
}

bool py_update_path(void)
{
	PyObject *mod_sys = NULL;
	PyObject *py_path = NULL;

	mod_sys = PyImport_ImportModule("sys");
	if (mod_sys == NULL) {
		return false;
	}

	py_path = PyObject_GetAttrString(mod_sys, "path");
	if (py_path == NULL) {
		goto error;
	}

	if (!PyList_Check(py_path)) {
		goto error;
	}

	if (!PySys_PathPrepend(py_path, dyn_PYTHONDIR)) {
		goto error;
	}

	if (strcmp(dyn_PYTHONARCHDIR, dyn_PYTHONDIR) != 0) {
		if (!PySys_PathPrepend(py_path, dyn_PYTHONARCHDIR)) {
			goto error;
		}
	}
	Py_XDECREF(py_path);
	Py_XDECREF(mod_sys);
	return true;
error:
	Py_XDECREF(py_path);
	Py_XDECREF(mod_sys);
	return false;
}

const char **PyList_AsStringList(TALLOC_CTX *mem_ctx, PyObject *list, 
				 const char *paramname)
{
	const char **ret;
	Py_ssize_t i;
	if (!PyList_Check(list)) {
		PyErr_Format(PyExc_TypeError, "%s is not a list", paramname);
		return NULL;
	}
	ret = talloc_array(NULL, const char *, PyList_Size(list)+1);
	if (ret == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	for (i = 0; i < PyList_Size(list); i++) {
		const char *value;
		Py_ssize_t size;
		PyObject *item = PyList_GetItem(list, i);
		if (!PyUnicode_Check(item)) {
			PyErr_Format(PyExc_TypeError, "%s should be strings", paramname);
			return NULL;
		}
		value = PyUnicode_AsUTF8AndSize(item, &size);
		if (value == NULL) {
			talloc_free(ret);
			return NULL;
		}
		ret[i] = talloc_strndup(ret, value, size);
	}
	ret[i] = NULL;
	return ret;
}

