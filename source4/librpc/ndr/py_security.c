/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2008
   
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
#include "libcli/security/security.h"

static PyObject *py_dom_sid_eq(PyObject *self, PyObject *args)
{
	struct dom_sid *this = py_talloc_get_ptr(self), *other;
	PyObject *py_other;

	if (!PyArg_ParseTuple(args, "O", &py_other)) 
		return NULL;

	other = py_talloc_get_type(py_other, struct dom_sid);
	if (other == NULL)
		return Py_False;

	return dom_sid_equal(this, other)?Py_True:Py_False;
}

static PyObject *py_dom_sid_str(PyObject *self)
{
	struct dom_sid *this = py_talloc_get_ptr(self);
	char *str = dom_sid_string(NULL, this);
	PyObject *ret = PyString_FromString(str);
	talloc_free(str);
	return ret;
}

static PyObject *py_dom_sid_repr(PyObject *self)
{
	struct dom_sid *this = py_talloc_get_ptr(self);
	char *str = dom_sid_string(NULL, this);
	PyObject *ret = PyString_FromFormat("dom_sid('%s')", str);
	talloc_free(str);
	return ret;
}

#define PY_DOM_SID_REPR py_dom_sid_repr

#define PY_DOM_SID_EXTRA_METHODS \
	{ "__eq__", (PyCFunction)py_dom_sid_eq, METH_VARARGS, "S.__eq__(x) -> S == x" }, \
	{ "__str__", (PyCFunction)py_dom_sid_str, METH_NOARGS, "S.__str__() -> str(S)" }, \
