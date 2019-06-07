/*
   Unix SMB/CIFS implementation.
   Samba utility functions

   Copyright (C) Catalyst IT 2017

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
#include "librpc/gen_ndr/lsa.h"

static PyObject *py_lsa_String_str(PyObject *py_self)
{
	struct lsa_String *self = pytalloc_get_ptr(py_self);
	PyObject *ret = NULL;
	if (self->string == NULL) {
		const char *empty = "";
		ret = PyUnicode_FromString(empty);
	} else {
		ret = PyUnicode_FromString(self->string);
	}
	return ret;
}

static PyObject *py_lsa_String_repr(PyObject *py_self)
{
	struct lsa_String *self = pytalloc_get_ptr(py_self);
	PyObject *ret = NULL;
	if (self->string == NULL) {
		const char *empty = "lsaString(None)";
		ret = PyUnicode_FromString(empty);
	} else {
		ret = PyUnicode_FromFormat("lsaString('%s')", self->string);
	}
	return ret;
}

static int py_lsa_String_init(PyObject *self, PyObject *args, PyObject *kwargs)
{
	struct lsa_String *string = pytalloc_get_ptr(self);
	const char *str = NULL;
	const char *kwnames[] = { "str", NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|s", discard_const_p(char *, kwnames), &str))
		return -1;

	string->string = talloc_strdup(string, str);

	if (str != NULL && string->string == NULL) {
		PyErr_NoMemory();
		return -1;
	}

	return 0;
}


static void py_lsa_String_patch(PyTypeObject *type)
{
	type->tp_init = py_lsa_String_init;
	type->tp_str = py_lsa_String_str;
	type->tp_repr = py_lsa_String_repr;
}

#define PY_STRING_PATCH py_lsa_String_patch

