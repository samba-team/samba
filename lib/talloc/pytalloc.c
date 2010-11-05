/* 
   Unix SMB/CIFS implementation.
   Python Talloc Module
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2010

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
#include <talloc.h>
#include <pytalloc.h>

/* print a talloc tree report for a talloc python object */
static PyObject *py_talloc_report_full(PyObject *self, PyObject *args)
{
	PyObject *py_obj = Py_None;
	PyTypeObject *type;

	if (!PyArg_ParseTuple(args, "|O", &py_obj))
		return NULL;

	if (py_obj == Py_None) {
		talloc_report_full(NULL, stdout);
	} else {
		type = (PyTypeObject*)PyObject_Type(py_obj);
		talloc_report_full(py_talloc_get_mem_ctx(py_obj), stdout);
	}
	return Py_None;
}

/* enable null tracking */
static PyObject *py_talloc_enable_null_tracking(PyObject *self)
{
	talloc_enable_null_tracking();
	return Py_None;
}

/* return the number of talloc blocks */
static PyObject *py_talloc_total_blocks(PyObject *self, PyObject *args)
{
	PyObject *py_obj = Py_None;
	PyTypeObject *type;

	if (!PyArg_ParseTuple(args, "|O", &py_obj))
		return NULL;

	if (py_obj == Py_None) {
		return PyLong_FromLong(talloc_total_blocks(NULL));
	}

	type = (PyTypeObject*)PyObject_Type(py_obj);

	return PyLong_FromLong(talloc_total_blocks(py_talloc_get_mem_ctx(py_obj)));
}

static PyMethodDef talloc_methods[] = {
	{ "report_full", (PyCFunction)py_talloc_report_full, METH_VARARGS,
		"show a talloc tree for an object"},
	{ "enable_null_tracking", (PyCFunction)py_talloc_enable_null_tracking, METH_NOARGS,
		"enable tracking of the NULL object"},
	{ "total_blocks", (PyCFunction)py_talloc_total_blocks, METH_VARARGS,
		"return talloc block count"},
	{ NULL }
};

void inittalloc(void)
{
	PyObject *m;

	m = Py_InitModule3("talloc", talloc_methods, "Debug utilities for talloc-wrapped objects.");
	if (m == NULL)
		return;
}
