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

/**
 * Default (but only slightly more useful than the default) implementation of Repr().
 */
static PyObject *py_talloc_default_repr(PyObject *obj)
{
	py_talloc_Object *talloc_obj = (py_talloc_Object *)obj;
	PyTypeObject *type = (PyTypeObject*)PyObject_Type(obj);

	return PyString_FromFormat("<%s talloc object at 0x%p>", 
				   type->tp_name, talloc_obj->ptr);
}

static PyTypeObject TallocObject_Type = {
	.tp_name = "talloc.Object",
	.tp_basicsize = sizeof(py_talloc_Object),
	.tp_dealloc = (destructor)py_talloc_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_repr = py_talloc_default_repr,
	.tp_compare = py_talloc_default_cmp,
};

void inittalloc(void)
{
	PyObject *m;

	if (PyType_Ready(&TallocObject_Type) < 0)
		return;

	m = Py_InitModule3("talloc", talloc_methods, "Debug utilities for talloc-wrapped objects.");
	if (m == NULL)
		return;

	Py_INCREF(&TallocObject_Type);
	PyModule_AddObject(m, "Object", (PyObject *)&TallocObject_Type);
}
