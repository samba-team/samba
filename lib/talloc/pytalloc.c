/* 
   Unix SMB/CIFS implementation.
   Python Talloc Module
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2010-2011

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
#include "pytalloc_private.h"

static PyTypeObject TallocObject_Type;

/* print a talloc tree report for a talloc python object */
static PyObject *pytalloc_report_full(PyObject *self, PyObject *args)
{
	PyObject *py_obj = Py_None;

	if (!PyArg_ParseTuple(args, "|O", &py_obj))
		return NULL;

	if (py_obj == Py_None) {
		talloc_report_full(NULL, stdout);
	} else {
		talloc_report_full(pytalloc_get_mem_ctx(py_obj), stdout);
	}
	Py_RETURN_NONE;
}

/* enable null tracking */
static PyObject *pytalloc_enable_null_tracking(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
	talloc_enable_null_tracking();
	Py_RETURN_NONE;
}

/* return the number of talloc blocks */
static PyObject *pytalloc_total_blocks(PyObject *self, PyObject *args)
{
	PyObject *py_obj = Py_None;

	if (!PyArg_ParseTuple(args, "|O", &py_obj))
		return NULL;

	if (py_obj == Py_None) {
		return PyLong_FromLong(talloc_total_blocks(NULL));
	}

	return PyLong_FromLong(talloc_total_blocks(pytalloc_get_mem_ctx(py_obj)));
}

static PyMethodDef talloc_methods[] = {
	{ "report_full", (PyCFunction)pytalloc_report_full, METH_VARARGS,
		"show a talloc tree for an object"},
	{ "enable_null_tracking", (PyCFunction)pytalloc_enable_null_tracking, METH_NOARGS,
		"enable tracking of the NULL object"},
	{ "total_blocks", (PyCFunction)pytalloc_total_blocks, METH_VARARGS,
		"return talloc block count"},
	{0}
};

/**
 * Default (but only slightly more useful than the default) implementation of Repr().
 */
static PyObject *pytalloc_default_repr(PyObject *obj)
{
	pytalloc_Object *talloc_obj = (pytalloc_Object *)obj;
	PyTypeObject *type = (PyTypeObject*)PyObject_Type(obj);

	return PyUnicode_FromFormat("<%s talloc object at %p>",
				type->tp_name, talloc_obj->ptr);
}

/**
 * Simple dealloc for talloc-wrapping PyObjects
 */
static void pytalloc_dealloc(PyObject* self)
{
	pytalloc_Object *obj = (pytalloc_Object *)self;
	assert(talloc_unlink(NULL, obj->talloc_ctx) != -1);
	obj->talloc_ctx = NULL;
	self->ob_type->tp_free(self);
}

/**
 * Default (but only slightly more useful than the default) implementation of cmp.
 */
#if PY_MAJOR_VERSION >= 3
static PyObject *pytalloc_default_richcmp(PyObject *obj1, PyObject *obj2, int op)
{
	void *ptr1;
	void *ptr2;
	if (Py_TYPE(obj1) == Py_TYPE(obj2)) {
		/* When types match, compare pointers */
		ptr1 = pytalloc_get_ptr(obj1);
		ptr2 = pytalloc_get_ptr(obj2);
	} else if (PyObject_TypeCheck(obj2, &TallocObject_Type)) {
		/* Otherwise, compare types */
		ptr1 = Py_TYPE(obj1);
		ptr2 = Py_TYPE(obj2);
	} else {
		Py_INCREF(Py_NotImplemented);
		return Py_NotImplemented;
	}
	switch (op) {
		case Py_EQ: return PyBool_FromLong(ptr1 == ptr2);
		case Py_NE: return PyBool_FromLong(ptr1 != ptr2);
		case Py_LT: return PyBool_FromLong(ptr1 < ptr2);
		case Py_GT: return PyBool_FromLong(ptr1 > ptr2);
		case Py_LE: return PyBool_FromLong(ptr1 <= ptr2);
		case Py_GE: return PyBool_FromLong(ptr1 >= ptr2);
	}
	Py_INCREF(Py_NotImplemented);
	return Py_NotImplemented;
}
#else
static int pytalloc_default_cmp(PyObject *_obj1, PyObject *_obj2)
{
	pytalloc_Object *obj1 = (pytalloc_Object *)_obj1,
					 *obj2 = (pytalloc_Object *)_obj2;
	if (obj1->ob_type != obj2->ob_type)
		return ((char *)obj1->ob_type - (char *)obj2->ob_type);

	return ((char *)pytalloc_get_ptr(obj1) - (char *)pytalloc_get_ptr(obj2));
}
#endif

static PyTypeObject TallocObject_Type = {
	.tp_name = "talloc.Object",
	.tp_doc = "Python wrapper for a talloc-maintained object.",
	.tp_basicsize = sizeof(pytalloc_Object),
	.tp_dealloc = (destructor)pytalloc_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_repr = pytalloc_default_repr,
#if PY_MAJOR_VERSION >= 3
	.tp_richcompare = pytalloc_default_richcmp,
#else
	.tp_compare = pytalloc_default_cmp,
#endif
};

/**
 * Default (but only slightly more useful than the default) implementation of Repr().
 */
static PyObject *pytalloc_base_default_repr(PyObject *obj)
{
	pytalloc_BaseObject *talloc_obj = (pytalloc_BaseObject *)obj;
	PyTypeObject *type = (PyTypeObject*)PyObject_Type(obj);

	return PyUnicode_FromFormat("<%s talloc based object at %p>",
				type->tp_name, talloc_obj->ptr);
}

/**
 * Simple dealloc for talloc-wrapping PyObjects
 */
static void pytalloc_base_dealloc(PyObject* self)
{
	pytalloc_BaseObject *obj = (pytalloc_BaseObject *)self;
	assert(talloc_unlink(NULL, obj->talloc_ctx) != -1);
	obj->talloc_ctx = NULL;
	self->ob_type->tp_free(self);
}

/**
 * Default (but only slightly more useful than the default) implementation of cmp.
 */
#if PY_MAJOR_VERSION >= 3
static PyObject *pytalloc_base_default_richcmp(PyObject *obj1, PyObject *obj2, int op)
{
	void *ptr1;
	void *ptr2;
	if (Py_TYPE(obj1) == Py_TYPE(obj2)) {
		/* When types match, compare pointers */
		ptr1 = pytalloc_get_ptr(obj1);
		ptr2 = pytalloc_get_ptr(obj2);
	} else if (PyObject_TypeCheck(obj2, &TallocObject_Type)) {
		/* Otherwise, compare types */
		ptr1 = Py_TYPE(obj1);
		ptr2 = Py_TYPE(obj2);
	} else {
		Py_INCREF(Py_NotImplemented);
		return Py_NotImplemented;
	}
	switch (op) {
		case Py_EQ: return PyBool_FromLong(ptr1 == ptr2);
		case Py_NE: return PyBool_FromLong(ptr1 != ptr2);
		case Py_LT: return PyBool_FromLong(ptr1 < ptr2);
		case Py_GT: return PyBool_FromLong(ptr1 > ptr2);
		case Py_LE: return PyBool_FromLong(ptr1 <= ptr2);
		case Py_GE: return PyBool_FromLong(ptr1 >= ptr2);
	}
	Py_INCREF(Py_NotImplemented);
	return Py_NotImplemented;
}
#else
static int pytalloc_base_default_cmp(PyObject *_obj1, PyObject *_obj2)
{
	pytalloc_BaseObject *obj1 = (pytalloc_BaseObject *)_obj1,
					 *obj2 = (pytalloc_BaseObject *)_obj2;
	if (obj1->ob_type != obj2->ob_type)
		return ((char *)obj1->ob_type - (char *)obj2->ob_type);

	return ((char *)pytalloc_get_ptr(obj1) - (char *)pytalloc_get_ptr(obj2));
}
#endif

static PyTypeObject TallocBaseObject_Type = {
	.tp_name = "talloc.BaseObject",
	.tp_doc = "Python wrapper for a talloc-maintained object.",
	.tp_basicsize = sizeof(pytalloc_BaseObject),
	.tp_dealloc = (destructor)pytalloc_base_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_repr = pytalloc_base_default_repr,
#if PY_MAJOR_VERSION >= 3
	.tp_richcompare = pytalloc_base_default_richcmp,
#else
	.tp_compare = pytalloc_base_default_cmp,
#endif
};

static PyTypeObject TallocGenericObject_Type = {
	.tp_name = "talloc.GenericObject",
	.tp_doc = "Python wrapper for a talloc-maintained object.",
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_base = &TallocBaseObject_Type,
	.tp_basicsize = sizeof(pytalloc_BaseObject),
};

#define MODULE_DOC PyDoc_STR("Python wrapping of talloc-maintained objects.")

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    .m_name = "talloc",
    .m_doc = MODULE_DOC,
    .m_size = -1,
    .m_methods = talloc_methods,
};
#endif

static PyObject *module_init(void);
static PyObject *module_init(void)
{
	PyObject *m;

	if (PyType_Ready(&TallocObject_Type) < 0)
		return NULL;

	if (PyType_Ready(&TallocBaseObject_Type) < 0)
		return NULL;

	if (PyType_Ready(&TallocGenericObject_Type) < 0)
		return NULL;

#if PY_MAJOR_VERSION >= 3
	m = PyModule_Create(&moduledef);
#else
	m = Py_InitModule3("talloc", talloc_methods, MODULE_DOC);
#endif
	if (m == NULL)
		return NULL;

	Py_INCREF(&TallocObject_Type);
	if (PyModule_AddObject(m, "Object", (PyObject *)&TallocObject_Type)) {
		goto err;
	}
	Py_INCREF(&TallocBaseObject_Type);
	if (PyModule_AddObject(m, "BaseObject", (PyObject *)&TallocBaseObject_Type)) {
		goto err;
	}
	Py_INCREF(&TallocGenericObject_Type);
	if (PyModule_AddObject(m, "GenericObject", (PyObject *)&TallocGenericObject_Type)) {
		goto err;
	}
	return m;

err:
	Py_DECREF(m);
	return NULL;
}

#if PY_MAJOR_VERSION >= 3
PyMODINIT_FUNC PyInit_talloc(void);
PyMODINIT_FUNC PyInit_talloc(void)
{
	return module_init();
}
#else
void inittalloc(void);
void inittalloc(void)
{
	module_init();
}
#endif
