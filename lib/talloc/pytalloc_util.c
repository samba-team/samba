/* 
   Unix SMB/CIFS implementation.
   Python/Talloc glue
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

#include <Python.h>
#include "replace.h"
#include <talloc.h>
#include "pytalloc.h"
#include <assert.h>
#include "pytalloc_private.h"

static PyObject *pytalloc_steal_or_reference(PyTypeObject *py_type,
					 TALLOC_CTX *mem_ctx, void *ptr, bool steal);

_PUBLIC_ PyTypeObject *pytalloc_GetObjectType(void)
{
	static PyTypeObject *type = NULL;
	PyObject *mod;

	mod = PyImport_ImportModule("talloc");
	if (mod == NULL) {
		return NULL;
	}

	type = (PyTypeObject *)PyObject_GetAttrString(mod, "Object");
	Py_DECREF(mod);

	return type;
}

_PUBLIC_ PyTypeObject *pytalloc_GetBaseObjectType(void)
{
	static PyTypeObject *type = NULL;
	PyObject *mod;

	mod = PyImport_ImportModule("talloc");
	if (mod == NULL) {
		return NULL;
	}

	type = (PyTypeObject *)PyObject_GetAttrString(mod, "BaseObject");
	Py_DECREF(mod);

	return type;
}

static PyTypeObject *pytalloc_GetGenericObjectType(void)
{
	static PyTypeObject *type = NULL;
	PyObject *mod;

	mod = PyImport_ImportModule("talloc");
	if (mod == NULL) {
		return NULL;
	}

	type = (PyTypeObject *)PyObject_GetAttrString(mod, "GenericObject");
	Py_DECREF(mod);

	return type;
}

/**
 * Import an existing talloc pointer into a Python object.
 */
_PUBLIC_ PyObject *pytalloc_steal_ex(PyTypeObject *py_type, TALLOC_CTX *mem_ctx,
				     void *ptr)
{
	return pytalloc_steal_or_reference(py_type, mem_ctx, ptr, true);
}

/**
 * Import an existing talloc pointer into a Python object.
 */
_PUBLIC_ PyObject *pytalloc_steal(PyTypeObject *py_type, void *ptr)
{
	return pytalloc_steal_or_reference(py_type, ptr, ptr, true);
}


/**
 * Import an existing talloc pointer into a Python object, leaving the
 * original parent, and creating a reference to the object in the python
 * object.
 *
 * We remember the object we hold the reference to (a
 * possibly-non-talloc pointer), the existing parent (typically the
 * start of the array) and the new referenced parent.  That way we can
 * cope with the fact that we will have multiple parents, one per time
 * python sees the object.
 */
_PUBLIC_ PyObject *pytalloc_reference_ex(PyTypeObject *py_type,
					 TALLOC_CTX *mem_ctx, void *ptr)
{
	return pytalloc_steal_or_reference(py_type, mem_ctx, ptr, false);
}


/**
 * Internal function that either steals or referecences the talloc
 * pointer into a new talloc context.
 */
static PyObject *pytalloc_steal_or_reference(PyTypeObject *py_type,
					 TALLOC_CTX *mem_ctx, void *ptr, bool steal)
{
	bool ok = false;
	TALLOC_CTX *talloc_ctx = NULL;
	bool is_baseobject = false;
	PyObject *obj = NULL;
	PyTypeObject *BaseObjectType = NULL, *ObjectType = NULL;

	BaseObjectType = pytalloc_GetBaseObjectType();
	if (BaseObjectType == NULL) {
		goto err;
	}
	ObjectType = pytalloc_GetObjectType();
	if (ObjectType == NULL) {
		goto err;
	}

	/* this should have been tested by caller */
	if (mem_ctx == NULL) {
		return PyErr_NoMemory();
	}

	is_baseobject = PyType_IsSubtype(py_type, BaseObjectType);
	if (!is_baseobject) {
		if (!PyType_IsSubtype(py_type, ObjectType)) {
			PyErr_SetString(PyExc_TypeError,
				"Expected type based on talloc");
			return NULL;
		}
	}

	obj = py_type->tp_alloc(py_type, 0);
	if (obj == NULL) {
		goto err;
	}

	talloc_ctx = talloc_new(NULL);
	if (talloc_ctx == NULL) {
		PyErr_NoMemory();
		goto err;
	}

	if (steal) {
		ok = (talloc_steal(talloc_ctx, mem_ctx) != NULL);
	} else {
		ok = (talloc_reference(talloc_ctx, mem_ctx) != NULL);
	}
	if (!ok) {
		goto err;
	}
	talloc_set_name_const(talloc_ctx, py_type->tp_name);

	if (is_baseobject) {
		pytalloc_BaseObject *ret = (pytalloc_BaseObject*)obj;
		ret->talloc_ctx = talloc_ctx;
		ret->talloc_ptr_ctx = mem_ctx;
		ret->ptr = ptr;
	} else {
		pytalloc_Object *ret = (pytalloc_Object*)obj;
		ret->talloc_ctx = talloc_ctx;
		ret->ptr = ptr;
	}
	return obj;

err:
	TALLOC_FREE(talloc_ctx);
	Py_XDECREF(obj);
	return NULL;
}

/*
 * Wrap a generic talloc pointer into a talloc.GenericObject,
 * this is a subclass of talloc.BaseObject.
 */
_PUBLIC_ PyObject *pytalloc_GenericObject_steal_ex(TALLOC_CTX *mem_ctx, void *ptr)
{
	PyTypeObject *tp = pytalloc_GetGenericObjectType();
	return pytalloc_steal_ex(tp, mem_ctx, ptr);
}

/*
 * Wrap a generic talloc pointer into a talloc.GenericObject,
 * this is a subclass of talloc.BaseObject.
 */
_PUBLIC_ PyObject *pytalloc_GenericObject_reference_ex(TALLOC_CTX *mem_ctx, void *ptr)
{
	PyTypeObject *tp = pytalloc_GetGenericObjectType();
	return pytalloc_reference_ex(tp, mem_ctx, ptr);
}

_PUBLIC_ int pytalloc_Check(PyObject *obj)
{
	PyTypeObject *tp = pytalloc_GetObjectType();

	return PyObject_TypeCheck(obj, tp);
}

_PUBLIC_ int pytalloc_BaseObject_check(PyObject *obj)
{
	PyTypeObject *tp = pytalloc_GetBaseObjectType();

	return PyObject_TypeCheck(obj, tp);
}

_PUBLIC_ size_t pytalloc_BaseObject_size(void)
{
	return sizeof(pytalloc_BaseObject);
}

static void *_pytalloc_get_checked_type(PyObject *py_obj, const char *type_name,
					bool check_only, const char *function)
{
	TALLOC_CTX *mem_ctx;
	void *ptr = NULL;
	void *type_obj;

	mem_ctx = _pytalloc_get_mem_ctx(py_obj);
	ptr = _pytalloc_get_ptr(py_obj);

	if (mem_ctx != ptr || ptr == NULL) {
		if (check_only) {
			return NULL;
		}

		PyErr_Format(PyExc_TypeError, "%s: expected %s, "
			     "but the pointer is no talloc pointer, "
			     "pytalloc_get_ptr() would get the raw pointer.",
			     function, type_name);
		return NULL;
	}

	type_obj = talloc_check_name(ptr, type_name);
	if (type_obj == NULL) {
		const char *name = NULL;

		if (check_only) {
			return NULL;
		}

		name = talloc_get_name(ptr);
		PyErr_Format(PyExc_TypeError, "%s: expected %s, got %s",
			     function, type_name, name);
		return NULL;
	}

	return ptr;
}

_PUBLIC_ int _pytalloc_check_type(PyObject *py_obj, const char *type_name)
{
	void *ptr = NULL;

	ptr = _pytalloc_get_checked_type(py_obj, type_name,
					 true, /* check_only */
					 "pytalloc_check_type");
	if (ptr == NULL) {
		return 0;
	}

	return 1;
}

_PUBLIC_ void *_pytalloc_get_type(PyObject *py_obj, const char *type_name)
{
	return _pytalloc_get_checked_type(py_obj, type_name,
					  false, /* not check_only */
					  "pytalloc_get_type");
}

_PUBLIC_ void *_pytalloc_get_ptr(PyObject *py_obj)
{
	if (pytalloc_BaseObject_check(py_obj)) {
		return ((pytalloc_BaseObject *)py_obj)->ptr;
	}
	if (pytalloc_Check(py_obj)) {
		return ((pytalloc_Object *)py_obj)->ptr;
	}
	return NULL;
}

_PUBLIC_ TALLOC_CTX *_pytalloc_get_mem_ctx(PyObject *py_obj)
{
	if (pytalloc_BaseObject_check(py_obj)) {
		return ((pytalloc_BaseObject *)py_obj)->talloc_ptr_ctx;
	}
	if (pytalloc_Check(py_obj)) {
		return ((pytalloc_Object *)py_obj)->talloc_ctx;
	}
	return NULL;
}

_PUBLIC_ int pytalloc_BaseObject_PyType_Ready(PyTypeObject *type)
{
	PyTypeObject *talloc_type = pytalloc_GetBaseObjectType();
	if (talloc_type == NULL) {
		return -1;
	}

	type->tp_base = talloc_type;
	type->tp_basicsize = pytalloc_BaseObject_size();

	return PyType_Ready(type);
}

_PUBLIC_ const char *_pytalloc_get_name(PyObject *obj)
{
	void *ptr = pytalloc_get_ptr(obj);
	if (ptr == NULL) {
		return "non-talloc object";
	}
	return talloc_get_name(ptr);
}
