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

_PUBLIC_ PyTypeObject *pytalloc_GetObjectType(void)
{
	static PyTypeObject *type = NULL;
	PyObject *mod;

	if (type != NULL) {
		return type;
	}

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

	if (type != NULL) {
		return type;
	}

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

	if (type != NULL) {
		return type;
	}

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
	PyTypeObject *BaseObjectType = pytalloc_GetBaseObjectType();
	PyTypeObject *ObjectType = pytalloc_GetObjectType();

	if (mem_ctx == NULL) {
		return PyErr_NoMemory();
	}

	if (PyType_IsSubtype(py_type, BaseObjectType)) {
		pytalloc_BaseObject *ret
			= (pytalloc_BaseObject *)py_type->tp_alloc(py_type, 0);

		ret->talloc_ctx = talloc_new(NULL);
		if (ret->talloc_ctx == NULL) {
			return NULL;
		}

		/*
		 * This allows us to keep multiple references to this object -
		 * we only reference this context, which is per ptr, not the
		 * talloc_ctx, which is per pytalloc_Object
		 */
		if (talloc_steal(ret->talloc_ctx, mem_ctx) == NULL) {
			return NULL;
		}
		ret->talloc_ptr_ctx = mem_ctx;
		talloc_set_name_const(ret->talloc_ctx, py_type->tp_name);
		ret->ptr = ptr;
		return (PyObject *)ret;

	} else if (PyType_IsSubtype(py_type, ObjectType)) {
		pytalloc_Object *ret
			= (pytalloc_Object *)py_type->tp_alloc(py_type, 0);

		ret->talloc_ctx = talloc_new(NULL);
		if (ret->talloc_ctx == NULL) {
			return NULL;
		}

		if (talloc_steal(ret->talloc_ctx, mem_ctx) == NULL) {
			return NULL;
		}
		talloc_set_name_const(ret->talloc_ctx, py_type->tp_name);
		ret->ptr = ptr;
		return (PyObject *)ret;
	} else {
		PyErr_SetString(PyExc_RuntimeError,
				"pytalloc_steal_ex() called for object type "
				"not based on talloc");
		return NULL;
	}
}

/**
 * Import an existing talloc pointer into a Python object.
 */
_PUBLIC_ PyObject *pytalloc_steal(PyTypeObject *py_type, void *ptr)
{
	return pytalloc_steal_ex(py_type, ptr, ptr);
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
	PyTypeObject *BaseObjectType = pytalloc_GetBaseObjectType();
	PyTypeObject *ObjectType = pytalloc_GetObjectType();

	if (mem_ctx == NULL) {
		return PyErr_NoMemory();
	}

	if (PyType_IsSubtype(py_type, BaseObjectType)) {
		pytalloc_BaseObject *ret
			= (pytalloc_BaseObject *)py_type->tp_alloc(py_type, 0);
		ret->talloc_ctx = talloc_new(NULL);
		if (ret->talloc_ctx == NULL) {
			return NULL;
		}
		if (talloc_reference(ret->talloc_ctx, mem_ctx) == NULL) {
			return NULL;
		}
		talloc_set_name_const(ret->talloc_ctx, py_type->tp_name);
		ret->talloc_ptr_ctx = mem_ctx;
		ret->ptr = ptr;
		return (PyObject *)ret;
	} else if (PyType_IsSubtype(py_type, ObjectType)) {
		pytalloc_Object *ret
			= (pytalloc_Object *)py_type->tp_alloc(py_type, 0);
		ret->talloc_ctx = talloc_new(NULL);
		if (ret->talloc_ctx == NULL) {
			return NULL;
		}
		if (talloc_reference(ret->talloc_ctx, mem_ctx) == NULL) {
			return NULL;
		}
		talloc_set_name_const(ret->talloc_ctx, py_type->tp_name);
		ret->ptr = ptr;
		return (PyObject *)ret;
	} else {
		PyErr_SetString(PyExc_RuntimeError,
				"pytalloc_reference_ex() called for object type "
				"not based on talloc");
		return NULL;
	}
}

#if PY_MAJOR_VERSION < 3

static void py_cobject_talloc_free(void *ptr)
{
	talloc_free(ptr);
}

_PUBLIC_ PyObject *pytalloc_CObject_FromTallocPtr(void *ptr)
{
	if (ptr == NULL) {
		Py_RETURN_NONE;
	}
	return PyCObject_FromVoidPtr(ptr, py_cobject_talloc_free);
}

#endif

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
	void *type_obj = talloc_check_name(ptr, type_name);

	mem_ctx = _pytalloc_get_mem_ctx(py_obj);
	ptr = _pytalloc_get_ptr(py_obj);

	if (mem_ctx != ptr) {
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
		PyErr_Format(PyExc_TypeError, "pytalloc: unable to get talloc.BaseObject type");
		return -1;
	}

	type->tp_base = talloc_type;
	type->tp_basicsize = pytalloc_BaseObject_size();

	return PyType_Ready(type);
}
