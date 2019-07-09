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

#ifndef _PYTALLOC_H_
#define _PYTALLOC_H_

#include <Python.h>
#include <talloc.h>

typedef struct {
	PyObject_HEAD
	TALLOC_CTX *talloc_ctx;
	void *ptr; /* eg the array element */
} pytalloc_Object;

/* Return the PyTypeObject for pytalloc_Object. Returns a borrowed reference. */
PyTypeObject *pytalloc_GetObjectType(void);

/* Return the PyTypeObject for pytalloc_BaseObject. Returns a borrowed reference. */
PyTypeObject *pytalloc_GetBaseObjectType(void);

/* Check whether a specific object is a talloc Object. */
int pytalloc_Check(PyObject *);

int pytalloc_BaseObject_check(PyObject *);

int _pytalloc_check_type(PyObject *py_obj, const char *type_name);
#define pytalloc_check_type(py_obj, type) \
	_pytalloc_check_type((PyObject *)(py_obj), #type)

/* Retrieve the pointer for a pytalloc_object. Like talloc_get_type() 
 * but for pytalloc_Objects. */
void *_pytalloc_get_type(PyObject *py_obj, const char *type_name);
#define pytalloc_get_type(py_obj, type) ((type *)_pytalloc_get_type((PyObject *)(py_obj), #type))

void *_pytalloc_get_ptr(PyObject *py_obj);
#define pytalloc_get_ptr(py_obj) _pytalloc_get_ptr((PyObject *)(py_obj))
TALLOC_CTX *_pytalloc_get_mem_ctx(PyObject *py_obj);
#define pytalloc_get_mem_ctx(py_obj) _pytalloc_get_mem_ctx((PyObject *)(py_obj))

const char *_pytalloc_get_name(PyObject *py_obj);
#define pytalloc_get_name(py_obj) _pytalloc_get_name((PyObject *)(py_obj))


PyObject *pytalloc_steal_ex(PyTypeObject *py_type, TALLOC_CTX *mem_ctx, void *ptr);
PyObject *pytalloc_steal(PyTypeObject *py_type, void *ptr);
PyObject *pytalloc_reference_ex(PyTypeObject *py_type, TALLOC_CTX *mem_ctx, void *ptr);
#define pytalloc_reference(py_type, talloc_ptr) pytalloc_reference_ex(py_type, talloc_ptr, talloc_ptr)

#define pytalloc_new(type, typeobj) pytalloc_steal(typeobj, talloc_zero(NULL, type))

/*
 * Wrap a generic talloc pointer into a talloc.GenericObject,
 * this is a subclass of talloc.BaseObject.
 */
PyObject *pytalloc_GenericObject_steal_ex(TALLOC_CTX *mem_ctx, void *ptr);
#define pytalloc_GenericObject_steal(talloc_ptr) \
	pytalloc_GenericObject_steal_ex(talloc_ptr, talloc_ptr)
PyObject *pytalloc_GenericObject_reference_ex(TALLOC_CTX *mem_ctx, void *ptr);
#define pytalloc_GenericObject_reference(talloc_ptr) \
	pytalloc_GenericObject_reference_ex(talloc_ptr, talloc_ptr)

size_t pytalloc_BaseObject_size(void);

int pytalloc_BaseObject_PyType_Ready(PyTypeObject *type);

#endif /* _PYTALLOC_H_ */
