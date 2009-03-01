/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2008

     ** NOTE! The following LGPL license applies to the tevent
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include <Python.h>

#ifndef Py_RETURN_NONE
#define Py_RETURN_NONE return Py_INCREF(Py_None), Py_None
#endif

#include <tevent.h>
#include <stdbool.h>

typedef struct {
	PyObject_HEAD
	struct tevent_context *ev_ctx;
} PyTEventContextObject;

PyAPI_DATA(PyTypeObject) PyTEventContext;

static PyObject *py_set_default_backend(PyObject *self, PyObject *args)
{
    char *name;

    if (!PyArg_ParseTuple(args, "s", &name))
        return NULL;
    tevent_set_default_backend(name);
    Py_RETURN_NONE;
}

static PyObject *py_backend_list(PyObject *self)
{
    const char **backends = tevent_backend_list(NULL);
    PyObject *ret;
    int i, len;

    for (len = 0; backends[len]; len++);

    ret = PyList_New(len);
    for (i = 0; i < len; i++)
        PyList_SetItem(ret, i, PyString_FromString(backends[i]));
    talloc_free(backends);

    return ret;
}

static PyMethodDef tevent_methods[] = {
    { "set_default_backend", (PyCFunction)py_set_default_backend, 
        METH_VARARGS, "set_default_backend(name) -> None" },
    { "backend_list", (PyCFunction)py_backend_list,
        METH_NOARGS, "backend_list() -> list" },
    { NULL },
};

static PyObject *py_event_ctx_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    const char *kwnames[] = { "name", NULL };
    char *name = NULL;
    struct tevent_context *ev_ctx;
    PyTEventContextObject *ret;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|s",
				     discard_const_p(char *, kwnames),
				     &name))
        return NULL;

    if (name == NULL)
        ev_ctx = tevent_context_init(NULL);
    else
        ev_ctx = tevent_context_init_byname(NULL, name);

    ret = (PyTEventContextObject *)type->tp_alloc(type, 0);
    ret->ev_ctx = ev_ctx;
    return (PyObject *)ret;
}

static PyObject *py_event_ctx_loop_once(PyTEventContextObject *self)
{
    return PyInt_FromLong(tevent_loop_once(self->ev_ctx));
}

static PyObject *py_event_ctx_loop_wait(PyTEventContextObject *self)
{
    return PyInt_FromLong(tevent_loop_wait(self->ev_ctx));
}

static PyMethodDef py_event_ctx_methods[] = {
    { "loop_once", (PyCFunction)py_event_ctx_loop_once, METH_NOARGS, 
        "S.loop_once() -> int" },
    { "loop_wait", (PyCFunction)py_event_ctx_loop_wait, METH_NOARGS, 
        "S.loop_wait() -> int" },
    { NULL }
};

static void py_event_ctx_dealloc(PyTEventContextObject * self)
{
	talloc_free(self->ev_ctx);
	self->ob_type->tp_free(self);
}


PyTypeObject PyTEventContext = {
    .tp_name = "TEventContext",
    .tp_methods = py_event_ctx_methods,
    .tp_basicsize = sizeof(PyTEventContextObject),
    .tp_dealloc = (destructor)py_event_ctx_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = py_event_ctx_new,
};

void inittevent(void)
{
    PyObject *m;

    if (PyType_Ready(&PyTEventContext) < 0)
    	return;

    m = Py_InitModule3("tevent", tevent_methods, "Event management.");
    if (m == NULL)
        return;

    Py_INCREF(&PyTEventContext);
    PyModule_AddObject(m, "TEventContext", (PyObject *)&PyTEventContext);
}

