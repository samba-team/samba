/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2008
   
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
#include <tevent.h>
#include <stdbool.h>
#include <../talloc/pytalloc.h>
#include <tevent_util.h>

PyAPI_DATA(PyTypeObject) PyEventContext;

static PyObject *py_set_default_backend(PyObject *self, PyObject *args)
{
    char *name;

    if (!PyArg_ParseTuple(args, "s", &name))
        return NULL;
    event_set_default_backend(name);
    return Py_None;
}

static PyObject *py_backend_list(PyObject *self)
{
    const char **backends = event_backend_list(NULL);
    PyObject *ret;
    int i, len;

    len = ev_str_list_length(backends);
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
    struct event_context *ev_ctx;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|s", (char **)kwnames, &name))
        return NULL;

    if (name == NULL)
        ev_ctx = event_context_init(NULL);
    else
        ev_ctx = event_context_init_byname(NULL, name);

    return py_talloc_import(&PyEventContext, ev_ctx);
}

static PyObject *py_event_ctx_loop_once(py_talloc_Object *self)
{
    return PyInt_FromLong(event_loop_once(self->ptr));
}

static PyObject *py_event_ctx_loop_wait(py_talloc_Object *self)
{
    return PyInt_FromLong(event_loop_wait(self->ptr));
}

static PyMethodDef py_event_ctx_methods[] = {
    { "loop_once", (PyCFunction)py_event_ctx_loop_once, METH_NOARGS, 
        "S.loop_once() -> int" },
    { "loop_wait", (PyCFunction)py_event_ctx_loop_wait, METH_NOARGS, 
        "S.loop_wait() -> int" },
    { NULL }
};

PyTypeObject PyEventContext = {
    .tp_name = "EventContext",
    .tp_methods = py_event_ctx_methods,
    .tp_basicsize = sizeof(py_talloc_Object),
    .tp_dealloc = py_talloc_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = py_event_ctx_new,
};

void inittevent(void)
{
    PyObject *m;

    if (PyType_Ready(&PyEventContext) < 0)
    	return;

    m = Py_InitModule3("tevent", tevent_methods, "Event management.");
    if (m == NULL)
        return;

    Py_INCREF(&PyEventContext);
    PyModule_AddObject(m, "EventContext", (PyObject *)&PyEventContext);
}

