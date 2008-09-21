/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright © Jelmer Vernooij <jelmer@samba.org> 2008

   Implementation of the WSGI interface described in PEP0333 
   (http://www.python.org/dev/peps/pep-0333)
   
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

#include "includes.h"
#include "web_server/web_server.h"
#include <Python.h>

static PyObject *start_response(PyObject *self, PyObject *args, PyObject *kwargs)
{
	PyObject *response_header, *exc_info;
	char *status;
	const char *kwnames[] = {
		"status", "response_header", "exc_info", NULL
	};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "sOO:start_response", discard_const_p(char *, kwnames), &status, &response_header, &exc_info)) {
		return NULL;
	}

	/* FIXME: response_header, exc_info */

	/* FIXME: Wrap stdout */
	return NULL;
}

typedef struct {
	PyObject_HEAD
} error_Stream_Object;

static PyObject *py_error_flush(PyObject *self, PyObject *args, PyObject *kwargs)
{
	/* Nothing to do here */
	return Py_None;
}

static PyObject *py_error_write(PyObject *self, PyObject *args, PyObject *kwargs)
{
	const char *kwnames[] = { "str", NULL };
	char *str = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s:write", discard_const_p(char *, kwnames), &str)) {
		return NULL;
	}

	DEBUG(0, ("WSGI App: %s", str));

	return Py_None;
}

static PyObject *py_error_writelines(PyObject *self, PyObject *args, PyObject *kwargs)
{
	const char *kwnames[] = { "seq", NULL };
	PyObject *seq = NULL, *item;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O:writelines", discard_const_p(char *, kwnames), &seq)) {
		return NULL;
	}
	
	while ((item = PyIter_Next(seq))) {
		char *str = PyString_AsString(item);

		DEBUG(0, ("WSGI App: %s", str));
	}

	return Py_None;
}

static PyMethodDef error_Stream_methods[] = {
	{ "flush", (PyCFunction)py_error_flush, METH_O|METH_VARARGS|METH_KEYWORDS, NULL },
	{ "write", (PyCFunction)py_error_write, METH_O|METH_VARARGS|METH_KEYWORDS, NULL },
	{ "writelines", (PyCFunction)py_error_writelines, METH_O|METH_VARARGS|METH_KEYWORDS, NULL },
	{ NULL, NULL, 0, NULL }
};

PyTypeObject error_Stream_Type = {
	PyObject_HEAD_INIT(NULL) 0,
	.tp_name = "wsgi.ErrorStream",
	.tp_basicsize = sizeof(error_Stream_Object),
	.tp_methods = error_Stream_methods,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

typedef struct {
	PyObject_HEAD
} input_Stream_Object;

static PyObject *py_input_read(PyObject *self, PyObject *args, PyObject *kwargs)
{
	return NULL;
}

static PyObject *py_input_readline(PyObject *self, PyObject *args, PyObject *kwargs)
{
	return NULL;
}

static PyObject *py_input_readlines(PyObject *self, PyObject *args, PyObject *kwargs)
{
	return NULL;
}

static PyObject *py_input___iter__(PyObject *self, PyObject *args, PyObject *kwargs)
{
	return NULL;
}

static PyMethodDef input_Stream_methods[] = {
	{ "read", (PyCFunction)py_input_read, METH_O|METH_VARARGS|METH_KEYWORDS, NULL },
	{ "readline", (PyCFunction)py_input_readline, METH_O|METH_VARARGS|METH_KEYWORDS, NULL },
	{ "readlines", (PyCFunction)py_input_readlines, METH_O|METH_VARARGS|METH_KEYWORDS, NULL },
	{ "__iter__", (PyCFunction)py_input___iter__, METH_O|METH_VARARGS|METH_KEYWORDS, NULL },
	{ NULL, NULL, 0, NULL }
};

PyTypeObject input_Stream_Type = {
	PyObject_HEAD_INIT(NULL) 0,
	.tp_name = "wsgi.InputStream",
	.tp_basicsize = sizeof(input_Stream_Object),
	.tp_methods = input_Stream_methods,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

static PyObject *Py_InputHttpStream(void *foo)
{
	input_Stream_Object *ret = PyObject_New(input_Stream_Object, &input_Stream_Type);
	return (PyObject *)ret;
}

static PyObject *Py_ErrorHttpStream(void)
{
	error_Stream_Object *ret = PyObject_New(error_Stream_Object, &error_Stream_Type);
	return (PyObject *)ret;
}

static PyObject *create_environ(void)
{
	PyObject *env, *osmodule, *osenviron;
	PyObject *inputstream, *errorstream;

	osmodule = PyImport_ImportModule("os");	
	if (osmodule == NULL)
		return NULL;

	osenviron = PyObject_CallMethod(osmodule, "environ", NULL);

	env = PyDict_Copy(osenviron);

	Py_DECREF(env);

	inputstream = Py_InputHttpStream(NULL);
	if (inputstream == NULL) {
		Py_DECREF(env);
		return NULL;
	}

	errorstream = Py_ErrorHttpStream();
	if (errorstream == NULL) {
		Py_DECREF(env);
		Py_DECREF(inputstream);
		return NULL;
	}

	PyDict_SetItemString(env, "wsgi.input", inputstream);
	PyDict_SetItemString(env, "wsgi.errors", errorstream);
	PyDict_SetItemString(env, "wsgi.version", Py_BuildValue("(i,i)", 1, 0));
	PyDict_SetItemString(env, "wsgi.multithread", Py_False);
	PyDict_SetItemString(env, "wsgi.multiprocess", Py_True);
	PyDict_SetItemString(env, "wsgi.run_once", Py_False);

	/* FIXME: 
	PyDict_SetItemString(env, "wsgi.url_scheme", "http");
	PyDict_SetItemString(env, "wsgi.url_scheme", "https");
	*/

	return env;
}

void wsgi_process_http_input(struct websrv_context *web)
{

}
