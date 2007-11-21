/* 
   Unix SMB/CIFS implementation.

   Python wrapper for reading smb.conf files

   Copyright (C) Jelmer Vernooij 2007
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "scripting/python/talloc.h"
#include "Python.h"
#include "param/param.h"

staticforward PyTypeObject param_ParamFileType;

typedef struct {
	PyObject_HEAD
	struct param_context *param_ctx;
} param_ParamFileObject;

static param_ParamFileObject *py_param_init(void)
{
	param_ParamFileObject *param; 

	param = PyObject_New(param_ParamFileObject, &param_ParamFileType);

	param->param_ctx = param_init(NULL);

	return param;
}

static PyObject *py_param_load(PyObject *self, PyObject *args)
{
	char *filename = NULL;
	param_ParamFileObject *param;

	if (!PyArg_ParseTuple(args, "|s:new", &filename))
	        return NULL;

	param = py_param_init();

	if (filename != NULL) {
		int ret = param_read(param->param_ctx, filename);

		if (ret == -1) {
			PyErr_SetString(PyExc_TypeError, "reading file failed");
			return NULL;
		}
	}

	return (PyObject *)param;
}

static void
param_dealloc(PyObject* self)
{
	PyObject_Del(self);
}

static PyObject *py_param_get(PyObject *_self, PyObject *args)
{
	struct param_opt *param;
	const char *section_name = NULL, *param_name = NULL;
	param_ParamFileObject *self = (param_ParamFileObject *)_self;

	if (!PyArg_ParseTuple(args, (char *)"s|s", &param_name, &section_name))
		return NULL;

	param = param_get(self->param_ctx, section_name, param_name);
	if (param == NULL)
		return Py_None;

	return PyString_FromString(param->value);
}

static PyObject *py_param_set(PyObject *_self, PyObject *args)
{
	param_ParamFileObject *self = (param_ParamFileObject *)_self;
	const char *section_name = NULL, *param_name = NULL, *param_value = NULL;

	if (!PyArg_ParseTuple(args, "ss|s", &param_name, &param_value, &section_name))
		return NULL;

	if (section_name == NULL)
		section_name = GLOBAL_NAME;

	if (param_set_string(self->param_ctx, section_name, param_name, param_value) != 0) {
		PyErr_SetString(PyExc_TypeError, "setting variable failed");
		return NULL;
	}

	return Py_None;
}

static PyObject *py_param_save(PyObject *_self, PyObject *args)
{
	param_ParamFileObject *self = (param_ParamFileObject *)_self;
	const char *filename = NULL;

	if (!PyArg_ParseTuple(args, "s", &filename))
		return NULL;

	if (param_write(self->param_ctx, filename) != 0) {
		PyErr_SetString(PyExc_TypeError, "unable to save");
		return NULL;
	}

	return Py_None;
}

static PyObject *py_param_use(PyObject *_self, PyObject *args)
{
	param_ParamFileObject *self = (param_ParamFileObject *)_self;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	if (param_use(global_loadparm, self->param_ctx) != 0) {
		PyErr_SetString(PyExc_TypeError, "unable to use");
		return NULL;
	}

	return Py_None;
}

static PyMethodDef param_methods[] = {
	{"get", (PyCFunction)py_param_get, METH_VARARGS,
		"Get a parameter."},
	{"set", (PyCFunction)py_param_set, METH_VARARGS,
		"Set a parameter."},
	{"save", (PyCFunction)py_param_save, METH_VARARGS,
		"Save file" },
	{"use", (PyCFunction)py_param_use, METH_VARARGS,
		"Use param file" },
	{NULL, NULL, 0, NULL}
};

static PyObject *
param_getattr(PyTypeObject *obj, char *name)
{
	return Py_FindMethod(param_methods, (PyObject *)obj, name);
}

static PyTypeObject param_ParamFileType = {
	PyObject_HEAD_INIT(NULL) 0,
	.tp_name = "ParamFile",
	.tp_basicsize = sizeof(param_ParamFileObject),
	.tp_dealloc = param_dealloc,
	.tp_getattr = param_getattr,
};


static PyMethodDef methods[] = {
	{ "ParamFile", (PyCFunction)py_param_load, METH_VARARGS, NULL},
	{ NULL, NULL }
};

PyDoc_STRVAR(param_doc, "Simple wrappers around the smb.conf parsers");

PyMODINIT_FUNC initparam(void)
{
	PyObject *mod = Py_InitModule3("param", methods, param_doc);
	if (mod == NULL)
		return;

	PyModule_AddObject(mod, "configfile", 
			   PyString_FromString(lp_configfile(global_loadparm)));
}
