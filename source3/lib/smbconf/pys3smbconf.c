/*
 *  Unix SMB/CIFS implementation.
 *  libsmbconf - Samba configuration library - Python bindings
 *
 *  Copyright (C) John Mulligan <phlogistonjohn@asynchrono.us> 2022
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <Python.h>
#include "includes.h"
#include "python/py3compat.h"

#include "lib/smbconf/smbconf.h"
#include "source3/lib/smbconf/smbconf_reg.h"
#include "source3/lib/smbconf/smbconf_init.h"
#include "lib/smbconf/pysmbconf.h"

/*
 * The name of the other, general, smbconf module that implements
 * the common type. We import this module by name to access
 * its methods by the python API.
 */
#define SMBCONF_MOD "samba.smbconf"

/*
 * Return a new but uninitialized SMBConf python object via
 * the python API of the (other) smbconf module.
 */
static PyObject *py_new_SMBConf(PyObject * smbconf_mod)
{
	PyObject *obj = NULL;
	PyObject *method = PyObject_GetAttrString(smbconf_mod, "SMBConf");
	if (method == NULL) {
		return NULL;
	}

	obj = PyObject_CallObject(method, NULL);
	Py_CLEAR(method);
	return obj;
}

/*
 * Raise a new SMBConfError python exception given a error code.
 * This uses the python API of the (other) smbconf module.
 */
static PyObject *py_raise_SMBConfError(PyObject * smbconf_mod, sbcErr err)
{
	PyObject *obj = NULL;
	PyObject *method =
	    PyObject_GetAttrString(smbconf_mod, "_smbconf_error");
	if (method == NULL) {
		return NULL;
	}

	obj = PyObject_CallFunction(method, "i", err);
	Py_CLEAR(method);
	return obj;
}

static PyObject *py_init_reg(PyObject * module, PyObject * args)
{
	PyObject *obj = NULL;
	PyObject *smbconf_mod = NULL;
	char *path = NULL;
	struct smbconf_ctx *conf_ctx = NULL;
	TALLOC_CTX *mem_ctx = NULL;
	sbcErr err;

	/*
	 * The path here is _NOT_ the path to a file in the file
	 * system. It's a special HK registry thingy. But passing
	 * a null string to smbconf_init_reg populates it with
	 * a functional default value. So we allow the python
	 * caller to pass None and convert to NULL.
	 */
	if (!PyArg_ParseTuple(args, "z", &path)) {
		return NULL;
	}

	smbconf_mod = PyImport_ImportModule(SMBCONF_MOD);
	if (smbconf_mod == NULL) {
		return NULL;
	}

	obj = py_new_SMBConf(smbconf_mod);
	if (obj == NULL) {
		Py_CLEAR(smbconf_mod);
		return NULL;
	}

	mem_ctx = ((py_SMBConf_Object *) obj)->mem_ctx;
	err = smbconf_init_reg(mem_ctx, &conf_ctx, path);
	if (err != SBC_ERR_OK) {
		py_raise_SMBConfError(smbconf_mod, err);
		Py_CLEAR(obj);
		Py_CLEAR(smbconf_mod);
		return NULL;
	}
	((py_SMBConf_Object *) obj)->conf_ctx = conf_ctx;

	Py_DECREF(smbconf_mod);
	return obj;
}

static PyObject *py_init_str(PyObject * module, PyObject * args)
{
	PyObject *obj = NULL;
	PyObject *smbconf_mod = NULL;
	char *path = NULL;
	struct smbconf_ctx *conf_ctx = NULL;
	TALLOC_CTX *mem_ctx = NULL;
	sbcErr err;

	if (!PyArg_ParseTuple(args, "s", &path)) {
		return NULL;
	}

	smbconf_mod = PyImport_ImportModule(SMBCONF_MOD);
	if (smbconf_mod == NULL) {
		return NULL;
	}

	obj = py_new_SMBConf(smbconf_mod);
	if (obj == NULL) {
		Py_CLEAR(smbconf_mod);
		return NULL;
	}

	mem_ctx = ((py_SMBConf_Object *) obj)->mem_ctx;
	err = smbconf_init(mem_ctx, &conf_ctx, path);
	if (err != SBC_ERR_OK) {
		py_raise_SMBConfError(smbconf_mod, err);
		Py_CLEAR(obj);
		Py_CLEAR(smbconf_mod);
		return NULL;
	}
	((py_SMBConf_Object *) obj)->conf_ctx = conf_ctx;

	Py_DECREF(smbconf_mod);
	return obj;
}

PyDoc_STRVAR(py_init_reg_doc,
"Return an SMBConf object using the registry based configuration.\n"
"The path argument provided must either be None to use the\n"
"default path or a path within the registry. It must start with\n"
"the characters 'HK' if provided. It is *not* a path to a\n"
"file or database in the file system.\n");

PyDoc_STRVAR(py_init_str_doc,
"Return an SMBConf object opened using one of the backends\n"
"supported by Samba.\n"
"The provided string argument must be in the form \"backend:path\".\n"
"The backend portion is to be the name of a supported backend\n"
"such as 'file', or 'registry'. The path following the colon is\n"
"backend specific. In the case of the file backend this is the path\n"
"to a configuration file.\n"
"Examples:\n"
"    c1 = samba.samba3.smbconfig.init(\"file:/tmp/smb.conf\")\n"
"    c2 = samba.samba3.smbconfig.init(\"registry:\")\n");
/*
 * The major advantage of having this `init` function in the
 * python wrapper is that if a backend is added without
 * explicit changes to the python wrapper libs, it should still
 * be able to access that backend through the general init
 * function. The value add is not huge but more like insurance.
 */

static PyMethodDef pys3smbconf_methods[] = {
	{ "init_reg", (PyCFunction) py_init_reg, METH_VARARGS,
	 py_init_reg_doc },
	{ "init", (PyCFunction) py_init_str, METH_VARARGS,
	 py_init_str_doc },
	{ 0 },
};

PyDoc_STRVAR(py_s3smbconf_doc,
"The s3smbconf module is a wrapper for Samba's 'source3' smbconf library.\n"
"This library provides functions to use configuration backends that are\n"
"specific to the file server suite of components within Samba.\n"
"This includes functions to access the registry backend of the\n"
"smbconf subsystem. This backend is read-write.\n");

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	.m_name = "smbconf",
	.m_doc = py_s3smbconf_doc,
	.m_size = -1,
	.m_methods = pys3smbconf_methods,
};

MODULE_INIT_FUNC(smbconf)
{
	PyObject *m = PyModule_Create(&moduledef);
	if (m == NULL) {
		return NULL;
	}

	return m;
}
