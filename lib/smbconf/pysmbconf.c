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
#include "lib/smbconf/smbconf_txt.h"
#include "lib/smbconf/pysmbconf.h"

static PyObject *PyExc_SMBConfError;

static void py_raise_SMBConfError(sbcErr err)
{
	PyObject *v = NULL;
	PyObject *args = NULL;

	/*
	 * TODO: have the exception type accept arguments in new/init
	 */
	args = Py_BuildValue("(is)", err, sbcErrorString(err));
	if (args == NULL) {
		PyErr_Format(PyExc_SMBConfError, "[%d]: %s", err,
			     sbcErrorString(err));
		return;
	}
	v = PyObject_Call(PyExc_SMBConfError, args, NULL);
	if (v == NULL) {
		Py_CLEAR(args);
		return;
	}
	/*
	 * It's clearer to set an explicit error_code attribute for use in calling
	 * code to check what kind of SMBConfError was raised.
	 */
	if (PyObject_SetAttrString(v, "error_code", PyTuple_GetItem(args, 0)) == -1) {
		Py_CLEAR(v);
		Py_CLEAR(args);
		return;
	}
	Py_CLEAR(args);
	PyErr_SetObject((PyObject *) Py_TYPE(v), v);
	Py_DECREF(v);
}

/*
 * py_from_smbconf_service returns a python tuple that is basically equivalent
 * to the struct smbconf_service type content-wise.
 */
static PyObject *py_from_smbconf_service(struct smbconf_service *svc)
{
	uint32_t count;
	PyObject *plist = PyList_New(svc->num_params);
	if (plist == NULL) {
		return NULL;
	}

	for (count = 0; count < svc->num_params; count++) {
		PyObject *pt = Py_BuildValue("(ss)",
					     svc->param_names[count],
					     svc->param_values[count]);
		if (pt == NULL) {
			Py_CLEAR(plist);
			return NULL;
		}
		if (PyList_SetItem(plist, count, pt) < 0) {
			Py_CLEAR(pt);
			Py_CLEAR(plist);
			return NULL;
		}
	}
	return Py_BuildValue("(sO)", svc->name, plist);
}

static PyObject *obj_new(PyTypeObject * type, PyObject * args, PyObject * kwds)
{
	py_SMBConf_Object *self = (py_SMBConf_Object *) type->tp_alloc(type, 0);
	if (self == NULL) {
		return NULL;
	}

	self->mem_ctx = talloc_new(NULL);
	if (self->mem_ctx == NULL) {
		Py_DECREF(self);
		return NULL;
	}

	return (PyObject *) self;
}

static void obj_dealloc(py_SMBConf_Object * self)
{
	if (self->conf_ctx != NULL) {
		smbconf_shutdown(self->conf_ctx);
	}
	talloc_free(self->mem_ctx);
	Py_TYPE(self)->tp_free((PyObject *) self);
}

static bool obj_ready(py_SMBConf_Object * self)
{
	if (self->conf_ctx == NULL) {
		PyErr_Format(PyExc_RuntimeError,
			     "attempt to use an uninitialized SMBConf object");
		return false;
	}
	return true;
}

static PyObject *obj_requires_messaging(py_SMBConf_Object * self,
					PyObject * Py_UNUSED(ignored))
{
	if (!obj_ready(self)) {
		return NULL;
	}
	if (smbconf_backend_requires_messaging(self->conf_ctx)) {
		Py_RETURN_TRUE;
	}
	Py_RETURN_FALSE;
}

static PyObject *obj_is_writable(py_SMBConf_Object * self,
				 PyObject * Py_UNUSED(ignored))
{
	if (!obj_ready(self)) {
		return NULL;
	}
	if (smbconf_is_writeable(self->conf_ctx)) {
		Py_RETURN_TRUE;
	}
	Py_RETURN_FALSE;
}

static PyObject *obj_share_names(py_SMBConf_Object * self,
				 PyObject * Py_UNUSED(ignored))
{
	sbcErr err;
	uint32_t count;
	uint32_t num_shares;
	char **share_names = NULL;
	PyObject *slist = NULL;
	TALLOC_CTX *mem_ctx = NULL;

	if (!obj_ready(self)) {
		return NULL;
	}

	mem_ctx = talloc_new(self->mem_ctx);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	err =
	    smbconf_get_share_names(self->conf_ctx, mem_ctx, &num_shares,
				    &share_names);
	if (err != SBC_ERR_OK) {
		talloc_free(mem_ctx);
		py_raise_SMBConfError(err);
		return NULL;
	}

	slist = PyList_New(num_shares);
	if (slist == NULL) {
		talloc_free(mem_ctx);
		return NULL;
	}
	for (count = 0; count < num_shares; count++) {
		PyObject *ustr = PyUnicode_FromString(share_names[count]);
		if (ustr == NULL) {
			Py_CLEAR(slist);
			talloc_free(mem_ctx);
			return NULL;
		}
		if (PyList_SetItem(slist, count, ustr) < 0) {
			Py_CLEAR(ustr);
			Py_CLEAR(slist);
			talloc_free(mem_ctx);
			return NULL;
		}
	}
	talloc_free(mem_ctx);
	return slist;
}

static PyObject *obj_get_share(py_SMBConf_Object * self, PyObject * args)
{
	sbcErr err;
	char *servicename = NULL;
	struct smbconf_service *svc = NULL;
	PyObject *plist = NULL;
	TALLOC_CTX *mem_ctx = NULL;

	if (!PyArg_ParseTuple(args, "s", &servicename)) {
		return NULL;
	}

	if (!obj_ready(self)) {
		return NULL;
	}

	mem_ctx = talloc_new(self->mem_ctx);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	err = smbconf_get_share(self->conf_ctx, mem_ctx, servicename, &svc);
	if (err != SBC_ERR_OK) {
		talloc_free(mem_ctx);
		py_raise_SMBConfError(err);
		return NULL;
	}
	/*
	 * if py_from_smbconf_service returns NULL, then an exception should
	 * already be set. No special error handling needed.
	 */
	plist = py_from_smbconf_service(svc);
	talloc_free(mem_ctx);
	return plist;
}

static PyObject *obj_get_config(py_SMBConf_Object * self,
				PyObject * Py_UNUSED(ignored))
{
	sbcErr err;
	PyObject *svclist = NULL;
	TALLOC_CTX *mem_ctx = NULL;
	uint32_t count;
	uint32_t num_shares;
	struct smbconf_service **svcs = NULL;

	if (!obj_ready(self)) {
		return NULL;
	}

	mem_ctx = talloc_new(self->mem_ctx);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	err = smbconf_get_config(self->conf_ctx, mem_ctx, &num_shares, &svcs);
	if (err != SBC_ERR_OK) {
		talloc_free(mem_ctx);
		py_raise_SMBConfError(err);
		return NULL;
	}

	svclist = PyList_New(num_shares);
	if (svclist == NULL) {
		talloc_free(mem_ctx);
		return NULL;
	}
	for (count = 0; count < num_shares; count++) {
		PyObject *svcobj = py_from_smbconf_service(svcs[count]);
		if (svcobj == NULL) {
			Py_CLEAR(svclist);
			talloc_free(mem_ctx);
			return NULL;
		}
		if (PyList_SetItem(svclist, count, svcobj) < 0) {
			Py_CLEAR(svcobj);
			Py_CLEAR(svclist);
			talloc_free(mem_ctx);
			return NULL;
		}
	}

	talloc_free(mem_ctx);
	return svclist;
}

static PyObject *obj_create_share(py_SMBConf_Object * self, PyObject * args)
{
	sbcErr err;
	char *servicename = NULL;

	if (!PyArg_ParseTuple(args, "s", &servicename)) {
		return NULL;
	}

	err = smbconf_create_share(self->conf_ctx, servicename);
	if (err != SBC_ERR_OK) {
		py_raise_SMBConfError(err);
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *obj_drop(py_SMBConf_Object * self,
			  PyObject * Py_UNUSED(ignored))
{
	sbcErr err;

	err = smbconf_drop(self->conf_ctx);
	if (err != SBC_ERR_OK) {
		py_raise_SMBConfError(err);
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *obj_set_parameter(py_SMBConf_Object * self, PyObject * args)
{
	sbcErr err;
	char *servicename = NULL;
	char *param = NULL;
	char *val = NULL;

	if (!PyArg_ParseTuple(args, "sss", &servicename, &param, &val)) {
		return NULL;
	}

	err = smbconf_set_parameter(self->conf_ctx, servicename, param, val);
	if (err != SBC_ERR_OK) {
		py_raise_SMBConfError(err);
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *obj_set_global_parameter(py_SMBConf_Object * self,
					  PyObject * args)
{
	sbcErr err;
	char *param = NULL;
	char *val = NULL;

	if (!PyArg_ParseTuple(args, "ss", &param, &val)) {
		return NULL;
	}

	err = smbconf_set_global_parameter(self->conf_ctx, param, val);
	if (err != SBC_ERR_OK) {
		py_raise_SMBConfError(err);
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *obj_delete_share(py_SMBConf_Object * self, PyObject * args)
{
	sbcErr err;
	char *servicename = NULL;

	if (!PyArg_ParseTuple(args, "s", &servicename)) {
		return NULL;
	}

	err = smbconf_delete_share(self->conf_ctx, servicename);
	if (err != SBC_ERR_OK) {
		py_raise_SMBConfError(err);
		return NULL;
	}
	Py_RETURN_NONE;
}

static char *py_get_kv_str(TALLOC_CTX * mem_ctx, PyObject * obj, Py_ssize_t idx)
{
	char *ss = NULL;
	PyObject *pystr = PySequence_GetItem(obj, idx);
	if (pystr == NULL) {
		return NULL;
	}
	if (!PyUnicode_Check(pystr)) {
		PyErr_SetString(PyExc_TypeError, "keys/values expect a str");
		Py_CLEAR(pystr);
		return NULL;
	}
	ss = talloc_strdup(mem_ctx, PyUnicode_AsUTF8(pystr));
	Py_CLEAR(pystr);
	return ss;
}

static PyObject *obj_create_set_share(py_SMBConf_Object * self, PyObject * args)
{
	sbcErr err;
	char *servicename = NULL;
	PyObject *kvs = NULL;
	Py_ssize_t size, idx;
	struct smbconf_service *tmp_service = NULL;
	TALLOC_CTX *tmp_ctx = talloc_new(self->mem_ctx);

	if (!PyArg_ParseTuple(args, "sO", &servicename, &kvs)) {
		talloc_free(tmp_ctx);
		return NULL;
	}

	if (PySequence_Check(kvs) == 0) {
		PyErr_SetString(PyExc_TypeError,
				"a sequence object is required");
		talloc_free(tmp_ctx);
		return NULL;
	}

	size = PySequence_Size(kvs);
	if (size == -1) {
		PyErr_SetString(PyExc_ValueError, "failed to get size");
		talloc_free(tmp_ctx);
		return NULL;
	}

	tmp_service = talloc_zero(tmp_ctx, struct smbconf_service);
	if (tmp_service == NULL) {
		PyErr_NoMemory();
		talloc_free(tmp_ctx);
		return NULL;
	}

	tmp_service->name = talloc_strdup(tmp_service, servicename);
	if (tmp_service->name == NULL) {
		PyErr_NoMemory();
		talloc_free(tmp_ctx);
		return NULL;
	}
	tmp_service->num_params = (uint32_t) size;
	tmp_service->param_names = talloc_array(tmp_ctx, char *, size);
	if (tmp_service->param_names == NULL) {
		PyErr_NoMemory();
		talloc_free(tmp_ctx);
		return NULL;
	}
	tmp_service->param_values = talloc_array(tmp_ctx, char *, size);
	if (tmp_service->param_values == NULL) {
		PyErr_NoMemory();
		talloc_free(tmp_ctx);
		return NULL;
	}

	for (idx = 0; idx < size; idx++) {
		char *tmp_str = NULL;
		PyObject *tmp_pair = PySequence_GetItem(kvs, idx);
		if (tmp_pair == NULL) {
			talloc_free(tmp_ctx);
			return NULL;
		}
		if (PySequence_Size(tmp_pair) != 2) {
			PyErr_SetString(PyExc_ValueError,
					"expecting two-item tuples");
			Py_CLEAR(tmp_pair);
			talloc_free(tmp_ctx);
			return NULL;
		}

		/* fetch key */
		tmp_str = py_get_kv_str(tmp_ctx, tmp_pair, 0);
		if (tmp_str == NULL) {
			Py_CLEAR(tmp_pair);
			talloc_free(tmp_ctx);
			return NULL;
		}
		tmp_service->param_names[idx] = tmp_str;

		/* fetch value */
		tmp_str = py_get_kv_str(tmp_ctx, tmp_pair, 1);
		if (tmp_str == NULL) {
			Py_CLEAR(tmp_pair);
			talloc_free(tmp_ctx);
			return NULL;
		}
		tmp_service->param_values[idx] = tmp_str;

		Py_CLEAR(tmp_pair);
	}

	err = smbconf_create_set_share(self->conf_ctx, tmp_service);
	if (err != SBC_ERR_OK) {
		py_raise_SMBConfError(err);
		talloc_free(tmp_ctx);
		return NULL;
	}
	talloc_free(tmp_ctx);
	Py_RETURN_NONE;
}

static PyObject *obj_delete_parameter(py_SMBConf_Object * self, PyObject * args)
{
	sbcErr err;
	char *servicename = NULL;
	char *param_name = NULL;

	if (!PyArg_ParseTuple(args, "ss", &servicename, &param_name)) {
		return NULL;
	}

	err = smbconf_delete_parameter(self->conf_ctx, servicename, param_name);
	if (err != SBC_ERR_OK) {
		py_raise_SMBConfError(err);
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *obj_delete_global_parameter(py_SMBConf_Object * self,
					     PyObject * args)
{
	sbcErr err;
	char *param_name = NULL;

	if (!PyArg_ParseTuple(args, "s", &param_name)) {
		return NULL;
	}

	err = smbconf_delete_global_parameter(self->conf_ctx, param_name);
	if (err != SBC_ERR_OK) {
		py_raise_SMBConfError(err);
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *obj_transaction_start(py_SMBConf_Object * self,
				       PyObject * Py_UNUSED(ignored))
{
	sbcErr err = smbconf_transaction_start(self->conf_ctx);
	if (err != SBC_ERR_OK) {
		py_raise_SMBConfError(err);
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *obj_transaction_commit(py_SMBConf_Object * self,
					PyObject * Py_UNUSED(ignored))
{
	sbcErr err = smbconf_transaction_commit(self->conf_ctx);
	if (err != SBC_ERR_OK) {
		py_raise_SMBConfError(err);
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *obj_transaction_cancel(py_SMBConf_Object * self,
					PyObject * Py_UNUSED(ignored))
{
	sbcErr err = smbconf_transaction_cancel(self->conf_ctx);
	if (err != SBC_ERR_OK) {
		py_raise_SMBConfError(err);
		return NULL;
	}
	Py_RETURN_NONE;
}

PyDoc_STRVAR(obj_requires_messaging_doc,
"requires_messaging() -> bool\n"
"\n"
"Returns true if the backend requires interprocess messaging.\n");

PyDoc_STRVAR(obj_is_writable_doc,
"is_writeable() -> bool\n"
"\n"
"Returns true if the SMBConf object's backend is writable.\n");

PyDoc_STRVAR(obj_share_names_doc,
"share_names() -> list[str]\n"
"\n"
"Return a list of the share names currently configured.\n"
"Includes the global section as a share name.\n");

PyDoc_STRVAR(obj_get_share_doc,
"get_share() -> (str, list[(str, str)])\n"
"\n"
"Given the name of a share, return a tuple of \n"
"(share_name, share_parms) where share_params is a list of\n"
"(param_name, param_value) tuples.\n"
"The term global can be specified to get global section parameters.\n");

PyDoc_STRVAR(obj_get_config_doc,
"get_config() -> list[(str, list[(str, str)])]\n"
"Return a list of tuples for every section/share of the current\n"
"configuration. Each tuple in the list is the same as described\n"
"for get_share().\n");

PyDoc_STRVAR(obj_create_share_doc,
"create_share(name: str) -> None\n"
"Create a new empty share in the configuration. The share\n"
"name must not exist or an error will be raised.\n");

PyDoc_STRVAR(obj_drop_doc,
"drop() -> None\n"
"Drop the entire configuration, resetting it to an empty state.\n");

PyDoc_STRVAR(obj_set_parameter_doc,
"set_parameter(str, str, str) -> None\n"
"Set a configuration parmeter. Specify service name, parameter name,\n"
"and parameter value.\n");

PyDoc_STRVAR(obj_set_global_parameter_doc,
"set_global_parameter(str, str) -> None\n"
"Set a global configuration parmeter. Specify the parameter name\n"
"and parameter value.\n");

PyDoc_STRVAR(obj_delete_share_doc,
"delete_share(str) -> None\n"
"Delete a service from the configuration.\n");

PyDoc_STRVAR(obj_create_set_share_doc,
"create_set_share(str, [(str, str)...]) -> None\n"
"Create and set the definition of a service.\n");

PyDoc_STRVAR(obj_delete_parameter_doc,
"delete_parameter(str, str) -> None\n"
"Delete a single configuration parameter.\n");

PyDoc_STRVAR(obj_delete_global_parameter_doc,
"delete_parameter(str, str) -> None\n"
"Delete a single global configuration parameter.\n");

PyDoc_STRVAR(obj_transaction_start_doc,
"transaction_start() -> None\n"
"Start a transaction.\n"
"Transactions allow making compound sets of changes atomically.\n");

PyDoc_STRVAR(obj_transaction_commit_doc,
"transaction_commit() -> None\n"
"Commit the transaction.\n");

PyDoc_STRVAR(obj_transaction_cancel_doc,
"transaction_cancel() -> None\n"
"Cancel the transaction.\n");

static PyMethodDef py_smbconf_obj_methods[] = {
	{ "requires_messaging", (PyCFunction) obj_requires_messaging,
	 METH_NOARGS, obj_requires_messaging_doc },
	{ "is_writeable", (PyCFunction) obj_is_writable, METH_NOARGS,
	 obj_is_writable_doc },
	{ "share_names", (PyCFunction) obj_share_names, METH_NOARGS,
	 obj_share_names_doc },
	{ "get_share", (PyCFunction) obj_get_share, METH_VARARGS,
	 obj_get_share_doc },
	{ "get_config", (PyCFunction) obj_get_config, METH_NOARGS,
	 obj_get_config_doc },
	{ "create_share", (PyCFunction) obj_create_share, METH_VARARGS,
	 obj_create_share_doc },
	{ "create_set_share", (PyCFunction) obj_create_set_share, METH_VARARGS,
	 obj_create_set_share_doc },
	{ "drop", (PyCFunction) obj_drop, METH_NOARGS,
	 obj_drop_doc },
	{ "set_parameter", (PyCFunction) obj_set_parameter, METH_VARARGS,
	 obj_set_parameter_doc },
	{ "set_global_parameter", (PyCFunction) obj_set_global_parameter,
	 METH_VARARGS, obj_set_global_parameter_doc },
	{ "delete_share", (PyCFunction) obj_delete_share, METH_VARARGS,
	 obj_delete_share_doc },
	{ "delete_parameter", (PyCFunction) obj_delete_parameter, METH_VARARGS,
	 obj_delete_parameter_doc },
	{ "delete_global_parameter", (PyCFunction) obj_delete_global_parameter,
	 METH_VARARGS, obj_delete_global_parameter_doc },
	{ "transaction_start", (PyCFunction) obj_transaction_start, METH_NOARGS,
	 obj_transaction_start_doc },
	{ "transaction_commit", (PyCFunction) obj_transaction_commit,
	 METH_NOARGS, obj_transaction_commit_doc },
	{ "transaction_cancel", (PyCFunction) obj_transaction_cancel,
	 METH_NOARGS, obj_transaction_cancel_doc },
	{ 0 },
};

PyDoc_STRVAR(py_SMBConf_type_doc,
"SMBConf objects provide uniform access to Samba configuration backends.\n"
"\n"
"The SMBConf type should not be instantiated directly. Rather, use a\n"
"backend specific init function like init_txt.\n");

static PyTypeObject py_SMBConf_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "smbconf.SMBConf",
	.tp_doc = py_SMBConf_type_doc,
	.tp_basicsize = sizeof(py_SMBConf_Object),
	.tp_methods = py_smbconf_obj_methods,
	.tp_new = obj_new,
	.tp_dealloc = (destructor) obj_dealloc,
};

static PyObject *py_init_txt(PyObject * module, PyObject * args)
{
	py_SMBConf_Object *obj;
	sbcErr err;
	char *path = NULL;
	struct smbconf_ctx *conf_ctx = NULL;

	if (!PyArg_ParseTuple(args, "s", &path)) {
		return NULL;
	}

	obj = (py_SMBConf_Object *) obj_new(&py_SMBConf_Type, NULL, NULL);
	if (obj == NULL) {
		return NULL;
	}

	err = smbconf_init_txt(obj->mem_ctx, &conf_ctx, path);
	if (err != SBC_ERR_OK) {
		Py_DECREF(obj);
		py_raise_SMBConfError(err);
		return NULL;
	}
	obj->conf_ctx = conf_ctx;
	return (PyObject *) obj;
}

static PyObject *py_smbconf_error(PyObject * module, PyObject * args)
{
	sbcErr errcode;

	if (!PyArg_ParseTuple(args, "i", &errcode)) {
		return NULL;
	}

	/* this always raises an exception. it doesn't return the exception. */
	py_raise_SMBConfError(errcode);
	return NULL;
}

static PyMethodDef pysmbconf_methods[] = {
	{ "init_txt", (PyCFunction) py_init_txt, METH_VARARGS,
	 "Return an SMBConf object for the given text config file." },
	{ "_smbconf_error", (PyCFunction) py_smbconf_error, METH_VARARGS,
	 "Raise an SMBConfError based on the given error code." },
	{ 0 },
};

PyDoc_STRVAR(py_smbconf_doc,
"The smbconf module is a wrapper for Samba's smbconf library.\n"
"This library supports common functions to access the contents\n"
"of a configuration backend, such as the text-based smb.conf file\n"
"or the read-write registry backend.\n"
"The read-only functions on the SMBConf type function on both backend\n"
"types. Future, write based functions need a writable backend (registry).\n"
"\n"
"Note that the registry backend will be provided by a different\n"
"library module from the source3 tree (implementation TBD).\n");

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	.m_name = "smbconf",
	.m_doc = py_smbconf_doc,
	.m_size = -1,
	.m_methods = pysmbconf_methods,
};

MODULE_INIT_FUNC(smbconf)
{
	PyObject *m = PyModule_Create(&moduledef);
	if (m == NULL) {
		return NULL;
	}

	if (PyType_Ready(&py_SMBConf_Type) < 0) {
		Py_DECREF(m);
		return NULL;
	}
	Py_INCREF(&py_SMBConf_Type);
	if (PyModule_AddObject(m, "SMBConf", (PyObject *) & py_SMBConf_Type) <
	    0) {
		Py_DECREF(&py_SMBConf_Type);
		Py_DECREF(m);
		return NULL;
	}

	PyExc_SMBConfError =
	    PyErr_NewException(discard_const_p(char, "smbconf.SMBConfError"),
			       NULL, NULL);
	if (PyExc_SMBConfError == NULL) {
		Py_DECREF(m);
		return NULL;
	}
	Py_INCREF(PyExc_SMBConfError);
	if (PyModule_AddObject(m, "SMBConfError", PyExc_SMBConfError) < 0) {
		Py_DECREF(PyExc_SMBConfError);
		Py_DECREF(m);
		return NULL;
	}

/*
 * ADD_FLAGS macro borrowed from source3/libsmb/pylibsmb.c
 */
#define ADD_FLAGS(val)	PyModule_AddObject(m, #val, PyLong_FromLong(val))

	ADD_FLAGS(SBC_ERR_OK);
	ADD_FLAGS(SBC_ERR_NOT_IMPLEMENTED);
	ADD_FLAGS(SBC_ERR_NOT_SUPPORTED);
	ADD_FLAGS(SBC_ERR_UNKNOWN_FAILURE);
	ADD_FLAGS(SBC_ERR_NOMEM);
	ADD_FLAGS(SBC_ERR_INVALID_PARAM);
	ADD_FLAGS(SBC_ERR_BADFILE);
	ADD_FLAGS(SBC_ERR_NO_SUCH_SERVICE);
	ADD_FLAGS(SBC_ERR_IO_FAILURE);
	ADD_FLAGS(SBC_ERR_CAN_NOT_COMPLETE);
	ADD_FLAGS(SBC_ERR_NO_MORE_ITEMS);
	ADD_FLAGS(SBC_ERR_FILE_EXISTS);
	ADD_FLAGS(SBC_ERR_ACCESS_DENIED);

	return m;
}
