/*
 * Unix SMB/CIFS implementation.
 * Copyright (C) Volker Lendecke 2022
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <Python.h>
#include "replace.h"
#include "python/modules.h"
#include "python/py3compat.h"
#include "reparse_symlink.h"

static PyObject *py_reparse_put(PyObject *module, PyObject *args)
{
	char *reparse = NULL;
	Py_ssize_t reparse_len;
	unsigned long long tag = 0;
	unsigned reserved = 0;
	struct iovec iov;
	uint8_t *buf = NULL;
	ssize_t buflen;
	PyObject *result = NULL;
	bool ok;

	ok = PyArg_ParseTuple(
		args,
		"Kk"PYARG_BYTES_LEN":put",
		&tag,
		&reserved,
		&reparse,
		&reparse_len);
	if (!ok) {
		return NULL;
	}
	iov = (struct iovec) {
		.iov_base = reparse, .iov_len = reparse_len,
	};

	buflen = reparse_buffer_marshall(tag, reserved, &iov, 1, NULL, 0);
	if (buflen == -1) {
		errno = EINVAL;
		PyErr_SetFromErrno(PyExc_RuntimeError);
		return NULL;
	}
	buf = talloc_array(NULL, uint8_t, buflen);
	if (buf == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	reparse_buffer_marshall(tag, reserved, &iov, 1, buf, buflen);

	result = PyBytes_FromStringAndSize((char *)buf, buflen);
	TALLOC_FREE(buf);
	return result;
}

static PyObject *py_reparse_symlink_put(PyObject *module, PyObject *args)
{
	char *substitute = NULL;
	char *printname = NULL;
	int unparsed = 0;
	int flags = 0;
	uint8_t *buf = NULL;
	size_t buflen;
	PyObject *result = NULL;
	bool ok;

	ok = PyArg_ParseTuple(
		args,
		"ssii:symlink_put",
		&substitute,
		&printname,
		&unparsed,
		&flags);
	if (!ok) {
		return NULL;
	}

	ok = symlink_reparse_buffer_marshall(
		substitute, printname, unparsed, flags, NULL, &buf, &buflen);
	if (!ok) {
		PyErr_NoMemory();
		return false;
	}

	result = PyBytes_FromStringAndSize((char *)buf, buflen);
	TALLOC_FREE(buf);
	return result;
}

static PyObject *py_reparse_symlink_get(PyObject *module, PyObject *args)
{
	char *buf = NULL;
	Py_ssize_t buflen;
	struct symlink_reparse_struct *syml = NULL;
	PyObject *result = NULL;
	bool ok;

	ok = PyArg_ParseTuple(args, PYARG_BYTES_LEN ":get", &buf, &buflen);
	if (!ok) {
		return NULL;
	}

	syml = symlink_reparse_buffer_parse(NULL, (uint8_t *)buf, buflen);
	if (syml == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	result = Py_BuildValue(
		"ssII",
		syml->substitute_name,
		syml->print_name,
		(unsigned)syml->unparsed_path_length,
		(unsigned)syml->flags);
	TALLOC_FREE(syml);
	return result;
}

static PyMethodDef py_reparse_symlink_methods[] = {
	{ "put",
	  PY_DISCARD_FUNC_SIG(PyCFunction, py_reparse_put),
	  METH_VARARGS,
	  "Create a reparse point blob"},
	{ "symlink_put",
	  PY_DISCARD_FUNC_SIG(PyCFunction, py_reparse_symlink_put),
	  METH_VARARGS,
	  "Create a reparse symlink blob"},
	{ "symlink_get",
	  PY_DISCARD_FUNC_SIG(PyCFunction, py_reparse_symlink_get),
	  METH_VARARGS,
	  "Parse a reparse symlink blob"},
	{0},
};

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	.m_name = "reparse_symlink",
	.m_doc = "[un]marshall reparse symlink blobs",
	.m_size = -1,
	.m_methods = py_reparse_symlink_methods,
};

MODULE_INIT_FUNC(reparse_symlink)
{
	PyObject *m;

	m = PyModule_Create(&moduledef);
	if (m == NULL)
		return NULL;

	return m;
}
