/*
   Unix SMB/CIFS implementation. Xattr manipulation bindings.
   Copyright (C) Matthieu Patou <mat@matws.net> 2009
   Base on work of pyglue.c by Jelmer Vernooij <jelmer@samba.org> 2007 and
    Matthias Dieter Wallnöfer 2009

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
#include "python/py3compat.h"
#include "includes.h"
#include "librpc/ndr/libndr.h"
#include "system/filesys.h"
#include "lib/util/base64.h"

static PyObject *py_is_xattr_supported(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
#if !defined(HAVE_XATTR_SUPPORT)
	Py_RETURN_FALSE;
#else
	Py_RETURN_TRUE;
#endif
}

static PyObject *py_wrap_setxattr(PyObject *self, PyObject *args)
{
	char *filename, *attribute;
	int ret = 0;
	Py_ssize_t blobsize;
	DATA_BLOB blob;

	if (!PyArg_ParseTuple(args, "ss"PYARG_BYTES_LEN, &filename, &attribute, &blob.data,
        &blobsize))
		return NULL;

	blob.length = blobsize;
	ret = setxattr(filename, attribute, blob.data, blob.length, 0);
	if( ret < 0 ) {
		if (errno == ENOTSUP) {
			PyErr_SetFromErrno(PyExc_IOError);
		} else {
			PyErr_SetFromErrno(PyExc_TypeError);
		}
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *py_wrap_getxattr(PyObject *self, PyObject *args)
{
	char *filename, *attribute;
	int len;
	TALLOC_CTX *mem_ctx;
	char *buf;
	PyObject *ret;
	if (!PyArg_ParseTuple(args, "ss", &filename, &attribute))
		return NULL;
	mem_ctx = talloc_new(NULL);
	len = getxattr(filename,attribute,NULL,0);
	if( len < 0 ) {
		if (errno == ENOTSUP) {
			PyErr_SetFromErrno(PyExc_IOError);
		} else {
			PyErr_SetFromErrno(PyExc_TypeError);
		}
		talloc_free(mem_ctx);
		return NULL;
	}
	/* check length ... */
	buf = talloc_zero_array(mem_ctx, char, len);
	len = getxattr(filename, attribute, buf, len);
	if( len < 0 ) {
		if (errno == ENOTSUP) {
			PyErr_SetFromErrno(PyExc_IOError);
		} else {
			PyErr_SetFromErrno(PyExc_TypeError);
		}
		talloc_free(mem_ctx);
		return NULL;
	}
	ret = Py_BuildValue(PYARG_BYTES_LEN, buf, len);
	talloc_free(mem_ctx);
	return ret;
}

static PyMethodDef py_xattr_methods[] = {
	{ "wrap_getxattr", (PyCFunction)py_wrap_getxattr, METH_VARARGS,
		"wrap_getxattr(filename,attribute) -> blob\n"
		"Retrieve given attribute on the given file." },
	{ "wrap_setxattr", (PyCFunction)py_wrap_setxattr, METH_VARARGS,
		"wrap_setxattr(filename,attribute,value)\n"
		"Set the given attribute to the given value on the given file." },
	{ "is_xattr_supported", (PyCFunction)py_is_xattr_supported, METH_NOARGS,
		"Return true if xattr are supported on this system\n"},
	{0}
};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    .m_name = "xattr_native",
    .m_doc = "Python bindings for xattr manipulation.",
    .m_size = -1,
    .m_methods = py_xattr_methods,
};

MODULE_INIT_FUNC(xattr_native)
{
	PyObject *m;

	m = PyModule_Create(&moduledef);

	if (m == NULL)
		return NULL;

	return m;
}
