/*
   Unix SMB/CIFS implementation. Xattr manipulation bindings.
   Copyright (C) Matthieu Patou <mat@matws.net> 2009-2010
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
#include "system/filesys.h"
#include <tdb.h>
#include "lib/tdb_wrap/tdb_wrap.h"
#include "librpc/ndr/libndr.h"
#include "ntvfs/posix/posix_eadb.h"
#include "libcli/util/pyerrors.h"
#include "param/pyparam.h"

static PyObject *py_is_xattr_supported(PyObject *self,
			PyObject *Py_UNUSED(ignored))
{
	Py_RETURN_TRUE;
}

static PyObject *py_wrap_setxattr(PyObject *self, PyObject *args)
{
	char *filename, *attribute, *tdbname;
	DATA_BLOB blob;
	Py_ssize_t blobsize;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	struct tdb_wrap *eadb;

	if (!PyArg_ParseTuple(args, "sss"PYARG_BYTES_LEN, &tdbname, &filename, &attribute,
						  &blob.data, &blobsize))
		return NULL;

	blob.length = blobsize;
	mem_ctx = talloc_new(NULL);
	eadb = tdb_wrap_open(
		mem_ctx, tdbname, 50000,
		lpcfg_tdb_flags(py_default_loadparm_context(mem_ctx),
				TDB_DEFAULT),
		O_RDWR|O_CREAT, 0600);

	if (eadb == NULL) {
		PyErr_SetFromErrno(PyExc_IOError);
		talloc_free(mem_ctx);
		return NULL;
	}
	status = push_xattr_blob_tdb_raw(eadb, attribute, filename, -1,
					 &blob);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		talloc_free(mem_ctx);
		return NULL;
	}
	talloc_free(mem_ctx);
	Py_RETURN_NONE;
}

static PyObject *py_wrap_getxattr(PyObject *self, PyObject *args)
{
	char *filename, *attribute, *tdbname;
	TALLOC_CTX *mem_ctx;
	DATA_BLOB blob;
	PyObject *ret;
	NTSTATUS status;
	struct tdb_wrap *eadb = NULL;

	if (!PyArg_ParseTuple(args, "sss", &tdbname, &filename, &attribute))
		return NULL;

	mem_ctx = talloc_new(NULL);
	eadb = tdb_wrap_open(
		mem_ctx, tdbname, 50000,
		lpcfg_tdb_flags(py_default_loadparm_context(mem_ctx),
				TDB_DEFAULT),
		O_RDWR|O_CREAT, 0600);
	if (eadb == NULL) {
		PyErr_SetFromErrno(PyExc_IOError);
		talloc_free(mem_ctx);
		return NULL;
	}
	status = pull_xattr_blob_tdb_raw(eadb, mem_ctx, attribute, filename,
									 -1, 100, &blob);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		talloc_free(mem_ctx);
		return NULL;
	}
	ret = Py_BuildValue(PYARG_BYTES_LEN, blob.data, blob.length);
	talloc_free(mem_ctx);
	return ret;
}

static PyMethodDef py_posix_eadb_methods[] = {
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
    .m_name = "posix_eadb",
    .m_doc = "Python bindings for xattr manipulation.",
    .m_size = -1,
    .m_methods = py_posix_eadb_methods,
};

MODULE_INIT_FUNC(posix_eadb)
{
	PyObject *m;

	m = PyModule_Create(&moduledef);

	if (m == NULL)
		return NULL;

	return m;
}
