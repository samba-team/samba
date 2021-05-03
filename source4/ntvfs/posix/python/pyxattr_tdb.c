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
#include "lib/dbwrap/dbwrap.h"
#include "lib/dbwrap/dbwrap_open.h"
#include "lib/dbwrap/dbwrap_tdb.h"
#include "source3/lib/xattr_tdb.h"

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
	int ret;
	TALLOC_CTX *mem_ctx;
	struct loadparm_context *lp_ctx;
	struct db_context *eadb = NULL;
	struct file_id id;
	struct stat sbuf;

	if (!PyArg_ParseTuple(args, "sss"PYARG_BYTES_LEN, &tdbname, &filename, &attribute,
						  &blob.data, &blobsize))
		return NULL;

	blob.length = blobsize;
	mem_ctx = talloc_new(NULL);

	lp_ctx = py_default_loadparm_context(mem_ctx);
	eadb = db_open_tdb(mem_ctx, tdbname, 50000,
			   lpcfg_tdb_flags(lp_ctx, TDB_DEFAULT),
			   O_RDWR|O_CREAT, 0600, DBWRAP_LOCK_ORDER_2,
			   DBWRAP_FLAG_NONE);

	if (eadb == NULL) {
		PyErr_SetFromErrno(PyExc_IOError);
		talloc_free(mem_ctx);
		return NULL;
	}

	ret = stat(filename, &sbuf);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_IOError);
		talloc_free(mem_ctx);
		return NULL;
	}

	ZERO_STRUCT(id);
	id.devid = sbuf.st_dev;
	id.inode = sbuf.st_ino;

	ret = xattr_tdb_setattr(eadb, &id, attribute, blob.data, blob.length, 0);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_TypeError);
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
	struct loadparm_context *lp_ctx;
	DATA_BLOB blob;
	PyObject *ret_obj;
	int ret;
	ssize_t xattr_size;
	struct db_context *eadb = NULL;
	struct file_id id;
	struct stat sbuf;

	if (!PyArg_ParseTuple(args, "sss", &tdbname, &filename, &attribute))
		return NULL;

	mem_ctx = talloc_new(NULL);

	lp_ctx = py_default_loadparm_context(mem_ctx);
	eadb = db_open_tdb(mem_ctx, tdbname, 50000,
			   lpcfg_tdb_flags(lp_ctx, TDB_DEFAULT),
			   O_RDWR|O_CREAT, 0600, DBWRAP_LOCK_ORDER_2,
			   DBWRAP_FLAG_NONE);

	if (eadb == NULL) {
		PyErr_SetFromErrno(PyExc_IOError);
		talloc_free(mem_ctx);
		return NULL;
	}

	ret = stat(filename, &sbuf);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_IOError);
		talloc_free(mem_ctx);
		return NULL;
	}

	ZERO_STRUCT(id);
	id.devid = sbuf.st_dev;
	id.inode = sbuf.st_ino;

	xattr_size = xattr_tdb_getattr(eadb, mem_ctx, &id, attribute, &blob);
	if (xattr_size < 0) {
		PyErr_SetFromErrno(PyExc_TypeError);
		talloc_free(mem_ctx);
		return NULL;
	}
	ret_obj = Py_BuildValue(PYARG_BYTES_LEN, blob.data, xattr_size);
	talloc_free(mem_ctx);
	return ret_obj;
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
    .m_name = "xattr_tdb",
    .m_doc = "Python bindings for xattr manipulation.",
    .m_size = -1,
    .m_methods = py_xattr_methods,
};

MODULE_INIT_FUNC(xattr_tdb)
{
	PyObject *m;

	m = PyModule_Create(&moduledef);

	if (m == NULL)
		return NULL;

	return m;
}

