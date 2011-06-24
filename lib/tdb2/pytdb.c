/*
   Unix SMB/CIFS implementation.

   Python interface to tdb2.  Simply modified from tdb1 version.

   Copyright (C) 2004-2006 Tim Potter <tpot@samba.org>
   Copyright (C) 2007-2008 Jelmer Vernooij <jelmer@samba.org>
   Copyright (C) 2011 Rusty Russell <rusty@rustcorp.com.au>

     ** NOTE! The following LGPL license applies to the tdb
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

#include <Python.h>
#include "replace.h"
#include "system/filesys.h"

#ifndef Py_RETURN_NONE
#define Py_RETURN_NONE return Py_INCREF(Py_None), Py_None
#endif

/* Include tdb headers */
#include <tdb2.h>

typedef struct {
	PyObject_HEAD
	struct tdb_context *ctx;
	bool closed;
} PyTdbObject;

staticforward PyTypeObject PyTdb;

static void PyErr_SetTDBError(enum TDB_ERROR e)
{
	PyErr_SetObject(PyExc_RuntimeError,
		Py_BuildValue("(i,s)", e, tdb_errorstr(e)));
}

static TDB_DATA PyString_AsTDB_DATA(PyObject *data)
{
	TDB_DATA ret;
	ret.dptr = (unsigned char *)PyString_AsString(data);
	ret.dsize = PyString_Size(data);
	return ret;
}

static PyObject *PyString_FromTDB_DATA(TDB_DATA data)
{
	PyObject *ret = PyString_FromStringAndSize((const char *)data.dptr,
						   data.dsize);
	free(data.dptr);
	return ret;
}

#define PyErr_TDB_ERROR_IS_ERR_RAISE(ret) \
	if (ret != TDB_SUCCESS) { \
		PyErr_SetTDBError(ret); \
		return NULL; \
	}

static void stderr_log(struct tdb_context *tdb,
		       enum tdb_log_level level,
		       const char *message,
		       void *data)
{
	fprintf(stderr, "%s:%s\n", tdb_name(tdb), message);
}

static PyObject *py_tdb_open(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	char *name = NULL;
	int tdb_flags = TDB_DEFAULT, flags = O_RDWR, mode = 0600;
	struct tdb_context *ctx;
	PyTdbObject *ret;
	union tdb_attribute logattr;
	const char *kwnames[] = { "name", "tdb_flags", "flags", "mode", NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|siii", (char **)kwnames, &name, &tdb_flags, &flags, &mode))
		return NULL;

	if (name == NULL) {
		tdb_flags |= TDB_INTERNAL;
	}

	logattr.log.base.attr = TDB_ATTRIBUTE_LOG;
	logattr.log.base.next = NULL;
	logattr.log.fn = stderr_log;
	ctx = tdb_open(name, tdb_flags, flags, mode, &logattr);
	if (ctx == NULL) {
		PyErr_SetFromErrno(PyExc_IOError);
		return NULL;
	}

	ret = PyObject_New(PyTdbObject, &PyTdb);
	if (!ret) {
		tdb_close(ctx);
		return NULL;
	}

	ret->ctx = ctx;
	ret->closed = false;
	return (PyObject *)ret;
}

static PyObject *obj_transaction_cancel(PyTdbObject *self)
{
	tdb_transaction_cancel(self->ctx);
	Py_RETURN_NONE;
}

static PyObject *obj_transaction_commit(PyTdbObject *self)
{
	enum TDB_ERROR ret = tdb_transaction_commit(self->ctx);
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret);
	Py_RETURN_NONE;
}

static PyObject *obj_transaction_prepare_commit(PyTdbObject *self)
{
	enum TDB_ERROR ret = tdb_transaction_prepare_commit(self->ctx);
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret);
	Py_RETURN_NONE;
}

static PyObject *obj_transaction_start(PyTdbObject *self)
{
	enum TDB_ERROR ret = tdb_transaction_start(self->ctx);
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret);
	Py_RETURN_NONE;
}

static PyObject *obj_lockall(PyTdbObject *self)
{
	enum TDB_ERROR ret = tdb_lockall(self->ctx);
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret);
	Py_RETURN_NONE;
}

static PyObject *obj_unlockall(PyTdbObject *self)
{
	tdb_unlockall(self->ctx);
	Py_RETURN_NONE;
}

static PyObject *obj_lockall_read(PyTdbObject *self)
{
	enum TDB_ERROR ret = tdb_lockall_read(self->ctx);
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret);
	Py_RETURN_NONE;
}

static PyObject *obj_unlockall_read(PyTdbObject *self)
{
	tdb_unlockall_read(self->ctx);
	Py_RETURN_NONE;
}

static PyObject *obj_close(PyTdbObject *self)
{
	enum TDB_ERROR ret;
	if (self->closed)
		Py_RETURN_NONE;
	ret = tdb_close(self->ctx);
	self->closed = true;
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret);
	Py_RETURN_NONE;
}

static PyObject *obj_get(PyTdbObject *self, PyObject *args)
{
	TDB_DATA key, data;
	PyObject *py_key;
	enum TDB_ERROR ret;
	if (!PyArg_ParseTuple(args, "O", &py_key))
		return NULL;

	key = PyString_AsTDB_DATA(py_key);
	ret = tdb_fetch(self->ctx, key, &data);
	if (ret == TDB_ERR_NOEXIST)
		Py_RETURN_NONE;
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret);
	return PyString_FromTDB_DATA(data);
}

static PyObject *obj_append(PyTdbObject *self, PyObject *args)
{
	TDB_DATA key, data;
	PyObject *py_key, *py_data;
	enum TDB_ERROR ret;
	if (!PyArg_ParseTuple(args, "OO", &py_key, &py_data))
		return NULL;

	key = PyString_AsTDB_DATA(py_key);
	data = PyString_AsTDB_DATA(py_data);

	ret = tdb_append(self->ctx, key, data);
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret);
	Py_RETURN_NONE;
}

static PyObject *obj_firstkey(PyTdbObject *self)
{
	enum TDB_ERROR ret;
	TDB_DATA key;

	ret = tdb_firstkey(self->ctx, &key);
	if (ret == TDB_ERR_NOEXIST)
		Py_RETURN_NONE;
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret);

	return PyString_FromTDB_DATA(key);
}

static PyObject *obj_nextkey(PyTdbObject *self, PyObject *args)
{
	TDB_DATA key;
	PyObject *py_key;
	enum TDB_ERROR ret;
	if (!PyArg_ParseTuple(args, "O", &py_key))
		return NULL;

	/* Malloc here, since tdb_nextkey frees. */
	key.dsize = PyString_Size(py_key);
	key.dptr = malloc(key.dsize);
	memcpy(key.dptr, PyString_AsString(py_key), key.dsize);

	ret = tdb_nextkey(self->ctx, &key);
	if (ret == TDB_ERR_NOEXIST)
		Py_RETURN_NONE;
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret);

	return PyString_FromTDB_DATA(key);
}

static PyObject *obj_delete(PyTdbObject *self, PyObject *args)
{
	TDB_DATA key;
	PyObject *py_key;
	enum TDB_ERROR ret;
	if (!PyArg_ParseTuple(args, "O", &py_key))
		return NULL;

	key = PyString_AsTDB_DATA(py_key);
	ret = tdb_delete(self->ctx, key);
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret);
	Py_RETURN_NONE;
}

static PyObject *obj_has_key(PyTdbObject *self, PyObject *args)
{
	TDB_DATA key;
	enum TDB_ERROR ret;
	PyObject *py_key;
	if (!PyArg_ParseTuple(args, "O", &py_key))
		return NULL;

	key = PyString_AsTDB_DATA(py_key);
	ret = tdb_exists(self->ctx, key);
	if (ret == TDB_ERR_NOEXIST)
		return Py_False;
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret);
	return Py_True;
}

static PyObject *obj_store(PyTdbObject *self, PyObject *args)
{
	TDB_DATA key, value;
	enum TDB_ERROR ret;
	int flag = TDB_REPLACE;
	PyObject *py_key, *py_value;

	if (!PyArg_ParseTuple(args, "OO|i", &py_key, &py_value, &flag))
		return NULL;

	key = PyString_AsTDB_DATA(py_key);
	value = PyString_AsTDB_DATA(py_value);

	ret = tdb_store(self->ctx, key, value, flag);
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret);
	Py_RETURN_NONE;
}

static PyObject *obj_add_flag(PyTdbObject *self, PyObject *args)
{
	unsigned flag;

	if (!PyArg_ParseTuple(args, "I", &flag))
		return NULL;

	tdb_add_flag(self->ctx, flag);
	Py_RETURN_NONE;
}

static PyObject *obj_remove_flag(PyTdbObject *self, PyObject *args)
{
	unsigned flag;

	if (!PyArg_ParseTuple(args, "I", &flag))
		return NULL;

	tdb_remove_flag(self->ctx, flag);
	Py_RETURN_NONE;
}

typedef struct {
	PyObject_HEAD
	TDB_DATA current;
	bool end;
	PyTdbObject *iteratee;
} PyTdbIteratorObject;

static PyObject *tdb_iter_next(PyTdbIteratorObject *self)
{
	enum TDB_ERROR e;
	PyObject *ret;
	if (self->end)
		return NULL;
	ret = PyString_FromStringAndSize((const char *)self->current.dptr,
					 self->current.dsize);
	e = tdb_nextkey(self->iteratee->ctx, &self->current);
	if (e == TDB_ERR_NOEXIST)
		self->end = true;
	else
		PyErr_TDB_ERROR_IS_ERR_RAISE(e);
	return ret;
}

static void tdb_iter_dealloc(PyTdbIteratorObject *self)
{
	Py_DECREF(self->iteratee);
	PyObject_Del(self);
}

PyTypeObject PyTdbIterator = {
	.tp_name = "Iterator",
	.tp_basicsize = sizeof(PyTdbIteratorObject),
	.tp_iternext = (iternextfunc)tdb_iter_next,
	.tp_dealloc = (destructor)tdb_iter_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_iter = PyObject_SelfIter,
};

static PyObject *tdb_object_iter(PyTdbObject *self)
{
	PyTdbIteratorObject *ret;
	enum TDB_ERROR e;

	ret = PyObject_New(PyTdbIteratorObject, &PyTdbIterator);
	if (!ret)
		return NULL;
	e = tdb_firstkey(self->ctx, &ret->current);
	if (e == TDB_ERR_NOEXIST) {
		ret->end = true;
	} else {
		PyErr_TDB_ERROR_IS_ERR_RAISE(e);
		ret->end = false;
	}
	ret->iteratee = self;
	Py_INCREF(self);
	return (PyObject *)ret;
}

static PyObject *obj_clear(PyTdbObject *self)
{
	enum TDB_ERROR ret = tdb_wipe_all(self->ctx);
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret);
	Py_RETURN_NONE;
}

static PyObject *obj_enable_seqnum(PyTdbObject *self)
{
	tdb_add_flag(self->ctx, TDB_SEQNUM);
	Py_RETURN_NONE;
}

static PyMethodDef tdb_object_methods[] = {
	{ "transaction_cancel", (PyCFunction)obj_transaction_cancel, METH_NOARGS,
		"S.transaction_cancel() -> None\n"
		"Cancel the currently active transaction." },
	{ "transaction_commit", (PyCFunction)obj_transaction_commit, METH_NOARGS,
		"S.transaction_commit() -> None\n"
		"Commit the currently active transaction." },
	{ "transaction_prepare_commit", (PyCFunction)obj_transaction_prepare_commit, METH_NOARGS,
		"S.transaction_prepare_commit() -> None\n"
		"Prepare to commit the currently active transaction" },
	{ "transaction_start", (PyCFunction)obj_transaction_start, METH_NOARGS,
		"S.transaction_start() -> None\n"
		"Start a new transaction." },
	{ "lock_all", (PyCFunction)obj_lockall, METH_NOARGS, NULL },
	{ "unlock_all", (PyCFunction)obj_unlockall, METH_NOARGS, NULL },
	{ "read_lock_all", (PyCFunction)obj_lockall_read, METH_NOARGS, NULL },
	{ "read_unlock_all", (PyCFunction)obj_unlockall_read, METH_NOARGS, NULL },
	{ "close", (PyCFunction)obj_close, METH_NOARGS, NULL },
	{ "get", (PyCFunction)obj_get, METH_VARARGS, "S.get(key) -> value\n"
		"Fetch a value." },
	{ "append", (PyCFunction)obj_append, METH_VARARGS, "S.append(key, value) -> None\n"
		"Append data to an existing key." },
	{ "firstkey", (PyCFunction)obj_firstkey, METH_NOARGS, "S.firstkey() -> data\n"
		"Return the first key in this database." },
	{ "nextkey", (PyCFunction)obj_nextkey, METH_NOARGS, "S.nextkey(key) -> data\n"
		"Return the next key in this database." },
	{ "delete", (PyCFunction)obj_delete, METH_VARARGS, "S.delete(key) -> None\n"
		"Delete an entry." },
	{ "has_key", (PyCFunction)obj_has_key, METH_VARARGS, "S.has_key(key) -> None\n"
		"Check whether key exists in this database." },
	{ "store", (PyCFunction)obj_store, METH_VARARGS, "S.store(key, data, flag=REPLACE) -> None"
		"Store data." },
	{ "add_flag", (PyCFunction)obj_add_flag, METH_VARARGS, "S.add_flag(flag) -> None" },
	{ "remove_flag", (PyCFunction)obj_remove_flag, METH_VARARGS, "S.remove_flag(flag) -> None" },
	{ "iterkeys", (PyCFunction)tdb_object_iter, METH_NOARGS, "S.iterkeys() -> iterator" },
	{ "clear", (PyCFunction)obj_clear, METH_NOARGS, "S.clear() -> None\n"
		"Wipe the entire database." },
	{ "enable_seqnum", (PyCFunction)obj_enable_seqnum, METH_NOARGS,
		"S.enable_seqnum() -> None" },
	{ NULL }
};

static PyObject *obj_get_flags(PyTdbObject *self, void *closure)
{
	return PyInt_FromLong(tdb_get_flags(self->ctx));
}

static PyObject *obj_get_filename(PyTdbObject *self, void *closure)
{
	return PyString_FromString(tdb_name(self->ctx));
}

static PyObject *obj_get_seqnum(PyTdbObject *self, void *closure)
{
	return PyInt_FromLong(tdb_get_seqnum(self->ctx));
}


static PyGetSetDef tdb_object_getsetters[] = {
	{ (char *)"flags", (getter)obj_get_flags, NULL, NULL },
	{ (char *)"filename", (getter)obj_get_filename, NULL, (char *)"The filename of this TDB file."},
	{ (char *)"seqnum", (getter)obj_get_seqnum, NULL, NULL },
	{ NULL }
};

static PyObject *tdb_object_repr(PyTdbObject *self)
{
	if (tdb_get_flags(self->ctx) & TDB_INTERNAL) {
		return PyString_FromString("Tdb(<internal>)");
	} else {
		return PyString_FromFormat("Tdb('%s')", tdb_name(self->ctx));
	}
}

static void tdb_object_dealloc(PyTdbObject *self)
{
	if (!self->closed)
		tdb_close(self->ctx);
	self->ob_type->tp_free(self);
}

static PyObject *obj_getitem(PyTdbObject *self, PyObject *key)
{
	TDB_DATA tkey, val;
	enum TDB_ERROR ret;

	if (!PyString_Check(key)) {
		PyErr_SetString(PyExc_TypeError, "Expected string as key");
		return NULL;
	}

	tkey.dptr = (unsigned char *)PyString_AsString(key);
	tkey.dsize = PyString_Size(key);

	ret = tdb_fetch(self->ctx, tkey, &val);
	if (ret == TDB_ERR_NOEXIST) {
		PyErr_SetString(PyExc_KeyError, "No such TDB entry");
		return NULL;
	} else {
		PyErr_TDB_ERROR_IS_ERR_RAISE(ret);
		return PyString_FromTDB_DATA(val);
	}
}

static int obj_setitem(PyTdbObject *self, PyObject *key, PyObject *value)
{
	TDB_DATA tkey, tval;
	enum TDB_ERROR ret;
	if (!PyString_Check(key)) {
		PyErr_SetString(PyExc_TypeError, "Expected string as key");
		return -1;
	}

	tkey = PyString_AsTDB_DATA(key);

	if (value == NULL) {
		ret = tdb_delete(self->ctx, tkey);
	} else {
		if (!PyString_Check(value)) {
			PyErr_SetString(PyExc_TypeError, "Expected string as value");
			return -1;
		}

		tval = PyString_AsTDB_DATA(value);

		ret = tdb_store(self->ctx, tkey, tval, TDB_REPLACE);
	}

	if (ret != TDB_SUCCESS) {
		PyErr_SetTDBError(ret);
		return -1;
	}

	return ret;
}

static PyMappingMethods tdb_object_mapping = {
	.mp_subscript = (binaryfunc)obj_getitem,
	.mp_ass_subscript = (objobjargproc)obj_setitem,
};
static PyTypeObject PyTdb = {
	.tp_name = "Tdb",
	.tp_basicsize = sizeof(PyTdbObject),
	.tp_methods = tdb_object_methods,
	.tp_getset = tdb_object_getsetters,
	.tp_new = py_tdb_open,
	.tp_doc = "A TDB file",
	.tp_repr = (reprfunc)tdb_object_repr,
	.tp_dealloc = (destructor)tdb_object_dealloc,
	.tp_as_mapping = &tdb_object_mapping,
	.tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE|Py_TPFLAGS_HAVE_ITER,
	.tp_iter = (getiterfunc)tdb_object_iter,
};

static PyMethodDef tdb_methods[] = {
	{ "open", (PyCFunction)py_tdb_open, METH_VARARGS|METH_KEYWORDS, "open(name, hash_size=0, tdb_flags=TDB_DEFAULT, flags=O_RDWR, mode=0600)\n"
		"Open a TDB file." },
	{ NULL }
};

void inittdb(void);
void inittdb(void)
{
	PyObject *m;

	if (PyType_Ready(&PyTdb) < 0)
		return;

	if (PyType_Ready(&PyTdbIterator) < 0)
		return;

	m = Py_InitModule3("tdb", tdb_methods, "TDB is a simple key-value database similar to GDBM that supports multiple writers.");
	if (m == NULL)
		return;

	PyModule_AddObject(m, "REPLACE", PyInt_FromLong(TDB_REPLACE));
	PyModule_AddObject(m, "INSERT", PyInt_FromLong(TDB_INSERT));
	PyModule_AddObject(m, "MODIFY", PyInt_FromLong(TDB_MODIFY));

	PyModule_AddObject(m, "DEFAULT", PyInt_FromLong(TDB_DEFAULT));
	PyModule_AddObject(m, "INTERNAL", PyInt_FromLong(TDB_INTERNAL));
	PyModule_AddObject(m, "NOLOCK", PyInt_FromLong(TDB_NOLOCK));
	PyModule_AddObject(m, "NOMMAP", PyInt_FromLong(TDB_NOMMAP));
	PyModule_AddObject(m, "CONVERT", PyInt_FromLong(TDB_CONVERT));
	PyModule_AddObject(m, "NOSYNC", PyInt_FromLong(TDB_NOSYNC));
	PyModule_AddObject(m, "SEQNUM", PyInt_FromLong(TDB_SEQNUM));
	PyModule_AddObject(m, "ALLOW_NESTING", PyInt_FromLong(TDB_ALLOW_NESTING));

	PyModule_AddObject(m, "__docformat__", PyString_FromString("restructuredText"));

	PyModule_AddObject(m, "__version__", PyString_FromString(PACKAGE_VERSION));

	Py_INCREF(&PyTdb);
	PyModule_AddObject(m, "Tdb", (PyObject *)&PyTdb);

	Py_INCREF(&PyTdbIterator);
}
