/* 
   Unix SMB/CIFS implementation.

   Python interface to tdb.

   Copyright (C) 2004-2006 Tim Potter <tpot@samba.org>
   Copyright (C) 2007-2008 Jelmer Vernooij <jelmer@samba.org>

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

/* Include tdb headers */
#include <tdb.h>

#if PY_MAJOR_VERSION >= 3
#define Py_TPFLAGS_HAVE_ITER 0
#endif

/* discard signature of 'func' in favour of 'target_sig' */
#define PY_DISCARD_FUNC_SIG(target_sig, func) (target_sig)(void(*)(void))func

typedef struct {
	PyObject_HEAD
	TDB_CONTEXT *ctx;
	bool closed;
} PyTdbObject;

static PyTypeObject PyTdb;

static void PyErr_SetTDBError(TDB_CONTEXT *tdb)
{
	PyErr_SetObject(PyExc_RuntimeError, 
		Py_BuildValue("(i,s)", tdb_error(tdb), tdb_errorstr(tdb)));
}

static TDB_DATA PyBytes_AsTDB_DATA(PyObject *data)
{
	TDB_DATA ret;
	ret.dptr = (unsigned char *)PyBytes_AsString(data);
	ret.dsize = PyBytes_Size(data);
	return ret;
}

static PyObject *PyBytes_FromTDB_DATA(TDB_DATA data)
{
	if (data.dptr == NULL && data.dsize == 0) {
		Py_RETURN_NONE;
	} else {
		PyObject *ret = PyBytes_FromStringAndSize((const char *)data.dptr,
												  data.dsize);
		free(data.dptr);
		return ret;
    }
}

#define PyErr_TDB_ERROR_IS_ERR_RAISE(ret, tdb) \
	if (ret != 0) { \
		PyErr_SetTDBError(tdb); \
		return NULL; \
	}

#define PyErr_TDB_RAISE_IF_CLOSED(self) \
	if (self->closed) {						\
	        PyErr_SetObject(PyExc_RuntimeError,				\
				Py_BuildValue("(i,s)", TDB_ERR_IO, "Database is already closed")); \
		return NULL;						\
	}

#define PyErr_TDB_RAISE_RETURN_MINUS_1_IF_CLOSED(self) \
	if (self->closed) {						\
	        PyErr_SetObject(PyExc_RuntimeError,				\
				Py_BuildValue("(i,s)", TDB_ERR_IO, "Database is already closed")); \
		return -1;						\
	}

static PyObject *py_tdb_open(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	char *name = NULL;
	int hash_size = 0, tdb_flags = TDB_DEFAULT, flags = O_RDWR, mode = 0600;
	TDB_CONTEXT *ctx;
	PyTdbObject *ret;
	const char *_kwnames[] = { "name", "hash_size", "tdb_flags", "flags", "mode", NULL };
	char **kwnames = discard_const_p(char *, _kwnames);

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|siiii", kwnames, &name, &hash_size, &tdb_flags, &flags, &mode))
		return NULL;

	if (name == NULL) {
		tdb_flags |= TDB_INTERNAL;
	}

	ctx = tdb_open(name, hash_size, tdb_flags, flags, mode);
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

static PyObject *obj_transaction_cancel(PyTdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	int ret;

	PyErr_TDB_RAISE_IF_CLOSED(self);

	ret = tdb_transaction_cancel(self->ctx);
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret, self->ctx);
	Py_RETURN_NONE;
}

static PyObject *obj_transaction_commit(PyTdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	int ret;
	PyErr_TDB_RAISE_IF_CLOSED(self);
	ret = tdb_transaction_commit(self->ctx);
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret, self->ctx);
	Py_RETURN_NONE;
}

static PyObject *obj_transaction_prepare_commit(PyTdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	int ret;
	PyErr_TDB_RAISE_IF_CLOSED(self);
	ret = tdb_transaction_prepare_commit(self->ctx);
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret, self->ctx);
	Py_RETURN_NONE;
}

static PyObject *obj_transaction_start(PyTdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	int ret;
	PyErr_TDB_RAISE_IF_CLOSED(self);
	ret = tdb_transaction_start(self->ctx);
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret, self->ctx);
	Py_RETURN_NONE;
}

static PyObject *obj_reopen(PyTdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	int ret;
	PyErr_TDB_RAISE_IF_CLOSED(self);
	ret = tdb_reopen(self->ctx);
	if (ret != 0) {
		self->closed = true;
		PyErr_SetObject(PyExc_RuntimeError,
				Py_BuildValue("(i,s)",
					      TDB_ERR_IO,
					      "Failed to reopen database"));
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *obj_lockall(PyTdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	int ret;
	PyErr_TDB_RAISE_IF_CLOSED(self);
	ret = tdb_lockall(self->ctx);
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret, self->ctx);
	Py_RETURN_NONE;
}

static PyObject *obj_unlockall(PyTdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	int ret;
	PyErr_TDB_RAISE_IF_CLOSED(self);
	ret = tdb_unlockall(self->ctx);
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret, self->ctx);
	Py_RETURN_NONE;
}

static PyObject *obj_lockall_read(PyTdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	int ret;
	PyErr_TDB_RAISE_IF_CLOSED(self);
	ret = tdb_lockall_read(self->ctx);
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret, self->ctx);
	Py_RETURN_NONE;
}

static PyObject *obj_unlockall_read(PyTdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	int ret = tdb_unlockall_read(self->ctx);
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret, self->ctx);
	Py_RETURN_NONE;
}

static PyObject *obj_close(PyTdbObject *self, PyObject *Py_UNUSED(ignored))
{
	int ret;
	if (self->closed)
		Py_RETURN_NONE;
	ret = tdb_close(self->ctx);
	self->closed = true;
	if (ret != 0) {
		PyErr_SetObject(PyExc_RuntimeError,
				Py_BuildValue("(i,s)",
					      TDB_ERR_IO,
					      "Failed to close database"));
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *obj_get(PyTdbObject *self, PyObject *args)
{
	TDB_DATA key;
	PyObject *py_key;

	PyErr_TDB_RAISE_IF_CLOSED(self);

	if (!PyArg_ParseTuple(args, "O", &py_key))
		return NULL;

	key = PyBytes_AsTDB_DATA(py_key);
	if (!key.dptr)
		return NULL;

	return PyBytes_FromTDB_DATA(tdb_fetch(self->ctx, key));
}

static PyObject *obj_append(PyTdbObject *self, PyObject *args)
{
	TDB_DATA key, data;
	PyObject *py_key, *py_data;
	int ret;

	PyErr_TDB_RAISE_IF_CLOSED(self);

	if (!PyArg_ParseTuple(args, "OO", &py_key, &py_data))
		return NULL;

	key = PyBytes_AsTDB_DATA(py_key);
	if (!key.dptr)
		return NULL;
	data = PyBytes_AsTDB_DATA(py_data);
	if (!data.dptr)
		return NULL;

	ret = tdb_append(self->ctx, key, data);
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret, self->ctx);
	Py_RETURN_NONE;
}

static PyObject *obj_firstkey(PyTdbObject *self, PyObject *Py_UNUSED(ignored))
{
	PyErr_TDB_RAISE_IF_CLOSED(self);

	return PyBytes_FromTDB_DATA(tdb_firstkey(self->ctx));
}

static PyObject *obj_nextkey(PyTdbObject *self, PyObject *args)
{
	TDB_DATA key;
	PyObject *py_key;
	PyErr_TDB_RAISE_IF_CLOSED(self);

	if (!PyArg_ParseTuple(args, "O", &py_key))
		return NULL;

	key = PyBytes_AsTDB_DATA(py_key);
	if (!key.dptr)
		return NULL;
	
	return PyBytes_FromTDB_DATA(tdb_nextkey(self->ctx, key));
}

static PyObject *obj_delete(PyTdbObject *self, PyObject *args)
{
	TDB_DATA key;
	PyObject *py_key;
	int ret;
	PyErr_TDB_RAISE_IF_CLOSED(self);

	if (!PyArg_ParseTuple(args, "O", &py_key))
		return NULL;

	key = PyBytes_AsTDB_DATA(py_key);
	if (!key.dptr)
		return NULL;
	ret = tdb_delete(self->ctx, key);
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret, self->ctx);
	Py_RETURN_NONE;
}

static int obj_contains(PyTdbObject *self, PyObject *py_key)
{
	TDB_DATA key;
	int ret;
	PyErr_TDB_RAISE_RETURN_MINUS_1_IF_CLOSED(self);

	key = PyBytes_AsTDB_DATA(py_key);
	if (!key.dptr) {
		PyErr_BadArgument();
		return -1;
	}
	ret = tdb_exists(self->ctx, key);
	if (ret)
		return 1;
	return 0;
}

#if PY_MAJOR_VERSION < 3
static PyObject *obj_has_key(PyTdbObject *self, PyObject *args)
{
	int ret;
	PyObject *py_key;
	PyErr_TDB_RAISE_IF_CLOSED(self);

	if (!PyArg_ParseTuple(args, "O", &py_key))
		return NULL;

	ret = obj_contains(self, py_key);
	if (ret == -1)
		return NULL;
	if (ret)
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;

}
#endif

static PyObject *obj_store(PyTdbObject *self, PyObject *args)
{
	TDB_DATA key, value;
	int ret;
	int flag = TDB_REPLACE;
	PyObject *py_key, *py_value;

	PyErr_TDB_RAISE_IF_CLOSED(self);

	if (!PyArg_ParseTuple(args, "OO|i", &py_key, &py_value, &flag))
		return NULL;

	key = PyBytes_AsTDB_DATA(py_key);
	if (!key.dptr)
		return NULL;
	value = PyBytes_AsTDB_DATA(py_value);
	if (!value.dptr)
		return NULL;

	ret = tdb_store(self->ctx, key, value, flag);
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret, self->ctx);
	Py_RETURN_NONE;
}

static PyObject *obj_storev(PyTdbObject *self, PyObject *args)
{
	TDB_DATA key, *values, value;
	int ret;
	int flag = TDB_REPLACE;
	Py_ssize_t num_values, i;
	PyObject *py_key, *py_values, *py_value;

	PyErr_TDB_RAISE_IF_CLOSED(self);

	if (!PyArg_ParseTuple(
		    args, "OO!|i", &py_key, &PyList_Type, &py_values, &flag)) {
		return NULL;
	}

	num_values = PyList_Size(py_values);

	key = PyBytes_AsTDB_DATA(py_key);
	if (key.dptr == NULL) {
		return NULL;
	}

	if (SSIZE_MAX/sizeof(TDB_DATA) < num_values) {
		PyErr_SetFromErrno(PyExc_OverflowError);
		return NULL;
	}
	values = malloc(sizeof(TDB_DATA) * num_values);
	if (values == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	for (i=0; i<num_values; i++) {
		py_value = PyList_GetItem(py_values, i);
		value = PyBytes_AsTDB_DATA(py_value);
		if (!value.dptr) {
			free(values);
			return NULL;
		}
		values[i] = value;
	}

	ret = tdb_storev(self->ctx, key, values, num_values, flag);
	free(values);
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret, self->ctx);
	Py_RETURN_NONE;
}

static PyObject *obj_add_flags(PyTdbObject *self, PyObject *args)
{
	unsigned flags;

	PyErr_TDB_RAISE_IF_CLOSED(self);

	if (!PyArg_ParseTuple(args, "I", &flags))
		return NULL;

	tdb_add_flags(self->ctx, flags);
	Py_RETURN_NONE;
}

static PyObject *obj_remove_flags(PyTdbObject *self, PyObject *args)
{
	unsigned flags;

	PyErr_TDB_RAISE_IF_CLOSED(self);

	if (!PyArg_ParseTuple(args, "I", &flags))
		return NULL;

	tdb_remove_flags(self->ctx, flags);
	Py_RETURN_NONE;
}

typedef struct {
	PyObject_HEAD
	TDB_DATA current;
	PyTdbObject *iteratee;
} PyTdbIteratorObject;

static PyObject *tdb_iter_next(PyTdbIteratorObject *self)
{
	TDB_DATA current;
	PyObject *ret;
	if (self->current.dptr == NULL && self->current.dsize == 0)
		return NULL;
	current = self->current;
	self->current = tdb_nextkey(self->iteratee->ctx, self->current);
	ret = PyBytes_FromTDB_DATA(current);
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

static PyObject *tdb_object_iter(PyTdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	PyTdbIteratorObject *ret;	

	PyErr_TDB_RAISE_IF_CLOSED(self);

	ret = PyObject_New(PyTdbIteratorObject, &PyTdbIterator);
	if (!ret)
		return NULL;
	ret->current = tdb_firstkey(self->ctx);
	ret->iteratee = self;
	Py_INCREF(self);
	return (PyObject *)ret;
}

static PyObject *obj_clear(PyTdbObject *self, PyObject *Py_UNUSED(ignored))
{
	int ret;
	PyErr_TDB_RAISE_IF_CLOSED(self);
	ret = tdb_wipe_all(self->ctx);
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret, self->ctx);
	Py_RETURN_NONE;
}

static PyObject *obj_repack(PyTdbObject *self, PyObject *Py_UNUSED(ignored))
{
	int ret;
	PyErr_TDB_RAISE_IF_CLOSED(self);
	ret = tdb_repack(self->ctx);
	PyErr_TDB_ERROR_IS_ERR_RAISE(ret, self->ctx);
	Py_RETURN_NONE;
}

static PyObject *obj_enable_seqnum(PyTdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	PyErr_TDB_RAISE_IF_CLOSED(self);
	tdb_enable_seqnum(self->ctx);
	Py_RETURN_NONE;
}

static PyObject *obj_increment_seqnum_nonblock(PyTdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	PyErr_TDB_RAISE_IF_CLOSED(self);
	tdb_increment_seqnum_nonblock(self->ctx);
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
	{ "reopen", (PyCFunction)obj_reopen, METH_NOARGS, "Reopen this file." },
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
	{ "nextkey", (PyCFunction)obj_nextkey, METH_VARARGS, "S.nextkey(key) -> data\n"
		"Return the next key in this database." },
	{ "delete", (PyCFunction)obj_delete, METH_VARARGS, "S.delete(key) -> None\n"
		"Delete an entry." },
#if PY_MAJOR_VERSION < 3
	{ "has_key", (PyCFunction)obj_has_key, METH_VARARGS, "S.has_key(key) -> None\n"
		"Check whether key exists in this database." },
#endif
	{ "store", (PyCFunction)obj_store, METH_VARARGS, "S.store(key, data, flag=REPLACE) -> None"
		"Store data." },
	{ "storev", (PyCFunction)obj_storev, METH_VARARGS, "S.storev(key, data, flag=REPLACE) -> None"
		"Store several data." },
	{ "add_flags", (PyCFunction)obj_add_flags, METH_VARARGS, "S.add_flags(flags) -> None" },
	{ "remove_flags", (PyCFunction)obj_remove_flags, METH_VARARGS, "S.remove_flags(flags) -> None" },
#if PY_MAJOR_VERSION >= 3
	{ "keys", (PyCFunction)tdb_object_iter, METH_NOARGS, "S.keys() -> iterator" },
#else
	{ "iterkeys", (PyCFunction)tdb_object_iter, METH_NOARGS, "S.iterkeys() -> iterator" },
#endif
	{ "clear", (PyCFunction)obj_clear, METH_NOARGS, "S.clear() -> None\n"
		"Wipe the entire database." },
	{ "repack", (PyCFunction)obj_repack, METH_NOARGS, "S.repack() -> None\n"
		"Repack the entire database." },
	{ "enable_seqnum", (PyCFunction)obj_enable_seqnum, METH_NOARGS,
		"S.enable_seqnum() -> None" },
	{ "increment_seqnum_nonblock", (PyCFunction)obj_increment_seqnum_nonblock, METH_NOARGS,
		"S.increment_seqnum_nonblock() -> None" },
	{0}
};

static PyObject *obj_get_hash_size(PyTdbObject *self, void *closure)
{
	PyErr_TDB_RAISE_IF_CLOSED(self);
	return PyLong_FromLong(tdb_hash_size(self->ctx));
}

static int obj_set_max_dead(PyTdbObject *self, PyObject *max_dead, void *closure)
{
	PyErr_TDB_RAISE_RETURN_MINUS_1_IF_CLOSED(self);
	if (!PyLong_Check(max_dead))
		return -1;
	tdb_set_max_dead(self->ctx, PyLong_AsLong(max_dead));
	return 0;
}

static PyObject *obj_get_map_size(PyTdbObject *self, void *closure)
{
	PyErr_TDB_RAISE_IF_CLOSED(self);
	return PyLong_FromLong(tdb_map_size(self->ctx));
}

static PyObject *obj_get_freelist_size(PyTdbObject *self, void *closure)
{
	PyErr_TDB_RAISE_IF_CLOSED(self);
	return PyLong_FromLong(tdb_freelist_size(self->ctx));
}

static PyObject *obj_get_flags(PyTdbObject *self, void *closure)
{
	PyErr_TDB_RAISE_IF_CLOSED(self);
	return PyLong_FromLong(tdb_get_flags(self->ctx));
}

static PyObject *obj_get_filename(PyTdbObject *self, void *closure)
{
	PyErr_TDB_RAISE_IF_CLOSED(self);
	return PyBytes_FromString(tdb_name(self->ctx));
}

static PyObject *obj_get_seqnum(PyTdbObject *self, void *closure)
{
	PyErr_TDB_RAISE_IF_CLOSED(self);
	return PyLong_FromLong(tdb_get_seqnum(self->ctx));
}

static PyObject *obj_get_text(PyTdbObject *self, void *closure)
{
	PyObject *mod, *cls, *inst;
	mod = PyImport_ImportModule("_tdb_text");
	if (mod == NULL)
		return NULL;
	cls = PyObject_GetAttrString(mod, "TdbTextWrapper");
	if (cls == NULL) {
		Py_DECREF(mod);
		return NULL;
	}
	inst = PyObject_CallFunction(cls, discard_const_p(char, "O"), self);
	Py_DECREF(mod);
	Py_DECREF(cls);
	return inst;
}

static PyGetSetDef tdb_object_getsetters[] = {
	{
		.name    = discard_const_p(char, "hash_size"),
		.get     = (getter)obj_get_hash_size,
	},
	{
		.name    = discard_const_p(char, "map_size"),
		.get     = (getter)obj_get_map_size,
	},
	{
		.name    = discard_const_p(char, "freelist_size"),
		.get     = (getter)obj_get_freelist_size,
	},
	{
		.name    = discard_const_p(char, "flags"),
		.get     = (getter)obj_get_flags,
	},
	{
		.name    = discard_const_p(char, "max_dead"),
		.set     = (setter)obj_set_max_dead,
	},
	{
		.name    = discard_const_p(char, "filename"),
		.get     = (getter)obj_get_filename,
		.doc     = discard_const_p(char, "The filename of this TDB file."),
	},
	{
		.name    = discard_const_p(char, "seqnum"),
		.get     = (getter)obj_get_seqnum,
	},
	{
		.name    = discard_const_p(char, "text"),
		.get     = (getter)obj_get_text,
	},
	{ .name = NULL }
};

static PyObject *tdb_object_repr(PyTdbObject *self)
{
	PyErr_TDB_RAISE_IF_CLOSED(self);
	if (tdb_get_flags(self->ctx) & TDB_INTERNAL) {
		return PyUnicode_FromString("Tdb(<internal>)");
	} else {
		return PyUnicode_FromFormat("Tdb('%s')", tdb_name(self->ctx));
	}
}

static void tdb_object_dealloc(PyTdbObject *self)
{
	if (!self->closed)
		tdb_close(self->ctx);
	Py_TYPE(self)->tp_free(self);
}

static PyObject *obj_getitem(PyTdbObject *self, PyObject *key)
{
	TDB_DATA tkey, val;
	PyErr_TDB_RAISE_IF_CLOSED(self);
	if (!PyBytes_Check(key)) {
		PyErr_SetString(PyExc_TypeError, "Expected bytestring as key");
		return NULL;
	}

	tkey.dptr = (unsigned char *)PyBytes_AsString(key);
	tkey.dsize = PyBytes_Size(key);

	val = tdb_fetch(self->ctx, tkey);
	if (val.dptr == NULL) {
		/*
		 * if the key doesn't exist raise KeyError(key) to be
		 * consistent with python dict
		 */
		PyErr_SetObject(PyExc_KeyError, key);
		return NULL;
	} else {
		return PyBytes_FromTDB_DATA(val);
	}
}

static int obj_setitem(PyTdbObject *self, PyObject *key, PyObject *value)
{
	TDB_DATA tkey, tval;
	int ret;
	PyErr_TDB_RAISE_RETURN_MINUS_1_IF_CLOSED(self);
	if (!PyBytes_Check(key)) {
		PyErr_SetString(PyExc_TypeError, "Expected bytestring as key");
		return -1;
	}

	tkey = PyBytes_AsTDB_DATA(key);

	if (value == NULL) { 
		ret = tdb_delete(self->ctx, tkey);
	} else { 
		if (!PyBytes_Check(value)) {
			PyErr_SetString(PyExc_TypeError, "Expected string as value");
			return -1;
		}

		tval = PyBytes_AsTDB_DATA(value);

		ret = tdb_store(self->ctx, tkey, tval, TDB_REPLACE);
	}

	if (ret != 0) {
		PyErr_SetTDBError(self->ctx);
		return -1;
	} 

	return ret;
}

static PyMappingMethods tdb_object_mapping = {
	.mp_subscript = (binaryfunc)obj_getitem,
	.mp_ass_subscript = (objobjargproc)obj_setitem,
};
static PySequenceMethods tdb_object_seq = {
	.sq_contains = (objobjproc)obj_contains,
};
static PyTypeObject PyTdb = {
	.tp_name = "tdb.Tdb",
	.tp_basicsize = sizeof(PyTdbObject),
	.tp_methods = tdb_object_methods,
	.tp_getset = tdb_object_getsetters,
	.tp_new = py_tdb_open,
	.tp_doc = "A TDB file",
	.tp_repr = (reprfunc)tdb_object_repr,
	.tp_dealloc = (destructor)tdb_object_dealloc,
	.tp_as_mapping = &tdb_object_mapping,
	.tp_as_sequence = &tdb_object_seq,
	.tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE|Py_TPFLAGS_HAVE_ITER,
	.tp_iter = PY_DISCARD_FUNC_SIG(getiterfunc,tdb_object_iter),
};

static PyMethodDef tdb_methods[] = {
	{
		.ml_name  = "open",
		.ml_meth  = PY_DISCARD_FUNC_SIG(PyCFunction, py_tdb_open),
		.ml_flags = METH_VARARGS|METH_KEYWORDS,
		.ml_doc   = "open(name, hash_size=0, tdb_flags=TDB_DEFAULT, "
			    "flags=O_RDWR, mode=0600)\nOpen a TDB file."
	},
	{ .ml_name = NULL }
};

#define MODULE_DOC "simple key-value database that supports multiple writers."

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    .m_name = "tdb",
    .m_doc = MODULE_DOC,
    .m_size = -1,
    .m_methods = tdb_methods,
};
#endif

PyObject* module_init(void);
PyObject* module_init(void)
{
	PyObject *m;

	if (PyType_Ready(&PyTdb) < 0)
		return NULL;

	if (PyType_Ready(&PyTdbIterator) < 0)
		return NULL;

#if PY_MAJOR_VERSION >= 3
	m = PyModule_Create(&moduledef);
#else
	m = Py_InitModule3("tdb", tdb_methods, MODULE_DOC);
#endif
	if (m == NULL)
		return NULL;

	PyModule_AddIntConstant(m, "REPLACE", TDB_REPLACE);
	PyModule_AddIntConstant(m, "INSERT", TDB_INSERT);
	PyModule_AddIntConstant(m, "MODIFY", TDB_MODIFY);

	PyModule_AddIntConstant(m, "DEFAULT", TDB_DEFAULT);
	PyModule_AddIntConstant(m, "CLEAR_IF_FIRST", TDB_CLEAR_IF_FIRST);
	PyModule_AddIntConstant(m, "INTERNAL", TDB_INTERNAL);
	PyModule_AddIntConstant(m, "NOLOCK", TDB_NOLOCK);
	PyModule_AddIntConstant(m, "NOMMAP", TDB_NOMMAP);
	PyModule_AddIntConstant(m, "CONVERT", TDB_CONVERT);
	PyModule_AddIntConstant(m, "BIGENDIAN", TDB_BIGENDIAN);
	PyModule_AddIntConstant(m, "NOSYNC", TDB_NOSYNC);
	PyModule_AddIntConstant(m, "SEQNUM", TDB_SEQNUM);
	PyModule_AddIntConstant(m, "VOLATILE", TDB_VOLATILE);
	PyModule_AddIntConstant(m, "ALLOW_NESTING", TDB_ALLOW_NESTING);
	PyModule_AddIntConstant(m, "DISALLOW_NESTING", TDB_DISALLOW_NESTING);
	PyModule_AddIntConstant(m, "INCOMPATIBLE_HASH", TDB_INCOMPATIBLE_HASH);

	PyModule_AddStringConstant(m, "__docformat__", "restructuredText");

	PyModule_AddStringConstant(m, "__version__", PACKAGE_VERSION);

	Py_INCREF(&PyTdb);
	PyModule_AddObject(m, "Tdb", (PyObject *)&PyTdb);

	Py_INCREF(&PyTdbIterator);

    return m;
}


#if PY_MAJOR_VERSION >= 3
PyMODINIT_FUNC PyInit_tdb(void);
PyMODINIT_FUNC PyInit_tdb(void)
{
    return module_init();
}
#else
void inittdb(void);
void inittdb(void)
{
    module_init();
}
#endif
