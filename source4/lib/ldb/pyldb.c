/*
   Unix SMB/CIFS implementation.

   Swig interface to ldb.

   Copyright (C) 2005,2006 Tim Potter <tpot@samba.org>
   Copyright (C) 2006 Simo Sorce <idra@samba.org>
   Copyright (C) 2007-2008 Jelmer Vernooij <jelmer@samba.org>

     ** NOTE! The following LGPL license applies to the ldb
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

#include <stdint.h>
#include <stdbool.h>
#include "pyldb.h"
#include "events.h"
#include "ldb_errors.h"
#include "ldb_private.h"

PyObject *PyExc_LdbError;

#define PyErr_LDB_ERROR_IS_ERR_RAISE(ret,ldb) \
	if (ret != LDB_SUCCESS) { \
        PyErr_SetObject(PyExc_LdbError, Py_BuildValue((char *)"(i,s)", ret, ldb == NULL?ldb_strerror(ret):ldb_errstring(ldb))); \
		return NULL; \
	}
#define PyLdb_AsLdbContext(pyobj) py_talloc_get_type(pyobj, struct ldb_context)
#define PyLdbModule_AsModule(pyobj) py_talloc_get_type(pyobj, struct ldb_module)
#define PyLdbMessage_AsMessage(pyobj) py_talloc_get_type(pyobj, struct ldb_message)
#define PyLdbMessageElement_AsMessageElement(pyobj) py_talloc_get_type(pyobj, struct ldb_message_element)

PyObject *PyObject_FromLdbValue(struct ldb_context *ldb_ctx, 
                               struct ldb_message_element *el, 
                               struct ldb_val *val)
{
	const struct ldb_schema_attribute *a;
	struct ldb_val new_val;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	PyObject *ret;
	
	new_val = *val;
	
	if (ldb_ctx != NULL) {        
		a = ldb_schema_attribute_by_name(ldb_ctx, el->name);
	
		if (a != NULL) {
			if (a->syntax->ldif_write_fn(ldb_ctx, mem_ctx, val, &new_val) != 0) {
				talloc_free(mem_ctx);
				return NULL;
			}
		}
	} 
	
	ret = PyString_FromStringAndSize((const char *)new_val.data, new_val.length);
	
	talloc_free(mem_ctx);
	
	return ret;
}

int PyObject_AsDn(TALLOC_CTX *mem_ctx, PyObject *object, 
                         struct ldb_context *ldb_ctx, struct ldb_dn **dn)
{
    struct ldb_dn *odn;
    if (ldb_ctx != NULL && PyString_Check(object)) {
        odn = ldb_dn_new(mem_ctx, ldb_ctx, PyString_AsString(object));
		*dn = odn;
        return 0;
    }
	if (PyLdbDn_Check(object)) {
		*dn = PyLdbDn_AsDn(object);
		return 0;
	}
	return -1;
}

static PyObject *PyLdbResult_FromResult(struct ldb_result *result)
{
	PyObject *ret;
	int i;
    if (result == NULL) {
        return Py_None;
    } 
	ret = PyList_New(result->count);
	for (i = 0; i < result->count; i++) {
		PyList_SetItem(ret, i, 
					   PyLdbMessage_FromMessage(result->msgs[i])
		);
	}
	return ret;
}

static struct ldb_result *PyLdbResult_AsResult(PyObject *obj)
{
	/* FIXME */
	return NULL;
}

static PyObject *py_ldb_dn_validate(PyLdbDnObject *self)
{
	return PyBool_FromLong(ldb_dn_validate(self->ptr));
}

static PyObject *py_ldb_dn_is_valid(PyLdbDnObject *self)
{
	return PyBool_FromLong(ldb_dn_is_valid(self->ptr));
}

static PyObject *py_ldb_dn_is_special(PyLdbDnObject *self)
{
	return PyBool_FromLong(ldb_dn_is_special(self->ptr));
}

static PyObject *py_ldb_dn_is_null(PyLdbDnObject *self)
{
	return PyBool_FromLong(ldb_dn_is_null(self->ptr));
}
 
static PyObject *py_ldb_dn_get_casefold(PyLdbDnObject *self)
{
	return PyString_FromString(ldb_dn_get_casefold(self->ptr));
}

static PyObject *py_ldb_dn_get_linearized(PyLdbDnObject *self)
{
	return PyString_FromString(ldb_dn_get_linearized(self->ptr));
}

static PyObject *py_ldb_dn_canonical_str(PyLdbDnObject *self)
{
	return PyString_FromString(ldb_dn_canonical_string(self->ptr, self->ptr));
}

static PyObject *py_ldb_dn_canonical_ex_str(PyLdbDnObject *self)
{
	return PyString_FromString(ldb_dn_canonical_ex_string(self->ptr, self->ptr));
}

static PyObject *py_ldb_dn_repr(PyLdbDnObject *self)
{
	return PyString_FromFormat("Dn('%s')", ldb_dn_get_linearized(self->ptr));
}

static PyObject *py_ldb_dn_check_special(PyLdbDnObject *self, PyObject *args)
{
	char *name;

	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	return ldb_dn_check_special(self->ptr, name)?Py_True:Py_False;
}
static int py_ldb_dn_compare(PyLdbDnObject *dn1, PyLdbDnObject *dn2)
{
	return ldb_dn_compare(dn1->ptr, dn2->ptr);
}

static PyMethodDef py_ldb_dn_methods[] = {
	{ "validate", (PyCFunction)py_ldb_dn_validate, METH_NOARGS, 
		"S.validate() -> bool\n"
		"Validate DN is correct." },
	{ "is_valid", (PyCFunction)py_ldb_dn_is_valid, METH_NOARGS,
		"S.is_valid() -> bool\n" },
	{ "is_special", (PyCFunction)py_ldb_dn_is_special, METH_NOARGS,
		"S.is_special() -> bool\n"
		"Check whether this is a special LDB DN." },
	{ "is_null", (PyCFunction)py_ldb_dn_is_null, METH_NOARGS,
		"Check whether this is a null DN." },
	{ "get_casefold", (PyCFunction)py_ldb_dn_get_casefold, METH_NOARGS,
		NULL },
	{ "get_linearized", (PyCFunction)py_ldb_dn_get_linearized, METH_NOARGS,
		NULL },
	{ "canonical_str", (PyCFunction)py_ldb_dn_canonical_str, METH_NOARGS,
		"S.canonical_str() -> string\n"
		"Canonical version of this DN (like a posix path)." },
	{ "canonical_ex_str", (PyCFunction)py_ldb_dn_canonical_ex_str, METH_NOARGS,
		"S.canonical_ex_str() -> string\n"
		"Canonical version of this DN (like a posix path, with terminating newline)." },
	{ "check_special", (PyCFunction)py_ldb_dn_is_special, METH_VARARGS, 
		NULL },
	{ NULL }
};

PyTypeObject PyLdbDn = {
	.tp_name = "Dn",
	.tp_methods = py_ldb_dn_methods,
	.tp_str = (reprfunc)py_ldb_dn_get_linearized,
	.tp_repr = (reprfunc)py_ldb_dn_repr,
	.tp_compare = (cmpfunc)py_ldb_dn_compare,
	.tp_doc = "A LDB distinguished name.",
};

/* Debug */
static void py_ldb_debug(void *context, enum ldb_debug_level level, const char *fmt, va_list ap)
{
    PyObject *fn = context;
    PyObject_CallFunction(fn, (char *)"(i,O)", level, PyString_FromFormatV(fmt, ap));
}

static PyObject *py_ldb_set_debug(PyLdbObject *self, PyObject *args)
{
	PyObject *cb;
	
	if (!PyArg_ParseTuple(args, "O", &cb))
		return NULL;

	Py_INCREF(cb);
	/* FIXME: Where do we DECREF cb ? */
	PyErr_LDB_ERROR_IS_ERR_RAISE(ldb_set_debug(self->ptr, py_ldb_debug, cb), PyLdb_AsLdbContext(self));
	
	return Py_None;
}

static PyObject *py_ldb_set_create_perms(PyTypeObject *self, PyObject *args)
{
	unsigned int perms;
	if (!PyArg_ParseTuple(args, "I", &perms))
		return NULL;

	ldb_set_create_perms(PyLdb_AsLdbContext(self), perms);

	return Py_None;
}

static PyObject *py_ldb_set_modules_dir(PyTypeObject *self, PyObject *args)
{
	char *modules_dir;
	if (!PyArg_ParseTuple(args, "s", &modules_dir))
		return NULL;

	ldb_set_modules_dir(PyLdb_AsLdbContext(self), modules_dir);

	return Py_None;
}

static PyObject *py_ldb_transaction_start(PyLdbObject *self)
{
	PyErr_LDB_ERROR_IS_ERR_RAISE(ldb_transaction_start(PyLdb_AsLdbContext(self)), PyLdb_AsLdbContext(self));
	return Py_None;
}

static PyObject *py_ldb_transaction_commit(PyLdbObject *self)
{
	PyErr_LDB_ERROR_IS_ERR_RAISE(ldb_transaction_commit(PyLdb_AsLdbContext(self)), PyLdb_AsLdbContext(self));
	return Py_None;
}

static PyObject *py_ldb_transaction_cancel(PyLdbObject *self)
{
	PyErr_LDB_ERROR_IS_ERR_RAISE(ldb_transaction_cancel(PyLdb_AsLdbContext(self)), PyLdb_AsLdbContext(self));
	return Py_None;
}

static PyObject *py_ldb_setup_wellknown_attributes(PyLdbObject *self)
{
	PyErr_LDB_ERROR_IS_ERR_RAISE(ldb_setup_wellknown_attributes(PyLdb_AsLdbContext(self)), PyLdb_AsLdbContext(self));
	return Py_None;
}

static PyObject *py_ldb_repr(PyLdbObject *self)
{
	return PyString_FromFormat("<ldb connection>");
}

static PyObject *py_ldb_get_root_basedn(PyLdbObject *self)
{
	struct ldb_dn *dn = ldb_get_root_basedn(PyLdb_AsLdbContext(self));
	if (dn == NULL)
		return Py_None;
	return PyLdbDn_FromDn(dn);
}


static PyObject *py_ldb_get_schema_basedn(PyLdbObject *self)
{
	struct ldb_dn *dn = ldb_get_schema_basedn(PyLdb_AsLdbContext(self));
	if (dn == NULL)
		return Py_None;
	return PyLdbDn_FromDn(dn);
}


static PyObject *py_ldb_get_config_basedn(PyLdbObject *self)
{
	struct ldb_dn *dn = ldb_get_config_basedn(PyLdb_AsLdbContext(self));
	if (dn == NULL)
		return Py_None;
	return PyLdbDn_FromDn(dn);
}


static PyObject *py_ldb_get_default_basedn(PyLdbObject *self)
{
	struct ldb_dn *dn = ldb_get_default_basedn(PyLdb_AsLdbContext(self));
	if (dn == NULL)
		return Py_None;
	return PyLdbDn_FromDn(dn);
}

static PyObject *py_ldb_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	struct ldb_context *ldb;
	char *kwnames[] = { NULL };
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "", kwnames))
		return NULL;

	ldb = ldb_init(NULL, event_context_init(NULL)); 
	if (ldb == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	return py_talloc_import(&PyLdb, ldb);
}

static PyObject *py_ldb_connect(PyLdbObject *self, PyObject *args, PyObject *kwargs)
{
	char *url;
	int flags;
	PyObject *py_options = Py_None;
	int ret;
	int i;
	const char **options;
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|iO", &url, &flags,
									 &py_options))
		return NULL;

	if (py_options == Py_None) {
		options = NULL;
	} else {
		if (!PyList_Check(py_options)) {
			PyErr_SetString(PyExc_TypeError, "options is not a list");
			return NULL;
		}
		options = talloc_array(NULL, const char *, PyList_Size(py_options));
		for (i = 0; i < PyList_Size(py_options); i++)
			options[i] = PyString_AsString(PyList_GetItem(py_options, i));
	}
	
	ret = ldb_connect(PyLdb_AsLdbContext(self), url, flags, options);
	talloc_free(options);

	PyErr_LDB_ERROR_IS_ERR_RAISE(ret, PyLdb_AsLdbContext(self));

	return Py_None;
}

static PyObject *py_ldb_modify(PyLdbObject *self, PyObject *args)
{
	PyObject *py_msg;
	int ret;
	if (!PyArg_ParseTuple(args, "O", &py_msg))
		return NULL;

	if (!PyLdbMessage_Check(py_msg)) {
		PyErr_SetString(PyExc_TypeError, "Expected Ldb Message");
		return NULL;
	}

	ret = ldb_modify(PyLdb_AsLdbContext(self), PyLdbMessage_AsMessage(py_msg));
	PyErr_LDB_ERROR_IS_ERR_RAISE(ret, PyLdb_AsLdbContext(self));

	return Py_None;
}

static PyObject *py_ldb_add(PyLdbObject *self, PyObject *args)
{
	PyObject *py_msg;
	int ret;
    Py_ssize_t dict_pos, msg_pos;
    struct ldb_message_element *msgel;
	struct ldb_message *msg;
    PyObject *key, *value;

	if (!PyArg_ParseTuple(args, "O", &py_msg))
		return NULL;

    if (PyDict_Check(py_msg)) {
		PyObject *dn_value = PyDict_GetItemString(py_msg, "dn");
        msg = ldb_msg_new(NULL);
        msg->elements = talloc_zero_array(msg, struct ldb_message_element, PyDict_Size(py_msg));
        msg_pos = dict_pos = 0;
		if (dn_value) {
           	if (PyObject_AsDn(msg, dn_value, PyLdb_AsLdbContext(self), &msg->dn) != 0) {
           		PyErr_SetString(PyExc_TypeError, "unable to import dn object");
				return NULL;
			}
			if (msg->dn == NULL) {
				PyErr_SetString(PyExc_TypeError, "dn set but not found");
				return NULL;
			}
		}

		while (PyDict_Next(py_msg, &dict_pos, &key, &value)) {
			char *key_str = PyString_AsString(key);
			if (strcmp(key_str, "dn") != 0) {
				msgel = PyObject_AsMessageElement(msg->elements, value, 0, key_str);
				if (msgel == NULL) {
					PyErr_SetString(PyExc_TypeError, "unable to import element");
					return NULL;
				}
				memcpy(&msg->elements[msg_pos], msgel, sizeof(*msgel));
				msg_pos++;
			}
		}

		if (msg->dn == NULL) {
			PyErr_SetString(PyExc_TypeError, "no dn set");
			return NULL;
		}

		msg->num_elements = msg_pos;
    } else {
		msg = PyLdbMessage_AsMessage(py_msg);
    }
	
	ret = ldb_add(PyLdb_AsLdbContext(self), msg);
	PyErr_LDB_ERROR_IS_ERR_RAISE(ret, PyLdb_AsLdbContext(self));

	return Py_None;
}



static PyObject *py_ldb_delete(PyLdbObject *self, PyObject *args)
{
	PyObject *py_dn;
	struct ldb_dn *dn;
	int ret;
	if (!PyArg_ParseTuple(args, "O", &py_dn))
		return NULL;

	if (!PyLdbDn_Check(py_dn)) {
		PyErr_SetString(PyExc_TypeError, "Expected Ldb Dn");
		return NULL;
	}

	dn = PyLdbDn_AsDn(py_dn);

	ret = ldb_delete(PyLdb_AsLdbContext(self), dn);
	PyErr_LDB_ERROR_IS_ERR_RAISE(ret, PyLdb_AsLdbContext(self));

	return Py_None;
}

static PyObject *py_ldb_rename(PyLdbObject *self, PyObject *args)
{
	PyObject *py_dn1, *py_dn2;
	struct ldb_dn *dn1, *dn2;
	int ret;
	if (!PyArg_ParseTuple(args, "OO", &py_dn1, &py_dn2))
		return NULL;

	if (!PyLdbDn_Check(py_dn1) || !PyLdbDn_Check(py_dn2)) {
		PyErr_SetString(PyExc_TypeError, "Expected Ldb Dn");
		return NULL;
	}

	dn1 = PyLdbDn_AsDn(py_dn1);
	dn2 = PyLdbDn_AsDn(py_dn2);

	ret = ldb_rename(PyLdb_AsLdbContext(self), dn1, dn2);
	PyErr_LDB_ERROR_IS_ERR_RAISE(ret, PyLdb_AsLdbContext(self));

	return Py_None;
}



static PyObject *py_ldb_schema_attribute_remove(PyLdbObject *self, PyObject *args)
{
	char *name;
	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	ldb_schema_attribute_remove(PyLdb_AsLdbContext(self), name);

	return Py_None;
}

static PyObject *py_ldb_schema_attribute_add(PyLdbObject *self, PyObject *args)
{
	char *attribute, *syntax;
	unsigned int flags;
	int ret;
	if (!PyArg_ParseTuple(args, "sIs", &attribute, &flags, &syntax))
		return NULL;

	ret = ldb_schema_attribute_add(PyLdb_AsLdbContext(self), attribute, flags, syntax);

	PyErr_LDB_ERROR_IS_ERR_RAISE(ret, PyLdb_AsLdbContext(self));

	return Py_None;
}

static PyObject *ldb_ldif_to_pyobject(struct ldb_ldif *ldif)
{
	if (ldif == NULL) {
		return Py_None;
	} else {
	/* We don't want this attached to the 'ldb' any more */
		talloc_steal(NULL, ldif);
		return Py_BuildValue((char *)"(iO)", ldif->changetype, 
							 PyLdbMessage_FromMessage(ldif->msg));
	}
}


static PyObject *py_ldb_parse_ldif(PyLdbObject *self, PyObject *args)
{
	char *filename;
	PyObject *list;
	struct ldb_ldif *ldif;
	const char *s;

	if (!PyArg_ParseTuple(args, "s", &filename))
		return NULL;

	list = PyList_New(0);
	while ((ldif = ldb_ldif_read_string(self->ptr, &s)) != NULL) {
		PyList_Append(list, ldb_ldif_to_pyobject(ldif));
	}
	return PyObject_GetIter(list);
}

static PyObject *py_ldb_schema_format_value(PyLdbObject *self, PyObject *args)
{
	const struct ldb_schema_attribute *a;
	struct ldb_val old_val;
	struct ldb_val new_val;
	TALLOC_CTX *mem_ctx;
	PyObject *ret;
	char *element_name;
	PyObject *val;

	if (!PyArg_ParseTuple(args, "sO", &element_name, &val))
		return NULL;
	
	mem_ctx = talloc_new(NULL);
	
	old_val.data = (uint8_t *)PyString_AsString(val);
	old_val.length = PyString_Size(val);
		
	a = ldb_schema_attribute_by_name(PyLdb_AsLdbContext(self), element_name);

	if (a == NULL) {
		return Py_None;
	}
	
	if (a->syntax->ldif_write_fn(PyLdb_AsLdbContext(self), mem_ctx, &old_val, &new_val) != 0) {
		talloc_free(mem_ctx);
		return Py_None;
	}

	ret = PyString_FromStringAndSize((const char *)new_val.data, new_val.length);

	talloc_free(mem_ctx);

	return ret;
}

static PyMethodDef py_ldb_methods[] = {
	{ "set_debug", (PyCFunction)py_ldb_set_debug, METH_VARARGS, 
		"S.set_debug(callback) -> None\n"
		"Set callback for LDB debug messages.\n"
		"The callback should accept a debug level and debug text." },
	{ "set_create_perms", (PyCFunction)py_ldb_set_create_perms, METH_VARARGS, 
		"S.set_create_perms(mode) -> None\n"
		"Set mode to use when creating new LDB files." },
	{ "set_modules_dir", (PyCFunction)py_ldb_set_modules_dir, METH_VARARGS,
		"S.set_modules_dir(path) -> None\n"
		"Set path LDB should search for modules" },
	{ "transaction_start", (PyCFunction)py_ldb_transaction_start, METH_NOARGS, 
		"S.transaction_start() -> None\n"
		"Start a new transaction." },
	{ "transaction_commit", (PyCFunction)py_ldb_transaction_commit, METH_NOARGS, 
		"S.transaction_commit() -> None\n"
		"commit a new transaction." },
	{ "transaction_cancel", (PyCFunction)py_ldb_transaction_cancel, METH_NOARGS, 
		"S.transaction_cancel() -> None\n"
		"cancel a new transaction." },
	{ "setup_wellknown_attributes", (PyCFunction)py_ldb_setup_wellknown_attributes, METH_NOARGS, 
		NULL },
	{ "get_root_basedn", (PyCFunction)py_ldb_get_root_basedn, METH_NOARGS,
		NULL },
	{ "get_schema_basedn", (PyCFunction)py_ldb_get_schema_basedn, METH_NOARGS,
		NULL },
	{ "get_default_basedn", (PyCFunction)py_ldb_get_default_basedn, METH_NOARGS,
		NULL },
	{ "get_config_basedn", (PyCFunction)py_ldb_get_config_basedn, METH_NOARGS,
		NULL },
	{ "connect", (PyCFunction)py_ldb_connect, METH_VARARGS|METH_KEYWORDS, 
		"S.connect(url,flags=0,options=None) -> None\n"
		"Connect to a LDB URL." },
	{ "modify", (PyCFunction)py_ldb_modify, METH_VARARGS, 
		"S.modify(message) -> None\n"
		"Modify an entry." },
	{ "add", (PyCFunction)py_ldb_add, METH_VARARGS, 
		"S.add(message) -> None\n"
		"Add an entry." },
	{ "delete", (PyCFunction)py_ldb_delete, METH_VARARGS,
		"S.delete(dn) -> None\n"
		"Remove an entry." },
	{ "rename", (PyCFunction)py_ldb_rename, METH_VARARGS,
		"S.rename(old_dn, new_dn) -> None\n"
		"Rename an entry." },
	{ "schema_attribute_remove", (PyCFunction)py_ldb_schema_attribute_remove, METH_VARARGS,
		NULL },
	{ "schema_attribute_add", (PyCFunction)py_ldb_schema_attribute_add, METH_VARARGS,
		NULL },
	{ "schema_format_value", (PyCFunction)py_ldb_schema_format_value, METH_VARARGS,
		NULL },
	{ "parse_ldif", (PyCFunction)py_ldb_parse_ldif, METH_VARARGS,
		"S.parse_ldif(ldif) -> iter(messages)\n"
        "Parse a string formatted using LDIF." },
	{ NULL },
};

PyObject *PyLdbModule_FromModule(struct ldb_module *mod)
{
	return py_talloc_import(&PyLdbModule, mod);
}

static PyObject *py_ldb_get_firstmodule(PyLdbObject *self, void *closure)
{
	return PyLdbModule_FromModule(PyLdb_AsLdbContext(self)->modules);
}

static PyGetSetDef py_ldb_getset[] = {
	{ (char *)"firstmodule", (getter)py_ldb_get_firstmodule, NULL, NULL },
	{ NULL }
};

PyTypeObject PyLdb = {
	.tp_name = "Ldb",
	.tp_methods = py_ldb_methods,
	.tp_repr = (reprfunc)py_ldb_repr,
	.tp_new = py_ldb_new,
	.tp_dealloc = py_talloc_dealloc,
	.tp_getset = py_ldb_getset,
	.tp_basicsize = sizeof(PyLdbObject),
	.tp_doc = "Connection to a LDB database.",
};

static PyObject *py_ldb_module_repr(PyLdbModuleObject *self)
{
	return PyString_FromFormat("<ldb module '%s'>", PyLdbModule_AsModule(self)->ops->name);
}

static PyObject *py_ldb_module_str(PyLdbModuleObject *self)
{
	return PyString_FromString(PyLdbModule_AsModule(self)->ops->name);
}

static PyObject *py_ldb_module_start_transaction(PyLdbModuleObject *self)
{
	PyLdbModule_AsModule(self)->ops->start_transaction(PyLdbModule_AsModule(self));
	return Py_None;
}

static PyObject *py_ldb_module_end_transaction(PyLdbModuleObject *self)
{
	PyLdbModule_AsModule(self)->ops->end_transaction(PyLdbModule_AsModule(self));
	return Py_None;
}

static PyObject *py_ldb_module_del_transaction(PyLdbModuleObject *self)
{
	PyLdbModule_AsModule(self)->ops->del_transaction(PyLdbModule_AsModule(self));
	return Py_None;
}

static PyObject *py_ldb_module_search(PyLdbModuleObject *self, PyObject *args, PyObject *kwargs)
{
	PyObject *py_base, *py_tree, *py_attrs;
	int ret, scope;
	struct ldb_request *req;
	const char *kwnames[] = { "base", "scope", "tree", "attrs", NULL };
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OiOO", (char **)kwnames, 
									 &py_base, &scope, &py_tree, &py_attrs))
		return NULL;

	req = talloc_zero(NULL, struct ldb_request);

	req->operation = LDB_SEARCH;
	req->op.search.base = PyLdbDn_AsDn(py_base);
	req->op.search.scope = scope;
	req->op.search.tree = PyLdbTree_AsTree(py_tree);
	req->op.search.attrs = attrs;

	req->op.search.res = talloc_zero(NULL, struct ldb_result);

	ret = PyLdbModule_AsModule(self)->ops->search(PyLdbModule_AsModule(self), req);
	talloc_free(req);

	PyErr_LDB_ERROR_IS_ERR_RAISE(ret, NULL);

	return PyLdbResult_FromResult(req->op.search.res);
}


static PyObject *py_ldb_module_add(PyLdbModuleObject *self, PyObject *args)
{
	struct ldb_request *req;
	PyObject *py_message;
	int ret;

	if (!PyArg_ParseTuple(args, "O", &py_message))
		return NULL;

	req = talloc_zero(NULL, struct ldb_request);
	req->operation = LDB_ADD;
	req->op.add.message = PyLdbMessage_AsMessage(py_message);

	ret = PyLdbModule_AsModule(self)->ops->add(PyLdbModule_AsModule(self), req);

	PyErr_LDB_ERROR_IS_ERR_RAISE(ret, NULL);

	return Py_None;
}

static PyObject *py_ldb_module_modify(PyLdbModuleObject *self, PyObject *args) 
{
	int ret;
	struct ldb_request *req;
	PyObject *py_message;

	if (!PyArg_ParseTuple(args, "O", &py_message))
		return NULL;
	
	req = talloc_zero(NULL, struct ldb_request);
	req->operation = LDB_MODIFY;
	req->op.mod.message = PyLdbMessage_AsMessage(py_message);
	
	ret = PyLdbModule_AsModule(self)->ops->modify(PyLdbModule_AsModule(self), req);

	PyErr_LDB_ERROR_IS_ERR_RAISE(ret, NULL);

	return Py_None;
}

static PyObject *py_ldb_module_delete(PyLdbModuleObject *self, PyObject *args) 
{
	int ret;
	struct ldb_request *req;
	PyObject *py_dn;

	if (!PyArg_ParseTuple(args, "O", &py_dn))
		return NULL;
	
	req = talloc_zero(NULL, struct ldb_request);
	req->operation = LDB_DELETE;
	req->op.del.dn = PyLdbDn_AsDn(py_dn);
	
	ret = PyLdbModule_AsModule(self)->ops->del(PyLdbModule_AsModule(self), req);

	PyErr_LDB_ERROR_IS_ERR_RAISE(ret, NULL);

	return Py_None;
}

static PyObject *py_ldb_module_rename(PyLdbModuleObject *self, PyObject *args)
{
	int ret;
	struct ldb_request *req;
	PyObject *py_dn1, *py_dn2;

	if (!PyArg_ParseTuple(args, "OO", &py_dn1, &py_dn2))
		return NULL;
	
	req = talloc_zero(NULL, struct ldb_request);

	req->operation = LDB_RENAME;
	req->op.rename.olddn = PyLdbDn_AsDn(py_dn1);
	req->op.rename.newdn = PyLdbDn_AsDn(py_dn2);
	
	ret = PyLdbModule_AsModule(self)->ops->rename(PyLdbModule_AsModule(self), req);

	PyErr_LDB_ERROR_IS_ERR_RAISE(ret, NULL);

	return Py_None;
}

static PyMethodDef py_ldb_module_methods[] = {
	{ "search", (PyCFunction)py_ldb_module_search, METH_VARARGS|METH_KEYWORDS, NULL },
	{ "add", (PyCFunction)py_ldb_module_add, METH_VARARGS, NULL },
	{ "modify", (PyCFunction)py_ldb_module_modify, METH_VARARGS, NULL },
	{ "rename", (PyCFunction)py_ldb_module_rename, METH_VARARGS, NULL },
	{ "delete", (PyCFunction)py_ldb_module_delete, METH_VARARGS, NULL },
	{ "start_transaction", (PyCFunction)py_ldb_module_start_transaction, METH_NOARGS, NULL },
	{ "end_transaction", (PyCFunction)py_ldb_module_end_transaction, METH_NOARGS, NULL },
	{ "del_transaction", (PyCFunction)py_ldb_module_del_transaction, METH_NOARGS, NULL },
	{ NULL },
};

PyTypeObject PyLdbModule = {
	.tp_name = "LdbModule",
	.tp_methods = py_ldb_module_methods,
	.tp_repr = (reprfunc)py_ldb_module_repr,
	.tp_str = (reprfunc)py_ldb_module_str,
	.tp_basicsize = sizeof(py_talloc_Object),
	.tp_dealloc = py_talloc_dealloc,
};

struct ldb_message_element *PyLdbMessagElement_AsMsgElement(TALLOC_CTX *mem_ctx,
                                               PyObject *set_obj, int flags,
                                               const char *attr_name)
{
    struct ldb_message_element *me = talloc(mem_ctx, struct ldb_message_element);

    me->name = attr_name;
    me->flags = flags;
    if (PyString_Check(set_obj)) {
        me->num_values = 1;
        me->values = talloc_array(me, struct ldb_val, me->num_values);
        me->values[0].length = PyString_Size(set_obj);
        me->values[0].data = (uint8_t *)talloc_strdup(me->values, 
                                           PyString_AsString(set_obj));
    } else if (PySequence_Check(set_obj)) {
        int i;
        me->num_values = PySequence_Size(set_obj);
        me->values = talloc_array(me, struct ldb_val, me->num_values);
        for (i = 0; i < me->num_values; i++) {
            PyObject *obj = PySequence_GetItem(set_obj, i);
            me->values[i].length = PyString_Size(obj);
            me->values[i].data = (uint8_t *)PyString_AsString(obj);
        }
    } else {
        talloc_free(me);
        me = NULL;
    }

    return me;
}


PyObject *ldb_msg_element_to_set(struct ldb_context *ldb_ctx, 
                                 struct ldb_message_element *me)
{
    int i;
    PyObject *result;

    /* Python << 2.5 doesn't have PySet_New and PySet_Add. */
    result = PyList_New(me->num_values);

    for (i = 0; i < me->num_values; i++) {
        PyList_SetItem(result, i,
            PyObject_FromLdbValue(ldb_ctx, me, &me->values[i]));
    }

    return result;
}

PyObject *py_ldb_msg_element_get(PyLdbMessageElementObject *self, PyObject *args)
{
	int i;
	if (!PyArg_ParseTuple(args, "i", &i))
		return NULL;
	if (i < 0 || i >= PyLdbMessageElement_AsMessageElement(self)->num_values)
		return Py_None;

	return PyObject_FromLdbValue(NULL, PyLdbMessageElement_AsMessageElement(self), 
								 &(PyLdbMessageElement_AsMessageElement(self)->values[i]));
}

static PyMethodDef py_ldb_msg_element_methods[] = {
	{ "get", (PyCFunction)py_ldb_msg_element_get, METH_VARARGS, NULL },
	{ NULL },
};

PyTypeObject PyLdbMessageElement = {
	.tp_name = "MessageElement",
	.tp_basicsize = sizeof(PyLdbMessageElementObject),
	.tp_dealloc = py_talloc_dealloc,
	.tp_methods = py_ldb_msg_element_methods,
};

static PyObject *py_ldb_msg_remove_attr(PyLdbMessageObject *self, PyObject *args)
{
	char *name;
	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	ldb_msg_remove_attr(self->ptr, name);

	return Py_None;
}

static PyMethodDef py_ldb_msg_methods[] = { 
	{ "remove", (PyCFunction)py_ldb_msg_remove_attr, METH_VARARGS, NULL },
	{ NULL },
};

static PyObject *py_ldb_msg_getitem(PyLdbMessageObject *self, PyObject *name)
{
	struct ldb_message_element *el;
	el = ldb_msg_find_element(PyLdbMessage_AsMessage(self), PyString_AsString(name));
	if (el == NULL)
		return NULL;
	return PyLdbMessageElement_FromMessageElement(el);
}

static PyObject *py_ldb_msg_setitem(PyLdbMessageObject *self, PyObject *name, PyObject *value)
{
	if (value == NULL) {
		ldb_msg_remove_attr(self->ptr, PyString_AsString(name));
	} else {
		/* FIXME */
	}
	return Py_None;
}

static PyMappingMethods py_ldb_msg_mapping = {
	.mp_subscript = (binaryfunc)py_ldb_msg_getitem,
	.mp_ass_subscript = (objobjargproc)py_ldb_msg_setitem,
};

static PyObject *py_ldb_msg_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	char *kwnames[] = { NULL };
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "", kwnames))
		return NULL;

	return py_talloc_import(&PyLdbMessage, ldb_msg_new(NULL)); 
}

PyObject *PyLdbMessage_FromMessage(struct ldb_message *msg)
{
	return py_talloc_import(&PyLdbMessage, msg);
}

PyTypeObject PyLdbMessage = {
	.tp_name = "Message",
	.tp_methods = py_ldb_msg_methods,
	.tp_as_mapping = &py_ldb_msg_mapping,
	.tp_basicsize = sizeof(PyLdbMessageObject),
	.tp_dealloc = py_talloc_dealloc,
	.tp_new = py_ldb_msg_new,
};

/* Ldb_module */
int py_module_search(struct ldb_module *mod, struct ldb_request *req)
{
    PyObject *py_ldb = mod->private_data;
    PyObject *py_result, *py_base, *py_attrs, *py_tree;

    py_base = PyLdbDn_FromDn(req->op.search.base);

    if (py_base == NULL)
        return LDB_ERR_OPERATIONS_ERROR;

    py_tree = PyLdbTree_FromTree(req->op.search.tree);

    if (py_tree == NULL)
        return LDB_ERR_OPERATIONS_ERROR;

    if (req->op.search.attrs == NULL) {
        py_attrs = Py_None;
    } else {
        int i, len;
        for (len = 0; req->op.search.attrs[len]; len++);
        py_attrs = PyList_New(len);
        for (i = 0; i < len; i++)
            PyList_SetItem(py_attrs, i, PyString_FromString(req->op.search.attrs[i]));
    }

    py_result = PyObject_CallMethod(py_ldb, (char *)"search", (char *)"OiOO", py_base, req->op.search.scope, py_tree, py_attrs);

    Py_DECREF(py_attrs);
    Py_DECREF(py_tree);
    Py_DECREF(py_base);

    if (py_result == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

	req->op.search.res = PyLdbResult_AsResult(py_result);
	if (req->op.search.res == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    Py_DECREF(py_result);

    return LDB_SUCCESS;
}

int py_module_add(struct ldb_module *mod, struct ldb_request *req)
{
    PyObject *py_ldb = mod->private_data;
    PyObject *py_result, *py_msg;

    py_msg = PyLdbMessage_FromMessage(req->op.add.message);

    if (py_msg == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    py_result = PyObject_CallMethod(py_ldb, (char *)"add", (char *)"O", py_msg);

    Py_DECREF(py_msg);

    if (py_result == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    Py_DECREF(py_result);

    return LDB_SUCCESS;
}

int py_module_modify(struct ldb_module *mod, struct ldb_request *req)
{
    PyObject *py_ldb = mod->private_data;
    PyObject *py_result, *py_msg;

    py_msg = PyLdbMessage_FromMessage(req->op.mod.message);

    if (py_msg == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    py_result = PyObject_CallMethod(py_ldb, (char *)"modify", (char *)"O", py_msg);

    Py_DECREF(py_msg);

    if (py_result == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    Py_DECREF(py_result);

    return LDB_SUCCESS;
}

int py_module_del(struct ldb_module *mod, struct ldb_request *req)
{
    PyObject *py_ldb = mod->private_data;
    PyObject *py_result, *py_dn;

    py_dn = PyLdbDn_FromDn(req->op.del.dn);

    if (py_dn == NULL)
        return LDB_ERR_OPERATIONS_ERROR;

    py_result = PyObject_CallMethod(py_ldb, (char *)"delete", (char *)"O", py_dn);

    if (py_result == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    Py_DECREF(py_result);

    return LDB_SUCCESS;
}

int py_module_rename(struct ldb_module *mod, struct ldb_request *req)
{
    PyObject *py_ldb = mod->private_data;
    PyObject *py_result, *py_olddn, *py_newdn;

    py_olddn = PyLdbDn_FromDn(req->op.rename.olddn);

    if (py_olddn == NULL)
        return LDB_ERR_OPERATIONS_ERROR;

    py_newdn = PyLdbDn_FromDn(req->op.rename.newdn);

    if (py_newdn == NULL)
        return LDB_ERR_OPERATIONS_ERROR;

    py_result = PyObject_CallMethod(py_ldb, (char *)"rename", (char *)"OO", py_olddn, py_newdn);

    Py_DECREF(py_olddn);
    Py_DECREF(py_newdn);

    if (py_result == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    Py_DECREF(py_result);

    return LDB_SUCCESS;
}

int py_module_request(struct ldb_module *mod, struct ldb_request *req)
{
    PyObject *py_ldb = mod->private_data;
    PyObject *py_result;

    py_result = PyObject_CallMethod(py_ldb, (char *)"request", (char *)"");

    return LDB_ERR_OPERATIONS_ERROR;
}

int py_module_extended(struct ldb_module *mod, struct ldb_request *req)
{
    PyObject *py_ldb = mod->private_data;
    PyObject *py_result;

    py_result = PyObject_CallMethod(py_ldb, (char *)"extended", (char *)"");

    return LDB_ERR_OPERATIONS_ERROR;
}

int py_module_start_transaction(struct ldb_module *mod)
{
    PyObject *py_ldb = mod->private_data;
    PyObject *py_result;

    py_result = PyObject_CallMethod(py_ldb, (char *)"start_transaction", (char *)"");

    if (py_result == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    Py_DECREF(py_result);

    return LDB_SUCCESS;
}

int py_module_end_transaction(struct ldb_module *mod)
{
    PyObject *py_ldb = mod->private_data;
    PyObject *py_result;

    py_result = PyObject_CallMethod(py_ldb, (char *)"end_transaction", (char *)"");

    if (py_result == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    Py_DECREF(py_result);

    return LDB_SUCCESS;
}

int py_module_del_transaction(struct ldb_module *mod)
{
    PyObject *py_ldb = mod->private_data;
    PyObject *py_result;

    py_result = PyObject_CallMethod(py_ldb, (char *)"del_transaction", (char *)"");

    if (py_result == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    Py_DECREF(py_result);

    return LDB_SUCCESS;
}

static int py_module_destructor(void *_mod)
{
    struct ldb_module *mod = _mod;
    Py_DECREF((PyObject *)mod->private_data);
    return 0;
}

int py_module_init (struct ldb_module *mod)
{
    PyObject *py_class = mod->ops->private_data;
    PyObject *py_result, *py_next, *py_ldb;

    py_ldb = SWIG_NewPointerObj(mod->ldb, SWIGTYPE_p_ldb_context, 0);

    if (py_ldb == NULL)
        return LDB_ERR_OPERATIONS_ERROR;

    py_next = PyLdbModule_FromModule(mod->next);

    if (py_next == NULL)
        return LDB_ERR_OPERATIONS_ERROR;

    py_result = PyObject_CallFunction(py_class, (char *)"OO", py_ldb, py_next);

    if (py_result == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    mod->private_data = py_result;

    talloc_set_destructor (mod, py_module_destructor);

    return ldb_next_init(mod);
}

static PyObject *py_register_module(PyObject *module, PyObject *args)
{
	int ret;
	struct ldb_module_ops *ops;
	PyObject *input;

	if (!PyArg_ParseTuple(args, "O", &input))
		return NULL;

    ops = talloc_zero(talloc_autofree_context(), struct ldb_module_ops);
	if (ops == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

    ops->name = talloc_strdup(ops, PyString_AsString(PyObject_GetAttrString(input, (char *)"name")));

    Py_INCREF(input);
    ops->private_data = input;
    ops->init_context = py_module_init;
    ops->search = py_module_search;
    ops->add = py_module_add;
    ops->modify = py_module_modify;
    ops->del = py_module_del;
    ops->rename = py_module_rename;
    ops->request = py_module_request;
    ops->extended = py_module_extended;
    ops->start_transaction = py_module_start_transaction;
    ops->end_transaction = py_module_end_transaction;
    ops->del_transaction = py_module_del_transaction;

	ret = ldb_register_module(ops);

	PyErr_LDB_ERROR_IS_ERR_RAISE(ret, NULL);

	return Py_None;
}

static PyObject *py_timestring(PyObject *module, PyObject *args)
{
	time_t t;
	char *tresult;
	PyObject *ret;
	if (!PyArg_ParseTuple(args, "L", &t))
		return NULL;
    tresult = ldb_timestring(NULL, t);
    ret = PyString_FromString(tresult);
    talloc_free(tresult);
    return ret;
}

static PyObject *py_string_to_time(PyObject *module, PyObject *args)
{
	char *str;
	if (!PyArg_ParseTuple(args, "s", &str))
		return NULL;

	return PyInt_FromLong(ldb_string_to_time(str));
}

static PyObject *py_valid_attr_name(PyObject *self, PyObject *args)
{
	char *name;
	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;
	return PyBool_FromLong(ldb_valid_attr_name(name));
}

static PyMethodDef py_ldb_global_methods[] = {
	{ "register_module", py_register_module, METH_VARARGS, 
		"S.register_module(module) -> None\n"
		"Register a LDB module."},
	{ "timestring", py_timestring, METH_VARARGS, 
		"S.timestring(int) -> string\n"
		"Generate a LDAP time string from a UNIX timestamp" },
	{ "string_to_time", py_string_to_time, METH_VARARGS,
		"S.string_to_time(string) -> int\n"
		"Parse a LDAP time string into a UNIX timestamp." },
	{ "valid_attr_name", py_valid_attr_name, METH_VARARGS,
		"S.valid_attr_name(name) -> bool\n"
		"Check whether the supplied name is a valid attribute name." },
	{ "open", (PyCFunction)py_ldb_new, METH_VARARGS|METH_KEYWORDS,
		NULL },
	{ NULL }
};

void initldb(void)
{
	PyObject *m;

	if (PyType_Ready(&PyLdbDn) < 0)
		return;

	if (PyType_Ready(&PyLdbMessage) < 0)
		return;

	if (PyType_Ready(&PyLdbMessageElement) < 0)
		return;

	if (PyType_Ready(&PyLdb) < 0)
		return;

	if (PyType_Ready(&PyLdbModule) < 0)
		return;

	m = Py_InitModule3("ldb", py_ldb_global_methods, 
		"An interface to LDB, a LDAP-like API that can either to talk an embedded database (TDB-based) or a standards-compliant LDAP server.");
	if (m == NULL)
		return;

	PyModule_AddObject(m, "SCOPE_DEFAULT", PyInt_FromLong(LDB_SCOPE_DEFAULT));
	PyModule_AddObject(m, "SCOPE_BASE", PyInt_FromLong(LDB_SCOPE_BASE));
	PyModule_AddObject(m, "SCOPE_ONELEVEL", PyInt_FromLong(LDB_SCOPE_ONELEVEL));
	PyModule_AddObject(m, "SCOPE_SUBTREE", PyInt_FromLong(LDB_SCOPE_SUBTREE));

	PyModule_AddObject(m, "CHANGETYPE_NONE", PyInt_FromLong(LDB_CHANGETYPE_NONE));
	PyModule_AddObject(m, "CHANGETYPE_ADD", PyInt_FromLong(LDB_CHANGETYPE_ADD));
	PyModule_AddObject(m, "CHANGETYPE_DELETE", PyInt_FromLong(LDB_CHANGETYPE_DELETE));
	PyModule_AddObject(m, "CHANGETYPE_MODIFY", PyInt_FromLong(LDB_CHANGETYPE_MODIFY));

	PyModule_AddObject(m, "__docformat__", PyString_FromString("restructuredText"));

    PyExc_LdbError = PyErr_NewException((char *)"_ldb.LdbError", NULL, NULL);
    PyModule_AddObject(m, "LdbError", PyExc_LdbError);
}

#if 0

/*
 * Wrap struct ldb_val
 */

%typemap(in,noblock=1) struct ldb_val *INPUT (struct ldb_val temp) {
	$1 = &temp;
	if (!PyString_Check($input)) {
		PyErr_SetString(PyExc_TypeError, "string arg expected");
		return NULL;
	}
	$1->length = PyString_Size($input);
	$1->data = PyString_AsString($input);
}

%inline %{


%}

%typemap(out,noblock=1) struct ldb_val * {
	$result = PyString_FromStringAndSize((const char *)$1->data, $1->length)
}

%typemap(out,noblock=1) struct ldb_val {
	$result = PyString_FromStringAndSize((const char *)$1.data, $1.length)
}

/*
 * Wrap struct ldb_result
 */

%typemap(in,noblock=1,numinputs=0) struct ldb_result ** (struct ldb_result *temp_ldb_result) {
	$1 = &temp_ldb_result;
}

%typemap(in,noblock=1,numinputs=1) const char * const *NULL_STR_LIST {
    if ($input == Py_None) {
        $1 = NULL;
    } else if (PySequence_Check($input)) {
        int i;
        $1 = talloc_array(NULL, char *, PySequence_Size($input)+1);
        for(i = 0; i < PySequence_Size($input); i++)
            $1[i] = PyString_AsString(PySequence_GetItem($input, i));
        $1[i] = NULL;
    } else {
        SWIG_exception(SWIG_TypeError, "expected sequence");
    }
}

%typemap(freearg,noblock=1) const char * const *NULL_STR_LIST {
    talloc_free($1);
}

%apply const char * const *NULL_STR_LIST { const char * const *attrs }
%apply const char * const *NULL_STR_LIST { const char * const *options }
%apply const char * const *NULL_STR_LIST { const char * const *control_strings }

/*
 * Wrap struct ldb_dn
 */

%rename(__len__) ldb_dn::get_comp_num;
typedef struct ldb_dn {
    %extend {
        %feature("docstring") ldb_dn "S.__init__(ldb, string)\n" \
                 "Create a new DN.";
        ldb_dn(ldb *ldb_ctx, const char *str)
        {
            ldb_dn *ret = ldb_dn_new(ldb_ctx, ldb_ctx, str);
            /* ldb_dn_new() doesn't accept NULL as memory context, so 
               we do it this way... */
            talloc_steal(NULL, ret);

            if (ret == NULL || !ldb_dn_validate(ret))
                SWIG_exception(SWIG_ValueError, 
                                "unable to parse dn string");
fail:
            return ret;
        }
        ~ldb_dn() { talloc_free($self); }
        %feature("docstring") parent "S.parent() -> dn\n" \
                                     "Get the parent for this DN.";
        ldb_dn *parent() { return ldb_dn_get_parent(NULL, $self); }
        int get_comp_num();
        %feature("docstring") add_child "S.add_child(dn) -> None\n" \
                                         "Add a child DN to this DN.";
        bool add_child(ldb_dn *child);
        %feature("docstring") add_base "S.add_base(dn) -> None\n" \
                                         "Add a base DN to this DN.";
        bool add_base(ldb_dn *base);
        ldb_dn *__add__(ldb_dn *other)
        {
            ldb_dn *ret = ldb_dn_copy(NULL, $self);
            ldb_dn_add_child(ret, other);
            return ret;
        }

        /* FIXME: implement __getslice__ */
    }
} ldb_dn;

%{
struct ldb_context *ldb_context_from_py_object(PyObject *py_obj)
{
        struct ldb_context *ldb_ctx;
    if (SWIG_ConvertPtr(py_obj, (void *)&ldb_ctx, SWIGTYPE_p_ldb_context, 0 |  0 ) < 0)
        return NULL;
    return ldb_ctx;
}


%}

/* ldb_message_element */
%rename(MessageElement) ldb_message_element;
%feature("docstring") ldb_message_element "Message element.";
typedef struct ldb_message_element {
    %extend {
        int __cmp__(ldb_message_element *other)
        {
            return ldb_msg_element_compare($self, other);
        }

        PyObject *__iter__(void)
        {
            return PyObject_GetIter(ldb_msg_element_to_set(NULL, $self));
        }

        PyObject *__set__(void)
        {
            return ldb_msg_element_to_set(NULL, $self);
        }

        ldb_message_element(PyObject *set_obj, int flags=0, const char *name = NULL)
        {
            return PyObject_AsMessageElement(NULL, set_obj, flags, name);
        }

        int __len__()
        {
            return $self->num_values;
        }
        ~ldb_message_element() { talloc_free($self); }
    }
    %pythoncode {
        def __getitem__(self, i):
            ret = self.get(i)
            if ret is None:
                raise KeyError("no such value")
            return ret

        def __repr__(self):
            return "MessageElement([%s])" % (",".join(repr(x) for x in self.__set__()))

        def __eq__(self, other):
            if (len(self) == 1 and self.get(0) == other):
                return True
            if isinstance(other, self.__class__):
                return self.__cmp__(other) == 0
            o = iter(other)
            for i in range(len(self)):
                if self.get(i) != o.next():
                    return False
            return True
    }
} ldb_message_element;

/* ldb_message */

%feature("docstring") ldb_message "Message.";
%rename(Message) ldb_message;
%rename(__delitem__) ldb_message::remove_attr;
%typemap(out) ldb_message_element * {
	if ($1 == NULL)
		PyErr_SetString(PyExc_KeyError, "no such element");
    else
        $result = SWIG_NewPointerObj($1, SWIGTYPE_p_ldb_message_element, 0);
}

%inline {
    PyObject *ldb_msg_list_elements(ldb_msg *msg)
    {
        int i, j = 0;
        PyObject *obj = PyList_New(msg->num_elements+(msg->dn != NULL?1:0));
        if (msg->dn != NULL) {
            PyList_SetItem(obj, j, PyString_FromString("dn"));
            j++;
        }
        for (i = 0; i < msg->num_elements; i++) {
            PyList_SetItem(obj, j, PyString_FromString(msg->elements[i].name));
            j++;
        }
        return obj;
    }
}


typedef struct ldb_message {
	ldb_dn *dn;

    %extend {
        ldb_msg(ldb_dn *dn = NULL) { 
            ret->dn = talloc_reference(ret, dn);
            return ret;
        }
        ~ldb_msg() { talloc_free($self); }
        
        void __setitem__(const char *attr_name, ldb_message_element *val)
        {
            struct ldb_message_element *el;
            
            ldb_msg_remove_attr($self, attr_name);

            el = talloc($self, struct ldb_message_element);
            el->name = talloc_strdup(el, attr_name);
            el->num_values = val->num_values;
            el->values = talloc_reference(el, val->values);

            ldb_msg_add($self, el, val->flags);
        }

        void __setitem__(const char *attr_name, PyObject *val)
        {
            struct ldb_message_element *el = PyObject_AsMessageElement(NULL,
                                                val, 0, attr_name);
            talloc_steal($self, el);
            ldb_msg_remove_attr($self, attr_name);
            ldb_msg_add($self, el, el->flags);
        }

        unsigned int __len__() { return $self->num_elements; }

        PyObject *keys(void)
        {
            return ldb_msg_list_elements($self);
        }

        PyObject *__iter__(void)
        {
            return PyObject_GetIter(ldb_msg_list_elements($self));
        }
%pythoncode {
    def get(self, key, default=None):
        if key == "dn":
            return self.dn
        return self.find_element(key)

    def __getitem__(self, key):
        ret = self.get(key, None)
        if ret is None:
            raise KeyError("No such element")
        return ret

    def iteritems(self):
        for k in self.keys():
            yield k, self[k]
    
    def items(self):
        return list(self.iteritems())

    def __repr__(self):
        return "Message(%s)" % repr(dict(self.iteritems()))
}
    }
} ldb_msg;

/* FIXME: Convert ldb_result to 3-tuple:
   (msgs, refs, controls)
 */

typedef struct ldb_ldif ldb_ldif;

%inline {
}

%typemap(out,noblock=1) struct ldb_control ** {
    if ($1 == NULL) {
        PyErr_SetObject(PyExc_LdbError, Py_BuildValue((char *)"(s)", ldb_errstring(arg1)));
        SWIG_fail;
    }
    $result = SWIG_NewPointerObj($1, $1_descriptor, 0);
}

/* Top-level ldb operations */
typedef struct ldb_context {
    %pythoncode {
        def itermodules(self):
            m = self.firstmodule
            while m is not None:
                yield m
                m = m.next

        def modules(self):
            return list(self.itermodules())
    }

    %extend {
        ldb_error search_ex(TALLOC_CTX *mem_ctx,
                   ldb_dn *base = NULL, 
                   enum ldb_scope scope = LDB_SCOPE_DEFAULT, 
                   const char *expression = NULL, 
                   const char *const *attrs = NULL, 
                   struct ldb_control **controls = NULL,
                   struct ldb_result **OUT) {
            int ret;
            struct ldb_result *res;
            struct ldb_request *req;
            res = talloc_zero(mem_ctx, struct ldb_result);
            if (!res) {
                return LDB_ERR_OPERATIONS_ERROR;
            }

            ret = ldb_build_search_req(&req, $self, mem_ctx,
                           base?base:ldb_get_default_basedn($self),
                           scope,
                           expression,
                           attrs,
                           controls,
                           res,
                           ldb_search_default_callback,
                           NULL);

            if (ret != LDB_SUCCESS) {
                talloc_free(res);
                return ret;
            }

            ret = ldb_request($self, req);
                
            if (ret == LDB_SUCCESS) {
                ret = ldb_wait(req->handle, LDB_WAIT_ALL);
            }

            talloc_free(req);

            *OUT = res;
            return ret;
        }

        struct ldb_control **parse_control_strings(TALLOC_CTX *mem_ctx, 
                                                   const char * const*control_strings);
        const char *errstring();
        %feature("docstring") set_opaque "S.set_opaque(name, value) -> None\n" \
            "Set an opaque value on this LDB connection. \n"
            ":note: Passing incorrect values may cause crashes.";
        ldb_error set_opaque(const char *name, void *value);
        %feature("docstring") get_opaque "S.get_opaque(name) -> value\n" \
            "Get an opaque value set on this LDB connection. \n"
            ":note: The returned value may not be useful in Python.";
        void *get_opaque(const char *name);
 
        %typemap(in,numinputs=0,noblock=1) struct ldb_result **result_as_bool (struct ldb_result *tmp) { $1 = &tmp; }
        %typemap(argout,noblock=1) struct ldb_result **result_as_bool { $result = ((*$1)->count > 0)?Py_True:Py_False; }
        %typemap(freearg,noblock=1) struct ldb_result **result_as_bool { talloc_free(*$1); }
        ldb_error __contains__(ldb_dn *dn, struct ldb_result **result_as_bool)
        {
            return ldb_search($self, $self, result_as_bool, dn, LDB_SCOPE_BASE, NULL, NULL);
        }
    }
    %pythoncode {
        def __init__(self, url=None, flags=0, options=None):
            """Create a new LDB object.

            Will also connect to the specified URL if one was given.
            """
            _ldb.Ldb_swiginit(self,_ldb.new_Ldb())
            if url is not None:
                self.connect(url, flags, options)

        def search(self, base=None, scope=SCOPE_DEFAULT, expression=None, 
                   attrs=None, controls=None):
            """Search in a database.

            :param base: Optional base DN to search
            :param scope: Search scope (SCOPE_BASE, SCOPE_ONELEVEL or SCOPE_SUBTREE)
            :param expression: Optional search expression
            :param attrs: Attributes to return (defaults to all)
            :param controls: Optional list of controls
            :return: Iterator over Message objects
            """
            if not (attrs is None or isinstance(attrs, list)):
                raise TypeError("attributes not a list")
            parsed_controls = None
            if controls is not None:
                parsed_controls = self.parse_control_strings(controls)
            return self.search_ex(base, scope, expression, attrs, 
                                  parsed_controls)
    }

} ldb;
#endif
