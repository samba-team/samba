/*
   Unix SMB/CIFS implementation.

   Python interface to ldb.

   Copyright (C) 2005,2006 Tim Potter <tpot@samba.org>
   Copyright (C) 2006 Simo Sorce <idra@samba.org>
   Copyright (C) 2007-2010 Jelmer Vernooij <jelmer@samba.org>
   Copyright (C) 2009-2010 Matthias Dieter Wallnöfer
   Copyright (C) 2009-2011 Andrew Tridgell
   Copyright (C) 2009-2011 Andrew Bartlett

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

#include <Python.h>
#include "ldb_private.h"
#include "ldb_handlers.h"
#include "pyldb.h"
#include "dlinklist.h"

/* discard signature of 'func' in favour of 'target_sig' */
#define PY_DISCARD_FUNC_SIG(target_sig, func) (target_sig)(void(*)(void))func

struct py_ldb_search_iterator_reply;

typedef struct {
	PyObject_HEAD
	TALLOC_CTX *mem_ctx;
	PyLdbObject *ldb;
	struct {
		struct ldb_request *req;
		struct py_ldb_search_iterator_reply *next;
		struct py_ldb_search_iterator_reply *result;
		PyObject *exception;
	} state;
} PyLdbSearchIteratorObject;

struct py_ldb_search_iterator_reply {
	struct py_ldb_search_iterator_reply *prev, *next;
	PyLdbSearchIteratorObject *py_iter;
	PyObject *obj;
};

void initldb(void);
static PyObject *PyLdbMessage_FromMessage(struct ldb_message *msg);
static PyObject *PyExc_LdbError;

static PyTypeObject PyLdbControl;
static PyTypeObject PyLdbResult;
static PyTypeObject PyLdbSearchIterator;
static PyTypeObject PyLdbMessage;
#define PyLdbMessage_Check(ob) PyObject_TypeCheck(ob, &PyLdbMessage)
static PyTypeObject PyLdbModule;
static PyTypeObject PyLdbDn;
#define pyldb_Dn_Check(ob) PyObject_TypeCheck(ob, &PyLdbDn)
static PyTypeObject PyLdb;
#define PyLdb_Check(ob) PyObject_TypeCheck(ob, &PyLdb)
static PyTypeObject PyLdbMessageElement;
#define pyldb_MessageElement_Check(ob) PyObject_TypeCheck(ob, &PyLdbMessageElement)

static PyTypeObject PyLdbTree;
static PyObject *PyLdb_FromLdbContext(struct ldb_context *ldb_ctx);
static PyObject *PyLdbModule_FromModule(struct ldb_module *mod);
static struct ldb_message_element *PyObject_AsMessageElement(
						      TALLOC_CTX *mem_ctx,
						      PyObject *set_obj,
						      unsigned int flags,
						      const char *attr_name);
static PyTypeObject PyLdbBytesType;

#if PY_MAJOR_VERSION >= 3

#define PYARG_STR_UNI "es"

static PyObject *PyLdbBytes_FromStringAndSize(const char *msg, int size)
{
	PyObject* result = NULL;
	PyObject* args = NULL;
	args = Py_BuildValue("(y#)", msg, size);
	result = PyLdbBytesType.tp_new(&PyLdbBytesType, args, NULL);
	Py_DECREF(args);
	return result;
}
#else
#define PyLdbBytes_FromStringAndSize PyString_FromStringAndSize

#define PYARG_STR_UNI "et"

#endif

static PyObject *richcmp(int cmp_val, int op)
{
	int ret;
	switch (op) {
		case Py_LT: ret = cmp_val < 0;  break;
		case Py_LE: ret = cmp_val <= 0; break;
		case Py_EQ: ret = cmp_val == 0; break;
		case Py_NE: ret = cmp_val != 0; break;
		case Py_GT: ret = cmp_val > 0;  break;
		case Py_GE: ret = cmp_val >= 0; break;
		default:
			Py_INCREF(Py_NotImplemented);
			return Py_NotImplemented;
	}
	return PyBool_FromLong(ret);
}


static PyObject *py_ldb_control_str(PyLdbControlObject *self)
{
	if (self->data != NULL) {
		char* control = ldb_control_to_string(self->mem_ctx, self->data);
		if (control == NULL) {
			PyErr_NoMemory();
			return NULL;
		}
		return PyUnicode_FromString(control);
	} else {
		return PyUnicode_FromString("ldb control");
	}
}

static void py_ldb_control_dealloc(PyLdbControlObject *self)
{
	if (self->mem_ctx != NULL) {
		talloc_free(self->mem_ctx);
	}
	self->data = NULL;
	Py_TYPE(self)->tp_free(self);
}

/* Create a text (rather than bytes) interface for a LDB result object */
static PyObject *wrap_text(const char *type, PyObject *wrapped)
{
	PyObject *mod, *cls, *constructor, *inst;
	mod = PyImport_ImportModule("_ldb_text");
	if (mod == NULL)
		return NULL;
	cls = PyObject_GetAttrString(mod, type);
	Py_DECREF(mod);
	if (cls == NULL) {
		Py_DECREF(mod);
		return NULL;
	}
	constructor = PyObject_GetAttrString(cls, "_wrap");
	Py_DECREF(cls);
	if (constructor == NULL) {
		return NULL;
	}
	inst = PyObject_CallFunction(constructor, discard_const_p(char, "O"), wrapped);
	Py_DECREF(constructor);
	return inst;
}

static PyObject *py_ldb_control_get_oid(PyLdbControlObject *self,
		PyObject *Py_UNUSED(ignored))
{
	return PyUnicode_FromString(self->data->oid);
}

static PyObject *py_ldb_control_get_critical(PyLdbControlObject *self,
		PyObject *Py_UNUSED(ignored))
{
	return PyBool_FromLong(self->data->critical);
}

static int py_ldb_control_set_critical(PyLdbControlObject *self, PyObject *value, void *closure)
{
	if (value == NULL) {
		PyErr_SetString(PyExc_AttributeError, "cannot delete critical flag");
		return -1;
	}
	if (PyObject_IsTrue(value)) {
		self->data->critical = true;
	} else {
		self->data->critical = false;
	}
	return 0;
}

static PyObject *py_ldb_control_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	char *data = NULL;
	const char * const kwnames[] = { "ldb", "data", NULL };
	struct ldb_control *parsed_controls;
	PyLdbControlObject *ret;
	PyObject *py_ldb;
	TALLOC_CTX *mem_ctx;
	struct ldb_context *ldb_ctx;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!s",
					 discard_const_p(char *, kwnames),
					 &PyLdb, &py_ldb, &data))
		return NULL;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	ldb_ctx = pyldb_Ldb_AS_LDBCONTEXT(py_ldb);
	parsed_controls = ldb_parse_control_from_string(ldb_ctx, mem_ctx, data);

	if (!parsed_controls) {
		talloc_free(mem_ctx);
		PyErr_SetString(PyExc_ValueError, "unable to parse control string");
		return NULL;
	}

	ret = PyObject_New(PyLdbControlObject, type);
	if (ret == NULL) {
		PyErr_NoMemory();
		talloc_free(mem_ctx);
		return NULL;
	}

	ret->mem_ctx = mem_ctx;

	ret->data = talloc_move(mem_ctx, &parsed_controls);
	if (ret->data == NULL) {
		Py_DECREF(ret);
		PyErr_NoMemory();
		talloc_free(mem_ctx);
		return NULL;
	}

	return (PyObject *)ret;
}

static PyGetSetDef py_ldb_control_getset[] = {
	{
		.name = discard_const_p(char, "oid"),
		.get  = (getter)py_ldb_control_get_oid,
	},
	{
		.name = discard_const_p(char, "critical"),
		.get  = (getter)py_ldb_control_get_critical,
		.set  = (setter)py_ldb_control_set_critical,
	},
	{ .name = NULL },
};

static PyTypeObject PyLdbControl = {
	.tp_name = "ldb.control",
	.tp_dealloc = (destructor)py_ldb_control_dealloc,
	.tp_getattro = PyObject_GenericGetAttr,
	.tp_basicsize = sizeof(PyLdbControlObject),
	.tp_getset = py_ldb_control_getset,
	.tp_doc = "LDB control.",
	.tp_str = (reprfunc)py_ldb_control_str,
	.tp_new = py_ldb_control_new,
	.tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
};

static void PyErr_SetLdbError(PyObject *error, int ret, struct ldb_context *ldb_ctx)
{
	if (ret == LDB_ERR_PYTHON_EXCEPTION)
		return; /* Python exception should already be set, just keep that */

	PyErr_SetObject(error, 
			Py_BuildValue(discard_const_p(char, "(i,s)"), ret,
				      ldb_ctx == NULL?ldb_strerror(ret):ldb_errstring(ldb_ctx)));
}
static PyObject *py_ldb_bytes_str(PyBytesObject *self)
{
	char *msg = NULL;
	Py_ssize_t size;
	int result = 0;
	if (!PyBytes_Check(self)) {
		PyErr_Format(PyExc_TypeError,"Unexpected type");
		return NULL;
	}
	result = PyBytes_AsStringAndSize((PyObject *)self, &msg, &size);
	if (result != 0) {
		PyErr_Format(PyExc_TypeError, "Failed to extract bytes");
		return NULL;
	}
	return PyUnicode_FromStringAndSize(msg, size);
}

static PyTypeObject PyLdbBytesType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "ldb.bytes",
	.tp_doc = "str/bytes (with custom str)",
        .tp_str = (reprfunc)py_ldb_bytes_str,
	.tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
};

static PyObject *PyObject_FromLdbValue(const struct ldb_val *val)
{
	return PyLdbBytes_FromStringAndSize((const char *)val->data, val->length);
}

static PyObject *PyStr_FromLdbValue(const struct ldb_val *val)
{
	return PyUnicode_FromStringAndSize((const char *)val->data, val->length);
}

/**
 * Create a Python object from a ldb_result.
 *
 * @param result LDB result to convert
 * @return Python object with converted result (a list object)
 */
static PyObject *PyLdbControl_FromControl(struct ldb_control *control)
{
	TALLOC_CTX *ctl_ctx = talloc_new(NULL);
	PyLdbControlObject *ctrl;
	if (ctl_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	ctrl = (PyLdbControlObject *)PyLdbControl.tp_alloc(&PyLdbControl, 0);
	if (ctrl == NULL) {
		talloc_free(ctl_ctx);
		PyErr_NoMemory();
		return NULL;
	}
	ctrl->mem_ctx = ctl_ctx;
	ctrl->data = talloc_steal(ctrl->mem_ctx, control);
	if (ctrl->data == NULL) {
		Py_DECREF(ctrl);
		PyErr_NoMemory();
		return NULL;
	}
	return (PyObject*) ctrl;
}

/**
 * Create a Python object from a ldb_result.
 *
 * @param result LDB result to convert
 * @return Python object with converted result (a list object)
 */
static PyObject *PyLdbResult_FromResult(struct ldb_result *result)
{
	PyLdbResultObject *ret;
	PyObject *list, *controls, *referals;
	Py_ssize_t i;

	if (result == NULL) {
		Py_RETURN_NONE;
	}

	ret = (PyLdbResultObject *)PyLdbResult.tp_alloc(&PyLdbResult, 0);
	if (ret == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	list = PyList_New(result->count);
	if (list == NULL) {
		PyErr_NoMemory();
		Py_DECREF(ret);
		return NULL;
	}

	for (i = 0; i < result->count; i++) {
		PyList_SetItem(list, i, PyLdbMessage_FromMessage(result->msgs[i]));
	}

	ret->mem_ctx = talloc_new(NULL);
	if (ret->mem_ctx == NULL) {
		Py_DECREF(list);
		Py_DECREF(ret);
		PyErr_NoMemory();
		return NULL;
	}

	ret->msgs = list;

	if (result->controls) {
		i = 0;
		while (result->controls[i]) {
			i++;
		}
		controls = PyList_New(i);
		if (controls == NULL) {
			Py_DECREF(ret);
			PyErr_NoMemory();
			return NULL;
		}
		for (i=0; result->controls[i]; i++) {
			PyObject *ctrl = (PyObject*) PyLdbControl_FromControl(result->controls[i]);
			if (ctrl == NULL) {
				Py_DECREF(ret);
				Py_DECREF(controls);
				PyErr_NoMemory();
				return NULL;
			}
			PyList_SetItem(controls, i, ctrl);
		}
	} else {
		/*
		 * No controls so we keep an empty list
		 */
		controls = PyList_New(0);
		if (controls == NULL) {
			Py_DECREF(ret);
			PyErr_NoMemory();
			return NULL;
		}
	}

	ret->controls = controls;

	i = 0;

	while (result->refs && result->refs[i]) {
		i++;
	}

	referals = PyList_New(i);
	if (referals == NULL) {
		Py_DECREF(ret);
		PyErr_NoMemory();
		return NULL;
	}

	for (i = 0;result->refs && result->refs[i]; i++) {
		PyList_SetItem(referals, i, PyUnicode_FromString(result->refs[i]));
	}
	ret->referals = referals;
	return (PyObject *)ret;
}

/**
 * Create a LDB Result from a Python object.
 * If conversion fails, NULL will be returned and a Python exception set.
 *
 * Note: the result object only includes the messages at the moment; extended
 * result, controls and referrals are ignored.
 *
 * @param mem_ctx Memory context in which to allocate the LDB Result
 * @param obj Python object to convert
 * @return a ldb_result, or NULL if the conversion failed
 */
static struct ldb_result *PyLdbResult_AsResult(TALLOC_CTX *mem_ctx, 
					       PyObject *obj)
{
	struct ldb_result *res;
	Py_ssize_t i;

	if (obj == Py_None)
		return NULL;

	res = talloc_zero(mem_ctx, struct ldb_result);
	res->count = PyList_Size(obj);
	res->msgs = talloc_array(res, struct ldb_message *, res->count);
	for (i = 0; i < res->count; i++) {
		PyObject *item = PyList_GetItem(obj, i);
		res->msgs[i] = pyldb_Message_AsMessage(item);
	}
	return res;
}

static PyObject *py_ldb_dn_validate(PyLdbDnObject *self,
		PyObject *Py_UNUSED(ignored))
{
	return PyBool_FromLong(ldb_dn_validate(self->dn));
}

static PyObject *py_ldb_dn_is_valid(PyLdbDnObject *self,
		PyObject *Py_UNUSED(ignored))
{
	return PyBool_FromLong(ldb_dn_is_valid(self->dn));
}

static PyObject *py_ldb_dn_is_special(PyLdbDnObject *self,
		PyObject *Py_UNUSED(ignored))
{
	return PyBool_FromLong(ldb_dn_is_special(self->dn));
}

static PyObject *py_ldb_dn_is_null(PyLdbDnObject *self,
		PyObject *Py_UNUSED(ignored))
{
	return PyBool_FromLong(ldb_dn_is_null(self->dn));
}
 
static PyObject *py_ldb_dn_get_casefold(PyLdbDnObject *self,
		PyObject *Py_UNUSED(ignored))
{
	return PyUnicode_FromString(ldb_dn_get_casefold(self->dn));
}

static PyObject *py_ldb_dn_get_linearized(PyLdbDnObject *self)
{
	return PyUnicode_FromString(ldb_dn_get_linearized(self->dn));
}

static PyObject *py_ldb_dn_canonical_str(PyLdbDnObject *self,
		PyObject *Py_UNUSED(ignored))
{
	return PyUnicode_FromString(ldb_dn_canonical_string(self->dn, self->dn));
}

static PyObject *py_ldb_dn_canonical_ex_str(PyLdbDnObject *self,
		PyObject *Py_UNUSED(ignored))
{
	return PyUnicode_FromString(ldb_dn_canonical_ex_string(self->dn, self->dn));
}

static PyObject *py_ldb_dn_extended_str(PyLdbDnObject *self, PyObject *args, PyObject *kwargs)
{
	const char * const kwnames[] = { "mode", NULL };
	int mode = 1;
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|i",
					 discard_const_p(char *, kwnames),
					 &mode))
		return NULL;
	return PyUnicode_FromString(ldb_dn_get_extended_linearized(self->dn, self->dn, mode));
}

static PyObject *py_ldb_dn_get_extended_component(PyLdbDnObject *self, PyObject *args)
{
	char *name;
	const struct ldb_val *val;

	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;
	val = ldb_dn_get_extended_component(self->dn, name);
	if (val == NULL) {
		Py_RETURN_NONE;
	}

	return PyBytes_FromStringAndSize((const char *)val->data, val->length);
}

static PyObject *py_ldb_dn_set_extended_component(PyLdbDnObject *self, PyObject *args)
{
	char *name;
	int err;
	uint8_t *value = NULL;
	Py_ssize_t size = 0;

	if (!PyArg_ParseTuple(args, "sz#", &name, (char **)&value, &size))
		return NULL;

	if (value == NULL) {
		err = ldb_dn_set_extended_component(self->dn, name, NULL);
	} else {
		struct ldb_val val;
		val.data = (uint8_t *)value;
		val.length = size;
		err = ldb_dn_set_extended_component(self->dn, name, &val);
	}

	if (err != LDB_SUCCESS) {
		PyErr_SetString(PyExc_TypeError, "Failed to set extended component");
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *py_ldb_dn_repr(PyLdbDnObject *self)
{
	PyObject *str = PyUnicode_FromString(ldb_dn_get_linearized(self->dn));
	PyObject *repr, *result;
	if (str == NULL)
		return NULL;
	repr = PyObject_Repr(str);
	if (repr == NULL) {
		Py_DECREF(str);
		return NULL;
	}
	result = PyUnicode_FromFormat("Dn(%s)", PyUnicode_AsUTF8(repr));
	Py_DECREF(str);
	Py_DECREF(repr);
	return result;
}

static PyObject *py_ldb_dn_check_special(PyLdbDnObject *self, PyObject *args)
{
	char *name;

	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	return PyBool_FromLong(ldb_dn_check_special(self->dn, name));
}

static PyObject *py_ldb_dn_richcmp(PyObject *dn1, PyObject *dn2, int op)
{
	int ret;
	if (!pyldb_Dn_Check(dn2)) {
		Py_INCREF(Py_NotImplemented);
		return Py_NotImplemented;
	}
	ret = ldb_dn_compare(pyldb_Dn_AS_DN(dn1), pyldb_Dn_AS_DN(dn2));
	return richcmp(ret, op);
}

static PyObject *py_ldb_dn_get_parent(PyLdbDnObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_dn *dn = pyldb_Dn_AS_DN((PyObject *)self);
	struct ldb_dn *parent;
	PyLdbDnObject *py_ret;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	parent = ldb_dn_get_parent(mem_ctx, dn);
	if (parent == NULL) {
		talloc_free(mem_ctx);
		Py_RETURN_NONE;
	}

	py_ret = (PyLdbDnObject *)PyLdbDn.tp_alloc(&PyLdbDn, 0);
	if (py_ret == NULL) {
		PyErr_NoMemory();
		talloc_free(mem_ctx);
		return NULL;
	}
	py_ret->mem_ctx = mem_ctx;
	py_ret->dn = parent;
	return (PyObject *)py_ret;
}

static PyObject *py_ldb_dn_add_child(PyLdbDnObject *self, PyObject *args)
{
	PyObject *py_other;
	struct ldb_dn *dn, *other;
	if (!PyArg_ParseTuple(args, "O", &py_other))
		return NULL;

	dn = pyldb_Dn_AS_DN((PyObject *)self);

	if (!pyldb_Object_AsDn(NULL, py_other, ldb_dn_get_ldb_context(dn), &other))
		return NULL;

	return PyBool_FromLong(ldb_dn_add_child(dn, other));
}

static PyObject *py_ldb_dn_add_base(PyLdbDnObject *self, PyObject *args)
{
	PyObject *py_other;
	struct ldb_dn *other, *dn;
	if (!PyArg_ParseTuple(args, "O", &py_other))
		return NULL;

	dn = pyldb_Dn_AS_DN((PyObject *)self);

	if (!pyldb_Object_AsDn(NULL, py_other, ldb_dn_get_ldb_context(dn), &other))
		return NULL;

	return PyBool_FromLong(ldb_dn_add_base(dn, other));
}

static PyObject *py_ldb_dn_remove_base_components(PyLdbDnObject *self, PyObject *args)
{
	struct ldb_dn *dn;
	int i;
	if (!PyArg_ParseTuple(args, "i", &i))
		return NULL;

	dn = pyldb_Dn_AS_DN((PyObject *)self);

	return PyBool_FromLong(ldb_dn_remove_base_components(dn, i));
}

static PyObject *py_ldb_dn_is_child_of(PyLdbDnObject *self, PyObject *args)
{
	PyObject *py_base;
	struct ldb_dn *dn, *base;
	if (!PyArg_ParseTuple(args, "O", &py_base))
		return NULL;

	dn = pyldb_Dn_AS_DN((PyObject *)self);

	if (!pyldb_Object_AsDn(NULL, py_base, ldb_dn_get_ldb_context(dn), &base))
		return NULL;

	return PyBool_FromLong(ldb_dn_compare_base(base, dn) == 0);
}

static PyObject *py_ldb_dn_get_component_name(PyLdbDnObject *self, PyObject *args)
{
	struct ldb_dn *dn;
	const char *name;
	unsigned int num = 0;

	if (!PyArg_ParseTuple(args, "I", &num))
		return NULL;

	dn = pyldb_Dn_AS_DN((PyObject *)self);

	name = ldb_dn_get_component_name(dn, num);
	if (name == NULL) {
		Py_RETURN_NONE;
	}

	return PyUnicode_FromString(name);
}

static PyObject *py_ldb_dn_get_component_value(PyLdbDnObject *self, PyObject *args)
{
	struct ldb_dn *dn;
	const struct ldb_val *val;
	unsigned int num = 0;

	if (!PyArg_ParseTuple(args, "I", &num))
		return NULL;

	dn = pyldb_Dn_AS_DN((PyObject *)self);

	val = ldb_dn_get_component_val(dn, num);
	if (val == NULL) {
		Py_RETURN_NONE;
	}

	return PyStr_FromLdbValue(val);
}

static PyObject *py_ldb_dn_set_component(PyLdbDnObject *self, PyObject *args)
{
	unsigned int num = 0;
	char *name = NULL, *value = NULL;
	struct ldb_val val = { 0 };
	int err;
	Py_ssize_t size = 0;

	if (!PyArg_ParseTuple(args, "Iss#", &num, &name, &value, &size))
		return NULL;

	val.data = (unsigned char*) value;
	val.length = size;

	err = ldb_dn_set_component(self->dn, num, name, val);
	if (err != LDB_SUCCESS) {
		PyErr_SetString(PyExc_TypeError, "Failed to set component");
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *py_ldb_dn_get_rdn_name(PyLdbDnObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_dn *dn;
	const char *name;

	dn = pyldb_Dn_AS_DN((PyObject *)self);

	name = ldb_dn_get_rdn_name(dn);
	if (name == NULL) {
		Py_RETURN_NONE;
	}

	return PyUnicode_FromString(name);
}

static PyObject *py_ldb_dn_get_rdn_value(PyLdbDnObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_dn *dn;
	const struct ldb_val *val;

	dn = pyldb_Dn_AS_DN((PyObject *)self);

	val = ldb_dn_get_rdn_val(dn);
	if (val == NULL) {
		Py_RETURN_NONE;
	}

	return PyStr_FromLdbValue(val);
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
	{ "get_linearized", PY_DISCARD_FUNC_SIG(PyCFunction,
						py_ldb_dn_get_linearized),
		METH_NOARGS,
		NULL },
	{ "canonical_str", (PyCFunction)py_ldb_dn_canonical_str, METH_NOARGS,
		"S.canonical_str() -> string\n"
		"Canonical version of this DN (like a posix path)." },
	{ "is_child_of", (PyCFunction)py_ldb_dn_is_child_of, METH_VARARGS,
		"S.is_child_of(basedn) -> int\nReturns True if this DN is a child of basedn\n"},
	{ "canonical_ex_str", (PyCFunction)py_ldb_dn_canonical_ex_str, METH_NOARGS,
		"S.canonical_ex_str() -> string\n"
		"Canonical version of this DN (like a posix path, with terminating newline)." },
	{ "extended_str", PY_DISCARD_FUNC_SIG(PyCFunction,
					      py_ldb_dn_extended_str),
		METH_VARARGS | METH_KEYWORDS,
		"S.extended_str(mode=1) -> string\n"
		"Extended version of this DN" },
	{ "parent", (PyCFunction)py_ldb_dn_get_parent, METH_NOARGS,
   		"S.parent() -> dn\n"
		"Get the parent for this DN." },
	{ "add_child", (PyCFunction)py_ldb_dn_add_child, METH_VARARGS, 
		"S.add_child(dn) -> None\n"
		"Add a child DN to this DN." },
	{ "add_base", (PyCFunction)py_ldb_dn_add_base, METH_VARARGS,
		"S.add_base(dn) -> None\n"
		"Add a base DN to this DN." },
	{ "remove_base_components", (PyCFunction)py_ldb_dn_remove_base_components, METH_VARARGS,
		"S.remove_base_components(int) -> bool\n"
		"Remove a number of DN components from the base of this DN." },
	{ "check_special", (PyCFunction)py_ldb_dn_check_special, METH_VARARGS,
		"S.check_special(name) -> bool\n\n"
		"Check if name is a special DN name"},
	{ "get_extended_component", (PyCFunction)py_ldb_dn_get_extended_component, METH_VARARGS,
		"S.get_extended_component(name) -> string\n\n"
		"returns a DN extended component as a binary string"},
	{ "set_extended_component", (PyCFunction)py_ldb_dn_set_extended_component, METH_VARARGS,
		"S.set_extended_component(name, value) -> None\n\n"
		"set a DN extended component as a binary string"},
	{ "get_component_name", (PyCFunction)py_ldb_dn_get_component_name, METH_VARARGS,
		"S.get_component_name(num) -> string\n"
		"get the attribute name of the specified component" },
	{ "get_component_value", (PyCFunction)py_ldb_dn_get_component_value, METH_VARARGS,
		"S.get_component_value(num) -> string\n"
		"get the attribute value of the specified component as a binary string" },
	{ "set_component", (PyCFunction)py_ldb_dn_set_component, METH_VARARGS,
		"S.set_component(num, name, value) -> None\n"
		"set the attribute name and value of the specified component" },
	{ "get_rdn_name", (PyCFunction)py_ldb_dn_get_rdn_name, METH_NOARGS,
		"S.get_rdn_name() -> string\n"
		"get the RDN attribute name" },
	{ "get_rdn_value", (PyCFunction)py_ldb_dn_get_rdn_value, METH_NOARGS,
		"S.get_rdn_value() -> string\n"
		"get the RDN attribute value as a binary string" },
	{0}
};

static Py_ssize_t py_ldb_dn_len(PyLdbDnObject *self)
{
	return ldb_dn_get_comp_num(pyldb_Dn_AS_DN((PyObject *)self));
}

/*
  copy a DN as a python object
 */
static PyObject *py_ldb_dn_copy(struct ldb_dn *dn)
{
	PyLdbDnObject *py_ret;

	py_ret = (PyLdbDnObject *)PyLdbDn.tp_alloc(&PyLdbDn, 0);
	if (py_ret == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	py_ret->mem_ctx = talloc_new(NULL);
	py_ret->dn = ldb_dn_copy(py_ret->mem_ctx, dn);
	return (PyObject *)py_ret;
}

static PyObject *py_ldb_dn_concat(PyLdbDnObject *self, PyObject *py_other)
{
	struct ldb_dn *dn = pyldb_Dn_AS_DN((PyObject *)self),
				  *other;
	PyLdbDnObject *py_ret;

	if (!pyldb_Object_AsDn(NULL, py_other, NULL, &other))
		return NULL;

	py_ret = (PyLdbDnObject *)PyLdbDn.tp_alloc(&PyLdbDn, 0);
	if (py_ret == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	py_ret->mem_ctx = talloc_new(NULL);
	py_ret->dn = ldb_dn_copy(py_ret->mem_ctx, dn);
	ldb_dn_add_base(py_ret->dn, other);
	return (PyObject *)py_ret;
}

static PySequenceMethods py_ldb_dn_seq = {
	.sq_length = (lenfunc)py_ldb_dn_len,
	.sq_concat = (binaryfunc)py_ldb_dn_concat,
};

static PyObject *py_ldb_dn_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	struct ldb_dn *ret = NULL;
	char *str = NULL;
	PyObject *py_ldb = NULL;
	struct ldb_context *ldb_ctx = NULL;
	TALLOC_CTX *mem_ctx = NULL;
	PyLdbDnObject *py_ret = NULL;
	const char * const kwnames[] = { "ldb", "dn", NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O"PYARG_STR_UNI,
					 discard_const_p(char *, kwnames),
					 &py_ldb, "utf8", &str))
		goto out;

	if (!PyLdb_Check(py_ldb)) {
		PyErr_SetString(PyExc_TypeError, "Expected Ldb");
		goto out;
	}
	ldb_ctx = pyldb_Ldb_AS_LDBCONTEXT(py_ldb);

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		goto out;
	}

	ret = ldb_dn_new(mem_ctx, ldb_ctx, str);
	if (!ldb_dn_validate(ret)) {
		talloc_free(mem_ctx);
		PyErr_SetString(PyExc_ValueError, "unable to parse dn string");
		goto out;
	}

	py_ret = (PyLdbDnObject *)type->tp_alloc(type, 0);
	if (py_ret == NULL) {
		talloc_free(mem_ctx);
		PyErr_NoMemory();
		goto out;
	}
	py_ret->mem_ctx = mem_ctx;
	py_ret->dn = ret;
out:
	if (str != NULL) {
		PyMem_Free(discard_const_p(char, str));
	}
	return (PyObject *)py_ret;
}

static void py_ldb_dn_dealloc(PyLdbDnObject *self)
{
	talloc_free(self->mem_ctx);
	PyObject_Del(self);
}

static PyTypeObject PyLdbDn = {
	.tp_name = "ldb.Dn",
	.tp_methods = py_ldb_dn_methods,
	.tp_str = (reprfunc)py_ldb_dn_get_linearized,
	.tp_repr = (reprfunc)py_ldb_dn_repr,
	.tp_richcompare = (richcmpfunc)py_ldb_dn_richcmp,
	.tp_as_sequence = &py_ldb_dn_seq,
	.tp_doc = "A LDB distinguished name.",
	.tp_new = py_ldb_dn_new,
	.tp_dealloc = (destructor)py_ldb_dn_dealloc,
	.tp_basicsize = sizeof(PyLdbDnObject),
	.tp_flags = Py_TPFLAGS_DEFAULT,
};

/* Debug */
static void py_ldb_debug(void *context, enum ldb_debug_level level, const char *fmt, va_list ap) PRINTF_ATTRIBUTE(3, 0);
static void py_ldb_debug(void *context, enum ldb_debug_level level, const char *fmt, va_list ap)
{
	PyObject *fn = (PyObject *)context;
	PyObject_CallFunction(fn, discard_const_p(char, "(i,O)"), level, PyUnicode_FromFormatV(fmt, ap));
}

static PyObject *py_ldb_debug_func;

static PyObject *py_ldb_set_debug(PyObject *self, PyObject *args)
{
	PyObject *cb;
	struct ldb_context *ldb_ctx;

	if (!PyArg_ParseTuple(args, "O", &cb))
		return NULL;

	if (py_ldb_debug_func != NULL) {
		Py_DECREF(py_ldb_debug_func);
	}

	Py_INCREF(cb);
	/* FIXME: DECREF cb when exiting program */
	py_ldb_debug_func = cb;
	ldb_ctx = pyldb_Ldb_AS_LDBCONTEXT(self);
	PyErr_LDB_ERROR_IS_ERR_RAISE(PyExc_LdbError,
		ldb_set_debug(ldb_ctx, py_ldb_debug, cb),
		ldb_ctx);

	Py_RETURN_NONE;
}

static PyObject *py_ldb_set_create_perms(PyTypeObject *self, PyObject *args)
{
	unsigned int perms;
	if (!PyArg_ParseTuple(args, "I", &perms))
		return NULL;

	ldb_set_create_perms(pyldb_Ldb_AS_LDBCONTEXT(self), perms);

	Py_RETURN_NONE;
}

static PyObject *py_ldb_set_modules_dir(PyTypeObject *self, PyObject *args)
{
	char *modules_dir;
	if (!PyArg_ParseTuple(args, "s", &modules_dir))
		return NULL;

	ldb_set_modules_dir(pyldb_Ldb_AS_LDBCONTEXT(self), modules_dir);

	Py_RETURN_NONE;
}

static PyObject *py_ldb_transaction_start(PyLdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_context *ldb_ctx = pyldb_Ldb_AS_LDBCONTEXT(self);
	int ldb_err;
	ldb_err = ldb_transaction_start(ldb_ctx);
	PyErr_LDB_ERROR_IS_ERR_RAISE(PyExc_LdbError, ldb_err, ldb_ctx);
	Py_RETURN_NONE;
}

static PyObject *py_ldb_transaction_commit(PyLdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_context *ldb_ctx = pyldb_Ldb_AS_LDBCONTEXT(self);
	int ldb_err;
	ldb_err = ldb_transaction_commit(ldb_ctx);
	PyErr_LDB_ERROR_IS_ERR_RAISE(PyExc_LdbError, ldb_err, ldb_ctx);
	Py_RETURN_NONE;
}

static PyObject *py_ldb_transaction_prepare_commit(PyLdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_context *ldb_ctx = pyldb_Ldb_AS_LDBCONTEXT(self);
	int ldb_err;
	ldb_err = ldb_transaction_prepare_commit(ldb_ctx);
	PyErr_LDB_ERROR_IS_ERR_RAISE(PyExc_LdbError, ldb_err, ldb_ctx);
	Py_RETURN_NONE;
}

static PyObject *py_ldb_transaction_cancel(PyLdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_context *ldb_ctx = pyldb_Ldb_AS_LDBCONTEXT(self);
	int ldb_err;
	ldb_err = ldb_transaction_cancel(ldb_ctx);
	PyErr_LDB_ERROR_IS_ERR_RAISE(PyExc_LdbError, ldb_err, ldb_ctx);
	Py_RETURN_NONE;
}

static PyObject *py_ldb_setup_wellknown_attributes(PyLdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_context *ldb_ctx = pyldb_Ldb_AS_LDBCONTEXT(self);
	int ldb_err;
	ldb_err = ldb_setup_wellknown_attributes(ldb_ctx);
	PyErr_LDB_ERROR_IS_ERR_RAISE(PyExc_LdbError, ldb_err, ldb_ctx);
	Py_RETURN_NONE;
}

static PyObject *py_ldb_repr(PyLdbObject *self)
{
	return PyUnicode_FromString("<ldb connection>");
}

static PyObject *py_ldb_get_root_basedn(PyLdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_dn *dn = ldb_get_root_basedn(pyldb_Ldb_AS_LDBCONTEXT(self));
	if (dn == NULL)
		Py_RETURN_NONE;
	return py_ldb_dn_copy(dn);
}


static PyObject *py_ldb_get_schema_basedn(PyLdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_dn *dn = ldb_get_schema_basedn(pyldb_Ldb_AS_LDBCONTEXT(self));
	if (dn == NULL)
		Py_RETURN_NONE;
	return py_ldb_dn_copy(dn);
}

static PyObject *py_ldb_get_config_basedn(PyLdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_dn *dn = ldb_get_config_basedn(pyldb_Ldb_AS_LDBCONTEXT(self));
	if (dn == NULL)
		Py_RETURN_NONE;
	return py_ldb_dn_copy(dn);
}

static PyObject *py_ldb_get_default_basedn(PyLdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_dn *dn = ldb_get_default_basedn(pyldb_Ldb_AS_LDBCONTEXT(self));
	if (dn == NULL)
		Py_RETURN_NONE;
	return py_ldb_dn_copy(dn);
}

static const char **PyList_AsStrList(TALLOC_CTX *mem_ctx, PyObject *list,
                    const char *paramname)
{
	const char **ret;
	Py_ssize_t i;
	if (!PyList_Check(list)) {
		PyErr_Format(PyExc_TypeError, "%s is not a list", paramname);
		return NULL;
	}
	ret = talloc_array(NULL, const char *, PyList_Size(list)+1);
	if (ret == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	for (i = 0; i < PyList_Size(list); i++) {
		const char *str = NULL;
		Py_ssize_t size;
		PyObject *item = PyList_GetItem(list, i);
		if (!PyUnicode_Check(item)) {
			PyErr_Format(PyExc_TypeError, "%s should be strings", paramname);
			talloc_free(ret);
			return NULL;
		}
		str = PyUnicode_AsUTF8AndSize(item, &size);
		if (str == NULL) {
			talloc_free(ret);
			return NULL;
		}
		ret[i] = talloc_strndup(ret, str, size);
	}
	ret[i] = NULL;
	return ret;
}

static int py_ldb_init(PyLdbObject *self, PyObject *args, PyObject *kwargs)
{
	const char * const kwnames[] = { "url", "flags", "options", NULL };
	char *url = NULL;
	PyObject *py_options = Py_None;
	const char **options;
	unsigned int flags = 0;
	int ret;
	struct ldb_context *ldb;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|zIO:Ldb.__init__",
					 discard_const_p(char *, kwnames),
					 &url, &flags, &py_options))
		return -1;

	ldb = pyldb_Ldb_AS_LDBCONTEXT(self);

	if (py_options == Py_None) {
		options = NULL;
	} else {
		options = PyList_AsStrList(ldb, py_options, "options");
		if (options == NULL)
			return -1;
	}

	if (url != NULL) {
		ret = ldb_connect(ldb, url, flags, options);
		if (ret != LDB_SUCCESS) {
			PyErr_SetLdbError(PyExc_LdbError, ret, ldb);
			return -1;
		}
	} else {
		ldb_set_flags(ldb, flags);
	}

	talloc_free(options);
	return 0;
}

static PyObject *py_ldb_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	PyLdbObject *ret;
	struct ldb_context *ldb;
	ret = (PyLdbObject *)type->tp_alloc(type, 0);
	if (ret == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	ret->mem_ctx = talloc_new(NULL);
	ldb = ldb_init(ret->mem_ctx, NULL);

	if (ldb == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	ret->ldb_ctx = ldb;
	return (PyObject *)ret;
}

static PyObject *py_ldb_connect(PyLdbObject *self, PyObject *args, PyObject *kwargs)
{
	char *url = NULL;
	unsigned int flags = 0;
	PyObject *py_options = Py_None;
	int ret;
	const char **options;
	const char * const kwnames[] = { "url", "flags", "options", NULL };
	struct ldb_context *ldb_ctx;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "z|IO",
					 discard_const_p(char *, kwnames),
					 &url, &flags, &py_options))
		return NULL;

	if (py_options == Py_None) {
		options = NULL;
	} else {
		options = PyList_AsStrList(NULL, py_options, "options");
		if (options == NULL)
			return NULL;
	}

	ldb_ctx = pyldb_Ldb_AS_LDBCONTEXT(self);
	ret = ldb_connect(ldb_ctx, url, flags, options);
	talloc_free(options);

	PyErr_LDB_ERROR_IS_ERR_RAISE(PyExc_LdbError, ret, ldb_ctx);

	Py_RETURN_NONE;
}

static PyObject *py_ldb_modify(PyLdbObject *self, PyObject *args, PyObject *kwargs)
{
	PyObject *py_msg;
	PyObject *py_controls = Py_None;
	struct ldb_context *ldb_ctx;
	struct ldb_request *req;
	struct ldb_control **parsed_controls;
	struct ldb_message *msg;
	int ret;
	TALLOC_CTX *mem_ctx;
	bool validate=true;
	const char * const kwnames[] = { "message", "controls", "validate", NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O|Ob",
					 discard_const_p(char *, kwnames),
					 &py_msg, &py_controls, &validate))
		return NULL;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	ldb_ctx = pyldb_Ldb_AS_LDBCONTEXT(self);

	if (py_controls == Py_None) {
		parsed_controls = NULL;
	} else {
		const char **controls = PyList_AsStrList(mem_ctx, py_controls, "controls");
		if (controls == NULL) {
			talloc_free(mem_ctx);
			return NULL;
		}
		parsed_controls = ldb_parse_control_strings(ldb_ctx, mem_ctx, controls);
		talloc_free(controls);
	}

	if (!PyLdbMessage_Check(py_msg)) {
		PyErr_SetString(PyExc_TypeError, "Expected Ldb Message");
		talloc_free(mem_ctx);
		return NULL;
	}
	msg = pyldb_Message_AsMessage(py_msg);

	if (validate) {
		ret = ldb_msg_sanity_check(ldb_ctx, msg);
		if (ret != LDB_SUCCESS) {
			PyErr_SetLdbError(PyExc_LdbError, ret, ldb_ctx);
			talloc_free(mem_ctx);
			return NULL;
		}
	}

	ret = ldb_build_mod_req(&req, ldb_ctx, mem_ctx, msg, parsed_controls,
				NULL, ldb_op_default_callback, NULL);
	if (ret != LDB_SUCCESS) {
		PyErr_SetString(PyExc_TypeError, "failed to build request");
		talloc_free(mem_ctx);
		return NULL;
	}

	/* do request and autostart a transaction */
	/* Then let's LDB handle the message error in case of pb as they are meaningful */

	ret = ldb_transaction_start(ldb_ctx);
	if (ret != LDB_SUCCESS) {
		talloc_free(mem_ctx);
		PyErr_SetLdbError(PyExc_LdbError, ret, ldb_ctx);
		return NULL;
	}

	ret = ldb_request(ldb_ctx, req);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}

	if (ret == LDB_SUCCESS) {
		ret = ldb_transaction_commit(ldb_ctx);
	} else {
		ldb_transaction_cancel(ldb_ctx);
	}

	talloc_free(mem_ctx);
	PyErr_LDB_ERROR_IS_ERR_RAISE(PyExc_LdbError, ret, ldb_ctx);

	Py_RETURN_NONE;
}


/**
 * Obtain a ldb message from a Python Dictionary object.
 *
 * @param mem_ctx Memory context
 * @param py_obj Python Dictionary object
 * @param ldb_ctx LDB context
 * @param mod_flags Flags to be set on every message element
 * @return ldb_message on success or NULL on failure
 */
static struct ldb_message *PyDict_AsMessage(TALLOC_CTX *mem_ctx,
					    PyObject *py_obj,
					    struct ldb_context *ldb_ctx,
					    unsigned int mod_flags)
{
	struct ldb_message *msg;
	unsigned int msg_pos = 0;
	Py_ssize_t dict_pos = 0;
	PyObject *key, *value;
	struct ldb_message_element *msg_el;
	PyObject *dn_value = PyDict_GetItemString(py_obj, "dn");

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	msg->elements = talloc_zero_array(msg, struct ldb_message_element, PyDict_Size(py_obj));

	if (dn_value) {
		if (!pyldb_Object_AsDn(msg, dn_value, ldb_ctx, &msg->dn)) {
			PyErr_SetString(PyExc_TypeError, "unable to import dn object");
			return NULL;
		}
		if (msg->dn == NULL) {
			PyErr_SetString(PyExc_TypeError, "dn set but not found");
			return NULL;
		}
	} else {
		PyErr_SetString(PyExc_TypeError, "no dn set");
		return NULL;
	}

	while (PyDict_Next(py_obj, &dict_pos, &key, &value)) {
		const char *key_str = PyUnicode_AsUTF8(key);
		if (ldb_attr_cmp(key_str, "dn") != 0) {
			msg_el = PyObject_AsMessageElement(msg->elements, value,
							   mod_flags, key_str);
			if (msg_el == NULL) {
				PyErr_Format(PyExc_TypeError, "unable to import element '%s'", key_str);
				return NULL;
			}
			memcpy(&msg->elements[msg_pos], msg_el, sizeof(*msg_el));
			msg_pos++;
		}
	}

	msg->num_elements = msg_pos;

	return msg;
}

static PyObject *py_ldb_add(PyLdbObject *self, PyObject *args, PyObject *kwargs)
{
	PyObject *py_obj;
	int ret;
	struct ldb_context *ldb_ctx;
	struct ldb_request *req;
	struct ldb_message *msg = NULL;
	PyObject *py_controls = Py_None;
	TALLOC_CTX *mem_ctx;
	struct ldb_control **parsed_controls;
	const char * const kwnames[] = { "message", "controls", NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O|O",
					 discard_const_p(char *, kwnames),
					 &py_obj, &py_controls))
		return NULL;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	ldb_ctx = pyldb_Ldb_AS_LDBCONTEXT(self);

	if (py_controls == Py_None) {
		parsed_controls = NULL;
	} else {
		const char **controls = PyList_AsStrList(mem_ctx, py_controls, "controls");
		if (controls == NULL) {
			talloc_free(mem_ctx);
			return NULL;
		}
		parsed_controls = ldb_parse_control_strings(ldb_ctx, mem_ctx, controls);
		talloc_free(controls);
	}

	if (PyLdbMessage_Check(py_obj)) {
		msg = pyldb_Message_AsMessage(py_obj);
	} else if (PyDict_Check(py_obj)) {
		msg = PyDict_AsMessage(mem_ctx, py_obj, ldb_ctx, LDB_FLAG_MOD_ADD);
	} else {
		PyErr_SetString(PyExc_TypeError,
				"Dictionary or LdbMessage object expected!");
	}

	if (!msg) {
		/* we should have a PyErr already set */
		talloc_free(mem_ctx);
		return NULL;
	}

	ret = ldb_msg_sanity_check(ldb_ctx, msg);
	if (ret != LDB_SUCCESS) {
		PyErr_SetLdbError(PyExc_LdbError, ret, ldb_ctx);
		talloc_free(mem_ctx);
		return NULL;
	}

	ret = ldb_build_add_req(&req, ldb_ctx, mem_ctx, msg, parsed_controls,
				NULL, ldb_op_default_callback, NULL);
	if (ret != LDB_SUCCESS) {
		PyErr_SetString(PyExc_TypeError, "failed to build request");
		talloc_free(mem_ctx);
		return NULL;
	}

        /* do request and autostart a transaction */
	/* Then let's LDB handle the message error in case of pb as they are meaningful */

	ret = ldb_transaction_start(ldb_ctx);
	if (ret != LDB_SUCCESS) {
		talloc_free(mem_ctx);
		PyErr_SetLdbError(PyExc_LdbError, ret, ldb_ctx);
		return NULL;
	}

	ret = ldb_request(ldb_ctx, req);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}

	if (ret == LDB_SUCCESS) {
		ret = ldb_transaction_commit(ldb_ctx);
	} else {
		ldb_transaction_cancel(ldb_ctx);
	}

	talloc_free(mem_ctx);
	PyErr_LDB_ERROR_IS_ERR_RAISE(PyExc_LdbError, ret, ldb_ctx);

	Py_RETURN_NONE;
}

static PyObject *py_ldb_delete(PyLdbObject *self, PyObject *args, PyObject *kwargs)
{
	PyObject *py_dn;
	struct ldb_dn *dn;
	int ret;
	struct ldb_context *ldb_ctx;
	struct ldb_request *req;
	PyObject *py_controls = Py_None;
	TALLOC_CTX *mem_ctx;
	struct ldb_control **parsed_controls;
	const char * const kwnames[] = { "dn", "controls", NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O|O",
					 discard_const_p(char *, kwnames),
					 &py_dn, &py_controls))
		return NULL;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	ldb_ctx = pyldb_Ldb_AS_LDBCONTEXT(self);

	if (py_controls == Py_None) {
		parsed_controls = NULL;
	} else {
		const char **controls = PyList_AsStrList(mem_ctx, py_controls, "controls");
		if (controls == NULL) {
			talloc_free(mem_ctx);
			return NULL;
		}
		parsed_controls = ldb_parse_control_strings(ldb_ctx, mem_ctx, controls);
		talloc_free(controls);
	}

	if (!pyldb_Object_AsDn(mem_ctx, py_dn, ldb_ctx, &dn)) {
		talloc_free(mem_ctx);
		return NULL;
	}

	ret = ldb_build_del_req(&req, ldb_ctx, mem_ctx, dn, parsed_controls,
				NULL, ldb_op_default_callback, NULL);
	if (ret != LDB_SUCCESS) {
		PyErr_SetString(PyExc_TypeError, "failed to build request");
		talloc_free(mem_ctx);
		return NULL;
	}

	/* do request and autostart a transaction */
	/* Then let's LDB handle the message error in case of pb as they are meaningful */

	ret = ldb_transaction_start(ldb_ctx);
	if (ret != LDB_SUCCESS) {
		talloc_free(mem_ctx);
		PyErr_SetLdbError(PyExc_LdbError, ret, ldb_ctx);
		return NULL;
	}

	ret = ldb_request(ldb_ctx, req);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}

	if (ret == LDB_SUCCESS) {
		ret = ldb_transaction_commit(ldb_ctx);
	} else {
		ldb_transaction_cancel(ldb_ctx);
	}

	talloc_free(mem_ctx);
	PyErr_LDB_ERROR_IS_ERR_RAISE(PyExc_LdbError, ret, ldb_ctx);

	Py_RETURN_NONE;
}

static PyObject *py_ldb_rename(PyLdbObject *self, PyObject *args, PyObject *kwargs)
{
	PyObject *py_dn1, *py_dn2;
	struct ldb_dn *dn1, *dn2;
	int ret;
	TALLOC_CTX *mem_ctx;
	PyObject *py_controls = Py_None;
	struct ldb_control **parsed_controls;
	struct ldb_context *ldb_ctx;
	struct ldb_request *req;
	const char * const kwnames[] = { "dn1", "dn2", "controls", NULL };

	ldb_ctx = pyldb_Ldb_AS_LDBCONTEXT(self);

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OO|O",
					 discard_const_p(char *, kwnames),
					 &py_dn1, &py_dn2, &py_controls))
		return NULL;


	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	if (py_controls == Py_None) {
		parsed_controls = NULL;
	} else {
		const char **controls = PyList_AsStrList(mem_ctx, py_controls, "controls");
		if (controls == NULL) {
			talloc_free(mem_ctx);
			return NULL;
		}
		parsed_controls = ldb_parse_control_strings(ldb_ctx, mem_ctx, controls);
		talloc_free(controls);
	}


	if (!pyldb_Object_AsDn(mem_ctx, py_dn1, ldb_ctx, &dn1)) {
		talloc_free(mem_ctx);
		return NULL;
	}

	if (!pyldb_Object_AsDn(mem_ctx, py_dn2, ldb_ctx, &dn2)) {
		talloc_free(mem_ctx);
		return NULL;
	}

	ret = ldb_build_rename_req(&req, ldb_ctx, mem_ctx, dn1, dn2, parsed_controls,
				NULL, ldb_op_default_callback, NULL);
	if (ret != LDB_SUCCESS) {
		PyErr_SetString(PyExc_TypeError, "failed to build request");
		talloc_free(mem_ctx);
		return NULL;
	}

	/* do request and autostart a transaction */
	/* Then let's LDB handle the message error in case of pb as they are meaningful */

	ret = ldb_transaction_start(ldb_ctx);
	if (ret != LDB_SUCCESS) {
		talloc_free(mem_ctx);
		PyErr_SetLdbError(PyExc_LdbError, ret, ldb_ctx);
		return NULL;
	}

	ret = ldb_request(ldb_ctx, req);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}

	if (ret == LDB_SUCCESS) {
		ret = ldb_transaction_commit(ldb_ctx);
	} else {
		ldb_transaction_cancel(ldb_ctx);
	}

	talloc_free(mem_ctx);
	PyErr_LDB_ERROR_IS_ERR_RAISE(PyExc_LdbError, ret, ldb_ctx);

	Py_RETURN_NONE;
}

static PyObject *py_ldb_schema_attribute_remove(PyLdbObject *self, PyObject *args)
{
	char *name;
	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	ldb_schema_attribute_remove(pyldb_Ldb_AS_LDBCONTEXT(self), name);

	Py_RETURN_NONE;
}

static PyObject *py_ldb_schema_attribute_add(PyLdbObject *self, PyObject *args)
{
	char *attribute, *syntax;
	unsigned int flags;
	int ret;
	struct ldb_context *ldb_ctx;

	if (!PyArg_ParseTuple(args, "sIs", &attribute, &flags, &syntax))
		return NULL;

	ldb_ctx = pyldb_Ldb_AS_LDBCONTEXT(self);
	ret = ldb_schema_attribute_add(ldb_ctx, attribute, flags, syntax);

	PyErr_LDB_ERROR_IS_ERR_RAISE(PyExc_LdbError, ret, ldb_ctx);

	Py_RETURN_NONE;
}

static PyObject *ldb_ldif_to_pyobject(struct ldb_ldif *ldif)
{
	if (ldif == NULL) {
		Py_RETURN_NONE;
	} else {
	/* We don't want this attached to the 'ldb' any more */
		PyObject *obj = PyLdbMessage_FromMessage(ldif->msg);
		PyObject *result =
			Py_BuildValue(discard_const_p(char, "(iO)"),
				      ldif->changetype,
				      obj);
		Py_CLEAR(obj);
		return result;
	}
}


static PyObject *py_ldb_write_ldif(PyLdbObject *self, PyObject *args)
{
	int changetype;
	PyObject *py_msg;
	struct ldb_ldif ldif;
	PyObject *ret;
	char *string;
	TALLOC_CTX *mem_ctx;

	if (!PyArg_ParseTuple(args, "Oi", &py_msg, &changetype))
		return NULL;

	if (!PyLdbMessage_Check(py_msg)) {
		PyErr_SetString(PyExc_TypeError, "Expected Ldb Message for msg");
		return NULL;
	}

	ldif.msg = pyldb_Message_AsMessage(py_msg);
	ldif.changetype = changetype;

	mem_ctx = talloc_new(NULL);

	string = ldb_ldif_write_string(pyldb_Ldb_AS_LDBCONTEXT(self), mem_ctx, &ldif);
	if (!string) {
		PyErr_SetString(PyExc_KeyError, "Failed to generate LDIF");
		return NULL;
	}

	ret = PyUnicode_FromString(string);

	talloc_free(mem_ctx);

	return ret;
}

static PyObject *py_ldb_parse_ldif(PyLdbObject *self, PyObject *args)
{
	PyObject *list, *ret;
	struct ldb_ldif *ldif;
	const char *s;
	struct ldb_dn *last_dn = NULL;

	TALLOC_CTX *mem_ctx;

	if (!PyArg_ParseTuple(args, "s", &s))
		return NULL;

	mem_ctx = talloc_new(NULL);
	if (!mem_ctx) {
		Py_RETURN_NONE;
	}

	list = PyList_New(0);
	while (s && *s != '\0') {
		ldif = ldb_ldif_read_string(self->ldb_ctx, &s);
		talloc_steal(mem_ctx, ldif);
		if (ldif) {
			int res = 0;
			PyObject *py_ldif = ldb_ldif_to_pyobject(ldif);
			if (py_ldif == NULL) {
				Py_CLEAR(list);
				PyErr_BadArgument();
				talloc_free(mem_ctx);
				return NULL;
			}
			res = PyList_Append(list, py_ldif);
			Py_CLEAR(py_ldif);
			if (res == -1) {
				Py_CLEAR(list);
				talloc_free(mem_ctx);
				return NULL;
			}
			last_dn = ldif->msg->dn;
		} else {
			const char *last_dn_str = NULL;
			const char *err_string = NULL;
			if (last_dn == NULL) {
				PyErr_SetString(PyExc_ValueError,
						"unable to parse LDIF "
						"string at first chunk");
				Py_CLEAR(list);
				talloc_free(mem_ctx);
				return NULL;
			}

			last_dn_str
				= ldb_dn_get_linearized(last_dn);

			err_string
				= talloc_asprintf(mem_ctx,
						  "unable to parse ldif "
						  "string AFTER %s",
						  last_dn_str);

			PyErr_SetString(PyExc_ValueError,
					err_string);
			talloc_free(mem_ctx);
			Py_CLEAR(list);
			return NULL;
		}
	}
	talloc_free(mem_ctx); /* The pyobject already has a reference to the things it needs */
	ret = PyObject_GetIter(list);
	Py_DECREF(list);
	return ret;
}

static PyObject *py_ldb_msg_diff(PyLdbObject *self, PyObject *args)
{
	int ldb_ret;
	PyObject *py_msg_old;
	PyObject *py_msg_new;
	struct ldb_message *diff;
	struct ldb_context *ldb;
	PyObject *py_ret;
	TALLOC_CTX *mem_ctx = NULL;

	if (!PyArg_ParseTuple(args, "OO", &py_msg_old, &py_msg_new))
		return NULL;

	if (!PyLdbMessage_Check(py_msg_old)) {
		PyErr_SetString(PyExc_TypeError, "Expected Ldb Message for old message");
		return NULL;
	}

	if (!PyLdbMessage_Check(py_msg_new)) {
		PyErr_SetString(PyExc_TypeError, "Expected Ldb Message for new message");
		return NULL;
	}

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	ldb = pyldb_Ldb_AS_LDBCONTEXT(self);
	ldb_ret = ldb_msg_difference(ldb, mem_ctx,
	                             pyldb_Message_AsMessage(py_msg_old),
	                             pyldb_Message_AsMessage(py_msg_new),
	                             &diff);
	if (ldb_ret != LDB_SUCCESS) {
		talloc_free(mem_ctx);
		PyErr_SetString(PyExc_RuntimeError, "Failed to generate the Ldb Message diff");
		return NULL;
	}

	diff = ldb_msg_copy(mem_ctx, diff);
	if (diff == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	py_ret = PyLdbMessage_FromMessage(diff);

	talloc_free(mem_ctx);

	return py_ret;
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
	Py_ssize_t size;
	int result;

	if (!PyArg_ParseTuple(args, "sO", &element_name, &val))
		return NULL;

	result = PyBytes_AsStringAndSize(val, (char **)&old_val.data, &size);
	old_val.length = size;

	if (result != 0) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to convert passed value to String");
		return NULL;
	}

	a = ldb_schema_attribute_by_name(pyldb_Ldb_AS_LDBCONTEXT(self), element_name);

	if (a == NULL) {
		Py_RETURN_NONE;
	}

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	if (a->syntax->ldif_write_fn(pyldb_Ldb_AS_LDBCONTEXT(self), mem_ctx, &old_val, &new_val) != 0) {
		talloc_free(mem_ctx);
		Py_RETURN_NONE;
	}

	ret = PyBytes_FromStringAndSize((const char *)new_val.data, new_val.length);

	talloc_free(mem_ctx);

	return ret;
}

static PyObject *py_ldb_search(PyLdbObject *self, PyObject *args, PyObject *kwargs)
{
	PyObject *py_base = Py_None;
	int scope = LDB_SCOPE_DEFAULT;
	char *expr = NULL;
	PyObject *py_attrs = Py_None;
	PyObject *py_controls = Py_None;
	const char * const kwnames[] = { "base", "scope", "expression", "attrs", "controls", NULL };
	int ret;
	struct ldb_result *res;
	struct ldb_request *req;
	const char **attrs;
	struct ldb_context *ldb_ctx;
	struct ldb_control **parsed_controls;
	struct ldb_dn *base;
	PyObject *py_ret;
	TALLOC_CTX *mem_ctx;

	/* type "int" rather than "enum" for "scope" is intentional */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|OizOO",
					 discard_const_p(char *, kwnames),
					 &py_base, &scope, &expr, &py_attrs, &py_controls))
		return NULL;


	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	ldb_ctx = pyldb_Ldb_AS_LDBCONTEXT(self);

	if (py_attrs == Py_None) {
		attrs = NULL;
	} else {
		attrs = PyList_AsStrList(mem_ctx, py_attrs, "attrs");
		if (attrs == NULL) {
			talloc_free(mem_ctx);
			return NULL;
		}
	}

	if (py_base == Py_None) {
		base = ldb_get_default_basedn(ldb_ctx);
	} else {
		if (!pyldb_Object_AsDn(mem_ctx, py_base, ldb_ctx, &base)) {
			talloc_free(mem_ctx);
			return NULL;
		}
	}

	if (py_controls == Py_None) {
		parsed_controls = NULL;
	} else {
		const char **controls = PyList_AsStrList(mem_ctx, py_controls, "controls");
		if (controls == NULL) {
			talloc_free(mem_ctx);
			return NULL;
		}
		parsed_controls = ldb_parse_control_strings(ldb_ctx, mem_ctx, controls);
		talloc_free(controls);
	}

	res = talloc_zero(mem_ctx, struct ldb_result);
	if (res == NULL) {
		PyErr_NoMemory();
		talloc_free(mem_ctx);
		return NULL;
	}

	ret = ldb_build_search_req(&req, ldb_ctx, mem_ctx,
				   base,
				   scope,
				   expr,
				   attrs,
				   parsed_controls,
				   res,
				   ldb_search_default_callback,
				   NULL);

	if (ret != LDB_SUCCESS) {
		talloc_free(mem_ctx);
		PyErr_SetLdbError(PyExc_LdbError, ret, ldb_ctx);
		return NULL;
	}

	talloc_steal(req, attrs);

	ret = ldb_request(ldb_ctx, req);

	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}

	if (ret != LDB_SUCCESS) {
		talloc_free(mem_ctx);
		PyErr_SetLdbError(PyExc_LdbError, ret, ldb_ctx);
		return NULL;
	}

	py_ret = PyLdbResult_FromResult(res);

	talloc_free(mem_ctx);

	return py_ret;
}

static int py_ldb_search_iterator_reply_destructor(struct py_ldb_search_iterator_reply *reply)
{
	if (reply->py_iter != NULL) {
		DLIST_REMOVE(reply->py_iter->state.next, reply);
		if (reply->py_iter->state.result == reply) {
			reply->py_iter->state.result = NULL;
		}
		reply->py_iter = NULL;
	}

	if (reply->obj != NULL) {
		Py_DECREF(reply->obj);
		reply->obj = NULL;
	}

	return 0;
}

static int py_ldb_search_iterator_callback(struct ldb_request *req,
					   struct ldb_reply *ares)
{
	PyLdbSearchIteratorObject *py_iter = (PyLdbSearchIteratorObject *)req->context;
	struct ldb_result result = { .msgs = NULL };
	struct py_ldb_search_iterator_reply *reply = NULL;

	if (ares == NULL) {
		return ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
	}

	if (ares->error != LDB_SUCCESS) {
		int ret = ares->error;
		TALLOC_FREE(ares);
		return ldb_request_done(req, ret);
	}

	reply = talloc_zero(py_iter->mem_ctx,
			    struct py_ldb_search_iterator_reply);
	if (reply == NULL) {
		TALLOC_FREE(ares);
		return ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
	}
	reply->py_iter = py_iter;
	talloc_set_destructor(reply, py_ldb_search_iterator_reply_destructor);

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		reply->obj = PyLdbMessage_FromMessage(ares->message);
		if (reply->obj == NULL) {
			TALLOC_FREE(ares);
			return ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
		}
		DLIST_ADD_END(py_iter->state.next, reply);
		TALLOC_FREE(ares);
		return LDB_SUCCESS;

	case LDB_REPLY_REFERRAL:
		reply->obj = PyUnicode_FromString(ares->referral);
		if (reply->obj == NULL) {
			TALLOC_FREE(ares);
			return ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
		}
		DLIST_ADD_END(py_iter->state.next, reply);
		TALLOC_FREE(ares);
		return LDB_SUCCESS;

	case LDB_REPLY_DONE:
		result = (struct ldb_result) { .controls = ares->controls };
		reply->obj = PyLdbResult_FromResult(&result);
		if (reply->obj == NULL) {
			TALLOC_FREE(ares);
			return ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
		}
		py_iter->state.result = reply;
		TALLOC_FREE(ares);
		return ldb_request_done(req, LDB_SUCCESS);
	}

	TALLOC_FREE(ares);
	return ldb_request_done(req, LDB_ERR_OPERATIONS_ERROR);
}

static PyObject *py_ldb_search_iterator(PyLdbObject *self, PyObject *args, PyObject *kwargs)
{
	PyObject *py_base = Py_None;
	int scope = LDB_SCOPE_DEFAULT;
	int timeout = 0;
	char *expr = NULL;
	PyObject *py_attrs = Py_None;
	PyObject *py_controls = Py_None;
	const char * const kwnames[] = { "base", "scope", "expression", "attrs", "controls", "timeout", NULL };
	int ret;
	const char **attrs;
	struct ldb_context *ldb_ctx;
	struct ldb_control **parsed_controls;
	struct ldb_dn *base;
	PyLdbSearchIteratorObject *py_iter;

	/* type "int" rather than "enum" for "scope" is intentional */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|OizOOi",
					 discard_const_p(char *, kwnames),
					 &py_base, &scope, &expr, &py_attrs, &py_controls, &timeout))
		return NULL;

	py_iter = (PyLdbSearchIteratorObject *)PyLdbSearchIterator.tp_alloc(&PyLdbSearchIterator, 0);
	if (py_iter == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	py_iter->ldb = self;
	Py_INCREF(self);
	ZERO_STRUCT(py_iter->state);
	py_iter->mem_ctx = talloc_new(NULL);
	if (py_iter->mem_ctx == NULL) {
		Py_DECREF(py_iter);
		PyErr_NoMemory();
		return NULL;
	}

	ldb_ctx = pyldb_Ldb_AS_LDBCONTEXT(self);

	if (py_attrs == Py_None) {
		attrs = NULL;
	} else {
		attrs = PyList_AsStrList(py_iter->mem_ctx, py_attrs, "attrs");
		if (attrs == NULL) {
			Py_DECREF(py_iter);
			PyErr_NoMemory();
			return NULL;
		}
	}

	if (py_base == Py_None) {
		base = ldb_get_default_basedn(ldb_ctx);
	} else {
		if (!pyldb_Object_AsDn(py_iter->mem_ctx, py_base, ldb_ctx, &base)) {
			Py_DECREF(py_iter);
			PyErr_NoMemory();
			return NULL;
		}
	}

	if (py_controls == Py_None) {
		parsed_controls = NULL;
	} else {
		const char **controls = NULL;

		controls = PyList_AsStrList(py_iter->mem_ctx,
					    py_controls, "controls");
		if (controls == NULL) {
			Py_DECREF(py_iter);
			PyErr_NoMemory();
			return NULL;
		}

		parsed_controls = ldb_parse_control_strings(ldb_ctx,
							    py_iter->mem_ctx,
							    controls);
		if (controls[0] != NULL && parsed_controls == NULL) {
			Py_DECREF(py_iter);
			PyErr_NoMemory();
			return NULL;
		}
		talloc_free(controls);
	}

	ret = ldb_build_search_req(&py_iter->state.req,
				   ldb_ctx,
				   py_iter->mem_ctx,
				   base,
				   scope,
				   expr,
				   attrs,
				   parsed_controls,
				   py_iter,
				   py_ldb_search_iterator_callback,
				   NULL);
	if (ret != LDB_SUCCESS) {
		Py_DECREF(py_iter);
		PyErr_SetLdbError(PyExc_LdbError, ret, ldb_ctx);
		return NULL;
	}

	ldb_set_timeout(ldb_ctx, py_iter->state.req, timeout);

	ret = ldb_request(ldb_ctx, py_iter->state.req);
	if (ret != LDB_SUCCESS) {
		Py_DECREF(py_iter);
		PyErr_SetLdbError(PyExc_LdbError, ret, ldb_ctx);
		return NULL;
	}

	return (PyObject *)py_iter;
}

static PyObject *py_ldb_get_opaque(PyLdbObject *self, PyObject *args)
{
	char *name;
	void *data;

	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	data = ldb_get_opaque(pyldb_Ldb_AS_LDBCONTEXT(self), name);

	if (data == NULL)
		Py_RETURN_NONE;

	/* FIXME: More interpretation */

	Py_RETURN_TRUE;
}

static PyObject *py_ldb_set_opaque(PyLdbObject *self, PyObject *args)
{
	char *name;
	PyObject *data;

	if (!PyArg_ParseTuple(args, "sO", &name, &data))
		return NULL;

	/* FIXME: More interpretation */

	ldb_set_opaque(pyldb_Ldb_AS_LDBCONTEXT(self), name, data);

	Py_RETURN_NONE;
}

static PyObject *py_ldb_modules(PyLdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_context *ldb = pyldb_Ldb_AS_LDBCONTEXT(self);
	PyObject *ret = PyList_New(0);
	struct ldb_module *mod;

	if (ret == NULL) {
		return PyErr_NoMemory();
	}
	for (mod = ldb->modules; mod; mod = mod->next) {
		PyObject *item = PyLdbModule_FromModule(mod);
		int res = 0;
		if (item == NULL) {
			PyErr_SetString(PyExc_RuntimeError,
				"Failed to load LdbModule");
			Py_CLEAR(ret);
			return NULL;
		}
		res = PyList_Append(ret, item);
		Py_CLEAR(item);
		if (res == -1) {
			Py_CLEAR(ret);
			return NULL;
		}
	}

	return ret;
}

static PyObject *py_ldb_sequence_number(PyLdbObject *self, PyObject *args)
{
	struct ldb_context *ldb = pyldb_Ldb_AS_LDBCONTEXT(self);
	int type, ret;
	uint64_t value;

	if (!PyArg_ParseTuple(args, "i", &type))
		return NULL;

	/* FIXME: More interpretation */

	ret = ldb_sequence_number(ldb, type, &value);

	PyErr_LDB_ERROR_IS_ERR_RAISE(PyExc_LdbError, ret, ldb);

	return PyLong_FromLongLong(value);
}


static const struct ldb_dn_extended_syntax test_dn_syntax = {
	.name             = "TEST",
	.read_fn          = ldb_handler_copy,
	.write_clear_fn   = ldb_handler_copy,
	.write_hex_fn     = ldb_handler_copy,
};

static PyObject *py_ldb_register_test_extensions(PyLdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_context *ldb = pyldb_Ldb_AS_LDBCONTEXT(self);
	int ret;

	ret = ldb_dn_extended_add_syntax(ldb, LDB_ATTR_FLAG_FIXED, &test_dn_syntax);

	PyErr_LDB_ERROR_IS_ERR_RAISE(PyExc_LdbError, ret, ldb);

	Py_RETURN_NONE;
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
	{ "transaction_prepare_commit", (PyCFunction)py_ldb_transaction_prepare_commit, METH_NOARGS,
		"S.transaction_prepare_commit() -> None\n"
		"prepare to commit a new transaction (2-stage commit)." },
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
	{ "connect", PY_DISCARD_FUNC_SIG(PyCFunction, py_ldb_connect),
		METH_VARARGS|METH_KEYWORDS,
		"S.connect(url, flags=0, options=None) -> None\n"
		"Connect to a LDB URL." },
	{ "modify", PY_DISCARD_FUNC_SIG(PyCFunction, py_ldb_modify),
		METH_VARARGS|METH_KEYWORDS,
		"S.modify(message, controls=None, validate=False) -> None\n"
		"Modify an entry." },
	{ "add", PY_DISCARD_FUNC_SIG(PyCFunction, py_ldb_add),
		METH_VARARGS|METH_KEYWORDS,
		"S.add(message, controls=None) -> None\n"
		"Add an entry." },
	{ "delete", PY_DISCARD_FUNC_SIG(PyCFunction, py_ldb_delete),
		METH_VARARGS|METH_KEYWORDS,
		"S.delete(dn, controls=None) -> None\n"
		"Remove an entry." },
	{ "rename", PY_DISCARD_FUNC_SIG(PyCFunction, py_ldb_rename),
		METH_VARARGS|METH_KEYWORDS,
		"S.rename(old_dn, new_dn, controls=None) -> None\n"
		"Rename an entry." },
	{ "search", PY_DISCARD_FUNC_SIG(PyCFunction, py_ldb_search),
		METH_VARARGS|METH_KEYWORDS,
		"S.search(base=None, scope=None, expression=None, attrs=None, controls=None) -> result\n"
		"Search in a database.\n"
		"\n"
		":param base: Optional base DN to search\n"
		":param scope: Search scope (SCOPE_BASE, SCOPE_ONELEVEL or SCOPE_SUBTREE)\n"
		":param expression: Optional search expression\n"
		":param attrs: Attributes to return (defaults to all)\n"
		":param controls: Optional list of controls\n"
		":return: ldb.Result object\n"
	},
	{ "search_iterator", PY_DISCARD_FUNC_SIG(PyCFunction,
						 py_ldb_search_iterator),
		METH_VARARGS|METH_KEYWORDS,
		"S.search_iterator(base=None, scope=None, expression=None, attrs=None, controls=None, timeout=None) -> iterator\n"
		"Search in a database.\n"
		"\n"
		":param base: Optional base DN to search\n"
		":param scope: Search scope (SCOPE_BASE, SCOPE_ONELEVEL or SCOPE_SUBTREE)\n"
		":param expression: Optional search expression\n"
		":param attrs: Attributes to return (defaults to all)\n"
		":param controls: Optional list of controls\n"
		":param timeout: Optional timeout in seconds (defaults to 300), 0 means the default, -1 no timeout\n"
		":return: ldb.SearchIterator object that provides results when they arrive\n"
	},
	{ "schema_attribute_remove", (PyCFunction)py_ldb_schema_attribute_remove, METH_VARARGS,
		NULL },
	{ "schema_attribute_add", (PyCFunction)py_ldb_schema_attribute_add, METH_VARARGS,
		NULL },
	{ "schema_format_value", (PyCFunction)py_ldb_schema_format_value, METH_VARARGS,
		NULL },
	{ "parse_ldif", (PyCFunction)py_ldb_parse_ldif, METH_VARARGS,
		"S.parse_ldif(ldif) -> iter(messages)\n"
		"Parse a string formatted using LDIF." },
	{ "write_ldif", (PyCFunction)py_ldb_write_ldif, METH_VARARGS,
		"S.write_ldif(message, changetype) -> ldif\n"
		"Print the message as a string formatted using LDIF." },
	{ "msg_diff", (PyCFunction)py_ldb_msg_diff, METH_VARARGS,
		"S.msg_diff(Message) -> Message\n"
		"Return an LDB Message of the difference between two Message objects." },
	{ "get_opaque", (PyCFunction)py_ldb_get_opaque, METH_VARARGS,
		"S.get_opaque(name) -> value\n"
		"Get an opaque value set on this LDB connection. \n"
		":note: The returned value may not be useful in Python."
	},
	{ "set_opaque", (PyCFunction)py_ldb_set_opaque, METH_VARARGS,
		"S.set_opaque(name, value) -> None\n"
		"Set an opaque value on this LDB connection. \n"
		":note: Passing incorrect values may cause crashes." },
	{ "modules", (PyCFunction)py_ldb_modules, METH_NOARGS,
		"S.modules() -> list\n"
		"Return the list of modules on this LDB connection " },
	{ "sequence_number", (PyCFunction)py_ldb_sequence_number, METH_VARARGS,
		"S.sequence_number(type) -> value\n"
		"Return the value of the sequence according to the requested type" },
	{ "_register_test_extensions", (PyCFunction)py_ldb_register_test_extensions, METH_NOARGS,
		"S._register_test_extensions() -> None\n"
		"Register internal extensions used in testing" },
	{0},
};

static PyObject *PyLdbModule_FromModule(struct ldb_module *mod)
{
	PyLdbModuleObject *ret;

	ret = (PyLdbModuleObject *)PyLdbModule.tp_alloc(&PyLdbModule, 0);
	if (ret == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	ret->mem_ctx = talloc_new(NULL);
	ret->mod = talloc_reference(ret->mem_ctx, mod);
	return (PyObject *)ret;
}

static PyObject *py_ldb_get_firstmodule(PyLdbObject *self, void *closure)
{
	struct ldb_module *mod = pyldb_Ldb_AS_LDBCONTEXT(self)->modules;
	if (mod == NULL) {
		Py_RETURN_NONE;
	}
	return PyLdbModule_FromModule(mod);
}

static PyGetSetDef py_ldb_getset[] = {
	{
		.name = discard_const_p(char, "firstmodule"),
		.get  = (getter)py_ldb_get_firstmodule,
	},
	{ .name = NULL },
};

static int py_ldb_contains(PyLdbObject *self, PyObject *obj)
{
	struct ldb_context *ldb_ctx = pyldb_Ldb_AS_LDBCONTEXT(self);
	struct ldb_dn *dn;
	struct ldb_result *result;
	unsigned int count;
	int ret;

	if (!pyldb_Object_AsDn(ldb_ctx, obj, ldb_ctx, &dn)) {
		return -1;
	}

	ret = ldb_search(ldb_ctx, ldb_ctx, &result, dn, LDB_SCOPE_BASE, NULL,
			 NULL);
	if (ret != LDB_SUCCESS) {
		PyErr_SetLdbError(PyExc_LdbError, ret, ldb_ctx);
		return -1;
	}

	count = result->count;

	talloc_free(result);

	if (count > 1) {
		PyErr_Format(PyExc_RuntimeError,
			     "Searching for [%s] dn gave %u results!",
			     ldb_dn_get_linearized(dn),
			     count);
		return -1;
	}

	return count;
}

static PySequenceMethods py_ldb_seq = {
	.sq_contains = (objobjproc)py_ldb_contains,
};

static PyObject *PyLdb_FromLdbContext(struct ldb_context *ldb_ctx)
{
	PyLdbObject *ret;

	ret = (PyLdbObject *)PyLdb.tp_alloc(&PyLdb, 0);
	if (ret == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	ret->mem_ctx = talloc_new(NULL);
	ret->ldb_ctx = talloc_reference(ret->mem_ctx, ldb_ctx);
	return (PyObject *)ret;
}

static void py_ldb_dealloc(PyLdbObject *self)
{
	talloc_free(self->mem_ctx);
	Py_TYPE(self)->tp_free(self);
}

static PyTypeObject PyLdb = {
	.tp_name = "ldb.Ldb",
	.tp_methods = py_ldb_methods,
	.tp_repr = (reprfunc)py_ldb_repr,
	.tp_new = py_ldb_new,
	.tp_init = (initproc)py_ldb_init,
	.tp_dealloc = (destructor)py_ldb_dealloc,
	.tp_getset = py_ldb_getset,
	.tp_getattro = PyObject_GenericGetAttr,
	.tp_basicsize = sizeof(PyLdbObject),
	.tp_doc = "Connection to a LDB database.",
	.tp_as_sequence = &py_ldb_seq,
	.tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
};

static void py_ldb_result_dealloc(PyLdbResultObject *self)
{
	talloc_free(self->mem_ctx);
	Py_DECREF(self->msgs);
	Py_DECREF(self->referals);
	Py_DECREF(self->controls);
	Py_TYPE(self)->tp_free(self);
}

static PyObject *py_ldb_result_get_msgs(PyLdbResultObject *self, void *closure)
{
	Py_INCREF(self->msgs);
	return self->msgs;
}

static PyObject *py_ldb_result_get_controls(PyLdbResultObject *self, void *closure)
{
	Py_INCREF(self->controls);
	return self->controls;
}

static PyObject *py_ldb_result_get_referals(PyLdbResultObject *self, void *closure)
{
	Py_INCREF(self->referals);
	return self->referals;
}

static PyObject *py_ldb_result_get_count(PyLdbResultObject *self, void *closure)
{
	Py_ssize_t size;
	if (self->msgs == NULL) {
		PyErr_SetString(PyExc_AttributeError, "Count attribute is meaningless in this context");
		return NULL;
	}
	size = PyList_Size(self->msgs);
	return PyLong_FromLong(size);
}

static PyGetSetDef py_ldb_result_getset[] = {
	{
		.name = discard_const_p(char, "controls"),
		.get  = (getter)py_ldb_result_get_controls,
	},
	{
		.name = discard_const_p(char, "msgs"),
		.get  = (getter)py_ldb_result_get_msgs,
	},
	{
		.name = discard_const_p(char, "referals"),
		.get  = (getter)py_ldb_result_get_referals,
	},
	{
		.name = discard_const_p(char, "count"),
		.get  = (getter)py_ldb_result_get_count,
	},
	{ .name = NULL },
};

static PyObject *py_ldb_result_iter(PyLdbResultObject *self)
{
	return PyObject_GetIter(self->msgs);
}

static Py_ssize_t py_ldb_result_len(PyLdbResultObject *self)
{
	return PySequence_Size(self->msgs);
}

static PyObject *py_ldb_result_find(PyLdbResultObject *self, Py_ssize_t idx)
{
	return PySequence_GetItem(self->msgs, idx);
}

static PySequenceMethods py_ldb_result_seq = {
	.sq_length = (lenfunc)py_ldb_result_len,
	.sq_item = (ssizeargfunc)py_ldb_result_find,
};

static PyObject *py_ldb_result_repr(PyLdbObject *self)
{
	return PyUnicode_FromString("<ldb result>");
}


static PyTypeObject PyLdbResult = {
	.tp_name = "ldb.Result",
	.tp_repr = (reprfunc)py_ldb_result_repr,
	.tp_dealloc = (destructor)py_ldb_result_dealloc,
	.tp_iter = (getiterfunc)py_ldb_result_iter,
	.tp_getset = py_ldb_result_getset,
	.tp_getattro = PyObject_GenericGetAttr,
	.tp_basicsize = sizeof(PyLdbResultObject),
	.tp_as_sequence = &py_ldb_result_seq,
	.tp_doc = "LDB result.",
	.tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
};

static void py_ldb_search_iterator_dealloc(PyLdbSearchIteratorObject *self)
{
	Py_XDECREF(self->state.exception);
	TALLOC_FREE(self->mem_ctx);
	ZERO_STRUCT(self->state);
	Py_DECREF(self->ldb);
	Py_TYPE(self)->tp_free(self);
}

static PyObject *py_ldb_search_iterator_next(PyLdbSearchIteratorObject *self)
{
	PyObject *py_ret = NULL;

	if (self->state.req == NULL) {
		PyErr_SetString(PyExc_RuntimeError,
				"ldb.SearchIterator request already finished");
		return NULL;
	}

	/*
	 * TODO: do we want a non-blocking mode?
	 * In future we may add an optional 'nonblocking'
	 * argument to search_iterator().
	 *
	 * For now we keep it simple and wait for at
	 * least one reply.
	 */

	while (self->state.next == NULL) {
		int ret;

		if (self->state.result != NULL) {
			/*
			 * We (already) got a final result from the server.
			 *
			 * We stop the iteration and let
			 * py_ldb_search_iterator_result() will deliver
			 * the result details.
			 */
			TALLOC_FREE(self->state.req);
			PyErr_SetNone(PyExc_StopIteration);
			return NULL;
		}

		ret = ldb_wait(self->state.req->handle, LDB_WAIT_NONE);
		if (ret != LDB_SUCCESS) {
			struct ldb_context *ldb_ctx;
			TALLOC_FREE(self->state.req);
			ldb_ctx = pyldb_Ldb_AS_LDBCONTEXT(self->ldb);
			/*
			 * We stop the iteration and let
			 * py_ldb_search_iterator_result() will deliver
			 * the exception.
			 */
			self->state.exception = Py_BuildValue(discard_const_p(char, "(i,s)"),
						ret, ldb_errstring(ldb_ctx));
			PyErr_SetNone(PyExc_StopIteration);
			return NULL;
		}
	}

	py_ret = self->state.next->obj;
	self->state.next->obj = NULL;
	/* no TALLOC_FREE() as self->state.next is a list */
	talloc_free(self->state.next);
	return py_ret;
}

static PyObject *py_ldb_search_iterator_result(PyLdbSearchIteratorObject *self,
		PyObject *Py_UNUSED(ignored))
{
	PyObject *py_ret = NULL;

	if (self->state.req != NULL) {
		PyErr_SetString(PyExc_RuntimeError,
				"ldb.SearchIterator request running");
		return NULL;
	}

	if (self->state.next != NULL) {
		PyErr_SetString(PyExc_RuntimeError,
				"ldb.SearchIterator not fully consumed.");
		return NULL;
	}

	if (self->state.exception != NULL) {
		PyErr_SetObject(PyExc_LdbError, self->state.exception);
		self->state.exception = NULL;
		return NULL;
	}

	if (self->state.result == NULL) {
		PyErr_SetString(PyExc_RuntimeError,
				"ldb.SearchIterator result already consumed");
		return NULL;
	}

	py_ret = self->state.result->obj;
	self->state.result->obj = NULL;
	TALLOC_FREE(self->state.result);
	return py_ret;
}

static PyObject *py_ldb_search_iterator_abandon(PyLdbSearchIteratorObject *self,
		PyObject *Py_UNUSED(ignored))
{
	if (self->state.req == NULL) {
		PyErr_SetString(PyExc_RuntimeError,
				"ldb.SearchIterator request already finished");
		return NULL;
	}

	Py_XDECREF(self->state.exception);
	TALLOC_FREE(self->mem_ctx);
	ZERO_STRUCT(self->state);
	Py_RETURN_NONE;
}

static PyMethodDef py_ldb_search_iterator_methods[] = {
	{ "result", (PyCFunction)py_ldb_search_iterator_result, METH_NOARGS,
		"S.result() -> ldb.Result (without msgs and referrals)\n" },
	{ "abandon", (PyCFunction)py_ldb_search_iterator_abandon, METH_NOARGS,
		"S.abandon()\n" },
	{0}
};

static PyObject *py_ldb_search_iterator_repr(PyLdbSearchIteratorObject *self)
{
	return PyUnicode_FromString("<ldb search iterator>");
}

static PyTypeObject PyLdbSearchIterator = {
	.tp_name = "ldb.SearchIterator",
	.tp_repr = (reprfunc)py_ldb_search_iterator_repr,
	.tp_dealloc = (destructor)py_ldb_search_iterator_dealloc,
	.tp_iter = PyObject_SelfIter,
	.tp_iternext = (iternextfunc)py_ldb_search_iterator_next,
	.tp_methods = py_ldb_search_iterator_methods,
	.tp_basicsize = sizeof(PyLdbSearchIteratorObject),
	.tp_doc = "LDB search_iterator.",
	.tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
};

static PyObject *py_ldb_module_repr(PyLdbModuleObject *self)
{
	return PyUnicode_FromFormat("<ldb module '%s'>",
		pyldb_Module_AsModule(self)->ops->name);
}

static PyObject *py_ldb_module_str(PyLdbModuleObject *self)
{
	return PyUnicode_FromString(pyldb_Module_AsModule(self)->ops->name);
}

static PyObject *py_ldb_module_start_transaction(PyLdbModuleObject *self,
		PyObject *Py_UNUSED(ignored))
{
	pyldb_Module_AsModule(self)->ops->start_transaction(pyldb_Module_AsModule(self));
	Py_RETURN_NONE;
}

static PyObject *py_ldb_module_end_transaction(PyLdbModuleObject *self,
		PyObject *Py_UNUSED(ignored))
{
	pyldb_Module_AsModule(self)->ops->end_transaction(pyldb_Module_AsModule(self));
	Py_RETURN_NONE;
}

static PyObject *py_ldb_module_del_transaction(PyLdbModuleObject *self,
		PyObject *Py_UNUSED(ignored))
{
	pyldb_Module_AsModule(self)->ops->del_transaction(pyldb_Module_AsModule(self));
	Py_RETURN_NONE;
}

static PyObject *py_ldb_module_search(PyLdbModuleObject *self, PyObject *args, PyObject *kwargs)
{
	PyObject *py_base, *py_tree, *py_attrs, *py_ret;
	int ret, scope;
	struct ldb_request *req;
	const char * const kwnames[] = { "base", "scope", "tree", "attrs", NULL };
	struct ldb_module *mod;
	const char * const*attrs;

	/* type "int" rather than "enum" for "scope" is intentional */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!iOO",
					 discard_const_p(char *, kwnames),
					 &PyLdbDn, &py_base, &scope, &py_tree, &py_attrs))
		return NULL;

	mod = self->mod;

	if (py_attrs == Py_None) {
		attrs = NULL;
	} else {
		attrs = PyList_AsStrList(NULL, py_attrs, "attrs");
		if (attrs == NULL)
			return NULL;
	}

	ret = ldb_build_search_req(&req, mod->ldb, NULL, pyldb_Dn_AS_DN(py_base),
			     scope, NULL /* expr */, attrs,
			     NULL /* controls */, NULL, NULL, NULL);

	talloc_steal(req, attrs);

	PyErr_LDB_ERROR_IS_ERR_RAISE(PyExc_LdbError, ret, mod->ldb);

	req->op.search.res = NULL;

	ret = mod->ops->search(mod, req);

	PyErr_LDB_ERROR_IS_ERR_RAISE(PyExc_LdbError, ret, mod->ldb);

	py_ret = PyLdbResult_FromResult(req->op.search.res);

	talloc_free(req);

	return py_ret;
}


static PyObject *py_ldb_module_add(PyLdbModuleObject *self, PyObject *args)
{
	struct ldb_request *req;
	PyObject *py_message;
	int ret;
	struct ldb_module *mod;

	if (!PyArg_ParseTuple(args, "O!", &PyLdbMessage, &py_message))
		return NULL;

	req = talloc_zero(NULL, struct ldb_request);
	req->operation = LDB_ADD;
	req->op.add.message = pyldb_Message_AsMessage(py_message);

	mod = pyldb_Module_AsModule(self);
	ret = mod->ops->add(mod, req);

	PyErr_LDB_ERROR_IS_ERR_RAISE(PyExc_LdbError, ret, mod->ldb);

	Py_RETURN_NONE;
}

static PyObject *py_ldb_module_modify(PyLdbModuleObject *self, PyObject *args) 
{
	int ret;
	struct ldb_request *req;
	PyObject *py_message;
	struct ldb_module *mod;

	if (!PyArg_ParseTuple(args, "O!", &PyLdbMessage, &py_message))
		return NULL;

	req = talloc_zero(NULL, struct ldb_request);
	req->operation = LDB_MODIFY;
	req->op.mod.message = pyldb_Message_AsMessage(py_message);

	mod = pyldb_Module_AsModule(self);
	ret = mod->ops->modify(mod, req);

	PyErr_LDB_ERROR_IS_ERR_RAISE(PyExc_LdbError, ret, mod->ldb);

	Py_RETURN_NONE;
}

static PyObject *py_ldb_module_delete(PyLdbModuleObject *self, PyObject *args) 
{
	int ret;
	struct ldb_request *req;
	PyObject *py_dn;

	if (!PyArg_ParseTuple(args, "O!", &PyLdbDn, &py_dn))
		return NULL;

	req = talloc_zero(NULL, struct ldb_request);
	req->operation = LDB_DELETE;
	req->op.del.dn = pyldb_Dn_AS_DN(py_dn);

	ret = pyldb_Module_AsModule(self)->ops->del(pyldb_Module_AsModule(self), req);

	PyErr_LDB_ERROR_IS_ERR_RAISE(PyExc_LdbError, ret, NULL);

	Py_RETURN_NONE;
}

static PyObject *py_ldb_module_rename(PyLdbModuleObject *self, PyObject *args)
{
	int ret;
	struct ldb_request *req;
	PyObject *py_dn1, *py_dn2;

	if (!PyArg_ParseTuple(args, "O!O!", &PyLdbDn, &py_dn1, &PyLdbDn, &py_dn2))
		return NULL;

	req = talloc_zero(NULL, struct ldb_request);

	req->operation = LDB_RENAME;
	req->op.rename.olddn = pyldb_Dn_AS_DN(py_dn1);
	req->op.rename.newdn = pyldb_Dn_AS_DN(py_dn2);

	ret = pyldb_Module_AsModule(self)->ops->rename(pyldb_Module_AsModule(self), req);

	PyErr_LDB_ERROR_IS_ERR_RAISE(PyExc_LdbError, ret, NULL);

	Py_RETURN_NONE;
}

static PyMethodDef py_ldb_module_methods[] = {
	{ "search", PY_DISCARD_FUNC_SIG(PyCFunction, py_ldb_module_search),
		METH_VARARGS|METH_KEYWORDS, NULL },
	{ "add", (PyCFunction)py_ldb_module_add, METH_VARARGS, NULL },
	{ "modify", (PyCFunction)py_ldb_module_modify, METH_VARARGS, NULL },
	{ "rename", (PyCFunction)py_ldb_module_rename, METH_VARARGS, NULL },
	{ "delete", (PyCFunction)py_ldb_module_delete, METH_VARARGS, NULL },
	{ "start_transaction", (PyCFunction)py_ldb_module_start_transaction, METH_NOARGS, NULL },
	{ "end_transaction", (PyCFunction)py_ldb_module_end_transaction, METH_NOARGS, NULL },
	{ "del_transaction", (PyCFunction)py_ldb_module_del_transaction, METH_NOARGS, NULL },
	{0},
};

static void py_ldb_module_dealloc(PyLdbModuleObject *self)
{
	talloc_free(self->mem_ctx);
	PyObject_Del(self);
}

static PyTypeObject PyLdbModule = {
	.tp_name = "ldb.LdbModule",
	.tp_methods = py_ldb_module_methods,
	.tp_repr = (reprfunc)py_ldb_module_repr,
	.tp_str = (reprfunc)py_ldb_module_str,
	.tp_basicsize = sizeof(PyLdbModuleObject),
	.tp_dealloc = (destructor)py_ldb_module_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = "LDB module (extension)",
};


/**
 * Create a ldb_message_element from a Python object.
 *
 * This will accept any sequence objects that contains strings, or 
 * a string object.
 *
 * A reference to set_obj will be borrowed. 
 *
 * @param mem_ctx Memory context
 * @param set_obj Python object to convert
 * @param flags ldb_message_element flags to set
 * @param attr_name Name of the attribute
 * @return New ldb_message_element, allocated as child of mem_ctx
 */
static struct ldb_message_element *PyObject_AsMessageElement(
						      TALLOC_CTX *mem_ctx,
						      PyObject *set_obj,
						      unsigned int flags,
						      const char *attr_name)
{
	struct ldb_message_element *me;
	const char *msg = NULL;
	Py_ssize_t size;
	int result;

	if (pyldb_MessageElement_Check(set_obj)) {
		PyLdbMessageElementObject *set_obj_as_me = (PyLdbMessageElementObject *)set_obj;
		/* We have to talloc_reference() the memory context, not the pointer
		 * which may not actually be it's own context */
		if (talloc_reference(mem_ctx, set_obj_as_me->mem_ctx)) {
			return pyldb_MessageElement_AsMessageElement(set_obj);
		}
		return NULL;
	}

	me = talloc(mem_ctx, struct ldb_message_element);
	if (me == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	me->name = talloc_strdup(me, attr_name);
	me->flags = flags;
	if (PyBytes_Check(set_obj) || PyUnicode_Check(set_obj)) {
		me->num_values = 1;
		me->values = talloc_array(me, struct ldb_val, me->num_values);
		if (PyBytes_Check(set_obj)) {
			char *_msg = NULL;
			result = PyBytes_AsStringAndSize(set_obj, &_msg, &size);
			if (result != 0) {
				talloc_free(me);
				return NULL;
			}
			msg = _msg;
		} else {
			msg = PyUnicode_AsUTF8AndSize(set_obj, &size);
			if (msg == NULL) {
				talloc_free(me);
				return NULL;
			}
		}
		me->values[0].data = talloc_memdup(me,
						   (const uint8_t *)msg,
						   size+1);
		me->values[0].length = size;
	} else if (PySequence_Check(set_obj)) {
		Py_ssize_t i;
		me->num_values = PySequence_Size(set_obj);
		me->values = talloc_array(me, struct ldb_val, me->num_values);
		for (i = 0; i < me->num_values; i++) {
			PyObject *obj = PySequence_GetItem(set_obj, i);
			if (PyBytes_Check(obj)) {
				char *_msg = NULL;
				result = PyBytes_AsStringAndSize(obj, &_msg, &size);
				if (result != 0) {
					talloc_free(me);
					return NULL;
				}
				msg = _msg;
			} else if (PyUnicode_Check(obj)) {
				msg = PyUnicode_AsUTF8AndSize(obj, &size);
				if (msg == NULL) {
					talloc_free(me);
					return NULL;
				}
			} else {
				PyErr_Format(PyExc_TypeError,
					     "Expected string as element %zd in list", i);
				talloc_free(me);
				return NULL;
			}
			me->values[i].data = talloc_memdup(me,
							   (const uint8_t *)msg,
							   size+1);
			me->values[i].length = size;
		}
	} else {
		PyErr_Format(PyExc_TypeError,
			     "String or List type expected for '%s' attribute", attr_name);
		talloc_free(me);
		me = NULL;
	}

	return me;
}


static PyObject *ldb_msg_element_to_set(struct ldb_context *ldb_ctx,
					struct ldb_message_element *me)
{
	Py_ssize_t i;
	PyObject *result;

	/* Python << 2.5 doesn't have PySet_New and PySet_Add. */
	result = PyList_New(me->num_values);

	for (i = 0; i < me->num_values; i++) {
		PyList_SetItem(result, i,
			PyObject_FromLdbValue(&me->values[i]));
	}

	return result;
}

static PyObject *py_ldb_msg_element_get(PyLdbMessageElementObject *self, PyObject *args)
{
	unsigned int i;
	if (!PyArg_ParseTuple(args, "I", &i))
		return NULL;
	if (i >= pyldb_MessageElement_AsMessageElement(self)->num_values)
		Py_RETURN_NONE;

	return PyObject_FromLdbValue(&(pyldb_MessageElement_AsMessageElement(self)->values[i]));
}

static PyObject *py_ldb_msg_element_flags(PyLdbMessageElementObject *self, PyObject *args)
{
	struct ldb_message_element *el = pyldb_MessageElement_AsMessageElement(self);
	return PyLong_FromLong(el->flags);
}

static PyObject *py_ldb_msg_element_set_flags(PyLdbMessageElementObject *self, PyObject *args)
{
	unsigned int flags;
	struct ldb_message_element *el;
	if (!PyArg_ParseTuple(args, "I", &flags))
		return NULL;

	el = pyldb_MessageElement_AsMessageElement(self);
	el->flags = flags;
	Py_RETURN_NONE;
}

static PyMethodDef py_ldb_msg_element_methods[] = {
	{ "get", (PyCFunction)py_ldb_msg_element_get, METH_VARARGS, NULL },
	{ "set_flags", (PyCFunction)py_ldb_msg_element_set_flags, METH_VARARGS, NULL },
	{ "flags", (PyCFunction)py_ldb_msg_element_flags, METH_NOARGS, NULL },
	{0},
};

static Py_ssize_t py_ldb_msg_element_len(PyLdbMessageElementObject *self)
{
	return pyldb_MessageElement_AsMessageElement(self)->num_values;
}

static PyObject *py_ldb_msg_element_find(PyLdbMessageElementObject *self, Py_ssize_t idx)
{
	struct ldb_message_element *el = pyldb_MessageElement_AsMessageElement(self);
	if (idx < 0 || idx >= el->num_values) {
		PyErr_SetString(PyExc_IndexError, "Out of range");
		return NULL;
	}
	return PyLdbBytes_FromStringAndSize((char *)el->values[idx].data, el->values[idx].length);
}

static PySequenceMethods py_ldb_msg_element_seq = {
	.sq_length = (lenfunc)py_ldb_msg_element_len,
	.sq_item = (ssizeargfunc)py_ldb_msg_element_find,
};

static PyObject *py_ldb_msg_element_richcmp(PyObject *self, PyObject *other, int op)
{
	int ret;
	if (!pyldb_MessageElement_Check(other)) {
		Py_INCREF(Py_NotImplemented);
		return Py_NotImplemented;
	}
	ret = ldb_msg_element_compare(pyldb_MessageElement_AsMessageElement(self),
									  pyldb_MessageElement_AsMessageElement(other));
	return richcmp(ret, op);
}

static PyObject *py_ldb_msg_element_iter(PyLdbMessageElementObject *self)
{
	PyObject *el = ldb_msg_element_to_set(NULL,
					      pyldb_MessageElement_AsMessageElement(self));
	PyObject *ret = PyObject_GetIter(el);
	Py_DECREF(el);
	return ret;
}

static PyObject *PyLdbMessageElement_FromMessageElement(struct ldb_message_element *el, TALLOC_CTX *mem_ctx)
{
	PyLdbMessageElementObject *ret;
	ret = PyObject_New(PyLdbMessageElementObject, &PyLdbMessageElement);
	if (ret == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	ret->mem_ctx = talloc_new(NULL);
	if (talloc_reference(ret->mem_ctx, mem_ctx) == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	ret->el = el;
	return (PyObject *)ret;
}

static PyObject *py_ldb_msg_element_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	PyObject *py_elements = NULL;
	struct ldb_message_element *el;
	unsigned int flags = 0;
	char *name = NULL;
	const char * const kwnames[] = { "elements", "flags", "name", NULL };
	PyLdbMessageElementObject *ret;
	TALLOC_CTX *mem_ctx;
	const char *msg = NULL;
	Py_ssize_t size;
	int result;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|OIs",
					 discard_const_p(char *, kwnames),
					 &py_elements, &flags, &name))
		return NULL;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	el = talloc_zero(mem_ctx, struct ldb_message_element);
	if (el == NULL) {
		PyErr_NoMemory();
		talloc_free(mem_ctx);
		return NULL;
	}

	if (py_elements != NULL) {
		Py_ssize_t i;
		if (PyBytes_Check(py_elements) || PyUnicode_Check(py_elements)) {
			char *_msg = NULL;
			el->num_values = 1;
			el->values = talloc_array(el, struct ldb_val, 1);
			if (el->values == NULL) {
				talloc_free(mem_ctx);
				PyErr_NoMemory();
				return NULL;
			}
			if (PyBytes_Check(py_elements)) {
				result = PyBytes_AsStringAndSize(py_elements, &_msg, &size);
				msg = _msg;
			} else {
				msg = PyUnicode_AsUTF8AndSize(py_elements, &size);
				result = (msg == NULL) ? -1 : 0;
			}
			if (result != 0) {
				talloc_free(mem_ctx);
				return NULL;
			}
			el->values[0].data = talloc_memdup(el->values, 
				(const uint8_t *)msg, size + 1);
			el->values[0].length = size;
		} else if (PySequence_Check(py_elements)) {
			el->num_values = PySequence_Size(py_elements);
			el->values = talloc_array(el, struct ldb_val, el->num_values);
			if (el->values == NULL) {
				talloc_free(mem_ctx);
				PyErr_NoMemory();
				return NULL;
			}
			for (i = 0; i < el->num_values; i++) {
				PyObject *item = PySequence_GetItem(py_elements, i);
				if (item == NULL) {
					talloc_free(mem_ctx);
					return NULL;
				}
				if (PyBytes_Check(item)) {
					char *_msg = NULL;
					result = PyBytes_AsStringAndSize(item, &_msg, &size);
					msg = _msg;
				} else if (PyUnicode_Check(item)) {
					msg = PyUnicode_AsUTF8AndSize(item, &size);
					result = (msg == NULL) ? -1 : 0;
				} else {
					PyErr_Format(PyExc_TypeError, 
						     "Expected string as element %zd in list", i);
					result = -1;
				}
				if (result != 0) {
					talloc_free(mem_ctx);
					return NULL;
				}
				el->values[i].data = talloc_memdup(el,
					(const uint8_t *)msg, size+1);
				el->values[i].length = size;
			}
		} else {
			PyErr_SetString(PyExc_TypeError, 
					"Expected string or list");
			talloc_free(mem_ctx);
			return NULL;
		}
	}

	el->flags = flags;
	el->name = talloc_strdup(el, name);

	ret = PyObject_New(PyLdbMessageElementObject, type);
	if (ret == NULL) {
		talloc_free(mem_ctx);
		return NULL;
	}

	ret->mem_ctx = mem_ctx;
	ret->el = el;
	return (PyObject *)ret;
}

static PyObject *py_ldb_msg_element_repr(PyLdbMessageElementObject *self)
{
	char *element_str = NULL;
	Py_ssize_t i;
	struct ldb_message_element *el = pyldb_MessageElement_AsMessageElement(self);
	PyObject *ret, *repr;

	for (i = 0; i < el->num_values; i++) {
		PyObject *o = py_ldb_msg_element_find(self, i);
		repr = PyObject_Repr(o);
		if (element_str == NULL)
			element_str = talloc_strdup(NULL, PyUnicode_AsUTF8(repr));
		else
			element_str = talloc_asprintf_append(element_str, ",%s", PyUnicode_AsUTF8(repr));
		Py_DECREF(repr);
	}

	if (element_str != NULL) {
		ret = PyUnicode_FromFormat("MessageElement([%s])", element_str);
		talloc_free(element_str);
	} else {
		ret = PyUnicode_FromString("MessageElement([])");
	}

	return ret;
}

static PyObject *py_ldb_msg_element_str(PyLdbMessageElementObject *self)
{
	struct ldb_message_element *el = pyldb_MessageElement_AsMessageElement(self);

	if (el->num_values == 1)
		return PyUnicode_FromStringAndSize((char *)el->values[0].data, el->values[0].length);
	else
		Py_RETURN_NONE;
}

static void py_ldb_msg_element_dealloc(PyLdbMessageElementObject *self)
{
	talloc_free(self->mem_ctx);
	PyObject_Del(self);
}

static PyObject *py_ldb_msg_element_get_text(PyObject *self, void *closure)
{
	return wrap_text("MessageElementTextWrapper", self);
}

static PyGetSetDef py_ldb_msg_element_getset[] = {
	{
		.name = discard_const_p(char, "text"),
		.get  = (getter)py_ldb_msg_element_get_text,
	},
	{ .name = NULL }
};

static PyTypeObject PyLdbMessageElement = {
	.tp_name = "ldb.MessageElement",
	.tp_basicsize = sizeof(PyLdbMessageElementObject),
	.tp_dealloc = (destructor)py_ldb_msg_element_dealloc,
	.tp_repr = (reprfunc)py_ldb_msg_element_repr,
	.tp_str = (reprfunc)py_ldb_msg_element_str,
	.tp_methods = py_ldb_msg_element_methods,
	.tp_getset = py_ldb_msg_element_getset,
	.tp_richcompare = (richcmpfunc)py_ldb_msg_element_richcmp,
	.tp_iter = (getiterfunc)py_ldb_msg_element_iter,
	.tp_as_sequence = &py_ldb_msg_element_seq,
	.tp_new = py_ldb_msg_element_new,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = "An element of a Message",
};


static PyObject *py_ldb_msg_from_dict(PyTypeObject *type, PyObject *args)
{
	PyObject *py_ldb;
	PyObject *py_dict;
	PyObject *py_ret;
	struct ldb_message *msg;
	struct ldb_context *ldb_ctx;
	unsigned int mod_flags = LDB_FLAG_MOD_REPLACE;

	if (!PyArg_ParseTuple(args, "O!O!|I",
			      &PyLdb, &py_ldb, &PyDict_Type, &py_dict,
			      &mod_flags)) {
		return NULL;
	}

	if (!PyLdb_Check(py_ldb)) {
		PyErr_SetString(PyExc_TypeError, "Expected Ldb");
		return NULL;
	}

	/* mask only flags we are going to use */
	mod_flags = LDB_FLAG_MOD_TYPE(mod_flags);
	if (!mod_flags) {
		PyErr_SetString(PyExc_ValueError,
				"FLAG_MOD_ADD, FLAG_MOD_REPLACE or FLAG_MOD_DELETE"
				" expected as mod_flag value");
		return NULL;
	}

	ldb_ctx = pyldb_Ldb_AS_LDBCONTEXT(py_ldb);

	msg = PyDict_AsMessage(ldb_ctx, py_dict, ldb_ctx, mod_flags);
	if (!msg) {
		return NULL;
	}

	py_ret = PyLdbMessage_FromMessage(msg);

	talloc_unlink(ldb_ctx, msg);

	return py_ret;
}

static PyObject *py_ldb_msg_remove_attr(PyLdbMessageObject *self, PyObject *args)
{
	char *name;
	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	ldb_msg_remove_attr(self->msg, name);

	Py_RETURN_NONE;
}

static PyObject *py_ldb_msg_keys(PyLdbMessageObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_message *msg = pyldb_Message_AsMessage(self);
	Py_ssize_t i, j = 0;
	PyObject *obj = PyList_New(msg->num_elements+(msg->dn != NULL?1:0));
	if (msg->dn != NULL) {
		PyList_SetItem(obj, j, PyUnicode_FromString("dn"));
		j++;
	}
	for (i = 0; i < msg->num_elements; i++) {
		PyList_SetItem(obj, j, PyUnicode_FromString(msg->elements[i].name));
		j++;
	}
	return obj;
}

static int py_ldb_msg_contains(PyLdbMessageObject *self, PyObject *py_name)
{
	struct ldb_message_element *el = NULL;
	const char *name = NULL;
	struct ldb_message *msg = pyldb_Message_AsMessage(self);
	name = PyUnicode_AsUTF8(py_name);
	if (name == NULL) {
		return -1;
	}
	if (!ldb_attr_cmp(name, "dn")) {
		return 1;
	}
	el = ldb_msg_find_element(msg, name);
	return el != NULL ? 1 : 0;
}

static PyObject *py_ldb_msg_getitem(PyLdbMessageObject *self, PyObject *py_name)
{
	struct ldb_message_element *el = NULL;
	const char *name = NULL;
	struct ldb_message *msg = pyldb_Message_AsMessage(self);
	name = PyUnicode_AsUTF8(py_name);
	if (name == NULL) {
		return NULL;
	}
	if (!ldb_attr_cmp(name, "dn")) {
		return pyldb_Dn_FromDn(msg->dn);
	}
	el = ldb_msg_find_element(msg, name);
	if (el == NULL) {
		PyErr_SetString(PyExc_KeyError, "No such element");
		return NULL;
	}

	return PyLdbMessageElement_FromMessageElement(el, msg->elements);
}

static PyObject *py_ldb_msg_get(PyLdbMessageObject *self, PyObject *args, PyObject *kwargs)
{
	PyObject *def = NULL;
	const char *kwnames[] = { "name", "default", "idx", NULL };
	const char *name = NULL;
	int idx = -1;
	struct ldb_message *msg = pyldb_Message_AsMessage(self);
	struct ldb_message_element *el;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|Oi:msg",
					 discard_const_p(char *, kwnames), &name, &def, &idx)) {
		return NULL;
	}

	if (strcasecmp(name, "dn") == 0) {
		return pyldb_Dn_FromDn(msg->dn);
	}

	el = ldb_msg_find_element(msg, name);

	if (el == NULL || (idx != -1 && el->num_values <= idx)) {
		if (def != NULL) {
			Py_INCREF(def);
			return def;
		}
		Py_RETURN_NONE;
	}

	if (idx == -1) {
		return (PyObject *)PyLdbMessageElement_FromMessageElement(el, msg->elements);
	}

	return PyObject_FromLdbValue(&el->values[idx]);
}

static PyObject *py_ldb_msg_items(PyLdbMessageObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_message *msg = pyldb_Message_AsMessage(self);
	Py_ssize_t i, j = 0;
	PyObject *l = PyList_New(msg->num_elements + (msg->dn == NULL?0:1));
	if (l == NULL) {
		return PyErr_NoMemory();
	}
	if (msg->dn != NULL) {
		PyObject *value = NULL;
		PyObject *obj = pyldb_Dn_FromDn(msg->dn);
		int res = 0;
		value = Py_BuildValue("(sO)", "dn", obj);
		Py_CLEAR(obj);
		if (value == NULL) {
			Py_CLEAR(l);
			return NULL;
		}
		res = PyList_SetItem(l, 0, value);
		if (res == -1) {
			Py_CLEAR(l);
			return NULL;
		}
		j++;
	}
	for (i = 0; i < msg->num_elements; i++, j++) {
		PyObject *value = NULL;
		PyObject *py_el = PyLdbMessageElement_FromMessageElement(&msg->elements[i], msg->elements);
		int res = 0;
		value = Py_BuildValue("(sO)", msg->elements[i].name, py_el);
		Py_CLEAR(py_el);
		if (value == NULL ) {
			Py_CLEAR(l);
			return NULL;
		}
		res = PyList_SetItem(l, j, value);
		if (res == -1) {
			Py_CLEAR(l);
			return NULL;
		}
	}
	return l;
}

static PyObject *py_ldb_msg_elements(PyLdbMessageObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_message *msg = pyldb_Message_AsMessage(self);
	Py_ssize_t i = 0;
	PyObject *l = PyList_New(msg->num_elements);
	for (i = 0; i < msg->num_elements; i++) {
		PyList_SetItem(l, i, PyLdbMessageElement_FromMessageElement(&msg->elements[i], msg->elements));
	}
	return l;
}

static PyObject *py_ldb_msg_add(PyLdbMessageObject *self, PyObject *args)
{
	struct ldb_message *msg = pyldb_Message_AsMessage(self);
	PyLdbMessageElementObject *py_element;
	int i, ret;
	struct ldb_message_element *el;
	struct ldb_message_element *el_new;

	if (!PyArg_ParseTuple(args, "O!", &PyLdbMessageElement, &py_element))
		return NULL;

	el = py_element->el;
	if (el == NULL) {
		PyErr_SetString(PyExc_ValueError, "Invalid MessageElement object");
		return NULL;
	}
	if (el->name == NULL) {
		PyErr_SetString(PyExc_ValueError,
				"The element has no name");
		return NULL;
	}
	ret = ldb_msg_add_empty(msg, el->name, el->flags, &el_new);
	PyErr_LDB_ERROR_IS_ERR_RAISE(PyExc_LdbError, ret, NULL);

	/* now deep copy all attribute values */
	el_new->values = talloc_array(msg->elements, struct ldb_val, el->num_values);
	if (el_new->values == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	el_new->num_values = el->num_values;

	for (i = 0; i < el->num_values; i++) {
		el_new->values[i] = ldb_val_dup(el_new->values, &el->values[i]);
		if (el_new->values[i].data == NULL
				&& el->values[i].length != 0) {
			PyErr_NoMemory();
			return NULL;
		}
	}

	Py_RETURN_NONE;
}

static PyMethodDef py_ldb_msg_methods[] = {
	{ "from_dict", (PyCFunction)py_ldb_msg_from_dict, METH_CLASS | METH_VARARGS,
		"Message.from_dict(ldb, dict, mod_flag=FLAG_MOD_REPLACE) -> ldb.Message\n"
		"Class method to create ldb.Message object from Dictionary.\n"
		"mod_flag is one of FLAG_MOD_ADD, FLAG_MOD_REPLACE or FLAG_MOD_DELETE."},
	{ "keys", (PyCFunction)py_ldb_msg_keys, METH_NOARGS,
		"S.keys() -> list\n\n"
		"Return sequence of all attribute names." },
	{ "remove", (PyCFunction)py_ldb_msg_remove_attr, METH_VARARGS, 
		"S.remove(name)\n\n"
		"Remove all entries for attributes with the specified name."},
	{ "get", PY_DISCARD_FUNC_SIG(PyCFunction, py_ldb_msg_get),
		METH_VARARGS | METH_KEYWORDS,
	  "msg.get(name,default=None,idx=None) -> string\n"
	  "idx is the index into the values array\n"
	  "if idx is None, then a list is returned\n"
	  "if idx is not None, then the element with that index is returned\n"
	  "if you pass the special name 'dn' then the DN object is returned\n"},
	{ "items", (PyCFunction)py_ldb_msg_items, METH_NOARGS, NULL },
	{ "elements", (PyCFunction)py_ldb_msg_elements, METH_NOARGS, NULL },
	{ "add", (PyCFunction)py_ldb_msg_add, METH_VARARGS,
		"S.add(element)\n\n"
		"Add an element to this message." },
	{0},
};

static PyObject *py_ldb_msg_iter(PyLdbMessageObject *self)
{
	PyObject *list, *iter;

	list = py_ldb_msg_keys(self, NULL);
	iter = PyObject_GetIter(list);
	Py_DECREF(list);
	return iter;
}

static int py_ldb_msg_setitem(PyLdbMessageObject *self, PyObject *name, PyObject *value)
{
	const char *attr_name;

	attr_name = PyUnicode_AsUTF8(name);
	if (attr_name == NULL) {
		PyErr_SetNone(PyExc_TypeError);
		return -1;
	}

	if (value == NULL) {
		/* delitem */
		ldb_msg_remove_attr(self->msg, attr_name);
	} else {
		int ret;
		struct ldb_message_element *el = PyObject_AsMessageElement(self->msg,
									   value, 0, attr_name);
		if (el == NULL) {
			return -1;
		}
		ldb_msg_remove_attr(pyldb_Message_AsMessage(self), attr_name);
		ret = ldb_msg_add(pyldb_Message_AsMessage(self), el, el->flags);
		if (ret != LDB_SUCCESS) {
			PyErr_SetLdbError(PyExc_LdbError, ret, NULL);
			return -1;
		}
	}
	return 0;
}

static Py_ssize_t py_ldb_msg_length(PyLdbMessageObject *self)
{
	return pyldb_Message_AsMessage(self)->num_elements;
}

static PySequenceMethods py_ldb_msg_sequence = {
	.sq_contains = (objobjproc)py_ldb_msg_contains,
};

static PyMappingMethods py_ldb_msg_mapping = {
	.mp_length = (lenfunc)py_ldb_msg_length,
	.mp_subscript = (binaryfunc)py_ldb_msg_getitem,
	.mp_ass_subscript = (objobjargproc)py_ldb_msg_setitem,
};

static PyObject *py_ldb_msg_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	const char * const kwnames[] = { "dn", NULL };
	struct ldb_message *ret;
	TALLOC_CTX *mem_ctx;
	PyObject *pydn = NULL;
	PyLdbMessageObject *py_ret;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|O",
					 discard_const_p(char *, kwnames),
					 &pydn))
		return NULL;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	ret = ldb_msg_new(mem_ctx);
	if (ret == NULL) {
		talloc_free(mem_ctx);
		PyErr_NoMemory();
		return NULL;
	}

	if (pydn != NULL) {
		struct ldb_dn *dn;
		if (!pyldb_Object_AsDn(NULL, pydn, NULL, &dn)) {
			talloc_free(mem_ctx);
			return NULL;
		}
		ret->dn = talloc_reference(ret, dn);
	}

	py_ret = (PyLdbMessageObject *)type->tp_alloc(type, 0);
	if (py_ret == NULL) {
		PyErr_NoMemory();
		talloc_free(mem_ctx);
		return NULL;
	}

	py_ret->mem_ctx = mem_ctx;
	py_ret->msg = ret;
	return (PyObject *)py_ret;
}

static PyObject *PyLdbMessage_FromMessage(struct ldb_message *msg)
{
	PyLdbMessageObject *ret;

	ret = (PyLdbMessageObject *)PyLdbMessage.tp_alloc(&PyLdbMessage, 0);
	if (ret == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	ret->mem_ctx = talloc_new(NULL);
	ret->msg = talloc_reference(ret->mem_ctx, msg);
	return (PyObject *)ret;
}

static PyObject *py_ldb_msg_get_dn(PyLdbMessageObject *self, void *closure)
{
	struct ldb_message *msg = pyldb_Message_AsMessage(self);
	return pyldb_Dn_FromDn(msg->dn);
}

static int py_ldb_msg_set_dn(PyLdbMessageObject *self, PyObject *value, void *closure)
{
	struct ldb_message *msg = pyldb_Message_AsMessage(self);
	if (value == NULL) {
		PyErr_SetString(PyExc_AttributeError, "cannot delete dn");
		return -1;
	}
	if (!pyldb_Dn_Check(value)) {
		PyErr_SetString(PyExc_TypeError, "expected dn");
		return -1;
	}

	msg->dn = talloc_reference(msg, pyldb_Dn_AS_DN(value));
	return 0;
}

static PyObject *py_ldb_msg_get_text(PyObject *self, void *closure)
{
	return wrap_text("MessageTextWrapper", self);
}

static PyGetSetDef py_ldb_msg_getset[] = {
	{
		.name = discard_const_p(char, "dn"),
		.get  = (getter)py_ldb_msg_get_dn,
		.set  = (setter)py_ldb_msg_set_dn,
	},
	{
		.name = discard_const_p(char, "text"),
		.get  = (getter)py_ldb_msg_get_text,
	},
	{ .name = NULL },
};

static PyObject *py_ldb_msg_repr(PyLdbMessageObject *self)
{
	PyObject *dict = PyDict_New(), *ret, *repr;
	if (PyDict_Update(dict, (PyObject *)self) != 0)
		return NULL;
	repr = PyObject_Repr(dict);
	if (repr == NULL) {
		Py_DECREF(dict);
		return NULL;
	}
	ret = PyUnicode_FromFormat("Message(%s)", PyUnicode_AsUTF8(repr));
	Py_DECREF(repr);
	Py_DECREF(dict);
	return ret;
}

static void py_ldb_msg_dealloc(PyLdbMessageObject *self)
{
	talloc_free(self->mem_ctx);
	PyObject_Del(self);
}

static PyObject *py_ldb_msg_richcmp(PyLdbMessageObject *py_msg1,
			      PyLdbMessageObject *py_msg2, int op)
{
	struct ldb_message *msg1, *msg2;
	unsigned int i;
	int ret;

	if (!PyLdbMessage_Check(py_msg2)) {
		Py_INCREF(Py_NotImplemented);
		return Py_NotImplemented;
	}

	msg1 = pyldb_Message_AsMessage(py_msg1),
	msg2 = pyldb_Message_AsMessage(py_msg2);

	if ((msg1->dn != NULL) || (msg2->dn != NULL)) {
		ret = ldb_dn_compare(msg1->dn, msg2->dn);
		if (ret != 0) {
			return richcmp(ret, op);
		}
	}

	ret = msg1->num_elements - msg2->num_elements;
	if (ret != 0) {
		return richcmp(ret, op);
	}

	for (i = 0; i < msg1->num_elements; i++) {
		ret = ldb_msg_element_compare_name(&msg1->elements[i],
						   &msg2->elements[i]);
		if (ret != 0) {
			return richcmp(ret, op);
		}

		ret = ldb_msg_element_compare(&msg1->elements[i],
					      &msg2->elements[i]);
		if (ret != 0) {
			return richcmp(ret, op);
		}
	}

	return richcmp(0, op);
}

static PyTypeObject PyLdbMessage = {
	.tp_name = "ldb.Message",
	.tp_methods = py_ldb_msg_methods,
	.tp_getset = py_ldb_msg_getset,
	.tp_as_sequence = &py_ldb_msg_sequence,
	.tp_as_mapping = &py_ldb_msg_mapping,
	.tp_basicsize = sizeof(PyLdbMessageObject),
	.tp_dealloc = (destructor)py_ldb_msg_dealloc,
	.tp_new = py_ldb_msg_new,
	.tp_repr = (reprfunc)py_ldb_msg_repr,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_iter = (getiterfunc)py_ldb_msg_iter,
	.tp_richcompare = (richcmpfunc)py_ldb_msg_richcmp,
	.tp_doc = "A LDB Message",
};

static PyObject *PyLdbTree_FromTree(struct ldb_parse_tree *tree)
{
	PyLdbTreeObject *ret;

	ret = (PyLdbTreeObject *)PyLdbTree.tp_alloc(&PyLdbTree, 0);
	if (ret == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	ret->mem_ctx = talloc_new(NULL);
	ret->tree = talloc_reference(ret->mem_ctx, tree);
	return (PyObject *)ret;
}

static void py_ldb_tree_dealloc(PyLdbTreeObject *self)
{
	talloc_free(self->mem_ctx);
	PyObject_Del(self);
}

static PyTypeObject PyLdbTree = {
	.tp_name = "ldb.Tree",
	.tp_basicsize = sizeof(PyLdbTreeObject),
	.tp_dealloc = (destructor)py_ldb_tree_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = "A search tree",
};

/* Ldb_module */
static int py_module_search(struct ldb_module *mod, struct ldb_request *req)
{
	PyObject *py_ldb = (PyObject *)mod->private_data;
	PyObject *py_result, *py_base, *py_attrs, *py_tree;

	py_base = pyldb_Dn_FromDn(req->op.search.base);

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
			PyList_SetItem(py_attrs, i, PyUnicode_FromString(req->op.search.attrs[i]));
	}

	py_result = PyObject_CallMethod(py_ldb, discard_const_p(char, "search"),
					discard_const_p(char, "OiOO"),
					py_base, req->op.search.scope, py_tree, py_attrs);

	Py_DECREF(py_attrs);
	Py_DECREF(py_tree);
	Py_DECREF(py_base);

	if (py_result == NULL) {
		return LDB_ERR_PYTHON_EXCEPTION;
	}

	req->op.search.res = PyLdbResult_AsResult(NULL, py_result);
	if (req->op.search.res == NULL) {
		return LDB_ERR_PYTHON_EXCEPTION;
	}

	Py_DECREF(py_result);

	return LDB_SUCCESS;
}

static int py_module_add(struct ldb_module *mod, struct ldb_request *req)
{
	PyObject *py_ldb = (PyObject *)mod->private_data;
	PyObject *py_result, *py_msg;

	py_msg = PyLdbMessage_FromMessage(discard_const_p(struct ldb_message, req->op.add.message));

	if (py_msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	py_result = PyObject_CallMethod(py_ldb, discard_const_p(char, "add"),
					discard_const_p(char, "O"),
					py_msg);

	Py_DECREF(py_msg);

	if (py_result == NULL) {
		return LDB_ERR_PYTHON_EXCEPTION;
	}

	Py_DECREF(py_result);

	return LDB_SUCCESS;
}

static int py_module_modify(struct ldb_module *mod, struct ldb_request *req)
{
	PyObject *py_ldb = (PyObject *)mod->private_data;
	PyObject *py_result, *py_msg;

	py_msg = PyLdbMessage_FromMessage(discard_const_p(struct ldb_message, req->op.mod.message));

	if (py_msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	py_result = PyObject_CallMethod(py_ldb, discard_const_p(char, "modify"),
					discard_const_p(char, "O"),
					py_msg);

	Py_DECREF(py_msg);

	if (py_result == NULL) {
		return LDB_ERR_PYTHON_EXCEPTION;
	}

	Py_DECREF(py_result);

	return LDB_SUCCESS;
}

static int py_module_del(struct ldb_module *mod, struct ldb_request *req)
{
	PyObject *py_ldb = (PyObject *)mod->private_data;
	PyObject *py_result, *py_dn;

	py_dn = pyldb_Dn_FromDn(req->op.del.dn);

	if (py_dn == NULL)
		return LDB_ERR_OPERATIONS_ERROR;

	py_result = PyObject_CallMethod(py_ldb, discard_const_p(char, "delete"),
					discard_const_p(char, "O"),
					py_dn);

	if (py_result == NULL) {
		return LDB_ERR_PYTHON_EXCEPTION;
	}

	Py_DECREF(py_result);

	return LDB_SUCCESS;
}

static int py_module_rename(struct ldb_module *mod, struct ldb_request *req)
{
	PyObject *py_ldb = (PyObject *)mod->private_data;
	PyObject *py_result, *py_olddn, *py_newdn;

	py_olddn = pyldb_Dn_FromDn(req->op.rename.olddn);

	if (py_olddn == NULL)
		return LDB_ERR_OPERATIONS_ERROR;

	py_newdn = pyldb_Dn_FromDn(req->op.rename.newdn);

	if (py_newdn == NULL)
		return LDB_ERR_OPERATIONS_ERROR;

	py_result = PyObject_CallMethod(py_ldb, discard_const_p(char, "rename"),
					discard_const_p(char, "OO"),
					py_olddn, py_newdn);

	Py_DECREF(py_olddn);
	Py_DECREF(py_newdn);

	if (py_result == NULL) {
		return LDB_ERR_PYTHON_EXCEPTION;
	}

	Py_DECREF(py_result);

	return LDB_SUCCESS;
}

static int py_module_request(struct ldb_module *mod, struct ldb_request *req)
{
	PyObject *py_ldb = (PyObject *)mod->private_data;
	PyObject *py_result;

	py_result = PyObject_CallMethod(py_ldb, discard_const_p(char, "request"),
					discard_const_p(char, ""));

	Py_XDECREF(py_result);

	return LDB_ERR_OPERATIONS_ERROR;
}

static int py_module_extended(struct ldb_module *mod, struct ldb_request *req)
{
	PyObject *py_ldb = (PyObject *)mod->private_data;
	PyObject *py_result;

	py_result = PyObject_CallMethod(py_ldb, discard_const_p(char, "extended"),
					discard_const_p(char, ""));

	Py_XDECREF(py_result);

	return LDB_ERR_OPERATIONS_ERROR;
}

static int py_module_start_transaction(struct ldb_module *mod)
{
	PyObject *py_ldb = (PyObject *)mod->private_data;
	PyObject *py_result;

	py_result = PyObject_CallMethod(py_ldb, discard_const_p(char, "start_transaction"),
					discard_const_p(char, ""));

	if (py_result == NULL) {
		return LDB_ERR_PYTHON_EXCEPTION;
	}

	Py_DECREF(py_result);

	return LDB_SUCCESS;
}

static int py_module_end_transaction(struct ldb_module *mod)
{
	PyObject *py_ldb = (PyObject *)mod->private_data;
	PyObject *py_result;

	py_result = PyObject_CallMethod(py_ldb, discard_const_p(char, "end_transaction"),
					discard_const_p(char, ""));

	if (py_result == NULL) {
		return LDB_ERR_PYTHON_EXCEPTION;
	}

	Py_DECREF(py_result);

	return LDB_SUCCESS;
}

static int py_module_del_transaction(struct ldb_module *mod)
{
	PyObject *py_ldb = (PyObject *)mod->private_data;
	PyObject *py_result;

	py_result = PyObject_CallMethod(py_ldb, discard_const_p(char, "del_transaction"),
					discard_const_p(char, ""));

	if (py_result == NULL) {
		return LDB_ERR_PYTHON_EXCEPTION;
	}

	Py_DECREF(py_result);

	return LDB_SUCCESS;
}

static int py_module_destructor(struct ldb_module *mod)
{
	Py_DECREF((PyObject *)mod->private_data);
	return 0;
}

static int py_module_init(struct ldb_module *mod)
{
	PyObject *py_class = (PyObject *)mod->ops->private_data;
	PyObject *py_result, *py_next, *py_ldb;

	py_ldb = PyLdb_FromLdbContext(mod->ldb);

	if (py_ldb == NULL)
		return LDB_ERR_OPERATIONS_ERROR;

	py_next = PyLdbModule_FromModule(mod->next);

	if (py_next == NULL)
		return LDB_ERR_OPERATIONS_ERROR;

	py_result = PyObject_CallFunction(py_class, discard_const_p(char, "OO"),
					  py_ldb, py_next);

	if (py_result == NULL) {
		return LDB_ERR_PYTHON_EXCEPTION;
	}

	mod->private_data = py_result;

	talloc_set_destructor(mod, py_module_destructor);

	return ldb_next_init(mod);
}

static PyObject *py_register_module(PyObject *module, PyObject *args)
{
	int ret;
	struct ldb_module_ops *ops;
	PyObject *input;
	PyObject *tmp = NULL;
	const char *name = NULL;

	if (!PyArg_ParseTuple(args, "O", &input))
		return NULL;

	ops = talloc_zero(NULL, struct ldb_module_ops);
	if (ops == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	tmp = PyObject_GetAttrString(input, discard_const_p(char, "name"));
	if (tmp == NULL) {
		return NULL;
	}
	name = PyUnicode_AsUTF8(tmp);
	if (name == NULL) {
		return NULL;
	}
	Py_XDECREF(tmp);
	Py_INCREF(input);

	ops->name = talloc_strdup(ops, name);
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
	if (ret != LDB_SUCCESS) {
		TALLOC_FREE(ops);
	}

	PyErr_LDB_ERROR_IS_ERR_RAISE(PyExc_LdbError, ret, NULL);

	Py_RETURN_NONE;
}

static PyObject *py_timestring(PyObject *module, PyObject *args)
{
	/* most times "time_t" is a signed integer type with 32 or 64 bit:
	 * http://stackoverflow.com/questions/471248/what-is-ultimately-a-time-t-typedef-to */
	long int t_val;
	char *tresult;
	PyObject *ret;
	if (!PyArg_ParseTuple(args, "l", &t_val))
		return NULL;
	tresult = ldb_timestring(NULL, (time_t) t_val);
	if (tresult == NULL) {
		/*
		 * Most likely EOVERFLOW from gmtime()
		 */
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	ret = PyUnicode_FromString(tresult);
	talloc_free(tresult);
	return ret;
}

static PyObject *py_string_to_time(PyObject *module, PyObject *args)
{
	char *str;
	if (!PyArg_ParseTuple(args, "s", &str))
		return NULL;

	return PyLong_FromLong(ldb_string_to_time(str));
}

static PyObject *py_valid_attr_name(PyObject *self, PyObject *args)
{
	char *name;
	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;
	return PyBool_FromLong(ldb_valid_attr_name(name));
}

/*
  encode a string using RFC2254 rules
 */
static PyObject *py_binary_encode(PyObject *self, PyObject *args)
{
	char *str, *encoded;
	Py_ssize_t size = 0;
	struct ldb_val val;
	PyObject *ret;

	if (!PyArg_ParseTuple(args, "s#", &str, &size))
		return NULL;
	val.data = (uint8_t *)str;
	val.length = size;

	encoded = ldb_binary_encode(NULL, val);
	if (encoded == NULL) {
		PyErr_SetString(PyExc_TypeError, "unable to encode binary string");
		return NULL;
	}
	ret = PyUnicode_FromString(encoded);
	talloc_free(encoded);
	return ret;
}

/*
  decode a string using RFC2254 rules
 */
static PyObject *py_binary_decode(PyObject *self, PyObject *args)
{
	char *str;
	struct ldb_val val;
	PyObject *ret;

	if (!PyArg_ParseTuple(args, "s", &str))
		return NULL;

	val = ldb_binary_decode(NULL, str);
	if (val.data == NULL) {
		PyErr_SetString(PyExc_TypeError, "unable to decode binary string");
		return NULL;
	}
	ret = PyBytes_FromStringAndSize((const char*)val.data, val.length);
	talloc_free(val.data);
	return ret;
}

static PyMethodDef py_ldb_global_methods[] = {
	{ "register_module", py_register_module, METH_VARARGS, 
		"S.register_module(module) -> None\n\n"
		"Register a LDB module."},
	{ "timestring", py_timestring, METH_VARARGS, 
		"S.timestring(int) -> string\n\n"
		"Generate a LDAP time string from a UNIX timestamp" },
	{ "string_to_time", py_string_to_time, METH_VARARGS,
		"S.string_to_time(string) -> int\n\n"
		"Parse a LDAP time string into a UNIX timestamp." },
	{ "valid_attr_name", py_valid_attr_name, METH_VARARGS,
		"S.valid_attr_name(name) -> bool\n\n"
		"Check whether the supplied name is a valid attribute name." },
	{ "binary_encode", py_binary_encode, METH_VARARGS,
		"S.binary_encode(string) -> string\n\n"
		"Perform a RFC2254 binary encoding on a string" },
	{ "binary_decode", py_binary_decode, METH_VARARGS,
		"S.binary_decode(string) -> string\n\n"
		"Perform a RFC2254 binary decode on a string" },
	{0}
};

#define MODULE_DOC "An interface to LDB, a LDAP-like API that can either to talk an embedded database (TDB-based) or a standards-compliant LDAP server."

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	.m_name = "ldb",
	.m_doc = MODULE_DOC,
	.m_size = -1,
	.m_methods = py_ldb_global_methods,
};
#endif

static PyObject* module_init(void)
{
	PyObject *m;

	PyLdbBytesType.tp_base = &PyBytes_Type;
	if (PyType_Ready(&PyLdbBytesType) < 0) {
		return NULL;
	}

	if (PyType_Ready(&PyLdbDn) < 0)
		return NULL;

	if (PyType_Ready(&PyLdbMessage) < 0)
		return NULL;

	if (PyType_Ready(&PyLdbMessageElement) < 0)
		return NULL;

	if (PyType_Ready(&PyLdb) < 0)
		return NULL;

	if (PyType_Ready(&PyLdbModule) < 0)
		return NULL;

	if (PyType_Ready(&PyLdbTree) < 0)
		return NULL;

	if (PyType_Ready(&PyLdbResult) < 0)
		return NULL;

	if (PyType_Ready(&PyLdbSearchIterator) < 0)
		return NULL;

	if (PyType_Ready(&PyLdbControl) < 0)
		return NULL;

#if PY_MAJOR_VERSION >= 3
	m = PyModule_Create(&moduledef);
#else
	m = Py_InitModule3("ldb", py_ldb_global_methods, MODULE_DOC);
#endif
	if (m == NULL)
		return NULL;

#define ADD_LDB_INT(val) PyModule_AddIntConstant(m, #val, LDB_ ## val)

	ADD_LDB_INT(SEQ_HIGHEST_SEQ);
	ADD_LDB_INT(SEQ_HIGHEST_TIMESTAMP);
	ADD_LDB_INT(SEQ_NEXT);
	ADD_LDB_INT(SCOPE_DEFAULT);
	ADD_LDB_INT(SCOPE_BASE);
	ADD_LDB_INT(SCOPE_ONELEVEL);
	ADD_LDB_INT(SCOPE_SUBTREE);

	ADD_LDB_INT(CHANGETYPE_NONE);
	ADD_LDB_INT(CHANGETYPE_ADD);
	ADD_LDB_INT(CHANGETYPE_DELETE);
	ADD_LDB_INT(CHANGETYPE_MODIFY);

	ADD_LDB_INT(FLAG_MOD_ADD);
	ADD_LDB_INT(FLAG_MOD_REPLACE);
	ADD_LDB_INT(FLAG_MOD_DELETE);
	ADD_LDB_INT(FLAG_FORCE_NO_BASE64_LDIF);

	ADD_LDB_INT(ATTR_FLAG_HIDDEN);
	ADD_LDB_INT(ATTR_FLAG_UNIQUE_INDEX);
	ADD_LDB_INT(ATTR_FLAG_SINGLE_VALUE);
	ADD_LDB_INT(ATTR_FLAG_FORCE_BASE64_LDIF);

	ADD_LDB_INT(SUCCESS);
	ADD_LDB_INT(ERR_OPERATIONS_ERROR);
	ADD_LDB_INT(ERR_PROTOCOL_ERROR);
	ADD_LDB_INT(ERR_TIME_LIMIT_EXCEEDED);
	ADD_LDB_INT(ERR_SIZE_LIMIT_EXCEEDED);
	ADD_LDB_INT(ERR_COMPARE_FALSE);
	ADD_LDB_INT(ERR_COMPARE_TRUE);
	ADD_LDB_INT(ERR_AUTH_METHOD_NOT_SUPPORTED);
	ADD_LDB_INT(ERR_STRONG_AUTH_REQUIRED);
	ADD_LDB_INT(ERR_REFERRAL);
	ADD_LDB_INT(ERR_ADMIN_LIMIT_EXCEEDED);
	ADD_LDB_INT(ERR_UNSUPPORTED_CRITICAL_EXTENSION);
	ADD_LDB_INT(ERR_CONFIDENTIALITY_REQUIRED);
	ADD_LDB_INT(ERR_SASL_BIND_IN_PROGRESS);
	ADD_LDB_INT(ERR_NO_SUCH_ATTRIBUTE);
	ADD_LDB_INT(ERR_UNDEFINED_ATTRIBUTE_TYPE);
	ADD_LDB_INT(ERR_INAPPROPRIATE_MATCHING);
	ADD_LDB_INT(ERR_CONSTRAINT_VIOLATION);
	ADD_LDB_INT(ERR_ATTRIBUTE_OR_VALUE_EXISTS);
	ADD_LDB_INT(ERR_INVALID_ATTRIBUTE_SYNTAX);
	ADD_LDB_INT(ERR_NO_SUCH_OBJECT);
	ADD_LDB_INT(ERR_ALIAS_PROBLEM);
	ADD_LDB_INT(ERR_INVALID_DN_SYNTAX);
	ADD_LDB_INT(ERR_ALIAS_DEREFERENCING_PROBLEM);
	ADD_LDB_INT(ERR_INAPPROPRIATE_AUTHENTICATION);
	ADD_LDB_INT(ERR_INVALID_CREDENTIALS);
	ADD_LDB_INT(ERR_INSUFFICIENT_ACCESS_RIGHTS);
	ADD_LDB_INT(ERR_BUSY);
	ADD_LDB_INT(ERR_UNAVAILABLE);
	ADD_LDB_INT(ERR_UNWILLING_TO_PERFORM);
	ADD_LDB_INT(ERR_LOOP_DETECT);
	ADD_LDB_INT(ERR_NAMING_VIOLATION);
	ADD_LDB_INT(ERR_OBJECT_CLASS_VIOLATION);
	ADD_LDB_INT(ERR_NOT_ALLOWED_ON_NON_LEAF);
	ADD_LDB_INT(ERR_NOT_ALLOWED_ON_RDN);
	ADD_LDB_INT(ERR_ENTRY_ALREADY_EXISTS);
	ADD_LDB_INT(ERR_OBJECT_CLASS_MODS_PROHIBITED);
	ADD_LDB_INT(ERR_AFFECTS_MULTIPLE_DSAS);
	ADD_LDB_INT(ERR_OTHER);

	ADD_LDB_INT(FLG_RDONLY);
	ADD_LDB_INT(FLG_NOSYNC);
	ADD_LDB_INT(FLG_RECONNECT);
	ADD_LDB_INT(FLG_NOMMAP);
	ADD_LDB_INT(FLG_SHOW_BINARY);
	ADD_LDB_INT(FLG_ENABLE_TRACING);
	ADD_LDB_INT(FLG_DONT_CREATE_DB);

	ADD_LDB_INT(PACKING_FORMAT);
	ADD_LDB_INT(PACKING_FORMAT_V2);

	/* Historical misspelling */
	PyModule_AddIntConstant(m, "ERR_ALIAS_DEREFERINCING_PROBLEM", LDB_ERR_ALIAS_DEREFERENCING_PROBLEM);

	PyModule_AddStringConstant(m, "__docformat__", "restructuredText");

	PyExc_LdbError = PyErr_NewException(discard_const_p(char, "_ldb.LdbError"), NULL, NULL);
	PyModule_AddObject(m, "LdbError", PyExc_LdbError);

	Py_INCREF(&PyLdb);
	Py_INCREF(&PyLdbDn);
	Py_INCREF(&PyLdbModule);
	Py_INCREF(&PyLdbMessage);
	Py_INCREF(&PyLdbMessageElement);
	Py_INCREF(&PyLdbTree);
	Py_INCREF(&PyLdbResult);
	Py_INCREF(&PyLdbControl);

	PyModule_AddObject(m, "Ldb", (PyObject *)&PyLdb);
	PyModule_AddObject(m, "Dn", (PyObject *)&PyLdbDn);
	PyModule_AddObject(m, "Message", (PyObject *)&PyLdbMessage);
	PyModule_AddObject(m, "MessageElement", (PyObject *)&PyLdbMessageElement);
	PyModule_AddObject(m, "Module", (PyObject *)&PyLdbModule);
	PyModule_AddObject(m, "Tree", (PyObject *)&PyLdbTree);
	PyModule_AddObject(m, "Control", (PyObject *)&PyLdbControl);

	PyModule_AddStringConstant(m, "__version__", PACKAGE_VERSION);

#define ADD_LDB_STRING(val)  PyModule_AddStringConstant(m, #val, LDB_## val)

	ADD_LDB_STRING(SYNTAX_DN);
	ADD_LDB_STRING(SYNTAX_DIRECTORY_STRING);
	ADD_LDB_STRING(SYNTAX_INTEGER);
	ADD_LDB_STRING(SYNTAX_ORDERED_INTEGER);
	ADD_LDB_STRING(SYNTAX_BOOLEAN);
	ADD_LDB_STRING(SYNTAX_OCTET_STRING);
	ADD_LDB_STRING(SYNTAX_UTC_TIME);
	ADD_LDB_STRING(OID_COMPARATOR_AND);
	ADD_LDB_STRING(OID_COMPARATOR_OR);

	return m;
}

#if PY_MAJOR_VERSION >= 3
PyMODINIT_FUNC PyInit_ldb(void);
PyMODINIT_FUNC PyInit_ldb(void)
{
	return module_init();
}
#else
void initldb(void);
void initldb(void)
{
	module_init();
}
#endif
