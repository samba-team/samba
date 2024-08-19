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

#include "lib/replace/system/python.h"
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

static PyObject *PyLdbMessage_FromMessage(struct ldb_message *msg, PyLdbObject *pyldb);
static PyObject *PyExc_LdbError;

static PyTypeObject PyLdbControl;
static PyTypeObject PyLdbResult;
static PyTypeObject PyLdbSearchIterator;
static PyTypeObject PyLdbMessage;
#define pyldb_Message_Check(ob) PyObject_TypeCheck(ob, &PyLdbMessage)
static PyTypeObject PyLdbDn;
#define pyldb_Dn_Check(ob) PyObject_TypeCheck(ob, &PyLdbDn)
static PyTypeObject PyLdb;
static PyTypeObject PyLdbMessageElement;
#define pyldb_MessageElement_Check(ob) PyObject_TypeCheck(ob, &PyLdbMessageElement)

static PyTypeObject PyLdbTree;
static struct ldb_message_element *PyObject_AsMessageElement(
						      TALLOC_CTX *mem_ctx,
						      PyObject *set_obj,
						      unsigned int flags,
						      const char *attr_name);
static PyTypeObject PyLdbBytesType;

#define PYARG_STR_UNI "es"

static PyObject *PyLdbBytes_FromStringAndSize(const char *msg, int size)
{
	PyObject* result = NULL;
	PyObject* args = NULL;
	args = Py_BuildValue("(y#)", msg, size);
	if (args == NULL) {
		return NULL;
	}
	result = PyLdbBytesType.tp_new(&PyLdbBytesType, args, NULL);
	Py_DECREF(args);
	return result;
}

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
static PyObject *PyLdbResult_FromResult(struct ldb_result *result, PyLdbObject *pyldb)
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

	ret->pyldb = pyldb;
	Py_INCREF(ret->pyldb);

	list = PyList_New(result->count);
	if (list == NULL) {
		PyErr_NoMemory();
		Py_DECREF(ret);
		return NULL;
	}

	for (i = 0; i < result->count; i++) {
		PyObject *pymessage = PyLdbMessage_FromMessage(result->msgs[i], pyldb);
		if (pymessage == NULL) {
			Py_DECREF(ret);
			Py_DECREF(list);
			return NULL;
		}
		PyList_SetItem(list, i, pymessage);
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
			Py_DECREF(list);
			PyErr_NoMemory();
			return NULL;
		}
		for (i=0; result->controls[i]; i++) {
			PyObject *ctrl = (PyObject*) PyLdbControl_FromControl(result->controls[i]);
			if (ctrl == NULL) {
				Py_DECREF(ret);
				Py_DECREF(list);
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
			Py_DECREF(list);
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
		Py_DECREF(list);
		PyErr_NoMemory();
		return NULL;
	}

	for (i = 0;result->refs && result->refs[i]; i++) {
		PyList_SetItem(referals, i, PyUnicode_FromString(result->refs[i]));
	}
	ret->referals = referals;
	return (PyObject *)ret;
}


/*
 * PyErr_interal_LDB_DN_OR_RAISE does exactly what
 * PyErr__LDB_DN_OR_RAISE does, but rather than going through the
 * Python layer to import the Dn object, it directly uses the the
 * address of the PyTypeObject. This is faster, but can only be done
 * in pyldb.c.
 */
#define PyErr_internal_LDB_DN_OR_RAISE(_py_obj, dn) do {		\
		PyLdbDnObject *_py_dn = NULL;				\
	if (_py_obj == NULL || !pyldb_Dn_Check(_py_obj)) {		\
		PyErr_SetString(PyExc_TypeError, "ldb Dn object required"); \
		return NULL;						\
	}								\
	_py_dn = (PyLdbDnObject *)_py_obj;				\
	dn = pyldb_Dn_AS_DN(_py_dn);					\
	if (_py_dn->pyldb->ldb_ctx != ldb_dn_get_ldb_context(dn)) {	\
		PyErr_SetString(PyExc_RuntimeError,			\
				"Dn has a stale LDB connection");	\
		return NULL;					       \
	}							       \
} while(0)


static PyObject *py_ldb_dn_validate(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_dn *dn = NULL;
	PyErr_internal_LDB_DN_OR_RAISE(self, dn);
	return PyBool_FromLong(ldb_dn_validate(dn));
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

static PyObject *py_ldb_dn_is_null(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_dn *dn = NULL;
	PyErr_internal_LDB_DN_OR_RAISE(self, dn);
	return PyBool_FromLong(ldb_dn_is_null(dn));
}

static PyObject *py_ldb_dn_get_casefold(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
	const char *s = NULL;
	struct ldb_dn *dn = NULL;
	PyErr_internal_LDB_DN_OR_RAISE(self, dn);
	s = ldb_dn_get_casefold(dn);
	if (s == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	return PyUnicode_FromString(s);
}

static PyObject *py_ldb_dn_get_linearized(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_dn *dn = NULL;
	PyErr_internal_LDB_DN_OR_RAISE(self, dn);
	return PyUnicode_FromString(ldb_dn_get_linearized(dn));
}

static PyObject *py_ldb_dn_canonical_str(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_dn *dn = NULL;
	PyErr_internal_LDB_DN_OR_RAISE(self, dn);
	return PyUnicode_FromString(ldb_dn_canonical_string(dn, dn));
}

static PyObject *py_ldb_dn_canonical_ex_str(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_dn *dn = NULL;
	PyErr_internal_LDB_DN_OR_RAISE(self, dn);
	return PyUnicode_FromString(ldb_dn_canonical_ex_string(dn, dn));
}

static PyObject *py_ldb_dn_extended_str(PyObject *self, PyObject *args, PyObject *kwargs)
{
	const char * const kwnames[] = { "mode", NULL };
	int mode = 1;
	struct ldb_dn *dn = NULL;
	PyErr_internal_LDB_DN_OR_RAISE(self, dn);
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|i",
					 discard_const_p(char *, kwnames),
					 &mode)) {
		return NULL;
	}
	return PyUnicode_FromString(ldb_dn_get_extended_linearized(dn, dn, mode));
}

static PyObject *py_ldb_dn_get_extended_component(PyObject *self, PyObject *args)
{
	char *name;
	const struct ldb_val *val = NULL;
	struct ldb_dn *dn = NULL;
	PyErr_internal_LDB_DN_OR_RAISE(self, dn);

	if (!PyArg_ParseTuple(args, "s", &name)) {
		return NULL;
	}
	val = ldb_dn_get_extended_component(dn, name);
	if (val == NULL) {
		Py_RETURN_NONE;
	}

	return PyBytes_FromStringAndSize((const char *)val->data, val->length);
}

static PyObject *py_ldb_dn_set_extended_component(PyObject *self, PyObject *args)
{
	char *name;
	int err;
	uint8_t *value = NULL;
	Py_ssize_t size = 0;
	struct ldb_dn *dn = NULL;
	PyErr_internal_LDB_DN_OR_RAISE(self, dn);

	if (!PyArg_ParseTuple(args, "sz#", &name, (char **)&value, &size))
		return NULL;

	if (value == NULL) {
		err = ldb_dn_set_extended_component(dn, name, NULL);
	} else {
		struct ldb_val val;
		val.data = (uint8_t *)value;
		val.length = size;
		err = ldb_dn_set_extended_component(dn, name, &val);
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

static PyObject *py_ldb_dn_richcmp(PyObject *pydn1, PyObject *pydn2, int op)
{
	int ret;
	struct ldb_dn *dn1 = NULL;
	struct ldb_dn *dn2 = NULL;
	if (!pyldb_Dn_Check(pydn2)) {
		Py_INCREF(Py_NotImplemented);
		return Py_NotImplemented;
	}
	PyErr_internal_LDB_DN_OR_RAISE(pydn1, dn1);
	PyErr_internal_LDB_DN_OR_RAISE(pydn2, dn2);

	ret = ldb_dn_compare(dn1, dn2);
	return richcmp(ret, op);
}

static PyObject *py_ldb_dn_get_parent(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_dn *dn = NULL;
	struct ldb_dn *parent;
	PyLdbDnObject *py_ret = NULL;
	PyLdbDnObject *dn_self = NULL;
	TALLOC_CTX *mem_ctx = NULL;

	PyErr_internal_LDB_DN_OR_RAISE(self, dn);

	if (ldb_dn_get_comp_num(dn) < 1) {
		Py_RETURN_NONE;
	}

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	parent = ldb_dn_get_parent(mem_ctx, dn);
	if (parent == NULL) {
		PyErr_NoMemory();
		talloc_free(mem_ctx);
		return NULL;
	}

	py_ret = (PyLdbDnObject *)PyLdbDn.tp_alloc(&PyLdbDn, 0);
	if (py_ret == NULL) {
		PyErr_NoMemory();
		talloc_free(mem_ctx);
		return NULL;
	}
	dn_self = (PyLdbDnObject *)self;

	py_ret->mem_ctx = mem_ctx;
	py_ret->dn = parent;
	py_ret->pyldb = dn_self->pyldb;
	Py_INCREF(py_ret->pyldb);
	return (PyObject *)py_ret;
}

static PyObject *py_ldb_dn_add_child(PyObject *self, PyObject *args)
{
	PyObject *py_other = NULL;
	struct ldb_dn *dn = NULL;
	struct ldb_dn *other = NULL;
	TALLOC_CTX *tmp_ctx = NULL;
	bool ok;

	PyErr_internal_LDB_DN_OR_RAISE(self, dn);

	if (!PyArg_ParseTuple(args, "O", &py_other)) {
		return NULL;
	}

	/*
	 * pyldb_Object_AsDn only uses tmp_ctx if py_other is str/bytes, in
	 * which case it allocates a struct ldb_dn. If py_other is a PyLdbDn,
	 * tmp_ctx is unused and the underlying dn is borrowed.
	 *
	 * The pieces of other are reassembled onto dn using dn itself as a
	 * talloc context (ldb_dn_add_child assumes all dns are talloc
	 * contexts), after which we don't need any temporary DN we made.
	 */
	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	ok = pyldb_Object_AsDn(tmp_ctx,
			       py_other,
			       ldb_dn_get_ldb_context(dn),
			       &other);
	if (!ok) {
		TALLOC_FREE(tmp_ctx);
		return NULL;
	}

	ok = ldb_dn_add_child(dn, other);
	TALLOC_FREE(tmp_ctx);
	if (!ok) {
		PyErr_SetLdbError(PyExc_LdbError, LDB_ERR_OPERATIONS_ERROR, NULL);
		return NULL;
	}
	Py_RETURN_TRUE;
}

static PyObject *py_ldb_dn_add_base(PyObject *self, PyObject *args)
{
	PyObject *py_other = NULL;
	struct ldb_dn *other = NULL;
	struct ldb_dn *dn = NULL;
	TALLOC_CTX *tmp_ctx = NULL;
	bool ok;

	PyErr_internal_LDB_DN_OR_RAISE(self, dn);

	if (!PyArg_ParseTuple(args, "O", &py_other)) {
		return NULL;
	}

	/*
	 * As noted in py_ldb_dn_add_child() comments, if py_other is a
	 * string, other is an ephemeral struct ldb_dn, but if py_other is a
	 * python DN, other points to the corresponding long-lived DN.
	 */
	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	ok = pyldb_Object_AsDn(tmp_ctx,
			       py_other,
			       ldb_dn_get_ldb_context(dn),
			       &other);
	if (!ok) {
		TALLOC_FREE(tmp_ctx);
		return NULL;
	}

	ok = ldb_dn_add_base(dn, other);
	TALLOC_FREE(tmp_ctx);
	if (!ok) {
		PyErr_SetLdbError(PyExc_LdbError, LDB_ERR_OPERATIONS_ERROR, NULL);
		return NULL;
	}
	Py_RETURN_TRUE;
}

static PyObject *py_ldb_dn_copy(struct ldb_dn *dn, PyLdbObject *pyldb);

static PyObject *py_ldb_dn_copy_method(PyObject *self, PyObject *args)
{
	struct ldb_dn *dn = NULL;
	PyLdbObject *pyldb = NULL;
	PyObject *obj = Py_None;
	PyErr_internal_LDB_DN_OR_RAISE(self, dn);

	if (!PyArg_ParseTuple(args, "|O", &obj)) {
		return NULL;
	}

	if (obj == Py_None) {
		/*
		 * With no argument, or None, dn.copy() uses its own ldb.
		 *
		 * There is not much reason to do this, other than as a
		 * convenience in this situation:
		 *
		 * >>> msg.dn = dn.copy(msg.ldb)
		 *
		 * when you don't know whether msg has a dn or not (if msg.ldb
		 * is None, msg will now belong to this dn's ldb).
		 */
		pyldb = ((PyLdbDnObject *)self)->pyldb;
	} else if (PyObject_TypeCheck(obj, &PyLdb)) {
		pyldb = (PyLdbObject *)obj;
	} else {
		PyErr_Format(PyExc_TypeError,
			     "Expected Ldb or None");
		return NULL;
	}
	if (pyldb != ((PyLdbDnObject *)self)->pyldb) {
		/*
		 * This is unfortunate, but we can't make a copy of the dn directly,
		 * since the opaque struct ldb_dn has a pointer to the ldb it knows,
		 * and it is the WRONG ONE.
		 *
		 * Instead we go via string serialisation.
		 */
		char *dn_str = NULL;
		struct ldb_dn *new_dn = NULL;
		dn_str = ldb_dn_get_extended_linearized(pyldb->mem_ctx, dn, 1);
		if (dn_str == NULL) {
			PyErr_Format(PyExc_RuntimeError,
				     "Could not linearize DN");
			return NULL;
		}
		new_dn = ldb_dn_new(pyldb->mem_ctx,
				    pyldb->ldb_ctx,
				    dn_str);

		if (new_dn == NULL) {
			PyErr_Format(PyExc_RuntimeError,
				     "Could not re-parse DN '%s'",
				dn_str);
			TALLOC_FREE(dn_str);
			return NULL;
		}
		TALLOC_FREE(dn_str);
		dn = new_dn;
	}
	return py_ldb_dn_copy(dn, pyldb);
}

static PyObject *py_ldb_dn_remove_base_components(PyObject *self, PyObject *args)
{
	struct ldb_dn *dn = NULL;
	int i;
	bool ok;
	if (!PyArg_ParseTuple(args, "i", &i)) {
		return NULL;
	}

	PyErr_internal_LDB_DN_OR_RAISE(self, dn);

	ok = ldb_dn_remove_base_components(dn, i);
	if (!ok) {
		PyErr_SetLdbError(PyExc_LdbError, LDB_ERR_OPERATIONS_ERROR, NULL);
		return NULL;
	}

	Py_RETURN_TRUE;
}

static PyObject *py_ldb_dn_is_child_of(PyObject *self, PyObject *args)
{
	PyObject *py_base;
	struct ldb_dn *dn, *base;
	if (!PyArg_ParseTuple(args, "O", &py_base)) {
		return NULL;
	}

	PyErr_internal_LDB_DN_OR_RAISE(self, dn);

	if (!pyldb_Object_AsDn(NULL, py_base, ldb_dn_get_ldb_context(dn), &base))
		return NULL;

	return PyBool_FromLong(ldb_dn_compare_base(base, dn) == 0);
}

static PyObject *py_ldb_dn_get_component_name(PyObject *self, PyObject *args)
{
	struct ldb_dn *dn = NULL;
	const char *name;
	unsigned int num = 0;

	if (!PyArg_ParseTuple(args, "I", &num)) {
		return NULL;
	}

	PyErr_internal_LDB_DN_OR_RAISE(self, dn);

	name = ldb_dn_get_component_name(dn, num);
	if (name == NULL) {
		Py_RETURN_NONE;
	}

	return PyUnicode_FromString(name);
}

static PyObject *py_ldb_dn_get_component_value(PyObject *self, PyObject *args)
{
	struct ldb_dn *dn = NULL;
	const struct ldb_val *val;
	unsigned int num = 0;

	if (!PyArg_ParseTuple(args, "I", &num)) {
		return NULL;
	}

	PyErr_internal_LDB_DN_OR_RAISE(self, dn);

	val = ldb_dn_get_component_val(dn, num);
	if (val == NULL) {
		Py_RETURN_NONE;
	}

	return PyStr_FromLdbValue(val);
}

static PyObject *py_ldb_dn_set_component(PyObject *self, PyObject *args)
{
	unsigned int num = 0;
	char *name = NULL, *value = NULL;
	struct ldb_val val = { 0 };
	int err;
	Py_ssize_t size = 0;
	struct ldb_dn *dn = NULL;

	PyErr_internal_LDB_DN_OR_RAISE(self, dn);

	if (!PyArg_ParseTuple(args, "Iss#", &num, &name, &value, &size)) {
		return NULL;
	}

	val.data = (unsigned char*) value;
	val.length = size;

	err = ldb_dn_set_component(dn, num, name, val);
	if (err != LDB_SUCCESS) {
		PyErr_SetString(PyExc_TypeError, "Failed to set component");
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *py_ldb_dn_get_rdn_name(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_dn *dn = NULL;
	const char *name;

	PyErr_internal_LDB_DN_OR_RAISE(self, dn);

	name = ldb_dn_get_rdn_name(dn);
	if (name == NULL) {
		Py_RETURN_NONE;
	}

	return PyUnicode_FromString(name);
}

static PyObject *py_ldb_dn_get_rdn_value(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_dn *dn = NULL;
	const struct ldb_val *val;

	PyErr_internal_LDB_DN_OR_RAISE(self, dn);

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
		"S.add_child(dn) -> bool\n"
		"Add a child DN to this DN." },
	{ "add_base", (PyCFunction)py_ldb_dn_add_base, METH_VARARGS,
		"S.add_base(dn) -> bool\n"
		"Add a base DN to this DN." },
	{ "copy", (PyCFunction)py_ldb_dn_copy_method, METH_VARARGS,
		"dn.copy(ldb) -> dn\n"
		"Make a copy of this DN, attached to the given ldb object." },
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


static PyObject *py_ldb_dn_get_ldb(PyLdbDnObject *self, void *closure)
{
	if (self->pyldb == NULL) {
		Py_RETURN_NONE;
	}
	Py_INCREF(self->pyldb);
	return (PyObject *)self->pyldb;
}


static PyGetSetDef py_ldb_dn_getset[] = {
	{
		.name = discard_const_p(char, "ldb"),
		.get  = (getter)py_ldb_dn_get_ldb,
		.doc = discard_const_p( /* for Py 3.6; 3.7+ have const char* */
			char, "returns the associated ldb object (or None)")
	},
	{ .name = NULL },
};


static Py_ssize_t py_ldb_dn_len(PyLdbDnObject *self)
{
	struct ldb_dn *dn = pyldb_Dn_AS_DN(self);
	if (dn == NULL || self->pyldb->ldb_ctx != ldb_dn_get_ldb_context(dn)) {
		return -1;
	}

	return ldb_dn_get_comp_num(dn);
}

/*
  copy a DN as a python object
 */
static PyObject *py_ldb_dn_copy(struct ldb_dn *dn, PyLdbObject *pyldb)
{
	TALLOC_CTX *mem_ctx = NULL;
	struct ldb_dn *new_dn = NULL;
	PyLdbDnObject *py_ret;

	if (ldb_dn_get_ldb_context(dn) != pyldb->ldb_ctx) {
		/*
		 * We can't do this, because we can't (for now) change the ldb
		 * pointer of the underlying dn returned by ldb_dn_copy().
		 *
		 * This error means someone editing this file got confused,
		 * which is quite understandable.
		 */
		PyErr_SetString(PyExc_RuntimeError,
				"py_ldb_dn_copy can't copy to a new LDB");
		return NULL;
	}

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		return PyErr_NoMemory();
	}

	new_dn = ldb_dn_copy(mem_ctx, dn);
	if (new_dn == NULL) {
		talloc_free(mem_ctx);
		return PyErr_NoMemory();
	}

	py_ret = (PyLdbDnObject *)PyLdbDn.tp_alloc(&PyLdbDn, 0);
	if (py_ret == NULL) {
		talloc_free(mem_ctx);
		PyErr_NoMemory();
		return NULL;
	}
	py_ret->mem_ctx = mem_ctx;
	py_ret->dn = new_dn;

	py_ret->pyldb = pyldb;
	Py_INCREF(py_ret->pyldb);
	return (PyObject *)py_ret;
}

static PyObject *py_ldb_dn_concat(PyObject *self, PyObject *py_other)
{
	TALLOC_CTX *mem_ctx = NULL;
	struct ldb_dn *dn = NULL;
	struct ldb_dn *other = NULL;

	struct ldb_dn *new_dn = NULL;
	PyLdbDnObject *py_ret = NULL;


	PyErr_internal_LDB_DN_OR_RAISE(self, dn);
	PyErr_internal_LDB_DN_OR_RAISE(py_other, other);

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		return PyErr_NoMemory();
	}

	new_dn = ldb_dn_copy(mem_ctx, dn);
	if (new_dn == NULL) {
		talloc_free(mem_ctx);
		return PyErr_NoMemory();
	}

	if (!ldb_dn_add_base(new_dn, other)) {
		PyErr_SetString(PyExc_RuntimeError, "unable to concatenate DNs");
		talloc_free(mem_ctx);
		return NULL;
	}

	py_ret = (PyLdbDnObject *)PyLdbDn.tp_alloc(&PyLdbDn, 0);
	if (py_ret == NULL) {
		talloc_free(mem_ctx);
		PyErr_NoMemory();
		return NULL;
	}
	py_ret->mem_ctx = mem_ctx;
	py_ret->dn = new_dn;

	py_ret->pyldb = ((PyLdbDnObject *)self)->pyldb;
	Py_INCREF(py_ret->pyldb);

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

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!"PYARG_STR_UNI,
					 discard_const_p(char *, kwnames),
					 &PyLdb, &py_ldb, "utf8", &str))
		goto out;

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
	py_ret->pyldb = (PyLdbObject *)py_ldb;
	Py_INCREF(py_ret->pyldb);
out:
	if (str != NULL) {
		PyMem_Free(discard_const_p(char, str));
	}
	return (PyObject *)py_ret;
}

static void py_ldb_dn_dealloc(PyLdbDnObject *self)
{
	talloc_free(self->mem_ctx);
	Py_DECREF(self->pyldb);
	PyObject_Del(self);
}

static PyTypeObject PyLdbDn = {
	.tp_name = "ldb.Dn",
	.tp_methods = py_ldb_dn_methods,
	.tp_str = (reprfunc)py_ldb_dn_get_linearized,
	.tp_repr = (reprfunc)py_ldb_dn_repr,
	.tp_richcompare = (richcmpfunc)py_ldb_dn_richcmp,
	.tp_as_sequence = &py_ldb_dn_seq,
	.tp_getset = py_ldb_dn_getset,
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
	PyObject *result = NULL;
	result = PyObject_CallFunction(fn, discard_const_p(char, "(i,O)"), level, PyUnicode_FromFormatV(fmt, ap));
	Py_XDECREF(result);
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
	struct ldb_context *ldb_ctx = pyldb_Ldb_AS_LDBCONTEXT(self);
	const char *url = ldb_get_opaque(ldb_ctx, "ldb_url");
	if (url == NULL) {
		url = "no connection";
	}
	return PyUnicode_FromFormat("<ldb connection %s>", url);
}

static PyObject *py_ldb_get_root_basedn(PyLdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_dn *dn = ldb_get_root_basedn(pyldb_Ldb_AS_LDBCONTEXT(self));
	if (dn == NULL)
		Py_RETURN_NONE;
	return py_ldb_dn_copy(dn, self);
}


static PyObject *py_ldb_get_schema_basedn(PyLdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_dn *dn = ldb_get_schema_basedn(pyldb_Ldb_AS_LDBCONTEXT(self));
	if (dn == NULL)
		Py_RETURN_NONE;
	return py_ldb_dn_copy(dn, self);
}

static PyObject *py_ldb_get_config_basedn(PyLdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_dn *dn = ldb_get_config_basedn(pyldb_Ldb_AS_LDBCONTEXT(self));
	if (dn == NULL)
		Py_RETURN_NONE;
	return py_ldb_dn_copy(dn, self);
}

static PyObject *py_ldb_get_default_basedn(PyLdbObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_dn *dn = ldb_get_default_basedn(pyldb_Ldb_AS_LDBCONTEXT(self));
	if (dn == NULL)
		Py_RETURN_NONE;
	return py_ldb_dn_copy(dn, self);
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

static PyObject *py_ldb_connect(PyLdbObject *self, PyObject *args, PyObject *kwargs);

static int py_ldb_init(PyLdbObject *self, PyObject *args, PyObject *kwargs)
{
	const char * const kwnames[] = { "url", "flags", "options", NULL };
	char *url = NULL;
	PyObject *py_options = NULL;
	unsigned int flags = 0;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|zIO:Ldb.__init__",
					 discard_const_p(char *, kwnames),
					 &url, &flags, &py_options)) {
		return -1;
	}

	if (url != NULL) {
		/* py_ldb_connect returns py_None on success, NULL on error */
		PyObject *result = py_ldb_connect(self, args, kwargs);
		if (result == NULL) {
			return -1;
		}
		Py_DECREF(result);
	} else {
		struct ldb_context *ldb = pyldb_Ldb_AS_LDBCONTEXT(self);
		ldb_set_flags(ldb, flags);
	}

	return 0;
}

static PyObject *py_ldb_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	TALLOC_CTX *mem_ctx = NULL;
	PyLdbObject *ret;
	struct ldb_context *ldb;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		return PyErr_NoMemory();
	}

	ldb = ldb_init(mem_ctx, NULL);
	if (ldb == NULL) {
		talloc_free(mem_ctx);
		PyErr_NoMemory();
		return NULL;
	}

	ret = (PyLdbObject *)type->tp_alloc(type, 0);
	if (ret == NULL) {
		talloc_free(mem_ctx);
		PyErr_NoMemory();
		return NULL;
	}
	ret->mem_ctx = mem_ctx;

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
		if (controls[0] != NULL && parsed_controls == NULL) {
			talloc_free(mem_ctx);
			PyErr_SetLdbError(PyExc_LdbError, LDB_ERR_OPERATIONS_ERROR, ldb_ctx);
			return NULL;
		}
		talloc_free(controls);
	}

	if (!pyldb_Message_Check(py_msg)) {
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
	if (msg->elements == NULL) {
		PyErr_NoMemory();
		TALLOC_FREE(msg);
		return NULL;
	}

	if (dn_value) {
		struct ldb_dn *dn = NULL;
		if (!pyldb_Object_AsDn(msg, dn_value, ldb_ctx, &dn)) {
			PyErr_SetString(PyExc_TypeError, "unable to import dn object");
			TALLOC_FREE(msg);
			return NULL;
		}
		if (dn == NULL) {
			PyErr_SetString(PyExc_TypeError, "dn set but not found");
			TALLOC_FREE(msg);
			return NULL;
		}
		msg->dn = talloc_reference(msg, dn);
		if (msg->dn == NULL) {
			talloc_free(mem_ctx);
			PyErr_NoMemory();
			return NULL;
		}
	} else {
		PyErr_SetString(PyExc_TypeError, "no dn set");
		TALLOC_FREE(msg);
		return NULL;
	}

	while (PyDict_Next(py_obj, &dict_pos, &key, &value)) {
		const char *key_str = PyUnicode_AsUTF8(key);
		if (ldb_attr_cmp(key_str, "dn") != 0) {
			msg_el = PyObject_AsMessageElement(msg->elements, value,
							   mod_flags, key_str);
			if (msg_el == NULL) {
				PyErr_Format(PyExc_TypeError, "unable to import element '%s'", key_str);
				TALLOC_FREE(msg);
				return NULL;
			}
			memcpy(&msg->elements[msg_pos], msg_el, sizeof(*msg_el));

			/*
			 * PyObject_AsMessageElement might have returned a
			 * reference to an existing MessageElement, and so left
			 * the name and flags unchanged. Thus if those members
			 * aren’t set, we’ll assume that the user forgot to
			 * initialize them.
			 */
			if (msg->elements[msg_pos].name == NULL) {
				/* No name was set — set it now. */
				msg->elements[msg_pos].name = talloc_strdup(msg->elements, key_str);
				if (msg->elements[msg_pos].name == NULL) {
					PyErr_NoMemory();
					TALLOC_FREE(msg);
					return NULL;
				}
			}
			if (msg->elements[msg_pos].flags == 0) {
				/* No flags were set — set them now. */
				msg->elements[msg_pos].flags = mod_flags;
			}

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
		if (controls[0] != NULL && parsed_controls == NULL) {
			talloc_free(mem_ctx);
			PyErr_SetLdbError(PyExc_LdbError, LDB_ERR_OPERATIONS_ERROR, ldb_ctx);
			return NULL;
		}
		talloc_free(controls);
	}

	if (pyldb_Message_Check(py_obj)) {
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
		if (controls[0] != NULL && parsed_controls == NULL) {
			talloc_free(mem_ctx);
			PyErr_SetLdbError(PyExc_LdbError, LDB_ERR_OPERATIONS_ERROR, ldb_ctx);
			return NULL;
		}
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
		if (controls[0] != NULL && parsed_controls == NULL) {
			talloc_free(mem_ctx);
			PyErr_SetLdbError(PyExc_LdbError, LDB_ERR_OPERATIONS_ERROR, ldb_ctx);
			return NULL;
		}
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

static PyObject *ldb_ldif_to_pyobject(PyLdbObject *pyldb, struct ldb_ldif *ldif)
{
	PyObject *obj = NULL;
	PyObject *result = NULL;
	struct ldb_context *ldb = pyldb->ldb_ctx;

	if (ldif == NULL) {
		Py_RETURN_NONE;
	}

	switch (ldif->changetype) {
	case LDB_CHANGETYPE_NONE:
	case LDB_CHANGETYPE_ADD:
		obj = PyLdbMessage_FromMessage(ldif->msg, pyldb);
		break;
	case LDB_CHANGETYPE_MODIFY:
		obj = PyLdbMessage_FromMessage(ldif->msg, pyldb);
		break;
	case LDB_CHANGETYPE_DELETE:
		if (ldif->msg->num_elements != 0) {
			PyErr_Format(PyExc_ValueError,
				     "CHANGETYPE(DELETE) with num_elements=%u",
				     ldif->msg->num_elements);
			return NULL;
		}
		obj = pyldb_Dn_FromDn(ldif->msg->dn, pyldb);
		break;
	case LDB_CHANGETYPE_MODRDN: {
		struct ldb_dn *olddn = NULL;
		PyObject *olddn_obj = NULL;
		bool deleteoldrdn = false;
		PyObject *deleteoldrdn_obj = NULL;
		struct ldb_dn *newdn = NULL;
		PyObject *newdn_obj = NULL;
		int ret;

		ret = ldb_ldif_parse_modrdn(ldb,
					    ldif,
					    ldif,
					    &olddn,
					    NULL,
					    &deleteoldrdn,
					    NULL,
					    &newdn);
		if (ret != LDB_SUCCESS) {
			PyErr_Format(PyExc_ValueError,
				     "ldb_ldif_parse_modrdn() failed");
			return NULL;
		}

		olddn_obj = pyldb_Dn_FromDn(olddn, pyldb);
		if (olddn_obj == NULL) {
			return NULL;
		}
		if (deleteoldrdn) {
			deleteoldrdn_obj = Py_True;
		} else {
			deleteoldrdn_obj = Py_False;
		}
		newdn_obj = pyldb_Dn_FromDn(newdn, pyldb);
		if (newdn_obj == NULL) {
			deleteoldrdn_obj = NULL;
			Py_CLEAR(olddn_obj);
			return NULL;
		}

		obj = Py_BuildValue(discard_const_p(char, "{s:O,s:O,s:O}"),
				    "olddn", olddn_obj,
				    "deleteoldrdn", deleteoldrdn_obj,
				    "newdn", newdn_obj);
		Py_CLEAR(olddn_obj);
		deleteoldrdn_obj = NULL;
		Py_CLEAR(newdn_obj);
		}
		break;
	default:
		PyErr_Format(PyExc_NotImplementedError,
			     "Unsupported LDB_CHANGETYPE(%u)",
			     ldif->changetype);
		return NULL;
	}

	if (obj == NULL) {
		return NULL;
	}

	/* We don't want this being attached * to the 'ldb' any more */
	result = Py_BuildValue(discard_const_p(char, "(iO)"),
			       ldif->changetype,
			       obj);
	Py_CLEAR(obj);
	return result;
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

	if (!pyldb_Message_Check(py_msg)) {
		PyErr_SetString(PyExc_TypeError, "Expected Ldb Message for msg");
		return NULL;
	}

	ldif.msg = pyldb_Message_AsMessage(py_msg);
	ldif.changetype = changetype;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		return PyErr_NoMemory();
	}

	string = ldb_ldif_write_string(pyldb_Ldb_AS_LDBCONTEXT(self), mem_ctx, &ldif);
	if (!string) {
		PyErr_SetString(PyExc_KeyError, "Failed to generate LDIF");
		talloc_free(mem_ctx);
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
	if (list == NULL) {
		talloc_free(mem_ctx);
		return NULL;
	}

	while (s && *s != '\0') {
		ldif = ldb_ldif_read_string(self->ldb_ctx, &s);
		talloc_steal(mem_ctx, ldif);
		if (ldif) {
			int res = 0;
			PyObject *py_ldif = ldb_ldif_to_pyobject(self, ldif);
			if (py_ldif == NULL) {
				Py_CLEAR(list);
				if (PyErr_Occurred() == NULL) {
					PyErr_BadArgument();
				}
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

	if (!pyldb_Message_Check(py_msg_old)) {
		PyErr_SetString(PyExc_TypeError, "Expected Ldb Message for old message");
		return NULL;
	}

	if (!pyldb_Message_Check(py_msg_new)) {
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
		talloc_free(mem_ctx);
		PyErr_NoMemory();
		return NULL;
	}

	py_ret = PyLdbMessage_FromMessage(diff, self);

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
		if (controls[0] != NULL && parsed_controls == NULL) {
			talloc_free(mem_ctx);
			PyErr_SetLdbError(PyExc_LdbError, LDB_ERR_OPERATIONS_ERROR, ldb_ctx);
			return NULL;
		}
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

	py_ret = PyLdbResult_FromResult(res, self);

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

	Py_CLEAR(reply->obj);

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
		reply->obj = PyLdbMessage_FromMessage(ares->message, py_iter->ldb);
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
		reply->obj = PyLdbResult_FromResult(&result, py_iter->ldb);
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
			PyErr_SetLdbError(PyExc_LdbError, LDB_ERR_OPERATIONS_ERROR, ldb_ctx);
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

	if (data == (void *)1) {
		/*
		 * This value is sometimes used to indicate that a opaque is
		 * set.
		 */
		Py_RETURN_TRUE;
	}

	{
		/*
		 * Let’s hope the opaque data is actually a talloc pointer,
		 * otherwise calling this would be Very Bad.
		 */
		const bool *opaque = talloc_get_type(data, bool);
		if (opaque != NULL) {
			return PyBool_FromLong(*opaque);
		}
	}

	{
		const unsigned long long *opaque = talloc_get_type(
			data, unsigned long long);
		if (opaque != NULL) {
			return PyLong_FromUnsignedLongLong(*opaque);
		}
	}

	{
		const char *opaque = talloc_get_type(data, char);
		if (opaque != NULL) {
			return PyUnicode_FromString(opaque);
		}
	}

	PyErr_SetString(PyExc_ValueError, "Unsupported type for opaque");
	return NULL;
}

static PyObject *py_ldb_set_opaque(PyLdbObject *self, PyObject *args)
{
	char *name;
	PyObject *data;
	void *value = NULL;
	int ret;

	if (!PyArg_ParseTuple(args, "sO", &name, &data))
		return NULL;

	if (data == Py_None) {
		value = NULL;
	} else if (PyBool_Check(data)) {
		bool *opaque = NULL;
		bool b;
		{
			const int is_true = PyObject_IsTrue(data);
			if (is_true == -1) {
				return NULL;
			}
			b = is_true;
		}

		opaque = talloc(self->ldb_ctx, bool);
		if (opaque == NULL) {
			return PyErr_NoMemory();
		}
		*opaque = b;
		value = opaque;
	} else if (PyLong_Check(data)) {
		unsigned long long *opaque = NULL;
		const unsigned long long n = PyLong_AsUnsignedLongLong(data);
		if (n == -1 && PyErr_Occurred()) {
			return NULL;
		}

		opaque = talloc(self->ldb_ctx, unsigned long long);
		if (opaque == NULL) {
			return PyErr_NoMemory();
		}
		*opaque = n;
		value = opaque;
	} else if (PyUnicode_Check(data)) {
		char *opaque = NULL;
		const char *s = PyUnicode_AsUTF8(data);
		if (s == NULL) {
			return NULL;
		}

		opaque = talloc_strdup(self->ldb_ctx, s);
		if (opaque == NULL) {
			return PyErr_NoMemory();
		}

		/*
		 * Assign the right type to the talloc pointer, so that
		 * py_ldb_get_opaque() can recognize it.
		 */
		talloc_set_name_const(opaque, "char");

		value = opaque;
	} else {
		PyErr_SetString(PyExc_ValueError,
				"Unsupported type for opaque");
		return NULL;
	}

	ret = ldb_set_opaque(pyldb_Ldb_AS_LDBCONTEXT(self), name, value);
	if (ret) {
		PyErr_SetLdbError(PyExc_LdbError,
				  ret,
				  pyldb_Ldb_AS_LDBCONTEXT(self));
		return NULL;
	}

	Py_RETURN_NONE;
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

static PyObject *py_ldb_whoami(PyLdbObject *self, PyObject *args)
{
	struct ldb_context *ldb = pyldb_Ldb_AS_LDBCONTEXT(self);
	struct ldb_result *res = NULL;
	struct ldb_extended *ext_res = NULL;
	size_t len = 0;
	int ret;

	ret = ldb_extended(ldb, LDB_EXTENDED_WHOAMI_OID, NULL, &res);
	PyErr_LDB_ERROR_IS_ERR_RAISE(PyExc_LdbError, ret, ldb);

	ext_res = res->extended;
	if (ext_res == NULL) {
		PyErr_SetString(PyExc_TypeError, "Got no exop reply");
		return NULL;
	}

	if (strcmp(ext_res->oid, LDB_EXTENDED_WHOAMI_OID) != 0) {
		PyErr_SetString(PyExc_TypeError, "Got wrong reply OID");
		return NULL;
	}

	len = talloc_get_size(ext_res->data);
	if (len == 0) {
		Py_RETURN_NONE;
	}

	return PyUnicode_FromStringAndSize(ext_res->data, len);
}

static PyObject *py_ldb_disconnect(PyLdbObject *self, PyObject *args)
{
	size_t ref_count;
	void *parent = NULL;
	TALLOC_CTX *mem_ctx = NULL;
	struct ldb_context *ldb = NULL;

	if (self->ldb_ctx == NULL) {
		/* It is hard to see how we'd get here. */
		PyErr_SetLdbError(PyExc_LdbError, LDB_ERR_OPERATIONS_ERROR, NULL);
		return NULL;
	}

	ref_count = talloc_reference_count(self->ldb_ctx);

	if (ref_count != 0) {
		PyErr_SetString(PyExc_RuntimeError,
				"ldb.disconnect() not possible as "
				"object still has C (or second "
				"python object) references");
		return NULL;
	}

	parent = talloc_parent(self->ldb_ctx);

	if (parent != self->mem_ctx) {
		PyErr_SetString(PyExc_RuntimeError,
				"ldb.disconnect() not possible as "
				"object is not talloc owned by this "
				"python object!");
		return NULL;
	}

	/*
	 * This recapitulates py_ldb_new(), cleaning out all the
	 * connections and state, but leaving the python object in a
	 * workable condition.
	 */
	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		return PyErr_NoMemory();
	}

	ldb = ldb_init(mem_ctx, NULL);
	if (ldb == NULL) {
		talloc_free(mem_ctx);
		PyErr_NoMemory();
		return NULL;
	}

	/*
	 * Notice we allocate the new mem_ctx and ldb before freeing
	 * the old one. This has two purposes: 1, the python object
	 * will still be consistent if an exception happens, and 2, it
	 * ensures the new ldb can't have the same memory address as
	 * the old one, and ldb address equality is a guard we use in
	 * Python DNs and such. Repeated calls to disconnect() *can* make
	 * this happen, so we don't advise doing that.
	 */
	TALLOC_FREE(self->mem_ctx);

	self->mem_ctx = mem_ctx;
	self->ldb_ctx = ldb;

	Py_RETURN_NONE;
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
	{ "sequence_number", (PyCFunction)py_ldb_sequence_number, METH_VARARGS,
		"S.sequence_number(type) -> value\n"
		"Return the value of the sequence according to the requested type" },
	{ "whoami",
	  (PyCFunction)py_ldb_whoami,
	  METH_NOARGS,
	  "S.whoami() -> value\n"
	  "Return the RFC4532 whoami string",
	},
	{ "disconnect",
	  (PyCFunction)py_ldb_disconnect,
	  METH_NOARGS,
	  "S.disconnect() -> None\n"
	  "Make this Ldb object unusable, disconnect and free the "
	  "underlying LDB, releasing any file handles and sockets.",
	},
	{ "_register_test_extensions", (PyCFunction)py_ldb_register_test_extensions, METH_NOARGS,
		"S._register_test_extensions() -> None\n"
		"Register internal extensions used in testing" },
	{0},
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
	.tp_getattro = PyObject_GenericGetAttr,
	.tp_basicsize = sizeof(PyLdbObject),
	.tp_doc = "Connection to a LDB database.",
	.tp_as_sequence = &py_ldb_seq,
	.tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
};

static void py_ldb_result_dealloc(PyLdbResultObject *self)
{
	talloc_free(self->mem_ctx);
	Py_CLEAR(self->msgs);
	Py_CLEAR(self->referals);
	Py_CLEAR(self->controls);
	Py_DECREF(self->pyldb);
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
	Py_CLEAR(self->state.exception);
	TALLOC_FREE(self->mem_ctx);
	ZERO_STRUCT(self->state);
	Py_CLEAR(self->ldb);
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
		Py_DECREF(self->state.exception);
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

	Py_CLEAR(self->state.exception);
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

/**
 * Create a ldb_message_element from a Python object.
 *
 * This will accept any sequence objects that contains strings, or
 * a string object.
 *
 * A reference to set_obj might be borrowed.
 *
 * @param mem_ctx Memory context
 * @param set_obj Python object to convert
 * @param flags ldb_message_element flags to set, if a new element is returned
 * @param attr_name Name of the attribute to set, if a new element is returned
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
	if (me->name == NULL) {
		PyErr_NoMemory();
		talloc_free(me);
		return NULL;
	}
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
	if (result == NULL) {
		return NULL;
	}

	for (i = 0; i < me->num_values; i++) {
		PyObject *obj = NULL;
		int ret;

		obj = PyObject_FromLdbValue(&me->values[i]);
		if (obj == NULL) {
			Py_DECREF(result);
			return NULL;
		}

		ret = PyList_SetItem(result, i, obj);
		if (ret) {
			Py_DECREF(obj);
			Py_DECREF(result);
			return NULL;
		}
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
	TALLOC_CTX *ret_mem_ctx = NULL;
	PyLdbMessageElementObject *ret;

	ret_mem_ctx = talloc_new(NULL);
	if (ret_mem_ctx == NULL) {
		return PyErr_NoMemory();
	}

	if (talloc_reference(ret_mem_ctx, mem_ctx) == NULL) {
		talloc_free(ret_mem_ctx);
		PyErr_NoMemory();
		return NULL;
	}

	ret = PyObject_New(PyLdbMessageElementObject, &PyLdbMessageElement);
	if (ret == NULL) {
		talloc_free(ret_mem_ctx);
		PyErr_NoMemory();
		return NULL;
	}
	ret->mem_ctx = ret_mem_ctx;
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
	if (name != NULL) {
		el->name = talloc_strdup(el, name);
		if (el->name == NULL) {
			talloc_free(mem_ctx);
			return PyErr_NoMemory();
		}
	}

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

		if (element_str == NULL) {
			return PyErr_NoMemory();
		}
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

	py_ret = PyLdbMessage_FromMessage(msg, (PyLdbObject *)py_ldb);

	talloc_unlink(ldb_ctx, msg);

	return py_ret;
}


#define pyldb_Message_as_message(pyobj) ((PyLdbMessageObject *)pyobj)->msg

#define pyldb_Message_get_pyldb(pyobj) ((PyLdbMessageObject *)pyobj)->pyldb

/*
 * PyErr_LDB_MESSAGE_OR_RAISE does 3 things:
 * 1. checks that a PyObject is really a PyLdbMessageObject.
 * 2. checks that the ldb that the PyLdbMessageObject knows is the ldb that
 *    its dn knows -- but only if the underlying message has a DN.
 * 3. sets message to the relevant struct ldb_message *.
 *
 * We need to do all this to ensure the message belongs to the right
 * ldb, lest it be freed before we are ready.
 */
#define PyErr_LDB_MESSAGE_OR_RAISE(_py_obj, message) do {		\
	PyLdbMessageObject *_py_message = NULL;			\
	struct ldb_dn *_dn = NULL;					\
	if (_py_obj == NULL || !pyldb_Message_Check(_py_obj)) {		\
		PyErr_SetString(PyExc_TypeError,			\
				"ldb Message object required");	\
		return NULL;						\
	}								\
	_py_message = (PyLdbMessageObject *)_py_obj;			\
	message = pyldb_Message_as_message(_py_message);		\
	_dn = message->dn;						\
	if (_dn != NULL &&						\
	    (_py_message->pyldb->ldb_ctx != ldb_dn_get_ldb_context(_dn))) { \
		PyErr_SetString(PyExc_RuntimeError,			\
				"Message has a stale LDB connection");	\
		return NULL;						\
	}								\
} while(0)


static PyObject *py_ldb_msg_remove_attr(PyObject *self, PyObject *args)
{
	char *name;
	struct ldb_message *msg = NULL;
	PyErr_LDB_MESSAGE_OR_RAISE(self, msg);

	if (!PyArg_ParseTuple(args, "s", &name)) {
		return NULL;
	}

	ldb_msg_remove_attr(msg, name);

	Py_RETURN_NONE;
}

static PyObject *py_ldb_msg_keys(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_message *msg = NULL;
	Py_ssize_t i, j = 0;
	PyObject *obj = NULL;

	PyErr_LDB_MESSAGE_OR_RAISE(self, msg);

	obj = PyList_New(msg->num_elements+(msg->dn != NULL?1:0));
	if (obj == NULL) {
		return NULL;
	}

	if (msg->dn != NULL) {
		PyObject *py_dn = NULL;
		int ret;

		py_dn = PyUnicode_FromString("dn");
		if (py_dn == NULL) {
			Py_DECREF(obj);
			return NULL;
		}

		ret = PyList_SetItem(obj, j, py_dn);
		if (ret) {
			Py_DECREF(py_dn);
			Py_DECREF(obj);
			return NULL;
		}

		j++;
	}
	for (i = 0; i < msg->num_elements; i++) {
		PyObject *py_name = NULL;
		int ret;

		py_name = PyUnicode_FromString(msg->elements[i].name);
		if (py_name == NULL) {
			Py_DECREF(obj);
			return NULL;
		}

		ret = PyList_SetItem(obj, j, py_name);
		if (ret) {
			Py_DECREF(py_name);
			Py_DECREF(obj);
			return NULL;
		}

		j++;
	}
	return obj;
}

static int py_ldb_msg_contains(PyLdbMessageObject *self, PyObject *py_name)
{
	struct ldb_message_element *el = NULL;
	const char *name = NULL;
	struct ldb_message *msg = pyldb_Message_as_message(self);
	struct ldb_dn *dn = msg->dn;

	if (dn != NULL && (self->pyldb->ldb_ctx != ldb_dn_get_ldb_context(dn))) {
		return -1;
	}

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

static PyObject *py_ldb_msg_getitem(PyObject *self, PyObject *py_name)
{
	struct ldb_message_element *el = NULL;
	const char *name = NULL;
	struct ldb_message *msg = NULL;
	PyErr_LDB_MESSAGE_OR_RAISE(self, msg);

	name = PyUnicode_AsUTF8(py_name);
	if (name == NULL) {
		return NULL;
	}
	if (!ldb_attr_cmp(name, "dn")) {
		return pyldb_Dn_FromDn(msg->dn, pyldb_Message_get_pyldb(self));
	}
	el = ldb_msg_find_element(msg, name);
	if (el == NULL) {
		PyErr_SetString(PyExc_KeyError, "No such element");
		return NULL;
	}

	return PyLdbMessageElement_FromMessageElement(el, msg->elements);
}

static PyObject *py_ldb_msg_get(PyObject *self, PyObject *args, PyObject *kwargs)
{
	PyObject *def = NULL;
	const char *kwnames[] = { "name", "default", "idx", NULL };
	const char *name = NULL;
	int idx = -1;
	struct ldb_message_element *el;
	struct ldb_message *msg = NULL;
	PyErr_LDB_MESSAGE_OR_RAISE(self, msg);

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|Oi:msg",
					 discard_const_p(char *, kwnames), &name, &def, &idx)) {
		return NULL;
	}

	if (strcasecmp(name, "dn") == 0) {
		return pyldb_Dn_FromDn(msg->dn, pyldb_Message_get_pyldb(self));
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

static PyObject *py_ldb_msg_items(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
	struct ldb_message *msg = NULL;
	Py_ssize_t i, j = 0;
	PyObject *l = NULL;

	PyErr_LDB_MESSAGE_OR_RAISE(self, msg);

	l = PyList_New(msg->num_elements + (msg->dn == NULL?0:1));
	if (l == NULL) {
		return PyErr_NoMemory();
	}
	if (msg->dn != NULL) {
		PyObject *value = NULL;
		int res = 0;
		PyObject *obj = pyldb_Dn_FromDn(msg->dn, pyldb_Message_get_pyldb(self));
		if (obj == NULL) {
			Py_CLEAR(l);
			return NULL;
		}
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
		int res = 0;
		PyObject *py_el = PyLdbMessageElement_FromMessageElement(&msg->elements[i],
									 msg->elements);
		if (py_el == NULL) {
			Py_CLEAR(l);
			return NULL;
		}
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

static PyObject *py_ldb_msg_elements(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
	Py_ssize_t i = 0;
	PyObject *l = NULL;
	struct ldb_message *msg = NULL;
	PyErr_LDB_MESSAGE_OR_RAISE(self, msg);

	l = PyList_New(msg->num_elements);
	if (l == NULL) {
		return NULL;
	}
	for (i = 0; i < msg->num_elements; i++) {
		PyObject *msg_el = NULL;
		int ret;

		msg_el = PyLdbMessageElement_FromMessageElement(&msg->elements[i], msg->elements);
		if (msg_el == NULL) {
			Py_DECREF(l);
			return NULL;
		}

		ret = PyList_SetItem(l, i, msg_el);
		if (ret) {
			Py_DECREF(msg_el);
			Py_DECREF(l);
			return NULL;
		}
	}
	return l;
}

static PyObject *py_ldb_msg_add(PyObject *self, PyObject *args)
{
	PyLdbMessageElementObject *py_element;
	int i, ret;
	struct ldb_message_element *el;
	struct ldb_message_element *el_new;
	struct ldb_message *msg = NULL;
	PyErr_LDB_MESSAGE_OR_RAISE(self, msg);

	if (!PyArg_ParseTuple(args, "O!", &PyLdbMessageElement, &py_element)) {
		return NULL;
	}

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
		"Message.from_dict(ldb, dict, mod_flag) -> ldb.Message\n"
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

static PyObject *py_ldb_msg_iter(PyObject *self)
{
	PyObject *list, *iter;

	list = py_ldb_msg_keys(self, NULL);
	if (list == NULL) {
		return NULL;
	}
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
		if (el->name == NULL) {
			/*
			 * If ‘value’ is a MessageElement,
			 * PyObject_AsMessageElement() will have returned a
			 * reference to it without setting the name. We don’t
			 * want to modify the original object to set the name
			 * ourselves, but making a copy would result in
			 * different behaviour for a caller relying on a
			 * reference being kept. Rather than continue with a
			 * NULL name (and probably fail later on), let’s catch
			 * this potential mistake early.
			 */
			PyErr_SetString(PyExc_ValueError, "MessageElement has no name set");
			talloc_unlink(self->msg, el);
			return -1;
		}
		ldb_msg_remove_attr(pyldb_Message_AsMessage(self), attr_name);
		ret = ldb_msg_add(pyldb_Message_AsMessage(self), el, el->flags);
		if (ret != LDB_SUCCESS) {
			PyErr_SetLdbError(PyExc_LdbError, ret, NULL);
			talloc_unlink(self->msg, el);
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
		if (ret->dn == NULL) {
			talloc_free(mem_ctx);
			return PyErr_NoMemory();
		}
	}

	py_ret = (PyLdbMessageObject *)type->tp_alloc(type, 0);
	if (py_ret == NULL) {
		PyErr_NoMemory();
		talloc_free(mem_ctx);
		return NULL;
	}

	py_ret->mem_ctx = mem_ctx;
	py_ret->msg = ret;
	if (pydn != NULL) {
		py_ret->pyldb = ((PyLdbDnObject *)pydn)->pyldb;
		Py_INCREF(py_ret->pyldb);
	}
	return (PyObject *)py_ret;
}

static PyObject *PyLdbMessage_FromMessage(struct ldb_message *msg, PyLdbObject *pyldb)
{
	TALLOC_CTX *mem_ctx = NULL;
	struct ldb_message *msg_ref = NULL;
	PyLdbMessageObject *ret;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		return PyErr_NoMemory();
	}

	msg_ref = talloc_reference(mem_ctx, msg);
	if (msg_ref == NULL) {
		talloc_free(mem_ctx);
		return PyErr_NoMemory();
	}

	ret = (PyLdbMessageObject *)PyLdbMessage.tp_alloc(&PyLdbMessage, 0);
	if (ret == NULL) {
		talloc_free(mem_ctx);
		PyErr_NoMemory();
		return NULL;
	}
	ret->mem_ctx = mem_ctx;
	ret->msg = msg_ref;

	ret->pyldb = pyldb;
	Py_INCREF(ret->pyldb);

	return (PyObject *)ret;
}

static PyObject *py_ldb_msg_get_dn(PyObject *self, void *closure)
{
	struct ldb_message *msg = NULL;
	PyErr_LDB_MESSAGE_OR_RAISE(self, msg);
	return pyldb_Dn_FromDn(msg->dn, pyldb_Message_get_pyldb(self));
}

static int py_ldb_msg_set_dn(PyObject *self, PyObject *value, void *closure)
{
	/*
	 * no PyErr_LDB_MESSAGE_OR_RAISE here, because this returns int.
	 *
	 * Also, since this is trying to replace the dn, we don't need to
	 * check the old one.
	 */
	struct ldb_message *msg = pyldb_Message_as_message(self);
	struct ldb_dn *dn = NULL;
	PyLdbObject *pyldb = pyldb_Message_get_pyldb(self);
	PyLdbMessageObject *self_as_msg = (PyLdbMessageObject *)self;

	if (value == NULL) {
		PyErr_SetString(PyExc_AttributeError, "cannot delete dn");
		return -1;
	}
	if (!pyldb_Dn_Check(value)) {
		PyErr_SetString(PyExc_TypeError, "expected dn");
		return -1;
	}

	dn = talloc_reference(msg, pyldb_Dn_AS_DN(value));
	if (dn == NULL) {
		PyErr_NoMemory();
		return -1;
	}

	if (pyldb != NULL) {
		if (pyldb->ldb_ctx != ldb_dn_get_ldb_context(dn)) {
			PyErr_SetString(PyExc_RuntimeError,
					"DN is from the wrong LDB");
			return -1;
		}
		Py_DECREF(pyldb);
	}

	msg->dn = dn;

	self_as_msg->pyldb = ((PyLdbDnObject *)value)->pyldb;
	Py_INCREF(self_as_msg->pyldb);

	return 0;
}

static PyObject *py_ldb_msg_get_text(PyObject *self, void *closure)
{
	return wrap_text("MessageTextWrapper", self);
}



static PyObject *py_ldb_msg_get_ldb(PyLdbMessageObject *self, void *closure)
{
	if (self->pyldb == NULL) {
		Py_RETURN_NONE;
	}
	Py_INCREF(self->pyldb);
	return (PyObject *)self->pyldb;
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
	{
		.name = discard_const_p(char, "ldb"),
		.get  = (getter)py_ldb_msg_get_ldb,
		.doc = discard_const_p(
			char, "returns the associated ldb object (or None)")
	},
	{ .name = NULL },
};

static PyObject *py_ldb_msg_repr(PyLdbMessageObject *self)
{
	PyObject *dict = PyDict_New(), *ret, *repr;
	const char *repr_str = NULL;
	if (dict == NULL) {
		return NULL;
	}
	if (PyDict_Update(dict, (PyObject *)self) != 0) {
		Py_DECREF(dict);
		return NULL;
	}
	repr = PyObject_Repr(dict);
	if (repr == NULL) {
		Py_DECREF(dict);
		return NULL;
	}
	repr_str = PyUnicode_AsUTF8(repr);
	if (repr_str == NULL) {
		Py_DECREF(repr);
		Py_DECREF(dict);
		return NULL;
	}
	ret = PyUnicode_FromFormat("Message(%s)", repr_str);
	Py_DECREF(repr);
	Py_DECREF(dict);
	return ret;
}

static void py_ldb_msg_dealloc(PyLdbMessageObject *self)
{
	talloc_free(self->mem_ctx);
	/* The pyldb element will only be present if a DN is assigned */
	if (self->pyldb) {
		Py_DECREF(self->pyldb);
	}
	PyObject_Del(self);
}

static PyObject *py_ldb_msg_richcmp(PyLdbMessageObject *py_msg1,
			      PyLdbMessageObject *py_msg2, int op)
{
	struct ldb_message *msg1, *msg2;
	unsigned int i;
	int ret;

	if (!pyldb_Message_Check(py_msg2)) {
		Py_INCREF(Py_NotImplemented);
		return Py_NotImplemented;
	}

	PyErr_LDB_MESSAGE_OR_RAISE(py_msg1, msg1);
	PyErr_LDB_MESSAGE_OR_RAISE(py_msg2, msg2);
	/*
	 * FIXME: this can be a non-transitive compare, unsuitable for
	 * sorting.
	 *
	 * supposing msg1, msg2, and msg3 have 1, 2, and 3 elements
	 * each. msg2 has a NULL DN, while msg1 has a DN that compares
	 * higher than msg3. Then:
	 *
	 * msg1 < msg2, due to num_elements.
	 * msg2 < msg3, due to num_elements.
	 * msg1 > msg3, due to DNs.
	 */
	if ((msg1->dn != NULL) || (msg2->dn != NULL)) {
		ret = ldb_dn_compare(msg1->dn, msg2->dn);
		if (ret != 0) {
			return richcmp(ret, op);
		}
	}

	if (msg1->num_elements > msg2->num_elements) {
		return richcmp(1, op);
	}
	if (msg1->num_elements < msg2->num_elements) {
		return richcmp(-1, op);
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
	time_t t;
	if (!PyArg_ParseTuple(args, "s", &str)) {
		return NULL;
	}
	t = ldb_string_to_time(str);

	if (t == 0 && errno != 0) {
		PyErr_SetFromErrno(PyExc_ValueError);
		return NULL;
	}
	return PyLong_FromLong(t);
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

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	.m_name = "ldb",
	.m_doc = MODULE_DOC,
	.m_size = -1,
	.m_methods = py_ldb_global_methods,
};

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

	if (PyType_Ready(&PyLdbTree) < 0)
		return NULL;

	if (PyType_Ready(&PyLdbResult) < 0)
		return NULL;

	if (PyType_Ready(&PyLdbSearchIterator) < 0)
		return NULL;

	if (PyType_Ready(&PyLdbControl) < 0)
		return NULL;

	m = PyModule_Create(&moduledef);
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
	ADD_LDB_INT(CHANGETYPE_MODRDN);

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
	Py_INCREF(&PyLdbMessage);
	Py_INCREF(&PyLdbMessageElement);
	Py_INCREF(&PyLdbTree);
	Py_INCREF(&PyLdbResult);
	Py_INCREF(&PyLdbControl);

	PyModule_AddObject(m, "Ldb", (PyObject *)&PyLdb);
	PyModule_AddObject(m, "Dn", (PyObject *)&PyLdbDn);
	PyModule_AddObject(m, "Message", (PyObject *)&PyLdbMessage);
	PyModule_AddObject(m, "MessageElement", (PyObject *)&PyLdbMessageElement);
	PyModule_AddObject(m, "Tree", (PyObject *)&PyLdbTree);
	PyModule_AddObject(m, "Result", (PyObject *)&PyLdbResult);
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

PyMODINIT_FUNC PyInit_ldb(void);
PyMODINIT_FUNC PyInit_ldb(void)
{
	return module_init();
}
