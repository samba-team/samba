/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2008
   
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
#include "libcli/security/security.h"

static PyObject *py_dom_sid_eq(PyObject *self, PyObject *args)
{
	struct dom_sid *this = py_talloc_get_ptr(self), *other;
	PyObject *py_other;

	if (!PyArg_ParseTuple(args, "O", &py_other)) 
		return NULL;

	other = py_talloc_get_type(py_other, struct dom_sid);
	if (other == NULL)
		return Py_False;

	return dom_sid_equal(this, other)?Py_True:Py_False;
}

static PyObject *py_dom_sid_str(PyObject *self)
{
	struct dom_sid *this = py_talloc_get_ptr(self);
	char *str = dom_sid_string(NULL, this);
	PyObject *ret = PyString_FromString(str);
	talloc_free(str);
	return ret;
}

static PyObject *py_dom_sid_repr(PyObject *self)
{
	struct dom_sid *this = py_talloc_get_ptr(self);
	char *str = dom_sid_string(NULL, this);
	PyObject *ret = PyString_FromFormat("dom_sid('%s')", str);
	talloc_free(str);
	return ret;
}

#define PY_DOM_SID_REPR py_dom_sid_repr

static PyObject *py_dom_sid_init(PyObject *self, PyObject *args)
{
	struct dom_sid *this = py_talloc_get_ptr(self);
	char *str;
	struct dom_sid *new_this;

	if (!PyArg_ParseTuple(args, "|s", &str))
		return NULL;

	new_this = dom_sid_parse_talloc(NULL, str);
	memcpy(this, new_this, sizeof(*new_this));
	talloc_free(new_this);
	return Py_None;
}

#define PY_DOM_SID_EXTRA_METHODS \
	{ "__eq__", (PyCFunction)py_dom_sid_eq, METH_VARARGS, "S.__eq__(x) -> S == x" }, \
	{ "__str__", (PyCFunction)py_dom_sid_str, METH_NOARGS, "S.__str__() -> str(S)" }, \
	{ "__init__", (PyCFunction)py_dom_sid_init, METH_VARARGS, "S.__init__(str=None)" },

static PyObject *py_descriptor_sacl_add(PyObject *self, PyObject *args)
{
	struct security_descriptor *desc = py_talloc_get_ptr(self);
	NTSTATUS status;
	struct security_ace *ace;
	PyObject *py_ace;

	if (!PyArg_ParseTuple(args, "O", &py_ace))
		return NULL;

	ace = py_talloc_get_ptr(py_ace);
	status = security_descriptor_sacl_add(desc, ace);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);
	return Py_None;
}

static PyObject *py_descriptor_dacl_add(PyObject *self, PyObject *args)
{
	struct security_descriptor *desc = py_talloc_get_ptr(self);
	NTSTATUS status;
	struct security_ace *ace;
	PyObject *py_ace;

	if (!PyArg_ParseTuple(args, "O", &py_ace))
		return NULL;

	ace = py_talloc_get_ptr(py_ace);

	status = security_descriptor_dacl_add(desc, ace);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);
	return Py_None;
}

static PyObject *py_descriptor_dacl_del(PyObject *self, PyObject *args)
{
	struct security_descriptor *desc = py_talloc_get_ptr(self);
	NTSTATUS status;
	struct dom_sid *sid;
	PyObject *py_sid;

	if (!PyArg_ParseTuple(args, "O", &py_sid))
		return NULL;

	sid = py_talloc_get_ptr(py_sid);
	status = security_descriptor_dacl_del(desc, sid);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);
	return Py_None;
}

static PyObject *py_descriptor_sacl_del(PyObject *self, PyObject *args)
{
	struct security_descriptor *desc = py_talloc_get_ptr(self);
	NTSTATUS status;
	struct dom_sid *sid;
	PyObject *py_sid;

	if (!PyArg_ParseTuple(args, "O", &py_sid))
		return NULL;

	sid = py_talloc_get_ptr(py_sid);
	status = security_descriptor_sacl_del(desc, sid);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);
	return Py_None;
}

static PyObject *py_descriptor_eq(PyObject *self, PyObject *args)
{
	struct security_descriptor *desc1 = py_talloc_get_ptr(self), *desc2;
	PyObject *py_other;

	if (!PyArg_ParseTuple(args, "O", &py_other))
		return NULL;

	desc2 = py_talloc_get_ptr(py_other);

	return PyBool_FromLong(security_descriptor_equal(desc1, desc2));
}

static PyObject *py_descriptor_new(PyTypeObject *self, PyObject *args, PyObject *kwargs)
{
	return py_talloc_import(self, security_descriptor_initialise(NULL));
}	

#define PY_SECURITY_DESCRIPTOR_EXTRA_METHODS \
	{ "sacl_add", (PyCFunction)py_descriptor_sacl_add, METH_VARARGS, \
		"S.sacl_add(ace) -> None\n" \
		"Add a security ace to this security descriptor" },\
	{ "dacl_add", (PyCFunction)py_descriptor_dacl_add, METH_VARARGS, \
		NULL }, \
	{ "dacl_del", (PyCFunction)py_descriptor_dacl_del, METH_VARARGS, \
		NULL }, \
	{ "sacl_del", (PyCFunction)py_descriptor_sacl_del, METH_VARARGS, \
		NULL }, \
	{ "__eq__", (PyCFunction)py_descriptor_eq, METH_VARARGS, \
		NULL },

static PyObject *py_token_is_sid(PyObject *self, PyObject *args)
{
	PyObject *py_sid;
	struct dom_sid *sid;
	struct security_token *token = py_talloc_get_ptr(self);
	if (!PyArg_ParseTuple(args, "O", &py_sid))
		return NULL;

	sid = py_talloc_get_ptr(py_sid);

	return PyBool_FromLong(security_token_is_sid(token, sid));
}

static PyObject *py_token_has_sid(PyObject *self, PyObject *args)
{
	PyObject *py_sid;
	struct dom_sid *sid;
	struct security_token *token = py_talloc_get_ptr(self);
	if (!PyArg_ParseTuple(args, "O", &py_sid))
		return NULL;

	sid = py_talloc_get_ptr(py_sid);

	return PyBool_FromLong(security_token_has_sid(token, sid));
}

static PyObject *py_token_is_anonymous(PyObject *self)
{
	struct security_token *token = py_talloc_get_ptr(self);
	
	return PyBool_FromLong(security_token_is_anonymous(token));
}

static PyObject *py_token_is_system(PyObject *self)
{
	struct security_token *token = py_talloc_get_ptr(self);
	
	return PyBool_FromLong(security_token_is_system(token));
}

static PyObject *py_token_has_builtin_administrators(PyObject *self)
{
	struct security_token *token = py_talloc_get_ptr(self);
	
	return PyBool_FromLong(security_token_has_builtin_administrators(token));
}

static PyObject *py_token_has_nt_authenticated_users(PyObject *self)
{
	struct security_token *token = py_talloc_get_ptr(self);
	
	return PyBool_FromLong(security_token_has_nt_authenticated_users(token));
}

static PyObject *py_token_has_privilege(PyObject *self, PyObject *args)
{
	int priv;
	struct security_token *token = py_talloc_get_ptr(self);

	if (!PyArg_ParseTuple(args, "i", &priv))
		return NULL;

	return PyBool_FromLong(security_token_has_privilege(token, priv));
}

static PyObject *py_token_set_privilege(PyObject *self, PyObject *args)
{
	int priv;
	struct security_token *token = py_talloc_get_ptr(self);

	if (!PyArg_ParseTuple(args, "i", &priv))
		return NULL;

	security_token_set_privilege(token, priv);
	return Py_None;
}

static PyObject *py_token_new(PyTypeObject *self, PyObject *args, PyObject *kwargs)
{
	return py_talloc_import(self, security_token_initialise(NULL));
}	

#define PY_SECURITY_TOKEN_EXTRA_METHODS \
	{ "is_sid", (PyCFunction)py_token_is_sid, METH_VARARGS, \
		"S.is_sid(sid) -> bool\n" \
		"Check whether this token is of the specified SID." }, \
	{ "has_sid", (PyCFunction)py_token_has_sid, METH_VARARGS, \
		NULL }, \
	{ "is_anonymous", (PyCFunction)py_token_is_anonymous, METH_NOARGS, \
		"S.is_anonymus() -> bool\n" \
		"Check whether this is an anonymous token." }, \
	{ "is_system", (PyCFunction)py_token_is_system, METH_NOARGS, \
		NULL }, \
	{ "has_builtin_administrators", (PyCFunction)py_token_has_builtin_administrators, METH_NOARGS, \
		NULL }, \
	{ "has_nt_authenticated_users", (PyCFunction)py_token_has_nt_authenticated_users, METH_NOARGS, \
		NULL }, \
	{ "has_privilege", (PyCFunction)py_token_has_privilege, METH_VARARGS, \
		NULL }, \
	{ "set_privilege", (PyCFunction)py_token_set_privilege, METH_VARARGS, \
		NULL },
