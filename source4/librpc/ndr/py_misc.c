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
#include <Python.h>
#include "python/py3compat.h"
#include "librpc/gen_ndr/misc.h"

#if PY_MAJOR_VERSION >= 3
static PyObject *py_GUID_richcmp(PyObject *py_self, PyObject *py_other, int op)
{
	int ret;
	struct GUID *self = pytalloc_get_ptr(py_self), *other;
	other = pytalloc_get_ptr(py_other);
	if (other == NULL) {
		Py_INCREF(Py_NotImplemented);
		return Py_NotImplemented;
	}

	ret = GUID_compare(self, other);

	switch (op) {
		case Py_EQ: if (ret == 0) Py_RETURN_TRUE; else Py_RETURN_FALSE;
		case Py_NE: if (ret != 0) Py_RETURN_TRUE; else Py_RETURN_FALSE;
		case Py_LT: if (ret <  0) Py_RETURN_TRUE; else Py_RETURN_FALSE;
		case Py_GT: if (ret >  0) Py_RETURN_TRUE; else Py_RETURN_FALSE;
		case Py_LE: if (ret <= 0) Py_RETURN_TRUE; else Py_RETURN_FALSE;
		case Py_GE: if (ret >= 0) Py_RETURN_TRUE; else Py_RETURN_FALSE;
	}
	Py_INCREF(Py_NotImplemented);
	return Py_NotImplemented;
}
#else
static int py_GUID_cmp(PyObject *py_self, PyObject *py_other)
{
	int ret;
	struct GUID *self = pytalloc_get_ptr(py_self), *other;
	other = pytalloc_get_ptr(py_other);
	if (other == NULL)
		return -1;

	ret = GUID_compare(self, other);
	if (ret < 0) {
		return -1;
	} else if (ret > 0) {
		return 1;
	} else {
		return 0;
	}
}
#endif

static PyObject *py_GUID_str(PyObject *py_self)
{
	struct GUID *self = pytalloc_get_ptr(py_self);
	char *str = GUID_string(NULL, self);
	PyObject *ret = PyStr_FromString(str);
	talloc_free(str);
	return ret;
}

static PyObject *py_GUID_repr(PyObject *py_self)
{
	struct GUID *self = pytalloc_get_ptr(py_self);
	char *str = GUID_string(NULL, self);
	PyObject *ret = PyStr_FromFormat("GUID('%s')", str);
	talloc_free(str);
	return ret;
}

static int py_GUID_init(PyObject *self, PyObject *args, PyObject *kwargs)
{
	PyObject *str = NULL;
	NTSTATUS status;
	struct GUID *guid = pytalloc_get_ptr(self);
	const char *kwnames[] = { "str", NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|O", discard_const_p(char *, kwnames), &str))
		return -1;

	if (str != NULL) {
		DATA_BLOB guid_val;
		Py_ssize_t _size;

		if (!IsPy3BytesOrString(str)) {
			PyErr_SetString(PyExc_TypeError, "Expected a string or bytes argument to GUID()");
			return -1;
		}

		if (!IsPy3Bytes(str)) {
			guid_val.data =
				(uint8_t *)PyStr_AsUTF8AndSize(str,
							       &_size);
		} else {
			guid_val.data = (uint8_t *)PyBytes_AsString(str);
			_size = PyBytes_Size(str);
		}
		guid_val.length = _size;
		status = GUID_from_data_blob(&guid_val, guid);
		if (!NT_STATUS_IS_OK(status)) {
			PyErr_SetNTSTATUS(status);
			return -1;
		}
	}

	return 0;
}

static void py_GUID_patch(PyTypeObject *type)
{
	type->tp_init = py_GUID_init;
	type->tp_str = py_GUID_str;
	type->tp_repr = py_GUID_repr;
#if PY_MAJOR_VERSION >= 3
	type->tp_richcompare = py_GUID_richcmp;
#else
	type->tp_compare = py_GUID_cmp;
#endif
}

#define PY_GUID_PATCH py_GUID_patch

static int py_policy_handle_init(PyObject *self, PyObject *args, PyObject *kwargs)
{
	char *str = NULL;
	NTSTATUS status;
	struct policy_handle *handle = pytalloc_get_ptr(self);
	const char *kwnames[] = { "uuid", "type", NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|si", discard_const_p(char *, kwnames), &str, &handle->handle_type))
		return -1;

	if (str != NULL) {
		status = GUID_from_string(str, &handle->uuid);
		if (!NT_STATUS_IS_OK(status)) {
			PyErr_SetNTSTATUS(status);
			return -1;
		}
	}

	return 0;
}

static PyObject *py_policy_handle_repr(PyObject *py_self)
{
	struct policy_handle *self = pytalloc_get_ptr(py_self);
	char *uuid_str = GUID_string(NULL, &self->uuid);
	PyObject *ret = PyStr_FromFormat("policy_handle(%d, '%s')", self->handle_type, uuid_str);
	talloc_free(uuid_str);
	return ret;
}

static PyObject *py_policy_handle_str(PyObject *py_self)
{
	struct policy_handle *self = pytalloc_get_ptr(py_self);
	char *uuid_str = GUID_string(NULL, &self->uuid);
	PyObject *ret = PyStr_FromFormat("%d, %s", self->handle_type, uuid_str);
	talloc_free(uuid_str);
	return ret;
}

static void py_policy_handle_patch(PyTypeObject *type)
{
	type->tp_init = py_policy_handle_init;
	type->tp_repr = py_policy_handle_repr;
	type->tp_str = py_policy_handle_str;
}

#define PY_POLICY_HANDLE_PATCH py_policy_handle_patch

