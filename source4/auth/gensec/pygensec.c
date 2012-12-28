/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2009
   
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
#include "includes.h"
#include "param/pyparam.h"
#include "auth/gensec/gensec.h"
#include "auth/credentials/pycredentials.h"
#include "libcli/util/pyerrors.h"
#include "python/modules.h"
#include <pytalloc.h>
#include <tevent.h>
#include "librpc/rpc/pyrpc_util.h"

static PyObject *py_get_name_by_authtype(PyObject *self, PyObject *args)
{
	int type;
	const char *name;
	struct gensec_security *security;

	if (!PyArg_ParseTuple(args, "i", &type))
		return NULL;

	security = pytalloc_get_type(self, struct gensec_security);

	name = gensec_get_name_by_authtype(security, type);
	if (name == NULL)
		Py_RETURN_NONE;

	return PyString_FromString(name);
}

static struct gensec_settings *settings_from_object(TALLOC_CTX *mem_ctx, PyObject *object)
{
	struct gensec_settings *s;
	PyObject *py_hostname, *py_lp_ctx;

	if (!PyDict_Check(object)) {
		PyErr_SetString(PyExc_ValueError, "settings should be a dictionary");
		return NULL;
	}

	s = talloc_zero(mem_ctx, struct gensec_settings);
	if (!s) return NULL;

	py_hostname = PyDict_GetItemString(object, "target_hostname");
	if (!py_hostname) {
		PyErr_SetString(PyExc_ValueError, "settings.target_hostname not found");
		return NULL;
	}

	py_lp_ctx = PyDict_GetItemString(object, "lp_ctx");
	if (!py_lp_ctx) {
		PyErr_SetString(PyExc_ValueError, "settings.lp_ctx not found");
		return NULL;
	}

	s->target_hostname = PyString_AsString(py_hostname);
	s->lp_ctx = lpcfg_from_py_object(s, py_lp_ctx);
	return s;
}

static PyObject *py_gensec_start_client(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	NTSTATUS status;
	pytalloc_Object *self;
	struct gensec_settings *settings;
	const char *kwnames[] = { "settings", NULL };
	PyObject *py_settings = Py_None;
	struct gensec_security *gensec;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|O", discard_const_p(char *, kwnames), &py_settings))
		return NULL;

	self = (pytalloc_Object*)type->tp_alloc(type, 0);
	if (self == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	self->talloc_ctx = talloc_new(NULL);
	if (self->talloc_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	if (py_settings != Py_None) {
		settings = settings_from_object(self->talloc_ctx, py_settings);
		if (settings == NULL) {
			PyObject_DEL(self);
			return NULL;
		}
	} else {
		settings = talloc_zero(self->talloc_ctx, struct gensec_settings);
		if (settings == NULL) {
			PyObject_DEL(self);
			return NULL;
		}

		settings->lp_ctx = loadparm_init_global(true);
		if (settings->lp_ctx == NULL) {
			PyErr_NoMemory();
			PyObject_DEL(self);
			return NULL;
		}
	}

	status = gensec_init();
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		PyObject_DEL(self);
		return NULL;
	}

	status = gensec_client_start(self->talloc_ctx, &gensec, settings);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		PyObject_DEL(self);
		return NULL;
	}

	self->ptr = gensec;

	return (PyObject *)self;
}

static PyObject *py_gensec_start_server(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	NTSTATUS status;
	pytalloc_Object *self;
	struct gensec_settings *settings = NULL;
	const char *kwnames[] = { "settings", "auth_context", NULL };
	PyObject *py_settings = Py_None;
	PyObject *py_auth_context = Py_None;
	struct gensec_security *gensec;
	struct auth4_context *auth_context = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|OO", discard_const_p(char *, kwnames), &py_settings, &py_auth_context))
		return NULL;

	self = (pytalloc_Object*)type->tp_alloc(type, 0);
	if (self == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	self->talloc_ctx = talloc_new(NULL);
	if (self->talloc_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	if (py_settings != Py_None) {
		settings = settings_from_object(self->talloc_ctx, py_settings);
		if (settings == NULL) {
			PyObject_DEL(self);
			return NULL;
		}
	} else {
		settings = talloc_zero(self->talloc_ctx, struct gensec_settings);
		if (settings == NULL) {
			PyObject_DEL(self);
			return NULL;
		}

		settings->lp_ctx = loadparm_init_global(true);
		if (settings->lp_ctx == NULL) {
			PyErr_NoMemory();
			PyObject_DEL(self);
			return NULL;
		}
	}

	if (py_auth_context != Py_None) {
		auth_context = pytalloc_get_type(py_auth_context, struct auth4_context);
		if (!auth_context) {
			PyErr_Format(PyExc_TypeError,
				     "Expected auth.AuthContext for auth_context argument, got %s",
				     talloc_get_name(pytalloc_get_ptr(py_auth_context)));
			return NULL;
		}
	}

	status = gensec_init();
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		PyObject_DEL(self);
		return NULL;
	}

	status = gensec_server_start(self->talloc_ctx, settings, auth_context, &gensec);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		PyObject_DEL(self);
		return NULL;
	}

	self->ptr = gensec;

	return (PyObject *)self;
}

static PyObject *py_gensec_set_credentials(PyObject *self, PyObject *args)
{
	PyObject *py_creds = Py_None;
	struct cli_credentials *creds;
	struct gensec_security *security = pytalloc_get_type(self, struct gensec_security);
	NTSTATUS status;

	if (!PyArg_ParseTuple(args, "O", &py_creds))
		return NULL;

	creds = PyCredentials_AsCliCredentials(py_creds);
	if (!creds) {
		PyErr_Format(PyExc_TypeError,
			     "Expected samba.credentaials for credentials argument got  %s",
			     talloc_get_name(pytalloc_get_ptr(py_creds)));
	}

	status = gensec_set_credentials(security, creds);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *py_gensec_session_info(PyObject *self)
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	PyObject *py_session_info;
	struct gensec_security *security = pytalloc_get_type(self, struct gensec_security);
	struct auth_session_info *info;
	if (security->ops == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "no mechanism selected");
		return NULL;
	}
	mem_ctx = talloc_new(NULL);

	status = gensec_session_info(security, mem_ctx, &info);
	if (NT_STATUS_IS_ERR(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	py_session_info = py_return_ndr_struct("samba.dcerpc.auth", "session_info",
						 info, info);
	talloc_free(mem_ctx);
	return py_session_info;
}

static PyObject *py_gensec_session_key(PyObject *self)
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	struct gensec_security *security = pytalloc_get_type(self, struct gensec_security);
	DATA_BLOB session_key = data_blob_null;
	static PyObject *session_key_obj = NULL;

	if (security->ops == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "no mechanism selected");
		return NULL;
	}
	mem_ctx = talloc_new(NULL);

	status = gensec_session_key(security, mem_ctx, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	session_key_obj = PyString_FromStringAndSize((const char *)session_key.data,
						     session_key.length);
	talloc_free(mem_ctx);
	return session_key_obj;
}

static PyObject *py_gensec_start_mech_by_name(PyObject *self, PyObject *args)
{
	char *name;
	struct gensec_security *security = pytalloc_get_type(self, struct gensec_security);
	NTSTATUS status;

	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	status = gensec_start_mech_by_name(security, name);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *py_gensec_start_mech_by_sasl_name(PyObject *self, PyObject *args)
{
	char *sasl_name;
	struct gensec_security *security = pytalloc_get_type(self, struct gensec_security);
	NTSTATUS status;

	if (!PyArg_ParseTuple(args, "s", &sasl_name))
		return NULL;

	status = gensec_start_mech_by_sasl_name(security, sasl_name);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *py_gensec_start_mech_by_authtype(PyObject *self, PyObject *args)
{
	int authtype, level;
	struct gensec_security *security = pytalloc_get_type(self, struct gensec_security);
	NTSTATUS status;
	if (!PyArg_ParseTuple(args, "ii", &authtype, &level))
		return NULL;

	status = gensec_start_mech_by_authtype(security, authtype, level);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *py_gensec_want_feature(PyObject *self, PyObject *args)
{
	int feature;
	struct gensec_security *security = pytalloc_get_type(self, struct gensec_security);
	/* This is i (and declared as an int above) by design, as they are handled as an integer in python */
	if (!PyArg_ParseTuple(args, "i", &feature))
		return NULL;

	gensec_want_feature(security, feature);

	Py_RETURN_NONE;
}

static PyObject *py_gensec_have_feature(PyObject *self, PyObject *args)
{
	int feature;
	struct gensec_security *security = pytalloc_get_type(self, struct gensec_security);
	/* This is i (and declared as an int above) by design, as they are handled as an integer in python */
	if (!PyArg_ParseTuple(args, "i", &feature))
		return NULL;

	if (gensec_have_feature(security, feature)) {
		return Py_True;
	} 
	return Py_False;
}

static PyObject *py_gensec_set_max_update_size(PyObject *self, PyObject *args)
{
	struct gensec_security *security = pytalloc_get_type(self, struct gensec_security);
	unsigned int max_update_size = 0;

	if (!PyArg_ParseTuple(args, "I", &max_update_size))
		return NULL;

	gensec_set_max_update_size(security, max_update_size);

	Py_RETURN_NONE;
}

static PyObject *py_gensec_max_update_size(PyObject *self)
{
	struct gensec_security *security = pytalloc_get_type(self, struct gensec_security);
	unsigned int max_update_size = gensec_max_update_size(security);

	return PyInt_FromLong(max_update_size);
}

static PyObject *py_gensec_update(PyObject *self, PyObject *args)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	DATA_BLOB in, out;
	PyObject *ret, *py_in;
	struct gensec_security *security = pytalloc_get_type(self, struct gensec_security);
	PyObject *finished_processing;
	struct tevent_context *ev;

	if (!PyArg_ParseTuple(args, "O", &py_in))
		return NULL;

	mem_ctx = talloc_new(NULL);

	if (!PyString_Check(py_in)) {
		PyErr_Format(PyExc_TypeError, "expected a string");
		return NULL;
	}

	in.data = (uint8_t *)PyString_AsString(py_in);
	in.length = PyString_Size(py_in);

	ev = tevent_context_init(mem_ctx);
	if (ev == NULL) {
		PyErr_NoMemory();
		PyObject_Del(self);
		return NULL;
	}

	status = gensec_update(security, mem_ctx, ev, in, &out);

	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)
	    && !NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		talloc_free(mem_ctx);
		return NULL;
	}
	ret = PyString_FromStringAndSize((const char *)out.data, out.length);
	talloc_free(mem_ctx);

	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		finished_processing = Py_False;
	} else {
		finished_processing = Py_True;
	}

	return PyTuple_Pack(2, finished_processing, ret);
}

static PyObject *py_gensec_wrap(PyObject *self, PyObject *args)
{
	NTSTATUS status;

	TALLOC_CTX *mem_ctx;
	DATA_BLOB in, out;
	PyObject *ret, *py_in;
	struct gensec_security *security = pytalloc_get_type(self, struct gensec_security);

	if (!PyArg_ParseTuple(args, "O", &py_in))
		return NULL;

	mem_ctx = talloc_new(NULL);

	if (!PyString_Check(py_in)) {
		PyErr_Format(PyExc_TypeError, "expected a string");
		return NULL;
	}
	in.data = (uint8_t *)PyString_AsString(py_in);
	in.length = PyString_Size(py_in);

	status = gensec_wrap(security, mem_ctx, &in, &out);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		talloc_free(mem_ctx);
		return NULL;
	}

	ret = PyString_FromStringAndSize((const char *)out.data, out.length);
	talloc_free(mem_ctx);
	return ret;
}

static PyObject *py_gensec_unwrap(PyObject *self, PyObject *args)
{
	NTSTATUS status;

	TALLOC_CTX *mem_ctx;
	DATA_BLOB in, out;
	PyObject *ret, *py_in;
	struct gensec_security *security = pytalloc_get_type(self, struct gensec_security);

	if (!PyArg_ParseTuple(args, "O", &py_in))
		return NULL;

	mem_ctx = talloc_new(NULL);

	if (!PyString_Check(py_in)) {
		PyErr_Format(PyExc_TypeError, "expected a string");
		return NULL;
	}

	in.data = (uint8_t *)PyString_AsString(py_in);
	in.length = PyString_Size(py_in);

	status = gensec_unwrap(security, mem_ctx, &in, &out);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		talloc_free(mem_ctx);
		return NULL;
	}

	ret = PyString_FromStringAndSize((const char *)out.data, out.length);
	talloc_free(mem_ctx);
	return ret;
}

static PyMethodDef py_gensec_security_methods[] = {
	{ "start_client", (PyCFunction)py_gensec_start_client, METH_VARARGS|METH_KEYWORDS|METH_CLASS, 
		"S.start_client(settings) -> gensec" },
	{ "start_server", (PyCFunction)py_gensec_start_server, METH_VARARGS|METH_KEYWORDS|METH_CLASS,
		"S.start_server(auth_ctx, settings) -> gensec" },
	{ "set_credentials", (PyCFunction)py_gensec_set_credentials, METH_VARARGS, 
		"S.start_client(credentials)" },
	{ "session_info", (PyCFunction)py_gensec_session_info, METH_NOARGS,
		"S.session_info() -> info" },
	{ "session_key", (PyCFunction)py_gensec_session_key, METH_NOARGS,
		"S.session_key() -> key" },
	{ "start_mech_by_name", (PyCFunction)py_gensec_start_mech_by_name, METH_VARARGS,
		"S.start_mech_by_name(name)" },
	{ "start_mech_by_sasl_name", (PyCFunction)py_gensec_start_mech_by_sasl_name, METH_VARARGS,
		"S.start_mech_by_sasl_name(name)" },
	{ "start_mech_by_authtype", (PyCFunction)py_gensec_start_mech_by_authtype, METH_VARARGS,
		"S.start_mech_by_authtype(authtype, level)" },
	{ "get_name_by_authtype", (PyCFunction)py_get_name_by_authtype, METH_VARARGS,
		"S.get_name_by_authtype(authtype) -> name\nLookup an auth type." },
	{ "want_feature", (PyCFunction)py_gensec_want_feature, METH_VARARGS,
		"S.want_feature(feature)\n Request that GENSEC negotiate a particular feature." },
	{ "have_feature", (PyCFunction)py_gensec_have_feature, METH_VARARGS,
		"S.have_feature()\n Return True if GENSEC negotiated a particular feature." },
	{ "set_max_update_size",  (PyCFunction)py_gensec_set_max_update_size, METH_VARARGS,
		"S.set_max_update_size(max_size) \n Some mechs can fragment update packets, needs to be use before the mech is started." },
	{ "max_update_size",  (PyCFunction)py_gensec_max_update_size, 0,
		"S.max_update_size() \n Return the current max_update_size." },
	{ "update",  (PyCFunction)py_gensec_update, METH_VARARGS,
		"S.update(blob_in) -> (finished, blob_out)\nPerform one step in a GENSEC dance.  Repeat with new packets until finished is true or exception." },
	{ "wrap",  (PyCFunction)py_gensec_wrap, METH_VARARGS,
		"S.wrap(blob_in) -> blob_out\nPackage one clear packet into a wrapped GENSEC packet." },
	{ "unwrap",  (PyCFunction)py_gensec_unwrap, METH_VARARGS,
		"S.unwrap(blob_in) -> blob_out\nPerform one wrapped GENSEC packet into a clear packet." },
	{ NULL }
};

static PyTypeObject Py_Security = {
	.tp_name = "gensec.Security",
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_methods = py_gensec_security_methods,
	.tp_basicsize = sizeof(pytalloc_Object),
};

void initgensec(void);
void initgensec(void)
{
	PyObject *m;

	Py_Security.tp_base = pytalloc_GetObjectType();
	if (Py_Security.tp_base == NULL)
		return;

	if (PyType_Ready(&Py_Security) < 0)
		return;

	m = Py_InitModule3("gensec", NULL, "Generic Security Interface.");
	if (m == NULL)
		return;

	PyModule_AddObject(m, "FEATURE_SESSION_KEY",     PyInt_FromLong(GENSEC_FEATURE_SESSION_KEY));
	PyModule_AddObject(m, "FEATURE_SIGN",            PyInt_FromLong(GENSEC_FEATURE_SIGN));
	PyModule_AddObject(m, "FEATURE_SEAL",            PyInt_FromLong(GENSEC_FEATURE_SEAL));
	PyModule_AddObject(m, "FEATURE_DCE_STYLE",       PyInt_FromLong(GENSEC_FEATURE_DCE_STYLE));
	PyModule_AddObject(m, "FEATURE_ASYNC_REPLIES",   PyInt_FromLong(GENSEC_FEATURE_ASYNC_REPLIES));
	PyModule_AddObject(m, "FEATURE_DATAGRAM_MODE",   PyInt_FromLong(GENSEC_FEATURE_DATAGRAM_MODE));
	PyModule_AddObject(m, "FEATURE_SIGN_PKT_HEADER", PyInt_FromLong(GENSEC_FEATURE_SIGN_PKT_HEADER));
	PyModule_AddObject(m, "FEATURE_NEW_SPNEGO",      PyInt_FromLong(GENSEC_FEATURE_NEW_SPNEGO));

	Py_INCREF(&Py_Security);
	PyModule_AddObject(m, "Security", (PyObject *)&Py_Security);
}
