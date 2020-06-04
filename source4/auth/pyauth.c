/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2008
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2011

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
#include "python/modules.h"
#include "libcli/util/pyerrors.h"
#include "param/param.h"
#include "pyauth.h"
#include "pyldb.h"
#include "auth/system_session_proto.h"
#include "auth/auth.h"
#include "auth/auth_util.h"
#include "param/pyparam.h"
#include "libcli/security/security.h"
#include "auth/credentials/pycredentials.h"
#include <tevent.h>
#include "librpc/rpc/pyrpc_util.h"
#include "lib/events/events.h"

static PyTypeObject PyAuthContext;

static PyObject *PyAuthSession_FromSession(struct auth_session_info *session)
{
	return py_return_ndr_struct("samba.dcerpc.auth", "session_info", session, session);
}

static PyObject *py_copy_session_info(PyObject *module,
				      PyObject *args,
				      PyObject *kwargs)
{
	PyObject *py_session = Py_None;
	PyObject *result = Py_None;
	struct auth_session_info *session = NULL;
	struct auth_session_info *session_duplicate = NULL;
	TALLOC_CTX *frame;
	int ret = 1;

	const char * const kwnames[] = { "session_info", NULL };

	ret = PyArg_ParseTupleAndKeywords(args,
					  kwargs,
					  "O",
					  discard_const_p(char *, kwnames),
					  &py_session);
	if (!ret) {
		return NULL;
	}

	ret = py_check_dcerpc_type(py_session,
				   "samba.dcerpc.auth",
				   "session_info");
	if (!ret) {
		return NULL;
	}
	session = pytalloc_get_type(py_session,
				    struct auth_session_info);
	if (!session) {
		PyErr_Format(PyExc_TypeError,
			     "Expected auth_session_info for session_info "
			     "argument got %s",
			     pytalloc_get_name(py_session));
		return NULL;
	}

	frame = talloc_stackframe();
	if (frame == NULL) {
		return PyErr_NoMemory();
	}

	session_duplicate = copy_session_info(frame, session);
	if (session_duplicate == NULL) {
		TALLOC_FREE(frame);
		return PyErr_NoMemory();
	}

	result = PyAuthSession_FromSession(session_duplicate);
	TALLOC_FREE(frame);
	return result;
}

static PyObject *py_system_session(PyObject *module, PyObject *args)
{
	PyObject *py_lp_ctx = Py_None;
	struct loadparm_context *lp_ctx = NULL;
	struct auth_session_info *session;
	TALLOC_CTX *mem_ctx;
	if (!PyArg_ParseTuple(args, "|O", &py_lp_ctx))
		return NULL;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	lp_ctx = lpcfg_from_py_object(mem_ctx, py_lp_ctx);
	if (lp_ctx == NULL) {
		talloc_free(mem_ctx);
		return NULL;
	}

	session = system_session(lp_ctx);

	talloc_free(mem_ctx);

	return PyAuthSession_FromSession(session);
}


static PyObject *py_admin_session(PyObject *module, PyObject *args)
{
	PyObject *py_lp_ctx;
	const char *sid;
	struct loadparm_context *lp_ctx = NULL;
	struct auth_session_info *session;
	struct dom_sid *domain_sid = NULL;
	TALLOC_CTX *mem_ctx;

	if (!PyArg_ParseTuple(args, "Os", &py_lp_ctx, &sid))
		return NULL;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	lp_ctx = lpcfg_from_py_object(mem_ctx, py_lp_ctx);
	if (lp_ctx == NULL) {
		talloc_free(mem_ctx);
		return NULL;
	}

	domain_sid = dom_sid_parse_talloc(mem_ctx, sid);
	if (domain_sid == NULL) {
		PyErr_Format(PyExc_RuntimeError, "Unable to parse sid %s", sid);
		talloc_free(mem_ctx);
		return NULL;
	}
	session = admin_session(NULL, lp_ctx, domain_sid);
	talloc_free(mem_ctx);

	return PyAuthSession_FromSession(session);
}

static PyObject *py_user_session(PyObject *module, PyObject *args, PyObject *kwargs)
{
	NTSTATUS nt_status;
	struct auth_session_info *session;
	TALLOC_CTX *mem_ctx;
	const char * const kwnames[] = { "ldb", "lp_ctx", "principal", "dn", "session_info_flags", NULL };
	struct ldb_context *ldb_ctx;
	PyObject *py_ldb = Py_None;
	PyObject *py_dn = Py_None;
	PyObject *py_lp_ctx = Py_None;
	struct loadparm_context *lp_ctx = NULL;
	struct ldb_dn *user_dn;
	char *principal = NULL;
	int session_info_flags = 0; /* This is an int, because that's
				 * what we need for the python
				 * PyArg_ParseTupleAndKeywords */

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O|OzOi",
					 discard_const_p(char *, kwnames),
					 &py_ldb, &py_lp_ctx, &principal, &py_dn, &session_info_flags)) {
		return NULL;
	}

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	ldb_ctx = pyldb_Ldb_AsLdbContext(py_ldb);
	if (ldb_ctx == NULL) {
		talloc_free(mem_ctx);
		return NULL;
	}

	if (py_dn == Py_None) {
		user_dn = NULL;
	} else {
		if (!pyldb_Object_AsDn(ldb_ctx, py_dn, ldb_ctx, &user_dn)) {
			talloc_free(mem_ctx);
			return NULL;
		}
	}

	lp_ctx = lpcfg_from_py_object(mem_ctx, py_lp_ctx);
	if (lp_ctx == NULL) {
		talloc_free(mem_ctx);
		return NULL;
	}

	nt_status = authsam_get_session_info_principal(mem_ctx, lp_ctx, ldb_ctx, principal, user_dn,
						       session_info_flags, &session);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(mem_ctx);
		PyErr_NTSTATUS_IS_ERR_RAISE(nt_status);
	}

	talloc_steal(NULL, session);
	talloc_free(mem_ctx);

	return PyAuthSession_FromSession(session);
}

static PyObject *py_session_info_fill_unix(PyObject *module,
					   PyObject *args,
					   PyObject *kwargs)
{
	NTSTATUS nt_status;
	char *user_name = NULL;
	struct loadparm_context *lp_ctx = NULL;
	struct auth_session_info *session_info;
	PyObject *py_lp_ctx = Py_None;
	PyObject *py_session = Py_None;
	TALLOC_CTX *frame;

	const char * const kwnames[] = { "session_info",
					 "user_name",
					 "lp_ctx",
					 NULL };
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "Oz|O",
					 discard_const_p(char *, kwnames),
					 &py_session,
					 &user_name,
					 &py_lp_ctx)) {
		return NULL;
	}

	if (!py_check_dcerpc_type(py_session,
				  "samba.dcerpc.auth",
				  "session_info")) {
		return NULL;
	}
	session_info = pytalloc_get_type(py_session,
					 struct auth_session_info);
	if (!session_info) {
		PyErr_Format(PyExc_TypeError,
			     "Expected auth_session_info for session_info argument got %s",
			     pytalloc_get_name(py_session));
		return NULL;
	}

	frame = talloc_stackframe();
	
	lp_ctx = lpcfg_from_py_object(frame, py_lp_ctx);
	if (lp_ctx == NULL) {
		TALLOC_FREE(frame);
		return NULL;
	}

	nt_status = auth_session_info_fill_unix(lp_ctx,
					       user_name,
					       session_info);
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(nt_status)) {
		PyErr_NTSTATUS_IS_ERR_RAISE(nt_status);
	}

	Py_RETURN_NONE;
}


static PyObject *py_session_info_set_unix(PyObject *module,
					  PyObject *args,
					  PyObject *kwargs)
{
	NTSTATUS nt_status;
	char *user_name = NULL;
	int uid = -1;
	int gid = -1;
	struct loadparm_context *lp_ctx = NULL;
	struct auth_session_info *session_info;
	PyObject *py_lp_ctx = Py_None;
	PyObject *py_session = Py_None;
	TALLOC_CTX *frame;

	const char * const kwnames[] = { "session_info",
					 "user_name",
					 "uid",
					 "gid",
					 "lp_ctx",
					 NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "Ozii|O",
					 discard_const_p(char *, kwnames),
					 &py_session,
					 &user_name,
					 &uid,
					 &gid,
					 &py_lp_ctx)) {
		return NULL;
	}

	if (!py_check_dcerpc_type(py_session,
				  "samba.dcerpc.auth",
				  "session_info")) {
		return NULL;
	}
	session_info = pytalloc_get_type(py_session,
					 struct auth_session_info);
	if (!session_info) {
		PyErr_Format(PyExc_TypeError,
			     "Expected auth_session_info for session_info "
			     "argument got %s",
			     pytalloc_get_name(py_session));
		return NULL;
	}

	frame = talloc_stackframe();

	lp_ctx = lpcfg_from_py_object(frame, py_lp_ctx);
	if (lp_ctx == NULL) {
		TALLOC_FREE(frame);
		return NULL;
	}

	nt_status = auth_session_info_set_unix(lp_ctx,
					       user_name,
					       uid,
					       gid,
					       session_info);
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(nt_status)) {
		PyErr_NTSTATUS_IS_ERR_RAISE(nt_status);
	}

	Py_RETURN_NONE;
}


static const char **PyList_AsStringList(TALLOC_CTX *mem_ctx, PyObject *list, 
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
		const char *value;
		Py_ssize_t size;
		PyObject *item = PyList_GetItem(list, i);
		if (!PyUnicode_Check(item)) {
			PyErr_Format(PyExc_TypeError, "%s should be strings", paramname);
			return NULL;
		}
		value = PyUnicode_AsUTF8AndSize(item, &size);
		if (value == NULL) {
			talloc_free(ret);
			return NULL;
		}
		ret[i] = talloc_strndup(ret, value, size);
	}
	ret[i] = NULL;
	return ret;
}

static PyObject *PyAuthContext_FromContext(struct auth4_context *auth_context)
{
	return pytalloc_reference(&PyAuthContext, auth_context);
}

static PyObject *py_auth_context_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	PyObject *py_lp_ctx = Py_None;
	PyObject *py_ldb = Py_None;
	PyObject *py_auth_context = Py_None;
	PyObject *py_methods = Py_None;
	TALLOC_CTX *mem_ctx;
	struct auth4_context *auth_context;
	struct loadparm_context *lp_ctx;
	struct tevent_context *ev;
	struct ldb_context *ldb = NULL;
	NTSTATUS nt_status;
	const char **methods;

	const char *const kwnames[] = {"lp_ctx", "ldb", "methods", NULL};

	if (!PyArg_ParseTupleAndKeywords(args,
					 kwargs,
					 "|OOO",
					 discard_const_p(char *, kwnames),
					 &py_lp_ctx,
					 &py_ldb,
					 &py_methods))
		return NULL;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	if (py_ldb != Py_None) {
		ldb = pyldb_Ldb_AsLdbContext(py_ldb);
		if (ldb == NULL) {
			talloc_free(mem_ctx);
			return NULL;
		}
	}

	lp_ctx = lpcfg_from_py_object(mem_ctx, py_lp_ctx);
	if (lp_ctx == NULL) {
		talloc_free(mem_ctx);
		PyErr_NoMemory();
		return NULL;
	}

	ev = s4_event_context_init(mem_ctx);
	if (ev == NULL) {
		talloc_free(mem_ctx);
		PyErr_NoMemory();
		return NULL;
	}

	if (py_methods == Py_None && py_ldb == Py_None) {
		nt_status = auth_context_create(
		    mem_ctx, ev, NULL, lp_ctx, &auth_context);
	} else {
		if (py_methods != Py_None) {
			methods = PyList_AsStringList(mem_ctx, py_methods, "methods");
			if (methods == NULL) {
				talloc_free(mem_ctx);
				return NULL;
			}
		} else {
			methods = auth_methods_from_lp(mem_ctx, lp_ctx);
		}
		nt_status = auth_context_create_methods(
		    mem_ctx, methods, ev, NULL, lp_ctx, ldb, &auth_context);
	}

	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(mem_ctx);
		PyErr_NTSTATUS_IS_ERR_RAISE(nt_status);
	}

	if (!talloc_reference(auth_context, lp_ctx)) {
		talloc_free(mem_ctx);
		PyErr_NoMemory();
		return NULL;
	}

	if (!talloc_reference(auth_context, ev)) {
		talloc_free(mem_ctx);
		PyErr_NoMemory();
		return NULL;
	}

	py_auth_context = PyAuthContext_FromContext(auth_context);

	talloc_free(mem_ctx);

	return py_auth_context;
}

static PyTypeObject PyAuthContext = {
	.tp_name = "AuthContext",
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = py_auth_context_new,
};

static PyMethodDef py_auth_methods[] = {
	{ "system_session", (PyCFunction)py_system_session, METH_VARARGS, NULL },
	{ "admin_session", (PyCFunction)py_admin_session, METH_VARARGS, NULL },
	{ "user_session", PY_DISCARD_FUNC_SIG(PyCFunction,py_user_session),
			  METH_VARARGS|METH_KEYWORDS, NULL },
	{ "session_info_fill_unix",
	  PY_DISCARD_FUNC_SIG(PyCFunction,py_session_info_fill_unix),
	  METH_VARARGS|METH_KEYWORDS,
	  NULL },
	{ "session_info_set_unix",
	  PY_DISCARD_FUNC_SIG(PyCFunction,py_session_info_set_unix),
	  METH_VARARGS|METH_KEYWORDS,
	  NULL },
	{ "copy_session_info",
	  PY_DISCARD_FUNC_SIG(PyCFunction,py_copy_session_info),
	  METH_VARARGS|METH_KEYWORDS,
	  NULL },
	{0},
};

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	.m_name = "auth",
	.m_doc = "Authentication and authorization support.",
	.m_size = -1,
	.m_methods = py_auth_methods,
};

MODULE_INIT_FUNC(auth)
{
	PyObject *m;

	if (pytalloc_BaseObject_PyType_Ready(&PyAuthContext) < 0)
		return NULL;

	m = PyModule_Create(&moduledef);
	if (m == NULL)
		return NULL;

	Py_INCREF(&PyAuthContext);
	PyModule_AddObject(m, "AuthContext", (PyObject *)&PyAuthContext);

#define ADD_FLAG(val)  PyModule_AddIntConstant(m, #val, val)
	ADD_FLAG(AUTH_SESSION_INFO_DEFAULT_GROUPS);
	ADD_FLAG(AUTH_SESSION_INFO_AUTHENTICATED);
	ADD_FLAG(AUTH_SESSION_INFO_SIMPLE_PRIVILEGES);
	ADD_FLAG(AUTH_SESSION_INFO_NTLM);

	return m;
}
