/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2008-2010
   Copyright (C) Kamen Mazdrashki <kamen.mazdrashki@postpath.com> 2009

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
#include "libnet.h"
#include "auth/credentials/pycredentials.h"
#include "libcli/security/security.h"
#include "lib/events/events.h"
#include "param/param.h"
#include "param/pyparam.h"

typedef struct {
	PyObject_HEAD
	TALLOC_CTX *mem_ctx;
	struct libnet_context *libnet_ctx;
	struct tevent_context *ev;
} py_net_Object;

static PyObject *py_net_join(py_net_Object *self, PyObject *args, PyObject *kwargs)
{
	struct libnet_Join r;
	NTSTATUS status;
	PyObject *result;
	TALLOC_CTX *mem_ctx;
	const char *kwnames[] = { "domain_name", "netbios_name", "join_type", "level", NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "ssii:Join", discard_const_p(char *, kwnames), 
					 &r.in.domain_name, &r.in.netbios_name, 
					 &r.in.join_type, &r.in.level))
		return NULL;

	mem_ctx = talloc_new(self->mem_ctx);

	status = libnet_Join(self->libnet_ctx, mem_ctx, &r);
	if (NT_STATUS_IS_ERR(status)) {
		PyErr_SetString(PyExc_RuntimeError, r.out.error_string?r.out.error_string:nt_errstr(status));
		talloc_free(mem_ctx);
		return NULL;
	}

	result = Py_BuildValue("sss", r.out.join_password,
			       dom_sid_string(mem_ctx, r.out.domain_sid),
			       r.out.domain_name);

	talloc_free(mem_ctx);

	return result;
}

static const char py_net_join_doc[] = "join(domain_name, netbios_name, join_type, level) -> (join_password, domain_sid, domain_name)\n\n" \
"Join the domain with the specified name.";

static PyObject *py_net_set_password(py_net_Object *self, PyObject *args, PyObject *kwargs)
{
	union libnet_SetPassword r;
	NTSTATUS status;
	PyObject *py_creds;
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	const char *kwnames[] = { "account_name", "domain_name", "newpassword", "credentials", NULL };

	r.generic.level = LIBNET_SET_PASSWORD_GENERIC;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "sssO:set_password", discard_const_p(char *, kwnames),
					 &r.generic.in.account_name, &r.generic.in.domain_name,
					 &r.generic.in.newpassword, &py_creds)) {
		return NULL;
	}

	/* FIXME: we really need to get a context from the caller or we may end
	 * up with 2 event contexts */
	ev = s4_event_context_init(NULL);
	mem_ctx = talloc_new(ev);

	status = libnet_SetPassword(self->libnet_ctx, mem_ctx, &r);
	if (NT_STATUS_IS_ERR(status)) {
		PyErr_SetString(PyExc_RuntimeError,
				r.generic.out.error_string?r.generic.out.error_string:nt_errstr(status));
		talloc_free(mem_ctx);
		return NULL;
	}

	talloc_free(mem_ctx);

	Py_RETURN_NONE;
}

static const char py_net_set_password_doc[] = "set_password(account_name, domain_name, newpassword) -> True\n\n" \
"Set password for a user. You must supply credential with enough rights to do this.\n\n" \
"Sample usage is:\n" \
"net.set_password(account_name=<account_name>,\n" \
"                domain_name=domain_name,\n" \
"                newpassword=new_pass)\n";


static PyObject *py_net_export_keytab(py_net_Object *self, PyObject *args, PyObject *kwargs)
{
	struct libnet_export_keytab r;
	TALLOC_CTX *mem_ctx;
	const char *kwnames[] = { "keytab", NULL };
	NTSTATUS status;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s:export_keytab", discard_const_p(char *, kwnames),
					 &r.in.keytab_name)) {
		return NULL;
	}

	mem_ctx = talloc_new(self->mem_ctx);

	status = libnet_export_keytab(self->libnet_ctx, mem_ctx, &r);
	if (NT_STATUS_IS_ERR(status)) {
		PyErr_SetString(PyExc_RuntimeError,
				r.out.error_string?r.out.error_string:nt_errstr(status));
		talloc_free(mem_ctx);
		return NULL;
	}

	talloc_free(mem_ctx);

	Py_RETURN_NONE;
}

static const char py_net_export_keytab_doc[] = "export_keytab(keytab, name)\n\n"
"Export the DC keytab to a keytab file.";

static PyObject *py_net_time(py_net_Object *self, PyObject *args, PyObject *kwargs)
{
	const char *kwnames[] = { "server_name", NULL };
	union libnet_RemoteTOD r;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	char timestr[64];
	PyObject *ret;
	struct tm *tm;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s",
		discard_const_p(char *, kwnames), &r.generic.in.server_name))
		return NULL;

	r.generic.level			= LIBNET_REMOTE_TOD_GENERIC;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	status = libnet_RemoteTOD(self->libnet_ctx, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetString(PyExc_RuntimeError,
				r.generic.out.error_string?r.generic.out.error_string:nt_errstr(status));
		talloc_free(mem_ctx);
		return NULL;
	}

	ZERO_STRUCT(timestr);
	tm = localtime(&r.generic.out.time);
	strftime(timestr, sizeof(timestr)-1, "%c %Z",tm);
	
	ret = PyString_FromString(timestr);

	talloc_free(mem_ctx);

	return ret;
}

static const char py_net_time_doc[] = "time(server_name) -> timestr\n"
"Retrieve the remote time on a server";

static PyObject *py_net_user_create(py_net_Object *self, PyObject *args, PyObject *kwargs)
{
	const char *kwnames[] = { "username", NULL };
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	struct libnet_CreateUser r;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", discard_const_p(char *, kwnames), 
									 &r.in.user_name))
		return NULL;

	r.in.domain_name = cli_credentials_get_domain(self->libnet_ctx->cred);

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	status = libnet_CreateUser(self->libnet_ctx, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetString(PyExc_RuntimeError, r.out.error_string?r.out.error_string:nt_errstr(status));
		talloc_free(mem_ctx);
		return NULL;
	}

	talloc_free(mem_ctx);
	
	Py_RETURN_NONE;
}

static const char py_net_create_user_doc[] = "create_user(username)\n"
"Create a new user.";

static PyObject *py_net_user_delete(py_net_Object *self, PyObject *args, PyObject *kwargs)
{
	const char *kwnames[] = { "username", NULL };
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	struct libnet_DeleteUser r;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", discard_const_p(char *, kwnames), 
									 &r.in.user_name))
		return NULL;

	r.in.domain_name = cli_credentials_get_domain(self->libnet_ctx->cred);

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	status = libnet_DeleteUser(self->libnet_ctx, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetString(PyExc_RuntimeError, r.out.error_string?r.out.error_string:nt_errstr(status));
		talloc_free(mem_ctx);
		return NULL;
	}

	talloc_free(mem_ctx);
	
	Py_RETURN_NONE;
}

static const char py_net_delete_user_doc[] = "delete_user(username)\n"
"Delete a user.";

static PyObject *py_dom_sid_FromSid(struct dom_sid *sid)
{
	PyObject *mod_security, *dom_sid_Type;

	mod_security = PyImport_ImportModule("samba.dcerpc.security");
	if (mod_security == NULL)
		return NULL;

	dom_sid_Type = PyObject_GetAttrString(mod_security, "dom_sid");
	if (dom_sid_Type == NULL)
		return NULL;

	return py_talloc_reference((PyTypeObject *)dom_sid_Type, sid);
}

static PyObject *py_net_vampire(py_net_Object *self, PyObject *args, PyObject *kwargs)
{
	const char *kwnames[] = { "domain", "target_dir", NULL };
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	PyObject *ret;
	struct libnet_Vampire r;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|z", discard_const_p(char *, kwnames),
	                                 &r.in.domain_name, &r.in.targetdir)) {
		return NULL;
	}

	r.in.netbios_name  = lpcfg_netbios_name(self->libnet_ctx->lp_ctx);
	r.out.error_string = NULL;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	status = libnet_Vampire(self->libnet_ctx, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetString(PyExc_RuntimeError,
		                r.out.error_string ? r.out.error_string : nt_errstr(status));
		talloc_free(mem_ctx);
		return NULL;
	}

	ret = Py_BuildValue("(sO)", r.out.domain_name, py_dom_sid_FromSid(r.out.domain_sid));

	talloc_free(mem_ctx);

	return ret;
}

static const char py_net_vampire_doc[] = "vampire(domain, target_dir=None)\n"
					 "Vampire a domain.";

static PyMethodDef net_obj_methods[] = {
	{"join", (PyCFunction)py_net_join, METH_VARARGS|METH_KEYWORDS, py_net_join_doc},
	{"set_password", (PyCFunction)py_net_set_password, METH_VARARGS|METH_KEYWORDS, py_net_set_password_doc},
	{"export_keytab", (PyCFunction)py_net_export_keytab, METH_VARARGS|METH_KEYWORDS, py_net_export_keytab_doc},
	{"time", (PyCFunction)py_net_time, METH_VARARGS|METH_KEYWORDS, py_net_time_doc},
	{"create_user", (PyCFunction)py_net_user_create, METH_VARARGS|METH_KEYWORDS, py_net_create_user_doc},
	{"delete_user", (PyCFunction)py_net_user_delete, METH_VARARGS|METH_KEYWORDS, py_net_delete_user_doc},
	{"vampire", (PyCFunction)py_net_vampire, METH_VARARGS|METH_KEYWORDS, py_net_vampire_doc},
	{ NULL }
};

static void py_net_dealloc(py_net_Object *self)
{
	talloc_free(self->mem_ctx);
}

static PyObject *net_obj_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	PyObject *py_creds, *py_lp = Py_None;
	const char *kwnames[] = { "creds", "lp", NULL };
	py_net_Object *ret;
	struct loadparm_context *lp;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O|O", 
			discard_const_p(char *, kwnames), &py_creds, &py_lp))
		return NULL;

	ret = PyObject_New(py_net_Object, type);
	if (ret == NULL) {
		return NULL;
	}

	/* FIXME: we really need to get a context from the caller or we may end
	 * up with 2 event contexts */
	ret->ev = s4_event_context_init(NULL);
	ret->mem_ctx = talloc_new(ret->ev);

	lp = lpcfg_from_py_object(ret->mem_ctx, py_lp);
	if (lp == NULL) {
		Py_DECREF(ret);
		return NULL;
	}

	ret->libnet_ctx = libnet_context_init(ret->ev, lp);
	if (ret->libnet_ctx == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "Unable to initialize net");
		Py_DECREF(ret);
		return NULL;
	}

	ret->libnet_ctx->cred = cli_credentials_from_py_object(py_creds);
	if (ret->libnet_ctx->cred == NULL) {
		PyErr_SetString(PyExc_TypeError, "Expected credentials object");
		Py_DECREF(ret);
		return NULL;
	}

	return (PyObject *)ret;
}


PyTypeObject py_net_Type = {
	PyObject_HEAD_INIT(NULL) 0,
	.tp_name = "net.Net",
	.tp_basicsize = sizeof(py_net_Object),
	.tp_dealloc = (destructor)py_net_dealloc,
	.tp_methods = net_obj_methods,
	.tp_new = net_obj_new,
};

void initnet(void)
{
	PyObject *m;

	if (PyType_Ready(&py_net_Type) < 0)
		return;

	m = Py_InitModule3("net", NULL, NULL);
	if (m == NULL)
		return;

	Py_INCREF(&py_net_Type);
	PyModule_AddObject(m, "Net", (PyObject *)&py_net_Type);
}
