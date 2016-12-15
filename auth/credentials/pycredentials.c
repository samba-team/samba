/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
   
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
#include "pycredentials.h"
#include "param/param.h"
#include "lib/cmdline/credentials.h"
#include "librpc/gen_ndr/samr.h" /* for struct samr_Password */
#include "libcli/util/pyerrors.h"
#include "param/pyparam.h"
#include <tevent.h>

void initcredentials(void);

static PyObject *PyString_FromStringOrNULL(const char *str)
{
	if (str == NULL)
		Py_RETURN_NONE;
	return PyString_FromString(str);
}

static PyObject *py_creds_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	return pytalloc_steal(type, cli_credentials_init(NULL));
}

static PyObject *py_creds_get_username(PyObject *self, PyObject *unused)
{
	return PyString_FromStringOrNULL(cli_credentials_get_username(PyCredentials_AsCliCredentials(self)));
}

static PyObject *py_creds_set_username(PyObject *self, PyObject *args)
{
	char *newval;
	enum credentials_obtained obt = CRED_SPECIFIED;
	int _obt = obt;

	if (!PyArg_ParseTuple(args, "s|i", &newval, &_obt)) {
		return NULL;
	}
	obt = _obt;

	return PyBool_FromLong(cli_credentials_set_username(PyCredentials_AsCliCredentials(self), newval, obt));
}

static PyObject *py_creds_get_ntlm_username_domain(PyObject *self, PyObject *unused)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *user = NULL;
	const char *domain = NULL;
	PyObject *ret = NULL;
	cli_credentials_get_ntlm_username_domain(PyCredentials_AsCliCredentials(self),
						 frame, &user, &domain);
	ret = Py_BuildValue("(OO)",
			    PyString_FromStringOrNULL(user),
			    PyString_FromStringOrNULL(domain));
	TALLOC_FREE(frame);
	return ret;
}

static PyObject *py_creds_get_principal(PyObject *self, PyObject *unused)
{
	TALLOC_CTX *frame = talloc_stackframe();
	PyObject *ret = PyString_FromStringOrNULL(cli_credentials_get_principal(PyCredentials_AsCliCredentials(self), frame));
	TALLOC_FREE(frame);
	return ret;
}

static PyObject *py_creds_set_principal(PyObject *self, PyObject *args)
{
	char *newval;
	enum credentials_obtained obt = CRED_SPECIFIED;
	int _obt = obt;

	if (!PyArg_ParseTuple(args, "s|i", &newval, &_obt)) {
		return NULL;
	}
	obt = _obt;

	return PyBool_FromLong(cli_credentials_set_principal(PyCredentials_AsCliCredentials(self), newval, obt));
}

static PyObject *py_creds_get_password(PyObject *self, PyObject *unused)
{
	return PyString_FromStringOrNULL(cli_credentials_get_password(PyCredentials_AsCliCredentials(self)));
}

static PyObject *py_creds_set_password(PyObject *self, PyObject *args)
{
	char *newval;
	enum credentials_obtained obt = CRED_SPECIFIED;
	int _obt = obt;

	if (!PyArg_ParseTuple(args, "s|i", &newval, &_obt)) {
		return NULL;
	}
	obt = _obt;

	return PyBool_FromLong(cli_credentials_set_password(PyCredentials_AsCliCredentials(self), newval, obt));
}

static PyObject *py_creds_set_utf16_password(PyObject *self, PyObject *args)
{
	enum credentials_obtained obt = CRED_SPECIFIED;
	int _obt = obt;
	PyObject *newval = NULL;
	DATA_BLOB blob = data_blob_null;
	Py_ssize_t size =  0;
	int result;
	bool ok;

	if (!PyArg_ParseTuple(args, "O|i", &newval, &_obt)) {
		return NULL;
	}
	obt = _obt;

	result = PyBytes_AsStringAndSize(newval, (char **)&blob.data, &size);
	if (result != 0) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to convert passed value to Bytes");
		return NULL;
	}
	blob.length = size;

	ok = cli_credentials_set_utf16_password(PyCredentials_AsCliCredentials(self),
						&blob, obt);

	return PyBool_FromLong(ok);
}

static PyObject *py_creds_get_old_password(PyObject *self, PyObject *unused)
{
	return PyString_FromStringOrNULL(cli_credentials_get_old_password(PyCredentials_AsCliCredentials(self)));
}

static PyObject *py_creds_set_old_password(PyObject *self, PyObject *args)
{
	char *oldval;
	enum credentials_obtained obt = CRED_SPECIFIED;
	int _obt = obt;

	if (!PyArg_ParseTuple(args, "s|i", &oldval, &_obt)) {
		return NULL;
	}
	obt = _obt;

	return PyBool_FromLong(cli_credentials_set_old_password(PyCredentials_AsCliCredentials(self), oldval, obt));
}

static PyObject *py_creds_set_old_utf16_password(PyObject *self, PyObject *args)
{
	PyObject *oldval = NULL;
	DATA_BLOB blob = data_blob_null;
	Py_ssize_t size =  0;
	int result;
	bool ok;

	if (!PyArg_ParseTuple(args, "O", &oldval)) {
		return NULL;
	}

	result = PyBytes_AsStringAndSize(oldval, (char **)&blob.data, &size);
	if (result != 0) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to convert passed value to Bytes");
		return NULL;
	}
	blob.length = size;

	ok = cli_credentials_set_old_utf16_password(PyCredentials_AsCliCredentials(self),
						    &blob);

	return PyBool_FromLong(ok);
}

static PyObject *py_creds_get_domain(PyObject *self, PyObject *unused)
{
	return PyString_FromStringOrNULL(cli_credentials_get_domain(PyCredentials_AsCliCredentials(self)));
}

static PyObject *py_creds_set_domain(PyObject *self, PyObject *args)
{
	char *newval;
	enum credentials_obtained obt = CRED_SPECIFIED;
	int _obt = obt;

	if (!PyArg_ParseTuple(args, "s|i", &newval, &_obt)) {
		return NULL;
	}
	obt = _obt;

	return PyBool_FromLong(cli_credentials_set_domain(PyCredentials_AsCliCredentials(self), newval, obt));
}

static PyObject *py_creds_get_realm(PyObject *self, PyObject *unused)
{
	return PyString_FromStringOrNULL(cli_credentials_get_realm(PyCredentials_AsCliCredentials(self)));
}

static PyObject *py_creds_set_realm(PyObject *self, PyObject *args)
{
	char *newval;
	enum credentials_obtained obt = CRED_SPECIFIED;
	int _obt = obt;

	if (!PyArg_ParseTuple(args, "s|i", &newval, &_obt)) {
		return NULL;
	}
	obt = _obt;

	return PyBool_FromLong(cli_credentials_set_realm(PyCredentials_AsCliCredentials(self), newval, obt));
}

static PyObject *py_creds_get_bind_dn(PyObject *self, PyObject *unused)
{
	return PyString_FromStringOrNULL(cli_credentials_get_bind_dn(PyCredentials_AsCliCredentials(self)));
}

static PyObject *py_creds_set_bind_dn(PyObject *self, PyObject *args)
{
	char *newval;
	if (!PyArg_ParseTuple(args, "s", &newval))
		return NULL;

	return PyBool_FromLong(cli_credentials_set_bind_dn(PyCredentials_AsCliCredentials(self), newval));
}

static PyObject *py_creds_get_workstation(PyObject *self, PyObject *unused)
{
	return PyString_FromStringOrNULL(cli_credentials_get_workstation(PyCredentials_AsCliCredentials(self)));
}

static PyObject *py_creds_set_workstation(PyObject *self, PyObject *args)
{
	char *newval;
	enum credentials_obtained obt = CRED_SPECIFIED;
	int _obt = obt;

	if (!PyArg_ParseTuple(args, "s|i", &newval, &_obt)) {
		return NULL;
	}
	obt = _obt;

	return PyBool_FromLong(cli_credentials_set_workstation(PyCredentials_AsCliCredentials(self), newval, obt));
}

static PyObject *py_creds_is_anonymous(PyObject *self, PyObject *unused)
{
	return PyBool_FromLong(cli_credentials_is_anonymous(PyCredentials_AsCliCredentials(self)));
}

static PyObject *py_creds_set_anonymous(PyObject *self, PyObject *unused)
{
	cli_credentials_set_anonymous(PyCredentials_AsCliCredentials(self));
	Py_RETURN_NONE;
}

static PyObject *py_creds_authentication_requested(PyObject *self, PyObject *unused)
{
        return PyBool_FromLong(cli_credentials_authentication_requested(PyCredentials_AsCliCredentials(self)));
}

static PyObject *py_creds_wrong_password(PyObject *self, PyObject *unused)
{
        return PyBool_FromLong(cli_credentials_wrong_password(PyCredentials_AsCliCredentials(self)));
}

static PyObject *py_creds_set_cmdline_callbacks(PyObject *self, PyObject *unused)
{
        return PyBool_FromLong(cli_credentials_set_cmdline_callbacks(PyCredentials_AsCliCredentials(self)));
}

static PyObject *py_creds_parse_string(PyObject *self, PyObject *args)
{
	char *newval;
	enum credentials_obtained obt = CRED_SPECIFIED;
	int _obt = obt;

	if (!PyArg_ParseTuple(args, "s|i", &newval, &_obt)) {
		return NULL;
	}
	obt = _obt;

	cli_credentials_parse_string(PyCredentials_AsCliCredentials(self), newval, obt);
	Py_RETURN_NONE;
}

static PyObject *py_creds_parse_file(PyObject *self, PyObject *args)
{
	char *newval;
	enum credentials_obtained obt = CRED_SPECIFIED;
	int _obt = obt;

	if (!PyArg_ParseTuple(args, "s|i", &newval, &_obt)) {
		return NULL;
	}
	obt = _obt;

	cli_credentials_parse_file(PyCredentials_AsCliCredentials(self), newval, obt);
	Py_RETURN_NONE;
}

static PyObject *py_cli_credentials_set_password_will_be_nt_hash(PyObject *self, PyObject *args)
{
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	PyObject *py_val = NULL;
	bool val = false;

	if (!PyArg_ParseTuple(args, "O!", &PyBool_Type, &py_val)) {
		return NULL;
	}
	val = PyObject_IsTrue(py_val);

	cli_credentials_set_password_will_be_nt_hash(creds, val);
	Py_RETURN_NONE;
}

static PyObject *py_creds_get_nt_hash(PyObject *self, PyObject *unused)
{
	PyObject *ret;
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	struct samr_Password *ntpw = cli_credentials_get_nt_hash(creds, creds);

	ret = PyString_FromStringAndSize(discard_const_p(char, ntpw->hash), 16);
	TALLOC_FREE(ntpw);
	return ret;
}

static PyObject *py_creds_get_kerberos_state(PyObject *self, PyObject *unused)
{
	int state = cli_credentials_get_kerberos_state(PyCredentials_AsCliCredentials(self));
	return PyInt_FromLong(state);
}

static PyObject *py_creds_set_kerberos_state(PyObject *self, PyObject *args)
{
	int state;
	if (!PyArg_ParseTuple(args, "i", &state))
		return NULL;

	cli_credentials_set_kerberos_state(PyCredentials_AsCliCredentials(self), state);
	Py_RETURN_NONE;
}

static PyObject *py_creds_set_krb_forwardable(PyObject *self, PyObject *args)
{
	int state;
	if (!PyArg_ParseTuple(args, "i", &state))
		return NULL;

	cli_credentials_set_krb_forwardable(PyCredentials_AsCliCredentials(self), state);
	Py_RETURN_NONE;
}


static PyObject *py_creds_get_forced_sasl_mech(PyObject *self, PyObject *unused)
{
	return PyString_FromStringOrNULL(cli_credentials_get_forced_sasl_mech(PyCredentials_AsCliCredentials(self)));
}

static PyObject *py_creds_set_forced_sasl_mech(PyObject *self, PyObject *args)
{
	char *newval;
	enum credentials_obtained obt = CRED_SPECIFIED;
	int _obt = obt;

	if (!PyArg_ParseTuple(args, "s", &newval)) {
		return NULL;
	}
	obt = _obt;

	cli_credentials_set_forced_sasl_mech(PyCredentials_AsCliCredentials(self), newval);
	Py_RETURN_NONE;
}

static PyObject *py_creds_guess(PyObject *self, PyObject *args)
{
	PyObject *py_lp_ctx = Py_None;
	struct loadparm_context *lp_ctx;
	TALLOC_CTX *mem_ctx;
	struct cli_credentials *creds;

	creds = PyCredentials_AsCliCredentials(self);

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

	cli_credentials_guess(creds, lp_ctx);

	talloc_free(mem_ctx);

	Py_RETURN_NONE;
}

static PyObject *py_creds_set_machine_account(PyObject *self, PyObject *args)
{
	PyObject *py_lp_ctx = Py_None;
	struct loadparm_context *lp_ctx;
	NTSTATUS status;
	struct cli_credentials *creds;
	TALLOC_CTX *mem_ctx;

	creds = PyCredentials_AsCliCredentials(self);

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

	status = cli_credentials_set_machine_account(creds, lp_ctx);
	talloc_free(mem_ctx);

	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	Py_RETURN_NONE;
}

static PyObject *PyCredentialCacheContainer_from_ccache_container(struct ccache_container *ccc)
{
	return pytalloc_reference(&PyCredentialCacheContainer, ccc);
}


static PyObject *py_creds_get_named_ccache(PyObject *self, PyObject *args)
{
	PyObject *py_lp_ctx = Py_None;
	char *ccache_name;
	struct loadparm_context *lp_ctx;
	struct ccache_container *ccc;
	struct tevent_context *event_ctx;
	int ret;
	const char *error_string;
	struct cli_credentials *creds;
	TALLOC_CTX *mem_ctx;

	creds = PyCredentials_AsCliCredentials(self);

	if (!PyArg_ParseTuple(args, "|Os", &py_lp_ctx, &ccache_name))
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

	event_ctx = samba_tevent_context_init(mem_ctx);

	ret = cli_credentials_get_named_ccache(creds, event_ctx, lp_ctx,
					       ccache_name, &ccc, &error_string);
	talloc_unlink(mem_ctx, lp_ctx);
	if (ret == 0) {
		talloc_steal(ccc, event_ctx);
		talloc_free(mem_ctx);
		return PyCredentialCacheContainer_from_ccache_container(ccc);
	}

	PyErr_SetString(PyExc_RuntimeError, error_string?error_string:"NULL");

	talloc_free(mem_ctx);
	return NULL;
}

static PyObject *py_creds_set_gensec_features(PyObject *self, PyObject *args)
{
	unsigned int gensec_features;

	if (!PyArg_ParseTuple(args, "I", &gensec_features))
		return NULL;

	cli_credentials_set_gensec_features(PyCredentials_AsCliCredentials(self), gensec_features);

	Py_RETURN_NONE;
}

static PyObject *py_creds_get_gensec_features(PyObject *self, PyObject *args)
{
	unsigned int gensec_features;

	gensec_features = cli_credentials_get_gensec_features(PyCredentials_AsCliCredentials(self));
	return PyInt_FromLong(gensec_features);
}


static PyMethodDef py_creds_methods[] = {
	{ "get_username", py_creds_get_username, METH_NOARGS,
		"S.get_username() -> username\nObtain username." },
	{ "set_username", py_creds_set_username, METH_VARARGS,
		"S.set_username(name[, credentials.SPECIFIED]) -> None\n"
		"Change username." },
	{ "get_principal", py_creds_get_principal, METH_NOARGS,
		"S.get_principal() -> user@realm\nObtain user principal." },
	{ "set_principal", py_creds_set_principal, METH_VARARGS,
		"S.set_principal(name[, credentials.SPECIFIED]) -> None\n"
		"Change principal." },
	{ "get_password", py_creds_get_password, METH_NOARGS,
		"S.get_password() -> password\n"
		"Obtain password." },
	{ "get_ntlm_username_domain", py_creds_get_ntlm_username_domain, METH_NOARGS,
		"S.get_ntlm_username_domain() -> (domain, username)\n"
		"Obtain NTLM username and domain, split up either as (DOMAIN, user) or (\"\", \"user@realm\")." },
	{ "set_password", py_creds_set_password, METH_VARARGS,
		"S.set_password(password[, credentials.SPECIFIED]) -> None\n"
		"Change password." },
	{ "set_utf16_password", py_creds_set_utf16_password, METH_VARARGS,
		"S.set_utf16_password(password[, credentials.SPECIFIED]) -> None\n"
		"Change password." },
	{ "get_old_password", py_creds_get_old_password, METH_NOARGS,
		"S.get_old_password() -> password\n"
		"Obtain old password." },
	{ "set_old_password", py_creds_set_old_password, METH_VARARGS,
		"S.set_old_password(password[, credentials.SPECIFIED]) -> None\n"
		"Change old password." },
	{ "set_old_utf16_password", py_creds_set_old_utf16_password, METH_VARARGS,
		"S.set_old_utf16_password(password[, credentials.SPECIFIED]) -> None\n"
		"Change old password." },
	{ "get_domain", py_creds_get_domain, METH_NOARGS,
		"S.get_domain() -> domain\n"
		"Obtain domain name." },
	{ "set_domain", py_creds_set_domain, METH_VARARGS,
		"S.set_domain(domain[, credentials.SPECIFIED]) -> None\n"
		"Change domain name." },
	{ "get_realm", py_creds_get_realm, METH_NOARGS,
		"S.get_realm() -> realm\n"
		"Obtain realm name." },
	{ "set_realm", py_creds_set_realm, METH_VARARGS,
		"S.set_realm(realm[, credentials.SPECIFIED]) -> None\n"
		"Change realm name." },
	{ "get_bind_dn", py_creds_get_bind_dn, METH_NOARGS,
		"S.get_bind_dn() -> bind dn\n"
		"Obtain bind DN." },
	{ "set_bind_dn", py_creds_set_bind_dn, METH_VARARGS,
		"S.set_bind_dn(bind_dn) -> None\n"
		"Change bind DN." },
	{ "is_anonymous", py_creds_is_anonymous, METH_NOARGS,
		NULL },
	{ "set_anonymous", py_creds_set_anonymous, METH_NOARGS,
        	"S.set_anonymous() -> None\n"
		"Use anonymous credentials." },
	{ "get_workstation", py_creds_get_workstation, METH_NOARGS,
		NULL },
	{ "set_workstation", py_creds_set_workstation, METH_VARARGS,
		NULL },
	{ "authentication_requested", py_creds_authentication_requested, METH_NOARGS,
		NULL },
	{ "wrong_password", py_creds_wrong_password, METH_NOARGS,
		"S.wrong_password() -> bool\n"
		"Indicate the returned password was incorrect." },
	{ "set_cmdline_callbacks", py_creds_set_cmdline_callbacks, METH_NOARGS,
		"S.set_cmdline_callbacks() -> bool\n"
		"Use command-line to obtain credentials not explicitly set." },
	{ "parse_string", py_creds_parse_string, METH_VARARGS,
		"S.parse_string(text[, credentials.SPECIFIED]) -> None\n"
		"Parse credentials string." },
	{ "parse_file", py_creds_parse_file, METH_VARARGS,
		"S.parse_file(filename[, credentials.SPECIFIED]) -> None\n"
		"Parse credentials file." },
	{ "set_password_will_be_nt_hash",
		py_cli_credentials_set_password_will_be_nt_hash, METH_VARARGS,
		"S.set_password_will_be_nt_hash(bool) -> None\n"
		"Alters the behaviour of S.set_password() "
		"to expect the NTHASH as hexstring." },
	{ "get_nt_hash", py_creds_get_nt_hash, METH_NOARGS,
		NULL },
	{ "get_kerberos_state", py_creds_get_kerberos_state, METH_NOARGS,
		NULL },
	{ "set_kerberos_state", py_creds_set_kerberos_state, METH_VARARGS,
		NULL },
	{ "set_krb_forwardable", py_creds_set_krb_forwardable, METH_VARARGS,
		NULL },
	{ "guess", py_creds_guess, METH_VARARGS, NULL },
	{ "set_machine_account", py_creds_set_machine_account, METH_VARARGS, NULL },
	{ "get_named_ccache", py_creds_get_named_ccache, METH_VARARGS, NULL },
	{ "set_gensec_features", py_creds_set_gensec_features, METH_VARARGS, NULL },
	{ "get_gensec_features", py_creds_get_gensec_features, METH_NOARGS, NULL },
	{ "get_forced_sasl_mech", py_creds_get_forced_sasl_mech, METH_NOARGS,
		"S.get_forced_sasl_mech() -> SASL mechanism\nObtain forced SASL mechanism." },
	{ "set_forced_sasl_mech", py_creds_set_forced_sasl_mech, METH_VARARGS,
		"S.set_forced_sasl_mech(name) -> None\n"
		"Set forced SASL mechanism." },
	{ NULL }
};

PyTypeObject PyCredentials = {
	.tp_name = "credentials.Credentials",
	.tp_new = py_creds_new,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_methods = py_creds_methods,
};


PyTypeObject PyCredentialCacheContainer = {
	.tp_name = "credentials.CredentialCacheContainer",
	.tp_flags = Py_TPFLAGS_DEFAULT,
};

void initcredentials(void)
{
	PyObject *m;
	if (pytalloc_BaseObject_PyType_Ready(&PyCredentials) < 0)
		return;

	if (pytalloc_BaseObject_PyType_Ready(&PyCredentialCacheContainer) < 0)
		return;

	m = Py_InitModule3("credentials", NULL, "Credentials management.");
	if (m == NULL)
		return;

	PyModule_AddObject(m, "UNINITIALISED", PyInt_FromLong(CRED_UNINITIALISED));
	PyModule_AddObject(m, "CALLBACK", PyInt_FromLong(CRED_CALLBACK));
	PyModule_AddObject(m, "GUESS_ENV", PyInt_FromLong(CRED_GUESS_ENV));
	PyModule_AddObject(m, "GUESS_FILE", PyInt_FromLong(CRED_GUESS_FILE));
	PyModule_AddObject(m, "CALLBACK_RESULT", PyInt_FromLong(CRED_CALLBACK_RESULT));
	PyModule_AddObject(m, "SPECIFIED", PyInt_FromLong(CRED_SPECIFIED));

	PyModule_AddObject(m, "AUTO_USE_KERBEROS", PyInt_FromLong(CRED_AUTO_USE_KERBEROS));
	PyModule_AddObject(m, "DONT_USE_KERBEROS", PyInt_FromLong(CRED_DONT_USE_KERBEROS));
	PyModule_AddObject(m, "MUST_USE_KERBEROS", PyInt_FromLong(CRED_MUST_USE_KERBEROS));

	PyModule_AddObject(m, "AUTO_KRB_FORWARDABLE",  PyInt_FromLong(CRED_AUTO_KRB_FORWARDABLE));
	PyModule_AddObject(m, "NO_KRB_FORWARDABLE",    PyInt_FromLong(CRED_NO_KRB_FORWARDABLE));
	PyModule_AddObject(m, "FORCE_KRB_FORWARDABLE", PyInt_FromLong(CRED_FORCE_KRB_FORWARDABLE));

	Py_INCREF(&PyCredentials);
	PyModule_AddObject(m, "Credentials", (PyObject *)&PyCredentials);
	Py_INCREF(&PyCredentialCacheContainer);
	PyModule_AddObject(m, "CredentialCacheContainer", (PyObject *)&PyCredentialCacheContainer);
}
