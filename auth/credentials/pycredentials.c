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
#include "python/py3compat.h"
#include "includes.h"
#include "python/modules.h"
#include "pycredentials.h"
#include "param/param.h"
#include "lib/cmdline/credentials.h"
#include "auth/credentials/credentials_internal.h"
#include "librpc/gen_ndr/samr.h" /* for struct samr_Password */
#include "librpc/gen_ndr/netlogon.h"
#include "libcli/util/pyerrors.h"
#include "libcli/auth/libcli_auth.h"
#include "param/pyparam.h"
#include <tevent.h>
#include "libcli/auth/libcli_auth.h"
#include "auth/credentials/credentials_internal.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"

void initcredentials(void);

static PyObject *py_creds_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	return pytalloc_steal(type, cli_credentials_init(NULL));
}

static PyObject *py_creds_get_username(PyObject *self, PyObject *unused)
{
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}
	return PyString_FromStringOrNULL(cli_credentials_get_username(creds));
}

static PyObject *py_creds_set_username(PyObject *self, PyObject *args)
{
	char *newval;
	enum credentials_obtained obt = CRED_SPECIFIED;
	int _obt = obt;
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "s|i", &newval, &_obt)) {
		return NULL;
	}
	obt = _obt;

	return PyBool_FromLong(cli_credentials_set_username(creds, newval, obt));
}

static PyObject *py_creds_get_ntlm_username_domain(PyObject *self, PyObject *unused)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *user = NULL;
	const char *domain = NULL;
	PyObject *ret = NULL;
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}
	cli_credentials_get_ntlm_username_domain(creds,
						 frame, &user, &domain);
	ret = Py_BuildValue("(ss)",
			    user,
			    domain);

	TALLOC_FREE(frame);
	return ret;
}

static PyObject *py_creds_get_ntlm_response(PyObject *self, PyObject *args, PyObject *kwargs)
{
	TALLOC_CTX *frame = talloc_stackframe();
	PyObject *ret = NULL;
	int flags;
	struct timeval tv_now;
	NTTIME server_timestamp;
	DATA_BLOB challenge = data_blob_null;
	DATA_BLOB target_info = data_blob_null;
	NTSTATUS status;
	DATA_BLOB lm_response = data_blob_null;
	DATA_BLOB nt_response = data_blob_null;
	DATA_BLOB lm_session_key = data_blob_null;
	DATA_BLOB nt_session_key = data_blob_null;
	const char *kwnames[] = { "flags", "challenge",
				  "target_info",
				  NULL };
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}

	tv_now = timeval_current();
	server_timestamp = timeval_to_nttime(&tv_now);

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "is#|s#",
					 discard_const_p(char *, kwnames),
					 &flags,
					 &challenge.data,
					 &challenge.length,
					 &target_info.data,
					 &target_info.length)) {
		return NULL;
	}

	status = cli_credentials_get_ntlm_response(creds,
						   frame, &flags,
						   challenge,
						   &server_timestamp,
						   target_info,
						   &lm_response, &nt_response,
						   &lm_session_key, &nt_session_key);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	ret = Py_BuildValue("{sis" PYARG_BYTES_LEN "s" PYARG_BYTES_LEN
			            "s" PYARG_BYTES_LEN "s" PYARG_BYTES_LEN "}",
			    "flags", flags,
			    "lm_response",
			    (const char *)lm_response.data, lm_response.length,
			    "nt_response",
			    (const char *)nt_response.data, nt_response.length,
			    "lm_session_key",
			    (const char *)lm_session_key.data, lm_session_key.length,
			    "nt_session_key",
			    (const char *)nt_session_key.data, nt_session_key.length);
	TALLOC_FREE(frame);
	return ret;
}

static PyObject *py_creds_get_principal(PyObject *self, PyObject *unused)
{
	TALLOC_CTX *frame = talloc_stackframe();
	PyObject *ret = NULL;
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}
	ret = PyString_FromStringOrNULL(cli_credentials_get_principal(creds, frame));
	TALLOC_FREE(frame);
	return ret;
}

static PyObject *py_creds_set_principal(PyObject *self, PyObject *args)
{
	char *newval;
	enum credentials_obtained obt = CRED_SPECIFIED;
	int _obt = obt;
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "s|i", &newval, &_obt)) {
		return NULL;
	}
	obt = _obt;

	return PyBool_FromLong(cli_credentials_set_principal(creds, newval, obt));
}

static PyObject *py_creds_get_password(PyObject *self, PyObject *unused)
{
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}
	return PyString_FromStringOrNULL(cli_credentials_get_password(creds));
}

static PyObject *py_creds_set_password(PyObject *self, PyObject *args)
{
	const char *newval = NULL;
	enum credentials_obtained obt = CRED_SPECIFIED;
	int _obt = obt;
	PyObject *result = NULL;
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, PYARG_STR_UNI"|i", "utf8", &newval, &_obt)) {
		return NULL;
	}
	obt = _obt;

	result = PyBool_FromLong(cli_credentials_set_password(creds, newval, obt));
	PyMem_Free(discard_const_p(void*, newval));
	return result;
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
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}

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

	ok = cli_credentials_set_utf16_password(creds,
						&blob, obt);

	return PyBool_FromLong(ok);
}

static PyObject *py_creds_get_old_password(PyObject *self, PyObject *unused)
{
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}
	return PyString_FromStringOrNULL(cli_credentials_get_old_password(creds));
}

static PyObject *py_creds_set_old_password(PyObject *self, PyObject *args)
{
	char *oldval;
	enum credentials_obtained obt = CRED_SPECIFIED;
	int _obt = obt;
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "s|i", &oldval, &_obt)) {
		return NULL;
	}
	obt = _obt;

	return PyBool_FromLong(cli_credentials_set_old_password(creds, oldval, obt));
}

static PyObject *py_creds_set_old_utf16_password(PyObject *self, PyObject *args)
{
	PyObject *oldval = NULL;
	DATA_BLOB blob = data_blob_null;
	Py_ssize_t size =  0;
	int result;
	bool ok;
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "O", &oldval)) {
		return NULL;
	}

	result = PyBytes_AsStringAndSize(oldval, (char **)&blob.data, &size);
	if (result != 0) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to convert passed value to Bytes");
		return NULL;
	}
	blob.length = size;

	ok = cli_credentials_set_old_utf16_password(creds,
						    &blob);

	return PyBool_FromLong(ok);
}

static PyObject *py_creds_get_domain(PyObject *self, PyObject *unused)
{
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}
	return PyString_FromStringOrNULL(cli_credentials_get_domain(creds));
}

static PyObject *py_creds_set_domain(PyObject *self, PyObject *args)
{
	char *newval;
	enum credentials_obtained obt = CRED_SPECIFIED;
	int _obt = obt;
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "s|i", &newval, &_obt)) {
		return NULL;
	}
	obt = _obt;

	return PyBool_FromLong(cli_credentials_set_domain(creds, newval, obt));
}

static PyObject *py_creds_get_realm(PyObject *self, PyObject *unused)
{
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}
	return PyString_FromStringOrNULL(cli_credentials_get_realm(creds));
}

static PyObject *py_creds_set_realm(PyObject *self, PyObject *args)
{
	char *newval;
	enum credentials_obtained obt = CRED_SPECIFIED;
	int _obt = obt;
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "s|i", &newval, &_obt)) {
		return NULL;
	}
	obt = _obt;

	return PyBool_FromLong(cli_credentials_set_realm(creds, newval, obt));
}

static PyObject *py_creds_get_bind_dn(PyObject *self, PyObject *unused)
{
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}
	return PyString_FromStringOrNULL(cli_credentials_get_bind_dn(creds));
}

static PyObject *py_creds_set_bind_dn(PyObject *self, PyObject *args)
{
	char *newval;
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}
	if (!PyArg_ParseTuple(args, "s", &newval))
		return NULL;

	return PyBool_FromLong(cli_credentials_set_bind_dn(creds, newval));
}

static PyObject *py_creds_get_workstation(PyObject *self, PyObject *unused)
{
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}
	return PyString_FromStringOrNULL(cli_credentials_get_workstation(creds));
}

static PyObject *py_creds_set_workstation(PyObject *self, PyObject *args)
{
	char *newval;
	enum credentials_obtained obt = CRED_SPECIFIED;
	int _obt = obt;
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "s|i", &newval, &_obt)) {
		return NULL;
	}
	obt = _obt;

	return PyBool_FromLong(cli_credentials_set_workstation(creds, newval, obt));
}

static PyObject *py_creds_is_anonymous(PyObject *self, PyObject *unused)
{
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}
	return PyBool_FromLong(cli_credentials_is_anonymous(creds));
}

static PyObject *py_creds_set_anonymous(PyObject *self, PyObject *unused)
{
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}
	cli_credentials_set_anonymous(creds);
	Py_RETURN_NONE;
}

static PyObject *py_creds_authentication_requested(PyObject *self, PyObject *unused)
{
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}
        return PyBool_FromLong(cli_credentials_authentication_requested(creds));
}

static PyObject *py_creds_wrong_password(PyObject *self, PyObject *unused)
{
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}
         return PyBool_FromLong(cli_credentials_wrong_password(creds));
}

static PyObject *py_creds_set_cmdline_callbacks(PyObject *self, PyObject *unused)
{
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}
        return PyBool_FromLong(cli_credentials_set_cmdline_callbacks(creds));
}

static PyObject *py_creds_parse_string(PyObject *self, PyObject *args)
{
	char *newval;
	enum credentials_obtained obt = CRED_SPECIFIED;
	int _obt = obt;
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "s|i", &newval, &_obt)) {
		return NULL;
	}
	obt = _obt;

	cli_credentials_parse_string(creds, newval, obt);
	Py_RETURN_NONE;
}

static PyObject *py_creds_parse_file(PyObject *self, PyObject *args)
{
	char *newval;
	enum credentials_obtained obt = CRED_SPECIFIED;
	int _obt = obt;
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "s|i", &newval, &_obt)) {
		return NULL;
	}
	obt = _obt;

	cli_credentials_parse_file(creds, newval, obt);
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
	struct samr_Password *ntpw = NULL;
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}
	ntpw = cli_credentials_get_nt_hash(creds, creds);

	ret = PyBytes_FromStringAndSize(discard_const_p(char, ntpw->hash), 16);
	TALLOC_FREE(ntpw);
	return ret;
}

static PyObject *py_creds_get_kerberos_state(PyObject *self, PyObject *unused)
{
	int state;
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}
	state = cli_credentials_get_kerberos_state(creds);
	return PyLong_FromLong(state);
}

static PyObject *py_creds_set_kerberos_state(PyObject *self, PyObject *args)
{
	int state;
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}
	if (!PyArg_ParseTuple(args, "i", &state))
		return NULL;

	cli_credentials_set_kerberos_state(creds, state);
	Py_RETURN_NONE;
}

static PyObject *py_creds_set_krb_forwardable(PyObject *self, PyObject *args)
{
	int state;
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}
	if (!PyArg_ParseTuple(args, "i", &state))
		return NULL;

	cli_credentials_set_krb_forwardable(creds, state);
	Py_RETURN_NONE;
}


static PyObject *py_creds_get_forced_sasl_mech(PyObject *self, PyObject *unused)
{
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}
	return PyString_FromStringOrNULL(cli_credentials_get_forced_sasl_mech(creds));
}

static PyObject *py_creds_set_forced_sasl_mech(PyObject *self, PyObject *args)
{
	char *newval;
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "s", &newval)) {
		return NULL;
	}

	cli_credentials_set_forced_sasl_mech(creds, newval);
	Py_RETURN_NONE;
}

static PyObject *py_creds_guess(PyObject *self, PyObject *args)
{
	PyObject *py_lp_ctx = Py_None;
	struct loadparm_context *lp_ctx;
	TALLOC_CTX *mem_ctx;
	struct cli_credentials *creds;

	creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}

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
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}

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
	char *ccache_name = NULL;
	struct loadparm_context *lp_ctx;
	struct ccache_container *ccc;
	struct tevent_context *event_ctx;
	int ret;
	const char *error_string;
	struct cli_credentials *creds;
	TALLOC_CTX *mem_ctx;

	creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}

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

static PyObject *py_creds_set_named_ccache(PyObject *self, PyObject *args)
{
	struct loadparm_context *lp_ctx = NULL;
	enum credentials_obtained obt = CRED_SPECIFIED;
	const char *error_string = NULL;
	TALLOC_CTX *mem_ctx = NULL;
	char *newval = NULL;
	PyObject *py_lp_ctx = Py_None;
	int _obt = obt;
	int ret;
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "s|iO", &newval, &_obt, &py_lp_ctx))
		return NULL;
	obt = _obt;

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

	ret = cli_credentials_set_ccache(creds,
					 lp_ctx,
					 newval, obt,
					 &error_string);

	if (ret != 0) {
		PyErr_SetString(PyExc_RuntimeError,
				error_string != NULL ? error_string : "NULL");
		talloc_free(mem_ctx);
		return NULL;
	}

	talloc_free(mem_ctx);
	Py_RETURN_NONE;
}

static PyObject *py_creds_set_gensec_features(PyObject *self, PyObject *args)
{
	unsigned int gensec_features;
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "I", &gensec_features))
		return NULL;

	cli_credentials_set_gensec_features(creds, gensec_features);

	Py_RETURN_NONE;
}

static PyObject *py_creds_get_gensec_features(PyObject *self, PyObject *args)
{
	unsigned int gensec_features;
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}

	gensec_features = cli_credentials_get_gensec_features(creds);
	return PyLong_FromLong(gensec_features);
}

static PyObject *py_creds_new_client_authenticator(PyObject *self,
						   PyObject *args)
{
	struct netr_Authenticator auth;
	struct cli_credentials *creds = NULL;
	struct netlogon_creds_CredentialState *nc = NULL;
	PyObject *ret = NULL;
	NTSTATUS status;

	creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_SetString(PyExc_RuntimeError,
				"Failed to get credentials from python");
		return NULL;
	}

	nc = creds->netlogon_creds;
	if (nc == NULL) {
		PyErr_SetString(PyExc_ValueError,
				"No netlogon credentials cannot make "
				"client authenticator");
		return NULL;
	}

	status = netlogon_creds_client_authenticator(nc, &auth);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetString(PyExc_ValueError,
				"Failed to create client authenticator");
		return NULL;
	}

	ret = Py_BuildValue("{s"PYARG_BYTES_LEN"si}",
			    "credential",
			    (const char *) &auth.cred, sizeof(auth.cred),
			    "timestamp", auth.timestamp);
	return ret;
}

static PyObject *py_creds_set_secure_channel_type(PyObject *self, PyObject *args)
{
	unsigned int channel_type;
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "I", &channel_type))
		return NULL;

	cli_credentials_set_secure_channel_type(
		creds,
		channel_type);

	Py_RETURN_NONE;
}

static PyObject *py_creds_get_secure_channel_type(PyObject *self, PyObject *args)
{
	enum netr_SchannelType channel_type = SEC_CHAN_NULL;
	struct cli_credentials *creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}

	channel_type = cli_credentials_get_secure_channel_type(creds);

	return PyLong_FromLong(channel_type);
}

static PyObject *py_creds_encrypt_netr_crypt_password(PyObject *self,
						      PyObject *args)
{
	DATA_BLOB data = data_blob_null;
	struct cli_credentials    *creds  = NULL;
	struct netr_CryptPassword *pwd    = NULL;
	NTSTATUS status;
	PyObject *py_cp = Py_None;

	creds = PyCredentials_AsCliCredentials(self);
	if (creds == NULL) {
		PyErr_Format(PyExc_TypeError, "Credentials expected");
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "O", &py_cp)) {
		return NULL;
	}

	pwd = pytalloc_get_type(py_cp, struct netr_CryptPassword);
	if (pwd == NULL) {
		/* pytalloc_get_type sets TypeError */
		return NULL;
	}
	data.length = sizeof(struct netr_CryptPassword);
	data.data   = (uint8_t *)pwd;
	status = netlogon_creds_session_encrypt(creds->netlogon_creds, data);

	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	Py_RETURN_NONE;
}

static PyMethodDef py_creds_methods[] = {
	{
		.ml_name  = "get_username",
		.ml_meth  = py_creds_get_username,
		.ml_flags = METH_NOARGS,
		.ml_doc   = "S.get_username() -> username\nObtain username.",
	},
	{
		.ml_name  = "set_username",
		.ml_meth  = py_creds_set_username,
		.ml_flags = METH_VARARGS,
		.ml_doc   = "S.set_username(name[, credentials.SPECIFIED]) -> None\n"
			    "Change username.",
	},
	{
		.ml_name  = "get_principal",
		.ml_meth  = py_creds_get_principal,
		.ml_flags = METH_NOARGS,
		.ml_doc   = "S.get_principal() -> user@realm\nObtain user principal.",
	},
	{
		.ml_name  = "set_principal",
		.ml_meth  = py_creds_set_principal,
		.ml_flags = METH_VARARGS,
		.ml_doc   = "S.set_principal(name[, credentials.SPECIFIED]) -> None\n"
			    "Change principal.",
	},
	{
		.ml_name  = "get_password",
		.ml_meth  = py_creds_get_password,
		.ml_flags = METH_NOARGS,
		.ml_doc   = "S.get_password() -> password\n"
			    "Obtain password.",
	},
	{
		.ml_name  = "get_ntlm_username_domain",
		.ml_meth  = py_creds_get_ntlm_username_domain,
		.ml_flags = METH_NOARGS,
		.ml_doc   = "S.get_ntlm_username_domain() -> (domain, username)\n"
			    "Obtain NTLM username and domain, split up either as (DOMAIN, user) or (\"\", \"user@realm\").",
	},
	{
		.ml_name  = "get_ntlm_response",
		.ml_meth  = PY_DISCARD_FUNC_SIG(PyCFunction,
						py_creds_get_ntlm_response),
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc   = "S.get_ntlm_response"
		            "(flags, challenge[, target_info]) -> "
			    "(flags, lm_response, nt_response, lm_session_key, nt_session_key)\n"
			    "Obtain LM or NTLM response.",
	},
	{
		.ml_name  = "set_password",
		.ml_meth  = py_creds_set_password,
		.ml_flags = METH_VARARGS,
		.ml_doc   = "S.set_password(password[, credentials.SPECIFIED]) -> None\n"
			    "Change password.",
	},
	{
		.ml_name  = "set_utf16_password",
		.ml_meth  = py_creds_set_utf16_password,
		.ml_flags = METH_VARARGS,
		.ml_doc   = "S.set_utf16_password(password[, credentials.SPECIFIED]) -> None\n"
			    "Change password.",
	},
	{
		.ml_name  = "get_old_password",
		.ml_meth  = py_creds_get_old_password,
		.ml_flags = METH_NOARGS,
		.ml_doc   = "S.get_old_password() -> password\n"
			    "Obtain old password.",
	},
	{
		.ml_name  = "set_old_password",
		.ml_meth  = py_creds_set_old_password,
		.ml_flags = METH_VARARGS,
		.ml_doc   = "S.set_old_password(password[, credentials.SPECIFIED]) -> None\n"
			    "Change old password.",
	},
	{
		.ml_name  = "set_old_utf16_password",
		.ml_meth  = py_creds_set_old_utf16_password,
		.ml_flags = METH_VARARGS,
		.ml_doc   = "S.set_old_utf16_password(password[, credentials.SPECIFIED]) -> None\n"
			    "Change old password.",
	},
	{
		.ml_name  = "get_domain",
		.ml_meth  = py_creds_get_domain,
		.ml_flags = METH_NOARGS,
		.ml_doc   = "S.get_domain() -> domain\n"
			    "Obtain domain name.",
	},
	{
		.ml_name  = "set_domain",
		.ml_meth  = py_creds_set_domain,
		.ml_flags = METH_VARARGS,
		.ml_doc   = "S.set_domain(domain[, credentials.SPECIFIED]) -> None\n"
			    "Change domain name.",
	},
	{
		.ml_name  = "get_realm",
		.ml_meth  = py_creds_get_realm,
		.ml_flags = METH_NOARGS,
		.ml_doc   = "S.get_realm() -> realm\n"
			    "Obtain realm name.",
	},
	{
		.ml_name  = "set_realm",
		.ml_meth  = py_creds_set_realm,
		.ml_flags = METH_VARARGS,
		.ml_doc   = "S.set_realm(realm[, credentials.SPECIFIED]) -> None\n"
			    "Change realm name.",
	},
	{
		.ml_name  = "get_bind_dn",
		.ml_meth  = py_creds_get_bind_dn,
		.ml_flags = METH_NOARGS,
		.ml_doc   = "S.get_bind_dn() -> bind dn\n"
			    "Obtain bind DN.",
	},
	{
		.ml_name  = "set_bind_dn",
		.ml_meth  = py_creds_set_bind_dn,
		.ml_flags = METH_VARARGS,
		.ml_doc   = "S.set_bind_dn(bind_dn) -> None\n"
			    "Change bind DN.",
	},
	{
		.ml_name  = "is_anonymous",
		.ml_meth  = py_creds_is_anonymous,
		.ml_flags = METH_NOARGS,
	},
	{
		.ml_name  = "set_anonymous",
		.ml_meth  = py_creds_set_anonymous,
		.ml_flags = METH_NOARGS,
		.ml_doc   = "S.set_anonymous() -> None\n"
			    "Use anonymous credentials.",
	},
	{
		.ml_name  = "get_workstation",
		.ml_meth  = py_creds_get_workstation,
		.ml_flags = METH_NOARGS,
	},
	{
		.ml_name  = "set_workstation",
		.ml_meth  = py_creds_set_workstation,
		.ml_flags = METH_VARARGS,
	},
	{
		.ml_name  = "authentication_requested",
		.ml_meth  = py_creds_authentication_requested,
		.ml_flags = METH_NOARGS,
	},
	{
		.ml_name  = "wrong_password",
		.ml_meth  = py_creds_wrong_password,
		.ml_flags = METH_NOARGS,
		.ml_doc   = "S.wrong_password() -> bool\n"
			    "Indicate the returned password was incorrect.",
	},
	{
		.ml_name  = "set_cmdline_callbacks",
		.ml_meth  = py_creds_set_cmdline_callbacks,
		.ml_flags = METH_NOARGS,
		.ml_doc   = "S.set_cmdline_callbacks() -> bool\n"
			    "Use command-line to obtain credentials not explicitly set.",
	},
	{
		.ml_name  = "parse_string",
		.ml_meth  = py_creds_parse_string,
		.ml_flags = METH_VARARGS,
		.ml_doc   = "S.parse_string(text[, credentials.SPECIFIED]) -> None\n"
			    "Parse credentials string.",
	},
	{
		.ml_name  = "parse_file",
		.ml_meth  = py_creds_parse_file,
		.ml_flags = METH_VARARGS,
		.ml_doc   = "S.parse_file(filename[, credentials.SPECIFIED]) -> None\n"
			    "Parse credentials file.",
	},
	{
		.ml_name  = "set_password_will_be_nt_hash",
		.ml_meth  = py_cli_credentials_set_password_will_be_nt_hash,
		.ml_flags = METH_VARARGS,
		.ml_doc   = "S.set_password_will_be_nt_hash(bool) -> None\n"
			    "Alters the behaviour of S.set_password() "
			    "to expect the NTHASH as hexstring.",
	},
	{
		.ml_name  = "get_nt_hash",
		.ml_meth  = py_creds_get_nt_hash,
		.ml_flags = METH_NOARGS,
	},
	{
		.ml_name  = "get_kerberos_state",
		.ml_meth  = py_creds_get_kerberos_state,
		.ml_flags = METH_NOARGS,
	},
	{
		.ml_name  = "set_kerberos_state",
		.ml_meth  = py_creds_set_kerberos_state,
		.ml_flags = METH_VARARGS,
	},
	{
		.ml_name  = "set_krb_forwardable",
		.ml_meth  = py_creds_set_krb_forwardable,
		.ml_flags = METH_VARARGS,
	},
	{
		.ml_name  = "guess",
		.ml_meth  = py_creds_guess,
		.ml_flags = METH_VARARGS,
	},
	{
		.ml_name  = "set_machine_account",
		.ml_meth  = py_creds_set_machine_account,
		.ml_flags = METH_VARARGS,
	},
	{
		.ml_name  = "get_named_ccache",
		.ml_meth  = py_creds_get_named_ccache,
		.ml_flags = METH_VARARGS,
	},
	{
		.ml_name  = "set_named_ccache",
		.ml_meth  = py_creds_set_named_ccache,
		.ml_flags = METH_VARARGS,
		.ml_doc   = "S.set_named_ccache(krb5_ccache_name, obtained, lp) -> None\n"
			    "Set credentials to KRB5 Credentials Cache (by name).",
	},
	{
		.ml_name  = "set_gensec_features",
		.ml_meth  = py_creds_set_gensec_features,
		.ml_flags = METH_VARARGS,
	},
	{
		.ml_name  = "get_gensec_features",
		.ml_meth  = py_creds_get_gensec_features,
		.ml_flags = METH_NOARGS,
	},
	{
		.ml_name  = "get_forced_sasl_mech",
		.ml_meth  = py_creds_get_forced_sasl_mech,
		.ml_flags = METH_NOARGS,
		.ml_doc   = "S.get_forced_sasl_mech() -> SASL mechanism\nObtain forced SASL mechanism.",
	},
	{
		.ml_name  = "set_forced_sasl_mech",
		.ml_meth  = py_creds_set_forced_sasl_mech,
		.ml_flags = METH_VARARGS,
		.ml_doc   = "S.set_forced_sasl_mech(name) -> None\n"
			    "Set forced SASL mechanism.",
	},
	{
		.ml_name  = "new_client_authenticator",
		.ml_meth  = py_creds_new_client_authenticator,
		.ml_flags = METH_NOARGS,
		.ml_doc   = "S.new_client_authenticator() -> Authenticator\n"
			    "Get a new client NETLOGON_AUTHENTICATOR"},
	{
		.ml_name  = "set_secure_channel_type",
		.ml_meth  = py_creds_set_secure_channel_type,
		.ml_flags = METH_VARARGS,
	},
	{
		.ml_name  = "get_secure_channel_type",
		.ml_meth  = py_creds_get_secure_channel_type,
		.ml_flags = METH_VARARGS,
	},
	{
		.ml_name  = "encrypt_netr_crypt_password",
		.ml_meth  = py_creds_encrypt_netr_crypt_password,
		.ml_flags = METH_VARARGS,
		.ml_doc   = "S.encrypt_netr_crypt_password(password) -> NTSTATUS\n"
			    "Encrypt the supplied password using the session key and\n"
			    "the negotiated encryption algorithm in place\n"
			    "i.e. it overwrites the original data"},
	{ .ml_name = NULL }
};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    .m_name = "credentials",
    .m_doc = "Credentials management.",
    .m_size = -1,
    .m_methods = py_creds_methods,
};

PyTypeObject PyCredentials = {
	.tp_name = "credentials.Credentials",
	.tp_new = py_creds_new,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_methods = py_creds_methods,
};

static PyObject *py_ccache_name(PyObject *self, PyObject *unused)
{
	struct ccache_container *ccc = NULL;
	char *name = NULL;
	PyObject *py_name = NULL;
	int ret;

	ccc = pytalloc_get_type(self, struct ccache_container);

	ret = krb5_cc_get_full_name(ccc->smb_krb5_context->krb5_context,
				    ccc->ccache, &name);
	if (ret == 0) {
		py_name = PyString_FromStringOrNULL(name);
		SAFE_FREE(name);
	} else {
		PyErr_SetString(PyExc_RuntimeError,
				"Failed to get ccache name");
		return NULL;
	}
	return py_name;
}

static PyMethodDef py_ccache_container_methods[] = {
	{ "get_name", py_ccache_name, METH_NOARGS,
	  "S.get_name() -> name\nObtain KRB5 credentials cache name." },
	{0}
};

PyTypeObject PyCredentialCacheContainer = {
	.tp_name = "credentials.CredentialCacheContainer",
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_methods = py_ccache_container_methods,
};

MODULE_INIT_FUNC(credentials)
{
	PyObject *m;
	if (pytalloc_BaseObject_PyType_Ready(&PyCredentials) < 0)
		return NULL;

	if (pytalloc_BaseObject_PyType_Ready(&PyCredentialCacheContainer) < 0)
		return NULL;

	m = PyModule_Create(&moduledef);
	if (m == NULL)
		return NULL;

	PyModule_AddObject(m, "UNINITIALISED", PyLong_FromLong(CRED_UNINITIALISED));
	PyModule_AddObject(m, "CALLBACK", PyLong_FromLong(CRED_CALLBACK));
	PyModule_AddObject(m, "GUESS_ENV", PyLong_FromLong(CRED_GUESS_ENV));
	PyModule_AddObject(m, "GUESS_FILE", PyLong_FromLong(CRED_GUESS_FILE));
	PyModule_AddObject(m, "CALLBACK_RESULT", PyLong_FromLong(CRED_CALLBACK_RESULT));
	PyModule_AddObject(m, "SPECIFIED", PyLong_FromLong(CRED_SPECIFIED));

	PyModule_AddObject(m, "AUTO_USE_KERBEROS", PyLong_FromLong(CRED_AUTO_USE_KERBEROS));
	PyModule_AddObject(m, "DONT_USE_KERBEROS", PyLong_FromLong(CRED_DONT_USE_KERBEROS));
	PyModule_AddObject(m, "MUST_USE_KERBEROS", PyLong_FromLong(CRED_MUST_USE_KERBEROS));

	PyModule_AddObject(m, "AUTO_KRB_FORWARDABLE",  PyLong_FromLong(CRED_AUTO_KRB_FORWARDABLE));
	PyModule_AddObject(m, "NO_KRB_FORWARDABLE",    PyLong_FromLong(CRED_NO_KRB_FORWARDABLE));
	PyModule_AddObject(m, "FORCE_KRB_FORWARDABLE", PyLong_FromLong(CRED_FORCE_KRB_FORWARDABLE));
	PyModule_AddObject(m, "CLI_CRED_NTLM2", PyLong_FromLong(CLI_CRED_NTLM2));
	PyModule_AddObject(m, "CLI_CRED_NTLMv2_AUTH", PyLong_FromLong(CLI_CRED_NTLMv2_AUTH));
	PyModule_AddObject(m, "CLI_CRED_LANMAN_AUTH", PyLong_FromLong(CLI_CRED_LANMAN_AUTH));
	PyModule_AddObject(m, "CLI_CRED_NTLM_AUTH", PyLong_FromLong(CLI_CRED_NTLM_AUTH));
	PyModule_AddObject(m, "CLI_CRED_CLEAR_AUTH", PyLong_FromLong(CLI_CRED_CLEAR_AUTH));

	Py_INCREF(&PyCredentials);
	PyModule_AddObject(m, "Credentials", (PyObject *)&PyCredentials);
	Py_INCREF(&PyCredentialCacheContainer);
	PyModule_AddObject(m, "CredentialCacheContainer", (PyObject *)&PyCredentialCacheContainer);
	return m;
}
