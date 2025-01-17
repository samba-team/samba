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

#include "lib/replace/system/python.h"
#include "python/py3compat.h"
#include "includes.h"
#include "python/modules.h"
#include "libcli/util/pyerrors.h"
#include "libcli/security/security.h"
#include "libcli/security/claims_transformation.h"
#include "source4/librpc/rpc/pyrpc_util.h"
#include "pytalloc.h"

static PyObject *py_se_access_check(PyObject *module, PyObject *args, PyObject *kwargs)
{
	NTSTATUS nt_status;
	const char * const kwnames[] = { "security_descriptor", "token", "access_desired", NULL };
	PyObject *py_sec_desc = NULL;
	PyObject *py_security_token = NULL;
	struct security_descriptor *security_descriptor;
	struct security_token *security_token;
	unsigned int access_desired; /* This is an unsigned int, not uint32_t,
				      * because that's what we need for the
				      * python PyArg_ParseTupleAndKeywords */
	uint32_t access_granted;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OOI",
					 discard_const_p(char *, kwnames),
					 &py_sec_desc, &py_security_token, &access_desired)) {
		return NULL;
	}

	security_descriptor = pytalloc_get_type(py_sec_desc, struct security_descriptor);
	if (!security_descriptor) {
		PyErr_Format(PyExc_TypeError,
			     "Expected dcerpc.security.descriptor for security_descriptor argument got  %s",
			     pytalloc_get_name(py_sec_desc));
		return NULL;
	}

	security_token = pytalloc_get_type(py_security_token, struct security_token);
	if (!security_token) {
		PyErr_Format(PyExc_TypeError,
			     "Expected dcerpc.security.token for token argument, got %s",
			     pytalloc_get_name(py_sec_desc));
		return NULL;
	}

	nt_status = se_access_check(security_descriptor, security_token, access_desired, &access_granted);
	if (!NT_STATUS_IS_OK(nt_status)) {
		PyErr_NTSTATUS_IS_ERR_RAISE(nt_status);
	}

	return PyLong_FromLong(access_granted);
}

static PyObject *py_claims_tf_policy_parse_rules(PyObject *self,
						 PyObject *args,
						 PyObject *kwargs)
{
	TALLOC_CTX *frame = NULL;
	PyObject *py_rules = NULL;
	const char * const kwnames[] = {
		"rules",
		"strip_xml",
		NULL
	};
	PyObject *py_ret = NULL;
	int strip_xml = 0;
	const char *rules_str = NULL;
	DATA_BLOB rules_blob = { .length = 0, };
	struct claims_tf_rule_set *rule_set = NULL;
	char *err_str = NULL;
	bool ok;

	ok = PyArg_ParseTupleAndKeywords(args, kwargs, "O|$p",
					 discard_const_p(char *, kwnames),
					 &py_rules,
					 &strip_xml);
	if (!ok) {
		return NULL;
	}

	rules_str = PyUnicode_AsUTF8(py_rules);
	if (rules_str == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	rules_blob = data_blob_string_const(rules_str);

	if (strip_xml != 0) {
		DATA_BLOB xml_blob = rules_blob;

		ok = claims_tf_policy_unwrap_xml(&xml_blob,
						 &rules_blob);
		if (!ok) {
			PyErr_SetString(PyExc_ValueError,
					"Invalid XML formatting");
			return NULL;
		}
	}

	frame = talloc_stackframe();

	ok = claims_tf_rule_set_parse_blob(&rules_blob, frame, &rule_set, &err_str);
	if (!ok) {
		PyErr_Format(PyExc_RuntimeError,
			     "Invalid Rules: %s",
			     err_str != NULL ?
			     err_str :
			     "<unknown reason>");
		TALLOC_FREE(frame);
		return NULL;
	}

	py_ret = py_return_ndr_struct("samba.dcerpc.claims",
				      "tf_rule_set",
				      rule_set,
				      rule_set);
	TALLOC_FREE(frame);
	return py_ret;
}

static PyObject *py_claims_tf_policy_wrap_xml(PyObject *self,
					      PyObject *args,
					      PyObject *kwargs)
{
	PyObject *py_rules = NULL;
	const char * const kwnames[] = {
		"rules",
		NULL
	};
	PyObject *py_ret = NULL;
	const char *rules_str = NULL;
	char *xml_str = NULL;
	bool ok;

	ok = PyArg_ParseTupleAndKeywords(args, kwargs, "O",
					 discard_const_p(char *, kwnames),
					 &py_rules);
	if (!ok) {
		return NULL;
	}

	rules_str = PyUnicode_AsUTF8(py_rules);
	if (rules_str == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	xml_str = claims_tf_policy_wrap_xml(NULL, rules_str);
	if (xml_str == NULL) {
		if (errno == EINVAL) {
			PyErr_SetString(PyExc_ValueError,
					"Invalid Rules String");
			return NULL;
		}

		PyErr_NoMemory();
		return NULL;
	}

	py_ret = PyUnicode_FromString(xml_str);
	TALLOC_FREE(xml_str);
	return py_ret;
}

static PyMethodDef py_security_methods[] = {
	{ "access_check", PY_DISCARD_FUNC_SIG(PyCFunction,
					      py_se_access_check),
	METH_VARARGS|METH_KEYWORDS,
	"access_check(security_descriptor, token, access_desired) -> access_granted.  Raises NT_STATUS on error, including on access check failure, returns access granted bitmask"},
	{ "claims_tf_policy_parse_rules",
	  (PyCFunction)py_claims_tf_policy_parse_rules,
	  METH_VARARGS | METH_KEYWORDS,
	  PyDoc_STR("claims_tf_policy_parse_rules(rules_string [, strip_xml])"
		    " -> samba.dcerpc.claims.tf_rule_set") },
	{ "claims_tf_policy_wrap_xml",
	  (PyCFunction)py_claims_tf_policy_wrap_xml,
	  METH_VARARGS | METH_KEYWORDS,
	  PyDoc_STR("claims_tf_policy_wrap_xml(rules_string)"
		    " -> xml_str") },
	{0},
};

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	.m_name = "security",
	.m_doc = "Security support.",
	.m_size = -1,
	.m_methods = py_security_methods,
};

MODULE_INIT_FUNC(security)
{
	PyObject *m;

	m = PyModule_Create(&moduledef);
	if (m == NULL)
		return NULL;

	return m;
}
