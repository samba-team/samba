/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
   Copyright (C) Matthias Dieter Wallnöfer          2009
   
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
#include "version.h"
#include "param/pyparam.h"
#include "lib/socket/netif.h"
#include "lib/util/debug.h"

void init_glue(void);
static PyObject *PyExc_NTSTATUSError;
static PyObject *PyExc_WERRORError;
static PyObject *PyExc_HRESULTError;
static PyObject *PyExc_DsExtendedError;

static PyObject *py_generate_random_str(PyObject *self, PyObject *args)
{
	int len;
	PyObject *ret;
	char *retstr;
	if (!PyArg_ParseTuple(args, "i", &len))
		return NULL;

	retstr = generate_random_str(NULL, len);
	ret = PyUnicode_FromString(retstr);
	talloc_free(retstr);
	return ret;
}

static PyObject *py_generate_random_password(PyObject *self, PyObject *args)
{
	int min, max;
	PyObject *ret;
	char *retstr;
	if (!PyArg_ParseTuple(args, "ii", &min, &max))
		return NULL;

	retstr = generate_random_password(NULL, min, max);
	if (retstr == NULL) {
		return NULL;
	}
	ret = PyUnicode_FromString(retstr);
	talloc_free(retstr);
	return ret;
}

static PyObject *py_generate_random_machine_password(PyObject *self, PyObject *args)
{
	int min, max;
	PyObject *ret;
	char *retstr;
	if (!PyArg_ParseTuple(args, "ii", &min, &max))
		return NULL;

	retstr = generate_random_machine_password(NULL, min, max);
	if (retstr == NULL) {
		return NULL;
	}
	ret = PyUnicode_FromString(retstr);
	talloc_free(retstr);
	return ret;
}

static PyObject *py_check_password_quality(PyObject *self, PyObject *args)
{
	char *pass;

	if (!PyArg_ParseTuple(args, "s", &pass)) {
		return NULL;
	}

	return PyBool_FromLong(check_password_quality(pass));
}

static PyObject *py_generate_random_bytes(PyObject *self, PyObject *args)
{
	int len;
	PyObject *ret;
	uint8_t *bytes = NULL;

	if (!PyArg_ParseTuple(args, "i", &len))
		return NULL;

	bytes = talloc_zero_size(NULL, len);
	generate_random_buffer(bytes, len);
	ret = PyBytes_FromStringAndSize((const char *)bytes, len);
	talloc_free(bytes);
	return ret;
}

static PyObject *py_unix2nttime(PyObject *self, PyObject *args)
{
	time_t t;
	unsigned int _t;
	NTTIME nt;

	if (!PyArg_ParseTuple(args, "I", &_t)) {
		return NULL;
	}
	t = _t;

	unix_to_nt_time(&nt, t);

	return PyLong_FromLongLong((uint64_t)nt);
}

static PyObject *py_nttime2unix(PyObject *self, PyObject *args)
{
	time_t t;
	NTTIME nt;
	if (!PyArg_ParseTuple(args, "K", &nt))
		return NULL;

	t = nt_time_to_unix(nt);

	return PyLong_FromLong((uint64_t)t);
}

static PyObject *py_nttime2string(PyObject *self, PyObject *args)
{
	PyObject *ret;
	NTTIME nt;
	TALLOC_CTX *tmp_ctx;
	const char *string;
	if (!PyArg_ParseTuple(args, "K", &nt))
		return NULL;

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	string = nt_time_string(tmp_ctx, nt);
	ret =  PyUnicode_FromString(string);

	talloc_free(tmp_ctx);

	return ret;
}

static PyObject *py_set_debug_level(PyObject *self, PyObject *args)
{
	unsigned level;
	if (!PyArg_ParseTuple(args, "I", &level))
		return NULL;
	debuglevel_set(level);
	Py_RETURN_NONE;
}

static PyObject *py_get_debug_level(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
	return PyLong_FromLong(debuglevel_get());
}

static PyObject *py_fault_setup(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
	static bool done;
	if (!done) {
		fault_setup();
		done = true;
	}
	Py_RETURN_NONE;
}

static PyObject *py_is_ntvfs_fileserver_built(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
#ifdef WITH_NTVFS_FILESERVER
	Py_RETURN_TRUE;
#else
	Py_RETURN_FALSE;
#endif
}

static PyObject *py_is_heimdal_built(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
#ifdef SAMBA4_USES_HEIMDAL
	Py_RETURN_TRUE;
#else
	Py_RETURN_FALSE;
#endif
}

/*
  return the list of interface IPs we have configured
  takes an loadparm context, returns a list of IPs in string form

  Does not return addresses on 127.0.0.0/8
 */
static PyObject *py_interface_ips(PyObject *self, PyObject *args)
{
	PyObject *pylist;
	int count;
	TALLOC_CTX *tmp_ctx;
	PyObject *py_lp_ctx;
	struct loadparm_context *lp_ctx;
	struct interface *ifaces;
	int i, ifcount;
	int all_interfaces = 1;

	if (!PyArg_ParseTuple(args, "O|i", &py_lp_ctx, &all_interfaces))
		return NULL;

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	lp_ctx = lpcfg_from_py_object(tmp_ctx, py_lp_ctx);
	if (lp_ctx == NULL) {
		talloc_free(tmp_ctx);
		return NULL;
	}

	load_interface_list(tmp_ctx, lp_ctx, &ifaces);

	count = iface_list_count(ifaces);

	/* first count how many are not loopback addresses */
	for (ifcount = i = 0; i<count; i++) {
		const char *ip = iface_list_n_ip(ifaces, i);

		if (all_interfaces) {
			ifcount++;
			continue;
		}

		if (iface_list_same_net(ip, "127.0.0.1", "255.0.0.0")) {
			continue;
		}

		if (iface_list_same_net(ip, "169.254.0.0", "255.255.0.0")) {
			continue;
		}

		if (iface_list_same_net(ip, "::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")) {
			continue;
		}

		if (iface_list_same_net(ip, "fe80::", "ffff:ffff:ffff:ffff::")) {
			continue;
		}

		ifcount++;
	}

	pylist = PyList_New(ifcount);
	for (ifcount = i = 0; i<count; i++) {
		const char *ip = iface_list_n_ip(ifaces, i);

		if (all_interfaces) {
			PyList_SetItem(pylist, ifcount, PyUnicode_FromString(ip));
			ifcount++;
			continue;
		}

		if (iface_list_same_net(ip, "127.0.0.1", "255.0.0.0")) {
			continue;
		}

		if (iface_list_same_net(ip, "169.254.0.0", "255.255.0.0")) {
			continue;
		}

		if (iface_list_same_net(ip, "::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")) {
			continue;
		}

		if (iface_list_same_net(ip, "fe80::", "ffff:ffff:ffff:ffff::")) {
			continue;
		}

		PyList_SetItem(pylist, ifcount, PyUnicode_FromString(ip));
		ifcount++;
	}
	talloc_free(tmp_ctx);
	return pylist;
}

static PyObject *py_strcasecmp_m(PyObject *self, PyObject *args)
{
	const char *s1 = NULL;
	const char *s2 = NULL;
	long cmp_result = 0;
	if (!PyArg_ParseTuple(args, PYARG_STR_UNI
			      PYARG_STR_UNI,
			      "utf8", &s1, "utf8", &s2)) {
		return NULL;
	}

	cmp_result = strcasecmp_m(s1, s2);
	PyMem_Free(discard_const_p(char, s1));
	PyMem_Free(discard_const_p(char, s2));
	return PyLong_FromLong(cmp_result);
}

static PyObject *py_strstr_m(PyObject *self, PyObject *args)
{
	const char *s1 = NULL;
	const char *s2 = NULL;
	char *strstr_ret = NULL;
	PyObject *result = NULL;
	if (!PyArg_ParseTuple(args, PYARG_STR_UNI
			      PYARG_STR_UNI,
			      "utf8", &s1, "utf8", &s2))
		return NULL;

	strstr_ret = strstr_m(s1, s2);
	if (!strstr_ret) {
		PyMem_Free(discard_const_p(char, s1));
		PyMem_Free(discard_const_p(char, s2));
		Py_RETURN_NONE;
	}
	result = PyUnicode_FromString(strstr_ret);
	PyMem_Free(discard_const_p(char, s1));
	PyMem_Free(discard_const_p(char, s2));
	return result;
}

static PyMethodDef py_misc_methods[] = {
	{ "generate_random_str", (PyCFunction)py_generate_random_str, METH_VARARGS,
		"generate_random_str(len) -> string\n"
		"Generate random string with specified length." },
	{ "generate_random_password", (PyCFunction)py_generate_random_password,
		METH_VARARGS, "generate_random_password(min, max) -> string\n"
		"Generate random password (based on printable ascii characters) "
		"with a length >= min and <= max." },
	{ "generate_random_machine_password", (PyCFunction)py_generate_random_machine_password,
		METH_VARARGS, "generate_random_machine_password(min, max) -> string\n"
		"Generate random password "
		"(based on random utf16 characters converted to utf8 or "
		"random ascii characters if 'unix charset' is not 'utf8')"
		"with a length >= min (at least 14) and <= max (at most 255)." },
	{ "check_password_quality", (PyCFunction)py_check_password_quality,
		METH_VARARGS, "check_password_quality(pass) -> bool\n"
		"Check password quality against Samba's check_password_quality,"
		"the implementation of Microsoft's rules:"
		"http://msdn.microsoft.com/en-us/subscriptions/cc786468%28v=ws.10%29.aspx"
	},
	{ "unix2nttime", (PyCFunction)py_unix2nttime, METH_VARARGS,
		"unix2nttime(timestamp) -> nttime" },
	{ "nttime2unix", (PyCFunction)py_nttime2unix, METH_VARARGS,
		"nttime2unix(nttime) -> timestamp" },
	{ "nttime2string", (PyCFunction)py_nttime2string, METH_VARARGS,
		"nttime2string(nttime) -> string" },
	{ "set_debug_level", (PyCFunction)py_set_debug_level, METH_VARARGS,
		"set debug level" },
	{ "get_debug_level", (PyCFunction)py_get_debug_level, METH_NOARGS,
		"get debug level" },
	{ "fault_setup", (PyCFunction)py_fault_setup, METH_NOARGS,
		"setup the default samba panic handler" },
	{ "interface_ips", (PyCFunction)py_interface_ips, METH_VARARGS,
		"interface_ips(lp_ctx[, all_interfaces) -> list_of_ifaces\n"
		"\n"
		"get interface IP address list"},
	{ "strcasecmp_m", (PyCFunction)py_strcasecmp_m, METH_VARARGS,
		"(for testing) compare two strings using Samba's strcasecmp_m()"},
	{ "strstr_m", (PyCFunction)py_strstr_m, METH_VARARGS,
		"(for testing) find one string in another with Samba's strstr_m()"},
	{ "is_ntvfs_fileserver_built", (PyCFunction)py_is_ntvfs_fileserver_built, METH_NOARGS,
		"is the NTVFS file server built in this installation?" },
	{ "is_heimdal_built", (PyCFunction)py_is_heimdal_built, METH_NOARGS,
		"is Samba built with Heimdal Kerberbos?" },
	{ "generate_random_bytes",
		(PyCFunction)py_generate_random_bytes,
		METH_VARARGS,
		"generate_random_bytes(len) -> bytes\n"
		"Generate random bytes with specified length." },
	{0}
};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    .m_name = "_glue",
    .m_doc = "Python bindings for miscellaneous Samba functions.",
    .m_size = -1,
    .m_methods = py_misc_methods,
};

MODULE_INIT_FUNC(_glue)
{
	PyObject *m;

	debug_setup_talloc_log();

	m = PyModule_Create(&moduledef);
	if (m == NULL)
		return NULL;

	PyModule_AddObject(m, "version",
					   PyUnicode_FromString(SAMBA_VERSION_STRING));
	PyExc_NTSTATUSError = PyErr_NewException(discard_const_p(char, "samba.NTSTATUSError"), PyExc_RuntimeError, NULL);
	if (PyExc_NTSTATUSError != NULL) {
		Py_INCREF(PyExc_NTSTATUSError);
		PyModule_AddObject(m, "NTSTATUSError", PyExc_NTSTATUSError);
	}

	PyExc_WERRORError = PyErr_NewException(discard_const_p(char, "samba.WERRORError"), PyExc_RuntimeError, NULL);
	if (PyExc_WERRORError != NULL) {
		Py_INCREF(PyExc_WERRORError);
		PyModule_AddObject(m, "WERRORError", PyExc_WERRORError);
	}

	PyExc_HRESULTError = PyErr_NewException(discard_const_p(char, "samba.HRESULTError"), PyExc_RuntimeError, NULL);
	if (PyExc_HRESULTError != NULL) {
		Py_INCREF(PyExc_HRESULTError);
		PyModule_AddObject(m, "HRESULTError", PyExc_HRESULTError);
	}

	PyExc_DsExtendedError = PyErr_NewException(discard_const_p(char, "samba.DsExtendedError"), PyExc_RuntimeError, NULL);
	if (PyExc_DsExtendedError != NULL) {
		Py_INCREF(PyExc_DsExtendedError);
		PyModule_AddObject(m, "DsExtendedError", PyExc_DsExtendedError);
	}

	return m;
}

