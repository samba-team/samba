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

#include "includes.h"
#include <Python.h>

static PyObject *py_get_predefined_key_by_name(PyObject *self, PyObject *args)
{
	return Py_None; /* FIXME */
}

static PyObject *py_key_del_abs(PyObject *self, PyObject *args)
{
	return Py_None; /* FIXME */
}

static PyMethodDef registry_methods[] = {
	{ "get_predefined_key_by_name", py_get_predefined_key_by_name, METH_VARARGS, 
		"S.get_predefined_key_by_name(name) -> key\n"
		"Find a predefined key by name" },
	{ "key_del_abs", py_key_del_abs, METH_VARARGS, "S.key_del_abs(name) -> None\n"
                "Delete a key by absolute path." },
	{ "get_predefined_key", py_get_predefined_key, METH_VARARGS, "S.get_predefined_key(hkey_id) -> key\n"
		"Find a predefined key by id" },
	{ "diff_apply", py_diff_apply, METH_VARARGS, "S.diff_apply(filename) -> None\n"
        	"Apply the diff from the specified file" },
	{ "mount_hive", py_mount_hive, METH_VARARGS, "S.mount_hive(key, key_id, elements=None) -> None\n"
		"Mount the specified key at the specified path." },
	{ "import_hive_key", py_import_hive_key, METH_VARARGS, "S.import_hive_key(hive, predef_key, elements=None) -> Key" },
	{ NULL }
};

PyTypeObject PyRegistry = {
	.tp_name = "Registry",
	.tp_methods = registry_methods,
	.tp_new = registry_new,
};

static PyMethodDef hive_key_methods[] = {
	{ "del", hive_key_del, METH_VARARGS, "S.del(name) -> None\n"
		"Delete a subkey" },
	{ "flush", hive_key_flush, METH_VARARGS, "S.flush() -> None\n"
                "Flush this key to disk" },
	{ "del_value", hive_key_del_value, METH_VARARGS, "S.del_value(name) -> None\n"
                 "Delete a value" },
	{ "set_value", hive_key_set_value, METH_VARARGS, "S.set_value(name, type, data) -> None\n"
                 "Set a value" },
	{ NULL }
};

static PyObject *hive_open(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	/* reg_open_hive */
	return Py_None;
}

PyTypeObject PyHiveKey = {
	.tp_name = "HiveKey",
	.tp_methods = hive_key_methods,
	.tp_new = hive_open,
};

static PyObject *py_open_samba(PyObject *self, PyObject *args, PyObject *kwargs)
{
	char *kwnames[] = { "lp_ctx", "session_info", };
	struct registry_context *reg_ctx;
	PyObject *py_lp_ctx, *py_session_info, *py_credentials;
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|OOO", kwnames,
					 &py_lp_ctx, &py_session_info, &py_credentials))
		return NULL;

	/* FIXME: */

	result = reg_open_samba(NULL, &reg_ctx, py_event_context(), 
				lp_ctx, session_info, credentials);
	if (!W_ERROR_IS_OK(result)) {
		PyErr_SetWERROR(result);
		return NULL;
	}
	
	/* FIXME */

	return Py_None;
}

static PyMethodDef py_registry_methods[] = {
	{ "open_samba", py_open_samba, METH_VARARGS|METH_KEYWORDS, "open_samba() -> reg" },
	{ "open_directory", py_open_directory, METH_VARARGS, "open_dir(location) -> key" },
	{ "create_directory", py_create_directory, METH_VARARGS, "create_dir(location) -> key" },
	{ "open_ldb_file", py_open_ldb_file, METH_VARARGS|METH_KEYWORDS, "open_ldb(location, session_info=None, credentials=None, loadparm_context=None) -> key" },
	{ "str_regtype", py_str_regtype, METH_VARARGS, "str_regtype(int) -> str" },
	{ "get_predef_name", py_get_predef_name, METH_VARARGS, "get_predef_name(hkey) -> str" },
	{ NULL }
};

void initregistry(void)
{
	PyModule *m;

	m = PyInitModule3("registry", py_registry_methods, "Registry");
	if (m == NULL)
		return;

	PyModule_AddObject(m, "HKEY_CLASSES_ROOT", PyInt_FromLong(HKEY_CLASSES_ROOT));
	PyModule_AddObject(m, "HKEY_CURRENT_USER", PyInt_FromLong(HKEY_CURRENT_USER));
	PyModule_AddObject(m, "HKEY_LOCAL_MACHINE", PyInt_FromLong(HKEY_LOCAL_MACHINE));
	PyModule_AddObject(m, "HKEY_USERS", PyInt_FromLong(HKEY_USERS));
	PyModule_AddObject(m, "HKEY_PERFORMANCE_DATA", PyInt_FromLong(HKEY_PERFORMANCE_DATA));
	PyModule_AddObject(m, "HKEY_CURRENT_CONFIG", PyInt_FromLong(HKEY_CURRENT_CONFIG));
	PyModule_AddObject(m, "HKEY_DYN_DATA", PyInt_FromLong(HKEY_DYN_DATA));
	PyModule_AddObject(m, "HKEY_PERFORMANCE_TEXT", PyInt_FromLong(HKEY_PERFORMANCE_TEXT));
	PyModule_AddObject(m, "HKEY_PERFORMANCE_NLSTEXT", PyInt_FromLong(HKEY_PERFORMANCE_NLSTEXT));
}
