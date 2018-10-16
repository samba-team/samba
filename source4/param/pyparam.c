/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2008
   
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
#include "param/param.h"
#include "param/loadparm.h"
#include <pytalloc.h>
#include "dynconfig/dynconfig.h"

#define PyLoadparmContext_AsLoadparmContext(obj) pytalloc_get_type(obj, struct loadparm_context)
#define PyLoadparmService_AsLoadparmService(obj) pytalloc_get_type(obj, struct loadparm_service)

extern PyTypeObject PyLoadparmContext;
extern PyTypeObject PyLoadparmService;

static PyObject *PyLoadparmService_FromService(struct loadparm_service *service)
{
	return pytalloc_reference(&PyLoadparmService, service);
}

static PyObject *py_lp_ctx_get_helper(struct loadparm_context *lp_ctx, const char *service_name, const char *param_name)
{
	struct parm_struct *parm = NULL;
	void *parm_ptr = NULL;
	int i;

	if (service_name != NULL && strwicmp(service_name, GLOBAL_NAME) && 
		strwicmp(service_name, GLOBAL_NAME2)) {
		struct loadparm_service *service;
		/* its a share parameter */
		service = lpcfg_service(lp_ctx, service_name);
		if (service == NULL) {
			return NULL;
		}
		if (strchr(param_name, ':')) {
			/* its a parametric option on a share */
			const char *type = talloc_strndup(lp_ctx, param_name,
											  strcspn(param_name, ":"));
			const char *option = strchr(param_name, ':') + 1;
			const char *value;
			if (type == NULL || option == NULL) {
			return NULL;
			}
			value = lpcfg_get_parametric(lp_ctx, service, type, option);
			if (value == NULL) {
			return NULL;
			}
			return PyUnicode_FromString(value);
		}

		parm = lpcfg_parm_struct(lp_ctx, param_name);
		if (parm == NULL || parm->p_class == P_GLOBAL) {
			return NULL;
		}
		parm_ptr = lpcfg_parm_ptr(lp_ctx, service, parm);
    } else if (strchr(param_name, ':')) {
		/* its a global parametric option */
		const char *type = talloc_strndup(lp_ctx,
				  param_name, strcspn(param_name, ":"));
		const char *option = strchr(param_name, ':') + 1;
		const char *value;
		if (type == NULL || option == NULL) {
			return NULL;
		}
		value = lpcfg_get_parametric(lp_ctx, NULL, type, option);
		if (value == NULL)
			return NULL;
		return PyUnicode_FromString(value);
	} else {
		/* its a global parameter */
		parm = lpcfg_parm_struct(lp_ctx, param_name);
		if (parm == NULL) {
			return NULL;
		}
		parm_ptr = lpcfg_parm_ptr(lp_ctx, NULL, parm);
	}

	if (parm == NULL || parm_ptr == NULL) {
		return NULL;
    }

    /* construct and return the right type of python object */
    switch (parm->type) {
    case P_CHAR:
	return PyUnicode_FromFormat("%c", *(char *)parm_ptr);
    case P_STRING:
    case P_USTRING:
	return PyUnicode_FromString(*(char **)parm_ptr);
    case P_BOOL:
	return PyBool_FromLong(*(bool *)parm_ptr);
    case P_BOOLREV:
	return PyBool_FromLong(!(*(bool *)parm_ptr));
    case P_INTEGER:
    case P_OCTAL:
    case P_BYTES:
	return PyLong_FromLong(*(int *)parm_ptr);
    case P_ENUM:
	for (i=0; parm->enum_list[i].name; i++) {
	    if (*(int *)parm_ptr == parm->enum_list[i].value) {
		return PyUnicode_FromString(parm->enum_list[i].name);
	    }
	}
	return NULL;
    case P_CMDLIST:
    case P_LIST: 
	{
	    int j;
	    const char **strlist = *(const char ***)parm_ptr;
	    PyObject *pylist;
		
	    if(strlist == NULL) {
		    return PyList_New(0);
	    }
		
	    pylist = PyList_New(str_list_length(strlist));
	    for (j = 0; strlist[j]; j++) 
		PyList_SetItem(pylist, j, 
			       PyUnicode_FromString(strlist[j]));
	    return pylist;
	}
    }
    return NULL;

}

static PyObject *py_lp_ctx_load(PyObject *self, PyObject *args)
{
	char *filename;
	bool ret;
	if (!PyArg_ParseTuple(args, "s", &filename))
		return NULL;

	ret = lpcfg_load(PyLoadparmContext_AsLoadparmContext(self), filename);

	if (!ret) {
		PyErr_Format(PyExc_RuntimeError, "Unable to load file %s", filename);
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *py_lp_ctx_load_default(PyObject *self, PyObject *unused)
{
	bool ret;
        ret = lpcfg_load_default(PyLoadparmContext_AsLoadparmContext(self));

	if (!ret) {
		PyErr_SetString(PyExc_RuntimeError, "Unable to load default file");
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *py_lp_ctx_get(PyObject *self, PyObject *args)
{
	char *param_name;
	char *section_name = NULL;
	PyObject *ret;
	if (!PyArg_ParseTuple(args, "s|z", &param_name, &section_name))
		return NULL;

	ret = py_lp_ctx_get_helper(PyLoadparmContext_AsLoadparmContext(self), section_name, param_name);
	if (ret == NULL)
		Py_RETURN_NONE;
	return ret;
}

static PyObject *py_lp_ctx_is_myname(PyObject *self, PyObject *args)
{
	char *name;
	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	return PyBool_FromLong(lpcfg_is_myname(PyLoadparmContext_AsLoadparmContext(self), name));
}

static PyObject *py_lp_ctx_is_mydomain(PyObject *self, PyObject *args)
{
	char *name;
	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	return PyBool_FromLong(lpcfg_is_mydomain(PyLoadparmContext_AsLoadparmContext(self), name));
}

static PyObject *py_lp_ctx_set(PyObject *self, PyObject *args)
{
	char *name, *value;
	bool ret;
	if (!PyArg_ParseTuple(args, "ss", &name, &value))
		return NULL;

	ret = lpcfg_set_cmdline(PyLoadparmContext_AsLoadparmContext(self), name, value);
	if (!ret) {
		PyErr_SetString(PyExc_RuntimeError, "Unable to set parameter");
		return NULL;
        }

	Py_RETURN_NONE;
}

static PyObject *py_lp_ctx_private_path(PyObject *self, PyObject *args)
{
	char *name, *path;
	PyObject *ret;
	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	path = lpcfg_private_path(NULL, PyLoadparmContext_AsLoadparmContext(self), name);
	ret = PyUnicode_FromString(path);
	talloc_free(path);

	return ret;
}

static PyObject *py_lp_ctx_services(PyObject *self, PyObject *unused)
{
	struct loadparm_context *lp_ctx = PyLoadparmContext_AsLoadparmContext(self);
	PyObject *ret;
	int i;
	ret = PyList_New(lpcfg_numservices(lp_ctx));
	for (i = 0; i < lpcfg_numservices(lp_ctx); i++) {
		struct loadparm_service *service = lpcfg_servicebynum(lp_ctx, i);
		if (service != NULL) {
			PyList_SetItem(ret, i, PyUnicode_FromString(lpcfg_servicename(service)));
		}
	}
	return ret;
}

static PyObject *py_lp_ctx_server_role(PyObject *self, PyObject *unused)
{
	struct loadparm_context *lp_ctx = PyLoadparmContext_AsLoadparmContext(self);
	uint32_t role;
	const char *role_str;

	role = lpcfg_server_role(lp_ctx);
	role_str = server_role_str(role);

	return PyUnicode_FromString(role_str);
}

static PyObject *py_lp_dump(PyObject *self, PyObject *args)
{
	bool show_defaults = false;
	const char *file_name = "";
	const char *mode = "w";
	FILE *f;
	struct loadparm_context *lp_ctx = PyLoadparmContext_AsLoadparmContext(self);

	if (!PyArg_ParseTuple(args, "|bss", &show_defaults, &file_name, &mode))
		return NULL;

	if (file_name[0] == '\0') {
		f = stdout;
	} else {
		f = fopen(file_name, mode);
	}

	if (f == NULL) {
		PyErr_SetFromErrno(PyExc_IOError);
		return NULL;
	}

	lpcfg_dump(lp_ctx, f, show_defaults, lpcfg_numservices(lp_ctx));

	if (f != stdout) {
		fclose(f);
	}

	Py_RETURN_NONE;
}

static PyObject *py_lp_dump_a_parameter(PyObject *self, PyObject *args)
{
	char *param_name;
	const char *section_name = NULL;
	const char *file_name = "";
	const char *mode = "w";
	FILE *f;
	struct loadparm_context *lp_ctx = PyLoadparmContext_AsLoadparmContext(self);
	struct loadparm_service *service;
	bool ret;

	if (!PyArg_ParseTuple(args, "s|zss", &param_name, &section_name, &file_name, &mode))
		return NULL;

	if (file_name[0] == '\0') {
		f = stdout;
	} else {
		f = fopen(file_name, mode);
	}

	if (f == NULL) {
		return NULL;
	}

	if (section_name != NULL && strwicmp(section_name, GLOBAL_NAME) &&
		strwicmp(section_name, GLOBAL_NAME2)) {
		/* it's a share parameter */
		service = lpcfg_service(lp_ctx, section_name);
		if (service == NULL) {
			PyErr_Format(PyExc_RuntimeError, "Unknown section %s", section_name);
			return NULL;
		}
	} else {
		/* it's global */
		service = NULL;
		section_name = "global";
	}

	ret = lpcfg_dump_a_parameter(lp_ctx, service, param_name, f);

	if (!ret) {
		PyErr_Format(PyExc_RuntimeError, "Parameter %s unknown for section %s", param_name, section_name);
		if (f != stdout) {
			fclose(f);
		}
		return NULL;
	}

	if (f != stdout) {
		fclose(f);
	}

	Py_RETURN_NONE;

}

static PyObject *py_lp_log_level(PyObject *self, PyObject *unused)
{
	int ret = debuglevel_get();
	return PyLong_FromLong(ret);
}


static PyObject *py_samdb_url(PyObject *self, PyObject *unused)
{
	struct loadparm_context *lp_ctx = PyLoadparmContext_AsLoadparmContext(self);
	return PyUnicode_FromFormat("tdb://%s/sam.ldb", lpcfg_private_dir(lp_ctx));
}

static PyObject *py_cache_path(PyObject *self, PyObject *args)
{
	struct loadparm_context *lp_ctx = PyLoadparmContext_AsLoadparmContext(self);
	char *name = NULL;
	char *path = NULL;
	PyObject *ret = NULL;

	if (!PyArg_ParseTuple(args, "s", &name)) {
		return NULL;
	}

	path = lpcfg_cache_path(NULL, lp_ctx, name);
	if (!path) {
		PyErr_Format(PyExc_RuntimeError,
			     "Unable to access cache %s", name);
		return NULL;
	}
	ret = PyUnicode_FromString(path);
	talloc_free(path);

	return ret;
}

static PyObject *py_state_path(PyObject *self, PyObject *args)
{
	struct loadparm_context *lp_ctx =
		PyLoadparmContext_AsLoadparmContext(self);
	char *name = NULL;
	char *path = NULL;
	PyObject *ret = NULL;

	if (!PyArg_ParseTuple(args, "s", &name)) {
		return NULL;
	}

	path = lpcfg_state_path(NULL, lp_ctx, name);
	if (!path) {
		PyErr_Format(PyExc_RuntimeError,
			     "Unable to access cache %s", name);
		return NULL;
	}
	ret = PyUnicode_FromString(path);
	talloc_free(path);

	return ret;
}

static PyMethodDef py_lp_ctx_methods[] = {
	{ "load", py_lp_ctx_load, METH_VARARGS,
		"S.load(filename) -> None\n"
		"Load specified file." },
	{ "load_default", py_lp_ctx_load_default, METH_NOARGS,
        	"S.load_default() -> None\n"
		"Load default smb.conf file." },
	{ "is_myname", py_lp_ctx_is_myname, METH_VARARGS,
		"S.is_myname(name) -> bool\n"
		"Check whether the specified name matches one of our netbios names." },
	{ "is_mydomain", py_lp_ctx_is_mydomain, METH_VARARGS,
		"S.is_mydomain(name) -> bool\n"
		"Check whether the specified name matches our domain name." },
	{ "get", py_lp_ctx_get, METH_VARARGS,
        	"S.get(name, service_name) -> value\n"
		"Find specified parameter." },
	{ "set", py_lp_ctx_set, METH_VARARGS,
		"S.set(name, value) -> bool\n"
		"Change a parameter." },
	{ "private_path", py_lp_ctx_private_path, METH_VARARGS,
		"S.private_path(name) -> path\n" },
	{ "services", py_lp_ctx_services, METH_NOARGS,
		"S.services() -> list" },
	{ "server_role", py_lp_ctx_server_role, METH_NOARGS,
		"S.server_role() -> value\n"
		"Get the server role." },
	{ "dump", py_lp_dump, METH_VARARGS,
		"S.dump(show_defaults=False, file_name='', mode='w')" },
	{ "dump_a_parameter", py_lp_dump_a_parameter, METH_VARARGS,
		"S.dump_a_parameter(name, service_name, file_name='', mode='w')" },
	{ "log_level", py_lp_log_level, METH_NOARGS,
		"S.log_level() -> int\n Get the active log level" },
	{ "samdb_url", py_samdb_url, METH_NOARGS,
	        "S.samdb_url() -> string\n"
	        "Returns the current URL for sam.ldb." },
	{ "cache_path", py_cache_path, METH_VARARGS,
		"S.cache_path(name) -> string\n"
		"Returns a path in the Samba cache directory." },
	{ "state_path", py_state_path, METH_VARARGS,
		"S.state_path(name) -> string\n"
		"Returns a path in the Samba state directory." },
	{0}
};

static PyObject *py_lp_ctx_default_service(PyObject *self, void *closure)
{
	return PyLoadparmService_FromService(lpcfg_default_service(PyLoadparmContext_AsLoadparmContext(self)));
}

static PyObject *py_lp_ctx_config_file(PyObject *self, void *closure)
{
	const char *configfile = lpcfg_configfile(PyLoadparmContext_AsLoadparmContext(self));
	if (configfile == NULL)
		Py_RETURN_NONE;
	else
		return PyUnicode_FromString(configfile);
}

static PyGetSetDef py_lp_ctx_getset[] = {
	{
		.name = discard_const_p(char, "default_service"),
		.get  = (getter)py_lp_ctx_default_service,
	},
	{
		.name = discard_const_p(char, "configfile"),
		.get  = (getter)py_lp_ctx_config_file,
		.doc  = discard_const_p(char, "Name of last config file that was loaded.")
	},
	{ .name = NULL }
};

static PyObject *py_lp_ctx_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	const char *kwnames[] = {"filename_for_non_global_lp", NULL};
	PyObject *lp_ctx;
	const char *non_global_conf = NULL;
	struct loadparm_context *ctx;

	if (!PyArg_ParseTupleAndKeywords(args,
					 kwargs,
					 "|s",
					 discard_const_p(char *,
							 kwnames),
					 &non_global_conf)) {
		return NULL;
	}

	/*
	 * by default, any LoadParm python objects map to a single global
	 * underlying object. The filename_for_non_global_lp arg overrides this
	 * default behaviour and creates a separate underlying LoadParm object.
	 */
	if (non_global_conf != NULL) {
		bool ok;
		ctx = loadparm_init(NULL);
		if (ctx == NULL) {
			PyErr_NoMemory();
			return NULL;
		}

		lp_ctx = pytalloc_reference(type, ctx);
		if (lp_ctx == NULL) {
			PyErr_NoMemory();
			return NULL;
		}

		ok = lpcfg_load_no_global(
			PyLoadparmContext_AsLoadparmContext(lp_ctx),
			non_global_conf);
		if (!ok) {
			PyErr_Format(PyExc_ValueError,
				     "Could not load non-global conf %s",
				     non_global_conf);
			return NULL;
		}
		return lp_ctx;
	} else{
		return pytalloc_reference(type, loadparm_init_global(false));
	}
}

static Py_ssize_t py_lp_ctx_len(PyObject *self)
{
	return lpcfg_numservices(PyLoadparmContext_AsLoadparmContext(self));
}

static PyObject *py_lp_ctx_getitem(PyObject *self, PyObject *name)
{
	struct loadparm_service *service;
	if (!PyUnicode_Check(name)) {
		PyErr_SetString(PyExc_TypeError, "Only string subscripts are supported");
		return NULL;
	}
	service = lpcfg_service(PyLoadparmContext_AsLoadparmContext(self), PyUnicode_AsUTF8(name));
	if (service == NULL) {
		PyErr_SetString(PyExc_KeyError, "No such section");
		return NULL;
	}
	return PyLoadparmService_FromService(service);
}

static PyMappingMethods py_lp_ctx_mapping = {
	.mp_length = (lenfunc)py_lp_ctx_len,
	.mp_subscript = (binaryfunc)py_lp_ctx_getitem,
};

PyTypeObject PyLoadparmContext = {
	.tp_name = "param.LoadParm",
	.tp_getset = py_lp_ctx_getset,
	.tp_methods = py_lp_ctx_methods,
	.tp_new = py_lp_ctx_new,
	.tp_as_mapping = &py_lp_ctx_mapping,
	.tp_flags = Py_TPFLAGS_DEFAULT,
};

static PyObject *py_lp_service_dump(PyObject *self, PyObject *args)
{
	bool show_defaults = false;
	FILE *f;
	const char *file_name = "";
	const char *mode = "w";
	struct loadparm_service *service = PyLoadparmService_AsLoadparmService(self);
	struct loadparm_service *default_service;
	PyObject *py_default_service;

	if (!PyArg_ParseTuple(args, "O|bss", &py_default_service, &show_defaults, &file_name, &mode))
		return NULL;

	if (file_name[0] == '\0') {
		f = stdout;
	} else {
		f = fopen(file_name, mode);
	}

	if (f == NULL) {
		return NULL;
	}

	if (!PyObject_TypeCheck(py_default_service, &PyLoadparmService)) {
		PyErr_SetNone(PyExc_TypeError);
		if (f != stdout) {
			fclose(f);
		}
		return NULL;
	}

	default_service = PyLoadparmService_AsLoadparmService(py_default_service);

	lpcfg_dump_one(f, show_defaults, service, default_service);

	if (f != stdout) {
		fclose(f);
	}

	Py_RETURN_NONE;
}

static PyMethodDef py_lp_service_methods[] = {
	{ "dump", (PyCFunction)py_lp_service_dump, METH_VARARGS, 
		"S.dump(default_service, show_defaults=False, file_name='', mode='w')" },
	{0}
};

PyTypeObject PyLoadparmService = {
	.tp_name = "param.LoadparmService",
	.tp_methods = py_lp_service_methods,
	.tp_flags = Py_TPFLAGS_DEFAULT,
};

static PyObject *py_data_dir(PyObject *self)
{
        return PyUnicode_FromString(dyn_DATADIR);
}

static PyObject *py_default_path(PyObject *self, PyObject *Py_UNUSED(ignored))
{
	return PyUnicode_FromString(lp_default_path());
}

static PyObject *py_setup_dir(PyObject *self, PyObject *Py_UNUSED(ignored))
{
	return PyUnicode_FromString(dyn_SETUPDIR);
}

static PyObject *py_modules_dir(PyObject *self, PyObject *Py_UNUSED(ignored))
{
	return PyUnicode_FromString(dyn_MODULESDIR);
}

static PyObject *py_bin_dir(PyObject *self, PyObject *Py_UNUSED(ignored))
{
	return PyUnicode_FromString(dyn_BINDIR);
}

static PyObject *py_sbin_dir(PyObject *self, PyObject *Py_UNUSED(ignored))
{
	return PyUnicode_FromString(dyn_SBINDIR);
}

static PyMethodDef pyparam_methods[] = {
	{ "data_dir", (PyCFunction)py_data_dir, METH_NOARGS,
		"Returns the compiled in location of data directory." },
	{ "default_path", (PyCFunction)py_default_path, METH_NOARGS,
		"Returns the default smb.conf path." },
	{ "setup_dir", (PyCFunction)py_setup_dir, METH_NOARGS,
		"Returns the compiled in location of provision templates." },
	{ "modules_dir", (PyCFunction)py_modules_dir, METH_NOARGS,
		"Returns the compiled in location of modules." },
	{ "bin_dir", (PyCFunction)py_bin_dir, METH_NOARGS,
		"Returns the compiled in BINDIR." },
	{ "sbin_dir", (PyCFunction)py_sbin_dir, METH_NOARGS,
		"Returns the compiled in SBINDIR." },
	{0}
};

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	.m_name = "param",
	.m_doc = "Parsing and writing Samba configuration files.",
	.m_size = -1,
	.m_methods = pyparam_methods,
};

MODULE_INIT_FUNC(param)
{
	PyObject *m;
	PyTypeObject *talloc_type = pytalloc_GetObjectType();
	if (talloc_type == NULL)
		return NULL;

	if (pytalloc_BaseObject_PyType_Ready(&PyLoadparmContext) < 0)
		return NULL;

	if (pytalloc_BaseObject_PyType_Ready(&PyLoadparmService) < 0)
		return NULL;

	m = PyModule_Create(&moduledef);
	if (m == NULL)
		return NULL;

	Py_INCREF(&PyLoadparmContext);
	PyModule_AddObject(m, "LoadParm", (PyObject *)&PyLoadparmContext);
	return m;
}
