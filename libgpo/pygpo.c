/*
   Unix SMB/CIFS implementation.
   Copyright (C) Luke Morrison <luc785@hotmail.com> 2013

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
#include "version.h"
#include "param/pyparam.h"
#include "gpo.h"
#include "ads.h"

/* A Python C API module to use LIBGPO */

#ifndef Py_RETURN_NONE
#define Py_RETURN_NONE return Py_INCREF(Py_None), Py_None
#endif

/* Parameter mapping and functions for the GP_EXT struct */
void initgpo(void);

/* Global methods aka do not need a special pyobject type */
static PyObject *py_gpo_get_sysvol_gpt_version(PyObject * self, PyObject * args)
{
	TALLOC_CTX *tmp_ctx = NULL;
	char *unix_path;
	char *display_name = NULL;
	uint32_t sysvol_version = 0;
	PyObject *result;

	tmp_ctx = talloc_new(NULL);

	if (!PyArg_ParseTuple(args, "s", &unix_path)) {
		return NULL;
	}
	gpo_get_sysvol_gpt_version(tmp_ctx, unix_path, &sysvol_version, &display_name);
	talloc_free(tmp_ctx);
	result = Py_BuildValue("[s,i]", display_name, sysvol_version);
	return result;
}

static PyMethodDef py_gpo_methods[] = {
	{"gpo_get_sysvol_gpt_version", (PyCFunction) py_gpo_get_sysvol_gpt_version, METH_VARARGS, NULL},
	{NULL}
};

/* Will be called by python when loading this module */
void initgpo(void)
{
	PyObject *m;

	debug_setup_talloc_log();
	/* Instantiate the types */
	m = Py_InitModule3("gpo", py_gpo_methods, "libgpo python bindings");
	if (m == NULL)
		return;
	PyModule_AddObject(m, "version", PyString_FromString(SAMBA_VERSION_STRING));
}
