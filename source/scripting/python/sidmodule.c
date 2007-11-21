/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
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

#include "includes.h"
#include "Python.h"
#include "libcli/security/security.h"

static PyObject *sid_random(PyObject *self, PyObject *args)
{
	char *str;

	if (!PyArg_ParseTuple(args, ""))
	        return NULL;

	str = talloc_asprintf(NULL, "S-1-5-21-%u-%u-%u", 
				  (unsigned)generate_random(), 
				  (unsigned)generate_random(), 
				  (unsigned)generate_random());

	if (str == NULL) {
		PyErr_SetString(PyExc_TypeError, "can't generate random sid");
		return NULL;
	}

	return PyString_FromString(str);
}

static PyMethodDef methods[] = {
	{ "random", (PyCFunction)sid_random, METH_VARARGS, NULL},
	{ NULL, NULL }
};

PyDoc_STRVAR(param_doc, "SID helper routines");

PyMODINIT_FUNC initsid(void)
{
	PyObject *mod = Py_InitModule3("sid", methods, param_doc);
	if (mod == NULL)
		return;
}
