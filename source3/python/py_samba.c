/* 
   Python wrappers for DCERPC/SMB client routines.

   Copyright (C) Tim Potter, 2002
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "Python.h"
#include "python/py_common.h"

/*
 * Module initialisation 
 */

static PyObject *lsa_open_policy(PyObject *self, PyObject *args, 
				PyObject *kw) 
{
	return NULL;
}

static PyMethodDef samba_methods[] = {
	{ NULL }
};

static PyMethodDef cheepy_methods[] = {
	{ "open_policy", (PyCFunction)lsa_open_policy, METH_VARARGS|METH_KEYWORDS,
	  "Foo"},
	{ NULL }
};

void initsamba(void)
{
	PyObject *module, *new_module, *dict;

	/* Initialise module */

	module = Py_InitModule("samba", samba_methods);
	dict = PyModule_GetDict(module);

	/* Do samba initialisation */

	py_samba_init();
}
