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

#include "python/py_smb.h"

/* 
 * Exceptions raised by this module 
 */

PyObject *smb_ntstatus;		/* This exception is raised when a RPC call
				   returns a status code other than
				   NT_STATUS_OK */


/*
 * Method dispatch tables
 */

static PyMethodDef smb_methods[] = {
	{ NULL }
};

/* Create a new cli_state python object */

PyObject *new_cli_state_object(struct cli_state *cli)
{
	cli_state_object *o;

	o = PyObject_New(cli_state_object, &cli_state_type);

	o->cli = cli;

	return (PyObject*)o;
}

static void py_cli_state_dealloc(PyObject* self)
{
	PyObject_Del(self);
}

static PyObject *py_cli_state_getattr(PyObject *self, char *attrname)
{
	return Py_FindMethod(smb_methods, self, attrname);
}

PyTypeObject cli_state_type = {
	PyObject_HEAD_INIT(NULL)
	0,
	"SMB client connection",
	sizeof(cli_state_object),
	0,
	py_cli_state_dealloc, /*tp_dealloc*/
	0,          /*tp_print*/
	py_cli_state_getattr,          /*tp_getattr*/
	0,          /*tp_setattr*/
	0,          /*tp_compare*/
	0,          /*tp_repr*/
	0,          /*tp_as_number*/
	0,          /*tp_as_sequence*/
	0,          /*tp_as_mapping*/
	0,          /*tp_hash */
};

/*
 * Module initialisation 
 */

void initsmb(void)
{
	PyObject *module, *dict;

	/* Initialise module */

	module = Py_InitModule("smb", smb_methods);
	dict = PyModule_GetDict(module);

	smb_ntstatus = PyErr_NewException("smb.ntstatus", NULL, NULL);
	PyDict_SetItemString(dict, "ntstatus", smb_ntstatus);

	/* Initialise policy handle object */

	cli_state_type.ob_type = &PyType_Type;

	/* Do samba initialisation */

	py_samba_init();

	setup_logging("smb", True);
	DEBUGLEVEL = 10;
}
