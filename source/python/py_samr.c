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

#include "includes.h"
#include "Python.h"

#include "python/py_samr.h"

PyObject *new_samr_connect_hnd_object(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				      POLICY_HND *pol)
{
	samr_connect_hnd_object *o;

	o = PyObject_New(samr_connect_hnd_object, &samr_connect_hnd_type);

	o->cli = cli;
	o->mem_ctx = mem_ctx;
	memcpy(&o->pol, pol, sizeof(POLICY_HND));

	return (PyObject*)o;
}

/* 
 * Exceptions raised by this module 
 */

PyObject *samr_error;		/* This indicates a non-RPC related error
				   such as name lookup failure */

PyObject *samr_ntstatus;	/* This exception is raised when a RPC call
				   returns a status code other than
				   NT_STATUS_OK */

static void py_samr_connect_hnd_dealloc(PyObject* self)
{
	PyObject_Del(self);
}

#if 0

static PyObject *py_samr_connect_hnd_getattr(PyObject *self, char *attrname)
{
	return Py_FindMethod(samr_connect_methods, self, attrname);
}

#endif

PyTypeObject samr_connect_hnd_type = {
	PyObject_HEAD_INIT(NULL)
	0,
	"SAMR Connect Handle",
	sizeof(samr_connect_hnd_object),
	0,
	py_samr_connect_hnd_dealloc, /*tp_dealloc*/
	0,          /*tp_print*/
//	py_samr_connect_hnd_getattr,          /*tp_getattr*/
	0,          /*tp_setattr*/
	0,          /*tp_compare*/
	0,          /*tp_repr*/
	0,          /*tp_as_number*/
	0,          /*tp_as_sequence*/
	0,          /*tp_as_mapping*/
	0,          /*tp_hash */
};

PyTypeObject samr_domain_hnd_type = {
	PyObject_HEAD_INIT(NULL)
	0,
	"SAMR Domain Handle",
	sizeof(samr_connect_hnd_object),
	0,
	py_samr_connect_hnd_dealloc, /*tp_dealloc*/
	0,          /*tp_print*/
//	py_samr_connect_hnd_getattr,          /*tp_getattr*/
	0,          /*tp_setattr*/
	0,          /*tp_compare*/
	0,          /*tp_repr*/
	0,          /*tp_as_number*/
	0,          /*tp_as_sequence*/
	0,          /*tp_as_mapping*/
	0,          /*tp_hash */
};

PyTypeObject samr_user_hnd_type = {
	PyObject_HEAD_INIT(NULL)
	0,
	"SAMR User Handle",
	sizeof(samr_connect_hnd_object),
	0,
	py_samr_connect_hnd_dealloc, /*tp_dealloc*/
	0,          /*tp_print*/
//	py_samr_connect_hnd_getattr,          /*tp_getattr*/
	0,          /*tp_setattr*/
	0,          /*tp_compare*/
	0,          /*tp_repr*/
	0,          /*tp_as_number*/
	0,          /*tp_as_sequence*/
	0,          /*tp_as_mapping*/
	0,          /*tp_hash */
};

PyTypeObject samr_group_hnd_type = {
	PyObject_HEAD_INIT(NULL)
	0,
	"SAMR Group Handle",
	sizeof(samr_connect_hnd_object),
	0,
	py_samr_connect_hnd_dealloc, /*tp_dealloc*/
	0,          /*tp_print*/
//	py_samr_connect_hnd_getattr,          /*tp_getattr*/
	0,          /*tp_setattr*/
	0,          /*tp_compare*/
	0,          /*tp_repr*/
	0,          /*tp_as_number*/
	0,          /*tp_as_sequence*/
	0,          /*tp_as_mapping*/
	0,          /*tp_hash */
};

PyTypeObject samr_alias_hnd_type = {
	PyObject_HEAD_INIT(NULL)
	0,
	"SAMR Alias Handle",
	sizeof(samr_connect_hnd_object),
	0,
	py_samr_connect_hnd_dealloc, /*tp_dealloc*/
	0,          /*tp_print*/
//	py_samr_connect_hnd_getattr,          /*tp_getattr*/
	0,          /*tp_setattr*/
	0,          /*tp_compare*/
	0,          /*tp_repr*/
	0,          /*tp_as_number*/
	0,          /*tp_as_sequence*/
	0,          /*tp_as_mapping*/
	0,          /*tp_hash */
};

static PyMethodDef samr_methods[] = {

	/* Open/close samr connect handles */
	
#if 0
	{ "connect", lsa_open_policy, METH_VARARGS | METH_KEYWORDS, 
	  "Open a connect handle" },
	
	{ "close", lsa_close, METH_VARARGS, "Close a policy handle" },
#endif

	{ NULL }
};

/*
 * Module initialisation 
*/

void initsamr(void)
{
	PyObject *module, *dict;

	/* Initialise module */

	module = Py_InitModule("samr", samr_methods);
	dict = PyModule_GetDict(module);

	samr_error = PyErr_NewException("samr.error", NULL, NULL);
	PyDict_SetItemString(dict, "error", samr_error);

	samr_ntstatus = PyErr_NewException("samr.ntstatus", NULL, NULL);
	PyDict_SetItemString(dict, "ntstatus", samr_ntstatus);

	/* Initialise policy handle object */

	samr_connect_hnd_type.ob_type = &PyType_Type;
	samr_domain_hnd_type.ob_type = &PyType_Type;
	samr_user_hnd_type.ob_type = &PyType_Type;
	samr_group_hnd_type.ob_type = &PyType_Type;
	samr_alias_hnd_type.ob_type = &PyType_Type;

	/* Initialise constants */

//	const_init(dict);

	/* Do samba initialisation */

	py_samba_init();

	setup_logging("samr", True);
	DEBUGLEVEL = 10;
}
