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

#include "python/py_spoolss.h"

/* Exceptions this module can raise */

PyObject *spoolss_error, *spoolss_werror;

/*
 * Routines to convert from python hashes to Samba structures
 */

struct cli_state *open_pipe_creds(char *system_name, PyObject *creds, 
				  cli_pipe_fn *connect_fn,
				  struct cli_state *cli)
{
	struct ntuser_creds nt_creds;

	if (!cli) {
		cli = (struct cli_state *)malloc(sizeof(struct cli_state));
		if (!cli)
			return NULL;
	}

	ZERO_STRUCTP(cli);

	/* Extract credentials from the python dictionary and initialise
	   the ntuser_creds struct from them. */

	ZERO_STRUCT(nt_creds);
	nt_creds.pwd.null_pwd = True;

	if (creds) {
		char *username, *password, *domain;
		PyObject *username_obj, *password_obj, *domain_obj;

		/* Check credentials passed are valid.  This means the
		   username, domain and password keys must exist and be
		   string objects. */

		username_obj = PyDict_GetItemString(creds, "username");
		domain_obj = PyDict_GetItemString(creds, "domain");
		password_obj = PyDict_GetItemString(creds, "password");

		if (!username_obj || !domain_obj || !password_obj) {
		error:
			PyErr_SetString(spoolss_error, "invalid credentials");
			return NULL;
		}

		if (!PyString_Check(username_obj) || 
		    !PyString_Check(domain_obj) || 
		    !PyString_Check(password_obj))
			goto error;

		username = PyString_AsString(username_obj);
		domain = PyString_AsString(domain_obj);
		password = PyString_AsString(password_obj);

		if (!username || !domain || !password)
			goto error;

		/* Initialise nt_creds structure with passed creds */

		fstrcpy(nt_creds.user_name, username);
		fstrcpy(nt_creds.domain, domain);

		if (lp_encrypted_passwords())
			pwd_make_lm_nt_16(&nt_creds.pwd, password);
		else
			pwd_set_cleartext(&nt_creds.pwd, password);

		nt_creds.pwd.null_pwd = False;
	}

	/* Now try to connect */

	connect_fn(cli, system_name, &nt_creds);

	return cli;
}

PyObject *new_policy_hnd_object(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
				POLICY_HND *pol)
{
	spoolss_policy_hnd_object *o;

	o = PyObject_New(spoolss_policy_hnd_object, &spoolss_policy_hnd_type);

	o->cli = cli;
	o->mem_ctx = mem_ctx;
	memcpy(&o->pol, pol, sizeof(POLICY_HND));

	return (PyObject*)o;
}
     
/* 
 * Method dispatch table
 */

static PyMethodDef spoolss_methods[] = {

	/* Open/close printer handles */
	
	{ "openprinter", spoolss_openprinter, METH_VARARGS | METH_KEYWORDS, 
	  "Open printer" },
	
	{ "closeprinter", spoolss_closeprinter, METH_VARARGS, 
	  "Close printer" },

	/* Server enumeratation functions */

	{ "enumprinters", spoolss_enumprinters, METH_VARARGS | METH_KEYWORDS,
	  "Enumerate printers" },

	{ "enumports", spoolss_enumports, METH_VARARGS | METH_KEYWORDS,
	  "Enumerate ports" },

	{ "enumprinterdrivers", spoolss_enumprinterdrivers, METH_VARARGS |
	  METH_KEYWORDS, "Enumerate printer drivers" },

	/* Miscellaneous other commands */

	{ "getprinterdriverdir", spoolss_getprinterdriverdir, METH_VARARGS |
	  METH_KEYWORDS, "Get printer driver directory" },

	{ NULL }
};

/* Methods attached to a spoolss handle object */

static PyMethodDef spoolss_hnd_methods[] = {

	/* Printer info */

	{ "getprinter", spoolss_getprinter, METH_VARARGS | METH_KEYWORDS,
	  "Fetch printer information" },

	{ "setprinter", spoolss_setprinter, METH_VARARGS | METH_KEYWORDS,
	  "Set printer information" },

	/* Printer drivers */

	{ "getprinterdriver", spoolss_getprinterdriver, 
	  METH_VARARGS | METH_KEYWORDS, "Fetch printer driver" },

	/* Forms */

	{ "enumforms", spoolss_enumforms, METH_VARARGS | METH_KEYWORDS,
	  "Enumerate forms" },

	{ "setform", spoolss_setform, METH_VARARGS | METH_KEYWORDS,
	  "Modify properties of a form" },

	{ "addform", spoolss_addform, METH_VARARGS | METH_KEYWORDS,
	  "Insert a form" },

	{ "getform", spoolss_getform, METH_VARARGS | METH_KEYWORDS,
	  "Fetch form properties" },

	{ "deleteform", spoolss_deleteform, METH_VARARGS | METH_KEYWORDS,
	  "Delete a form" },

	{ NULL }

};

static void py_policy_hnd_dealloc(PyObject* self)
{
	PyObject_Del(self);
}

static PyObject *py_policy_hnd_getattr(PyObject *self, char *attrname)
{
	return Py_FindMethod(spoolss_hnd_methods, self, attrname);
}

PyTypeObject spoolss_policy_hnd_type = {
	PyObject_HEAD_INIT(NULL)
	0,
	"Spoolss Policy Handle",
	sizeof(spoolss_policy_hnd_object),
	0,
	py_policy_hnd_dealloc, /*tp_dealloc*/
	0,          /*tp_print*/
	py_policy_hnd_getattr,          /*tp_getattr*/
	0,          /*tp_setattr*/
	0,          /*tp_compare*/
	0,          /*tp_repr*/
	0,          /*tp_as_number*/
	0,          /*tp_as_sequence*/
	0,          /*tp_as_mapping*/
	0,          /*tp_hash */
};

/* Initialise constants */

struct spoolss_const {
	char *name;
	uint32 value;
} spoolss_const_vals[] = {
	
	/* Access permissions */

	{ "MAXIMUM_ALLOWED_ACCESS", MAXIMUM_ALLOWED_ACCESS },
	{ "SERVER_ALL_ACCESS", SERVER_ALL_ACCESS },
	{ "PRINTER_ALL_ACCESS", PRINTER_ALL_ACCESS },

	/* Printer enumeration flags */

	{ "PRINTER_ENUM_DEFAULT", PRINTER_ENUM_DEFAULT },
	{ "PRINTER_ENUM_LOCAL", PRINTER_ENUM_LOCAL },
	{ "PRINTER_ENUM_CONNECTIONS", PRINTER_ENUM_CONNECTIONS },
	{ "PRINTER_ENUM_FAVORITE", PRINTER_ENUM_FAVORITE },
	{ "PRINTER_ENUM_NAME", PRINTER_ENUM_NAME },
	{ "PRINTER_ENUM_REMOTE", PRINTER_ENUM_REMOTE },
	{ "PRINTER_ENUM_SHARED", PRINTER_ENUM_SHARED },
	{ "PRINTER_ENUM_NETWORK", PRINTER_ENUM_NETWORK },

	{ NULL },
};

static void const_init(PyObject *dict)
{
	struct spoolss_const *tmp;
	PyObject *obj;

	for (tmp = spoolss_const_vals; tmp->name; tmp++) {
		obj = PyInt_FromLong(tmp->value);
		PyDict_SetItemString(dict, tmp->name, obj);
		Py_DECREF(obj);
	}
}

/* Module initialisation */

void initspoolss(void)
{
	PyObject *module, *dict;

	/* Initialise module */

	module = Py_InitModule("spoolss", spoolss_methods);
	dict = PyModule_GetDict(module);

	/* Make spools_error global an exception we can raise when an error
	   occurs. */

	spoolss_error = PyErr_NewException("spoolss.error", NULL, NULL);
	PyDict_SetItemString(dict, "error", spoolss_error);

	spoolss_werror = PyErr_NewException("spoolss.werror", NULL, NULL);
	PyDict_SetItemString(dict, "werror", spoolss_werror);

	/* Initialise policy handle object */

	spoolss_policy_hnd_type.ob_type = &PyType_Type;

	/* Initialise constants */

	const_init(dict);

	/* Do samba initialisation */

	py_samba_init();
}
