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

PyObject *new_spoolss_policy_hnd_object(struct cli_state *cli, 
					TALLOC_CTX *mem_ctx, POLICY_HND *pol)
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
	  "openprinter(printername, [creds, access]) -> <spoolss hnd object>

Open a printer given by printername in UNC format.  Optionally a dictionary
of (domain, username, password) may be given in which case they are used
when opening the RPC pipe.  An access mask may also be given which defaults
to MAXIMUM_ALLOWED_ACCESS.

Example:

>>> hnd = spoolss.openprinter(\"\\\\\\\\NPSD-PDC2\\\\meanie\")
"},
	
	{ "closeprinter", spoolss_closeprinter, METH_VARARGS, 
	  "closeprinter()

Close a printer handle opened with openprinter or addprinter.

Example:

>>> spoolss.closeprinter(hnd)
"},

	/* Server enumeratation functions */

	{ "enumprinters", spoolss_enumprinters, METH_VARARGS | METH_KEYWORDS,
	  "enumprinters(server, [creds, level, flags]) -> list

Return a list of printers on a print server.  The credentials, info level
and flags may be specified as keyword arguments.

Example:

>>> print spoolss.enumprinters(\"\\\\\\\\npsd-pdc2\")
[{'comment': 'i am a comment', 'printer_name': 'meanie', 'flags': 8388608, 
  'description': 'meanie,Generic / Text Only,i am a location'}, 
 {'comment': '', 'printer_name': 'fileprint', 'flags': 8388608, 
  'description': 'fileprint,Generic / Text Only,'}]
"},

	{ "enumports", spoolss_enumports, METH_VARARGS | METH_KEYWORDS,
	  "enumports(server, [creds, level]) -> list

Return a list of ports on a print server.

Example:

>>> print spoolss.enumports(\"\\\\\\\\npsd-pdc2\")
[{'name': 'LPT1:'}, {'name': 'LPT2:'}, {'name': 'COM1:'}, {'name': 'COM2:'}, 
 {'name': 'FILE:'}, {'name': '\\\\nautilus1\\zpekt3r'}]
"},

	{ "enumprinterdrivers", spoolss_enumprinterdrivers, METH_VARARGS |
	  METH_KEYWORDS, 
"enumprinterdrivers(server, [creds, level, arch]) -> list

Return a list of printer drivers.
"},
	/* Miscellaneous other commands */

	{ "getprinterdriverdir", spoolss_getprinterdriverdir, METH_VARARGS |
	  METH_KEYWORDS, "getprinterdriverdir(server, [creds]) -> string

Return the printer driver directory for a given architecture.  The 
architecture defaults to \"Windows NT x86\".
"},

	/* Other stuff - this should really go into a samba config module
  	   but for the moment let's leave it here. */

	{ "setup_logging", py_setup_logging, METH_VARARGS | METH_KEYWORDS, 
	  "" },

	{ "get_debuglevel", get_debuglevel, METH_VARARGS, "" },
	{ "set_debuglevel", set_debuglevel, METH_VARARGS, "" },

	{ NULL }
};

/* Methods attached to a spoolss handle object */

static PyMethodDef spoolss_hnd_methods[] = {

	/* Printer info */

	{ "getprinter", spoolss_getprinter, METH_VARARGS | METH_KEYWORDS,
	  "getprinter([level]) -> dict

Return a dictionary of print information.  The info level defaults to 1.

Example:

>>> hnd.getprinter()
{'comment': 'i am a comment', 'printer_name': '\\\\NPSD-PDC2\\meanie', 
 'description': '\\\\NPSD-PDC2\\meanie,Generic / Text Only,i am a location',
 'flags': 8388608}
"},

	{ "setprinter", spoolss_setprinter, METH_VARARGS | METH_KEYWORDS,
	  "setprinter(dict) -> None

Set printer information.
"},

	/* Printer drivers */

	{ "getprinterdriver", spoolss_getprinterdriver, 
	  METH_VARARGS | METH_KEYWORDS, 
	  "getprinterdriver([level = 1, arch = \"Windows NT x86\"] -> dict

Return a dictionary of printer driver information.
"},

	/* Forms */

	{ "enumforms", spoolss_enumforms, METH_VARARGS | METH_KEYWORDS,
	  "enumforms([level = 1]) -> list

Return a list of forms supported by a printer.
"},

	{ "setform", spoolss_setform, METH_VARARGS | METH_KEYWORDS,
	  "setform(dict) -> None

Set the form given by the dictionary argument.
"},

	{ "addform", spoolss_addform, METH_VARARGS | METH_KEYWORDS,
	  "Insert a form" },

	{ "getform", spoolss_getform, METH_VARARGS | METH_KEYWORDS,
	  "Fetch form properties" },

	{ "deleteform", spoolss_deleteform, METH_VARARGS | METH_KEYWORDS,
	  "Delete a form" },

        /* Job related methods */

        { "enumjobs", spoolss_enumjobs, METH_VARARGS | METH_KEYWORDS,
          "Enumerate jobs" },

	{ NULL }

};

static void py_policy_hnd_dealloc(PyObject* self)
{
        spoolss_policy_hnd_object *hnd;

        /* Close down policy handle and free talloc context */

        hnd = (spoolss_policy_hnd_object*)self;

        cli_shutdown(hnd->cli);
        talloc_destroy(hnd->mem_ctx);

	PyObject_Del(self);
}

static PyObject *py_policy_hnd_getattr(PyObject *self, char *attrname)
{
	return Py_FindMethod(spoolss_hnd_methods, self, attrname);
}

static char spoolss_type_doc[] = 
"Python wrapper for Windows NT SPOOLSS rpc pipe.";

PyTypeObject spoolss_policy_hnd_type = {
	PyObject_HEAD_INIT(NULL)
	0,
	"spoolss.hnd",
	sizeof(spoolss_policy_hnd_object),
	0,
	py_policy_hnd_dealloc,	/* tp_dealloc*/
	0,			/* tp_print*/
	py_policy_hnd_getattr,	/* tp_getattr*/
	0,			/* tp_setattr*/
	0,			/* tp_compare*/
	0,			/* tp_repr*/
	0,			/* tp_as_number*/
	0,			/* tp_as_sequence*/
	0,			/* tp_as_mapping*/
	0,			/* tp_hash */
	0,			/* tp_call */
	0,			/* tp_str */
	0,			/* tp_getattro */
	0,			/* tp_setattro */
	0,			/* tp_as_buffer*/
	Py_TPFLAGS_DEFAULT,	/* tp_flags */
	spoolss_type_doc,	/* tp_doc */
};

/* Initialise constants */

struct spoolss_const {
	char *name;
	uint32 value;
} spoolss_const_vals[] = {
	
	/* Access permissions */

	{ "MAXIMUM_ALLOWED_ACCESS", MAXIMUM_ALLOWED_ACCESS },
	{ "SERVER_ALL_ACCESS", SERVER_ALL_ACCESS },
	{ "SERVER_READ", SERVER_READ },
	{ "SERVER_WRITE", SERVER_WRITE },
	{ "SERVER_EXECUTE", SERVER_EXECUTE },
	{ "SERVER_ACCESS_ADMINISTER", SERVER_ACCESS_ADMINISTER },
	{ "SERVER_ACCESS_ENUMERATE", SERVER_ACCESS_ENUMERATE },
	{ "PRINTER_ALL_ACCESS", PRINTER_ALL_ACCESS },
	{ "PRINTER_READ", PRINTER_READ },
	{ "PRINTER_WRITE", PRINTER_WRITE },
	{ "PRINTER_EXECUTE", PRINTER_EXECUTE },
	{ "PRINTER_ACCESS_ADMINISTER", PRINTER_ACCESS_ADMINISTER },
	{ "PRINTER_ACCESS_USE", PRINTER_ACCESS_USE },
	{ "JOB_ACCESS_ADMINISTER", JOB_ACCESS_ADMINISTER },
	{ "JOB_ALL_ACCESS", JOB_ALL_ACCESS },
	{ "JOB_READ", JOB_READ },
	{ "JOB_WRITE", JOB_WRITE },
	{ "JOB_EXECUTE", JOB_EXECUTE },
	{ "STANDARD_RIGHTS_ALL_ACCESS", STANDARD_RIGHTS_ALL_ACCESS },
	{ "STANDARD_RIGHTS_EXECUTE_ACCESS", STANDARD_RIGHTS_EXECUTE_ACCESS },
	{ "STANDARD_RIGHTS_READ_ACCESS", STANDARD_RIGHTS_READ_ACCESS },
	{ "STANDARD_RIGHTS_REQUIRED_ACCESS", STANDARD_RIGHTS_REQUIRED_ACCESS },
	{ "STANDARD_RIGHTS_WRITE_ACCESS", STANDARD_RIGHTS_WRITE_ACCESS },

	/* Printer enumeration flags */

	{ "PRINTER_ENUM_DEFAULT", PRINTER_ENUM_DEFAULT },
	{ "PRINTER_ENUM_LOCAL", PRINTER_ENUM_LOCAL },
	{ "PRINTER_ENUM_CONNECTIONS", PRINTER_ENUM_CONNECTIONS },
	{ "PRINTER_ENUM_FAVORITE", PRINTER_ENUM_FAVORITE },
	{ "PRINTER_ENUM_NAME", PRINTER_ENUM_NAME },
	{ "PRINTER_ENUM_REMOTE", PRINTER_ENUM_REMOTE },
	{ "PRINTER_ENUM_SHARED", PRINTER_ENUM_SHARED },
	{ "PRINTER_ENUM_NETWORK", PRINTER_ENUM_NETWORK },

	/* Form types */

	{ "FORM_USER", FORM_USER },
	{ "FORM_BUILTIN", FORM_BUILTIN },
	{ "FORM_PRINTER", FORM_PRINTER },

	/* WERRORs */

	{ "WERR_OK", 0 },
	{ "WERR_BADFILE", 2 },
	{ "WERR_ACCESS_DENIED", 5 },
	{ "WERR_BADFID", 6 },
	{ "WERR_BADFUNC", 1 },
	{ "WERR_INSUFFICIENT_BUFFER", 122 },
	{ "WERR_NO_SUCH_SHARE", 67 },
	{ "WERR_ALREADY_EXISTS", 80 },
	{ "WERR_INVALID_PARAM", 87 },
	{ "WERR_NOT_SUPPORTED", 50 },
	{ "WERR_BAD_PASSWORD", 86 },
	{ "WERR_NOMEM", 8 },
	{ "WERR_INVALID_NAME", 123 },
	{ "WERR_UNKNOWN_LEVEL", 124 },
	{ "WERR_OBJECT_PATH_INVALID", 161 },
	{ "WERR_NO_MORE_ITEMS", 259 },
	{ "WERR_MORE_DATA", 234 },
	{ "WERR_UNKNOWN_PRINTER_DRIVER", 1797 },
	{ "WERR_INVALID_PRINTER_NAME", 1801 },
	{ "WERR_PRINTER_ALREADY_EXISTS", 1802 },
	{ "WERR_INVALID_DATATYPE", 1804 },
	{ "WERR_INVALID_ENVIRONMENT", 1805 },
	{ "WERR_INVALID_FORM_NAME", 1902 },
	{ "WERR_INVALID_FORM_SIZE", 1903 },
	{ "WERR_BUF_TOO_SMALL", 2123 },
	{ "WERR_JOB_NOT_FOUND", 2151 },
	{ "WERR_DEST_NOT_FOUND", 2152 },
	{ "WERR_NOT_LOCAL_DOMAIN", 2320 },
	{ "WERR_PRINTER_DRIVER_IN_USE", 3001 },
	{ "WERR_STATUS_MORE_ENTRIES  ", 0x0105 },

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

	/* Exceptions we can raise */

	spoolss_error = PyErr_NewException("spoolss.error", NULL, NULL);
	PyDict_SetItemString(dict, "error", spoolss_error);

	spoolss_werror = PyErr_NewException("spoolss.werror", NULL, NULL);
	PyDict_SetItemString(dict, "werror", spoolss_werror);

	/* Initialise policy handle object */

	spoolss_policy_hnd_type.ob_type = &PyType_Type;

	PyDict_SetItemString(dict, "spoolss.hnd", 
			     (PyObject *)&spoolss_policy_hnd_type);

	/* Initialise constants */

	const_init(dict);

	/* Do samba initialisation */

	py_samba_init();
}
