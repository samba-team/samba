/* 
   Unix SMB/CIFS implementation.

   Python wrapper for winbind client functions.

   Copyright (C) Tim Potter      2002
   
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

/* 
 * Exceptions raised by this module 
 */

PyObject *winbind_error;	/* A winbind call returned WINBINDD_ERROR */

/* Prototypes from common.h */

NSS_STATUS winbindd_request(int req_type, 
			    struct winbindd_request *request,
			    struct winbindd_response *response);

/* FIXME: grr this needs to be a fn in a library somewhere */

static BOOL parse_domain_user(const char *domuser, fstring domain, 
			      fstring user)
{
	char *p = strchr(domuser,*lp_winbind_separator());

	if (!(p || lp_winbind_use_default_domain()))
		return False;
	
	if(!p && lp_winbind_use_default_domain()) {
		fstrcpy(user, domuser);
		fstrcpy(domain, lp_workgroup());
	} else {
		fstrcpy(user, p+1);
		fstrcpy(domain, domuser);
		domain[PTR_DIFF(p, domuser)] = 0;
	}
	strupper(domain);
	return True;
}

/*
 * Name <-> SID conversion
 */

/* Convert a name to a sid */

static PyObject *winbind_name_to_sid(PyObject *self, PyObject *args)

{
	struct winbindd_request request;
	struct winbindd_response response;
	PyObject *result;
	char *name, *p;

	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* FIXME: use winbind separator */

	if ((p = strchr(name, '\\'))) {
		*p = 0;
		fstrcpy(request.data.name.dom_name, name);
		fstrcpy(request.data.name.name, p + 1);
	} else {
		fstrcpy(request.data.name.dom_name, lp_workgroup());
		fstrcpy(request.data.name.name, name);
	}

	if (winbindd_request(WINBINDD_LOOKUPNAME, &request, &response)  
	    != NSS_STATUS_SUCCESS) {
		PyErr_SetString(winbind_error, "lookup failed");
		return NULL;
	}

	result = PyString_FromString(response.data.sid.sid);

	return result;
}

/* Convert a sid to a name */

static PyObject *winbind_sid_to_name(PyObject *self, PyObject *args)
{
	struct winbindd_request request;
	struct winbindd_response response;
	PyObject *result;
	char *sid, *name;

	if (!PyArg_ParseTuple(args, "s", &sid))
		return NULL;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	fstrcpy(request.data.sid, sid);

	if (winbindd_request(WINBINDD_LOOKUPSID, &request, &response)  
	    != NSS_STATUS_SUCCESS) {
		PyErr_SetString(winbind_error, "lookup failed");
		return NULL;
	}

	/* FIXME: use actual winbind separator */

	asprintf(&name, "%s%c%s", response.data.name.dom_name,
		 '\\', response.data.name.name);

	result = PyString_FromString(name);

	free(name);

	return result;
}

/*
 * Method dispatch table
 */

static PyMethodDef winbind_methods[] = {

	/* Name <-> SID conversion */

	{ "name_to_sid", winbind_name_to_sid, METH_VARARGS,
	  "Convert a name to a sid" },

	{ "sid_to_name", winbind_sid_to_name, METH_VARARGS,
	  "Convert a sid to a name" },

	{ NULL }
};

/*
 * Module initialisation 
 */

void initwinbind(void)
{
	PyObject *module, *dict;

	/* Initialise module */

	module = Py_InitModule("winbind", winbind_methods);
	dict = PyModule_GetDict(module);

	winbind_error = PyErr_NewException("winbind.error", NULL, NULL);
	PyDict_SetItemString(dict, "error", winbind_error);
}
