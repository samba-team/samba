/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright © Jelmer Vernooij <jelmer@samba.org> 2008

   Implementation of the WSGI interface described in PEP0333 
   (http://www.python.org/dev/peps/pep-0333)
   
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

static PyObject *start_response(PyObject *args, PyObject *kwargs)
{
	PyObject *response_header, *exc_info;
	char *status;
	const char *kwnames[] = {
		"status", "response_header", "exc_info", NULL
	};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, (char *)"sOO:start_response", (char **)kwnames, &status, &response_header, &exc_info)) {
		return NULL;
	}

	/* FIXME: response_header, exc_info */

	/* FIXME: Wrap stdout */
	return NULL;
}

static PyObject *create_environ(void)
{
	PyObject *env, *osmodule, *osenviron;

	osmodule = PyImport_ImportModule("os");	
	if (osmodule == NULL)
		return NULL;

	osenviron = PyObject_CallMethod(osmodule, "environ", NULL);

	env = PyDict_Copy(osenviron);

	PyDict_SetItemString(env, "wsgi.input", NULL); /* FIXME */
	PyDict_SetItemString(env, "wsgi.errors", NULL); /* FIXME */
	PyDict_SetItemString(env, "wsgi.version", Py_BuildValue("(i,i)", 1, 0));
	PyDict_SetItemString(env, "wsgi.multithread", Py_False);
	PyDict_SetItemString(env, "wsgi.multiprocess", Py_True);
	PyDict_SetItemString(env, "wsgi.run_once", Py_False);

	/* FIXME: 
	PyDict_SetItemString(env, "wsgi.url_scheme", "http");
	PyDict_SetItemString(env, "wsgi.url_scheme", "https");
	*/

	return env;
}
