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

/* Return a tuple of (error code, error string) from a WERROR */

PyObject *py_werror_tuple(WERROR werror)
{
	return Py_BuildValue("is", W_ERROR_V(werror), 
			     dos_errstr(werror));
}

/* Return a tuple of (error code, error string) from a WERROR */

PyObject *py_ntstatus_tuple(NTSTATUS ntstatus)
{
	return Py_BuildValue("is", NT_STATUS_V(ntstatus), 
			     nt_errstr(ntstatus));
}

/* Initialise samba client routines */

static BOOL initialised;

void py_samba_init(void)
{
	if (initialised)
		return;

	/* Load configuration file */

	if (!lp_load(dyn_CONFIGFILE, True, False, False))
		fprintf(stderr, "Can't load %s\n", dyn_CONFIGFILE);

	/* Misc other stuff */

	load_interfaces();
	
	initialised = True;
}

/* Debuglevel routines */

PyObject *get_debuglevel(PyObject *self, PyObject *args)
{
	PyObject *debuglevel;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	debuglevel = PyInt_FromLong(DEBUGLEVEL);

	return debuglevel;
}

PyObject *set_debuglevel(PyObject *self, PyObject *args)
{
	int debuglevel;

	if (!PyArg_ParseTuple(args, "i", &debuglevel))
		return NULL;

	DEBUGLEVEL = debuglevel;

	Py_INCREF(Py_None);
	return Py_None;
}

/* Initialise logging */

PyObject *py_setup_logging(PyObject *self, PyObject *args, PyObject *kw)
{
	BOOL interactive = False;
	char *logfilename = NULL;
	static char *kwlist[] = {"interactive", "logfilename", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kw, "|is", kwlist,
					 &interactive, &logfilename))
		return NULL;
	
	if (interactive && logfilename) {
		PyErr_SetString(PyExc_RuntimeError,
				"can't be interactive and set log file name");
		return NULL;
	}

	if (interactive)
		setup_logging("spoolss", True);

	if (logfilename) {
		lp_set_logfile(logfilename);
		setup_logging(logfilename, False);
		reopen_logs();
	}

	Py_INCREF(Py_None);
	return Py_None;
}
