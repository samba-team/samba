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

/* Open a printer */

PyObject *spoolss_openprinter(PyObject *self, PyObject *args, PyObject *kw)
{
	char *full_name, *computer_name = NULL;
	TALLOC_CTX *mem_ctx;
	POLICY_HND hnd;
	WERROR werror;
	PyObject *result = NULL, *creds = NULL;
	static char *kwlist[] = { "printername", "creds", "access", NULL };
	uint32 desired_access = MAXIMUM_ALLOWED_ACCESS;
	struct cli_state *cli;

	if (!PyArg_ParseTupleAndKeywords(
		args, kw, "s|O!i", kwlist, &full_name, &PyDict_Type, &creds,
		&desired_access)) {

		goto done;
	}

	/* FIXME: Return name format exception for names without a UNC
	   prefix */ 

	computer_name = strdup(full_name + 2);

	if (strchr(computer_name, '\\')) {
		char *c = strchr(computer_name, '\\');
		*c = 0;
	}

	if (!(cli = open_pipe_creds(computer_name, creds, 
				    cli_spoolss_initialise, NULL))) {

		/* Error state set in open_pipe_creds() */

		goto done;
	}

	if (!(mem_ctx = talloc_init())) {
		PyErr_SetString(spoolss_error, 
				"unable to initialise talloc context\n");
		goto done;
	}

	werror = cli_spoolss_open_printer_ex(
		cli, mem_ctx, full_name, "", desired_access, computer_name, 
		"", &hnd);

	if (!W_ERROR_IS_OK(werror)) {
		cli_shutdown(cli);
		SAFE_FREE(cli);
		PyErr_SetObject(spoolss_werror, py_werror_tuple(werror));
		goto done;
	}

	result = new_spoolss_policy_hnd_object(cli, mem_ctx, &hnd);

 done:
	SAFE_FREE(computer_name);

	return result;
}

/* Close a printer */

PyObject *spoolss_closeprinter(PyObject *self, PyObject *args)
{
	PyObject *po;
	spoolss_policy_hnd_object *hnd;
	WERROR result;

	/* Parse parameters */

	if (!PyArg_ParseTuple(args, "O!", &spoolss_policy_hnd_type, &po))
		return NULL;

	hnd = (spoolss_policy_hnd_object *)po;

	/* Call rpc function */

	result = cli_spoolss_close_printer(hnd->cli, hnd->mem_ctx, &hnd->pol);

	/* Return value */

	Py_INCREF(Py_None);
	return Py_None;	
}

/* Fetch printer information */

PyObject *spoolss_getprinter(PyObject *self, PyObject *args, PyObject *kw)
{
	spoolss_policy_hnd_object *hnd = (spoolss_policy_hnd_object *)self;
	WERROR werror;
	PyObject *result = NULL;
	PRINTER_INFO_CTR ctr;
	int level = 1;
	uint32 needed;
	static char *kwlist[] = {"level", NULL};

	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(args, kw, "|i", kwlist, &level))
		return NULL;
	
	/* Call rpc function */
	
	werror = cli_spoolss_getprinter(
		hnd->cli, hnd->mem_ctx, 0, &needed, &hnd->pol, level, &ctr);

	if (W_ERROR_V(werror) == ERRinsufficientbuffer)
		werror = cli_spoolss_getprinter(
			hnd->cli, hnd->mem_ctx, needed, NULL, &hnd->pol,
			level, &ctr);

	/* Return value */

	if (!W_ERROR_IS_OK(werror)) {
		PyErr_SetObject(spoolss_werror,
				PyInt_FromLong(W_ERROR_V(werror)));
		return NULL;
	}

	result = Py_None;

	switch (level) {
		
	case 0:
		py_from_PRINTER_INFO_0(&result, ctr.printers_0);
		break;

	case 1:
		py_from_PRINTER_INFO_1(&result, ctr.printers_1);
		break;

	case 2:
		py_from_PRINTER_INFO_2(&result, ctr.printers_2);
		break;

	case 3:
		py_from_PRINTER_INFO_3(&result, ctr.printers_3);
		break;
	}

	PyDict_SetItemString(result, "level", PyInt_FromLong(level));

	Py_INCREF(result);
	return result;
}

/* Set printer information */

PyObject *spoolss_setprinter(PyObject *self, PyObject *args, PyObject *kw)
{
	spoolss_policy_hnd_object *hnd = (spoolss_policy_hnd_object *)self;
	WERROR werror;
	PyObject *info, *level_obj;
	PRINTER_INFO_CTR ctr;
	uint32 level;
	static char *kwlist[] = {"dict", NULL};
	union {
		PRINTER_INFO_2 printers_2;
		PRINTER_INFO_3 printers_3;
	} pinfo;

	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(args, kw, "O!", kwlist, 
					 &PyDict_Type, &info))
		return NULL;
	
	/* Check dictionary contains a level */

	if ((level_obj = PyDict_GetItemString(info, "level"))) {

		if (!PyInt_Check(level_obj)) {
			DEBUG(0, ("** level not an integer\n"));
			goto error;
		}

		level = PyInt_AsLong(level_obj);

		/* Only level 2, 3 supported by NT */

		if (level != 2 && level != 3) {
			DEBUG(0, ("** unsupported info level\n"));
			goto error;
		}

	} else {
		DEBUG(0, ("** no level info\n"));
	error:
		PyErr_SetString(spoolss_error, "invalid info");
		return NULL;
	}

	/* Fill in printer info */

	ZERO_STRUCT(ctr);

	switch (level) {
	case 2:
		ctr.printers_2 = &pinfo.printers_2;

		if (!py_to_PRINTER_INFO_2(&pinfo.printers_2, info,
					  hnd->mem_ctx))
			goto error;

		break;
	default:
		PyErr_SetString(spoolss_error, "unsupported info level");
		return NULL;
	}

	/* Call rpc function */
	
	werror = cli_spoolss_setprinter(hnd->cli, hnd->mem_ctx, &hnd->pol,
					level, &ctr, 0);

	/* Return value */

	if (!W_ERROR_IS_OK(werror)) {
		PyErr_SetObject(spoolss_werror, py_werror_tuple(werror));
		return NULL;
	}

	Py_INCREF(Py_None);
	return Py_None;
}

/* Enumerate printers */

PyObject *spoolss_enumprinters(PyObject *self, PyObject *args, PyObject *kw)
{
	WERROR werror;
	PyObject *result, *creds = NULL;
	PRINTER_INFO_CTR ctr;
	int level = 1, flags = PRINTER_ENUM_LOCAL, i;
	uint32 needed, num_printers;
	static char *kwlist[] = {"server", "name", "level", "flags", 
				 "creds", NULL};
	TALLOC_CTX *mem_ctx = NULL;
	struct cli_state *cli = NULL;
	char *server, *name = NULL;

	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(args, kw, "s|siiO!", kwlist, 
					 &server, &name, &level, &flags, 
					 &PyDict_Type, &creds))
		return NULL;
	
	if (server[0] == '\\' && server[1] == '\\')
		server += 2;

	mem_ctx = talloc_init();
	cli = open_pipe_creds(server, creds, cli_spoolss_initialise, NULL);

	/* Call rpc function */
	
	werror = cli_spoolss_enum_printers(
		cli, mem_ctx, 0, &needed, flags, level,
		&num_printers, &ctr);

	if (W_ERROR_V(werror) == ERRinsufficientbuffer)
		werror = cli_spoolss_enum_printers(
			cli, mem_ctx, needed, NULL, flags, level,
			&num_printers, &ctr);

	/* Return value */
	
	if (!W_ERROR_IS_OK(werror)) {
		PyErr_SetObject(spoolss_werror,
				PyInt_FromLong(W_ERROR_V(werror)));
		return NULL;
	}

	result = PyList_New(num_printers);

	switch (level) {
	case 0: 
		for (i = 0; i < num_printers; i++) {
			PyObject *value;

			py_from_PRINTER_INFO_0(&value, &ctr.printers_0[i]);

			PyList_SetItem(result, i, value);
		}

		break;
	case 1:
		for(i = 0; i < num_printers; i++) {
			PyObject *value;

			py_from_PRINTER_INFO_1(&value, &ctr.printers_1[i]);

			PyList_SetItem(result, i, value);
		}
		
		break;
	case 2:
		for(i = 0; i < num_printers; i++) {
			PyObject *value;

			py_from_PRINTER_INFO_2(&value, &ctr.printers_2[i]);

			PyList_SetItem(result, i, value);
		}
		
		break;
	case 3:
		for(i = 0; i < num_printers; i++) {
			PyObject *value;

			py_from_PRINTER_INFO_3(&value, &ctr.printers_3[i]);

			PyList_SetItem(result, i, value);
		}
		
		break;
	}

	Py_INCREF(result);
	return result;
}
