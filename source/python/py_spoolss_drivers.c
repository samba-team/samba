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

/* Enumerate printer drivers */

PyObject *spoolss_enumprinterdrivers(PyObject *self, PyObject *args,
				     PyObject *kw)
{
	WERROR werror;
	PyObject *result = Py_None, *creds = NULL;
	PRINTER_DRIVER_CTR ctr;
	int level = 1, i;
	uint32 needed, num_drivers;
	char *arch = "Windows NT x86", *server, *errstr;
	static char *kwlist[] = {"server", "creds", "level", "arch", NULL};
	struct cli_state *cli = NULL;
	TALLOC_CTX *mem_ctx = NULL;
	
	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(
		    args, kw, "s|O!is", kwlist, &server, &PyDict_Type,
		    &creds, &level, &arch))
		return NULL;
	
	/* Call rpc function */
	
	if (!(cli = open_pipe_creds(
		      server, creds, cli_spoolss_initialise, &errstr))) {
		PyErr_SetString(spoolss_error, errstr);
		free(errstr);
		goto done;
	}

	if (!(mem_ctx = talloc_init())) {
		PyErr_SetString(
			spoolss_error, "unable to initialise talloc context\n");
		goto done;
	}	

	werror = cli_spoolss_enumprinterdrivers(
		cli, mem_ctx, 0, &needed, level, arch,
		&num_drivers, &ctr);

	if (W_ERROR_V(werror) == ERRinsufficientbuffer)
		werror = cli_spoolss_enumprinterdrivers(
			cli, mem_ctx, needed, NULL, level, arch, 
			&num_drivers, &ctr);

	if (!W_ERROR_IS_OK(werror)) {
		PyErr_SetObject(spoolss_werror, py_werror_tuple(werror));
		goto done;
	}

	/* Return value */
	
	switch (level) {
	case 1:
		result = PyDict_New();
		
		for (i = 0; i < num_drivers; i++) {
			PyObject *value;
			fstring name;
			
			rpcstr_pull(name, ctr.info1[i].name.buffer,
				    sizeof(fstring), -1, STR_TERMINATE);

			py_from_DRIVER_INFO_1(&value, &ctr.info1[i]);

			PyDict_SetItemString(
				value, "level", PyInt_FromLong(1));

			PyDict_SetItemString(result, name, value);
		}
		
		break;
	case 2: 
		result = PyDict_New();

		for(i = 0; i < num_drivers; i++) {
			PyObject *value;
			fstring name;

			rpcstr_pull(name, ctr.info2[i].name.buffer,
				    sizeof(fstring), -1, STR_TERMINATE);

			py_from_DRIVER_INFO_2(&value, &ctr.info2[i]);

			PyDict_SetItemString(
				value, "level", PyInt_FromLong(2));

			PyDict_SetItemString(result, name, value);
		}

		break;
	case 3: 
		result = PyDict_New();

		for(i = 0; i < num_drivers; i++) {
			PyObject *value;
			fstring name;

			rpcstr_pull(name, ctr.info3[i].name.buffer,
				    sizeof(fstring), -1, STR_TERMINATE);

			py_from_DRIVER_INFO_3(&value, &ctr.info3[i]);

			PyDict_SetItemString(
				value, "level", PyInt_FromLong(3));

			PyDict_SetItemString(result, name, value);
		}

		break;
	case 6: 
		result = PyDict_New();

		for(i = 0; i < num_drivers; i++) {
			PyObject *value;
			fstring name;

			rpcstr_pull(name, ctr.info6[i].name.buffer,
				    sizeof(fstring), -1, STR_TERMINATE);

			py_from_DRIVER_INFO_6(&value, &ctr.info6[i]);

			PyDict_SetItemString(
				value, "level", PyInt_FromLong(6));

			PyList_SetItem(result, i, value);
		}

		break;
	default:
		PyErr_SetString(spoolss_error, "unknown info level returned");
		result = NULL;
		break;
	}
	
 done:
	if (cli)
		cli_shutdown(cli);

	if (mem_ctx)
		talloc_destroy(mem_ctx);

	Py_INCREF(result);
	return result;
}

/* Fetch printer driver */

PyObject *spoolss_hnd_getprinterdriver(PyObject *self, PyObject *args,
				   PyObject *kw)
{
	spoolss_policy_hnd_object *hnd = (spoolss_policy_hnd_object *)self;
	WERROR werror;
	PyObject *result = Py_None;
	PRINTER_DRIVER_CTR ctr;
	int level = 1;
	uint32 needed;
	char *arch = "Windows NT x86";
	static char *kwlist[] = {"level", "arch", NULL};

	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(
		    args, kw, "|is", kwlist, &level, &arch))
		return NULL;

	/* Call rpc function */

	werror = cli_spoolss_getprinterdriver(
		hnd->cli, hnd->mem_ctx, 0, &needed, &hnd->pol, level,
		arch, &ctr);

	if (W_ERROR_V(werror) == ERRinsufficientbuffer)
		werror = cli_spoolss_getprinterdriver(
			hnd->cli, hnd->mem_ctx, needed, NULL, &hnd->pol,
			level, arch, &ctr);

	if (!W_ERROR_IS_OK(werror)) {
		PyErr_SetObject(spoolss_werror, py_werror_tuple(werror));
		return NULL;
	}

	/* Return value */
	
	switch (level) {
	case 1:
		py_from_DRIVER_INFO_1(&result, ctr.info1);
		break;
	case 2: 
		py_from_DRIVER_INFO_2(&result, ctr.info2);
		break;
	case 6:
		py_from_DRIVER_INFO_6(&result,  ctr.info6);
		break;
	default:
		break;
	}
	
	Py_INCREF(result);
	return result;
}

/* Fetch printer driver directory */

PyObject *spoolss_getprinterdriverdir(PyObject *self, PyObject *args, 
				      PyObject *kw)
{
	WERROR werror;
	PyObject *result = Py_None, *creds = NULL;
	DRIVER_DIRECTORY_CTR ctr;
	uint32 needed, level;
	char *arch = "Windows NT x86", *server, *errstr;
	static char *kwlist[] = {"server", "level", "arch", "creds", NULL};
	struct cli_state *cli = NULL;
	TALLOC_CTX *mem_ctx = NULL;

	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(
		    args, kw, "s|isO!", kwlist, &server, &level,
		    &arch, &PyDict_Type, &creds))
		return NULL;

	/* Call rpc function */

	if (!(cli = open_pipe_creds(
		      server, creds, cli_spoolss_initialise, &errstr))) {
		PyErr_SetString(spoolss_error, errstr);
		free(errstr);
		goto done;
	}
	
	if (!(mem_ctx = talloc_init())) {
		PyErr_SetString(
			spoolss_error, "unable to initialise talloc context\n");
		goto done;
	}	

	werror = cli_spoolss_getprinterdriverdir(
		cli, mem_ctx, 0, &needed, level, arch, &ctr);

	if (W_ERROR_V(werror) == ERRinsufficientbuffer)
		werror = cli_spoolss_getprinterdriverdir(
			cli, mem_ctx, needed, NULL, level, arch, &ctr);

	if (!W_ERROR_IS_OK(werror)) {
		PyErr_SetObject(spoolss_werror, py_werror_tuple(werror));
		return NULL;
	}

	/* Return value */
	
	switch (level) {
	case 1:
		py_from_DRIVER_DIRECTORY_1(&result, ctr.info1);
		break;
	}
	
 done:
	if (cli)
		cli_shutdown(cli);
	
	if (mem_ctx)
		talloc_destroy(mem_ctx);

	Py_INCREF(result);
	return result;
}

PyObject *spoolss_addprinterdriver(PyObject *self, PyObject *args,
				   PyObject *kw)
{
	static char *kwlist[] = { "server", "info", "creds", NULL };
	char *server, *errstr;
	uint32 level;
	PyObject *info, *result = NULL, *creds = NULL, *level_obj;
	WERROR werror;
	TALLOC_CTX *mem_ctx;
	struct cli_state *cli;
	PRINTER_DRIVER_CTR ctr;
	union {
		DRIVER_INFO_3 driver_3;
	} dinfo;

	if (!PyArg_ParseTupleAndKeywords(
		    args, kw, "sO!|O!", kwlist, &server, &PyDict_Type,
		    &info, &PyDict_Type, &creds))
		return NULL;
	
	if (server[0] == '\\' && server[1] == '\\')
		server += 2;

	if (!(mem_ctx = talloc_init())) {
		PyErr_SetString(
			spoolss_error, "unable to initialise talloc context\n");
		return NULL;
	}

	if (!(cli = open_pipe_creds(
		      server, creds, cli_spoolss_initialise, &errstr))) {
		PyErr_SetString(spoolss_error, errstr);
		free(errstr);
		goto done;
	}

	if ((level_obj = PyDict_GetItemString(info, "level"))) {

		if (!PyInt_Check(level_obj)) {
			PyErr_SetString(spoolss_error, 
					"level not an integer");
			goto done;
		}

		level = PyInt_AsLong(level_obj);

		/* Only level 2, 3 supported by NT */

		if (level != 3) {
			PyErr_SetString(spoolss_error,
					"unsupported info level");
			goto done;
		}

	} else {
		PyErr_SetString(spoolss_error, "no info level present");
		goto done;
	}
	
	ZERO_STRUCT(ctr);
	
	switch(level) {
	case 3:
		ctr.info3 = &dinfo.driver_3;

		if (!py_to_DRIVER_INFO_3(&dinfo.driver_3, info)) {
			PyErr_SetString(spoolss_error,
					"error converting to driver info 3");
			goto done;
		}

		break;
	default:
		PyErr_SetString(spoolss_error, "unsupported info level");
		goto done;
	}

	werror = cli_spoolss_addprinterdriver(cli, mem_ctx, level, &ctr);

	if (!W_ERROR_IS_OK(werror)) {
		PyErr_SetObject(spoolss_werror, py_werror_tuple(werror));
		goto done;
	}

	Py_INCREF(Py_None);
	result = Py_None;

done:
	cli_shutdown(cli);
	talloc_destroy(mem_ctx);
	
	return result;
	
}

PyObject *spoolss_addprinterdriverex(PyObject *self, PyObject *args,
					     PyObject *kw)
{
	/* Not supported by Samba server */
	
	PyErr_SetString(spoolss_error, "Not implemented");
	return NULL;
}
	
PyObject *spoolss_deleteprinterdriver(PyObject *self, PyObject *args,
				      PyObject *kw)
{
	PyErr_SetString(spoolss_error, "Not implemented");
	return NULL;
}

PyObject *spoolss_deleteprinterdriverex(PyObject *self, PyObject *args,
					PyObject *kw)
{
	PyErr_SetString(spoolss_error, "Not implemented");
	return NULL;
}
