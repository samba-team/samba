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

static BOOL py_from_printerdata(PyObject **dict, char *value,
				uint32 data_type, char *data, 
				uint32 data_size) 
{
	*dict = PyDict_New();

	PyDict_SetItemString(*dict, "type", Py_BuildValue("i", data_type));
	PyDict_SetItemString(*dict, "value", Py_BuildValue("s", value));

	PyDict_SetItemString(*dict, "data", 
			     Py_BuildValue("s#", data, data_size));

	return True;
}

static BOOL py_to_printerdata(char **value, uint32 *data_type, 
			      char **data, uint32 *data_size, 
			      PyObject *dict)
{
	PyObject *obj;

	if ((obj = PyDict_GetItemString(dict, "type"))) {

		if (!PyInt_Check(obj)) {
			PyErr_SetString(spoolss_error,
					"type not an integer");
			return False;
		}

		*data_type = PyInt_AsLong(obj);
	} else {
		PyErr_SetString(spoolss_error, "no type present");
		return False;
	}

	if ((obj = PyDict_GetItemString(dict, "value"))) {

		if (!PyString_Check(obj)) {
			PyErr_SetString(spoolss_error,
					"value not a string");
			return False;
		}

		*value = PyString_AsString(obj);
	} else {
		PyErr_SetString(spoolss_error, "no value present");
		return False;
	}

	if ((obj = PyDict_GetItemString(dict, "data"))) {

		if (!PyString_Check(obj)) {
			PyErr_SetString(spoolss_error,
					"data not a string");
			return False;
		}

		*data = PyString_AsString(obj);
		*data_size = PyString_Size(obj);
	} else {
		PyErr_SetString(spoolss_error, "no data present");
		return False;
	}

	return True;
}

PyObject *spoolss_getprinterdata(PyObject *self, PyObject *args, PyObject *kw)
{
	spoolss_policy_hnd_object *hnd = (spoolss_policy_hnd_object *)self;
	static char *kwlist[] = { "value", NULL };
	char *value;
	WERROR werror;
	uint32 needed, data_type, data_size;
	char *data;
	PyObject *result;

	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(args, kw, "s", kwlist, &value))
	    return NULL;

	/* Call rpc function */

	werror = cli_spoolss_getprinterdata(
		hnd->cli, hnd->mem_ctx, 0, &needed, &hnd->pol, value,
		&data_type, &data, &data_size);

	if (W_ERROR_V(werror) == ERRmoredata) 
		werror = cli_spoolss_getprinterdata(
			hnd->cli, hnd->mem_ctx, needed, NULL, &hnd->pol, value,
			&data_type, &data, &data_size);

	if (!W_ERROR_IS_OK(werror)) {
		PyErr_SetObject(spoolss_werror, py_werror_tuple(werror));
		return NULL;
	}

	py_from_printerdata(&result, value, data_type, data, needed);

	return result;
}

PyObject *spoolss_setprinterdata(PyObject *self, PyObject *args, PyObject *kw)
{
	spoolss_policy_hnd_object *hnd = (spoolss_policy_hnd_object *)self;
	static char *kwlist[] = { "data", NULL };
	PyObject *py_data;
	char *value, *data;
	uint32 data_size, data_type;
	WERROR werror;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "O!", kwlist,
					 &PyDict_Type, &py_data))
		return NULL;
	
	if (!py_to_printerdata(&value, &data_type, &data, &data_size, py_data))
		return NULL;

	/* Call rpc function */

	werror = cli_spoolss_setprinterdata(
		hnd->cli, hnd->mem_ctx, &hnd->pol, value, data_type,
		data, data_size);

	if (!W_ERROR_IS_OK(werror)) {
		PyErr_SetObject(spoolss_werror, py_werror_tuple(werror));
		return NULL;
	}

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *spoolss_enumprinterdata(PyObject *self, PyObject *args, PyObject *kw)
{
	spoolss_policy_hnd_object *hnd = (spoolss_policy_hnd_object *)self;
	static char *kwlist[] = { NULL };
	uint32 data_needed, value_needed, ndx = 0, data_size, data_type;
	char *value, *data;
	WERROR werror;
	PyObject *result;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "", kwlist))
		return NULL;

	/* Get max buffer sizes for value and data */

	werror = cli_spoolss_enumprinterdata(
		hnd->cli, hnd->mem_ctx, &hnd->pol, ndx, 0, 0,
		&value_needed, &data_needed, NULL, NULL, NULL, NULL);

	if (!W_ERROR_IS_OK(werror)) {
		PyErr_SetObject(spoolss_werror, py_werror_tuple(werror));
		return NULL;
	}

	/* Iterate over all printerdata */

	result = PyDict_New();

	while (W_ERROR_IS_OK(werror)) {
		PyObject *obj;

		werror = cli_spoolss_enumprinterdata(
			hnd->cli, hnd->mem_ctx, &hnd->pol, ndx,
			value_needed, data_needed, NULL, NULL,
			&value, &data_type, &data, &data_size); 

		if (py_from_printerdata(&obj, value, data_type, data, 
					data_size))
			PyDict_SetItemString(result, value, obj);

		ndx++;
	}

	return result;
}

PyObject *spoolss_deleteprinterdata(PyObject *self, PyObject *args, PyObject *kw)
{
	spoolss_policy_hnd_object *hnd = (spoolss_policy_hnd_object *)self;
	static char *kwlist[] = { "value", NULL };
	char *value;
	WERROR werror;

	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(args, kw, "s", kwlist, &value))
	    return NULL;

	/* Call rpc function */

	werror = cli_spoolss_deleteprinterdata(
		hnd->cli, hnd->mem_ctx, &hnd->pol, value);

	if (!W_ERROR_IS_OK(werror)) {
		PyErr_SetObject(spoolss_werror, py_werror_tuple(werror));
		return NULL;
	}

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *spoolss_deleteprinterdataex(PyObject *self, PyObject *args, PyObject *kw)
{
	/* Not supported by Samba server */

	PyErr_SetString(spoolss_error, "Not implemented");
	return NULL;
}
