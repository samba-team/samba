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

struct pyconv py_FORM[] = {
	{ "flags", PY_UINT32, offsetof(FORM, flags) },
	{ "width", PY_UINT32, offsetof(FORM, size_x) },
	{ "length", PY_UINT32, offsetof(FORM, size_y) },
	{ "top", PY_UINT32, offsetof(FORM, top) },
	{ "left", PY_UINT32, offsetof(FORM, left) },
	{ "right", PY_UINT32, offsetof(FORM, right) },
	{ "bottom", PY_UINT32, offsetof(FORM, bottom) },
	{ NULL }
};

struct pyconv py_FORM_1[] = {
	{ "flags", PY_UINT32, offsetof(FORM_1, flag) },
	{ "width", PY_UINT32, offsetof(FORM_1, width) },
	{ "length", PY_UINT32, offsetof(FORM_1, length) },
	{ "top", PY_UINT32, offsetof(FORM_1, top) },
	{ "left", PY_UINT32, offsetof(FORM_1, left) },
	{ "right", PY_UINT32, offsetof(FORM_1, right) },
	{ "bottom", PY_UINT32, offsetof(FORM_1, bottom) },
	{ "name", PY_UNISTR, offsetof(FORM_1, name) },
	{ NULL }
};

/* Add a form */

static PyObject *spoolss_addform(PyObject *self, PyObject *args, PyObject *kw)
{
	spoolss_policy_hnd_object *hnd = (spoolss_policy_hnd_object *)self;
	WERROR werror;
	PyObject *py_form;
	FORM form;
	int level = 1;
	static char *kwlist[] = {"form", "level", NULL};

	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(
		    args, kw, "O!|i", kwlist, &PyDict_Type, &py_form, &level))
		return NULL;
	
	/* Call rpc function */

	switch (level) {
	case 1: {
		PyObject *py_form_name;
		char *form_name;

		to_struct(&form, py_form, py_FORM);

		py_form_name = PyDict_GetItemString(py_form, "name");
		form_name = PyString_AsString(py_form_name);

		init_unistr2(&form.name, form_name, strlen(form_name) + 1);

		break;
	}
	default:
		PyErr_SetString(spoolss_error, "unsupported info level");
		return NULL;
	}

	werror = cli_spoolss_addform(hnd->cli, hnd->mem_ctx, &hnd->pol,
				     level, &form);


	if (!W_ERROR_IS_OK(werror)) {
		PyErr_SetObject(spoolss_werror,
				PyInt_FromLong(W_ERROR_V(werror)));
		return NULL;
	}

	Py_INCREF(Py_None);
	return Py_None;
}

/* Get form properties */

static PyObject *spoolss_getform(PyObject *self, PyObject *args, PyObject *kw)
{
	spoolss_policy_hnd_object *hnd = (spoolss_policy_hnd_object *)self;
	WERROR werror;
	PyObject *result;
	char *form_name;
	int level = 1;
	static char *kwlist[] = {"form_name", "level", NULL};
	uint32 needed;
	FORM_1 form;

	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(args, kw, "s|i", kwlist, 
					 &form_name, &level))
		return NULL;
	
	/* Call rpc function */

	werror = cli_spoolss_getform(hnd->cli, hnd->mem_ctx, 0, &needed,
				     &hnd->pol, form_name, 1, &form);

	if (W_ERROR_V(werror) == ERRinsufficientbuffer)
		werror = cli_spoolss_getform(
			hnd->cli, hnd->mem_ctx, needed, NULL, &hnd->pol,
			form_name, 1, &form);

	if (!W_ERROR_IS_OK(werror)) {
		PyErr_SetObject(spoolss_werror,
				PyInt_FromLong(W_ERROR_V(werror)));
		return NULL;
	}

	result = Py_None;

	switch(level) {
	case 1:
		result = from_struct(&form, py_FORM_1);
		break;
	}

	Py_INCREF(result);
	return result;
}

/* Set form properties */

static PyObject *spoolss_setform(PyObject *self, PyObject *args, PyObject *kw)
{
	spoolss_policy_hnd_object *hnd = (spoolss_policy_hnd_object *)self;
	WERROR werror;
	PyObject *py_form;
	int level = 1;
	static char *kwlist[] = {"form_name", "form", "level", NULL};
	char *form_name;
	FORM form;

	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(args, kw, "sO!|i", kwlist, 
					 &form_name, &PyDict_Type, &py_form,
					 &level))
		return NULL;
	
	/* Call rpc function */

	to_struct(&form, py_form, py_FORM);
	init_unistr2(&form.name, form_name, strlen(form_name) + 1);

	werror = cli_spoolss_setform(hnd->cli, hnd->mem_ctx, &hnd->pol,
				     level, form_name, &form);

	if (!W_ERROR_IS_OK(werror)) {
		PyErr_SetObject(spoolss_werror, 
				PyInt_FromLong(W_ERROR_V(werror)));

		return NULL;
	}

	Py_INCREF(Py_None);
	return Py_None;
}

/* Delete a form */

static PyObject *spoolss_deleteform(PyObject *self, PyObject *args, 
				    PyObject *kw)
{
	spoolss_policy_hnd_object *hnd = (spoolss_policy_hnd_object *)self;
	WERROR werror;
	int level = 1;
	static char *kwlist[] = {"form_name", "level", NULL};
	char *form_name;

	/* Parse parameters */
	
	if (!PyArg_ParseTupleAndKeywords(
		    args, kw, "s|i", kwlist, &form_name, &level))
		return NULL;
	
	/* Call rpc function */

	werror = cli_spoolss_deleteform(
		hnd->cli, hnd->mem_ctx, &hnd->pol, form_name);

	if (!W_ERROR_IS_OK(werror)) {
		PyErr_SetObject(spoolss_werror,
				PyInt_FromLong(W_ERROR_V(werror)));
		return NULL;
	}

	Py_INCREF(Py_None);
	return Py_None;
}

/* Enumerate forms */

static PyObject *spoolss_enumforms(PyObject *self, PyObject *args, 
				   PyObject *kw)
{
	PyObject *result;
	spoolss_policy_hnd_object *hnd = (spoolss_policy_hnd_object *)self;
	WERROR werror;
	uint32 level = 1, num_forms, needed, i;
	static char *kwlist[] = {"level", NULL};
	FORM_1 *forms;

	/* Parse parameters */
	
	if (!PyArg_ParseTupleAndKeywords(
		    args, kw, "|i", kwlist, &level))
		return NULL;
	
	/* Call rpc function */

	werror = cli_spoolss_enumforms(
		hnd->cli, hnd->mem_ctx, 0, &needed, &hnd->pol, level,
		&num_forms, &forms);

	if (W_ERROR_V(werror) == ERRinsufficientbuffer)
		werror = cli_spoolss_enumforms(
			hnd->cli, hnd->mem_ctx, needed, NULL, &hnd->pol, level,
			&num_forms, &forms);

	if (!W_ERROR_IS_OK(werror)) {
		PyErr_SetObject(spoolss_werror,
				PyInt_FromLong(W_ERROR_V(werror)));
		return NULL;
	}

	result = PyList_New(num_forms);

	for (i = 0; i < num_forms; i++) {
		PyObject *obj = NULL;

		switch(level) {
		case 1:
			obj = from_struct(&forms[i], py_FORM_1);
			break;
		}

		PyList_SetItem(result, i, obj);
	}

	return result;
}
