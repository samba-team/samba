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

#include "python/py_lsa.h"

PyObject *new_lsa_policy_hnd_object(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				    POLICY_HND *pol)
{
	lsa_policy_hnd_object *o;

	o = PyObject_New(lsa_policy_hnd_object, &lsa_policy_hnd_type);

	o->cli = cli;
	o->mem_ctx = mem_ctx;
	memcpy(&o->pol, pol, sizeof(POLICY_HND));

	return (PyObject*)o;
}

/* 
 * Exceptions raised by this module 
 */

PyObject *lsa_error;		/* This indicates a non-RPC related error
				   such as name lookup failure */

PyObject *lsa_ntstatus;		/* This exception is raised when a RPC call
				   returns a status code other than
				   NT_STATUS_OK */

/*
 * Open/close lsa handles
 */

static PyObject *lsa_open_policy(PyObject *self, PyObject *args, 
				PyObject *kw) 
{
	static char *kwlist[] = { "servername", "creds", "access", NULL };
	char *server_name;
	PyObject *creds = NULL, *result;
	uint32 desired_access = MAXIMUM_ALLOWED_ACCESS;
	struct cli_state *cli;
	NTSTATUS ntstatus;
	TALLOC_CTX *mem_ctx;
	POLICY_HND hnd;

	if (!PyArg_ParseTupleAndKeywords(
		args, kw, "s|O!i", kwlist, &server_name, &PyDict_Type,
		&creds, &desired_access))
		return NULL;

	if (!(cli = open_pipe_creds(server_name, creds, cli_lsa_initialise,
				    NULL))) {
		fprintf(stderr, "could not initialise cli state\n");
		return NULL;
	}

	if (!(mem_ctx = talloc_init())) {
		fprintf(stderr, "unable to initialise talloc context\n");
		return NULL;
	}

	ntstatus = cli_lsa_open_policy(cli, mem_ctx, True,
				       SEC_RIGHTS_MAXIMUM_ALLOWED, &hnd);

	if (!NT_STATUS_IS_OK(ntstatus)) {
		cli_shutdown(cli);
		SAFE_FREE(cli);
		PyErr_SetObject(lsa_ntstatus, py_ntstatus_tuple(ntstatus));
		return NULL;
	}

	result = new_lsa_policy_hnd_object(cli, mem_ctx, &hnd);

	return result;
}

static PyObject *lsa_close(PyObject *self, PyObject *args, PyObject *kw) 
{
	PyObject *po;
	lsa_policy_hnd_object *hnd;
	NTSTATUS result;

	/* Parse parameters */

	if (!PyArg_ParseTuple(args, "O!", &lsa_policy_hnd_type, &po))
		return NULL;

	hnd = (lsa_policy_hnd_object *)po;

	/* Call rpc function */

	result = cli_lsa_close(hnd->cli, hnd->mem_ctx, &hnd->pol);

	/* Cleanup samba stuff */

	cli_shutdown(hnd->cli);
	talloc_destroy(hnd->mem_ctx);

	/* Return value */

	Py_INCREF(Py_None);
	return Py_None;	
}

static PyObject *lsa_lookup_names(PyObject *self, PyObject *args)
{
	PyObject *py_names, *result;
	NTSTATUS ntstatus;
	lsa_policy_hnd_object *hnd = (lsa_policy_hnd_object *)self;
	int num_names, i;
	const char **names;
	DOM_SID *sids;
	uint32 *name_types;

	if (!PyArg_ParseTuple(args, "O!", &PyList_Type, &py_names))
		return NULL;

	/* Convert dictionary to char ** array */

	num_names = PyList_Size(py_names);
	names = (const char **)talloc(
		hnd->mem_ctx, num_names * sizeof(char *));

	for (i = 0; i < num_names; i++) {
		PyObject *obj = PyList_GetItem(py_names, i);

		names[i] = talloc_strdup(hnd->mem_ctx, PyString_AsString(obj));
	}

	ntstatus = cli_lsa_lookup_names(hnd->cli, hnd->mem_ctx, &hnd->pol,
					num_names, names, &sids, &name_types);

	if (!NT_STATUS_IS_OK(ntstatus) && NT_STATUS_V(ntstatus) != 0x107) {
		PyErr_SetObject(lsa_ntstatus, py_ntstatus_tuple(ntstatus));
		return NULL;
	}

	result = PyList_New(num_names);

	for (i = 0; i < num_names; i++) {
		PyObject *sid_obj, *obj;

		py_from_SID(&sid_obj, &sids[i]);

		obj = Py_BuildValue("(Oi)", sid_obj, name_types[i]);

		PyList_SetItem(result, i, obj);
	}
	
	return result;
}

static PyObject *lsa_lookup_sids(PyObject *self, PyObject *args, 
				 PyObject *kw) 
{
	PyObject *py_sids, *result;
	NTSTATUS ntstatus;
	int num_sids, i;
	char **domains, **names;
	uint32 *types;
	lsa_policy_hnd_object *hnd = (lsa_policy_hnd_object *)self;
	DOM_SID *sids;

	if (!PyArg_ParseTuple(args, "O!", &PyList_Type, &py_sids))
		return NULL;

	/* Convert dictionary to char ** array */

	num_sids = PyList_Size(py_sids);
	sids = (DOM_SID *)talloc(hnd->mem_ctx, num_sids * sizeof(DOM_SID));

	memset(sids, 0, num_sids * sizeof(DOM_SID));

	for (i = 0; i < num_sids; i++) {
		PyObject *obj = PyList_GetItem(py_sids, i);

		string_to_sid(&sids[i], PyString_AsString(obj));
	}

	ntstatus = cli_lsa_lookup_sids(hnd->cli, hnd->mem_ctx, &hnd->pol,
				       num_sids, sids, &domains, &names, 
				       &types);

	if (!NT_STATUS_IS_OK(ntstatus)) {
		PyErr_SetObject(lsa_ntstatus, py_ntstatus_tuple(ntstatus));
		return NULL;
	}

	result = PyList_New(num_sids);

	for (i = 0; i < num_sids; i++) {
		PyObject *obj;

		obj = Py_BuildValue("{sssssi}", "username", names[i],
				    "domain", domains[i], "name_type", 
				    types[i]);

		PyList_SetItem(result, i, obj);
	}
	
	return result;
}

static PyObject *lsa_enum_trust_dom(PyObject *self, PyObject *args)
{
	lsa_policy_hnd_object *hnd = (lsa_policy_hnd_object *)self;
	NTSTATUS ntstatus;
	uint32 enum_ctx = 0, num_domains, i;
	char **domain_names;
	DOM_SID *domain_sids;
	PyObject *result;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;
	
	ntstatus = cli_lsa_enum_trust_dom(hnd->cli, hnd->mem_ctx,
					  &hnd->pol, &enum_ctx,
					  &num_domains, &domain_names,
					  &domain_sids);

	if (!NT_STATUS_IS_OK(ntstatus)) {
		PyErr_SetObject(lsa_ntstatus, py_ntstatus_tuple(ntstatus));
		return NULL;
	}

	result = PyList_New(num_domains);

	for (i = 0; i < num_domains; i++) {
		fstring sid_str;

		sid_to_string(sid_str, &domain_sids[i]);
		PyList_SetItem(
			result, i, 
			Py_BuildValue("(ss)", domain_names[i], sid_str));
	}

	return result;
}

/*
 * Method dispatch tables
 */

static PyMethodDef lsa_hnd_methods[] = {

	/* SIDs<->names */

	{ "lookup_sids", lsa_lookup_sids, METH_VARARGS | METH_KEYWORDS,
	  "Convert sids to names." },

	{ "lookup_names", lsa_lookup_names, METH_VARARGS | METH_KEYWORDS,
	  "Convert names to sids." },

	/* Trusted domains */

	{ "enum_trusted_domains", lsa_enum_trust_dom, METH_VARARGS, 
	  "Enumerate trusted domains." },

	{ NULL }
};

static void py_lsa_policy_hnd_dealloc(PyObject* self)
{
	PyObject_Del(self);
}

static PyObject *py_lsa_policy_hnd_getattr(PyObject *self, char *attrname)
{
	return Py_FindMethod(lsa_hnd_methods, self, attrname);
}

PyTypeObject lsa_policy_hnd_type = {
	PyObject_HEAD_INIT(NULL)
	0,
	"LSA Policy Handle",
	sizeof(lsa_policy_hnd_object),
	0,
	py_lsa_policy_hnd_dealloc, /*tp_dealloc*/
	0,          /*tp_print*/
	py_lsa_policy_hnd_getattr,          /*tp_getattr*/
	0,          /*tp_setattr*/
	0,          /*tp_compare*/
	0,          /*tp_repr*/
	0,          /*tp_as_number*/
	0,          /*tp_as_sequence*/
	0,          /*tp_as_mapping*/
	0,          /*tp_hash */
};

static PyMethodDef lsa_methods[] = {

	/* Open/close lsa handles */
	
	{ "open_policy", lsa_open_policy, METH_VARARGS | METH_KEYWORDS, 
	  "Open a policy handle" },
	
	{ "close", lsa_close, METH_VARARGS, "Close a policy handle" },

	{ NULL }
};

/*
 * Module initialisation 
*/

void initlsa(void)
{
	PyObject *module, *dict;

	/* Initialise module */

	module = Py_InitModule("lsa", lsa_methods);
	dict = PyModule_GetDict(module);

	lsa_error = PyErr_NewException("lsa.error", NULL, NULL);
	PyDict_SetItemString(dict, "error", lsa_error);

	lsa_ntstatus = PyErr_NewException("lsa.ntstatus", NULL, NULL);
	PyDict_SetItemString(dict, "ntstatus", lsa_ntstatus);

	/* Initialise policy handle object */

	lsa_policy_hnd_type.ob_type = &PyType_Type;

	/* Initialise constants */

//	const_init(dict);

	/* Do samba initialisation */

	py_samba_init();

	setup_logging("lsa", True);
	DEBUGLEVEL = 10;
}
