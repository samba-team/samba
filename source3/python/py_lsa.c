#include "includes.h"
#include "Python.h"

#include "python/py_lsa.h"
static void py_policy_hnd_dealloc(PyObject* self)
{
	PyObject_Del(self);
}

PyTypeObject lsa_policy_hnd_type = {
	PyObject_HEAD_INIT(NULL)
	0,
	"LSA Policy Handle",
	sizeof(lsa_policy_hnd_object),
	0,
	py_policy_hnd_dealloc, /*tp_dealloc*/
	0,          /*tp_print*/
	0,          /*tp_getattr*/
	0,          /*tp_setattr*/
	0,          /*tp_compare*/
	0,          /*tp_repr*/
	0,          /*tp_as_number*/
	0,          /*tp_as_sequence*/
	0,          /*tp_as_mapping*/
	0,          /*tp_hash */
};

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

static PyObject *lsa_openpolicy(PyObject *self, PyObject *args, 
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

	/* Cleanup samba stuf */

	cli_shutdown(hnd->cli);
	talloc_destroy(hnd->mem_ctx);

	/* Return value */

	Py_INCREF(Py_None);
	return Py_None;	
}

static PyObject *lsa_lookupnames(PyObject *self, PyObject *args, 
				 PyObject *kw) 
{
	return NULL;
}

static PyObject *lsa_lookupsids(PyObject *self, PyObject *args, 
				PyObject *kw) 
{
	return NULL;
}

/*
 * Method dispatch table
 */

static PyMethodDef lsa_methods[] = {

	/* Open/close lsa handles */
	
	{ "openpolicy", lsa_openpolicy, METH_VARARGS | METH_KEYWORDS, 
	  "Open a policy handle" },
	
	{ "close", lsa_close, METH_VARARGS, 
	  "Close a policy handle" },

	/* Name <-> SID resolution */

	{ "lookupnames", lsa_lookupnames, METH_VARARGS | METH_KEYWORDS,
	  "Look up SIDS from a list of names" },

	{ "lookupsids", lsa_lookupsids, METH_VARARGS | METH_KEYWORDS,
	  "Look up names from a list of SIDS" },

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
}
