#include "includes.h"
#include "Python.h"
#include "python/py_common.h"

static void py_policy_hnd_dealloc(PyObject* self)
{
	PyObject_Del(self);
}

typedef struct {
	PyObject_HEAD
	struct cli_state *cli;
	TALLOC_CTX *mem_ctx;
	POLICY_HND pol;
} lsa_policy_hnd_object;

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
	PyObject *creds = NULL;
	uint32 desired_access = MAXIMUM_ALLOWED_ACCESS;

	if (!PyArg_ParseTupleAndKeywords(
		args, kw, "s|O!i", kwlist, &server_name, &PyDict_Type,
		&creds, &desired_access)) {

		goto done;
	}

 done:
	return NULL;
}

static PyObject *lsa_close(PyObject *self, PyObject *args, PyObject *kw) 
{
	return NULL;
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
