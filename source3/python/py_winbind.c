#include "includes.h"
#include "Python.h"
#include "python/py_common.h"

/* 
 * Exceptions raised by this module 
 */

PyObject *winbind_error;	/* A winbind call returned WINBINDD_ERROR */

/*
 * Method dispatch table
 */

static PyMethodDef winbind_methods[] = {
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
