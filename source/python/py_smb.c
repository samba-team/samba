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

#include "python/py_smb.h"

/* Create a new cli_state python object */

PyObject *new_cli_state_object(struct cli_state *cli)
{
	cli_state_object *o;

	o = PyObject_New(cli_state_object, &cli_state_type);

	o->cli = cli;

	return (PyObject*)o;
}

static PyObject *py_smb_connect(PyObject *self, PyObject *args, PyObject *kw)
{
	static char *kwlist[] = { "server", NULL };
	struct cli_state *cli;
	char *server;
	struct in_addr ip;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "s", kwlist, &server))
		return NULL;

	if (!(cli = cli_initialise(NULL)))
		return NULL;

	ZERO_STRUCT(ip);

	if (!cli_connect(cli, server, &ip))
		return NULL;

	return new_cli_state_object(cli);
}

static PyObject *py_smb_session_request(PyObject *self, PyObject *args,
					PyObject *kw)
{
	cli_state_object *cli = (cli_state_object *)self;
	static char *kwlist[] = { "called", "calling", NULL };
	char *calling_name = NULL, *called_name;
	struct nmb_name calling, called;
	extern pstring global_myname;
	BOOL result;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "s|s", kwlist, &called_name, 
					 &calling_name))
		return NULL;

	if (!calling_name)
		calling_name = global_myname;

	make_nmb_name(&calling, calling_name, 0x00);
	make_nmb_name(&called, called_name, 0x20);

	result = cli_session_request(cli->cli, &calling, &called);

	return Py_BuildValue("i", result);
}
				      
static PyObject *py_smb_negprot(PyObject *self, PyObject *args, PyObject *kw)
{
	cli_state_object *cli = (cli_state_object *)self;
	static char *kwlist[] = { NULL };
	BOOL result;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "", kwlist))
		return NULL;

	result = cli_negprot(cli->cli);

	return Py_BuildValue("i", result);
}

static PyObject *py_smb_session_setup(PyObject *self, PyObject *args, 
				      PyObject *kw)
{
	cli_state_object *cli = (cli_state_object *)self;
	static char *kwlist[] = { "creds" };
	PyObject *creds;
	char *username, *domain, *password, *errstr;
	BOOL result;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "O", kwlist, &creds))
		return NULL;

	if (!py_parse_creds(creds, &username, &domain, &password, &errstr)) {
		free(errstr);
		return NULL;
	}

	result = cli_session_setup(
		cli->cli, username, password, strlen(password) + 1,
		password, strlen(password) + 1, domain);

	return Py_BuildValue("i", result);
}

static PyObject *py_smb_tconx(PyObject *self, PyObject *args, PyObject *kw)
{
	cli_state_object *cli = (cli_state_object *)self;
	static char *kwlist[] = { "service", "creds" };
	PyObject *creds;
	char *service, *username, *domain, *password, *errstr;
	BOOL result;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "sO", kwlist, &service, 
					 &creds))
		return NULL;

	if (!py_parse_creds(creds, &username, &domain, &password, &errstr)) {
		free(errstr);
		return NULL;
	}

	result = cli_send_tconX(
		cli->cli, service, strequal(service, "IPC$") ? "IPC" : "?????", 
		password, strlen(password) + 1);

	return Py_BuildValue("i", result);
}

static PyMethodDef smb_hnd_methods[] = {

	{ "session_request", (PyCFunction)py_smb_session_request, 
	  METH_VARARGS | METH_KEYWORDS, "Request a session" },

	{ "negprot", (PyCFunction)py_smb_negprot, 
	  METH_VARARGS | METH_KEYWORDS, "Protocol negotiation" },

	{ "session_setup", (PyCFunction)py_smb_session_setup,
	  METH_VARARGS | METH_KEYWORDS, "Session setup" },

	{ "tconx", (PyCFunction)py_smb_tconx,
	  METH_VARARGS | METH_KEYWORDS, "Tree connect" },

	{ NULL }
};

/*
 * Method dispatch tables
 */

static PyMethodDef smb_methods[] = {

	{ "connect", (PyCFunction)py_smb_connect, METH_VARARGS | METH_KEYWORDS,
	  "Connect to a host" },

	{ NULL }
};

static void py_cli_state_dealloc(PyObject* self)
{
	PyObject_Del(self);
}

static PyObject *py_cli_state_getattr(PyObject *self, char *attrname)
{
	return Py_FindMethod(smb_hnd_methods, self, attrname);
}

PyTypeObject cli_state_type = {
	PyObject_HEAD_INIT(NULL)
	0,
	"SMB client connection",
	sizeof(cli_state_object),
	0,
	py_cli_state_dealloc, /*tp_dealloc*/
	0,          /*tp_print*/
	py_cli_state_getattr,          /*tp_getattr*/
	0,          /*tp_setattr*/
	0,          /*tp_compare*/
	0,          /*tp_repr*/
	0,          /*tp_as_number*/
	0,          /*tp_as_sequence*/
	0,          /*tp_as_mapping*/
	0,          /*tp_hash */
};

/*
 * Module initialisation 
 */

void initsmb(void)
{
	PyObject *module, *dict;

	/* Initialise module */

	module = Py_InitModule("smb", smb_methods);
	dict = PyModule_GetDict(module);

	/* Initialise policy handle object */

	cli_state_type.ob_type = &PyType_Type;

	/* Do samba initialisation */

	py_samba_init();

	setup_logging("smb", True);
	DEBUGLEVEL = 10;
}
