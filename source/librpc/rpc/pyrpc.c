/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2008
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include <Python.h>
#include "librpc/rpc/pyrpc.h"
#include "librpc/rpc/dcerpc.h"
#include "lib/events/events.h"

static bool PyString_AsGUID(PyObject *object, struct GUID *uuid)
{
	NTSTATUS status;
	status = GUID_from_string(PyString_AsString(object), uuid);
	if (NT_STATUS_IS_ERR(status)) {
		PyErr_SetNTSTATUS(status);
		return false;
	}
	return true;
}

static PyObject *py_iface_server_name(PyObject *obj, void *closure)
{
	const char *server_name;
	dcerpc_InterfaceObject *iface = (dcerpc_InterfaceObject *)obj;
	
	server_name = dcerpc_server_name(iface->pipe);
	if (server_name == NULL)
		return Py_None;

	return PyString_FromString(server_name);
}

static PyGetSetDef dcerpc_interface_getsetters[] = {
	{ discard_const_p(char, "server_name"), py_iface_server_name, NULL },
	{ NULL }
};

static PyObject *py_iface_request(PyObject *self, PyObject *args, PyObject *kwargs)
{
	dcerpc_InterfaceObject *iface = (dcerpc_InterfaceObject *)self;
	int opnum;
	DATA_BLOB data_in, data_out;
	NTSTATUS status;
	char *in_data;
	int in_length;
	PyObject *ret;
	PyObject *object = NULL;
	struct GUID object_guid;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	const char *kwnames[] = { "opnum", "data", "object", NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "is#|O:request", 
		discard_const_p(char *, kwnames), &opnum, &in_data, &in_length, &object)) {
		return NULL;
	}

	data_in.data = (uint8_t *)talloc_memdup(mem_ctx, in_data, in_length);
	data_in.length = in_length;

	ZERO_STRUCT(data_out);

	if (object != NULL && !PyString_AsGUID(object, &object_guid)) {
		return NULL;
	}

	status = dcerpc_request(iface->pipe, object?&object_guid:NULL,
				opnum, false, mem_ctx, &data_in, &data_out);

	if (NT_STATUS_IS_ERR(status)) {
		PyErr_SetNTSTATUS(status);
		talloc_free(mem_ctx);
		return NULL;
	}

	ret = PyString_FromStringAndSize((char *)data_out.data, data_out.length);

	talloc_free(mem_ctx);
	return ret;
}

static PyMethodDef dcerpc_interface_methods[] = {
	{ "request", (PyCFunction)py_iface_request, METH_VARARGS|METH_KEYWORDS, "S.request(opnum, data, object=None) -> data\nMake a raw request" },
	{ NULL, NULL, 0, NULL },
};


static void dcerpc_interface_dealloc(PyObject* self)
{
	dcerpc_InterfaceObject *interface = (dcerpc_InterfaceObject *)self;
	talloc_free(interface->pipe);
	PyObject_Del(self);
}

static bool ndr_syntax_from_py_object(PyObject *object, struct ndr_syntax_id *syntax_id)
{
	ZERO_STRUCTP(syntax_id);

	if (PyString_Check(object)) {
		return PyString_AsGUID(object, &syntax_id->uuid);
	} else if (PyTuple_Check(object)) {
		if (PyTuple_Size(object) < 1 || PyTuple_Size(object) > 2) {
			PyErr_SetString(PyExc_ValueError, "Syntax ID tuple has invalid size");
			return false;
		}

		if (!PyString_Check(PyTuple_GetItem(object, 0))) {
			PyErr_SetString(PyExc_ValueError, "Expected GUID as first element in tuple");
			return false;
		}

		if (!PyString_AsGUID(PyTuple_GetItem(object, 0), &syntax_id->uuid)) 
			return false;

		if (!PyInt_Check(PyTuple_GetItem(object, 1))) {
			PyErr_SetString(PyExc_ValueError, "Expected version as second element in tuple");
			return false;
		}

		syntax_id->if_version = PyInt_AsLong(PyTuple_GetItem(object, 1));
		return true;
	}

	PyErr_SetString(PyExc_TypeError, "Expected UUID or syntax id tuple");
	return false;
}	

static PyObject *dcerpc_interface_new(PyTypeObject *self, PyObject *args, PyObject *kwargs)
{
	dcerpc_InterfaceObject *ret;
	const char *binding_string;
	struct cli_credentials *credentials;
	struct loadparm_context *lp_ctx = NULL;
	PyObject *py_lp_ctx = Py_None, *py_credentials = Py_None;
	TALLOC_CTX *mem_ctx = NULL;
	struct event_context *event_ctx;
	NTSTATUS status;

	PyObject *syntax;
	const char *kwnames[] = {
		"binding", "syntax", "lp_ctx", "credentials", NULL
	};
	extern struct loadparm_context *lp_from_py_object(PyObject *py_obj);
	extern struct cli_credentials *cli_credentials_from_py_object(PyObject *py_obj);
	struct ndr_interface_table *table;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "sO|OO:connect", discard_const_p(char *, kwnames), &binding_string, &syntax, &py_lp_ctx, &py_credentials)) {
		return NULL;
	}

	lp_ctx = lp_from_py_object(py_lp_ctx);
	if (lp_ctx == NULL) {
		PyErr_SetString(PyExc_TypeError, "Expected loadparm context");
		return NULL;
	}

	credentials = cli_credentials_from_py_object(py_credentials);
	if (credentials == NULL) {
		PyErr_SetString(PyExc_TypeError, "Expected credentials");
		return NULL;
	}
	ret = PyObject_New(dcerpc_InterfaceObject, &dcerpc_InterfaceType);

	event_ctx = event_context_init(mem_ctx);

	/* Create a dummy interface table struct. TODO: In the future, we should rather just allow 
	 * connecting without requiring an interface table.
	 */

	table = talloc_zero(mem_ctx, struct ndr_interface_table);

	if (table == NULL) {
		PyErr_SetString(PyExc_MemoryError, "Allocating interface table");
		return NULL;
	}

	if (!ndr_syntax_from_py_object(syntax, &table->syntax_id)) {
		return NULL;
	}

	status = dcerpc_pipe_connect(NULL, &ret->pipe, binding_string, 
	             table, credentials, event_ctx, lp_ctx);
	if (NT_STATUS_IS_ERR(status)) {
		PyErr_SetString(PyExc_RuntimeError, nt_errstr(status));
		talloc_free(mem_ctx);
		return NULL;
	}

	ret->pipe->conn->flags |= DCERPC_NDR_REF_ALLOC;
	return (PyObject *)ret;
}

PyTypeObject dcerpc_InterfaceType = {
	PyObject_HEAD_INIT(NULL) 0,
	.tp_name = "dcerpc.ClientConnection",
	.tp_basicsize = sizeof(dcerpc_InterfaceObject),
	.tp_dealloc = dcerpc_interface_dealloc,
	.tp_getset = dcerpc_interface_getsetters,
	.tp_methods = dcerpc_interface_methods,
	.tp_doc = "ClientConnection(binding, syntax, lp_ctx=None, credentials=None) -> connection\n"
"\n"
"binding should be a DCE/RPC binding string (for example: ncacn_ip_tcp:127.0.0.1)\n"
"syntax should be a tuple with a GUID and version number of an interface\n"
"lp_ctx should be a path to a smb.conf file or a param.LoadParm object\n"
"credentials should be a credentials.Credentials object.\n\n",
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_new = dcerpc_interface_new,
};

void initbase(void)
{
	PyObject *m;

	if (PyType_Ready(&dcerpc_InterfaceType) < 0)
		return;

	m = Py_InitModule3("base", NULL, "DCE/RPC protocol implementation");
	if (m == NULL)
		return;

	Py_INCREF((PyObject *)&dcerpc_InterfaceType);
	PyModule_AddObject(m, "ClientConnection", (PyObject *)&dcerpc_InterfaceType);
}
