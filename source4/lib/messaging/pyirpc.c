/* 
   Unix SMB/CIFS implementation.
   Copyright © Jelmer Vernooij <jelmer@samba.org> 2008

   Based on the equivalent for EJS:
   Copyright © Andrew Tridgell <tridge@samba.org> 2005
   
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
#include "libcli/util/pyerrors.h"
#include "lib/messaging/irpc.h"
#include "lib/events/events.h"
#include "cluster/cluster.h"
#include "param/param.h"

PyAPI_DATA(PyTypeObject) messaging_Type;
PyAPI_DATA(PyTypeObject) irpc_InterfaceType;

static bool server_id_from_py(PyObject *object, struct server_id *server_id)
{
	if (!PyTuple_Check(object)) {
		PyErr_SetString(PyExc_ValueError, "Expected tuple");
		return false;
	}

	return PyArg_ParseTuple(object, "iii", &server_id->id, &server_id->id2, &server_id->node);
}



typedef struct {
	PyObject_HEAD
	TALLOC_CTX *mem_ctx;
	struct messaging_context *msg_ctx;
} messaging_Object;

PyObject *py_messaging_connect(PyTypeObject *self, PyObject *args, PyObject *kwargs)
{
	struct event_context *ev;
	const char *kwnames[] = { "own_id", "messaging_path", NULL };
	PyObject *own_id = Py_None;
	const char *messaging_path = NULL;
	messaging_Object *ret;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|Os:connect", 
		discard_const_p(char *, kwnames), &own_id, &messaging_path)) {
		return NULL;
	}

	ret = PyObject_New(messaging_Object, &messaging_Type);
	if (ret == NULL)
		return NULL;

	ret->mem_ctx = talloc_new(NULL);

	ev = event_context_init(ret->mem_ctx);

	if (messaging_path == NULL) {
		messaging_path = lp_messaging_path(ret, global_loadparm);
	} else {
		messaging_path = talloc_strdup(ret->mem_ctx, messaging_path);
	}

	if (own_id != Py_None) {
		struct server_id server_id;

		if (!server_id_from_py(own_id, &server_id)) 
			return NULL;

		ret->msg_ctx = messaging_init(ret->mem_ctx, 
					    messaging_path,
					    server_id,
				            lp_iconv_convenience(global_loadparm),
					    ev);
	} else {
		ret->msg_ctx = messaging_client_init(ret->mem_ctx, 
					    messaging_path,
				            lp_iconv_convenience(global_loadparm),
					    ev);
	}

	if (ret->msg_ctx == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "messaging_connect unable to create a messaging context");
		talloc_free(ret->mem_ctx);
		return NULL;
	}

	return (PyObject *)ret;
}

static void py_messaging_dealloc(PyObject *self)
{
	messaging_Object *iface = (messaging_Object *)self;
	talloc_free(iface->msg_ctx);
	PyObject_Del(self);
}

static PyObject *py_messaging_send(PyObject *self, PyObject *args, PyObject *kwargs)
{
	messaging_Object *iface = (messaging_Object *)self;
	uint32_t msg_type;
	DATA_BLOB data;
	PyObject *target;
	NTSTATUS status;
	struct server_id server;
	const char *kwnames[] = { "target", "msg_type", "data", NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "Ois#|:send", 
		discard_const_p(char *, kwnames), &target, &msg_type, &data.data, &data.length)) {
		return NULL;
	}

	if (!server_id_from_py(target, &server)) 
		return NULL;

	status = messaging_send(iface->msg_ctx, server, msg_type, &data);
	if (NT_STATUS_IS_ERR(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	return Py_None;
}

static void py_msg_callback_wrapper(struct messaging_context *msg, void *private, 
			       uint32_t msg_type, 
			       struct server_id server_id, DATA_BLOB *data)
{
	PyObject *callback = (PyObject *)private;

	PyObject_CallFunction(callback, discard_const_p(char, "i(iii)s#"), msg_type, 
			      server_id.id, server_id.id2, server_id.node, 
			      data->data, data->length);
}

static PyObject *py_messaging_register(PyObject *self, PyObject *args, PyObject *kwargs)
{
	messaging_Object *iface = (messaging_Object *)self;
	uint32_t msg_type = -1;
	PyObject *callback;
	NTSTATUS status;
	const char *kwnames[] = { "callback", "msg_type", NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O|i:send", 
		discard_const_p(char *, kwnames), &callback, &msg_type)) {
		return NULL;
	}

	Py_INCREF(callback);

	if (msg_type == -1) {
		status = messaging_register_tmp(iface->msg_ctx, callback,
						py_msg_callback_wrapper, &msg_type);
	} else {
		status = messaging_register(iface->msg_ctx, callback,
				    msg_type, py_msg_callback_wrapper);
	}
	if (NT_STATUS_IS_ERR(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	return PyLong_FromLong(msg_type);
}

static PyObject *py_messaging_add_name(PyObject *self, PyObject *args, PyObject *kwargs)
{
	messaging_Object *iface = (messaging_Object *)self;
	NTSTATUS status;
	char *name;
	const char *kwnames[] = { "name", NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|:send", 
		discard_const_p(char *, kwnames), &name)) {
		return NULL;
	}

	status = irpc_add_name(iface->msg_ctx, name);
	if (NT_STATUS_IS_ERR(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	return Py_None;
}


static PyObject *py_messaging_remove_name(PyObject *self, PyObject *args, PyObject *kwargs)
{
	messaging_Object *iface = (messaging_Object *)self;
	char *name;
	const char *kwnames[] = { "name", NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|:send", 
		discard_const_p(char *, kwnames), &name)) {
		return NULL;
	}

	irpc_remove_name(iface->msg_ctx, name);

	return Py_None;
}

static PyMethodDef py_messaging_methods[] = {
	{ "send", (PyCFunction)py_messaging_send, METH_VARARGS|METH_KEYWORDS, 
		"S.send(target, msg_type, data) -> None\nSend a message" },
	{ "register", (PyCFunction)py_messaging_register, METH_VARARGS|METH_KEYWORDS,
		"S.register(msg_type, callback) -> None\nRegister a message handler" },
	{ "add_name", (PyCFunction)py_messaging_add_name, METH_VARARGS|METH_KEYWORDS, "S.add_name(name) -> None\nListen on another name" },
	{ "remove_name", (PyCFunction)py_messaging_remove_name, METH_VARARGS|METH_KEYWORDS, "S.remove_name(name) -> None\nStop listening on a name" },
	{ NULL, NULL, 0, NULL }
};

PyTypeObject messaging_Type = {
	PyObject_HEAD_INIT(NULL) 0,
	.tp_name = "irpc.Messaging",
	.tp_basicsize = sizeof(messaging_Object),
	.tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
	.tp_new = py_messaging_connect,
	.tp_dealloc = py_messaging_dealloc,
	.tp_methods = py_messaging_methods,
};


/*
  state of a irpc 'connection'
*/
typedef struct {
	PyObject_HEAD
	const char *server_name;
	struct server_id *dest_ids;
	struct messaging_context *msg_ctx;
	TALLOC_CTX *mem_ctx;
} irpc_InterfaceObject;

/*
  setup a context for talking to a irpc server
     example: 
        status = irpc.connect("smb_server");
*/

PyObject *py_irpc_connect(PyTypeObject *self, PyObject *args, PyObject *kwargs)
{
	struct event_context *ev;
	const char *kwnames[] = { "server", "own_id", "messaging_path", NULL };
	char *server;
	const char *messaging_path = NULL;
	PyObject *own_id = Py_None;
	irpc_InterfaceObject *ret;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|Os:connect", 
		discard_const_p(char *, kwnames), &server, &own_id, &messaging_path)) {
		return NULL;
	}

	ret = PyObject_New(irpc_InterfaceObject, &irpc_InterfaceType);
	if (ret == NULL)
		return NULL;

	ret->mem_ctx = talloc_new(NULL);

	ret->server_name = server;

	ev = event_context_init(ret->mem_ctx);

	if (messaging_path == NULL) {
		messaging_path = lp_messaging_path(ret, global_loadparm);
	}

	if (own_id != Py_None) {
		struct server_id server_id;

		if (!server_id_from_py(own_id, &server_id)) 
			return NULL;

		ret->msg_ctx = messaging_init(ret->mem_ctx, 
					    messaging_path,
					    server_id,
				            lp_iconv_convenience(global_loadparm),
					    ev);
	} else {
		ret->msg_ctx = messaging_client_init(ret->mem_ctx, 
					    messaging_path,
				            lp_iconv_convenience(global_loadparm),
					    ev);
	}

	if (ret->msg_ctx == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "irpc_connect unable to create a messaging context");
		talloc_free(ret->mem_ctx);
		return NULL;
	}

	ret->dest_ids = irpc_servers_byname(ret->msg_ctx, ret->mem_ctx, ret->server_name);
	if (ret->dest_ids == NULL || ret->dest_ids[0].id == 0) {
		talloc_free(ret->mem_ctx);
		PyErr_SetNTSTATUS(NT_STATUS_OBJECT_NAME_NOT_FOUND);
		return NULL;
	} else {
		return (PyObject *)ret;
	}
}

static void py_irpc_dealloc(PyObject *self)
{
	irpc_InterfaceObject *iface = (irpc_InterfaceObject *)self;
	talloc_free(iface->mem_ctx);
	PyObject_Del(self);
}

PyTypeObject irpc_InterfaceType = {
	PyObject_HEAD_INIT(NULL) 0,
	.tp_name = "irpc.ClientConnection",
	.tp_basicsize = sizeof(irpc_InterfaceObject),
	.tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
	.tp_new = py_irpc_connect,
	.tp_dealloc = py_irpc_dealloc,
};

#if 0
/*
  make an irpc call - called via the same interface as rpc
*/
static int ejs_irpc_call(int eid, struct MprVar *io, 
			 const struct ndr_interface_table *iface, int callnum,
			 ejs_pull_function_t ejs_pull, ejs_push_function_t ejs_push)
{
	NTSTATUS status;
	void *ptr;
	struct ejs_rpc *ejs;
	const struct ndr_interface_call *call;
	struct ejs_irpc_connection *p;
	struct irpc_request **reqs;
	int i, count;
	struct MprVar *results;

	p = (struct ejs_irpc_connection *)mprGetThisPtr(eid, "irpc");

	ejs = talloc(mprMemCtx(), struct ejs_rpc);
	if (ejs == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	call = &iface->calls[callnum];

	ejs->eid = eid;
	ejs->callname = call->name;

	/* allocate the C structure */
	ptr = talloc_zero_size(ejs, call->struct_size);
	if (ptr == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	/* convert the mpr object into a C structure */
	status = ejs_pull(ejs, io, ptr);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	for (count=0;p->dest_ids[count].id;count++) /* noop */ ;

	/* we need to make a call per server */
	reqs = talloc_array(ejs, struct irpc_request *, count);
	if (reqs == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	/* make the actual calls */
	for (i=0;i<count;i++) {
		reqs[i] = irpc_call_send(p->msg_ctx, p->dest_ids[i], 
					 iface, callnum, ptr, ptr);
		if (reqs[i] == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
		talloc_steal(reqs, reqs[i]);
	}
	
	mprSetVar(io, "results", mprObject("results"));
	results = mprGetProperty(io, "results", NULL);

	/* and receive the results, placing them in io.results[i] */
	for (i=0;i<count;i++) {
		struct MprVar *output;

		status = irpc_call_recv(reqs[i]);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
		status = ejs_push(ejs, io, ptr);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

		/* add to the results array */
		output = mprGetProperty(io, "output", NULL);
		if (output) {
			char idx[16];
			mprItoa(i, idx, sizeof(idx));
			mprSetProperty(results, idx, output);
			mprDeleteProperty(io, "output");
		}
	}
	mprSetVar(results, "length", mprCreateIntegerVar(i));

done:
	talloc_free(ejs);
	mpr_Return(eid, mprNTSTATUS(status));
	if (NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR)) {
		return -1;
	}
	return 0;
}
#endif

void initirpc(void)
{
	PyObject *mod;

	if (PyType_Ready(&irpc_InterfaceType) < 0)
		return;

	if (PyType_Ready(&messaging_Type) < 0)
		return;

	mod = Py_InitModule3("irpc", NULL, "Internal RPC");
	if (mod == NULL)
		return;

	Py_INCREF((PyObject *)&irpc_InterfaceType);
	PyModule_AddObject(mod, "ClientConnection", (PyObject *)&irpc_InterfaceType);

	Py_INCREF((PyObject *)&messaging_Type);
	PyModule_AddObject(mod, "Messaging", (PyObject *)&messaging_Type);
}
