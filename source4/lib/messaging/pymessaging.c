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

#include <Python.h>
#include "python/py3compat.h"
#include "includes.h"
#include "python/modules.h"
#include "libcli/util/pyerrors.h"
#include "librpc/rpc/pyrpc_util.h"
#include "librpc/ndr/libndr.h"
#include "lib/messaging/messaging.h"
#include "lib/messaging/irpc.h"
#include "lib/events/events.h"
#include "cluster/cluster.h"
#include "param/param.h"
#include "param/pyparam.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/gen_ndr/server_id.h"
#include <pytalloc.h>
#include "messaging_internal.h"


extern PyTypeObject imessaging_Type;

static bool server_id_from_py(PyObject *object, struct server_id *server_id)
{
	if (!PyTuple_Check(object)) {
		if (!py_check_dcerpc_type(object, "samba.dcerpc.server_id", "server_id")) {

			PyErr_SetString(PyExc_ValueError, "Expected tuple or server_id");
			return false;
		}
		*server_id = *pytalloc_get_type(object, struct server_id);
		return true;
	}
	if (PyTuple_Size(object) == 3) {
		unsigned long long pid;
		int task_id, vnn;

		if (!PyArg_ParseTuple(object, "Kii", &pid, &task_id, &vnn)) {
			return false;
		}
		server_id->pid = pid;
		server_id->task_id = task_id;
		server_id->vnn = vnn;
		return true;
	} else if (PyTuple_Size(object) == 2) {
		unsigned long long pid;
		int task_id;
		if (!PyArg_ParseTuple(object, "Ki", &pid, &task_id))
			return false;
		*server_id = cluster_id(pid, task_id);
		return true;
	} else {
		unsigned long long pid = getpid();
		int task_id;
		if (!PyArg_ParseTuple(object, "i", &task_id))
			return false;
		*server_id = cluster_id(pid, task_id);
		return true;
	}
}

typedef struct {
	PyObject_HEAD
	TALLOC_CTX *mem_ctx;
	struct imessaging_context *msg_ctx;
} imessaging_Object;

static PyObject *py_imessaging_connect(PyTypeObject *self, PyObject *args, PyObject *kwargs)
{
	struct tevent_context *ev;
	const char *kwnames[] = { "own_id", "lp_ctx", NULL };
	PyObject *own_id = Py_None;
	PyObject *py_lp_ctx = Py_None;
	imessaging_Object *ret;
	struct loadparm_context *lp_ctx;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|OO:connect", 
		discard_const_p(char *, kwnames), &own_id, &py_lp_ctx)) {
		return NULL;
	}

	ret = PyObject_New(imessaging_Object, &imessaging_Type);
	if (ret == NULL)
		return NULL;

	ret->mem_ctx = talloc_new(NULL);

	lp_ctx = lpcfg_from_py_object(ret->mem_ctx, py_lp_ctx);
	if (lp_ctx == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "imessaging_connect unable to interpret loadparm_context");
		talloc_free(ret->mem_ctx);
		return NULL;
	}

	ev = s4_event_context_init(ret->mem_ctx);

	if (own_id != Py_None) {
		struct server_id server_id;

		if (!server_id_from_py(own_id, &server_id)) 
			return NULL;

		ret->msg_ctx = imessaging_init(ret->mem_ctx,
					       lp_ctx,
					       server_id,
					       ev);
	} else {
		ret->msg_ctx = imessaging_client_init(ret->mem_ctx,
						      lp_ctx,
						      ev);
	}

	if (ret->msg_ctx == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "imessaging_connect unable to create a messaging context");
		talloc_free(ret->mem_ctx);
		return NULL;
	}

	return (PyObject *)ret;
}

static void py_imessaging_dealloc(PyObject *self)
{
	imessaging_Object *iface = (imessaging_Object *)self;
	talloc_free(iface->msg_ctx);
	self->ob_type->tp_free(self);
}

static PyObject *py_imessaging_send(PyObject *self, PyObject *args, PyObject *kwargs)
{
	imessaging_Object *iface = (imessaging_Object *)self;
	uint32_t msg_type;
	DATA_BLOB data;
	PyObject *target;
	NTSTATUS status;
	struct server_id server;
	const char *kwnames[] = { "target", "msg_type", "data", NULL };
	Py_ssize_t length;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OIs#:send",
		discard_const_p(char *, kwnames), &target, &msg_type, &data.data, &length)) {

		return NULL;
	}

	data.length = length;

	if (!server_id_from_py(target, &server))
		return NULL;

	status = imessaging_send(iface->msg_ctx, server, msg_type, &data);
	if (NT_STATUS_IS_ERR(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	Py_RETURN_NONE;
}

static void py_msg_callback_wrapper(struct imessaging_context *msg,
				    void *private_data,
				    uint32_t msg_type,
				    struct server_id server_id,
				    size_t num_fds,
				    int *fds,
				    DATA_BLOB *data)
{
	PyObject *py_server_id, *callback_and_tuple = (PyObject *)private_data;
	PyObject *callback, *py_private;

	struct server_id *p_server_id = talloc(NULL, struct server_id);

	if (num_fds != 0) {
		DBG_WARNING("Received %zu fds, ignoring message\n", num_fds);
		return;
	}

	if (!p_server_id) {
		PyErr_NoMemory();
		return;
	}
	*p_server_id = server_id;

	if (!PyArg_ParseTuple(callback_and_tuple, "OO",
			      &callback,
			      &py_private)) {
		return;
	}

	py_server_id = py_return_ndr_struct("samba.dcerpc.server_id", "server_id", p_server_id, p_server_id);
	talloc_unlink(NULL, p_server_id);

	PyObject_CallFunction(callback, discard_const_p(char, "OiOs#"),
			      py_private,
			      msg_type,
			      py_server_id,
			      data->data, data->length);
}

static PyObject *py_imessaging_register(PyObject *self, PyObject *args, PyObject *kwargs)
{
	imessaging_Object *iface = (imessaging_Object *)self;
	int msg_type = -1;
	PyObject *callback_and_context;
	NTSTATUS status;
	const char *kwnames[] = { "callback_and_context", "msg_type", NULL };
	
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O|i:register", 
		discard_const_p(char *, kwnames),
					 &callback_and_context, &msg_type)) {
		return NULL;
	}
	if (!PyTuple_Check(callback_and_context)
	    || PyTuple_Size(callback_and_context) != 2) {
		PyErr_SetString(PyExc_ValueError, "Expected of size 2 for callback_and_context");
		return NULL;
	}

	Py_INCREF(callback_and_context);

	if (msg_type == -1) {
		uint32_t msg_type32 = msg_type;
		status = imessaging_register_tmp(iface->msg_ctx, callback_and_context,
						py_msg_callback_wrapper, &msg_type32);
		msg_type = msg_type32;
	} else {
		status = imessaging_register(iface->msg_ctx, callback_and_context,
				    msg_type, py_msg_callback_wrapper);
	}
	if (NT_STATUS_IS_ERR(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	return PyLong_FromLong(msg_type);
}

static PyObject *py_imessaging_deregister(PyObject *self, PyObject *args, PyObject *kwargs)
{
	imessaging_Object *iface = (imessaging_Object *)self;
	int msg_type = -1;
	PyObject *callback;
	const char *kwnames[] = { "callback", "msg_type", NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O|i:deregister",
		discard_const_p(char *, kwnames), &callback, &msg_type)) {
		return NULL;
	}

	imessaging_deregister(iface->msg_ctx, msg_type, callback);

	Py_RETURN_NONE;
}

static void simple_timer_handler(struct tevent_context *ev,
				 struct tevent_timer *te,
				 struct timeval current_time,
				 void *private_data)
{
	return;
}

static PyObject *py_imessaging_loop_once(PyObject *self, PyObject *args, PyObject *kwargs)
{
	imessaging_Object *iface = (imessaging_Object *)self;
	double offset;
	int seconds;
	struct timeval next_event;
	struct tevent_timer *timer = NULL;
	const char *kwnames[] = { "timeout", NULL };

	TALLOC_CTX *frame = talloc_stackframe();

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "d",
					 discard_const_p(char *, kwnames), &offset)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	if (offset != 0.0) {
		seconds = offset;
		offset -= seconds;
		next_event = tevent_timeval_current_ofs(seconds, (int)(offset*1000000));

		timer = tevent_add_timer(iface->msg_ctx->ev, frame, next_event, simple_timer_handler,
					 NULL);
		if (timer == NULL) {
			PyErr_NoMemory();
			TALLOC_FREE(frame);
			return NULL;
		}
	}

	tevent_loop_once(iface->msg_ctx->ev);

	TALLOC_FREE(frame);

	Py_RETURN_NONE;
}

static PyObject *py_irpc_add_name(PyObject *self, PyObject *args)
{
	imessaging_Object *iface = (imessaging_Object *)self;
	char *server_name;
	NTSTATUS status;

	if (!PyArg_ParseTuple(args, "s", &server_name)) {
		return NULL;
	}

	status = irpc_add_name(iface->msg_ctx, server_name);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *py_irpc_remove_name(PyObject *self, PyObject *args)
{
	imessaging_Object *iface = (imessaging_Object *)self;
	char *server_name;

	if (!PyArg_ParseTuple(args, "s", &server_name)) {
		return NULL;
	}

	irpc_remove_name(iface->msg_ctx, server_name);

	Py_RETURN_NONE;
}

static PyObject *py_irpc_servers_byname(PyObject *self, PyObject *args)
{
	imessaging_Object *iface = (imessaging_Object *)self;
	char *server_name;
	unsigned i, num_ids;
	struct server_id *ids;
	PyObject *pylist;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	NTSTATUS status;

	if (!mem_ctx) {
		PyErr_NoMemory();
		return NULL;
	}

	if (!PyArg_ParseTuple(args, "s", &server_name)) {
		TALLOC_FREE(mem_ctx);
		return NULL;
	}

	status = irpc_servers_byname(iface->msg_ctx, mem_ctx, server_name,
				     &num_ids, &ids);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(mem_ctx);
		PyErr_SetString(PyExc_KeyError, "No such name");
		return NULL;
	}

	pylist = PyList_New(num_ids);
	if (pylist == NULL) {
		TALLOC_FREE(mem_ctx);
		PyErr_NoMemory();
		return NULL;
	}
	for (i = 0; i < num_ids; i++) {
		PyObject *py_server_id;
		struct server_id *p_server_id = talloc(NULL, struct server_id);
		if (!p_server_id) {
			PyErr_NoMemory();
			return NULL;
		}
		*p_server_id = ids[i];

		py_server_id = py_return_ndr_struct("samba.dcerpc.server_id", "server_id", p_server_id, p_server_id);
		if (!py_server_id) {
			return NULL;
		}
		PyList_SetItem(pylist, i, py_server_id);
		talloc_unlink(NULL, p_server_id);
	}
	TALLOC_FREE(mem_ctx);
	return pylist;
}

static PyObject *py_irpc_all_servers(PyObject *self,
		PyObject *Py_UNUSED(ignored))
{
	imessaging_Object *iface = (imessaging_Object *)self;
	PyObject *pylist;
	int i;
	struct irpc_name_records *records;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	if (!mem_ctx) {
		PyErr_NoMemory();
		return NULL;
	}

	records = irpc_all_servers(iface->msg_ctx, mem_ctx);
	if (records == NULL) {
		return NULL;
	}

	pylist = PyList_New(records->num_records);
	if (pylist == NULL) {
		TALLOC_FREE(mem_ctx);
		PyErr_NoMemory();
		return NULL;
	}
	for (i = 0; i < records->num_records; i++) {
		PyObject *py_name_record
			= py_return_ndr_struct("samba.dcerpc.irpc",
					       "name_record",
					       records->names[i],
					       records->names[i]);
		if (!py_name_record) {
			return NULL;
		}
		PyList_SetItem(pylist, i,
			       py_name_record);
	}
	TALLOC_FREE(mem_ctx);
	return pylist;
}

static PyMethodDef py_imessaging_methods[] = {
	{ "send", PY_DISCARD_FUNC_SIG(PyCFunction, py_imessaging_send),
		METH_VARARGS|METH_KEYWORDS,
		"S.send(target, msg_type, data) -> None\nSend a message" },
	{ "register", PY_DISCARD_FUNC_SIG(PyCFunction, py_imessaging_register),
		METH_VARARGS|METH_KEYWORDS,
		"S.register((callback, context), msg_type=None) -> msg_type\nRegister a message handler.  "
	        "The callback and context must be supplied as a two-element tuple." },
	{ "deregister", PY_DISCARD_FUNC_SIG(PyCFunction,
					    py_imessaging_deregister),
		METH_VARARGS|METH_KEYWORDS,
		"S.deregister((callback, context), msg_type) -> None\nDeregister a message handler "
	        "The callback and context must be supplied as the exact same two-element tuple "
	        "as was used as registration time." },
	{ "loop_once", PY_DISCARD_FUNC_SIG(PyCFunction,
					   py_imessaging_loop_once),
		METH_VARARGS|METH_KEYWORDS,
		"S.loop_once(timeout) -> None\n"
	        "Loop on the internal event context until we get an event "
	        "(which might be a message calling the callback), "
	        "timeout after timeout seconds (if not 0)" },
	{ "irpc_add_name", (PyCFunction)py_irpc_add_name, METH_VARARGS,
		"S.irpc_add_name(name) -> None\n"
	        "Add this context to the list of server_id values that "
	        "are registered for a particular name" },
	{ "irpc_remove_name", (PyCFunction)py_irpc_remove_name, METH_VARARGS,
		"S.irpc_remove_name(name) -> None\n"
	        "Remove this context from the list of server_id values that "
	        "are registered for a particular name" },
	{ "irpc_servers_byname", (PyCFunction)py_irpc_servers_byname, METH_VARARGS,
		"S.irpc_servers_byname(name) -> list\nGet list of server_id values that are registered for a particular name" },
	{ "irpc_all_servers", (PyCFunction)py_irpc_all_servers, METH_NOARGS,
		"S.irpc_all_servers() -> list\n"
	        "Get list of all registered names and the associated server_id values" },
	{ NULL, NULL, 0, NULL }
};

static PyObject *py_imessaging_server_id(PyObject *obj, void *closure)
{
	imessaging_Object *iface = (imessaging_Object *)obj;
	PyObject *py_server_id;
	struct server_id server_id = imessaging_get_server_id(iface->msg_ctx);
	struct server_id *p_server_id = talloc(NULL, struct server_id);
	if (!p_server_id) {
		PyErr_NoMemory();
		return NULL;
	}
	*p_server_id = server_id;

	py_server_id = py_return_ndr_struct("samba.dcerpc.server_id", "server_id", p_server_id, p_server_id);
	talloc_unlink(NULL, p_server_id);

	return py_server_id;
}

static PyGetSetDef py_imessaging_getset[] = {
	{
		.name = discard_const_p(char, "server_id"),
		.get  = py_imessaging_server_id,
		.doc  = discard_const_p(char, "local server id")
	},
	{ .name = NULL },
};


PyTypeObject imessaging_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "messaging.Messaging",
	.tp_basicsize = sizeof(imessaging_Object),
	.tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
	.tp_new = py_imessaging_connect,
	.tp_dealloc = py_imessaging_dealloc,
	.tp_methods = py_imessaging_methods,
	.tp_getset = py_imessaging_getset,
	.tp_doc = "Messaging(own_id=None)\n" \
		  "Create a new object that can be used to communicate with the peers in the specified messaging path.\n"
};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    .m_name = "messaging",
    .m_doc = "Internal RPC",
    .m_size = -1,
    .m_methods = NULL,
};

MODULE_INIT_FUNC(messaging)
{
	PyObject *mod;

	if (PyType_Ready(&imessaging_Type) < 0)
		return NULL;

	mod = PyModule_Create(&moduledef);
	if (mod == NULL)
		return NULL;

	Py_INCREF((PyObject *)&imessaging_Type);
	PyModule_AddObject(mod, "Messaging", (PyObject *)&imessaging_Type);
	PyModule_AddObject(mod, "IRPC_CALL_TIMEOUT", PyLong_FromLong(IRPC_CALL_TIMEOUT));
	PyModule_AddObject(mod, "IRPC_CALL_TIMEOUT_INF", PyLong_FromLong(IRPC_CALL_TIMEOUT_INF));

	return mod;
}
