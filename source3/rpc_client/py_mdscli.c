/*
   Python interface to cli_mdssvc

   Copyright (C) Ralph Boehme 2019

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
#include <pytalloc.h>
#include "includes.h"
#include "python/py3compat.h"
#include "python/modules.h"
#include "lib/util/talloc_stack.h"
#include "lib/util/tevent_ntstatus.h"
#include "librpc/rpc/rpc_common.h"
#include "librpc/rpc/pyrpc_util.h"
#include "rpc_client/cli_mdssvc.h"
#include "rpc_client/cli_mdssvc_private.h"

static PyObject *search_get_results(PyObject *self,
				    PyObject *args,
				    PyObject *kwargs)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char * const kwnames[] = {"pipe", NULL};
	PyObject *pypipe = NULL;
	PyObject *result = NULL;
	dcerpc_InterfaceObject *pipe = NULL;
	struct tevent_req *req = NULL;
	struct mdscli_search_ctx *search = NULL;
	uint64_t *cnids = NULL;
	size_t i;
	size_t ncnids;
	NTSTATUS status;
	int ret;
	bool ok;

	if (!PyArg_ParseTupleAndKeywords(args,
					 kwargs,
					 "O",
					 discard_const_p(char *, kwnames),
					 &pypipe)) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to parse args");
		goto out;
	}

	ok = py_check_dcerpc_type(pypipe,
				  "samba.dcerpc.base",
				  "ClientConnection");
	if (!ok) {
		goto out;
	}

	pipe = (dcerpc_InterfaceObject *)pypipe;

	search = pytalloc_get_type(self, struct mdscli_search_ctx);
	if (search == NULL) {
		goto out;
	}

	/*
	 * We must use the async send/recv versions in order to pass the correct
	 * tevent context, here and any other place we call mdscli_*
	 * functions. Using the sync version we would be polling a temporary
	 * event context, but unfortunately the s4 Python RPC bindings dispatch
	 * events through
	 *
	 *    dcerpc_bh_raw_call_send()
         *    -> dcerpc_request_send()
         *    -> dcerpc_schedule_io_trigger()
         *    -> dcerpc_send_request()
         *    -> tstream_writev_queue_send()
	 *
	 * on an hardcoded event context allocated via
	 *
	 *   py_dcerpc_interface_init_helper()
	 *   -> dcerpc_pipe_connect()
	 */
	req = mdscli_get_results_send(frame,
				      pipe->ev,
				      search);
	if (req == NULL) {
		PyErr_NoMemory();
		goto out;
	}

	if (!tevent_req_poll_ntstatus(req, pipe->ev, &status)) {
		PyErr_SetNTSTATUS(status);
		goto out;
	}

	status = mdscli_get_results_recv(req, frame, &cnids);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_NO_MORE_MATCHES))
	{
		PyErr_SetNTSTATUS(status);
		goto out;
	}
	TALLOC_FREE(req);

	result = Py_BuildValue("[]");

	ncnids = talloc_array_length(cnids);
	for (i = 0; i < ncnids; i++) {
		char *path = NULL;
		PyObject *pypath = NULL;

		req = mdscli_get_path_send(frame,
					   pipe->ev,
					   search->mdscli_ctx,
					   cnids[i]);
		if (req == NULL) {
			PyErr_NoMemory();
			Py_DECREF(result);
			result = NULL;
			goto out;
		}

		if (!tevent_req_poll_ntstatus(req, pipe->ev, &status)) {
			PyErr_SetNTSTATUS(status);
			Py_DECREF(result);
			result = NULL;
			goto out;
		}

		status = mdscli_get_path_recv(req, frame, &path);
		TALLOC_FREE(req);
		PyErr_NTSTATUS_NOT_OK_RAISE(status);

		pypath = PyUnicode_FromString(path);
		if (pypath == NULL) {
			PyErr_NoMemory();
			Py_DECREF(result);
			result = NULL;
			goto out;
		}

		ret = PyList_Append(result, pypath);
		Py_DECREF(pypath);
		if (ret == -1) {
			PyErr_SetString(PyExc_RuntimeError,
					"list append failed");
			Py_DECREF(result);
			result = NULL;
			goto out;
		}
	}

out:
	talloc_free(frame);
	return result;
}

static PyObject *search_close(PyObject *self,
			      PyObject *args,
			      PyObject *kwargs)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char * const kwnames[] = {"pipe", NULL};
	PyObject *pypipe = NULL;
	dcerpc_InterfaceObject *pipe = NULL;
	struct tevent_req *req = NULL;
	struct mdscli_search_ctx *search = NULL;
	NTSTATUS status;
	bool ok;

	if (!PyArg_ParseTupleAndKeywords(args,
					 kwargs,
					 "O",
					 discard_const_p(char *, kwnames),
					 &pypipe)) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to parse args");
		goto fail;
	}

	ok = py_check_dcerpc_type(pypipe,
				  "samba.dcerpc.base",
				  "ClientConnection");
	if (!ok) {
		goto fail;
	}

	pipe = (dcerpc_InterfaceObject *)pypipe;

	search = pytalloc_get_type(self, struct mdscli_search_ctx);
	if (search == NULL) {
		goto fail;
	}

	req = mdscli_close_search_send(frame,
				       pipe->ev,
				       &search);
	if (req == NULL) {
		PyErr_NoMemory();
		goto fail;
	}

	if (!tevent_req_poll_ntstatus(req, pipe->ev, &status)) {
		PyErr_SetNTSTATUS(status);
		goto fail;
	}

	status = mdscli_close_search_recv(req);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_NO_MORE_MATCHES))
	{
		PyErr_SetNTSTATUS(status);
		goto fail;
	}
	TALLOC_FREE(req);

	talloc_free(frame);
	Py_INCREF(Py_None);
	return Py_None;

fail:
	talloc_free(frame);
	return NULL;
}

static PyMethodDef search_methods[] = {
	{
		.ml_name  = "get_results",
		.ml_meth  = PY_DISCARD_FUNC_SIG(PyCFunction, search_get_results),
		.ml_flags = METH_VARARGS|METH_KEYWORDS,
		.ml_doc   = "",
	},
	{
		.ml_name  = "close",
		.ml_meth  = PY_DISCARD_FUNC_SIG(PyCFunction, search_close),
		.ml_flags = METH_VARARGS|METH_KEYWORDS,
		.ml_doc   = "",
	},
	{0},
};

static PyObject *search_new(PyTypeObject *type,
			    PyObject *args,
			    PyObject *kwds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct mdscli_search_ctx *search = NULL;
	PyObject *self = NULL;

	search = talloc_zero(frame, struct mdscli_search_ctx);
	if (search == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	self = pytalloc_steal(type, search);
	talloc_free(frame);
	return self;
}

static PyTypeObject search_type = {
	.tp_name = "mdscli.ctx.search",
	.tp_new = search_new,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = "search([....]) -> mdssvc client search context\n",
	.tp_methods = search_methods,
};

static PyObject *conn_sharepath(PyObject *self,
				PyObject *unused)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct mdscli_ctx *ctx = NULL;
	char *sharepath = NULL;
	PyObject *result = NULL;

	ctx = pytalloc_get_type(self, struct mdscli_ctx);
	if (ctx == NULL) {
		goto fail;
	}

	sharepath = mdscli_get_basepath(frame, ctx);
	if (sharepath == NULL) {
		PyErr_NoMemory();
		goto fail;
	}

	result = PyUnicode_FromString(sharepath);

fail:
	talloc_free(frame);
	return result;
}

static PyObject *conn_search(PyObject *self,
			     PyObject *args,
			     PyObject *kwargs)
{
	TALLOC_CTX *frame = talloc_stackframe();
	PyObject *pypipe = NULL;
	dcerpc_InterfaceObject *pipe = NULL;
	struct mdscli_ctx *ctx = NULL;
	PyObject *result = NULL;
	char *query = NULL;
	char *basepath = NULL;
	struct tevent_req *req = NULL;
	struct mdscli_search_ctx *search = NULL;
	const char * const kwnames[] = {
		"pipe", "query", "basepath", NULL
	};
	NTSTATUS status;
	bool ok;

	if (!PyArg_ParseTupleAndKeywords(args,
					 kwargs,
					 "Oss",
					 discard_const_p(char *, kwnames),
					 &pypipe,
					 &query,
					 &basepath)) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to parse args");
		goto fail;
	}

	ok = py_check_dcerpc_type(pypipe,
				  "samba.dcerpc.base",
				  "ClientConnection");
	if (!ok) {
		goto fail;
	}

	pipe = (dcerpc_InterfaceObject *)pypipe;

	ctx = pytalloc_get_type(self, struct mdscli_ctx);
	if (ctx == NULL) {
		goto fail;
	}

	req = mdscli_search_send(frame,
				 pipe->ev,
				 ctx,
				 query,
				 basepath,
				 false);
	if (req == NULL) {
		PyErr_NoMemory();
		goto fail;
	}

	if (!tevent_req_poll_ntstatus(req, pipe->ev, &status)) {
		PyErr_SetNTSTATUS(status);
		goto fail;
	}

	status = mdscli_search_recv(req, frame, &search);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	result = pytalloc_steal(&search_type, search);

fail:
	talloc_free(frame);
	return result;
}

static PyObject *conn_disconnect(PyObject *self,
				 PyObject *args,
				 PyObject *kwargs)
{
	TALLOC_CTX *frame = talloc_stackframe();
	PyObject *pypipe = NULL;
	dcerpc_InterfaceObject *pipe = NULL;
	struct mdscli_ctx *ctx = NULL;
	struct tevent_req *req = NULL;
	const char * const kwnames[] = {"pipe", NULL};
	NTSTATUS status;
	bool ok;

	if (!PyArg_ParseTupleAndKeywords(args,
					 kwargs,
					 "O",
					 discard_const_p(char *, kwnames),
					 &pypipe)) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to parse args");
		goto fail;
	}

	ok = py_check_dcerpc_type(pypipe,
				  "samba.dcerpc.base",
				  "ClientConnection");
	if (!ok) {
		goto fail;
	}

	pipe = (dcerpc_InterfaceObject *)pypipe;

	ctx = pytalloc_get_type(self, struct mdscli_ctx);
	if (ctx == NULL) {
		goto fail;
	}

	req = mdscli_disconnect_send(frame, pipe->ev, ctx);
	if (req == NULL) {
		PyErr_NoMemory();
		goto fail;
	}

	if (!tevent_req_poll_ntstatus(req, pipe->ev, &status)) {
		PyErr_SetNTSTATUS(status);
		goto fail;
	}

	status = mdscli_disconnect_recv(req);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	talloc_free(frame);
	Py_INCREF(Py_None);
	return Py_None;

fail:
	talloc_free(frame);
	return NULL;
}

static PyMethodDef conn_methods[] = {
	{
		.ml_name  = "sharepath",
		.ml_meth  = PY_DISCARD_FUNC_SIG(PyCFunction, conn_sharepath),
		.ml_flags = METH_NOARGS,
		.ml_doc   = "mdscli.conn.sharepath(...) -> get share basepath",
	},
	{
		.ml_name  = "search",
		.ml_meth  = PY_DISCARD_FUNC_SIG(PyCFunction, conn_search),
		.ml_flags = METH_VARARGS|METH_KEYWORDS,
		.ml_doc   = "mdscli.conn.search(...) -> run mdssvc query",
	},
	{
		.ml_name  = "disconnect",
		.ml_meth  = PY_DISCARD_FUNC_SIG(PyCFunction, conn_disconnect),
		.ml_flags = METH_VARARGS|METH_KEYWORDS,
		.ml_doc   = "mdscli.conn.disconnect(...) -> disconnect",
	},
	{0},
};

static PyObject *conn_new(PyTypeObject *type,
			  PyObject *args,
			  PyObject *kwargs)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char * const kwnames[] = { "pipe", "share", "mountpoint", NULL };
	PyObject *pypipe = NULL;
	dcerpc_InterfaceObject *pipe = NULL;
	struct tevent_req *req = NULL;
	char *share = NULL;
	char *mountpoint = NULL;
	struct mdscli_ctx *ctx = NULL;
	PyObject *self = NULL;
	NTSTATUS status;
	bool ok;

	if (!PyArg_ParseTupleAndKeywords(args,
					 kwargs,
					 "Oss",
					 discard_const_p(char *, kwnames),
	                                 &pypipe,
					 &share,
					 &mountpoint)) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to parse args");
		goto fail;
	}

	ok = py_check_dcerpc_type(pypipe,
				  "samba.dcerpc.base",
				  "ClientConnection");
	if (!ok) {
		goto fail;
	}

	pipe = (dcerpc_InterfaceObject *)pypipe;

	req = mdscli_connect_send(frame,
				  pipe->ev,
				  pipe->binding_handle,
				  share,
				  mountpoint);
	if (req == NULL) {
		PyErr_NoMemory();
		goto fail;
	}

	if (!tevent_req_poll_ntstatus(req, pipe->ev, &status)) {
		PyErr_SetNTSTATUS(status);
		goto fail;
	}

	status = mdscli_connect_recv(req, frame, &ctx);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	self = pytalloc_steal(type, ctx);

fail:
	talloc_free(frame);
	return self;
}

static PyTypeObject conn_type = {
	.tp_name = "mdscli.conn",
	.tp_new = conn_new,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = "conn([....]) -> mdssvc connection\n",
	.tp_methods = conn_methods,
};

static PyMethodDef mdscli_methods[] = {
	{0},
};

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	.m_name = "mdscli",
	.m_doc = "RPC mdssvc client",
	.m_size = -1,
	.m_methods = mdscli_methods,
};

MODULE_INIT_FUNC(mdscli)
{
	TALLOC_CTX *frame = talloc_stackframe();
	PyObject *m = NULL;
	int ret;

	ret = pytalloc_BaseObject_PyType_Ready(&conn_type);
	if (ret < 0) {
		TALLOC_FREE(frame);
		return NULL;
	}

	ret = pytalloc_BaseObject_PyType_Ready(&search_type);
	if (ret < 0) {
		TALLOC_FREE(frame);
		return NULL;
	}

	m = PyModule_Create(&moduledef);
	if (m == NULL) {
		TALLOC_FREE(frame);
		return NULL;
	}

	Py_INCREF(&conn_type);
	PyModule_AddObject(m, "conn", (PyObject *)&conn_type);

	Py_INCREF(&search_type);
	PyModule_AddObject(m, "search", (PyObject *)&search_type);

	TALLOC_FREE(frame);
	return m;
}
