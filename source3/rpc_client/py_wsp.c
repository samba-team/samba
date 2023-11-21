/*
 * Python interface to WSP
 *
 * Copyright (C) Noel Power
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "lib/replace/system/python.h"
#include <pytalloc.h>
#include "includes.h"
#include <Python.h>
#include "python/py3compat.h"
#include "python/modules.h"
#include "librpc/rpc/rpc_common.h"
#include "auth/credentials/pycredentials.h"
#include "param/pyparam.h"
#include "client.h"
#include "rpc_client/wsp_cli.h"
#include "libsmb/proto.h"
#include "dcerpc.h"

struct py_wsp_context {
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev_ctx;
	struct wsp_client_ctx *wsp_ctx;
	struct loadparm_context *lp_ctx;
};

static PyObject *conn_wsp(PyTypeObject *type,
			  PyObject *args,
			  PyObject *kwargs)
{
	const char *kwnames[] = { "creds", "lp", "server", NULL };
	PyObject *py_creds = NULL;
	PyObject *py_lp = NULL;
	const char *server_address = NULL;
	NTSTATUS status;
	PyObject *self = NULL;
	struct tevent_context *ev_ctx = NULL;
	struct cli_credentials *credentials = NULL;
	struct wsp_client_ctx *wsp_ctx = NULL;
	struct loadparm_context *lp_ctx = NULL;
	struct py_wsp_context *py_wsp_ctx = NULL;
	TALLOC_CTX *mem_ctx = NULL;
	struct cli_state *c = NULL;
	struct dcerpc_binding_handle *h = NULL;
	uint32_t flags = CLI_FULL_CONNECTION_IPC;
	struct smb_transports ts = { .num_transports = 0, };

	mem_ctx = talloc_stackframe();

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OOz",
					 discard_const_p(char *, kwnames),
					 &py_creds,
					 &py_lp,
					 &server_address)) {
		goto out;
	}

	ev_ctx = samba_tevent_context_init(mem_ctx);
	if (ev_ctx == NULL) {
		PyErr_SetString(PyExc_TypeError,
				"Failed to initialise event context");
		goto out;
	}

	credentials = cli_credentials_from_py_object(py_creds);
	if (credentials == NULL) {
		PyErr_SetString(PyExc_TypeError,
				"Expected credentials object");
		goto out;
	}

	lp_ctx = lpcfg_from_py_object(mem_ctx, py_lp);
	if (lp_ctx == NULL) {
		PyErr_SetString(PyExc_TypeError, "Expected param object");
		goto out;
	}

	/*
	 * is there a better way to do this ???
	 * is there something in python we can call that will
	 * initialise the s3 param stuff ? so that lp_client_min_protocol()
	 * style calls (e.g. not passing a lp_parm context)) will work ??
	 * In the mean time call lp_load_client
	 */

	lp_load_client(lp_ctx->szConfigFile);
	ts = smb_transports_parse("client smb transports",
				  lp_client_smb_transports());
	status =  cli_full_connection_creds(mem_ctx,
					    &c,
					    lp_netbios_name(),
					    server_address,
					    NULL,
					    &ts,
					    "IPC$",
					    "IPC",
					    credentials,
					    flags);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	status = wsp_server_connect(mem_ctx,
				    server_address,
				    ev_ctx,
				    lp_ctx,
				    credentials,
				    c,
				    &wsp_ctx);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	py_wsp_ctx = talloc_zero(NULL, struct py_wsp_context);
	if (py_wsp_ctx == NULL) {
		PyErr_SetString(PyExc_TypeError,
				"Failed to allocate wsp python object");
		goto out;
	}

	h = get_wsp_pipe(wsp_ctx);
	dcerpc_binding_handle_set_timeout(h,
					  DCERPC_REQUEST_TIMEOUT * 1000);

	py_wsp_ctx->ev_ctx = ev_ctx;
	py_wsp_ctx->wsp_ctx = wsp_ctx;
	py_wsp_ctx->lp_ctx = lp_ctx;
	py_wsp_ctx->mem_ctx = mem_ctx;
	self = pytalloc_steal(type, py_wsp_ctx);
out:
	return self;
}

static PyObject *py_wsp_send_msg(PyObject *self,
				 PyObject *args,
				 PyObject *kwargs)
{
	const char *kwnames[] = { "in", NULL };
	struct py_wsp_context *py_wsp_ctx = NULL;
	struct wsp_request *wsp_request = NULL;
	struct wsp_response *wsp_response = NULL;
	PyObject *in_py_wsp_request = NULL;
	PyObject *response = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	DATA_BLOB unread = data_blob_null;
	NTSTATUS status;

	if (!PyArg_ParseTupleAndKeywords(args,
					 kwargs,
					 "O",
					 discard_const_p(char *, kwnames),
					 &in_py_wsp_request)) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to parse args");
		goto fail;
	}

	wsp_request = pytalloc_get_type(in_py_wsp_request, struct wsp_request);
	if (wsp_request == NULL) {
		PyErr_SetString(PyExc_RuntimeError,
				"Failed to extract wsp request from args");
		goto fail;
	}

	py_wsp_ctx = pytalloc_get_type(self, struct py_wsp_context);
	if (py_wsp_ctx == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "Unexpected type");
		goto fail;
	}

	if (py_wsp_ctx->wsp_ctx == NULL
	    || py_wsp_ctx->lp_ctx == NULL
	    || py_wsp_ctx->mem_ctx == NULL
	    || py_wsp_ctx->ev_ctx == NULL)
	{
		PyErr_SetString(PyExc_RuntimeError, "WSP conn object is invalid.");
		goto fail;
	}

	wsp_response = talloc_zero(frame, struct wsp_response);
	if (wsp_response == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "out of memory");
		goto fail;
	}

	status = wsp_request_response(frame,
				      py_wsp_ctx->wsp_ctx,
				      wsp_request,
				      wsp_response,
				      &unread);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		goto fail;
	}

	response = py_return_ndr_struct("samba.dcerpc.wsp",
					"response",
					wsp_response,
					wsp_response);
fail:
	TALLOC_FREE(frame);
	return response;
}

static PyObject *py_wsp_disconnect(PyObject *self, PyObject *unused)
{
	struct py_wsp_context *py_wsp_ctx = NULL;

	py_wsp_ctx = pytalloc_get_type(self, struct py_wsp_context);
	if (py_wsp_ctx == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "Unexpected type");
		goto fail;
	}
	TALLOC_FREE(py_wsp_ctx->mem_ctx);
	py_wsp_ctx->wsp_ctx = NULL;
	py_wsp_ctx->ev_ctx = NULL;
	py_wsp_ctx->lp_ctx = NULL;
	Py_INCREF(Py_None);
	return Py_None;
fail:
	return NULL;
}

static PyMethodDef conn_methods[] = {
	{
		.ml_name  = "send",
		.ml_meth  = PY_DISCARD_FUNC_SIG(PyCFunction, py_wsp_send_msg),
		.ml_flags = METH_VARARGS|METH_KEYWORDS,
		.ml_doc	  = "send message to server"
	},
	{
		.ml_name  = "disconnect",
		.ml_meth  = PY_DISCARD_FUNC_SIG(PyCFunction, py_wsp_disconnect),
		.ml_flags = METH_NOARGS,
		.ml_doc	  = "disconnect from wsp server"
	},
	{ NULL },
};

static PyTypeObject conn_type = {
	.tp_name = "wsp.conn",
	.tp_new = conn_wsp,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = "conn([....]) -> wsp connection\n",
	.tp_methods = conn_methods,
};

static PyMethodDef wspcli_methods[] = {
	{ NULL },
};

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	.m_name = "wspcli",
	.m_doc = "wsp client",
	.m_size = -1,
	.m_methods = wspcli_methods,
};

MODULE_INIT_FUNC(wspcli)
{
	TALLOC_CTX *frame = talloc_stackframe();
	PyObject *m = NULL;
	int ret;

	ret = pytalloc_BaseObject_PyType_Ready(&conn_type);
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

	TALLOC_FREE(frame);
	return m;
}
