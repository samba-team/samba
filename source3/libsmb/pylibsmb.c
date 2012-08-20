/*
 * Unix SMB/CIFS implementation.
 * Samba-internal work in progress Python binding for libsmbclient
 *
 * Copyright (C) Volker Lendecke 2012
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

#include <Python.h>
#include "includes.h"
#include "libsmb/libsmb.h"
#include "libcli/security/security.h"
#include "system/select.h"
#include "source4/libcli/util/pyerrors.h"
#include "auth/credentials/pycredentials.h"

static PyTypeObject *get_pytype(const char *module, const char *type)
{
	PyObject *mod;
	PyTypeObject *result;

	mod = PyImport_ImportModule(module);
	if (mod == NULL) {
		PyErr_Format(PyExc_RuntimeError,
			     "Unable to import %s to check type %s",
			     module, type);
		return NULL;
	}
	result = (PyTypeObject *)PyObject_GetAttrString(mod, type);
	Py_DECREF(mod);
	if (result == NULL) {
		PyErr_Format(PyExc_RuntimeError,
			     "Unable to find type %s in module %s",
			     module, type);
		return NULL;
	}
	return result;
}

struct py_cli_thread;

struct py_cli_state {
	PyObject_HEAD
	struct cli_state *cli;
	struct tevent_context *ev;
	struct py_cli_thread *thread_state;
};

#if HAVE_PTHREAD

#include <pthread.h>

struct py_cli_thread {

	/*
	 * Pipe to make the poll thread wake up in our destructor, so
	 * that we can exit and join the thread.
	 */
	int shutdown_pipe[2];
	struct tevent_fd *shutdown_fde;
	bool do_shutdown;
	pthread_t id;

	/*
	 * Thread state to release the GIL during the poll(2) syscall
	 */
	PyThreadState *py_threadstate;
};

static void *py_cli_state_poll_thread(void *private_data)
{
	struct py_cli_state *self = (struct py_cli_state *)private_data;
	struct py_cli_thread *t = self->thread_state;
	PyGILState_STATE gstate;

	gstate = PyGILState_Ensure();

	while (!t->do_shutdown) {
		int ret;
		ret = tevent_loop_once(self->ev);
		assert(ret == 0);
	}
	PyGILState_Release(gstate);
	return NULL;
}

static void py_cli_state_trace_callback(enum tevent_trace_point point,
					void *private_data)
{
	struct py_cli_state *self = (struct py_cli_state *)private_data;
	struct py_cli_thread *t = self->thread_state;

	switch(point) {
	case TEVENT_TRACE_BEFORE_WAIT:
		assert(t->py_threadstate == NULL);
		t->py_threadstate = PyEval_SaveThread();
		break;
	case TEVENT_TRACE_AFTER_WAIT:
		assert(t->py_threadstate != NULL);
		PyEval_RestoreThread(t->py_threadstate);
		t->py_threadstate = NULL;
		break;
	default:
		break;
	}
}

static void py_cli_state_shutdown_handler(struct tevent_context *ev,
					  struct tevent_fd *fde,
					  uint16_t flags,
					  void *private_data)
{
	struct py_cli_state *self = (struct py_cli_state *)private_data;
	struct py_cli_thread *t = self->thread_state;

	if ((flags & TEVENT_FD_READ) == 0) {
		return;
	}
	TALLOC_FREE(t->shutdown_fde);
	t->do_shutdown = true;
}

static int py_cli_thread_destructor(struct py_cli_thread *t)
{
	char c = 0;
	ssize_t written;
	int ret;

	do {
		/*
		 * This will wake the poll thread from the poll(2)
		 */
		written = write(t->shutdown_pipe[1], &c, 1);
	} while ((written == -1) && (errno == EINTR));

	/*
	 * Allow the poll thread to do its own cleanup under the GIL
	 */
	Py_BEGIN_ALLOW_THREADS
	ret = pthread_join(t->id, NULL);
	Py_END_ALLOW_THREADS
	assert(ret == 0);

	if (t->shutdown_pipe[0] != -1) {
		close(t->shutdown_pipe[0]);
		t->shutdown_pipe[0] = -1;
	}
	if (t->shutdown_pipe[1] != -1) {
		close(t->shutdown_pipe[1]);
		t->shutdown_pipe[1] = -1;
	}
	return 0;
}

static bool py_cli_state_setup_ev(struct py_cli_state *self)
{
	struct py_cli_thread *t;
	int ret;

	self->ev = tevent_context_init_byname(NULL, "poll_mt");
	if (self->ev == NULL) {
		goto fail;
	}
	tevent_set_trace_callback(self->ev, py_cli_state_trace_callback, self);

	self->thread_state = talloc_zero(NULL, struct py_cli_thread);
	if (self->thread_state == NULL) {
		goto fail;
	}
	t = self->thread_state;

	ret = pipe(t->shutdown_pipe);
	if (ret == -1) {
		goto fail;
	}
	t->shutdown_fde = tevent_add_fd(
		self->ev, self->ev, t->shutdown_pipe[0], TEVENT_FD_READ,
		py_cli_state_shutdown_handler, self);
	if (t->shutdown_fde == NULL) {
		goto fail;
	}

	PyEval_InitThreads();

	ret = pthread_create(&t->id, NULL, py_cli_state_poll_thread, self);
	if (ret != 0) {
		goto fail;
	}
	talloc_set_destructor(self->thread_state, py_cli_thread_destructor);
	return true;

fail:
	TALLOC_FREE(t->shutdown_fde);

	if (t->shutdown_pipe[0] != -1) {
		close(t->shutdown_pipe[0]);
		t->shutdown_pipe[0] = -1;
	}
	if (t->shutdown_pipe[1] != -1) {
		close(t->shutdown_pipe[1]);
		t->shutdown_pipe[1] = -1;
	}

	TALLOC_FREE(self->thread_state);
	TALLOC_FREE(self->ev);
	return false;
}

struct py_tevent_cond {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	bool is_done;
};

static void py_tevent_signalme(struct tevent_req *req);

static int py_tevent_req_wait(struct tevent_context *ev,
			      struct tevent_req *req)
{
	struct py_tevent_cond cond;
	int ret, result;

	result = pthread_mutex_init(&cond.mutex, NULL);
	if (result != 0) {
		goto fail;
	}
	result = pthread_cond_init(&cond.cond, NULL);
	if (result != 0) {
		goto fail_mutex;
	}

	cond.is_done = false;
	tevent_req_set_callback(req, py_tevent_signalme, &cond);

	result = pthread_mutex_lock(&cond.mutex);
	if (result != 0) {
		goto fail_cond;
	}

	while (!cond.is_done) {

		Py_BEGIN_ALLOW_THREADS
		result = pthread_cond_wait(&cond.cond, &cond.mutex);
		Py_END_ALLOW_THREADS

		if (result != 0) {
			goto fail_unlock;
		}
	}

fail_unlock:
	ret = pthread_mutex_unlock(&cond.mutex);
	assert(ret == 0);
fail_cond:
	ret = pthread_cond_destroy(&cond.cond);
	assert(ret == 0);
fail_mutex:
	ret = pthread_mutex_destroy(&cond.mutex);
	assert(ret == 0);
fail:
	return result;
}

static void py_tevent_signalme(struct tevent_req *req)
{
	struct py_tevent_cond *cond = (struct py_tevent_cond *)
		tevent_req_callback_data_void(req);
	int ret;

	ret = pthread_mutex_lock(&cond->mutex);
	assert(ret == 0);

	cond->is_done = true;

	ret = pthread_cond_signal(&cond->cond);
	assert(ret == 0);
	ret = pthread_mutex_unlock(&cond->mutex);
	assert(ret == 0);
}

#else

static bool py_cli_state_setup_ev(struct py_cli_state *self)
{
	self->ev = tevent_context_init(NULL);
	return (self->ev != NULL);
}

static int py_tevent_req_wait(struct tevent_context *ev,
			      struct tevent_req *req)
{
	while (tevent_req_is_in_progress(req)) {
		int ret;

		ret = tevent_loop_once(ev);
		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}

#endif

static PyObject *py_cli_state_new(PyTypeObject *type, PyObject *args,
				  PyObject *kwds)
{
	struct py_cli_state *self;

	self = (struct py_cli_state *)type->tp_alloc(type, 0);
	if (self == NULL) {
		return NULL;
	}
	self->cli = NULL;
	self->ev = NULL;
	self->thread_state = NULL;
	return (PyObject *)self;
}

static int py_cli_state_init(struct py_cli_state *self, PyObject *args,
			     PyObject *kwds)
{
	NTSTATUS status;
	char *host, *share;
	PyObject *creds;
	struct cli_credentials *cli_creds;
	bool ret;

	static const char *kwlist[] = {
		"host", "share", "credentials", NULL
	};

	PyTypeObject *py_type_Credentials = get_pytype(
		"samba.credentials", "Credentials");
	if (py_type_Credentials == NULL) {
		return -1;
	}

	ret = PyArg_ParseTupleAndKeywords(
		args, kwds, "ss|O!", (char **)kwlist,
		&host, &share, py_type_Credentials, &creds);

	Py_DECREF(py_type_Credentials);

	if (!ret) {
		return -1;
	}

	if (!py_cli_state_setup_ev(self)) {
		return -1;
	}

	cli_creds = cli_credentials_from_py_object(creds);
	if (cli_creds == NULL) {
		PyErr_SetString(PyExc_TypeError, "Expected credentials");
		return -1;
	}

	status = cli_full_connection(
		&self->cli, "myname", host, NULL, 0, share, "?????",
		cli_credentials_get_username(cli_creds),
		cli_credentials_get_domain(cli_creds),
		cli_credentials_get_password(cli_creds),
		0, 0);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		return -1;
	}
	return 0;
}

static void py_cli_state_dealloc(struct py_cli_state *self)
{
	TALLOC_FREE(self->thread_state);
	TALLOC_FREE(self->ev);

	if (self->cli != NULL) {
		cli_shutdown(self->cli);
		self->cli = NULL;
	}
	self->ob_type->tp_free((PyObject *)self);
}

static bool py_tevent_req_wait_exc(struct tevent_context *ev,
				   struct tevent_req *req)
{
	int ret;

	if (req == NULL) {
		PyErr_NoMemory();
		return false;
	}
	ret = py_tevent_req_wait(ev, req);
	if (ret != 0) {
		TALLOC_FREE(req);
		errno = ret;
		PyErr_SetFromErrno(PyExc_RuntimeError);
		return false;
	}
	return true;
}

static PyObject *py_cli_create(struct py_cli_state *self, PyObject *args,
			       PyObject *kwds)
{
	char *fname;
	unsigned CreateFlags = 0;
	unsigned DesiredAccess = FILE_GENERIC_READ;
	unsigned FileAttributes = 0;
	unsigned ShareAccess = 0;
	unsigned CreateDisposition = FILE_OPEN;
	unsigned CreateOptions = 0;
	unsigned SecurityFlags = 0;
	uint16_t fnum;
	struct tevent_req *req;
	NTSTATUS status;

	static const char *kwlist[] = {
		"Name", "CreateFlags", "DesiredAccess", "FileAttributes",
		"ShareAccess", "CreateDisposition", "CreateOptions",
		"SecurityFlags", NULL };

	if (!PyArg_ParseTupleAndKeywords(
		    args, kwds, "s|IIIIIII", (char **)kwlist,
		    &fname, &CreateFlags, &DesiredAccess, &FileAttributes,
		    &ShareAccess, &CreateDisposition, &CreateOptions,
		    &SecurityFlags)) {
		return NULL;
	}

	req = cli_ntcreate_send(NULL, self->ev, self->cli, fname, CreateFlags,
				DesiredAccess, FileAttributes, ShareAccess,
				CreateDisposition, CreateOptions,
				SecurityFlags);
	if (!py_tevent_req_wait_exc(self->ev, req)) {
		return NULL;
	}
	status = cli_ntcreate_recv(req, &fnum);
	TALLOC_FREE(req);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}
	return Py_BuildValue("I", (unsigned)fnum);
}

static PyObject *py_cli_close(struct py_cli_state *self, PyObject *args)
{
	struct tevent_req *req;
	int fnum;
	NTSTATUS status;

	if (!PyArg_ParseTuple(args, "i", &fnum)) {
		return NULL;
	}

	req = cli_close_send(NULL, self->ev, self->cli, fnum);
	if (!py_tevent_req_wait_exc(self->ev, req)) {
		return NULL;
	}
	status = cli_close_recv(req);
	TALLOC_FREE(req);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *py_cli_write(struct py_cli_state *self, PyObject *args,
			      PyObject *kwds)
{
	int fnum;
	unsigned mode = 0;
	char *buf;
	int buflen;
	unsigned long long offset;
	struct tevent_req *req;
	NTSTATUS status;
	size_t written;

	static const char *kwlist[] = {
		"fnum", "buffer", "offset", "mode", NULL };

	if (!PyArg_ParseTupleAndKeywords(
		    args, kwds, "Is#K|I", (char **)kwlist,
		    &fnum, &buf, &buflen, &offset, &mode)) {
		return NULL;
	}

	req = cli_write_andx_send(NULL, self->ev, self->cli, fnum, mode,
				  (uint8_t *)buf, offset, buflen);
	if (!py_tevent_req_wait_exc(self->ev, req)) {
		return NULL;
	}
	status = cli_write_andx_recv(req, &written);
	TALLOC_FREE(req);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}
	return Py_BuildValue("K", (unsigned long long)written);
}

static PyObject *py_cli_read(struct py_cli_state *self, PyObject *args,
			     PyObject *kwds)
{
	int fnum;
	unsigned long long offset;
	unsigned size;
	struct tevent_req *req;
	NTSTATUS status;
	uint8_t *buf;
	ssize_t buflen;
	PyObject *result;

	static const char *kwlist[] = {
		"fnum", "offset", "size", NULL };

	if (!PyArg_ParseTupleAndKeywords(
		    args, kwds, "IKI", (char **)kwlist, &fnum, &offset,
		    &size)) {
		return NULL;
	}

	req = cli_read_andx_send(NULL, self->ev, self->cli, fnum,
				 offset, size);
	if (!py_tevent_req_wait_exc(self->ev, req)) {
		return NULL;
	}
	status = cli_read_andx_recv(req, &buflen, &buf);

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(req);
		PyErr_SetNTSTATUS(status);
		return NULL;
	}
	result = Py_BuildValue("s#", (char *)buf, (int)buflen);
	TALLOC_FREE(req);
	return result;
}

static PyObject *py_cli_ftruncate(struct py_cli_state *self, PyObject *args,
				  PyObject *kwds)
{
	int fnum;
	unsigned long long size;
	struct tevent_req *req;
	NTSTATUS status;

	static const char *kwlist[] = {
		"fnum", "size", NULL };

	if (!PyArg_ParseTupleAndKeywords(
		    args, kwds, "IK", (char **)kwlist, &fnum, &size)) {
		return NULL;
	}

	req = cli_ftruncate_send(NULL, self->ev, self->cli, fnum, size);
	if (!py_tevent_req_wait_exc(self->ev, req)) {
		return NULL;
	}
	status = cli_ftruncate_recv(req);
	TALLOC_FREE(req);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *py_cli_delete_on_close(struct py_cli_state *self,
					PyObject *args,
					PyObject *kwds)
{
	unsigned fnum, flag;
	struct tevent_req *req;
	NTSTATUS status;

	static const char *kwlist[] = {
		"fnum", "flag", NULL };

	if (!PyArg_ParseTupleAndKeywords(
		    args, kwds, "II", (char **)kwlist, &fnum, &flag)) {
		return NULL;
	}

	req = cli_nt_delete_on_close_send(NULL, self->ev, self->cli, fnum,
					  flag);
	if (!py_tevent_req_wait_exc(self->ev, req)) {
		return NULL;
	}
	status = cli_nt_delete_on_close_recv(req);
	TALLOC_FREE(req);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}
	Py_INCREF(Py_None);
	return Py_None;
}

static PyMethodDef py_cli_state_methods[] = {
	{ "create", (PyCFunction)py_cli_create, METH_VARARGS|METH_KEYWORDS,
	  "Open a file" },
	{ "close", (PyCFunction)py_cli_close, METH_VARARGS,
	  "Close a file handle" },
	{ "write", (PyCFunction)py_cli_write, METH_VARARGS|METH_KEYWORDS,
	  "Write to a file handle" },
	{ "read", (PyCFunction)py_cli_read, METH_VARARGS|METH_KEYWORDS,
	  "Read from a file handle" },
	{ "truncate", (PyCFunction)py_cli_ftruncate,
	  METH_VARARGS|METH_KEYWORDS,
	  "Truncate a file" },
	{ "delete_on_close", (PyCFunction)py_cli_delete_on_close,
	  METH_VARARGS|METH_KEYWORDS,
	  "Set/Reset the delete on close flag" },
	{ NULL, NULL, 0, NULL }
};

static PyTypeObject py_cli_state_type = {
	PyObject_HEAD_INIT(NULL)
	.tp_name = "libsmb_samba_internal.Conn",
	.tp_basicsize = sizeof(struct py_cli_state),
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_doc = "libsmb connection",
	.tp_new = py_cli_state_new,
	.tp_init = (initproc)py_cli_state_init,
	.tp_dealloc = (destructor)py_cli_state_dealloc,
	.tp_methods = py_cli_state_methods,
};

static PyMethodDef py_libsmb_methods[] = {
	{ NULL },
};

void initlibsmb_samba_internal(void);
void initlibsmb_samba_internal(void)
{
	PyObject *m;

	talloc_stackframe();

	m = Py_InitModule3("libsmb_samba_internal", py_libsmb_methods,
			   "libsmb wrapper");

	if (PyType_Ready(&py_cli_state_type) < 0) {
		return;
	}
	Py_INCREF(&py_cli_state_type);
	PyModule_AddObject(m, "Conn", (PyObject *)&py_cli_state_type);
}
