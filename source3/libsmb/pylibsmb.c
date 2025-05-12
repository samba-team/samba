/*
 * Unix SMB/CIFS implementation.
 *
 * SMB client Python bindings used internally by Samba (for things like
 * samba-tool). These Python bindings may change without warning, and so
 * should not be used outside of the Samba codebase.
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

/*
Template code to use this library:

-------------------------
from samba.samba3 import libsmb_samba_internal as libsmb
from samba.samba3 import param as s3param
from samba import (credentials,NTSTATUSError)

lp = s3param.get_context()
lp.load("/etc/samba/smb.conf");

creds = credentials.Credentials()
creds.guess(lp)
creds.set_username("administrator")
creds.set_password("1234")

c = libsmb.Conn("127.0.0.1",
                "tmp",
                lp,
                creds,
                multi_threaded=True)
-------------------------
*/

#include "lib/replace/system/python.h"
#include "includes.h"
#include "python/py3compat.h"
#include "python/modules.h"
#include "param/pyparam.h"
#include "libcli/smb/smbXcli_base.h"
#include "libcli/smb/smb2_negotiate_context.h"
#include "libcli/smb/reparse.h"
#include "libsmb/libsmb.h"
#include "libcli/security/security.h"
#include "system/select.h"
#include "source4/libcli/util/pyerrors.h"
#include "auth/credentials/pycredentials.h"
#include "trans2.h"
#include "libsmb/clirap.h"
#include "librpc/rpc/pyrpc_util.h"
#include "librpc/gen_ndr/ndr_security.h"

#define LIST_ATTRIBUTE_MASK \
	(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN)

static PyTypeObject *dom_sid_Type = NULL;

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

/*
 * We're using "const char * const *" for keywords,
 * PyArg_ParseTupleAndKeywords expects a "char **". Confine the
 * inevitable warnings to just one place.
 */
static int ParseTupleAndKeywords(PyObject *args, PyObject *kw,
				 const char *format, const char * const *keywords,
				 ...)
{
	char **_keywords = discard_const_p(char *, keywords);
	va_list a;
	int ret;
	va_start(a, keywords);
	ret = PyArg_VaParseTupleAndKeywords(args, kw, format,
					    _keywords, a);
	va_end(a);
	return ret;
}

struct py_cli_thread;

struct py_cli_oplock_break {
	uint16_t fnum;
	uint8_t level;
};

struct py_cli_state {
	PyObject_HEAD
	struct cli_state *cli;
	struct tevent_context *ev;
	int (*req_wait_fn)(struct tevent_context *ev,
			   struct tevent_req *req);
	struct py_cli_thread *thread_state;

	struct tevent_req *oplock_waiter;
	struct py_cli_oplock_break *oplock_breaks;
	struct py_tevent_cond *oplock_cond;
};

#ifdef HAVE_PTHREAD

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
		TALLOC_CTX *frame = talloc_stackframe();
		int ret;
		ret = tevent_loop_once(self->ev);
		assert(ret == 0);
		TALLOC_FREE(frame);
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

	if (t->shutdown_pipe[1] != -1) {
		do {
			/*
			* This will wake the poll thread from the poll(2)
			*/
			written = write(t->shutdown_pipe[1], &c, 1);
		} while ((written == -1) && (errno == EINTR));
	}

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

static int py_tevent_cond_req_wait(struct tevent_context *ev,
				   struct tevent_req *req);

static bool py_cli_state_setup_mt_ev(struct py_cli_state *self)
{
	struct py_cli_thread *t = NULL;
	int ret;

	self->ev = tevent_context_init_byname(NULL, "poll_mt");
	if (self->ev == NULL) {
		goto fail;
	}
	samba_tevent_set_debug(self->ev, "pylibsmb_tevent_mt");
	tevent_set_trace_callback(self->ev, py_cli_state_trace_callback, self);

	self->req_wait_fn = py_tevent_cond_req_wait;

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

#if PY_VERSION_HEX < 0x03070000
	/*
	 * Should be explicitly called in 3.6 and older, see
	 * https://docs.python.org/3/c-api/init.html#c.PyEval_InitThreads
	 */
	PyEval_InitThreads();
#endif

	ret = pthread_create(&t->id, NULL, py_cli_state_poll_thread, self);
	if (ret != 0) {
		goto fail;
	}
	talloc_set_destructor(self->thread_state, py_cli_thread_destructor);
	return true;

fail:
	if (t != NULL) {
		TALLOC_FREE(t->shutdown_fde);

		if (t->shutdown_pipe[0] != -1) {
			close(t->shutdown_pipe[0]);
			t->shutdown_pipe[0] = -1;
		}
		if (t->shutdown_pipe[1] != -1) {
			close(t->shutdown_pipe[1]);
			t->shutdown_pipe[1] = -1;
		}
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

static int py_tevent_cond_wait(struct py_tevent_cond *cond)
{
	int ret, result;

	result = pthread_mutex_init(&cond->mutex, NULL);
	if (result != 0) {
		goto fail;
	}
	result = pthread_cond_init(&cond->cond, NULL);
	if (result != 0) {
		goto fail_mutex;
	}

	result = pthread_mutex_lock(&cond->mutex);
	if (result != 0) {
		goto fail_cond;
	}

	cond->is_done = false;

	while (!cond->is_done) {

		Py_BEGIN_ALLOW_THREADS
		result = pthread_cond_wait(&cond->cond, &cond->mutex);
		Py_END_ALLOW_THREADS

		if (result != 0) {
			goto fail_unlock;
		}
	}

fail_unlock:
	ret = pthread_mutex_unlock(&cond->mutex);
	assert(ret == 0);
fail_cond:
	ret = pthread_cond_destroy(&cond->cond);
	assert(ret == 0);
fail_mutex:
	ret = pthread_mutex_destroy(&cond->mutex);
	assert(ret == 0);
fail:
	return result;
}

static int py_tevent_cond_req_wait(struct tevent_context *ev,
				   struct tevent_req *req)
{
	struct py_tevent_cond cond;
	tevent_req_set_callback(req, py_tevent_signalme, &cond);
	return py_tevent_cond_wait(&cond);
}

static void py_tevent_cond_signal(struct py_tevent_cond *cond)
{
	int ret;

	ret = pthread_mutex_lock(&cond->mutex);
	assert(ret == 0);

	cond->is_done = true;

	ret = pthread_cond_signal(&cond->cond);
	assert(ret == 0);
	ret = pthread_mutex_unlock(&cond->mutex);
	assert(ret == 0);
}

static void py_tevent_signalme(struct tevent_req *req)
{
	struct py_tevent_cond *cond = (struct py_tevent_cond *)
		tevent_req_callback_data_void(req);

	py_tevent_cond_signal(cond);
}

#endif

static int py_tevent_req_wait(struct tevent_context *ev,
			      struct tevent_req *req);

static bool py_cli_state_setup_ev(struct py_cli_state *self)
{
	self->ev = tevent_context_init(NULL);
	if (self->ev == NULL) {
		return false;
	}

	samba_tevent_set_debug(self->ev, "pylibsmb_tevent");

	self->req_wait_fn = py_tevent_req_wait;

	return true;
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

static bool py_tevent_req_wait_exc(struct py_cli_state *self,
				   struct tevent_req *req)
{
	int ret;

	if (req == NULL) {
		PyErr_NoMemory();
		return false;
	}
	ret = self->req_wait_fn(self->ev, req);
	if (ret != 0) {
		TALLOC_FREE(req);
		errno = ret;
		PyErr_SetFromErrno(PyExc_RuntimeError);
		return false;
	}
	return true;
}

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
	self->oplock_waiter = NULL;
	self->oplock_cond = NULL;
	self->oplock_breaks = NULL;
	return (PyObject *)self;
}

static struct smb2_negotiate_contexts *py_cli_get_negotiate_contexts(
	TALLOC_CTX *mem_ctx, PyObject *list)
{
	struct smb2_negotiate_contexts *ctxs = NULL;
	Py_ssize_t i, len;
	int ret;

	ret = PyList_Check(list);
	if (!ret) {
		goto fail;
	}

	len = PyList_Size(list);
	if (len == 0) {
		goto fail;
	}

	ctxs = talloc_zero(mem_ctx, struct smb2_negotiate_contexts);
	if (ctxs == NULL) {
		goto fail;
	}

	for (i=0; i<len; i++) {
		NTSTATUS status;

		PyObject *t = PyList_GetItem(list, i);
		Py_ssize_t tlen;

		PyObject *ptype = NULL;
		long type;

		PyObject *pdata = NULL;
		DATA_BLOB data = { .data = NULL, };

		if (t == NULL) {
			goto fail;
		}

		ret = PyTuple_Check(t);
		if (!ret) {
			goto fail;
		}

		tlen = PyTuple_Size(t);
		if (tlen != 2) {
			goto fail;
		}

		ptype = PyTuple_GetItem(t, 0);
		if (ptype == NULL) {
			goto fail;
		}
		type = PyLong_AsLong(ptype);
		if ((type < 0) || (type > UINT16_MAX)) {
			goto fail;
		}

		pdata = PyTuple_GetItem(t, 1);

		ret = PyBytes_Check(pdata);
		if (!ret) {
			goto fail;
		}

		data.data = (uint8_t *)PyBytes_AsString(pdata);
		data.length = PyBytes_Size(pdata);

		status = smb2_negotiate_context_add(
			ctxs, ctxs, type, data.data, data.length);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	}
	return ctxs;

fail:
	TALLOC_FREE(ctxs);
	return NULL;
}

static void py_cli_got_oplock_break(struct tevent_req *req);

static int py_cli_state_init(struct py_cli_state *self, PyObject *args,
			     PyObject *kwds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	char *host, *share;
	PyObject *creds = NULL;
	struct cli_credentials *cli_creds;
	PyObject *py_lp = Py_None;
	struct loadparm_context *lp_ctx = NULL;
	PyObject *py_multi_threaded = Py_False;
	bool multi_threaded = false;
	PyObject *py_force_smb1 = Py_False;
	bool force_smb1 = false;
	PyObject *py_ipc = Py_False;
	PyObject *py_posix = Py_False;
	PyObject *py_negotiate_contexts = NULL;
	struct smb2_negotiate_contexts *negotiate_contexts = NULL;
	struct smb_transports ts = { .num_transports = 0, };
	bool use_ipc = false;
	bool request_posix = false;
	struct tevent_req *req;
	bool ret;
	int flags = 0;

	static const char *kwlist[] = {
		"host", "share", "lp", "creds",
		"multi_threaded", "force_smb1",
		"ipc",
		"posix",
		"negotiate_contexts",
		NULL
	};

	PyTypeObject *py_type_Credentials = get_pytype(
		"samba.credentials", "Credentials");
	if (py_type_Credentials == NULL) {
		TALLOC_FREE(frame);
		return -1;
	}

	ret = ParseTupleAndKeywords(
		args, kwds, "ssO|O!OOOOO", kwlist,
		&host, &share, &py_lp,
		py_type_Credentials, &creds,
		&py_multi_threaded,
		&py_force_smb1,
		&py_ipc,
		&py_posix,
		&py_negotiate_contexts);

	Py_DECREF(py_type_Credentials);

	if (!ret) {
		TALLOC_FREE(frame);
		return -1;
	}

	multi_threaded = PyObject_IsTrue(py_multi_threaded);
	force_smb1 = PyObject_IsTrue(py_force_smb1);

	if (force_smb1) {
		/*
		 * As most of the cli_*_send() function
		 * don't support SMB2 (it's only plugged
		 * into the sync wrapper functions currently)
		 * we have a way to force SMB1.
		 */
		flags = CLI_FULL_CONNECTION_FORCE_SMB1;
	}

	use_ipc = PyObject_IsTrue(py_ipc);
	if (use_ipc) {
		flags |= CLI_FULL_CONNECTION_IPC;
	}

	request_posix = PyObject_IsTrue(py_posix);
	if (request_posix) {
		flags |= CLI_FULL_CONNECTION_REQUEST_POSIX;
	}

	if (py_negotiate_contexts != NULL) {
		negotiate_contexts = py_cli_get_negotiate_contexts(
			frame, py_negotiate_contexts);
		if (negotiate_contexts == NULL) {
			TALLOC_FREE(frame);
			return -1;
		}
	}

	if (multi_threaded) {
#ifdef HAVE_PTHREAD
		ret = py_cli_state_setup_mt_ev(self);
		if (!ret) {
			TALLOC_FREE(frame);
			return -1;
		}
#else
		PyErr_SetString(PyExc_RuntimeError,
				"No PTHREAD support available");
		TALLOC_FREE(frame);
		return -1;
#endif
	} else {
		ret = py_cli_state_setup_ev(self);
		if (!ret) {
			TALLOC_FREE(frame);
			return -1;
		}
	}

	if (creds == NULL) {
		cli_creds = cli_credentials_init_anon(frame);
	} else {
		cli_creds = PyCredentials_AsCliCredentials(creds);
	}

	lp_ctx = lpcfg_from_py_object(frame, py_lp);
	if (lp_ctx == NULL) {
		TALLOC_FREE(frame);
		return -1;
	}

	ts = smb_transports_parse("client smb transports",
				  lpcfg_client_smb_transports(lp_ctx));

	req = cli_full_connection_creds_send(
		frame, self->ev, "myname", host, NULL, &ts, share, "?????",
		cli_creds, flags,
		negotiate_contexts);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return -1;
	}
	status = cli_full_connection_creds_recv(req, NULL, &self->cli);
	TALLOC_FREE(req);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return -1;
	}

	/*
	 * Oplocks require a multi threaded connection
	 */
	if (self->thread_state == NULL) {
		TALLOC_FREE(frame);
		return 0;
	}

	self->oplock_waiter = cli_smb_oplock_break_waiter_send(
		self->ev, self->ev, self->cli);
	if (self->oplock_waiter == NULL) {
		PyErr_NoMemory();
		TALLOC_FREE(frame);
		return -1;
	}
	tevent_req_set_callback(self->oplock_waiter, py_cli_got_oplock_break,
				self);
	TALLOC_FREE(frame);
	return 0;
}

static void py_cli_got_oplock_break(struct tevent_req *req)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct py_cli_state *self = (struct py_cli_state *)
		tevent_req_callback_data_void(req);
	struct py_cli_oplock_break b;
	struct py_cli_oplock_break *tmp;
	size_t num_breaks;
	NTSTATUS status;

	status = cli_smb_oplock_break_waiter_recv(req, &b.fnum, &b.level);
	TALLOC_FREE(req);
	self->oplock_waiter = NULL;

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return;
	}

	num_breaks = talloc_array_length(self->oplock_breaks);
	tmp = talloc_realloc(self->ev, self->oplock_breaks,
			     struct py_cli_oplock_break, num_breaks+1);
	if (tmp == NULL) {
		TALLOC_FREE(frame);
		return;
	}
	self->oplock_breaks = tmp;
	self->oplock_breaks[num_breaks] = b;

	if (self->oplock_cond != NULL) {
		py_tevent_cond_signal(self->oplock_cond);
	}

	self->oplock_waiter = cli_smb_oplock_break_waiter_send(
		self->ev, self->ev, self->cli);
	if (self->oplock_waiter == NULL) {
		TALLOC_FREE(frame);
		return;
	}
	tevent_req_set_callback(self->oplock_waiter, py_cli_got_oplock_break,
				self);
}

static PyObject *py_cli_get_oplock_break(struct py_cli_state *self,
					 PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	size_t num_oplock_breaks;

	if (!PyArg_ParseTuple(args, "")) {
		TALLOC_FREE(frame);
		return NULL;
	}

	if (self->thread_state == NULL) {
		PyErr_SetString(PyExc_RuntimeError,
				"get_oplock_break() only possible on "
				"a multi_threaded connection");
		TALLOC_FREE(frame);
		return NULL;
	}

	if (self->oplock_cond != NULL) {
		TALLOC_FREE(frame);
		errno = EBUSY;
		PyErr_SetFromErrno(PyExc_RuntimeError);
		return NULL;
	}

	num_oplock_breaks = talloc_array_length(self->oplock_breaks);

	if (num_oplock_breaks == 0) {
		struct py_tevent_cond cond;
		int ret;

		self->oplock_cond = &cond;
		ret = py_tevent_cond_wait(&cond);
		self->oplock_cond = NULL;

		if (ret != 0) {
			TALLOC_FREE(frame);
			errno = ret;
			PyErr_SetFromErrno(PyExc_RuntimeError);
			return NULL;
		}
	}

	num_oplock_breaks = talloc_array_length(self->oplock_breaks);
	if (num_oplock_breaks > 0) {
		PyObject *result;

		result = Py_BuildValue(
			"{s:i,s:i}",
			"fnum", self->oplock_breaks[0].fnum,
			"level", self->oplock_breaks[0].level);

		memmove(&self->oplock_breaks[0], &self->oplock_breaks[1],
			sizeof(self->oplock_breaks[0]) *
			(num_oplock_breaks - 1));
		self->oplock_breaks = talloc_realloc(
			NULL, self->oplock_breaks, struct py_cli_oplock_break,
			num_oplock_breaks - 1);

		TALLOC_FREE(frame);
		return result;
	}

	TALLOC_FREE(frame);
	Py_RETURN_NONE;
}

static void py_cli_state_dealloc(struct py_cli_state *self)
{
	TALLOC_CTX *frame = talloc_stackframe();

	TALLOC_FREE(self->thread_state);
	TALLOC_FREE(self->oplock_waiter);
	TALLOC_FREE(self->ev);

	if (self->cli != NULL) {
		cli_shutdown(self->cli);
		self->cli = NULL;
	}
	Py_TYPE(self)->tp_free((PyObject *)self);
	TALLOC_FREE(frame);
}

static PyObject *py_cli_settimeout(struct py_cli_state *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	unsigned int nmsecs = 0;
	unsigned int omsecs = 0;

	if (!PyArg_ParseTuple(args, "I", &nmsecs)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	omsecs = cli_set_timeout(self->cli, nmsecs);

	TALLOC_FREE(frame);
	return PyLong_FromLong(omsecs);
}

static PyObject *py_cli_echo(struct py_cli_state *self,
			     PyObject *Py_UNUSED(ignored))
{
	TALLOC_CTX *frame = talloc_stackframe();
	DATA_BLOB data = data_blob_string_const("keepalive");
	struct tevent_req *req = NULL;
	NTSTATUS status;

	req = cli_echo_send(frame, self->ev, self->cli, 1, data);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_echo_recv(req);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	TALLOC_FREE(frame);
	Py_RETURN_NONE;
}

static PyObject *py_cli_create(struct py_cli_state *self, PyObject *args,
			       PyObject *kwds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *fname;
	unsigned CreateFlags = 0;
	unsigned DesiredAccess = FILE_GENERIC_READ;
	unsigned FileAttributes = 0;
	unsigned ShareAccess = 0;
	unsigned CreateDisposition = FILE_OPEN;
	unsigned CreateOptions = 0;
	unsigned ImpersonationLevel = SMB2_IMPERSONATION_IMPERSONATION;
	unsigned SecurityFlags = 0;
	uint16_t fnum;
	struct tevent_req *req;
	NTSTATUS status;

	static const char *kwlist[] = {
		"Name", "CreateFlags", "DesiredAccess", "FileAttributes",
		"ShareAccess", "CreateDisposition", "CreateOptions",
		"ImpersonationLevel", "SecurityFlags", NULL };

	if (!ParseTupleAndKeywords(
		    args, kwds, "s|IIIIIIII", kwlist,
		    &fname, &CreateFlags, &DesiredAccess, &FileAttributes,
		    &ShareAccess, &CreateDisposition, &CreateOptions,
		    &ImpersonationLevel, &SecurityFlags)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	req = cli_ntcreate_send(frame, self->ev, self->cli, fname, CreateFlags,
				DesiredAccess, FileAttributes, ShareAccess,
				CreateDisposition, CreateOptions,
				ImpersonationLevel, SecurityFlags);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_ntcreate_recv(req, &fnum, NULL);
	TALLOC_FREE(req);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	TALLOC_FREE(frame);
	return Py_BuildValue("I", (unsigned)fnum);
}

static struct smb2_create_blobs *py_cli_get_create_contexts(
	TALLOC_CTX *mem_ctx, PyObject *list)
{
	struct smb2_create_blobs *ctxs = NULL;
	Py_ssize_t i, len;
	int ret;

	ret = PyList_Check(list);
	if (!ret) {
		goto fail;
	}

	len = PyList_Size(list);
	if (len == 0) {
		goto fail;
	}

	ctxs = talloc_zero(mem_ctx, struct smb2_create_blobs);
	if (ctxs == NULL) {
		goto fail;
	}

	for (i=0; i<len; i++) {
		NTSTATUS status;

		PyObject *t = NULL;
		Py_ssize_t tlen;

		PyObject *pname = NULL;
		char *name = NULL;

		PyObject *pdata = NULL;
		DATA_BLOB data = { .data = NULL, };

		t = PyList_GetItem(list, i);
		if (t == NULL) {
			goto fail;
		}

		ret = PyTuple_Check(t);
		if (!ret) {
			goto fail;
		}

		tlen = PyTuple_Size(t);
		if (tlen != 2) {
			goto fail;
		}

		pname = PyTuple_GetItem(t, 0);
		if (pname == NULL) {
			goto fail;
		}
		ret = PyBytes_Check(pname);
		if (!ret) {
			goto fail;
		}
		name = PyBytes_AsString(pname);

		pdata = PyTuple_GetItem(t, 1);
		if (pdata == NULL) {
			goto fail;
		}
		ret = PyBytes_Check(pdata);
		if (!ret) {
			goto fail;
		}
		data = (DATA_BLOB) {
			.data = (uint8_t *)PyBytes_AsString(pdata),
			.length = PyBytes_Size(pdata),
		};
		status = smb2_create_blob_add(ctxs, ctxs, name, data);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	}
	return ctxs;

fail:
	TALLOC_FREE(ctxs);
	return NULL;
}

static PyObject *py_cli_create_contexts(const struct smb2_create_blobs *blobs)
{
	PyObject *py_blobs = NULL;
	uint32_t i;

	if (blobs == NULL) {
		Py_RETURN_NONE;
	}

	py_blobs = PyList_New(blobs->num_blobs);
	if (py_blobs == NULL) {
		return NULL;
	}

	for (i=0; i<blobs->num_blobs; i++) {
		struct smb2_create_blob *blob = &blobs->blobs[i];
		PyObject *py_blob = NULL;
		int ret;

		py_blob = Py_BuildValue(
			"(yy#)",
			blob->tag,
			blob->data.data,
			(int)blob->data.length);
		if (py_blob == NULL) {
			goto fail;
		}

		ret = PyList_SetItem(py_blobs, i, py_blob);
		if (ret == -1) {
			Py_XDECREF(py_blob);
			goto fail;
		}
	}
	return py_blobs;

fail:
	Py_XDECREF(py_blobs);
	return NULL;
}

static PyObject *py_cli_create_returns(const struct smb_create_returns *r)
{
	PyObject *v = NULL;

	v = Py_BuildValue(
		"{sLsLsLsLsLsLsLsLsLsL}",
		"oplock_level",
		(unsigned long long)r->oplock_level,
		"flags",
		(unsigned long long)r->flags,
		"create_action",
		(unsigned long long)r->create_action,
		"creation_time",
		(unsigned long long)r->creation_time,
		"last_access_time",
		(unsigned long long)r->last_access_time,
		"last_write_time",
		(unsigned long long)r->last_write_time,
		"change_time",
		(unsigned long long)r->change_time,
		"allocation_size",
		(unsigned long long)r->allocation_size,
		"end_of_file",
		(unsigned long long)r->end_of_file,
		"file_attributes",
		(unsigned long long)r->file_attributes);
	return v;
}

static PyObject *py_cli_symlink_error(const struct symlink_reparse_struct *s)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *subst_utf8 = NULL, *print_utf8 = NULL;
	size_t subst_utf8_len, print_utf8_len;
	PyObject *v = NULL;
	bool ok = true;

	/*
	 * Python wants utf-8, regardless of our unix charset (which
	 * most likely is utf-8 these days, but you never know).
	 */

	ok = convert_string_talloc(
		frame,
		CH_UNIX,
		CH_UTF8,
		s->substitute_name,
		strlen(s->substitute_name),
		&subst_utf8,
		&subst_utf8_len);
	if (!ok) {
		goto fail;
	}

	ok = convert_string_talloc(
		frame,
		CH_UNIX,
		CH_UTF8,
		s->print_name,
		strlen(s->print_name),
		&print_utf8,
		&print_utf8_len);
	if (!ok) {
		goto fail;
	}

	v = Py_BuildValue(
		"{sLsssssL}",
		"unparsed_path_length",
		(unsigned long long)s->unparsed_path_length,
		"substitute_name",
		subst_utf8,
		"print_name",
		print_utf8,
		"flags",
		(unsigned long long)s->flags);

fail:
	TALLOC_FREE(frame);
	return v;
}

static PyObject *py_cli_get_posix_fs_info(
	struct py_cli_state *self, PyObject *args, PyObject *kwds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct tevent_req *req = NULL;
	uint32_t optimal_transfer_size = 0;
	uint32_t block_size = 0;
	uint64_t total_blocks = 0;
	uint64_t blocks_available = 0;
	uint64_t user_blocks_available = 0;
	uint64_t total_file_nodes = 0;
	uint64_t free_file_nodes = 0;
	uint64_t fs_identifier = 0;

	req = cli_get_posix_fs_info_send(frame, self->ev, self->cli);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	status = cli_get_posix_fs_info_recv(req,
					    &optimal_transfer_size,
					    &block_size,
					    &total_blocks,
					    &blocks_available,
					    &user_blocks_available,
					    &total_file_nodes,
					    &free_file_nodes,
					    &fs_identifier);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	TALLOC_FREE(frame);
	return Py_BuildValue("{s:I,s:I,s:I,s:I,s:I,s:I,s:I,s:I}",
			     "optimal_transfer_size", optimal_transfer_size,
			     "block_size", block_size,
			     "total_blocks", total_blocks,
			     "blocks_available", blocks_available,
			     "user_blocks_available", user_blocks_available,
			     "total_file_nodes", total_file_nodes,
			     "free_file_nodes", free_file_nodes,
			     "fs_identifier", fs_identifier);
}

static PyObject *py_cli_create_ex(
	struct py_cli_state *self, PyObject *args, PyObject *kwds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *fname = NULL;
	unsigned CreateFlags = 0;
	unsigned DesiredAccess = FILE_GENERIC_READ;
	unsigned FileAttributes = 0;
	unsigned ShareAccess = 0;
	unsigned CreateDisposition = FILE_OPEN;
	unsigned CreateOptions = 0;
	unsigned ImpersonationLevel = SMB2_IMPERSONATION_IMPERSONATION;
	unsigned SecurityFlags = 0;
	PyObject *py_create_contexts_in = NULL;
	PyObject *py_create_contexts_out = NULL;
	struct smb2_create_blobs *create_contexts_in = NULL;
	struct smb2_create_blobs create_contexts_out = { .num_blobs = 0 };
	struct smb_create_returns cr = { .create_action = 0, };
	struct symlink_reparse_struct *symlink = NULL;
	PyObject *py_cr = NULL;
	uint16_t fnum;
	struct tevent_req *req;
	NTSTATUS status;
	int ret;
	bool ok;
	PyObject *v = NULL;

	static const char *kwlist[] = {
		"Name",
		"CreateFlags",
		"DesiredAccess",
		"FileAttributes",
		"ShareAccess",
		"CreateDisposition",
		"CreateOptions",
		"ImpersonationLevel",
		"SecurityFlags",
		"CreateContexts",
		NULL };

	ret = ParseTupleAndKeywords(
		args,
		kwds,
		"s|IIIIIIIIO",
		kwlist,
		&fname,
		&CreateFlags,
		&DesiredAccess,
		&FileAttributes,
		&ShareAccess,
		&CreateDisposition,
		&CreateOptions,
		&ImpersonationLevel,
		&SecurityFlags,
		&py_create_contexts_in);
	if (!ret) {
		TALLOC_FREE(frame);
		return NULL;
	}

	if (py_create_contexts_in != NULL) {
		create_contexts_in = py_cli_get_create_contexts(
			frame, py_create_contexts_in);
		if (create_contexts_in == NULL) {
			TALLOC_FREE(frame);
			errno = EINVAL;
			PyErr_SetFromErrno(PyExc_RuntimeError);
			return NULL;
		}
	}

	if (smbXcli_conn_protocol(self->cli->conn) >= PROTOCOL_SMB2_02) {
		struct cli_smb2_create_flags cflags = {
			.batch_oplock = (CreateFlags & REQUEST_BATCH_OPLOCK),
			.exclusive_oplock = (CreateFlags & REQUEST_OPLOCK),
		};

		req = cli_smb2_create_fnum_send(
			frame,
			self->ev,
			self->cli,
			fname,
			cflags,
			ImpersonationLevel,
			DesiredAccess,
			FileAttributes,
			ShareAccess,
			CreateDisposition,
			CreateOptions,
			create_contexts_in);
	} else {
		req = cli_ntcreate_send(
			frame,
			self->ev,
			self->cli,
			fname,
			CreateFlags,
			DesiredAccess,
			FileAttributes,
			ShareAccess,
			CreateDisposition,
			CreateOptions,
			ImpersonationLevel,
			SecurityFlags);
	}

	TALLOC_FREE(create_contexts_in);

	ok = py_tevent_req_wait_exc(self, req);
	if (!ok) {
		TALLOC_FREE(frame);
		return NULL;
	}

	if (smbXcli_conn_protocol(self->cli->conn) >= PROTOCOL_SMB2_02) {
		status = cli_smb2_create_fnum_recv(
			req,
			&fnum,
			&cr,
			frame,
			&create_contexts_out,
			&symlink);
	} else {
		status = cli_ntcreate_recv(req, &fnum, &cr);
	}

	TALLOC_FREE(req);

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	SMB_ASSERT(symlink == NULL);

	py_create_contexts_out = py_cli_create_contexts(&create_contexts_out);
	TALLOC_FREE(create_contexts_out.blobs);
	if (py_create_contexts_out == NULL) {
		goto nomem;
	}

	py_cr = py_cli_create_returns(&cr);
	if (py_cr == NULL) {
		goto nomem;
	}

	v = Py_BuildValue("(IOO)",
			  (unsigned)fnum,
			  py_cr,
			  py_create_contexts_out);
	TALLOC_FREE(frame);
	return v;
nomem:
	status = NT_STATUS_NO_MEMORY;
fail:
	Py_XDECREF(py_create_contexts_out);
	Py_XDECREF(py_cr);
	Py_XDECREF(v);

	if (NT_STATUS_EQUAL(status, NT_STATUS_STOPPED_ON_SYMLINK) &&
	    (symlink != NULL)) {
		PyErr_SetObject(
			PyObject_GetAttrString(
				PyImport_ImportModule("samba"),
				"NTSTATUSError"),
			Py_BuildValue(
				"I,s,O",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status),
				py_cli_symlink_error(symlink)));
	} else {
		PyErr_SetNTSTATUS(status);
	}

	TALLOC_FREE(frame);
	return NULL;
}

static PyObject *py_cli_close(struct py_cli_state *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_req *req;
	int fnum;
	int flags = 0;
	NTSTATUS status;

	if (!PyArg_ParseTuple(args, "i|i", &fnum, &flags)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	req = cli_close_send(frame, self->ev, self->cli, fnum, flags);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_close_recv(req);
	TALLOC_FREE(req);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	TALLOC_FREE(frame);
	Py_RETURN_NONE;
}

static PyObject *py_wire_mode_to_unix(struct py_cli_state *self,
				      PyObject *args)
{
	unsigned long long wire = 0;
	mode_t mode;
	bool ok;
	PyObject *v = NULL;

	ok = PyArg_ParseTuple(args, "K", &wire);
	if (!ok) {
		return NULL;
	}
	mode = wire_mode_to_unix(wire);

	v = Py_BuildValue("I", (unsigned)mode);
	return v;
}

static PyObject *py_unix_mode_to_wire(struct py_cli_state *self,
				      PyObject *args)
{
	unsigned long long mode = 0;
	uint32_t wire;
	bool ok;
	PyObject *v = NULL;

	ok = PyArg_ParseTuple(args, "K", &mode);
	if (!ok) {
		return NULL;
	}
	wire = unix_mode_to_wire(mode);

	v = Py_BuildValue("I", (unsigned)wire);
	return v;
}

static PyObject *py_cli_qfileinfo(struct py_cli_state *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_req *req = NULL;
	int fnum, level;
	uint16_t recv_flags2;
	uint8_t *rdata = NULL;
	uint32_t num_rdata;
	PyObject *result = NULL;
	NTSTATUS status;

	if (!PyArg_ParseTuple(args, "ii", &fnum, &level)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	req = cli_qfileinfo_send(
		frame, self->ev, self->cli, fnum, level, 0, UINT32_MAX);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_qfileinfo_recv(
		req, frame, &recv_flags2, &rdata, &num_rdata);
	TALLOC_FREE(req);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	switch (level) {
	case FSCC_FILE_ATTRIBUTE_TAG_INFORMATION: {
		uint32_t mode = PULL_LE_U32(rdata, 0);
		uint32_t tag = PULL_LE_U32(rdata, 4);

		if (num_rdata != 8) {
			PyErr_SetNTSTATUS(NT_STATUS_INVALID_NETWORK_RESPONSE);
			TALLOC_FREE(frame);
			return NULL;
		}

		result = Py_BuildValue("{s:K,s:K}",
				       "mode",
				       (unsigned long long)mode,
				       "tag",
				       (unsigned long long)tag);
		break;
	}
	case FSCC_FILE_POSIX_INFORMATION: {
		size_t data_off = 0;
		time_t btime;
		time_t atime;
		time_t mtime;
		time_t ctime;
		uint64_t size;
		uint64_t alloc_size;
		uint32_t attr;
		uint64_t ino;
		uint32_t dev;
		uint32_t nlinks;
		uint32_t reparse_tag;
		uint32_t mode;
		size_t sid_size;
		enum ndr_err_code ndr_err;
		struct dom_sid owner, group;
		struct dom_sid_buf owner_buf, group_buf;

		if (num_rdata < 80) {
			PyErr_SetNTSTATUS(NT_STATUS_INVALID_NETWORK_RESPONSE);
			TALLOC_FREE(frame);
			return NULL;
		}

		btime = nt_time_to_unix(PULL_LE_U64(rdata, data_off));
		data_off += 8;
		atime = nt_time_to_unix(PULL_LE_U64(rdata, data_off));
		data_off += 8;
		mtime = nt_time_to_unix(PULL_LE_U64(rdata, data_off));
		data_off += 8;
		ctime = nt_time_to_unix(PULL_LE_U64(rdata, data_off));
		data_off += 8;
		size = PULL_LE_U64(rdata, data_off);
		data_off += 8;
		alloc_size = PULL_LE_U64(rdata, data_off);
		data_off += 8;
		attr = PULL_LE_U32(rdata, data_off);
		data_off += 4;
		ino = PULL_LE_U64(rdata, data_off);
		data_off += 8;
		dev = PULL_LE_U32(rdata, data_off);
		data_off += 4;
		/* 4 bytes reserved */
		data_off += 4;
		nlinks = PULL_LE_U32(rdata, data_off);
		data_off += 4;
		reparse_tag = PULL_LE_U32(rdata, data_off);
		data_off += 4;
		mode = PULL_LE_U32(rdata, data_off);
		data_off += 4;

		ndr_err = ndr_pull_struct_blob_noalloc(
			rdata + data_off,
			num_rdata - data_off,
			&owner,
			(ndr_pull_flags_fn_t)ndr_pull_dom_sid,
			&sid_size);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			PyErr_SetNTSTATUS(NT_STATUS_INVALID_NETWORK_RESPONSE);
			TALLOC_FREE(frame);
			return NULL;
		}
		if (data_off + sid_size < data_off ||
		    data_off + sid_size > num_rdata)
		{
			PyErr_SetNTSTATUS(NT_STATUS_INVALID_NETWORK_RESPONSE);
			TALLOC_FREE(frame);
			return NULL;
		}
		data_off += sid_size;

		ndr_err = ndr_pull_struct_blob_noalloc(
			rdata + data_off,
			num_rdata - data_off,
			&group,
			(ndr_pull_flags_fn_t)ndr_pull_dom_sid,
			&sid_size);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			PyErr_SetNTSTATUS(NT_STATUS_INVALID_NETWORK_RESPONSE);
			TALLOC_FREE(frame);
			return NULL;
		}

		result = Py_BuildValue(
			"{s:i,"			/* attr */
			"s:K,s:K,s:K,s:K,"	/* dates */
			"s:K,s:K,"		/* sizes */
			"s:K,s:K,s:K,"		/* ino, dev, nlinks */
			"s:K,s:K,"		/* tag, mode */
			"s:s,s:s}",		/* owner, group */

			"attrib",
			attr,

			"btime",
			(unsigned long long)btime,
			"atime",
			(unsigned long long)atime,
			"mtime",
			(unsigned long long)mtime,
			"ctime",
			(unsigned long long)ctime,

			"allocation_size",
			(unsigned long long)alloc_size,
			"size",
			(unsigned long long)size,

			"ino",
			(unsigned long long)ino,
			"dev",
			(unsigned long long)dev,
			"nlink",
			(unsigned long long)nlinks,

			"reparse_tag",
			(unsigned long long)reparse_tag,
			"perms",
			(unsigned long long)mode,

			"owner_sid",
			dom_sid_str_buf(&owner, &owner_buf),
			"group_sid",
			dom_sid_str_buf(&group, &group_buf));
		break;
	}
	default:
		result = PyBytes_FromStringAndSize((char *)rdata, num_rdata);
		break;
	}

	TALLOC_FREE(frame);

	return result;
}

static PyObject *py_cli_rename(
	struct py_cli_state *self, PyObject *args, PyObject *kwds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *fname_src = NULL, *fname_dst = NULL;
	int replace = false;
	struct tevent_req *req = NULL;
	NTSTATUS status;
	bool ok;

	static const char *kwlist[] = { "src", "dst", "replace", NULL };

	ok = ParseTupleAndKeywords(
		args, kwds, "ss|p", kwlist, &fname_src, &fname_dst, &replace);
	if (!ok) {
		TALLOC_FREE(frame);
		return NULL;
	}

	req = cli_rename_send(
		frame, self->ev, self->cli, fname_src, fname_dst, replace);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_rename_recv(req);
	TALLOC_FREE(req);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	TALLOC_FREE(frame);
	Py_RETURN_NONE;
}


struct push_state {
	char *data;
	off_t nread;
	off_t total_data;
};

/*
 * cli_push() helper to write a chunk of data to a remote file
 */
static size_t push_data(uint8_t *buf, size_t n, void *priv)
{
	struct push_state *state = (struct push_state *)priv;
	char *curr_ptr = NULL;
	off_t remaining;
	size_t copied_bytes;

	if (state->nread >= state->total_data) {
		return 0;
	}

	curr_ptr = state->data + state->nread;
	remaining = state->total_data - state->nread;
	copied_bytes = MIN(remaining, n);

	memcpy(buf, curr_ptr, copied_bytes);
	state->nread += copied_bytes;
	return copied_bytes;
}

/*
 * Writes a file with the contents specified
 */
static PyObject *py_smb_savefile(struct py_cli_state *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	uint16_t fnum;
	const char *filename = NULL;
	char *data = NULL;
	Py_ssize_t size = 0;
	NTSTATUS status;
	struct tevent_req *req = NULL;
	struct push_state state;

	if (!PyArg_ParseTuple(args, "s"PYARG_BYTES_LEN":savefile", &filename,
			      &data, &size)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	/* create a new file handle for writing to */
	req = cli_ntcreate_send(frame, self->ev, self->cli, filename, 0,
				FILE_WRITE_DATA, FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ|FILE_SHARE_WRITE,
				FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE,
				SMB2_IMPERSONATION_IMPERSONATION, 0);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_ntcreate_recv(req, &fnum, NULL);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	/* write the new file contents */
	state.data = data;
	state.nread = 0;
	state.total_data = size;

	req = cli_push_send(frame, self->ev, self->cli, fnum, 0, 0, 0,
			    push_data, &state);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_push_recv(req);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	/* close the file handle */
	req = cli_close_send(frame, self->ev, self->cli, fnum, 0);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_close_recv(req);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	TALLOC_FREE(frame);
	Py_RETURN_NONE;
}

static PyObject *py_cli_write(struct py_cli_state *self, PyObject *args,
			      PyObject *kwds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	int fnum;
	unsigned mode = 0;
	char *buf;
	Py_ssize_t buflen;
	unsigned long long offset;
	struct tevent_req *req;
	NTSTATUS status;
	size_t written;

	static const char *kwlist[] = {
		"fnum", "buffer", "offset", "mode", NULL };

	if (!ParseTupleAndKeywords(
		    args, kwds, "i" PYARG_BYTES_LEN "K|I", kwlist,
		    &fnum, &buf, &buflen, &offset, &mode)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	req = cli_write_send(NULL, self->ev, self->cli, fnum, mode,
			     (uint8_t *)buf, offset, buflen);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_write_recv(req, &written);
	TALLOC_FREE(req);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}
	TALLOC_FREE(frame);
	return Py_BuildValue("K", (unsigned long long)written);
}

/*
 * Returns the size of the given file
 */
static NTSTATUS py_smb_filesize(struct py_cli_state *self, uint16_t fnum,
				off_t *size)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct tevent_req *req = NULL;

	req = cli_qfileinfo_basic_send(frame, self->ev, self->cli, fnum);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_ERROR;
	}
	status = cli_qfileinfo_basic_recv(
		req, NULL, size, NULL, NULL, NULL, NULL, NULL);
	TALLOC_FREE(frame);
	return status;
}

/*
 * Loads the specified file's contents and returns it
 */
static PyObject *py_smb_loadfile(struct py_cli_state *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	const char *filename = NULL;
	struct tevent_req *req = NULL;
	uint16_t fnum;
	off_t size;
	char *buf = NULL;
	off_t nread = 0;
	PyObject *result = NULL;

	if (!PyArg_ParseTuple(args, "s:loadfile", &filename)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	/* get a read file handle */
	req = cli_ntcreate_send(NULL, self->ev, self->cli, filename, 0,
				FILE_READ_DATA | FILE_READ_ATTRIBUTES,
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ, FILE_OPEN, 0,
				SMB2_IMPERSONATION_IMPERSONATION, 0);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_ntcreate_recv(req, &fnum, NULL);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	/* get a buffer to hold the file contents */
	status = py_smb_filesize(self, fnum, &size);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	result = PyBytes_FromStringAndSize(NULL, size);
	if (result == NULL) {
		TALLOC_FREE(frame);
		return NULL;
	}

	/* read the file contents */
	buf = PyBytes_AS_STRING(result);
	req = cli_pull_send(NULL, self->ev, self->cli, fnum, 0, size,
			    size, cli_read_sink, &buf);
	if (!py_tevent_req_wait_exc(self, req)) {
		Py_XDECREF(result);
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_pull_recv(req, &nread);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		Py_XDECREF(result);
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	/* close the file handle */
	req = cli_close_send(NULL, self->ev, self->cli, fnum, 0);
	if (!py_tevent_req_wait_exc(self, req)) {
		Py_XDECREF(result);
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_close_recv(req);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		Py_XDECREF(result);
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	/* sanity-check we read the expected number of bytes */
	if (nread > size) {
		Py_XDECREF(result);
		PyErr_Format(PyExc_IOError,
			     "read invalid - got %zu requested %zu",
			     nread, size);
		TALLOC_FREE(frame);
		return NULL;
	}

	if (nread < size) {
		if (_PyBytes_Resize(&result, nread) < 0) {
			TALLOC_FREE(frame);
			return NULL;
		}
	}

	TALLOC_FREE(frame);
	return result;
}

static PyObject *py_cli_read(struct py_cli_state *self, PyObject *args,
			     PyObject *kwds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	int fnum;
	unsigned long long offset;
	unsigned size;
	struct tevent_req *req;
	NTSTATUS status;
	char *buf;
	size_t received;
	PyObject *result;

	static const char *kwlist[] = {
		"fnum", "offset", "size", NULL };

	if (!ParseTupleAndKeywords(
		    args, kwds, "iKI", kwlist, &fnum, &offset,
		    &size)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	result = PyBytes_FromStringAndSize(NULL, size);
	if (result == NULL) {
		TALLOC_FREE(frame);
		return NULL;
	}
	buf = PyBytes_AS_STRING(result);

	req = cli_read_send(NULL, self->ev, self->cli, fnum,
			    buf, offset, size);
	if (!py_tevent_req_wait_exc(self, req)) {
		Py_XDECREF(result);
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_read_recv(req, &received);
	TALLOC_FREE(req);

	if (!NT_STATUS_IS_OK(status)) {
		Py_XDECREF(result);
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	if (received > size) {
		Py_XDECREF(result);
		PyErr_Format(PyExc_IOError,
			     "read invalid - got %zu requested %u",
			     received, size);
		TALLOC_FREE(frame);
		return NULL;
	}

	if (received < size) {
		if (_PyBytes_Resize(&result, received) < 0) {
			TALLOC_FREE(frame);
			return NULL;
		}
	}

	TALLOC_FREE(frame);
	return result;
}

static PyObject *py_cli_ftruncate(struct py_cli_state *self, PyObject *args,
				  PyObject *kwds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	int fnum;
	unsigned long long size;
	struct tevent_req *req;
	NTSTATUS status;

	static const char *kwlist[] = {
		"fnum", "size", NULL };

	if (!ParseTupleAndKeywords(
		    args, kwds, "IK", kwlist, &fnum, &size)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	req = cli_ftruncate_send(frame, self->ev, self->cli, fnum, size);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_ftruncate_recv(req);
	TALLOC_FREE(req);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	TALLOC_FREE(frame);
	Py_RETURN_NONE;
}

static PyObject *py_cli_delete_on_close(struct py_cli_state *self,
					PyObject *args,
					PyObject *kwds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	unsigned fnum, flag;
	struct tevent_req *req;
	NTSTATUS status;

	static const char *kwlist[] = {
		"fnum", "flag", NULL };

	if (!ParseTupleAndKeywords(
		    args, kwds, "II", kwlist, &fnum, &flag)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	req = cli_nt_delete_on_close_send(frame, self->ev, self->cli, fnum,
					  flag);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_nt_delete_on_close_recv(req);
	TALLOC_FREE(req);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	TALLOC_FREE(frame);
	Py_RETURN_NONE;
}

struct py_cli_notify_state {
	PyObject_HEAD
	struct py_cli_state *py_cli_state;
	struct tevent_req *req;
};

static void py_cli_notify_state_dealloc(struct py_cli_notify_state *self)
{
	TALLOC_CTX *frame = talloc_stackframe();

	TALLOC_FREE(self->req);
	Py_CLEAR(self->py_cli_state);
	Py_TYPE(self)->tp_free(self);

	TALLOC_FREE(frame);
}

static PyTypeObject py_cli_notify_state_type;

static PyObject *py_cli_notify(struct py_cli_state *self,
			       PyObject *args,
			       PyObject *kwds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	static const char *kwlist[] = {
		"fnum",
		"buffer_size",
		"completion_filter",
		"recursive",
		NULL
	};
	unsigned fnum = 0;
	unsigned buffer_size = 0;
	unsigned completion_filter = 0;
	PyObject *py_recursive = Py_False;
	bool recursive = false;
	struct tevent_req *req = NULL;
	struct tevent_queue *send_queue = NULL;
	struct tevent_req *flush_req = NULL;
	bool ok;
	struct py_cli_notify_state *py_notify_state = NULL;
	struct timeval endtime;

	ok = ParseTupleAndKeywords(args,
				   kwds,
				   "IIIO",
				   kwlist,
				   &fnum,
				   &buffer_size,
				   &completion_filter,
				   &py_recursive);
	if (!ok) {
		TALLOC_FREE(frame);
		return NULL;
	}

	recursive = PyObject_IsTrue(py_recursive);

	req = cli_notify_send(NULL,
			      self->ev,
			      self->cli,
			      fnum,
			      buffer_size,
			      completion_filter,
			      recursive);
	if (req == NULL) {
		TALLOC_FREE(frame);
		PyErr_NoMemory();
		return NULL;
	}
	/*
	 * only reparent to frame,
	 * if we would pass frame to
	 * cli_query_security_descriptor_recv()
	 * we'd leak a potential talloc_stackframe_pool
	 * via py_return_ndr_struct().
	 */
	talloc_reparent(NULL, frame, req);

	/*
	 * Just wait for the request being submitted to
	 * the kernel/socket/wire.
	 */
	send_queue = smbXcli_conn_send_queue(self->cli->conn);
	flush_req = tevent_queue_wait_send(req,
					   self->ev,
					   send_queue);
	if (flush_req == NULL) {
		TALLOC_FREE(frame);
		PyErr_NoMemory();
		return NULL;
	}
	endtime = timeval_current_ofs_msec(self->cli->timeout);
	ok = tevent_req_set_endtime(flush_req,
				    self->ev,
				    endtime);
	if (!ok) {
		TALLOC_FREE(frame);
		PyErr_NoMemory();
		return NULL;
	}
	ok = py_tevent_req_wait_exc(self, flush_req);
	if (!ok) {
		TALLOC_FREE(frame);
		return NULL;
	}
	TALLOC_FREE(flush_req);

	py_notify_state = (struct py_cli_notify_state *)
		py_cli_notify_state_type.tp_alloc(&py_cli_notify_state_type, 0);
	if (py_notify_state == NULL) {
		TALLOC_FREE(frame);
		PyErr_NoMemory();
		return NULL;
	}
	Py_INCREF(self);
	py_notify_state->py_cli_state = self;
	py_notify_state->req = talloc_move(NULL, &req);

	TALLOC_FREE(frame);
	return (PyObject *)py_notify_state;
}

static PyObject *py_cli_notify_get_changes(struct py_cli_notify_state *self,
					   PyObject *args,
					   PyObject *kwds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct py_cli_state *py_cli_state = self->py_cli_state;
	struct tevent_req *req = NULL;
	uint32_t i;
	uint32_t num_changes = 0;
	struct notify_change *changes = NULL;
	PyObject *result = NULL;
	NTSTATUS status;
	bool ok;
	static const char *kwlist[] = {
		"wait",
		NULL
	};
	PyObject *py_wait = Py_False;
	bool wait = false;
	bool pending;

	ok = ParseTupleAndKeywords(args,
				   kwds,
				   "O",
				   kwlist,
				   &py_wait);
	if (!ok) {
		TALLOC_FREE(frame);
		return NULL;
	}

	wait = PyObject_IsTrue(py_wait);

	if (self->req == NULL) {
		PyErr_SetString(PyExc_RuntimeError,
				"TODO req == NULL "
				"- missing change notify request?");
		TALLOC_FREE(frame);
		return NULL;
	}

	pending = tevent_req_is_in_progress(self->req);
	if (pending && !wait) {
		TALLOC_FREE(frame);
		Py_RETURN_NONE;
	}

	/*
	 * Now we really return success or an exception
	 * so we move self->req to frame and set
	 * self->req to NULL.
	 *
	 * Below we also call Py_CLEAR(self->py_cli_state)
	 * as soon as possible.
	 */
	req = talloc_move(frame, &self->req);

	if (pending) {
		struct timeval endtime;

		endtime = timeval_current_ofs_msec(py_cli_state->cli->timeout);
		ok = tevent_req_set_endtime(req,
					    py_cli_state->ev,
					    endtime);
		if (!ok) {
			TALLOC_FREE(frame);
			Py_CLEAR(self->py_cli_state);
			PyErr_NoMemory();
			return NULL;
		}
	}

	ok = py_tevent_req_wait_exc(py_cli_state, req);
	Py_CLEAR(self->py_cli_state);
	if (!ok) {
		TALLOC_FREE(frame);
		return NULL;
	}

	status = cli_notify_recv(req, req, &num_changes, &changes);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	result = Py_BuildValue("[]");
	if (result == NULL) {
		TALLOC_FREE(frame);
		return NULL;
	}

	for (i = 0; i < num_changes; i++) {
		PyObject *change = NULL;
		int ret;

		change = Py_BuildValue("{s:s,s:I}",
				       "name", changes[i].name,
				       "action", changes[i].action);
		if (change == NULL) {
			Py_XDECREF(result);
			TALLOC_FREE(frame);
			return NULL;
		}

		ret = PyList_Append(result, change);
		Py_DECREF(change);
		if (ret == -1) {
			Py_XDECREF(result);
			TALLOC_FREE(frame);
			return NULL;
		}
	}

	TALLOC_FREE(frame);
	return result;
}

static PyMethodDef py_cli_notify_state_methods[] = {
	{
		.ml_name = "get_changes",
		.ml_meth = (PY_DISCARD_FUNC_SIG(PyCFunction,
			    py_cli_notify_get_changes)),
		.ml_flags = METH_VARARGS|METH_KEYWORDS,
		.ml_doc  = "Wait for change notifications: \n"
			   "N.get_changes(wait=BOOLEAN) -> "
			   "change notifications as a dictionary\n"
			   "\t\tList contents of a directory. The keys are, \n"
			   "\t\t\tname: name of changed object\n"
			   "\t\t\taction: type of the change\n"
			   "None is returned if there's no response yet and "
			   "wait=False is passed"
	},
	{
		.ml_name = NULL
	}
};

static PyTypeObject py_cli_notify_state_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "libsmb_samba_cwrapper.Notify",
	.tp_basicsize = sizeof(struct py_cli_notify_state),
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_doc = "notify request",
	.tp_dealloc = (destructor)py_cli_notify_state_dealloc,
	.tp_methods = py_cli_notify_state_methods,
};

/*
 * Helper to add posix directory listing entries to an overall Python list
 */
static NTSTATUS list_posix_helper(struct file_info *finfo,
				  const char *mask, void *state)
{
	PyObject *result = (PyObject *)state;
	PyObject *file = NULL;
	struct dom_sid_buf owner_buf, group_buf;
	int ret;

	/*
	 * Build a dictionary representing the file info.
	 */
	file = Py_BuildValue("{s:s,s:I,"
			     "s:K,s:K,"
			     "s:l,s:l,s:l,s:l,"
			     "s:i,s:K,s:i,s:i,s:I,"
			     "s:s,s:s,s:k}",
			     "name",
			     finfo->name,
			     "attrib",
			     finfo->attr,
			     "size",
			     finfo->size,
			     "allocation_size",
			     finfo->allocated_size,
			     "btime",
			     convert_timespec_to_time_t(finfo->btime_ts),
			     "atime",
			     convert_timespec_to_time_t(finfo->atime_ts),
			     "mtime",
			     convert_timespec_to_time_t(finfo->mtime_ts),
			     "ctime",
			     convert_timespec_to_time_t(finfo->ctime_ts),
			     "perms",
			     finfo->st_ex_mode,
			     "ino",
			     finfo->ino,
			     "dev",
			     finfo->st_ex_dev,
			     "nlink",
			     finfo->st_ex_nlink,
			     "reparse_tag",
			     finfo->reparse_tag,
			     "owner_sid",
			     dom_sid_str_buf(&finfo->owner_sid, &owner_buf),
			     "group_sid",
			     dom_sid_str_buf(&finfo->group_sid, &group_buf),
			     "reparse_tag",
			     (unsigned long)finfo->reparse_tag);
	if (file == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = PyList_Append(result, file);
	Py_CLEAR(file);
	if (ret == -1) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	return NT_STATUS_OK;
}

/*
 * Helper to add directory listing entries to an overall Python list
 */
static NTSTATUS list_helper(struct file_info *finfo,
			    const char *mask, void *state)
{
	PyObject *result = (PyObject *)state;
	PyObject *file = NULL;
	PyObject *size = NULL;
	int ret;

	/* suppress '.' and '..' in the results we return */
	if (ISDOT(finfo->name) || ISDOTDOT(finfo->name)) {
		return NT_STATUS_OK;
	}
	size = PyLong_FromUnsignedLongLong(finfo->size);
	/*
	 * Build a dictionary representing the file info.
	 * Note: Windows does not always return short_name (so it may be None)
	 */
	file = Py_BuildValue("{s:s,s:i,s:s,s:O,s:l,s:k}",
			     "name",
			     finfo->name,
			     "attrib",
			     (int)finfo->attr,
			     "short_name",
			     finfo->short_name,
			     "size",
			     size,
			     "mtime",
			     convert_timespec_to_time_t(finfo->mtime_ts),
			     "reparse_tag",
			     (unsigned long)finfo->reparse_tag);

	Py_CLEAR(size);

	if (file == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (finfo->attr & FILE_ATTRIBUTE_REPARSE_POINT) {
		unsigned long tag = finfo->reparse_tag;

		ret = PyDict_SetItemString(
			file,
			"reparse_tag",
			PyLong_FromUnsignedLong(tag));
		if (ret == -1) {
			return NT_STATUS_INTERNAL_ERROR;
		}
	}

	ret = PyList_Append(result, file);
	Py_CLEAR(file);
	if (ret == -1) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	return NT_STATUS_OK;
}

struct do_listing_state {
	const char *mask;
	NTSTATUS (*callback_fn)(
		struct file_info *finfo,
		const char *mask,
		void *private_data);
	void *private_data;
	NTSTATUS status;
};

static void do_listing_cb(struct tevent_req *subreq)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct do_listing_state *state = tevent_req_callback_data_void(subreq);
	struct file_info *finfo = NULL;

	state->status = cli_list_recv(subreq, frame, &finfo);
	if (!NT_STATUS_IS_OK(state->status)) {
		TALLOC_FREE(frame);
		return;
	}
	state->callback_fn(finfo, state->mask, state->private_data);
	TALLOC_FREE(frame);
}

static NTSTATUS do_listing(struct py_cli_state *self,
			   const char *base_dir, const char *user_mask,
			   uint16_t attribute,
			   unsigned int info_level,
			   NTSTATUS (*callback_fn)(struct file_info *,
						   const char *, void *),
			   void *priv)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *mask = NULL;
	struct do_listing_state state = {
		.mask = mask,
		.callback_fn = callback_fn,
		.private_data = priv,
	};
	struct tevent_req *req = NULL;
	NTSTATUS status;

	if (user_mask == NULL) {
		mask = talloc_asprintf(frame, "%s\\*", base_dir);
	} else {
		mask = talloc_asprintf(frame, "%s\\%s", base_dir, user_mask);
	}

	if (mask == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	dos_format(mask);

	req = cli_list_send(frame, self->ev, self->cli, mask, attribute,
			    info_level);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	tevent_req_set_callback(req, do_listing_cb, &state);

	if (!py_tevent_req_wait_exc(self, req)) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}
	TALLOC_FREE(req);

	status = state.status;
	if (NT_STATUS_EQUAL(status, NT_STATUS_NO_MORE_FILES)) {
		status = NT_STATUS_OK;
	}

done:
	TALLOC_FREE(frame);
	return status;
}

static PyObject *py_cli_list(struct py_cli_state *self,
			     PyObject *args,
			     PyObject *kwds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *base_dir;
	char *user_mask = NULL;
	unsigned int attribute = LIST_ATTRIBUTE_MASK;
	unsigned int info_level = 0;
	NTSTATUS status;
	enum protocol_types proto = smbXcli_conn_protocol(self->cli->conn);
	PyObject *result = NULL;
	const char *kwlist[] = { "directory", "mask", "attribs",
				 "info_level", NULL };
	NTSTATUS (*callback_fn)(struct file_info *, const char *, void *) =
		list_helper;

	if (!ParseTupleAndKeywords(args, kwds, "z|sII:list", kwlist,
				   &base_dir, &user_mask, &attribute,
				   &info_level)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	result = Py_BuildValue("[]");
	if (result == NULL) {
		TALLOC_FREE(frame);
		return NULL;
	}

	if (!info_level) {
		if (proto >= PROTOCOL_SMB2_02) {
			info_level = SMB2_FIND_ID_BOTH_DIRECTORY_INFO;
		} else {
			info_level = SMB_FIND_FILE_BOTH_DIRECTORY_INFO;
		}
	}

	if (info_level == SMB2_FIND_POSIX_INFORMATION) {
		callback_fn = list_posix_helper;
	}
	status = do_listing(self, base_dir, user_mask, attribute,
			    info_level, callback_fn, result);

	if (!NT_STATUS_IS_OK(status)) {
		Py_XDECREF(result);
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	TALLOC_FREE(frame);
	return result;
}

static PyObject *py_smb_unlink(struct py_cli_state *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	const char *filename = NULL;
	struct tevent_req *req = NULL;
	const uint32_t attrs = (FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);

	if (!PyArg_ParseTuple(args, "s:unlink", &filename)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	req = cli_unlink_send(frame, self->ev, self->cli, filename, attrs);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_unlink_recv(req);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	TALLOC_FREE(frame);
	Py_RETURN_NONE;
}

static PyObject *py_smb_rmdir(struct py_cli_state *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct tevent_req *req = NULL;
	const char *dirname = NULL;

	if (!PyArg_ParseTuple(args, "s:rmdir", &dirname)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	req = cli_rmdir_send(frame, self->ev, self->cli, dirname);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_rmdir_recv(req);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	TALLOC_FREE(frame);
	Py_RETURN_NONE;
}

/*
 * Create a directory
 */
static PyObject *py_smb_mkdir(struct py_cli_state *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	const char *dirname = NULL;
	struct tevent_req *req = NULL;

	if (!PyArg_ParseTuple(args, "s:mkdir", &dirname)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	req = cli_mkdir_send(frame, self->ev, self->cli, dirname);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_mkdir_recv(req);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	TALLOC_FREE(frame);
	Py_RETURN_NONE;
}

/*
 * Does a whoami call
 */
static PyObject *py_smb_posix_whoami(struct py_cli_state *self,
				     PyObject *Py_UNUSED(ignored))
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct tevent_req *req = NULL;
	uint64_t uid;
	uint64_t gid;
	uint32_t num_gids;
	uint64_t *gids = NULL;
	uint32_t num_sids;
	struct dom_sid *sids = NULL;
	bool guest;
	PyObject *py_gids = NULL;
	PyObject *py_sids = NULL;
	PyObject *py_guest = NULL;
	PyObject *py_ret = NULL;
	Py_ssize_t i;

	req = cli_posix_whoami_send(frame, self->ev, self->cli);
	if (!py_tevent_req_wait_exc(self, req)) {
		goto fail;
	}
	status = cli_posix_whoami_recv(req,
				frame,
				&uid,
				&gid,
				&num_gids,
				&gids,
				&num_sids,
				&sids,
				&guest);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		goto fail;
	}

	py_gids = PyList_New(num_gids);
	if (!py_gids) {
		goto fail;
	}
	for (i = 0; i < num_gids; ++i) {
		int ret;
		PyObject *py_item = PyLong_FromUnsignedLongLong(gids[i]);
		if (!py_item) {
			goto fail2;
		}

		ret = PyList_SetItem(py_gids, i, py_item);
		if (ret) {
			goto fail2;
		}
	}
	py_sids = PyList_New(num_sids);
	if (!py_sids) {
		goto fail2;
	}
	for (i = 0; i < num_sids; ++i) {
		int ret;
		struct dom_sid *sid;
		PyObject *py_item;

		sid = dom_sid_dup(frame, &sids[i]);
		if (!sid) {
			PyErr_NoMemory();
			goto fail3;
		}

		py_item = pytalloc_steal(dom_sid_Type, sid);
		if (!py_item) {
			PyErr_NoMemory();
			goto fail3;
		}

		ret = PyList_SetItem(py_sids, i, py_item);
		if (ret) {
			goto fail3;
		}
	}

	py_guest = guest ? Py_True : Py_False;

	py_ret = Py_BuildValue("KKNNO",
			uid,
			gid,
			py_gids,
			py_sids,
			py_guest);
	if (!py_ret) {
		goto fail3;
	}

	TALLOC_FREE(frame);
	return py_ret;

fail3:
	Py_CLEAR(py_sids);

fail2:
	Py_CLEAR(py_gids);

fail:
	TALLOC_FREE(frame);
	return NULL;
}

/*
 * Checks existence of a directory
 */
static bool check_dir_path(struct py_cli_state *self, const char *path)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct tevent_req *req = NULL;

	req = cli_chkpath_send(frame, self->ev, self->cli, path);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return false;
	}
	status = cli_chkpath_recv(req);
	TALLOC_FREE(req);

	TALLOC_FREE(frame);
	return NT_STATUS_IS_OK(status);
}

static PyObject *py_smb_chkpath(struct py_cli_state *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *path = NULL;
	bool dir_exists;

	if (!PyArg_ParseTuple(args, "s:chkpath", &path)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	dir_exists = check_dir_path(self, path);
	TALLOC_FREE(frame);
	return PyBool_FromLong(dir_exists);
}

static PyObject *py_smb_have_posix(struct py_cli_state *self,
				   PyObject *Py_UNUSED(ignored))
{
	bool posix = smbXcli_conn_have_posix(self->cli->conn);

	if (posix) {
		Py_RETURN_TRUE;
	}
	Py_RETURN_FALSE;
}

static PyObject *py_smb_protocol(struct py_cli_state *self,
				 PyObject *Py_UNUSED(ignored))
{
	enum protocol_types proto = smbXcli_conn_protocol(self->cli->conn);
	PyObject *result = PyLong_FromLong(proto);
	return result;
}

static PyObject *py_smb_get_sd(struct py_cli_state *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	int fnum;
	unsigned sinfo;
	struct tevent_req *req = NULL;
	struct security_descriptor *sd = NULL;
	PyObject *py_sd = NULL;
	NTSTATUS status;

	if (!PyArg_ParseTuple(args, "iI:get_acl", &fnum, &sinfo)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	req = cli_query_security_descriptor_send(
		frame, self->ev, self->cli, fnum, sinfo);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_query_security_descriptor_recv(req, NULL, &sd);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}
	/*
	 * only reparent to frame,
	 * if we would pass frame to
	 * cli_query_security_descriptor_recv()
	 * we'd leak a potential talloc_stackframe_pool
	 * via py_return_ndr_struct().
	 */
	talloc_reparent(NULL, frame, sd);

	py_sd = py_return_ndr_struct("samba.dcerpc.security", "descriptor",
				     sd, sd);
	TALLOC_FREE(frame);
	return py_sd;
}

static PyObject *py_smb_set_sd(struct py_cli_state *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	PyObject *py_sd = NULL;
	struct tevent_req *req = NULL;
	struct security_descriptor *sd = NULL;
	uint16_t fnum;
	unsigned int sinfo;
	NTSTATUS status;

	if (!PyArg_ParseTuple(args, "iOI:set_sd", &fnum, &py_sd, &sinfo)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	sd = pytalloc_get_type(py_sd, struct security_descriptor);
	if (!sd) {
		PyErr_Format(PyExc_TypeError,
			"Expected dcerpc.security.descriptor as argument, got %s",
			pytalloc_get_name(py_sd));
		TALLOC_FREE(frame);
		return NULL;
	}

	req = cli_set_security_descriptor_send(
		frame, self->ev, self->cli, fnum, sinfo, sd);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	status = cli_set_security_descriptor_recv(req);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	TALLOC_FREE(frame);
	Py_RETURN_NONE;
}

static PyObject *py_smb_smb1_posix(
	struct py_cli_state *self, PyObject *Py_UNUSED(ignored))
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct tevent_req *req = NULL;
	uint16_t major, minor;
	uint32_t caplow, caphigh;
	PyObject *result = NULL;

	req = cli_unix_extensions_version_send(frame, self->ev, self->cli);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_unix_extensions_version_recv(
		req, &major, &minor, &caplow, &caphigh);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	req = cli_set_unix_extensions_capabilities_send(
		frame, self->ev, self->cli, major, minor, caplow, caphigh);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_set_unix_extensions_capabilities_recv(req);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	result = Py_BuildValue(
		"[IIII]",
		(unsigned)minor,
		(unsigned)major,
		(unsigned)caplow,
		(unsigned)caphigh);
	TALLOC_FREE(frame);
	return result;
}

static PyObject *py_smb_smb1_readlink(
	struct py_cli_state *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	const char *filename = NULL;
	struct tevent_req *req = NULL;
	char *target = NULL;
	PyObject *result = NULL;

	if (!PyArg_ParseTuple(args, "s:smb1_readlink", &filename)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	req = cli_posix_readlink_send(frame, self->ev, self->cli, filename);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_posix_readlink_recv(req, frame, &target);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	result = PyBytes_FromString(target);
	TALLOC_FREE(frame);
	return result;
}

static PyObject *py_smb_smb1_symlink(
	struct py_cli_state *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	const char *target = NULL, *newname = NULL;
	struct tevent_req *req = NULL;

	if (!PyArg_ParseTuple(args, "ss:smb1_symlink", &target, &newname)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	req = cli_posix_symlink_send(
		frame, self->ev, self->cli, target, newname);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_posix_symlink_recv(req);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	TALLOC_FREE(frame);
	Py_RETURN_NONE;
}

static PyObject *py_smb_smb1_stat(
	struct py_cli_state *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	const char *fname = NULL;
	struct tevent_req *req = NULL;
	struct stat_ex sbuf = { .st_ex_nlink = 0, };

	if (!PyArg_ParseTuple(args, "s:smb1_stat", &fname)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	req = cli_posix_stat_send(frame, self->ev, self->cli, fname);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_posix_stat_recv(req, &sbuf);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	TALLOC_FREE(frame);
	return Py_BuildValue(
		"{sLsLsLsLsLsLsLsLsLsLsLsLsLsLsLsLsLsLsLsL}",
		"dev",
		(unsigned long long)sbuf.st_ex_dev,
		"ino",
		(unsigned long long)sbuf.st_ex_ino,
		"mode",
		(unsigned long long)sbuf.st_ex_mode,
		"nlink",
		(unsigned long long)sbuf.st_ex_nlink,
		"uid",
		(unsigned long long)sbuf.st_ex_uid,
		"gid",
		(unsigned long long)sbuf.st_ex_gid,
		"rdev",
		(unsigned long long)sbuf.st_ex_size,
		"atime_sec",
		(unsigned long long)sbuf.st_ex_atime.tv_sec,
		"atime_nsec",
		(unsigned long long)sbuf.st_ex_atime.tv_nsec,
		"mtime_sec",
		(unsigned long long)sbuf.st_ex_mtime.tv_sec,
		"mtime_nsec",
		(unsigned long long)sbuf.st_ex_mtime.tv_nsec,
		"ctime_sec",
		(unsigned long long)sbuf.st_ex_ctime.tv_sec,
		"ctime_nsec",
		(unsigned long long)sbuf.st_ex_ctime.tv_nsec,
		"btime_sec",
		(unsigned long long)sbuf.st_ex_btime.tv_sec,
		"btime_nsec",
		(unsigned long long)sbuf.st_ex_btime.tv_nsec,
		"cached_dos_attributes",
		(unsigned long long)sbuf.cached_dos_attributes,
		"blksize",
		(unsigned long long)sbuf.st_ex_blksize,
		"blocks",
		(unsigned long long)sbuf.st_ex_blocks,
		"flags",
		(unsigned long long)sbuf.st_ex_flags,
		"iflags",
		(unsigned long long)sbuf.st_ex_iflags);
}

static PyObject *py_cli_mknod(
	struct py_cli_state *self, PyObject *args, PyObject *kwds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *fname = NULL;
	int mode = 0, major = 0, minor = 0, dev = 0;
	struct tevent_req *req = NULL;
	static const char *kwlist[] = {
		"fname", "mode", "major", "minor", NULL,
	};
	NTSTATUS status;
	bool ok;

	ok = ParseTupleAndKeywords(
		args,
		kwds,
		"sI|II:mknod",
		kwlist,
		&fname,
		&mode,
		&major,
		&minor);
	if (!ok) {
		TALLOC_FREE(frame);
		return NULL;
	}

#if defined(HAVE_MAKEDEV)
	dev = makedev(major, minor);
#endif

	req = cli_mknod_send(
		frame, self->ev, self->cli, fname, mode, dev);
	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}
	status = cli_mknod_recv(req);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	TALLOC_FREE(frame);
	Py_RETURN_NONE;
}

static PyObject *py_cli_fsctl(
	struct py_cli_state *self, PyObject *args, PyObject *kwds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	int fnum, ctl_code;
	int max_out = 0;
	char *buf = NULL;
	Py_ssize_t buflen;
	DATA_BLOB in = { .data = NULL, };
	DATA_BLOB out = { .data = NULL, };
	struct tevent_req *req = NULL;
	PyObject *result = NULL;
	static const char *kwlist[] = {
		"fnum", "ctl_code", "in", "max_out", NULL,
	};
	NTSTATUS status;
	bool ok;

	ok = ParseTupleAndKeywords(
		    args,
		    kwds,
		    "ii" PYARG_BYTES_LEN "i",
		    kwlist,
		    &fnum,
		    &ctl_code,
		    &buf,
		    &buflen,
		    &max_out);
	if (!ok) {
		TALLOC_FREE(frame);
		return NULL;
	}

	in = (DATA_BLOB) { .data = (uint8_t *)buf, .length = buflen, };

	req = cli_fsctl_send(
		frame, self->ev, self->cli, fnum, ctl_code, &in, max_out);

	if (!py_tevent_req_wait_exc(self, req)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	status = cli_fsctl_recv(req, frame, &out);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		TALLOC_FREE(frame);
		return NULL;
	}

	result = PyBytes_FromStringAndSize((char *)out.data, out.length);
	TALLOC_FREE(frame);
	return result;
}

static int copy_chunk_cb(off_t n, void *priv)
{
	return 1;
}

static PyObject *py_cli_copy_chunk(struct py_cli_state *self,
				   PyObject *args,
				   PyObject *kwds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_req *req = NULL;
	PyObject *result = NULL;
	int fnum_src;
	int fnum_dst;
	unsigned long long size;
	unsigned long long src_offset;
	unsigned long long dst_offset;
	off_t written;
	static const char *kwlist[] = {
		"fnum_src",
		"fnum_dst",
		"size",
		"src_offset",
		"dst_offset",
		NULL,
	};
	NTSTATUS status;
	bool ok;

	if (smbXcli_conn_protocol(self->cli->conn) < PROTOCOL_SMB2_02) {
		errno = EINVAL;
		PyErr_SetFromErrno(PyExc_RuntimeError);
		goto err;
	}

	ok = ParseTupleAndKeywords(
		    args,
		    kwds,
		    "iiKKK",
		    kwlist,
		    &fnum_src,
		    &fnum_dst,
		    &size,
		    &src_offset,
		    &dst_offset);
	if (!ok) {
		goto err;
	}

	req = cli_smb2_splice_send(frame,
				   self->ev,
				   self->cli,
				   fnum_src,
				   fnum_dst,
				   size,
				   src_offset,
				   dst_offset,
				   copy_chunk_cb,
				   NULL);
	if (!py_tevent_req_wait_exc(self, req)) {
		goto err;
	}

	status = cli_smb2_splice_recv(req, &written);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		goto err;
	}

	result = Py_BuildValue("K", written);

err:
	TALLOC_FREE(frame);
	return result;
}

static PyMethodDef py_cli_state_methods[] = {
	{ "settimeout", (PyCFunction)py_cli_settimeout, METH_VARARGS,
	  "settimeout(new_timeout_msecs) => return old_timeout_msecs" },
	{ "echo", (PyCFunction)py_cli_echo, METH_NOARGS,
	  "Ping the server connection" },
	{ "create", PY_DISCARD_FUNC_SIG(PyCFunction, py_cli_create),
		METH_VARARGS|METH_KEYWORDS,
	  "Open a file" },
	{ "get_posix_fs_info",
	  PY_DISCARD_FUNC_SIG(PyCFunction, py_cli_get_posix_fs_info),
	  METH_NOARGS,
	  "Get posix filesystem attribute information" },
	{ "create_ex",
	  PY_DISCARD_FUNC_SIG(PyCFunction, py_cli_create_ex),
	  METH_VARARGS|METH_KEYWORDS,
	  "Open a file, SMB2 version returning create contexts" },
	{ "close", (PyCFunction)py_cli_close, METH_VARARGS,
	  "Close a file handle" },
	{ "write", PY_DISCARD_FUNC_SIG(PyCFunction, py_cli_write),
		METH_VARARGS|METH_KEYWORDS,
	  "Write to a file handle" },
	{ "read", PY_DISCARD_FUNC_SIG(PyCFunction, py_cli_read),
		METH_VARARGS|METH_KEYWORDS,
	  "Read from a file handle" },
	{ "truncate", PY_DISCARD_FUNC_SIG(PyCFunction,
			py_cli_ftruncate),
	  METH_VARARGS|METH_KEYWORDS,
	  "Truncate a file" },
	{ "delete_on_close", PY_DISCARD_FUNC_SIG(PyCFunction,
					 py_cli_delete_on_close),
	  METH_VARARGS|METH_KEYWORDS,
	  "Set/Reset the delete on close flag" },
	{ "notify", PY_DISCARD_FUNC_SIG(PyCFunction, py_cli_notify),
	  METH_VARARGS|METH_KEYWORDS,
	  "Wait for change notifications: \n"
	  "notify(fnum, buffer_size, completion_filter...) -> "
	  "libsmb_samba_internal.Notify request handle\n" },
	{ "list", PY_DISCARD_FUNC_SIG(PyCFunction, py_cli_list),
		METH_VARARGS|METH_KEYWORDS,
	  "list(directory, mask='*', attribs=DEFAULT_ATTRS) -> "
	  "directory contents as a dictionary\n"
	  "\t\tDEFAULT_ATTRS: FILE_ATTRIBUTE_SYSTEM | "
	  "FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_ARCHIVE\n\n"
	  "\t\tList contents of a directory. The keys are, \n"
	  "\t\t\tname: Long name of the directory item\n"
	  "\t\t\tshort_name: Short name of the directory item\n"
	  "\t\t\tsize: File size in bytes\n"
	  "\t\t\tattrib: Attributes\n"
	  "\t\t\tmtime: Modification time\n" },
	{ "get_oplock_break", (PyCFunction)py_cli_get_oplock_break,
	  METH_VARARGS, "Wait for an oplock break" },
	{ "unlink", (PyCFunction)py_smb_unlink,
	  METH_VARARGS,
	  "unlink(path) -> None\n\n \t\tDelete a file." },
	{ "mkdir", (PyCFunction)py_smb_mkdir, METH_VARARGS,
	  "mkdir(path) -> None\n\n \t\tCreate a directory." },
	{ "posix_whoami", (PyCFunction)py_smb_posix_whoami, METH_NOARGS,
	"posix_whoami() -> (uid, gid, gids, sids, guest)" },
	{ "rmdir", (PyCFunction)py_smb_rmdir, METH_VARARGS,
	  "rmdir(path) -> None\n\n \t\tDelete a directory." },
	{ "rename",
	  PY_DISCARD_FUNC_SIG(PyCFunction, py_cli_rename),
	  METH_VARARGS|METH_KEYWORDS,
	  "rename(src,dst) -> None\n\n \t\tRename a file." },
	{ "chkpath", (PyCFunction)py_smb_chkpath, METH_VARARGS,
	  "chkpath(dir_path) -> True or False\n\n"
	  "\t\tReturn true if directory exists, false otherwise." },
	{ "savefile", (PyCFunction)py_smb_savefile, METH_VARARGS,
	  "savefile(path, bytes) -> None\n\n"
	  "\t\tWrite bytes to file." },
	{ "loadfile", (PyCFunction)py_smb_loadfile, METH_VARARGS,
	  "loadfile(path) -> file contents as a bytes object"
	  "\n\n\t\tRead contents of a file." },
	{ "get_sd", (PyCFunction)py_smb_get_sd, METH_VARARGS,
	  "get_sd(fnum[, security_info=0]) -> security_descriptor object\n\n"
	  "\t\tGet security descriptor for opened file." },
	{ "set_sd", (PyCFunction)py_smb_set_sd, METH_VARARGS,
	  "set_sd(fnum, security_descriptor[, security_info=0]) -> None\n\n"
	  "\t\tSet security descriptor for opened file." },
	{ "protocol",
	  (PyCFunction)py_smb_protocol,
	  METH_NOARGS,
	  "protocol() -> Number"
	},
	{ "have_posix",
	  (PyCFunction)py_smb_have_posix,
	  METH_NOARGS,
	  "have_posix() -> True/False\n\n"
	  "\t\tReturn if the server has posix extensions"
	},
	{ "smb1_posix",
	  (PyCFunction)py_smb_smb1_posix,
	  METH_NOARGS,
	  "Negotiate SMB1 posix extensions",
	},
	{ "smb1_readlink",
	  (PyCFunction)py_smb_smb1_readlink,
	  METH_VARARGS,
	  "smb1_readlink(path) -> link target",
	},
	{ "smb1_symlink",
	  (PyCFunction)py_smb_smb1_symlink,
	  METH_VARARGS,
	  "smb1_symlink(target, newname) -> None",
	},
	{ "smb1_stat",
	  (PyCFunction)py_smb_smb1_stat,
	  METH_VARARGS,
	  "smb1_stat(path) -> stat info",
	},
	{ "fsctl",
	  PY_DISCARD_FUNC_SIG(PyCFunction, py_cli_fsctl),
	  METH_VARARGS|METH_KEYWORDS,
	  "fsctl(fnum, ctl_code, in_bytes, max_out) -> out_bytes",
	},
	{
		"qfileinfo",
		(PyCFunction)py_cli_qfileinfo,
		METH_VARARGS | METH_KEYWORDS,
		"qfileinfo(fnum, level) -> blob",
	},
	{ "mknod",
	  PY_DISCARD_FUNC_SIG(PyCFunction, py_cli_mknod),
	  METH_VARARGS|METH_KEYWORDS,
	  "mknod(path, mode | major, minor)",
	},
	{ "copy_chunk",
	  PY_DISCARD_FUNC_SIG(PyCFunction, py_cli_copy_chunk),
	  METH_VARARGS|METH_KEYWORDS,
	  "copy_chunk(fnum_src, fnum_dst, size, src_offset, dst_offset) -> written",
	},
	{ NULL, NULL, 0, NULL }
};

static PyTypeObject py_cli_state_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "libsmb_samba_cwrapper.LibsmbCConn",
	.tp_basicsize = sizeof(struct py_cli_state),
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_doc = "libsmb cwrapper connection",
	.tp_new = py_cli_state_new,
	.tp_init = (initproc)py_cli_state_init,
	.tp_dealloc = (destructor)py_cli_state_dealloc,
	.tp_methods = py_cli_state_methods,
};

static PyMethodDef py_libsmb_methods[] = {
	{
		"unix_mode_to_wire",
		(PyCFunction)py_unix_mode_to_wire,
		METH_VARARGS,
		"Convert mode_t to posix extensions wire format",
	},
	{
		"wire_mode_to_unix",
		(PyCFunction)py_wire_mode_to_unix,
		METH_VARARGS,
		"Convert posix wire format mode to mode_t",
	},
	{0},
};

void initlibsmb_samba_cwrapper(void);

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    .m_name = "libsmb_samba_cwrapper",
    .m_doc = "libsmb wrapper",
    .m_size = -1,
    .m_methods = py_libsmb_methods,
};

MODULE_INIT_FUNC(libsmb_samba_cwrapper)
{
	PyObject *m = NULL;
	PyObject *mod = NULL;

	if (PyType_Ready(&py_cli_state_type) < 0) {
		return NULL;
	}
	if (PyType_Ready(&py_cli_notify_state_type) < 0) {
		return NULL;
	}

	m = PyModule_Create(&moduledef);
	if (m == NULL) {
		return m;
	}

	/* Import dom_sid type from dcerpc.security */
	mod = PyImport_ImportModule("samba.dcerpc.security");
	if (mod == NULL) {
		return NULL;
	}

	dom_sid_Type = (PyTypeObject *)PyObject_GetAttrString(mod, "dom_sid");
	if (dom_sid_Type == NULL) {
		Py_DECREF(mod);
		return NULL;
	}

	Py_INCREF(&py_cli_state_type);
	PyModule_AddObject(m, "LibsmbCConn", (PyObject *)&py_cli_state_type);

#define ADD_FLAGS(val)	PyModule_AddObject(m, #val, PyLong_FromLong(val))

	ADD_FLAGS(PROTOCOL_NONE);
	ADD_FLAGS(PROTOCOL_CORE);
	ADD_FLAGS(PROTOCOL_COREPLUS);
	ADD_FLAGS(PROTOCOL_LANMAN1);
	ADD_FLAGS(PROTOCOL_LANMAN2);
	ADD_FLAGS(PROTOCOL_NT1);
	ADD_FLAGS(PROTOCOL_SMB2_02);
	ADD_FLAGS(PROTOCOL_SMB2_10);
	ADD_FLAGS(PROTOCOL_SMB3_00);
	ADD_FLAGS(PROTOCOL_SMB3_02);
	ADD_FLAGS(PROTOCOL_SMB3_11);

	ADD_FLAGS(FILE_ATTRIBUTE_READONLY);
	ADD_FLAGS(FILE_ATTRIBUTE_HIDDEN);
	ADD_FLAGS(FILE_ATTRIBUTE_SYSTEM);
	ADD_FLAGS(FILE_ATTRIBUTE_VOLUME);
	ADD_FLAGS(FILE_ATTRIBUTE_DIRECTORY);
	ADD_FLAGS(FILE_ATTRIBUTE_ARCHIVE);
	ADD_FLAGS(FILE_ATTRIBUTE_DEVICE);
	ADD_FLAGS(FILE_ATTRIBUTE_NORMAL);
	ADD_FLAGS(FILE_ATTRIBUTE_TEMPORARY);
	ADD_FLAGS(FILE_ATTRIBUTE_SPARSE);
	ADD_FLAGS(FILE_ATTRIBUTE_REPARSE_POINT);
	ADD_FLAGS(FILE_ATTRIBUTE_COMPRESSED);
	ADD_FLAGS(FILE_ATTRIBUTE_OFFLINE);
	ADD_FLAGS(FILE_ATTRIBUTE_NONINDEXED);
	ADD_FLAGS(FILE_ATTRIBUTE_ENCRYPTED);
	ADD_FLAGS(FILE_ATTRIBUTE_ALL_MASK);

	ADD_FLAGS(FILE_DIRECTORY_FILE);
	ADD_FLAGS(FILE_WRITE_THROUGH);
	ADD_FLAGS(FILE_SEQUENTIAL_ONLY);
	ADD_FLAGS(FILE_NO_INTERMEDIATE_BUFFERING);
	ADD_FLAGS(FILE_SYNCHRONOUS_IO_ALERT);
	ADD_FLAGS(FILE_SYNCHRONOUS_IO_NONALERT);
	ADD_FLAGS(FILE_NON_DIRECTORY_FILE);
	ADD_FLAGS(FILE_CREATE_TREE_CONNECTION);
	ADD_FLAGS(FILE_COMPLETE_IF_OPLOCKED);
	ADD_FLAGS(FILE_NO_EA_KNOWLEDGE);
	ADD_FLAGS(FILE_EIGHT_DOT_THREE_ONLY);
	ADD_FLAGS(FILE_RANDOM_ACCESS);
	ADD_FLAGS(FILE_DELETE_ON_CLOSE);
	ADD_FLAGS(FILE_OPEN_BY_FILE_ID);
	ADD_FLAGS(FILE_OPEN_FOR_BACKUP_INTENT);
	ADD_FLAGS(FILE_NO_COMPRESSION);
	ADD_FLAGS(FILE_RESERVER_OPFILTER);
	ADD_FLAGS(FILE_OPEN_REPARSE_POINT);
	ADD_FLAGS(FILE_OPEN_NO_RECALL);
	ADD_FLAGS(FILE_OPEN_FOR_FREE_SPACE_QUERY);

	ADD_FLAGS(FILE_SHARE_READ);
	ADD_FLAGS(FILE_SHARE_WRITE);
	ADD_FLAGS(FILE_SHARE_DELETE);

	ADD_FLAGS(VFS_PWRITE_APPEND_OFFSET);

	/* change notify completion filter flags */
	ADD_FLAGS(FILE_NOTIFY_CHANGE_FILE_NAME);
	ADD_FLAGS(FILE_NOTIFY_CHANGE_DIR_NAME);
	ADD_FLAGS(FILE_NOTIFY_CHANGE_ATTRIBUTES);
	ADD_FLAGS(FILE_NOTIFY_CHANGE_SIZE);
	ADD_FLAGS(FILE_NOTIFY_CHANGE_LAST_WRITE);
	ADD_FLAGS(FILE_NOTIFY_CHANGE_LAST_ACCESS);
	ADD_FLAGS(FILE_NOTIFY_CHANGE_CREATION);
	ADD_FLAGS(FILE_NOTIFY_CHANGE_EA);
	ADD_FLAGS(FILE_NOTIFY_CHANGE_SECURITY);
	ADD_FLAGS(FILE_NOTIFY_CHANGE_STREAM_NAME);
	ADD_FLAGS(FILE_NOTIFY_CHANGE_STREAM_SIZE);
	ADD_FLAGS(FILE_NOTIFY_CHANGE_STREAM_WRITE);
	ADD_FLAGS(FILE_NOTIFY_CHANGE_NAME);
	ADD_FLAGS(FILE_NOTIFY_CHANGE_ALL);

	/* change notify action results */
	ADD_FLAGS(NOTIFY_ACTION_ADDED);
	ADD_FLAGS(NOTIFY_ACTION_REMOVED);
	ADD_FLAGS(NOTIFY_ACTION_MODIFIED);
	ADD_FLAGS(NOTIFY_ACTION_OLD_NAME);
	ADD_FLAGS(NOTIFY_ACTION_NEW_NAME);
	ADD_FLAGS(NOTIFY_ACTION_ADDED_STREAM);
	ADD_FLAGS(NOTIFY_ACTION_REMOVED_STREAM);
	ADD_FLAGS(NOTIFY_ACTION_MODIFIED_STREAM);

	/* CreateDisposition values */
	ADD_FLAGS(FILE_SUPERSEDE);
	ADD_FLAGS(FILE_OPEN);
	ADD_FLAGS(FILE_CREATE);
	ADD_FLAGS(FILE_OPEN_IF);
	ADD_FLAGS(FILE_OVERWRITE);
	ADD_FLAGS(FILE_OVERWRITE_IF);

	ADD_FLAGS(FSCTL_DFS_GET_REFERRALS);
	ADD_FLAGS(FSCTL_DFS_GET_REFERRALS_EX);
	ADD_FLAGS(FSCTL_REQUEST_OPLOCK_LEVEL_1);
	ADD_FLAGS(FSCTL_REQUEST_OPLOCK_LEVEL_2);
	ADD_FLAGS(FSCTL_REQUEST_BATCH_OPLOCK);
	ADD_FLAGS(FSCTL_OPLOCK_BREAK_ACKNOWLEDGE);
	ADD_FLAGS(FSCTL_OPBATCH_ACK_CLOSE_PENDING);
	ADD_FLAGS(FSCTL_OPLOCK_BREAK_NOTIFY);
	ADD_FLAGS(FSCTL_GET_COMPRESSION);
	ADD_FLAGS(FSCTL_FILESYS_GET_STATISTICS);
	ADD_FLAGS(FSCTL_GET_NTFS_VOLUME_DATA);
	ADD_FLAGS(FSCTL_IS_VOLUME_DIRTY);
	ADD_FLAGS(FSCTL_FIND_FILES_BY_SID);
	ADD_FLAGS(FSCTL_SET_OBJECT_ID);
	ADD_FLAGS(FSCTL_GET_OBJECT_ID);
	ADD_FLAGS(FSCTL_DELETE_OBJECT_ID);
	ADD_FLAGS(FSCTL_SET_REPARSE_POINT);
	ADD_FLAGS(FSCTL_GET_REPARSE_POINT);
	ADD_FLAGS(FSCTL_DELETE_REPARSE_POINT);
	ADD_FLAGS(FSCTL_SET_OBJECT_ID_EXTENDED);
	ADD_FLAGS(FSCTL_CREATE_OR_GET_OBJECT_ID);
	ADD_FLAGS(FSCTL_SET_SPARSE);
	ADD_FLAGS(FSCTL_SET_ZERO_DATA);
	ADD_FLAGS(FSCTL_SET_ZERO_ON_DEALLOCATION);
	ADD_FLAGS(FSCTL_READ_FILE_USN_DATA);
	ADD_FLAGS(FSCTL_WRITE_USN_CLOSE_RECORD);
	ADD_FLAGS(FSCTL_QUERY_ALLOCATED_RANGES);
	ADD_FLAGS(FSCTL_QUERY_ON_DISK_VOLUME_INFO);
	ADD_FLAGS(FSCTL_QUERY_SPARING_INFO);
	ADD_FLAGS(FSCTL_FILE_LEVEL_TRIM);
	ADD_FLAGS(FSCTL_OFFLOAD_READ);
	ADD_FLAGS(FSCTL_OFFLOAD_WRITE);
	ADD_FLAGS(FSCTL_SET_INTEGRITY_INFORMATION);
	ADD_FLAGS(FSCTL_DUP_EXTENTS_TO_FILE);
	ADD_FLAGS(FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX);
	ADD_FLAGS(FSCTL_STORAGE_QOS_CONTROL);
	ADD_FLAGS(FSCTL_SVHDX_SYNC_TUNNEL_REQUEST);
	ADD_FLAGS(FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT);
	ADD_FLAGS(FSCTL_PIPE_PEEK);
	ADD_FLAGS(FSCTL_NAMED_PIPE_READ_WRITE);
	ADD_FLAGS(FSCTL_PIPE_TRANSCEIVE);
	ADD_FLAGS(FSCTL_PIPE_WAIT);
	ADD_FLAGS(FSCTL_GET_SHADOW_COPY_DATA);
	ADD_FLAGS(FSCTL_SRV_ENUM_SNAPS);
	ADD_FLAGS(FSCTL_SRV_REQUEST_RESUME_KEY);
	ADD_FLAGS(FSCTL_SRV_COPYCHUNK);
	ADD_FLAGS(FSCTL_SRV_COPYCHUNK_WRITE);
	ADD_FLAGS(FSCTL_SRV_READ_HASH);
	ADD_FLAGS(FSCTL_LMR_REQ_RESILIENCY);
	ADD_FLAGS(FSCTL_LMR_SET_LINK_TRACKING_INFORMATION);
	ADD_FLAGS(FSCTL_QUERY_NETWORK_INTERFACE_INFO);

	ADD_FLAGS(SYMLINK_ERROR_TAG);
	ADD_FLAGS(SYMLINK_FLAG_RELATIVE);
	ADD_FLAGS(SYMLINK_ADMIN);
	ADD_FLAGS(SYMLINK_UNTRUSTED);
	ADD_FLAGS(SYMLINK_TRUST_UNKNOWN);
	ADD_FLAGS(SYMLINK_TRUST_MASK);

	ADD_FLAGS(IO_REPARSE_TAG_RESERVED_ZERO);
	ADD_FLAGS(IO_REPARSE_TAG_SYMLINK);
	ADD_FLAGS(IO_REPARSE_TAG_MOUNT_POINT);
	ADD_FLAGS(IO_REPARSE_TAG_HSM);
	ADD_FLAGS(IO_REPARSE_TAG_SIS);
	ADD_FLAGS(IO_REPARSE_TAG_DFS);
	ADD_FLAGS(IO_REPARSE_TAG_NFS);

	ADD_FLAGS(NFS_SPECFILE_LNK);
	ADD_FLAGS(NFS_SPECFILE_CHR);
	ADD_FLAGS(NFS_SPECFILE_BLK);
	ADD_FLAGS(NFS_SPECFILE_FIFO);
	ADD_FLAGS(NFS_SPECFILE_SOCK);

	ADD_FLAGS(FSCC_FILE_DIRECTORY_INFORMATION);
	ADD_FLAGS(FSCC_FILE_FULL_DIRECTORY_INFORMATION);
	ADD_FLAGS(FSCC_FILE_BOTH_DIRECTORY_INFORMATION);
	ADD_FLAGS(FSCC_FILE_BASIC_INFORMATION);
	ADD_FLAGS(FSCC_FILE_STANDARD_INFORMATION);
	ADD_FLAGS(FSCC_FILE_INTERNAL_INFORMATION);
	ADD_FLAGS(FSCC_FILE_EA_INFORMATION);
	ADD_FLAGS(FSCC_FILE_ACCESS_INFORMATION);
	ADD_FLAGS(FSCC_FILE_NAME_INFORMATION);
	ADD_FLAGS(FSCC_FILE_RENAME_INFORMATION);
	ADD_FLAGS(FSCC_FILE_LINK_INFORMATION);
	ADD_FLAGS(FSCC_FILE_NAMES_INFORMATION);
	ADD_FLAGS(FSCC_FILE_DISPOSITION_INFORMATION);
	ADD_FLAGS(FSCC_FILE_POSITION_INFORMATION);
	ADD_FLAGS(FSCC_FILE_FULL_EA_INFORMATION);
	ADD_FLAGS(FSCC_FILE_MODE_INFORMATION);
	ADD_FLAGS(FSCC_FILE_ALIGNMENT_INFORMATION);
	ADD_FLAGS(FSCC_FILE_ALL_INFORMATION);
	ADD_FLAGS(FSCC_FILE_ALLOCATION_INFORMATION);
	ADD_FLAGS(FSCC_FILE_END_OF_FILE_INFORMATION);
	ADD_FLAGS(FSCC_FILE_ALTERNATE_NAME_INFORMATION);
	ADD_FLAGS(FSCC_FILE_STREAM_INFORMATION);
	ADD_FLAGS(FSCC_FILE_PIPE_INFORMATION);
	ADD_FLAGS(FSCC_FILE_PIPE_LOCAL_INFORMATION);
	ADD_FLAGS(FSCC_FILE_PIPE_REMOTE_INFORMATION);
	ADD_FLAGS(FSCC_FILE_MAILSLOT_QUERY_INFORMATION);
	ADD_FLAGS(FSCC_FILE_MAILSLOT_SET_INFORMATION);
	ADD_FLAGS(FSCC_FILE_COMPRESSION_INFORMATION);
	ADD_FLAGS(FSCC_FILE_OBJECTID_INFORMATION);
	ADD_FLAGS(FSCC_FILE_COMPLETION_INFORMATION);
	ADD_FLAGS(FSCC_FILE_MOVE_CLUSTER_INFORMATION);
	ADD_FLAGS(FSCC_FILE_QUOTA_INFORMATION);
	ADD_FLAGS(FSCC_FILE_REPARSEPOINT_INFORMATION);
	ADD_FLAGS(FSCC_FILE_NETWORK_OPEN_INFORMATION);
	ADD_FLAGS(FSCC_FILE_ATTRIBUTE_TAG_INFORMATION);
	ADD_FLAGS(FSCC_FILE_TRACKING_INFORMATION);
	ADD_FLAGS(FSCC_FILE_ID_BOTH_DIRECTORY_INFORMATION);
	ADD_FLAGS(FSCC_FILE_ID_FULL_DIRECTORY_INFORMATION);
	ADD_FLAGS(FSCC_FILE_VALID_DATA_LENGTH_INFORMATION);
	ADD_FLAGS(FSCC_FILE_SHORT_NAME_INFORMATION);
	ADD_FLAGS(FSCC_FILE_SFIO_RESERVE_INFORMATION);
	ADD_FLAGS(FSCC_FILE_SFIO_VOLUME_INFORMATION);
	ADD_FLAGS(FSCC_FILE_HARD_LINK_INFORMATION);
	ADD_FLAGS(FSCC_FILE_NORMALIZED_NAME_INFORMATION);
	ADD_FLAGS(FSCC_FILE_ID_GLOBAL_TX_DIRECTORY_INFORMATION);
	ADD_FLAGS(FSCC_FILE_STANDARD_LINK_INFORMATION);
	ADD_FLAGS(FSCC_FILE_MAXIMUM_INFORMATION);
	ADD_FLAGS(FSCC_FILE_POSIX_INFORMATION);

#define ADD_STRING(val) PyModule_AddObject(m, #val, PyBytes_FromString(val))

	ADD_STRING(SMB2_CREATE_TAG_EXTA);
	ADD_STRING(SMB2_CREATE_TAG_MXAC);
	ADD_STRING(SMB2_CREATE_TAG_SECD);
	ADD_STRING(SMB2_CREATE_TAG_DHNQ);
	ADD_STRING(SMB2_CREATE_TAG_DHNC);
	ADD_STRING(SMB2_CREATE_TAG_ALSI);
	ADD_STRING(SMB2_CREATE_TAG_TWRP);
	ADD_STRING(SMB2_CREATE_TAG_QFID);
	ADD_STRING(SMB2_CREATE_TAG_RQLS);
	ADD_STRING(SMB2_CREATE_TAG_DH2Q);
	ADD_STRING(SMB2_CREATE_TAG_DH2C);
	ADD_STRING(SMB2_CREATE_TAG_AAPL);
	ADD_STRING(SMB2_CREATE_TAG_APP_INSTANCE_ID);
	ADD_STRING(SVHDX_OPEN_DEVICE_CONTEXT);
	ADD_STRING(SMB2_CREATE_TAG_POSIX);
	ADD_FLAGS(SMB2_FIND_POSIX_INFORMATION);
	ADD_FLAGS(FILE_SUPERSEDE);
	ADD_FLAGS(FILE_OPEN);
	ADD_FLAGS(FILE_CREATE);
	ADD_FLAGS(FILE_OPEN_IF);
	ADD_FLAGS(FILE_OVERWRITE);
	ADD_FLAGS(FILE_OVERWRITE_IF);
	ADD_FLAGS(FILE_DIRECTORY_FILE);

	ADD_FLAGS(SMB2_CLOSE_FLAGS_FULL_INFORMATION);

	return m;
}
