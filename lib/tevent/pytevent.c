/* 
   Unix SMB/CIFS implementation.
   Python bindings for tevent

   Copyright (C) Jelmer Vernooij 2010

     ** NOTE! The following LGPL license applies to the tevent
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include <Python.h>
#include <tevent.h>

typedef struct {
	PyObject_HEAD
	struct tevent_context *ev;
} TeventContext_Object;

static int py_context_init(struct tevent_context *ev)
{
	PyObject *ret, *self;
	/* FIXME */
	ret = PyObject_CallFunction(self, "");
	if (ret == NULL) {
		return -1;
	} else {
		return 0;
	}
}

static struct tevent_fd *py_add_fd(struct tevent_context *ev,
				    TALLOC_CTX *mem_ctx,
				    int fd, uint16_t flags,
				    tevent_fd_handler_t handler,
				    void *private_data,
				    const char *handler_name,
				    const char *location)
{
	/* FIXME */
}

static void py_set_fd_close_fn(struct tevent_fd *fde,
				tevent_fd_close_fn_t close_fn)
{
	/* FIXME */
}

uint16_t py_get_fd_flags(struct tevent_fd *fde)
{
	/* FIXME */
}

static void py_set_fd_flags(struct tevent_fd *fde, uint16_t flags)
{
	/* FIXME */
}

/* timed_event functions */
static struct tevent_timer *py_add_timer(struct tevent_context *ev,
					  TALLOC_CTX *mem_ctx,
					  struct timeval next_event,
					  tevent_timer_handler_t handler,
					  void *private_data,
					  const char *handler_name,
					  const char *location)
{
	/* FIXME */
}

/* immediate event functions */
static void py_schedule_immediate(struct tevent_immediate *im,
				   struct tevent_context *ev,
				   tevent_immediate_handler_t handler,
				   void *private_data,
				   const char *handler_name,
				   const char *location)
{
	/* FIXME */
}

/* signal functions */
static struct tevent_signal *py_add_signal(struct tevent_context *ev,
					    TALLOC_CTX *mem_ctx,
					    int signum, int sa_flags,
					    tevent_signal_handler_t handler,
					    void *private_data,
					    const char *handler_name,
					    const char *location)
{
	/* FIXME */
}

/* loop functions */
static int py_loop_once(struct tevent_context *ev, const char *location)
{
	/* FIXME */
}

static int py_loop_wait(struct tevent_context *ev, const char *location)
{
	/* FIXME */
}

const static struct tevent_ops py_tevent_ops = {
	.context_init = py_context_init,
	.add_fd = py_add_fd,
	.set_fd_close_fn = py_set_fd_close_fn,
	.get_fd_flags = py_get_fd_flags,
	.set_fd_flags = py_set_fd_flags,
	.add_timer = py_add_timer,
	.schedule_immediate = py_schedule_immediate,
	.add_signal = py_add_signal,
	.loop_wait = py_loop_wait,
	.loop_once = py_loop_once,
};

static PyObject *py_register_backend(PyObject *self, PyObject *args)
{
	/* FIXME */
}

static PyObject *py_tevent_context_reinitialise(PyObject *self)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_queue_stop(PyObject *self)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_queue_start(PyObject *self)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_queue_add(PyObject *self, PyObject *args)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyMethodDef py_tevent_queue_methods[] = {
	{ "stop", (PyCFunction)py_tevent_queue_stop, METH_NOARGS,
		"S.stop()" },
	{ "start", (PyCFunction)py_tevent_queue_start, METH_NOARGS,
		"S.start()" },
	{ "add", (PyCFunction)py_tevent_queue_add, METH_VARARGS,
		"S.add(ctx, req, trigger, baton)" },
	{ NULL },
};

static PyObject *py_tevent_context_wakeup_send(PyObject *self, PyObject *args)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_context_loop_wait(PyObject *self)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_context_loop_once(PyObject *self)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_context_add_signal(PyObject *self, PyObject *args)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_context_add_timer(PyObject *self, PyObject *args)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_context_add_fd(PyObject *self, PyObject *args)
{
	/* FIXME */
	Py_RETURN_NONE;
}



static PyMethodDef py_tevent_context_methods[] = {
	{ "reinitialise", (PyCFunction)py_tevent_context_reinitialise, METH_NOARGS,
		"S.reinitialise()" },
	{ "wakeup_send", (PyCFunction)py_tevent_context_wakeup_send, 
		METH_VARARGS, "S.wakeup_send(wakeup_time) -> req" },
	{ "loop_wait", (PyCFunction)py_tevent_context_loop_wait,
		METH_NOARGS, "S.loop_wait()" },
	{ "loop_once", (PyCFunction)py_tevent_context_loop_once,
		METH_NOARGS, "S.loop_once()" },
	{ "add_signal", (PyCFunction)py_tevent_context_add_signal,
		METH_VARARGS, "S.add_signal(signum, sa_flags, handler) -> signal" },
	{ "add_timer", (PyCFunction)py_tevent_context_add_timer,
		METH_VARARGS, "S.add_timer(next_event, handler) -> timer" },
	{ "add_fd", (PyCFunction)py_tevent_context_add_fd, 
		METH_VARARGS, "S.add_fd(fd, flags, handler) -> fd" },
	{ NULL },
};

static PyObject *py_tevent_req_wakeup_recv(PyObject *self)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_req_received(PyObject *self)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_req_is_error(PyObject *self)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_req_poll(PyObject *self)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_req_is_in_progress(PyObject *self)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyGetSetDef py_tevent_req_getsetters[] = {
	{ "in_progress", (getter)py_tevent_req_is_in_progress, NULL,
		"Whether the request is in progress" },
	{ NULL }
};

static PyObject *py_tevent_req_post(PyObject *self, PyObject *args)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_req_set_error(PyObject *self, PyObject *args)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_req_done(PyObject *self)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_req_notify_callback(PyObject *self)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_req_set_endtime(PyObject *self, PyObject *args)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_req_cancel(PyObject *self)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyMethodDef py_tevent_req_methods[] = {
	{ "wakeup_recv", (PyCFunction)py_tevent_req_wakeup_recv, METH_NOARGS,
		"Wakeup received" },
	{ "received", (PyCFunction)py_tevent_req_received, METH_NOARGS,
		"Receive finished" },
	{ "is_error", (PyCFunction)py_tevent_req_is_error, METH_NOARGS,
		"is_error() -> (error, state)" },
	{ "poll", (PyCFunction)py_tevent_req_poll, METH_VARARGS,
		"poll(ctx)" },
	{ "post", (PyCFunction)py_tevent_req_post, METH_VARARGS,
		"post(ctx) -> req" },
	{ "set_error", (PyCFunction)py_tevent_req_set_error, METH_VARARGS,
		"set_error(error)" },
	{ "done", (PyCFunction)py_tevent_req_done, METH_NOARGS,
		"done()" },
	{ "notify_callback", (PyCFunction)py_tevent_req_notify_callback,
		METH_NOARGS, "notify_callback()" },
	{ "set_endtime", (PyCFunction)py_tevent_req_set_endtime,
		METH_VARARGS, "set_endtime(ctx, endtime)" },
	{ "cancel", (PyCFunction)py_tevent_req_cancel,
		METH_NOARGS, "cancel()" },
	{ NULL }
};

static PyObject *py_tevent_queue_get_length(PyObject *self)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyGetSetDef py_tevent_queue_getsetters[] = {
	{ "length", (getter)py_tevent_queue_get_length,
		NULL, "The number of elements in the queue." },
	{ NULL },
};

static PyObject *py_tevent_context_signal_support(PyObject *_self)
{
	TeventContext_Object *self = (TeventContext_Object *)_self;
	return PyBool_FromLong(tevent_signal_support(self->ev));
}

static PyObject *py_tevent_context_get_allow_nesting(PyObject *self)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_tevent_context_set_allow_nesting(PyObject *self, PyObject *value)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyGetSetDef py_tevent_context_getsetters[] = {
	{ "allow_nesting", (getter)py_tevent_context_get_allow_nesting,
		(setter)py_tevent_context_set_allow_nesting, 
		"Whether to allow nested tevent loops." },
	{ "signal_support", (getter)py_tevent_context_signal_support,
		NULL, "if this platform and tevent context support signal handling" },
	{ NULL }
};

static PyTypeObject TeventContext_Type = {
	.tp_methods = py_tevent_context_methods,
	.tp_getset = py_tevent_context_getsetters,
};

static PyObject *py_set_default_backend(PyObject *self, PyObject *args)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyObject *py_backend_list(PyObject *self)
{
	/* FIXME */
	Py_RETURN_NONE;
}

static PyMethodDef tevent_methods[] = {
	{ "register_backend", (PyCFunction)py_register_backend, METH_VARARGS,
		"register_backend(backend)" },
	{ "set_default_backend", (PyCFunction)py_set_default_backend, 
		METH_VARARGS, "set_default_backend(backend)" },
	{ "backend_list", (PyCFunction)py_backend_list, 
		METH_NOARGS, "backend_list() -> list" },
	{ NULL },
};

int inittevent(void)
{
	PyObject *m;
	m = Py_InitModule3("tevent", tevent_methods, "Tevent integration for twisted.");
	if (m == NULL)
		return;
}
