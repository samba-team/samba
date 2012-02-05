/*
 * Copyright (C) Amitay Isaacs 2011
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/*
   Python interface to socket wrapper library.

   Passes all socket communication over unix domain sockets if the environment
   variable SOCKET_WRAPPER_DIR is set.
*/

#include <Python.h>
#include <pytalloc.h>
#include "replace/replace.h"
#include "system/network.h"
#include "socket_wrapper.h"

/* There's no Py_ssize_t in 2.4, apparently */
#if PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION < 5
typedef int Py_ssize_t;
typedef inquiry lenfunc;
typedef intargfunc ssizeargfunc;
#endif

#ifndef Py_RETURN_NONE
#define Py_RETURN_NONE	return Py_INCREF(Py_None), Py_None
#endif

#ifndef Py_TYPE /* Py_TYPE is only available on Python > 2.6 */
#define Py_TYPE(ob)		(((PyObject*)(ob))->ob_type)
#endif

#ifndef PY_CHECK_TYPE
#define PY_CHECK_TYPE(type, var, fail) \
	if (!PyObject_TypeCheck(var, type)) {\
		PyErr_Format(PyExc_TypeError, __location__ ": Expected type '%s' for '%s' of type '%s'", (type)->tp_name, #var, Py_TYPE(var)->tp_name); \
		fail; \
	}
#endif

staticforward PyTypeObject PySocket;

static PyObject *py_socket_error;

void initsocket_wrapper(void);

static PyObject *py_socket_addr_to_tuple(struct sockaddr *addr, socklen_t len)
{
	char host[256];
	char service[8];
	int status;
	PyObject *pyaddr;

	status = getnameinfo(addr, len, host, 255, service, 7, NI_NUMERICHOST|NI_NUMERICSERV);
	if (status < 0) {
		PyErr_SetString(py_socket_error, gai_strerror(status));
		return NULL;
	}

	pyaddr = PyTuple_New(2);
	if (pyaddr == NULL) {
		return PyErr_NoMemory();
	}

	PyTuple_SetItem(pyaddr, 0, PyString_FromString(host));
	PyTuple_SetItem(pyaddr, 1, PyInt_FromLong(atoi(service)));

	return pyaddr;
}

static bool py_socket_tuple_to_addr(PyObject *pyaddr, struct sockaddr *addr, socklen_t *len)
{
	const char *host;
	char *service;
	in_port_t port;
	struct addrinfo *ainfo;
	int status;

	if (!PyTuple_Check(pyaddr)) {
		PyErr_SetString(PyExc_TypeError, "Expected a tuple");
		return false;
	}

	if (!PyArg_ParseTuple(pyaddr, "sH", &host, &port)) {
		return false;
	}

	service = talloc_asprintf(NULL, "%d", port);
	if (service == NULL) {
		PyErr_NoMemory();
		return false;
	}

	status = getaddrinfo(host, service, NULL, &ainfo);
	if (status < 0) {
		talloc_free(service);
		PyErr_SetString(py_socket_error, gai_strerror(status));
		return false;
	}

	talloc_free(service);

	memcpy(addr, ainfo->ai_addr, sizeof(struct sockaddr));
	*len = ainfo->ai_addrlen;

	freeaddrinfo(ainfo);
	return true;
}


static PyObject *py_socket_accept(pytalloc_Object *self, PyObject *args)
{
	int *sock, *new_sock;
	struct sockaddr addr;
	socklen_t addrlen;
	PyObject *pysocket;
	PyObject *pyaddr;
	PyObject *pyret;

	sock = pytalloc_get_ptr(self);

	new_sock = talloc_zero(NULL, int);
	if (new_sock == NULL) {
		return PyErr_NoMemory();
	}

	*new_sock = swrap_accept(*sock, &addr, &addrlen);
	if (*new_sock < 0) {
		return PyErr_SetFromErrno(py_socket_error);
	}

	if ((pysocket = pytalloc_steal(&PySocket, new_sock)) == NULL) {
		return PyErr_NoMemory();
	}

	pyret = PyTuple_New(2);
	if (pyret == NULL) {
		Py_DECREF(pysocket);
		return PyErr_NoMemory();
	}

	pyaddr = py_socket_addr_to_tuple(&addr, addrlen);
	if (pyaddr == NULL) {
		Py_DECREF(pysocket);
		Py_DECREF(pysocket);
		return NULL;
	}

	PyTuple_SetItem(pyret, 0, pysocket);
	PyTuple_SetItem(pyret, 1, pyaddr);
	return pyret;
}

static PyObject *py_socket_bind(pytalloc_Object *self, PyObject *args)
{
	PyObject *pyaddr;
	int *sock;
	int status;
	struct sockaddr addr;
	socklen_t addrlen;

	if (!PyArg_ParseTuple(args, "O:bind", &pyaddr)) {
		return NULL;
	}

	if (!py_socket_tuple_to_addr(pyaddr, &addr, &addrlen)) {
		return NULL;
	}

	sock = pytalloc_get_ptr(self);

	status = swrap_bind(*sock, &addr, addrlen);
	if (status < 0) {
		PyErr_SetString(py_socket_error, "Unable to bind");
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *py_socket_close(pytalloc_Object *self, PyObject *args)
{
	int *sock;
	int status;

	sock = pytalloc_get_ptr(self);

	status = swrap_close(*sock);
	if (status < 0) {
		return PyErr_SetFromErrno(py_socket_error);
	}

	Py_RETURN_NONE;
}

static PyObject *py_socket_connect(pytalloc_Object *self, PyObject *args)
{
	int *sock;
	PyObject *pyaddr;
	struct sockaddr addr;
	socklen_t addrlen;
	int status;

	if (!PyArg_ParseTuple(args, "O:connect", &pyaddr)) {
		return NULL;
	}

	if (!py_socket_tuple_to_addr(pyaddr, &addr, &addrlen)) {
		return NULL;
	}

	sock = pytalloc_get_ptr(self);

	status = swrap_connect(*sock, &addr, addrlen);
	if (status < 0) {
		PyErr_SetFromErrno(py_socket_error);
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *py_socket_connect_ex(pytalloc_Object *self, PyObject *args)
{
	int *sock;
	PyObject *pyaddr;
	struct sockaddr addr;
	socklen_t addrlen;
	int status;

	if (!PyArg_ParseTuple(args, "O:connect", &pyaddr)) {
		return NULL;
	}

	if (!py_socket_tuple_to_addr(pyaddr, &addr, &addrlen)) {
		return NULL;
	}

	sock = pytalloc_get_ptr(self);

	status = swrap_connect(*sock, &addr, addrlen);
	if (status < 0) {
		return Py_BuildValue("%d", errno);
	}

	return Py_BuildValue("%d", 0);
}

static PyObject *py_socket_dup(pytalloc_Object *self, PyObject *args)
{
	int *sock, *new_sock;
	PyObject *pysocket;

	sock = pytalloc_get_ptr(self);

	new_sock = talloc_zero(NULL, int);
	if (new_sock == NULL) {
		return PyErr_NoMemory();
	}

	*new_sock = swrap_dup(*sock);
	if (*new_sock < 0) {
		return PyErr_SetFromErrno(py_socket_error);
	}

	pysocket = pytalloc_steal(&PySocket, new_sock);
	if (pysocket == NULL) {
		return PyErr_NoMemory();
	}

	return pysocket;
}

static PyObject *py_socket_dup2(pytalloc_Object *self, PyObject *args)
{
	int *sock, *new_sock;
	PyObject *pysocket;
	int status;

	if (!PyArg_ParseTuple(args, "O", &pysocket)) {
		return NULL;
	}

	PY_CHECK_TYPE(&PySocket, pysocket, return NULL);

	sock = pytalloc_get_ptr(self);
	new_sock = pytalloc_get_ptr(pysocket);

	status = swrap_dup2(*sock, *new_sock);
	if (status < 0) {
		return PyErr_SetFromErrno(py_socket_error);
	}

	Py_RETURN_NONE;
}

static PyObject *py_socket_fileno(pytalloc_Object *self, PyObject *args)
{
	PyErr_SetString(py_socket_error, "Not Supported");
	return NULL;
}

static PyObject *py_socket_getpeername(pytalloc_Object *self, PyObject *args)
{
	int *sock;
	struct sockaddr addr;
	socklen_t addrlen;
	int status;
	PyObject *pyaddr;

	sock = pytalloc_get_ptr(self);

	status = swrap_getpeername(*sock, &addr, &addrlen);
	if (status < 0) {
		return PyErr_SetFromErrno(py_socket_error);
	}

	pyaddr = py_socket_addr_to_tuple(&addr, addrlen);

	return pyaddr;
}

static PyObject *py_socket_getsockname(pytalloc_Object *self, PyObject *args)
{
	int *sock;
	struct sockaddr addr;
	socklen_t addrlen;
	int status;
	PyObject *pyaddr;

	sock = pytalloc_get_ptr(self);

	status = swrap_getsockname(*sock, &addr, &addrlen);
	if (status < 0) {
		return PyErr_SetFromErrno(py_socket_error);
	}

	pyaddr = py_socket_addr_to_tuple(&addr, addrlen);

	return pyaddr;
}

static PyObject *py_socket_getsockopt(pytalloc_Object *self, PyObject *args)
{
	int level, optname;
	int *sock;
	socklen_t optlen = 0, newlen;
	int optval;
	bool is_integer = false;
	char *buffer;
	PyObject *pyret;
	int status;

	if (!PyArg_ParseTuple(args, "ii|i:getsockopt", &level, &optname, &optlen)) {
		return NULL;
	}

	if (optlen == 0) {
		optlen = sizeof(int);
		is_integer = true;
	}

	buffer = talloc_zero_array(NULL, char, optlen);
	if (buffer == NULL) {
		return PyErr_NoMemory();
	}

	sock = pytalloc_get_ptr(self);

	status = swrap_getsockopt(*sock, level, optname, (void *)buffer, &newlen);
	if (status < 0) {
		talloc_free(buffer);
		return PyErr_SetFromErrno(py_socket_error);
	}

	if (is_integer) {
		optval = *(int *)buffer;
		pyret = PyInt_FromLong(optval);
	} else {
		pyret = PyString_FromStringAndSize(buffer, optlen);
	}

	talloc_free(buffer);

	return pyret;
}

static PyObject *py_socket_gettimeout(pytalloc_Object *self, PyObject *args)
{
	PyErr_SetString(py_socket_error, "Not Supported");
	return NULL;
}

static PyObject *py_socket_listen(pytalloc_Object *self, PyObject *args)
{
	int backlog;
	int *sock;
	int status;

	if (!PyArg_ParseTuple(args, "i:listen", &backlog)) {
		return NULL;
	}

	sock = pytalloc_get_ptr(self);

	status = swrap_listen(*sock, backlog);
	if (status < 0) {
		return PyErr_SetFromErrno(py_socket_error);
	}

	Py_RETURN_NONE;
}

static PyObject *py_socket_makefile(pytalloc_Object *self, PyObject *args)
{
	PyErr_SetString(py_socket_error, "Not Supported");
	return NULL;
}

static PyObject *py_socket_read(pytalloc_Object *self, PyObject *args)
{
	int bufsize, len;
	int *sock;
	char *buffer;
	PyObject *pyret;

	if (!PyArg_ParseTuple(args, "i:read", &bufsize)) {
		return NULL;
	}

	buffer = talloc_zero_array(NULL, char, bufsize);
	if (buffer == NULL) {
		return PyErr_NoMemory();
	}

	sock = pytalloc_get_ptr(self);

	len = swrap_read(*sock, buffer, bufsize);
	if (len < 0) {
		return PyErr_SetFromErrno(py_socket_error);
	}

	pyret = PyString_FromStringAndSize(buffer, len);

	talloc_free(buffer);

	return pyret;
}

static PyObject *py_socket_recv(pytalloc_Object *self, PyObject *args)
{
	int bufsize, flags, len;
	int *sock;
	char *buffer;
	PyObject *pyret;

	if (!PyArg_ParseTuple(args, "ii:recv", &bufsize, &flags)) {
		return NULL;
	}

	buffer = talloc_zero_array(NULL, char, bufsize);
	if (buffer == NULL) {
		return PyErr_NoMemory();
	}

	sock = pytalloc_get_ptr(self);

	len = swrap_recv(*sock, buffer, bufsize, flags);
	if (len < 0) {
		return PyErr_SetFromErrno(py_socket_error);
	}

	pyret = PyString_FromStringAndSize(buffer, len);

	talloc_free(buffer);

	return pyret;
}

static PyObject *py_socket_recvfrom(pytalloc_Object *self, PyObject *args)
{
	int bufsize, flags, len;
	int *sock;
	char *buffer;
	struct sockaddr from;
	socklen_t fromlen;
	PyObject *pybuf, *pyaddr, *pyret;

	if (!PyArg_ParseTuple(args, "ii:recvfrom", &bufsize, &flags)) {
		return NULL;
	}

	buffer = talloc_zero_array(NULL, char, bufsize);
	if (buffer == NULL) {
		return PyErr_NoMemory();
	}

	sock = pytalloc_get_ptr(self);

	fromlen = sizeof(struct sockaddr);

	len = swrap_recvfrom(*sock, buffer, bufsize, flags, &from, &fromlen);
	if (len < 0) {
		talloc_free(buffer);
		return PyErr_SetFromErrno(py_socket_error);
	}

	pybuf = PyString_FromStringAndSize(buffer, len);
	if (pybuf == NULL) {
		talloc_free(buffer);
		return PyErr_NoMemory();
	}

	talloc_free(buffer);

	pyaddr = py_socket_addr_to_tuple(&from, fromlen);
	if (pyaddr == NULL) {
		Py_DECREF(pybuf);
		return NULL;
	}

	pyret = PyTuple_New(2);
	if (pyret == NULL) {
		Py_DECREF(pybuf);
		Py_DECREF(pyaddr);
		return PyErr_NoMemory();
	}

	PyTuple_SetItem(pyret, 0, pybuf);
	PyTuple_SetItem(pyret, 1, pyaddr);

	return pyret;
}

static PyObject *py_socket_send(pytalloc_Object *self, PyObject *args)
{
	char *buffer;
	int len, flags;
	int *sock;
	int status;

	if (!PyArg_ParseTuple(args, "s#i:sendto", &buffer, &len, &flags)) {
		return NULL;
	}

	sock = pytalloc_get_ptr(self);

	status = swrap_send(*sock, buffer, len, flags);
	if (status < 0) {
		PyErr_SetFromErrno(py_socket_error);
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *py_socket_sendall(pytalloc_Object *self, PyObject *args)
{
	char *buffer;
	int len, flags;
	int *sock;
	int status;

	if (!PyArg_ParseTuple(args, "s#i:sendall", &buffer, &len, &flags)) {
		return NULL;
	}

	sock = pytalloc_get_ptr(self);

	status = swrap_send(*sock, buffer, len, flags);
	if (status < 0) {
		PyErr_SetFromErrno(py_socket_error);
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *py_socket_sendto(pytalloc_Object *self, PyObject *args)
{
	PyObject *pyaddr;
	char *buffer;
	int len, flags;
	int *sock;
	struct sockaddr addr;
	socklen_t addrlen;
	int status;

	if (!PyArg_ParseTuple(args, "s#iO:sendto", &buffer, &len, &flags, &pyaddr)) {
		return NULL;
	}

	if (!py_socket_tuple_to_addr(pyaddr, &addr, &addrlen)) {
		return NULL;
	}

	sock = pytalloc_get_ptr(self);

	status = swrap_sendto(*sock, buffer, len, flags, &addr, addrlen);
	if (status < 0) {
		PyErr_SetFromErrno(py_socket_error);
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *py_socket_setblocking(pytalloc_Object *self, PyObject *args)
{
	PyErr_SetString(py_socket_error, "Not Supported");
	return NULL;
}

static PyObject *py_socket_setsockopt(pytalloc_Object *self, PyObject *args)
{
	int level, optname;
	int *sock;
	PyObject *pyval;
	int optval;
	Py_ssize_t optlen;
	char *buffer;
	int status;

	if (!PyArg_ParseTuple(args, "iiO:getsockopt", &level, &optname, &pyval)) {
		return NULL;
	}

	if (PyInt_Check(pyval)) {
		optval = PyInt_AsLong(pyval);
		buffer = (char *)&optval;
		optlen = sizeof(int);
	} else {
		PyString_AsStringAndSize(pyval, &buffer, &optlen);
	}

	sock = pytalloc_get_ptr(self);

	status = swrap_setsockopt(*sock, level, optname, (void *)buffer, optlen);
	if (status < 0) {
		return PyErr_SetFromErrno(py_socket_error);
	}

	Py_RETURN_NONE;
}

static PyObject *py_socket_settimeout(pytalloc_Object *self, PyObject *args)
{
	PyErr_SetString(py_socket_error, "Not Supported");
	return NULL;
}

static PyObject *py_socket_shutdown(pytalloc_Object *self, PyObject *args)
{
	PyErr_SetString(py_socket_error, "Not Supported");
	return NULL;
}

static PyObject *py_socket_write(pytalloc_Object *self, PyObject *args)
{
	char *buffer;
	int len;
	int *sock;
	int status;

	if (!PyArg_ParseTuple(args, "s#:write", &buffer, &len)) {
		return NULL;
	}

	sock = pytalloc_get_ptr(self);

	status = swrap_send(*sock, buffer, len, 0);
	if (status < 0) {
		PyErr_SetFromErrno(py_socket_error);
		return NULL;
	}

	Py_RETURN_NONE;
}


static PyMethodDef py_socket_methods[] = {
	{ "accept", (PyCFunction)py_socket_accept, METH_NOARGS,
		"accept() -> (socket object, address info)\n\n \
		Wait for an incoming connection." },
	{ "bind", (PyCFunction)py_socket_bind, METH_VARARGS,
		"bind(address)\n\n \
		Bind the socket to a local address." },
	{ "close", (PyCFunction)py_socket_close, METH_NOARGS,
		"close()\n\n \
		Close the socket." },
	{ "connect", (PyCFunction)py_socket_connect, METH_VARARGS,
		"connect(address)\n\n \
		Connect the socket to a remote address." },
	{ "connect_ex", (PyCFunction)py_socket_connect_ex, METH_VARARGS,
		"connect_ex(address)\n\n \
		Connect the socket to a remote address." },
	{ "dup", (PyCFunction)py_socket_dup, METH_VARARGS,
		"dup() -> socket object\n\n \
		Return a new socket object connected to the same system resource." },
	{ "dup2", (PyCFunction)py_socket_dup2, METH_VARARGS,
		"dup2(socket object) -> socket object\n\n \
		Return a new socket object connected to teh same system resource." },
	{ "fileno", (PyCFunction)py_socket_fileno, METH_NOARGS,
		"fileno() -> file descriptor\n\n \
		Return socket's file descriptor." },
	{ "getpeername", (PyCFunction)py_socket_getpeername, METH_NOARGS,
		"getpeername() -> address info\n\n \
		Return the address of the remote endpoint." },
	{ "getsockname", (PyCFunction)py_socket_getsockname, METH_NOARGS,
		"getsockname() -> address info\n\n \
		Return the address of the local endpoing." },
	{ "getsockopt", (PyCFunction)py_socket_getsockopt, METH_VARARGS,
		"getsockopt(level, option[, buffersize]) -> value\n\n \
		Get a socket option." },
	{ "gettimeout", (PyCFunction)py_socket_gettimeout, METH_NOARGS,
		"gettimeout() -> value\n\n \
		Return the timeout in seconds associated with socket operations." },
	{ "listen", (PyCFunction)py_socket_listen, METH_VARARGS,
		"listen(backlog)\n\n \
		Enable a server to accept connections." },
	{ "makefile", (PyCFunction)py_socket_makefile, METH_NOARGS,
		"makefile() -> file object\n\n \
		Return a file object associated with the socket." },
	{ "read", (PyCFunction)py_socket_read, METH_VARARGS,
		"read(buflen) -> data\n\n \
		Receive data." },
	{ "recv", (PyCFunction)py_socket_recv, METH_VARARGS,
		"recv(buflen, flags) -> data\n\n \
		Receive data." },
	{ "recvfrom", (PyCFunction)py_socket_recvfrom, METH_VARARGS,
		"recvfrom(buflen, flags) -> (data, sender address)\n\n \
		Receive data and sender's address." },
	{ "send", (PyCFunction)py_socket_send, METH_VARARGS,
		"send(data, flags)\n\n \
		Send data." },
	{ "sendall", (PyCFunction)py_socket_sendall, METH_VARARGS,
		"sendall(data, flags)\n\n \
		Send data." },
	{ "sendto", (PyCFunction)py_socket_sendto, METH_VARARGS,
		"sendto(data, flags, addr)\n\n \
		Send data to a given address." },
	{ "setblocking", (PyCFunction)py_socket_setblocking, METH_VARARGS,
		"setblocking(flag)\n\n \
		Set blocking or non-blocking mode of the socket." },
	{ "setsockopt", (PyCFunction)py_socket_setsockopt, METH_VARARGS,
		"setsockopt(level, option, value)\n\n \
		Set a socket option." },
	{ "settimeout", (PyCFunction)py_socket_settimeout, METH_VARARGS,
		"settimeout(value)\n\n \
		Set a timeout on socket blocking operations." },
	{ "shutdown", (PyCFunction)py_socket_shutdown, METH_VARARGS,
		"shutdown(how)\n\n \
		Shut down one or both halves of the connection." },
	{ "write", (PyCFunction)py_socket_write, METH_VARARGS,
		"write(data)\n\n \
		Send data." },
	{ NULL },
};


static PyObject *py_socket_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	int family, sock_type, protocol;
	int *sock;
	PyObject *pysocket;

	if (!PyArg_ParseTuple(args, "iii:socket", &family, &sock_type, &protocol)) {
		return NULL;
	}

	sock = talloc_zero(NULL, int);
	if (sock == NULL) {
		return PyErr_NoMemory();
	}

	*sock = swrap_socket(family, sock_type, protocol);
	if (*sock < 0) {
		return PyErr_SetFromErrno(py_socket_error);
	}

	if ((pysocket = pytalloc_steal(type, sock)) == NULL) {
		return PyErr_NoMemory();
	}

	return pysocket;
}


static PyTypeObject PySocket = {
	.tp_name = "socket_wrapper.socket",
	.tp_basicsize = sizeof(pytalloc_Object),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_methods = py_socket_methods,
	.tp_new = py_socket_new,
	.tp_doc = "socket(family, type, proto) -> socket object\n\n Open a socket of the give type.",
};

static PyObject *py_socket_wrapper_dir(PyObject *self)
{
	const char *dir;

	dir = socket_wrapper_dir();

	return PyString_FromString(dir);
}

static PyObject *py_socket_wrapper_default_interface(PyObject *self)
{
	unsigned int id;

	id = socket_wrapper_default_iface();

	return PyInt_FromLong(id);
}


static PyMethodDef py_socket_wrapper_methods[] = {
	{ "dir", (PyCFunction)py_socket_wrapper_dir, METH_NOARGS,
		"dir() -> path\n\n \
		Return socket_wrapper directory." },
	{ "default_iface", (PyCFunction)py_socket_wrapper_default_interface, METH_NOARGS,
		"default_iface() -> id\n\n \
		Return default interface id." },
	{ NULL },
};

void initsocket_wrapper(void)
{
	PyObject *m;
	char exception_name[] = "socket_wrapper.error";

	PyTypeObject *talloc_type = pytalloc_GetObjectType();
	if (talloc_type == NULL) {
		return;
	}

	PySocket.tp_base = talloc_type;
	if (PyType_Ready(&PySocket) < 0) {
		return;
	}

	m = Py_InitModule3("socket_wrapper", py_socket_wrapper_methods, "Socket wrapper");
	if (m == NULL) {
		return;
	}

	py_socket_error = PyErr_NewException(exception_name, NULL, NULL);
	Py_INCREF(py_socket_error);
	PyModule_AddObject(m, "error", py_socket_error);

	Py_INCREF(&PySocket);
	PyModule_AddObject(m, "socket", (PyObject *)&PySocket);
}
