/* Tastes like -*- C -*- */

/* 
   Unix SMB/CIFS implementation.

   Swig interface to librpc functions.

   Copyright (C) Tim Potter 2004
   
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

%module dcerpc

%{

/* This symbol is used in both includes.h and Python.h which causes an
   annoying compiler warning. */

#ifdef HAVE_FSTAT
#undef HAVE_FSTAT
#endif

#include "includes.h"

#undef strcpy

PyObject *ntstatus_exception;

/* Set up return of a dcerpc.NTSTATUS exception */

void set_ntstatus_exception(int status)
{
	PyObject *obj = Py_BuildValue("(i,s)", status, 
				nt_errstr(NT_STATUS(status)));

	PyErr_SetObject(ntstatus_exception, obj);
}

/* Conversion functions for scalar types */

uint8 uint8_from_python(PyObject *obj, char *name)
{
	if (obj == NULL) {
		PyErr_Format(PyExc_ValueError, "Expecting key %s", name);
		return 0;
	}

	if (!PyInt_Check(obj)) {
		PyErr_Format(PyExc_TypeError, "Expecting int value for %s", name);
		return 0;
	}

	return (uint8)PyInt_AsLong(obj);
}

PyObject *uint8_to_python(uint8 obj)
{
	return PyInt_FromLong(obj);
}

uint16 uint16_from_python(PyObject *obj, char *name)
{
	if (obj == NULL) {
		PyErr_Format(PyExc_ValueError, "Expecting key %s", name);
		return 0;
	}

	if (!PyInt_Check(obj)) {
		PyErr_Format(PyExc_TypeError, "Expecting int value for %s", name);
		return 0;
	}

	return (uint16)PyInt_AsLong(obj);
}

PyObject *uint16_to_python(uint16 obj)
{
	return PyInt_FromLong(obj);
}

uint32 uint32_from_python(PyObject *obj, char *name)
{
	if (obj == NULL) {
		PyErr_Format(PyExc_ValueError, "Expecting key %s", name);
		return 0;
	}

	if (!PyInt_Check(obj)) {
		PyErr_Format(PyExc_TypeError, "Expecting int value for %s", name);
		return 0;
	}

	return (uint32)PyInt_AsLong(obj);
}

PyObject *uint32_to_python(uint32 obj)
{
	return PyInt_FromLong(obj);
}

int64 int64_from_python(PyObject *obj, char *name)
{
	if (obj == NULL) {
		PyErr_Format(PyExc_ValueError, "Expecting key %s", name);
		return 0;
	}

	if (!PyInt_Check(obj)) {
		PyErr_Format(PyExc_TypeError, "Expecting int value for %s", name);
		return 0;
	}

	return (int64)PyLong_AsLong(obj);
}

PyObject *int64_to_python(int64 obj)
{
	return PyLong_FromLong(obj);
}

uint64 uint64_from_python(PyObject *obj, char *name)
{
	if (obj == NULL) {
		PyErr_Format(PyExc_ValueError, "Expecting key %s", name);
		return 0;
	}

	if (!PyInt_Check(obj)) {
		PyErr_Format(PyExc_TypeError, "Expecting int value for %s", name);
		return 0;
	}

	return (uint64)PyLong_AsLong(obj);
}

PyObject *uint64_to_python(uint64 obj)
{
	return PyLong_FromLong(obj);
}

NTTIME NTTIME_from_python(PyObject *obj, char *name)
{
	if (obj == NULL) {
		PyErr_Format(PyExc_ValueError, "Expecting key %s", name);
		return 0;
	}

	if (!PyInt_Check(obj)) {
		PyErr_Format(PyExc_TypeError, "Expecting integer value for %s", name);
		return 0;
	}

	return (NTTIME)PyLong_AsLong(obj);
}

PyObject *NTTIME_to_python(NTTIME obj)
{
	return PyLong_FromLong(obj);
}

HYPER_T HYPER_T_from_python(PyObject *obj, char *name)
{
	if (obj == NULL) {
		PyErr_Format(PyExc_ValueError, "Expecting key %s", name);
		return 0;
	}

	if (!PyInt_Check(obj)) {
		PyErr_Format(PyExc_TypeError, "Expecting integer value for %s", name);
		return 0;
	}

	return (HYPER_T)PyLong_AsLong(obj);
}

PyObject *HYPER_T_to_python(HYPER_T obj)
{
	return PyLong_FromLong(obj);
}

/* Conversion functions for types that we don't want generated automatically.
   This is mostly security realted stuff in misc.idl */

char *string_ptr_from_python(TALLOC_CTX *mem_ctx, PyObject *obj, char *name)
{
	if (obj == NULL) {
		PyErr_Format(PyExc_ValueError, "Expecting key %s", name);
		return NULL;
	}

	if (obj == Py_None)
		return NULL;

	if (!PyString_Check(obj)) {
		PyErr_Format(PyExc_TypeError, "Expecting string value for %s", name);
		return NULL;
	}

	return PyString_AsString(obj);
}

PyObject *string_ptr_to_python(TALLOC_CTX *mem_ctx, char *obj)
{
	if (obj == NULL) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	return PyString_FromString(obj);
}

#define dom_sid2_ptr_to_python dom_sid_ptr_to_python
#define dom_sid2_ptr_from_python dom_sid_ptr_from_python

%}

%include "samba.i"

%pythoncode %{
	NTSTATUS = _dcerpc.NTSTATUS
%}

%init  %{
	setup_logging("python", DEBUG_STDOUT);	
	lp_load(dyn_CONFIGFILE, True, False, False);
	load_interfaces();
	ntstatus_exception = PyErr_NewException("_dcerpc.NTSTATUS", NULL, NULL);
	PyDict_SetItemString(d, "NTSTATUS", ntstatus_exception);
%}

%typemap(in, numinputs=0) struct dcerpc_pipe **OUT (struct dcerpc_pipe *temp_dcerpc_pipe) {
        $1 = &temp_dcerpc_pipe;
}

%typemap(in, numinputs=0) TALLOC_CTX * {
	$1 = talloc_init("$symname");
}

%typemap(freearg) TALLOC_CTX * {
	talloc_free($1);
}

%typemap(argout) struct dcerpc_pipe ** {
	long status = PyLong_AsLong(resultobj);

	/* Throw exception if result was not OK */

	if (status != 0) {
		set_ntstatus_exception(status);
		return NULL;
	}

	/* Set REF_ALLOC flag so we don't have to do too much extra
	   mucking around with ref variables in ndr unmarshalling. */

	(*$1)->flags |= DCERPC_NDR_REF_ALLOC;

	/* Return swig handle on dcerpc_pipe */

        resultobj = SWIG_NewPointerObj(*$1, SWIGTYPE_p_dcerpc_pipe, 0);
}

%types(struct dcerpc_pipe *);

%rename(pipe_connect) dcerpc_pipe_connect;

NTSTATUS dcerpc_pipe_connect(struct dcerpc_pipe **OUT,
                             const char *binding,
                             const char *pipe_uuid,
                             uint32 pipe_version,
                             const char *domain,
                             const char *username,
                             const char *password);

/* Run this test after each wrapped function */

%exception {
	$action
	if (!NT_STATUS_IS_OK(result)) {
		set_ntstatus_exception(NT_STATUS_V(result));
		return NULL;
	}
}

%include "librpc/gen_ndr/misc.i"
%include "librpc/gen_ndr/lsa.i"
%include "librpc/gen_ndr/samr.i"
