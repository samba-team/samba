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

uint8 uint8_from_python(PyObject *obj)
{
	return (uint8)PyInt_AsLong(obj);
}

PyObject *uint8_to_python(uint8 obj)
{
	return PyInt_FromLong(obj);
}

uint16 uint16_from_python(PyObject *obj)
{
	return (uint16)PyInt_AsLong(obj);
}

PyObject *uint16_to_python(uint16 obj)
{
	return PyInt_FromLong(obj);
}

uint32 uint32_from_python(PyObject *obj)
{
	return (uint32)PyInt_AsLong(obj);
}

PyObject *uint32_to_python(uint32 obj)
{
	return PyInt_FromLong(obj);
}

int64 int64_from_python(PyObject *obj)
{
	return (int64)PyLong_AsLong(obj);
}

PyObject *int64_to_python(int64 obj)
{
	return PyLong_FromLong(obj);
}

uint64 uint64_from_python(PyObject *obj)
{
	return (uint64)PyLong_AsLong(obj);
}

PyObject *uint64_to_python(uint64 obj)
{
	return PyLong_FromLong(obj);
}

NTTIME NTTIME_from_python(PyObject *obj)
{
	return (NTTIME)PyLong_AsLong(obj);
}

PyObject *NTTIME_to_python(NTTIME obj)
{
	return PyLong_FromLong(obj);
}

HYPER_T HYPER_T_from_python(PyObject *obj)
{
	return (HYPER_T)PyLong_AsLong(obj);
}

PyObject *HYPER_T_to_python(HYPER_T obj)
{
	return PyLong_FromLong(obj);
}

/* Conversion functions for types that we don't want generated automatically.
   This is mostly security realted stuff in misc.idl */

char *string_ptr_from_python(TALLOC_CTX *mem_ctx, PyObject *obj)
{
	if (obj == Py_None)
		return NULL;

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

struct policy_handle *policy_handle_ptr_from_python(TALLOC_CTX *mem_ctx, PyObject *obj)
{
	return (struct policy_handle *)PyString_AsString(obj);
}

PyObject *policy_handle_ptr_to_python(TALLOC_CTX *mem_ctx, struct policy_handle *handle)
{
	return PyString_FromStringAndSize((char *)handle, sizeof(*handle));
}

PyObject *dom_sid_ptr_to_python(TALLOC_CTX *mem_ctx, struct dom_sid *obj)
{
	return PyString_FromString(dom_sid_string(mem_ctx, obj));
}

struct dom_sid *dom_sid_ptr_from_python(TALLOC_CTX *mem_ctx, PyObject *obj)
{
	return dom_sid_parse_talloc(mem_ctx, PyString_AsString(obj));
}

#define dom_sid2_ptr_to_python dom_sid_ptr_to_python
#define dom_sid2_ptr_from_python dom_sid_ptr_from_python

void dom_sid_from_python(TALLOC_CTX *mem_ctx, struct dom_sid *sid, PyObject *obj)
{
	memset(sid, 0, sizeof(struct dom_sid)); // XXX
}

PyObject *security_acl_ptr_to_python(TALLOC_CTX *mem_ctx, struct security_acl *obj)
{
	PyObject *result = PyDict_New();
	PyObject *ace_list;
	int i;

	if (!obj) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	PyDict_SetItem(result, PyString_FromString("revision"), PyInt_FromLong(obj->revision));
	PyDict_SetItem(result, PyString_FromString("size"), PyInt_FromLong(obj->size));

	ace_list = PyList_New(obj->num_aces);

	for(i = 0; i < obj->num_aces; i++) {
		PyObject *ace = PyDict_New();

		PyDict_SetItem(ace, PyString_FromString("type"), PyInt_FromLong(obj->aces[i].type));
		PyDict_SetItem(ace, PyString_FromString("flags"), PyInt_FromLong(obj->aces[i].flags));
		PyDict_SetItem(ace, PyString_FromString("access_mask"), PyInt_FromLong(obj->aces[i].access_mask));
		PyDict_SetItem(ace, PyString_FromString("trustee"), dom_sid_ptr_to_python(mem_ctx, &obj->aces[i].trustee));

		PyList_SetItem(ace_list, i, ace);
	}

	PyDict_SetItem(result, PyString_FromString("aces"), ace_list);

	return result;
}

struct security_acl *security_acl_ptr_from_python(TALLOC_CTX *mem_ctx, PyObject *obj)
{
	struct security_acl *acl = talloc(mem_ctx, sizeof(struct security_acl));
	PyObject *ace_list;
	int i, len;

	acl->revision = PyInt_AsLong(PyDict_GetItem(obj, PyString_FromString("revision")));
	acl->size = PyInt_AsLong(PyDict_GetItem(obj, PyString_FromString("size")));
	ace_list = PyDict_GetItem(obj, PyString_FromString("aces"));

	len = PyList_Size(ace_list);
	acl->num_aces = len;
	acl->aces = talloc(mem_ctx, len * sizeof(struct security_ace));

	for (i = 0; i < len; i++) {
		acl->aces[i].type = PyInt_AsLong(PyDict_GetItem(obj, PyString_FromString("type")));
		acl->aces[i].flags = PyInt_AsLong(PyDict_GetItem(obj, PyString_FromString("flags")));
		acl->aces[i].size = 0;
		acl->aces[i].access_mask = PyInt_AsLong(PyDict_GetItem(obj, PyString_FromString("access_mask")));

		dom_sid_from_python(mem_ctx, &acl->aces[i].trustee, PyDict_GetItem(obj, PyString_FromString("trustee")));
	}

	return acl;
}

PyObject *security_descriptor_ptr_to_python(TALLOC_CTX *mem_ctx, struct security_descriptor *obj)
{
	PyObject *result = PyDict_New();

	if (!obj) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	PyDict_SetItem(result, PyString_FromString("revision"), PyInt_FromLong(obj->revision));
	PyDict_SetItem(result, PyString_FromString("type"), PyInt_FromLong(obj->type));

	PyDict_SetItem(result, PyString_FromString("owner_sid"), dom_sid_ptr_to_python(mem_ctx, obj->owner_sid));
	PyDict_SetItem(result, PyString_FromString("group_sid"), dom_sid_ptr_to_python(mem_ctx, obj->group_sid));

	PyDict_SetItem(result, PyString_FromString("sacl"), security_acl_ptr_to_python(mem_ctx, obj->sacl));
	PyDict_SetItem(result, PyString_FromString("dacl"), security_acl_ptr_to_python(mem_ctx, obj->dacl));

	return result;
}

struct security_descriptor *security_descriptor_ptr_from_python(TALLOC_CTX *mem_ctx, PyObject *obj)
{
	struct security_descriptor *sd = talloc(mem_ctx, sizeof(struct security_descriptor));

	sd->revision = PyInt_AsLong(PyDict_GetItem(obj, PyString_FromString("revision")));
	sd->type = PyInt_AsLong(PyDict_GetItem(obj, PyString_FromString("type")));

	sd->owner_sid = security_descriptor_ptr_from_python(mem_ctx, PyDict_GetItem(obj, PyString_FromString("owner_sid")));
	sd->group_sid = security_descriptor_ptr_from_python(mem_ctx, PyDict_GetItem(obj, PyString_FromString("group_sid")));

	sd->sacl = security_acl_ptr_from_python(mem_ctx, PyDict_GetItem(obj, PyString_FromString("sacl")));
	sd->dacl = security_acl_ptr_from_python(mem_ctx, PyDict_GetItem(obj, PyString_FromString("dacl")));

	return sd;
}

struct samr_Password *samr_Password_ptr_from_python(TALLOC_CTX *mem_ctx, PyObject *obj)
{
	return NULL;
}

PyObject *samr_Password_ptr_to_python(TALLOC_CTX *mem_ctx, struct samr_Password *obj)
{
	Py_INCREF(Py_None);
	return Py_None;
}

%}

%include "samba.i"

%init  %{
/* setup_logging("python", DEBUG_STDOUT);	*/
	lp_load(dyn_CONFIGFILE, True, False, False);
	load_interfaces();
	ntstatus_exception = PyErr_NewException("dcerpc.NTSTATUS", NULL, NULL);
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

%include "librpc/gen_ndr/lsa.i"
%include "librpc/gen_ndr/samr.i"
