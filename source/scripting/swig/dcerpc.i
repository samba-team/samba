/* Tastes like -*- C -*- */

/* 
   Unix SMB/CIFS implementation.

   Swig interface to librpc functions.

   Copyright (C) Tim Potter 2004
   
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

%module dcerpc

%{

/* This symbol is used in both includes.h and Python.h which causes an
   annoying compiler warning. */

#ifdef HAVE_FSTAT
#undef HAVE_FSTAT
#endif

#include "includes.h"
#include "dynconfig.h"

#undef strcpy

PyObject *ntstatus_exception, *werror_exception;

/* Set up return of a dcerpc.NTSTATUS exception */

void set_ntstatus_exception(int status)
{
	PyObject *obj = Py_BuildValue("(i,s)", status, 
				nt_errstr(NT_STATUS(status)));

	PyErr_SetObject(ntstatus_exception, obj);
}

void set_werror_exception(int status)
{
	PyObject *obj = Py_BuildValue("(i,s)", status, 
				win_errstr(W_ERROR(status)));

	PyErr_SetObject(werror_exception, obj);
}

%}

%include "samba.i"

%pythoncode %{
	NTSTATUS = _dcerpc.NTSTATUS
	WERROR = _dcerpc.WERROR
%}

%init  %{
	setup_logging("python", DEBUG_STDOUT);	
	lp_load();
	ntstatus_exception = PyErr_NewException("_dcerpc.NTSTATUS", NULL, NULL);
	werror_exception = PyErr_NewException("_dcerpc.WERROR", NULL, NULL);
	PyDict_SetItemString(d, "NTSTATUS", ntstatus_exception);
	PyDict_SetItemString(d, "WERROR", werror_exception);

/* BINARY swig_dcerpc INIT */

		extern NTSTATUS dcerpc_misc_init(void);
		extern NTSTATUS dcerpc_krb5pac_init(void);
		extern NTSTATUS dcerpc_samr_init(void);
		extern NTSTATUS dcerpc_dcerpc_init(void);
		extern NTSTATUS auth_sam_init(void);
		extern NTSTATUS dcerpc_lsa_init(void);
		extern NTSTATUS dcerpc_netlogon_init(void);
		extern NTSTATUS gensec_init(void);
		extern NTSTATUS auth_developer_init(void);
		extern NTSTATUS gensec_spnego_init(void);
		extern NTSTATUS auth_winbind_init(void);
		extern NTSTATUS gensec_gssapi_init(void);
		extern NTSTATUS gensec_ntlmssp_init(void);
		extern NTSTATUS dcerpc_nbt_init(void);
		extern NTSTATUS auth_anonymous_init(void);
		extern NTSTATUS gensec_krb5_init(void);
		extern NTSTATUS dcerpc_schannel_init(void);
		extern NTSTATUS dcerpc_epmapper_init(void);
		if (NT_STATUS_IS_ERR(dcerpc_misc_init())) exit(1);
		if (NT_STATUS_IS_ERR(dcerpc_krb5pac_init())) exit(1);
		if (NT_STATUS_IS_ERR(dcerpc_samr_init())) exit(1);
		if (NT_STATUS_IS_ERR(dcerpc_dcerpc_init())) exit(1);
		if (NT_STATUS_IS_ERR(auth_sam_init())) exit(1);
		if (NT_STATUS_IS_ERR(dcerpc_lsa_init())) exit(1);
		if (NT_STATUS_IS_ERR(dcerpc_netlogon_init())) exit(1);
		if (NT_STATUS_IS_ERR(gensec_init())) exit(1);
		if (NT_STATUS_IS_ERR(auth_developer_init())) exit(1);
		if (NT_STATUS_IS_ERR(gensec_spnego_init())) exit(1);
		if (NT_STATUS_IS_ERR(auth_winbind_init())) exit(1);
		if (NT_STATUS_IS_ERR(gensec_gssapi_init())) exit(1);
		if (NT_STATUS_IS_ERR(gensec_ntlmssp_init())) exit(1);
		if (NT_STATUS_IS_ERR(dcerpc_nbt_init())) exit(1);
		if (NT_STATUS_IS_ERR(auth_anonymous_init())) exit(1);
		if (NT_STATUS_IS_ERR(gensec_krb5_init())) exit(1);
		if (NT_STATUS_IS_ERR(dcerpc_schannel_init())) exit(1);
		if (NT_STATUS_IS_ERR(dcerpc_epmapper_init())) exit(1);

%}

%typemap(in, numinputs=0) struct dcerpc_pipe **OUT (struct dcerpc_pipe *temp_dcerpc_pipe) {
        $1 = &temp_dcerpc_pipe;
}

%typemap(in, numinputs=0) TALLOC_CTX * {
	$1 = talloc_init("$symname");
}

%typemap(freearg) TALLOC_CTX * {
//	talloc_free($1);
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

	(*$1)->conn->flags |= DCERPC_NDR_REF_ALLOC;

	/* Return swig handle on dcerpc_pipe */

        resultobj = SWIG_NewPointerObj(*$1, SWIGTYPE_p_dcerpc_pipe, 0);
}

%types(struct dcerpc_pipe *);

%rename(pipe_connect) dcerpc_pipe_connect;

NTSTATUS dcerpc_pipe_connect(TALLOC_CTX *parent_ctx,
	                     struct dcerpc_pipe **OUT,
                             const char *binding,
                             const char *pipe_uuid,
                             uint32_t pipe_version,
			     struct cli_credentials *credentials);

%typemap(in) DATA_BLOB * (DATA_BLOB temp_data_blob) {
	temp_data_blob.data = PyString_AsString($input);
	temp_data_blob.length = PyString_Size($input);
	$1 = &temp_data_blob;
}

const char *dcerpc_server_name(struct dcerpc_pipe *p);

char *nt_errstr(NTSTATUS nt_code);

/* Some typemaps for easier access to resume handles.  Really this can
   also be done using the uint32 carray functions, but it's a bit of a
   hassle.  TODO: Fix memory leak here. */

%typemap(in) uint32_t *resume_handle {
	$1 = malloc(sizeof(*$1));
	*$1 = PyLong_AsLong($input);
}

%typemap(out) uint32_t *resume_handle {
	$result = PyLong_FromLong(*$1);
}

%typemap(in) struct policy_handle * {

	if ((SWIG_ConvertPtr($input, (void **) &$1, $1_descriptor,
			     SWIG_POINTER_EXCEPTION)) == -1) 
	        return NULL;

	if ($1 == NULL) {
		PyErr_SetString(PyExc_TypeError, "None is not a valid policy handle");
		return NULL;
	}
}

/* When returning a policy handle to Python we need to make a copy of
   as the talloc context it is created under is destroyed after the
   wrapper function returns.  TODO: Fix memory leak created here. */

%typemap(out) struct policy_handle * {
	if ($1) {
		struct policy_handle *temp = (struct policy_handle *)malloc(sizeof(struct policy_handle));
		memcpy(temp, $1, sizeof(struct policy_handle));
		$result = SWIG_NewPointerObj(temp, SWIGTYPE_p_policy_handle, 0);
	} else {
		Py_INCREF(Py_None);
		$result = Py_None;
	}
}

%{
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/gen_ndr/ndr_samr.h"
%}

%include "carrays.i"

/* Some functions for accessing arrays of fixed-width integers. */

%array_functions(uint8_t, uint8_array);
%array_functions(uint16_t, uint16_array);
%array_functions(uint32_t, uint32_array);

/* Functions for handling arrays of structures.  It would be nice for 
   pidl to automatically generating these instead of having to find
   them all by hand. */

%array_functions(struct samr_SamEntry, samr_SamEntry_array);
%array_functions(union samr_ConnectInfo, samr_ConnectInfo_array);
%array_functions(struct samr_RidWithAttribute, samr_RidWithAttribute_array);

%array_functions(struct lsa_SidPtr, lsa_SidPtr_array);

%include "librpc/gen_ndr/misc.i"
%include "librpc/gen_ndr/security.i"
%include "librpc/gen_ndr/samr.i"
%include "librpc/gen_ndr/lsa.i"
