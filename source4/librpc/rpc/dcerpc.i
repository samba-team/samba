/* Tastes like -*- C -*- */

/* 
   Unix SMB/CIFS implementation.

   Swig interface to librpc functions.

   Copyright (C) Tim Potter 2004
   Copyright (C) Jelmer Vernooij 2007
   
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
#include "librpc/rpc/dcerpc.h"
#include "param/param.h"

#undef strcpy

%}

%import "../../lib/talloc/talloc.i"
%import "../../auth/credentials/credentials.i"

%typemap(in,noblock=1, numinputs=0) struct dcerpc_pipe **OUT (struct dcerpc_pipe *temp_dcerpc_pipe) {
        $1 = &temp_dcerpc_pipe;
}

%typemap(argout,noblock=1) struct dcerpc_pipe ** {
	/* Set REF_ALLOC flag so we don't have to do too much extra
	   mucking around with ref variables in ndr unmarshalling. */

	(*$1)->conn->flags |= DCERPC_NDR_REF_ALLOC;

	/* Return swig handle on dcerpc_pipe */

    $result = SWIG_NewPointerObj(*$1, SWIGTYPE_p_dcerpc_pipe, 0);
}

%types(struct dcerpc_pipe *);

%rename(pipe_connect) dcerpc_pipe_connect;

NTSTATUS dcerpc_pipe_connect(TALLOC_CTX *parent_ctx, 
			     struct dcerpc_pipe **pp, 
			     const char *binding,
			     const struct ndr_interface_table *table,
			     struct cli_credentials *credentials,
			     struct event_context *ev,
			     struct loadparm_context *lp_ctx);

%typemap(in,noblock=1) DATA_BLOB * (DATA_BLOB temp_data_blob) {
	temp_data_blob.data = PyString_AsString($input);
	temp_data_blob.length = PyString_Size($input);
	$1 = &temp_data_blob;
}

const char *dcerpc_server_name(struct dcerpc_pipe *p);

/* Some typemaps for easier access to resume handles.  Really this can
   also be done using the uint32 carray functions, but it's a bit of a
   hassle.  TODO: Fix memory leak here. */

%typemap(in,noblock=1) uint32_t *resume_handle {
	$1 = malloc(sizeof(*$1));
	*$1 = PyLong_AsLong($input);
}

%typemap(out,noblock=1) uint32_t *resume_handle {
	$result = PyLong_FromLong(*$1);
}

%typemap(in,noblock=1) struct policy_handle * {

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

%typemap(out,noblock=1) struct policy_handle * {
	if ($1) {
		struct policy_handle *temp = (struct policy_handle *)malloc(sizeof(struct policy_handle));
		memcpy(temp, $1, sizeof(struct policy_handle));
		$result = SWIG_NewPointerObj(temp, SWIGTYPE_p_policy_handle, 0);
	} else {
		Py_INCREF(Py_None);
		$result = Py_None;
	}
}
