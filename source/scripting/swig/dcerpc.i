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

%}

%include "samba.i"

%init  %{
/* setup_logging("python", DEBUG_STDOUT);	*/
	lp_load(dyn_CONFIGFILE, True, False, False);
	load_interfaces();
%}

%typemap(in, numinputs=0) struct dcerpc_pipe **OUT (struct dcerpc_pipe *temp) {
        $1 = &temp;
}

%typemap(argout) struct dcerpc_pipe ** {
        PyObject *o = PyTuple_New(2);
        PyTuple_SetItem(o, 0, resultobj);
        PyTuple_SetItem(o, 1, SWIG_NewPointerObj(*$1, SWIGTYPE_p_dcerpc_pipe, 0));
        resultobj = o;
}

%types(struct dcerpc_pipe *);

NTSTATUS dcerpc_pipe_connect(struct dcerpc_pipe **OUT,
                             const char *binding,
                             const char *pipe_uuid,
                             uint32 pipe_version,
                             const char *domain,
                             const char *username,
                             const char *password);
%include "samr.i"
