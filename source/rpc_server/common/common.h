/* 
   Unix SMB/CIFS implementation.

   common macros for the dcerpc server interfaces

   Copyright (C) Stefan (metze) Metzmacher 2004
   Copyright (C) Andrew Tridgell 2004
   
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

/* a useful macro for generating a RPC fault in the backend code */
#define DCESRV_FAULT(code) do { \
	dce_call->fault_code = code; \
	return r->out.result; \
} while(0)

/* a useful macro for generating a RPC fault in the backend code */
#define DCESRV_FAULT_VOID(code) do { \
	dce_call->fault_code = code; \
	return; \
} while(0)

/* a useful macro for checking the validity of a dcerpc policy handle
   and giving the right fault code if invalid */
#define DCESRV_CHECK_HANDLE(h) do {if (!(h)) DCESRV_FAULT(DCERPC_FAULT_CONTEXT_MISMATCH); } while (0)

/* this checks for a valid policy handle, and gives a fault if an
   invalid handle or retval if the handle is of the
   wrong type */
#define DCESRV_PULL_HANDLE_RETVAL(h, inhandle, t, retval) do { \
	(h) = dcesrv_handle_fetch(dce_call->context, (inhandle), DCESRV_HANDLE_ANY); \
	DCESRV_CHECK_HANDLE(h); \
	if ((t) != DCESRV_HANDLE_ANY && (h)->wire_handle.handle_type != (t)) { \
		return retval; \
	} \
} while (0)

/* this checks for a valid policy handle and gives a dcerpc fault 
   if its the wrong type of handle */
#define DCESRV_PULL_HANDLE_FAULT(h, inhandle, t) do { \
	(h) = dcesrv_handle_fetch(dce_call->context, (inhandle), t); \
	DCESRV_CHECK_HANDLE(h); \
} while (0)

#define DCESRV_PULL_HANDLE(h, inhandle, t) DCESRV_PULL_HANDLE_RETVAL(h, inhandle, t, NT_STATUS_INVALID_HANDLE)
#define DCESRV_PULL_HANDLE_WERR(h, inhandle, t) DCESRV_PULL_HANDLE_RETVAL(h, inhandle, t, WERR_BADFID)

struct dcesrv_context;

#include "param/share.h"
#include "rpc_server/common/proto.h"
