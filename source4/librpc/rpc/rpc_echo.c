/* 
   Unix SMB/CIFS implementation.

   rpc echo pipe calls

   Copyright (C) Andrew Tridgell 2003
   
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

#include "includes.h"

NTSTATUS dcerpc_echo_AddOne(struct dcerpc_pipe *p,
			    TALLOC_CTX *mem_ctx,
			    struct echo_AddOne *r)
{
	return dcerpc_ndr_request(p, DCERPC_ECHO_ADDONE, mem_ctx,
				  (ndr_push_fn_t) ndr_push_echo_AddOne,
				  (ndr_pull_fn_t) ndr_pull_echo_AddOne,
				  r);
}


NTSTATUS dcerpc_echo_EchoData(struct dcerpc_pipe *p,
			      TALLOC_CTX *mem_ctx,
			      struct echo_EchoData *r)
{
	return dcerpc_ndr_request(p, DCERPC_ECHO_ECHODATA, mem_ctx,
				  (ndr_push_fn_t) ndr_push_echo_EchoData,
				  (ndr_pull_fn_t) ndr_pull_echo_EchoData,
				  r);
}

NTSTATUS dcerpc_echo_SinkData(struct dcerpc_pipe *p,
			      TALLOC_CTX *mem_ctx,
			      struct echo_SinkData *r)
{
	return dcerpc_ndr_request(p, DCERPC_ECHO_SINKDATA, mem_ctx,
				  (ndr_push_fn_t) ndr_push_echo_SinkData,
				  (ndr_pull_fn_t) ndr_pull_echo_SinkData,
				  r);
}

NTSTATUS dcerpc_echo_SourceData(struct dcerpc_pipe *p,
			      TALLOC_CTX *mem_ctx,
			      struct echo_SourceData *r)
{
	return dcerpc_ndr_request(p, DCERPC_ECHO_SOURCEDATA, mem_ctx,
				  (ndr_push_fn_t) ndr_push_echo_SourceData,
				  (ndr_pull_fn_t) ndr_pull_echo_SourceData,
				  r);
}
