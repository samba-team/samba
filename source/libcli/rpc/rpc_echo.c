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

/*
  addone interface
*/
NTSTATUS dcerpc_rpcecho_addone(struct dcerpc_pipe *p,
			       int in_data, int *out_data)
{
	struct rpcecho_addone r;
	NTSTATUS status;
	DATA_BLOB request, response;
	TALLOC_CTX *mem_ctx;
	struct ndr_push *push;
	struct ndr_pull *pull;

	mem_ctx = talloc_init("dcerpc_rpcecho_addone");
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	push = ndr_push_init();
	if (!push) {
		talloc_destroy(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	r.in.data = in_data;

	status = ndr_push_rpcecho_addone(push, &r);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	request = ndr_push_blob(push);

	status = cli_dcerpc_request(p, RPCECHO_CALL_ADDONE, mem_ctx, &request, &response);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	pull = ndr_pull_init_blob(&response, mem_ctx);
	if (!pull) {
		goto failed;
	}

	status = ndr_pull_rpcecho_addone(pull, &r);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	*out_data = r.out.data;

failed:
	ndr_push_free(push);
	talloc_destroy(mem_ctx);
	return status;
}
