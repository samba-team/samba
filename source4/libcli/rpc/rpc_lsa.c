/* 
   Unix SMB/CIFS implementation.

   rpc lsa pipe calls

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
  OpenPolicy interface
*/
NTSTATUS dcerpc_lsa_OpenPolicy(struct dcerpc_pipe *p,
			       const char *server,
			       struct lsa_ObjectAttribute *attr,
			       uint32 access_mask,
			       struct policy_handle *handle)
{
	struct lsa_OpenPolicy r;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("dcerpc_rpcecho_addone");
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	/* fill the .in side of the call */
	r.in.system_name = server;
	r.in.attr = attr;
	r.in.desired_access = access_mask;

	/* make the call */
	status = dcerpc_ndr_request(p, LSA_OPENPOLICY, mem_ctx,
				    (ndr_push_fn_t) ndr_push_lsa_OpenPolicy,
				    (ndr_pull_fn_t) ndr_pull_lsa_OpenPolicy,
				    &r);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}
	
	/* and extract the .out parameters */
	*handle = r.out.handle;
	status = r.out.status;

done:
	talloc_destroy(mem_ctx);
	return status;
}


/*
  OpenPolicy2 interface
*/
NTSTATUS dcerpc_lsa_OpenPolicy2(struct dcerpc_pipe *p,
				const char *server,
				struct lsa_ObjectAttribute *attr,
				uint32 access_mask,
				struct policy_handle *handle)
{
	struct lsa_OpenPolicy2 r;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("dcerpc_rpcecho_addone");
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	/* fill the .in side of the call */
	r.in.system_name = server;
	r.in.attr = attr;
	r.in.desired_access = access_mask;

	/* make the call */
	status = dcerpc_ndr_request(p, LSA_OPENPOLICY2, mem_ctx,
				    (ndr_push_fn_t) ndr_push_lsa_OpenPolicy2,
				    (ndr_pull_fn_t) ndr_pull_lsa_OpenPolicy2,
				    &r);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}
	
	/* and extract the .out parameters */
	*handle = r.out.handle;
	status = r.out.status;

done:
	talloc_destroy(mem_ctx);
	return status;
}
