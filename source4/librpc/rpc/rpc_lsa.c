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


NTSTATUS ndr_push_lsa_OpenPolicy(struct ndr_push *ndr, struct lsa_OpenPolicy *r);
NTSTATUS ndr_push_lsa_OpenPolicy2(struct ndr_push *ndr, struct lsa_OpenPolicy2 *r);
NTSTATUS ndr_push_lsa_EnumSids(struct ndr_push *ndr, struct lsa_EnumSids *r);

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
	uint16 s;

	mem_ctx = talloc_init("dcerpc_lsa_openpolicy");
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	/* fill the .in side of the call */
	s = server[0];
	r.in.system_name = &s;
	r.in.attr = attr;
	r.in.desired_access = access_mask;
	r.out.handle = handle;

	/* make the call */
	status = dcerpc_ndr_request(p, LSA_OPENPOLICY, mem_ctx,
				    (ndr_push_fn_t) ndr_push_lsa_OpenPolicy,
				    (ndr_pull_fn_t) ndr_pull_lsa_OpenPolicy,
				    &r);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}
	
	/* and extract the .out parameters */
	status = r.out.result;

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

	mem_ctx = talloc_init("dcerpc_lsa_openpolicy2");
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	/* fill the .in side of the call */
	r.in.system_name = server;
	r.in.attr = attr;
	r.in.desired_access = access_mask;
	r.out.handle = handle;

	/* make the call */
	status = dcerpc_ndr_request(p, LSA_OPENPOLICY2, mem_ctx,
				    (ndr_push_fn_t) ndr_push_lsa_OpenPolicy2,
				    (ndr_pull_fn_t) ndr_pull_lsa_OpenPolicy2,
				    &r);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}
	
	/* and extract the .out parameters */
	status = r.out.result;

done:
	talloc_destroy(mem_ctx);
	return status;
}

/*
  EnumSids interface
*/
NTSTATUS dcerpc_lsa_EnumSids(struct dcerpc_pipe *p,
			     TALLOC_CTX *mem_ctx,
			     struct policy_handle *handle,
			     uint32 *resume_handle,
			     uint32 num_entries,
			     struct lsa_SidArray *sids)
{
	struct lsa_EnumSids r;
	NTSTATUS status;

	/* fill the .in side of the call */
	r.in.handle = handle;
	r.in.resume_handle = resume_handle;
	r.in.num_entries = num_entries;

	r.out.resume_handle = resume_handle;
	r.out.sids = sids;

	/* make the call */
	status = dcerpc_ndr_request(p, LSA_ENUM_ACCOUNTS, mem_ctx,
				    (ndr_push_fn_t) ndr_push_lsa_EnumSids,
				    (ndr_pull_fn_t) ndr_pull_lsa_EnumSids,
				    &r);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}
	
	/* and extract the .out parameters */
	status = r.out.result;

done:
	return status;
}

/*
  LookupSids interface
*/
NTSTATUS dcerpc_lsa_LookupSids(struct dcerpc_pipe *p,
			       TALLOC_CTX *mem_ctx,
			       struct lsa_LookupSids *r)
{
	NTSTATUS status;

	status = dcerpc_ndr_request(p, LSA_LOOKUPSIDS, mem_ctx,
				    (ndr_push_fn_t) ndr_push_lsa_LookupSids,
				    (ndr_pull_fn_t) ndr_pull_lsa_LookupSids,
				    r);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	return r->out.result;
}
