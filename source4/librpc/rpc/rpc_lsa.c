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
			       TALLOC_CTX *mem_ctx,
			       struct lsa_OpenPolicy *r)
{
	NTSTATUS status;

	status = dcerpc_ndr_request(p, LSA_OPENPOLICY, mem_ctx,
				    (ndr_push_fn_t) ndr_push_lsa_OpenPolicy,
				    (ndr_pull_fn_t) ndr_pull_lsa_OpenPolicy,
				    r);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	return r->out.result;
}


/*
  OpenPolicy2 interface
*/
NTSTATUS dcerpc_lsa_OpenPolicy2(struct dcerpc_pipe *p,
				TALLOC_CTX *mem_ctx,
				struct lsa_OpenPolicy2 *r)
{
	NTSTATUS status;

	status = dcerpc_ndr_request(p, LSA_OPENPOLICY2, mem_ctx,
				    (ndr_push_fn_t) ndr_push_lsa_OpenPolicy2,
				    (ndr_pull_fn_t) ndr_pull_lsa_OpenPolicy2,
				    r);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return r->out.result;
}

/*
  EnumSids interface
*/
NTSTATUS dcerpc_lsa_EnumSids(struct dcerpc_pipe *p,
			     TALLOC_CTX *mem_ctx,
			     struct lsa_EnumSids *r)
{
	NTSTATUS status;

	/* make the call */
	status = dcerpc_ndr_request(p, LSA_ENUM_ACCOUNTS, mem_ctx,
				    (ndr_push_fn_t) ndr_push_lsa_EnumSids,
				    (ndr_pull_fn_t) ndr_pull_lsa_EnumSids,
				    r);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	return r->out.result;
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

/*
  LookupNames interface
*/
NTSTATUS dcerpc_lsa_LookupNames(struct dcerpc_pipe *p,
			       TALLOC_CTX *mem_ctx,
			       struct lsa_LookupNames *r)
{
	NTSTATUS status;

	status = dcerpc_ndr_request(p, LSA_LOOKUPNAMES, mem_ctx,
				    (ndr_push_fn_t) ndr_push_lsa_LookupNames,
				    (ndr_pull_fn_t) ndr_pull_lsa_LookupNames,
				    r);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	return r->out.result;
}
