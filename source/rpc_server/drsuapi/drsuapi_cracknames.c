/* 
   Unix SMB/CIFS implementation.

   endpoint server for the drsuapi pipe
   DsCrackNames()

   Copyright (C) Stefan Metzmacher 2004
   
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
#include "rpc_server/common/common.h"
#include "rpc_server/drsuapi/dcesrv_drsuapi.h"


static NTSTATUS DsCrackNameOneName(struct drsuapi_bind_state *b_state, TALLOC_CTX *mem_ctx,
			uint32 format_offered, uint32 format_desired, const char *name,
			struct drsuapi_DsNameInfo1 *info1)
{
	info1->status = DRSUAPI_DS_NAME_STATUS_RESOLVE_ERROR;
	info1->dns_domain_name = NULL;
	info1->result_name = NULL;

	/* TODO: fill crack the correct names in all cases! */
	switch (format_offered) {
		case DRSUAPI_DS_NAME_FORMAT_CANONICAL: {
			int ret;
			char *str;

			str = talloc_asprintf(mem_ctx, "%s/", lp_realm());
			NTSTATUS_TALLOC_CHECK(str);

			ret = strcasecmp(str, name);
			talloc_free(str);
			if (ret != 0) {
				info1->status = DRSUAPI_DS_NAME_STATUS_NOT_FOUND;
				return NT_STATUS_OK;
			}

			info1->status = DRSUAPI_DS_NAME_STATUS_DOMAIN_ONLY;
			info1->dns_domain_name = talloc_asprintf(mem_ctx, "%s", lp_realm());
			NTSTATUS_TALLOC_CHECK(info1->dns_domain_name);
			switch (format_desired) {
				case DRSUAPI_DS_NAME_FORMAT_NT4_ACCOUNT:
					info1->status = DRSUAPI_DS_NAME_STATUS_OK;
					info1->result_name = talloc_asprintf(mem_ctx, "%s\\",
										lp_workgroup());
					NTSTATUS_TALLOC_CHECK(info1->result_name);
					return NT_STATUS_OK;
				default:
					return NT_STATUS_OK;
			}
			return NT_STATUS_INVALID_PARAMETER;
		}
		default: {
			info1->status = DRSUAPI_DS_NAME_STATUS_NOT_FOUND;
			return NT_STATUS_OK;
		}
	}

	return NT_STATUS_INVALID_PARAMETER;
}

/* 
  drsuapi_DsCrackNames 
*/
NTSTATUS dcesrv_drsuapi_DsCrackNames(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct drsuapi_DsCrackNames *r)
{
	NTSTATUS status;
	struct drsuapi_bind_state *b_state;
	struct dcesrv_handle *h;

	r->out.level = r->in.level;
	ZERO_STRUCT(r->out.ctr);

	DCESRV_PULL_HANDLE(h, r->in.bind_handle, DRSUAPI_BIND_HANDLE);
	b_state = h->data;

	switch (r->in.level) {
		case 1: {
			struct drsuapi_DsNameInfo1 *names;
			int count;
			int i;

			r->out.ctr.ctr1 = talloc_p(mem_ctx, struct drsuapi_DsNameCtr1);
			NTSTATUS_TALLOC_CHECK(r->out.ctr.ctr1);

			r->out.ctr.ctr1->count = 0;
			r->out.ctr.ctr1->array = NULL;

			count = r->in.req.req1.count;
			names = talloc_array_p(mem_ctx, struct drsuapi_DsNameInfo1, count);
			NTSTATUS_TALLOC_CHECK(names);

			for (i=0; i < count; i++) {
				status = DsCrackNameOneName(b_state, mem_ctx,
							    r->in.req.req1.format_offered,
							    r->in.req.req1.format_desired,
							    r->in.req.req1.names[i].str,
							    &names[i]);
				if (!NT_STATUS_IS_OK(status)) {
					return status;
				}
			}

			r->out.ctr.ctr1->count = count;
			r->out.ctr.ctr1->array = names;

			return NT_STATUS_OK;
		}
	}
	
	return NT_STATUS_INVALID_LEVEL;
}
