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
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "rpc_server/dcerpc_server.h"
#include "rpc_server/common/common.h"
#include "rpc_server/drsuapi/dcesrv_drsuapi.h"
#include "lib/ldb/include/ldb.h"

static WERROR DsCrackNameOneName(struct drsuapi_bind_state *b_state, TALLOC_CTX *mem_ctx,
			uint32 format_offered, uint32 format_desired, const char *name,
			struct drsuapi_DsNameInfo1 *info1)
{
	int ret;
	const char *domain_filter;
	const char * const *domain_attrs;
	struct ldb_message **domain_res;
	const char *result_basedn;
	const char *result_filter = NULL;
	const char * const *result_attrs;
	struct ldb_message **result_res;

	info1->status = DRSUAPI_DS_NAME_STATUS_RESOLVE_ERROR;
	info1->dns_domain_name = NULL;
	info1->result_name = NULL;

	/* TODO: fill crack the correct names in all cases! */
	switch (format_offered) {
		case DRSUAPI_DS_NAME_FORMAT_CANONICAL: {
			char *str;

			str = talloc_asprintf(mem_ctx, "%s/", lp_realm());
			WERR_TALLOC_CHECK(str);

			ret = strcasecmp(str, name);
			talloc_free(str);
			if (ret != 0) {
				info1->status = DRSUAPI_DS_NAME_STATUS_NOT_FOUND;
				return WERR_OK;
			}

			domain_filter = talloc_asprintf(mem_ctx, "(&(objectClass=domainDNS)(name=%s))",
								lp_workgroup());
			WERR_TALLOC_CHECK(domain_filter);

			break;
		}
		case DRSUAPI_DS_NAME_FORMAT_NT4_ACCOUNT: {
			char *p;
			char *domain;
			const char *account = NULL;

			domain = talloc_strdup(mem_ctx, name);
			WERR_TALLOC_CHECK(domain);

			p = strchr(domain, '\\');
			if (!p) {
				/* invalid input format */
				info1->status = DRSUAPI_DS_NAME_STATUS_RESOLVE_ERROR;
				return WERR_OK;
			}
			p[0] = '\0';

			if (p[1]) {
				account = &p[1];
			}

			domain_filter = talloc_asprintf(mem_ctx, "(&(objectClass=domainDNS)(name=%s))",
								domain);
			WERR_TALLOC_CHECK(domain_filter);
			if (account) {
				result_filter = talloc_asprintf(mem_ctx, "(sAMAccountName=%s)",
								account);
				WERR_TALLOC_CHECK(result_filter);
			}

			talloc_free(domain);
			break;
		}
		default: {
			info1->status = DRSUAPI_DS_NAME_STATUS_NOT_FOUND;
			return WERR_OK;
		}
	}

	switch (format_desired) {
		case DRSUAPI_DS_NAME_FORMAT_FQDN_1779: {
			const char * const _domain_attrs[] = { "dn", "dnsDomain", NULL};
			const char * const _result_attrs[] = { "dn", NULL};
			
			domain_attrs = _domain_attrs;
			result_attrs = _result_attrs;
			break;
		}
		case DRSUAPI_DS_NAME_FORMAT_NT4_ACCOUNT: {
			const char * const _domain_attrs[] = { "name", "dnsDomain", "dn", NULL};
			const char * const _result_attrs[] = { "sAMAccountName", NULL};
			
			domain_attrs = _domain_attrs;
			result_attrs = _result_attrs;
			break;
		}
		case DRSUAPI_DS_NAME_FORMAT_GUID: {
			const char * const _domain_attrs[] = { "objectGUID", "dnsDomain", "dn", NULL};
			const char * const _result_attrs[] = { "objectGUID", NULL};
			
			domain_attrs = _domain_attrs;
			result_attrs = _result_attrs;
			break;
		}
		default:
			return WERR_OK;
	}

	ret = samdb_search(b_state->sam_ctx, mem_ctx, NULL, &domain_res, domain_attrs,
				"%s", domain_filter);
	switch (ret) {
		case 1: 
			break;
		case 0: 
			info1->status = DRSUAPI_DS_NAME_STATUS_NOT_FOUND;
			return WERR_OK;
		case -1: 
			info1->status = DRSUAPI_DS_NAME_STATUS_RESOLVE_ERROR;
			return WERR_OK;
		default:
			info1->status = DRSUAPI_DS_NAME_STATUS_NOT_UNIQUE;
			return WERR_OK;
	}

	info1->dns_domain_name	= samdb_result_string(domain_res[0], "dnsDomain", NULL);
	WERR_TALLOC_CHECK(info1->dns_domain_name);
	info1->status		= DRSUAPI_DS_NAME_STATUS_DOMAIN_ONLY;

	if (result_filter) {
		result_basedn = samdb_result_string(domain_res[0], "dn", NULL);
		
		ret = samdb_search(b_state->sam_ctx, mem_ctx, result_basedn, &result_res,
					result_attrs, "%s", result_filter);
		switch (ret) {
			case 1:
				break;
			case 0:
				return WERR_OK;
			case -1:
				info1->status = DRSUAPI_DS_NAME_STATUS_RESOLVE_ERROR;
				return WERR_OK;
			default:
				info1->status = DRSUAPI_DS_NAME_STATUS_NOT_UNIQUE;
				return WERR_OK;
		}
	} else {
		result_res = domain_res;
	}

	switch (format_desired) {
		case DRSUAPI_DS_NAME_FORMAT_FQDN_1779: {
			info1->result_name	= samdb_result_string(result_res[0], "dn", NULL);
			WERR_TALLOC_CHECK(info1->result_name);
			info1->status		= DRSUAPI_DS_NAME_STATUS_OK;
			return WERR_OK;
		}
		case DRSUAPI_DS_NAME_FORMAT_NT4_ACCOUNT: {
			const char *_dom = samdb_result_string(domain_res[0], "name", NULL);
			const char *_acc = "";
			WERR_TALLOC_CHECK(_dom);
			if (result_filter) {
				_acc = samdb_result_string(result_res[0], "sAMAccountName", NULL);
				WERR_TALLOC_CHECK(_acc);
			}
			info1->result_name	= talloc_asprintf(mem_ctx, "%s\\%s", _dom, _acc);
			WERR_TALLOC_CHECK(info1->result_name);
			info1->status		= DRSUAPI_DS_NAME_STATUS_OK;
			return WERR_OK;
		}
		case DRSUAPI_DS_NAME_FORMAT_GUID: {
			const char *result = samdb_result_string(result_res[0], "objectGUID", NULL);
			WERR_TALLOC_CHECK(result);
			info1->result_name	= talloc_asprintf(mem_ctx, "{%s}", result);
			WERR_TALLOC_CHECK(info1->result_name);
			info1->status		= DRSUAPI_DS_NAME_STATUS_OK;
			return WERR_OK;
		}
		default:
			return WERR_OK;
	}

	return WERR_INVALID_PARAM;
}

/* 
  drsuapi_DsCrackNames 
*/
WERROR dcesrv_drsuapi_DsCrackNames(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct drsuapi_DsCrackNames *r)
{
	WERROR status;
	struct drsuapi_bind_state *b_state;
	struct dcesrv_handle *h;

	r->out.level = r->in.level;
	ZERO_STRUCT(r->out.ctr);

	DCESRV_PULL_HANDLE_WERR(h, r->in.bind_handle, DRSUAPI_BIND_HANDLE);
	b_state = h->data;

	switch (r->in.level) {
		case 1: {
			struct drsuapi_DsNameInfo1 *names;
			int count;
			int i;

			r->out.ctr.ctr1 = talloc_p(mem_ctx, struct drsuapi_DsNameCtr1);
			WERR_TALLOC_CHECK(r->out.ctr.ctr1);

			r->out.ctr.ctr1->count = 0;
			r->out.ctr.ctr1->array = NULL;

			count = r->in.req.req1.count;
			names = talloc_array_p(mem_ctx, struct drsuapi_DsNameInfo1, count);
			WERR_TALLOC_CHECK(names);

			for (i=0; i < count; i++) {
				status = DsCrackNameOneName(b_state, mem_ctx,
							    r->in.req.req1.format_offered,
							    r->in.req.req1.format_desired,
							    r->in.req.req1.names[i].str,
							    &names[i]);
				if (!W_ERROR_IS_OK(status)) {
					return status;
				}
			}

			r->out.ctr.ctr1->count = count;
			r->out.ctr.ctr1->array = names;

			return WERR_OK;
		}
	}
	
	return WERR_UNKNOWN_LEVEL;
}
