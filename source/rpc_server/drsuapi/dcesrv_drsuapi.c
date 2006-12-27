/* 
   Unix SMB/CIFS implementation.

   endpoint server for the drsuapi pipe

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
#include "dsdb/samdb/samdb.h"

/* 
  drsuapi_DsBind 
*/
static WERROR drsuapi_DsBind(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct drsuapi_DsBind *r)
{
	struct drsuapi_bind_state *b_state;
	struct dcesrv_handle *handle;
	struct drsuapi_DsBindInfoCtr *bind_info;
	struct GUID site_guid;

	r->out.bind_info = NULL;
	ZERO_STRUCTP(r->out.bind_handle);

	b_state = talloc(dce_call->conn, struct drsuapi_bind_state);
	W_ERROR_HAVE_NO_MEMORY(b_state);

	b_state->sam_ctx = samdb_connect(b_state, dce_call->conn->auth_state.session_info); 
	if (!b_state->sam_ctx) {
		talloc_free(b_state);
		return WERR_FOOBAR;
	}

	handle = dcesrv_handle_new(dce_call->context, DRSUAPI_BIND_HANDLE);
	if (!handle) {
		talloc_free(b_state);
		return WERR_NOMEM;
	}

	handle->data = talloc_steal(handle, b_state);

	bind_info = talloc(mem_ctx, struct drsuapi_DsBindInfoCtr);
	W_ERROR_HAVE_NO_MEMORY(bind_info);

	ZERO_STRUCT(site_guid);

	bind_info->length				= 28;
	bind_info->info.info28.supported_extensions	= 0;
	bind_info->info.info28.site_guid		= site_guid;
	bind_info->info.info28.u1			= 0;
	bind_info->info.info28.repl_epoch		= 0;

	r->out.bind_info = bind_info;
	*r->out.bind_handle = handle->wire_handle;

	return WERR_OK;
}


/* 
  drsuapi_DsUnbind 
*/
static WERROR drsuapi_DsUnbind(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			       struct drsuapi_DsUnbind *r)
{
	struct dcesrv_handle *h;

	*r->out.bind_handle = *r->in.bind_handle;

	DCESRV_PULL_HANDLE_WERR(h, r->in.bind_handle, DRSUAPI_BIND_HANDLE);

	talloc_free(h);

	ZERO_STRUCTP(r->out.bind_handle);

	return WERR_OK;
}


/* 
  drsuapi_DsReplicaSync 
*/
static WERROR drsuapi_DsReplicaSync(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct drsuapi_DsReplicaSync *r)
{
	/* TODO: implement this call correct!
	 *       for now we just say yes,
	 *       because we have no output parameter
	 */
	return WERR_OK;
}


/* 
  drsuapi_DsGetNCChanges
*/
static WERROR drsuapi_DsGetNCChanges(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct drsuapi_DsGetNCChanges *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  drsuapi_DsReplicaUpdateRefs
*/
static WERROR drsuapi_DsReplicaUpdateRefs(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct drsuapi_DsReplicaUpdateRefs *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_REPLICA_ADD 
*/
static WERROR DRSUAPI_REPLICA_ADD(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_REPLICA_ADD *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_REPLICA_DEL 
*/
static WERROR DRSUAPI_REPLICA_DEL(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_REPLICA_DEL *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_REPLICA_MODIFY 
*/
static WERROR DRSUAPI_REPLICA_MODIFY(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_REPLICA_MODIFY *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_VERIFY_NAMES 
*/
static WERROR DRSUAPI_VERIFY_NAMES(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_VERIFY_NAMES *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  drsuapi_DsGetMemberships 
*/
static WERROR drsuapi_DsGetMemberships(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct drsuapi_DsGetMemberships *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_INTER_DOMAIN_MOVE 
*/
static WERROR DRSUAPI_INTER_DOMAIN_MOVE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_INTER_DOMAIN_MOVE *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_GET_NT4_CHANGELOG 
*/
static WERROR DRSUAPI_GET_NT4_CHANGELOG(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_GET_NT4_CHANGELOG *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  drsuapi_DsCrackNames 
*/
WERROR drsuapi_DsCrackNames(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
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
			struct drsuapi_DsNameCtr1 *ctr1;
			struct drsuapi_DsNameInfo1 *names;
			int count;
			int i;

			ctr1 = talloc(mem_ctx, struct drsuapi_DsNameCtr1);
			W_ERROR_HAVE_NO_MEMORY(ctr1);

			count = r->in.req.req1.count;
			names = talloc_array(mem_ctx, struct drsuapi_DsNameInfo1, count);
			W_ERROR_HAVE_NO_MEMORY(names);

			for (i=0; i < count; i++) {
				status = DsCrackNameOneName(b_state->sam_ctx, mem_ctx,
							    r->in.req.req1.format_flags,
							    r->in.req.req1.format_offered,
							    r->in.req.req1.format_desired,
							    r->in.req.req1.names[i].str,
							    &names[i]);
				if (!W_ERROR_IS_OK(status)) {
					return status;
				}
			}

			ctr1->count = count;
			ctr1->array = names;
			r->out.ctr.ctr1 = ctr1;

			return WERR_OK;
		}
	}
	
	return WERR_UNKNOWN_LEVEL;
}

/* 
  drsuapi_DsWriteAccountSpn 
*/
static WERROR drsuapi_DsWriteAccountSpn(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct drsuapi_DsWriteAccountSpn *r)
{
	struct drsuapi_bind_state *b_state;
	struct dcesrv_handle *h;

	r->out.level = r->in.level;

	DCESRV_PULL_HANDLE_WERR(h, r->in.bind_handle, DRSUAPI_BIND_HANDLE);
	b_state = h->data;

	switch (r->in.level) {
		case 1: {
			struct drsuapi_DsWriteAccountSpnRequest1 *req;
			struct ldb_message *msg;
			int count, i, ret;
			req = &r->in.req.req1;
			count = req->count;

			msg = ldb_msg_new(mem_ctx);
			if (msg == NULL) {
				return WERR_NOMEM;
			}

			msg->dn = ldb_dn_new(msg, b_state->sam_ctx, req->object_dn);
			if ( ! ldb_dn_validate(msg->dn)) {
				r->out.res.res1.status = WERR_OK;
				return WERR_OK;
			}
			
			/* construct mods */
			for (i = 0; i < count; i++) {
				samdb_msg_add_string(b_state->sam_ctx, 
						     msg, msg, "servicePrincipalName",
						     req->spn_names[i].str);
			}
			for (i=0;i<msg->num_elements;i++) {
				switch (req->operation) {
				case DRSUAPI_DS_SPN_OPERATION_ADD:
 					msg->elements[i].flags = LDB_FLAG_MOD_ADD;
					break;
				case DRSUAPI_DS_SPN_OPERATION_REPLACE:
					msg->elements[i].flags = LDB_FLAG_MOD_REPLACE;
					break;
				case DRSUAPI_DS_SPN_OPERATION_DELETE:
					msg->elements[i].flags = LDB_FLAG_MOD_DELETE;
					break;
				}
			}
   
			/* Apply to database */

			ret = samdb_modify(b_state->sam_ctx, mem_ctx, msg);
			if (ret != 0) {
				DEBUG(0,("Failed to modify SPNs on %s: %s\n",
					 ldb_dn_get_linearized(msg->dn), 
					 ldb_errstring(b_state->sam_ctx)));
				r->out.res.res1.status = WERR_ACCESS_DENIED;
			} else {
				r->out.res.res1.status = WERR_OK;
			}

			return WERR_OK;
		}
	}
	
	return WERR_UNKNOWN_LEVEL;
}


/* 
  drsuapi_DsRemoveDSServer
*/
static WERROR drsuapi_DsRemoveDSServer(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				       struct drsuapi_DsRemoveDSServer *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_REMOVE_DS_DOMAIN 
*/
static WERROR DRSUAPI_REMOVE_DS_DOMAIN(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_REMOVE_DS_DOMAIN *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/* Obtain the site name from a server DN */
const char *result_site_name(struct ldb_dn *site_dn)
{
	/* Format is cn=<NETBIOS name>,cn=Servers,cn=<site>,cn=sites.... */
	const struct ldb_val *val = ldb_dn_get_component_val(site_dn, 2);
	const char *name = ldb_dn_get_component_name(site_dn, 2);

	if (!name || (ldb_attr_cmp(name, "cn") != 0)) {
		/* Ensure this matches the format.  This gives us a
		 * bit more confidence that a 'cn' value will be a
		 * ascii string */
		return NULL;
	}
	if (val) {
		return (char *)val->data;
	}
	return NULL;
}

/* 
  drsuapi_DsGetDomainControllerInfo 
*/
static WERROR drsuapi_DsGetDomainControllerInfo_1(struct drsuapi_bind_state *b_state, 
						TALLOC_CTX *mem_ctx,
						struct drsuapi_DsGetDomainControllerInfo *r)
{
	struct ldb_dn *sites_dn;
	struct ldb_result *res;

	const char *attrs_account_1[] = { "cn", "dnsHostName", NULL };
	const char *attrs_account_2[] = { "cn", "dnsHostName", "objectGUID", NULL };

	const char *attrs_none[] = { NULL };

	const char *attrs_site[] = { "objectGUID", NULL };

	const char *attrs_ntds[] = { "options", "objectGUID", NULL };

	const char *attrs_1[] = { "serverReference", "cn", "dnsHostName", NULL };
	const char *attrs_2[] = { "serverReference", "cn", "dnsHostName", "objectGUID", NULL };
	const char **attrs;

	struct drsuapi_DsGetDCInfoCtr1 *ctr1;
	struct drsuapi_DsGetDCInfoCtr2 *ctr2;

	int ret, i;

	r->out.level_out = r->in.req.req1.level;

	sites_dn = samdb_domain_to_dn(b_state->sam_ctx, mem_ctx, r->in.req.req1.domain_name);
	if (!sites_dn) {
		return WERR_DS_OBJ_NOT_FOUND;
	}

	if (!ldb_dn_add_child_fmt(sites_dn, "CN=Sites,CN=Configuration")) {
		return WERR_NOMEM;
	}

	switch (r->out.level_out) {
	case -1:
		/* this level is not like the others */
		return WERR_UNKNOWN_LEVEL;
	case 1:
		attrs = attrs_1;
		break;
	case 2:
		attrs = attrs_2;
		break;
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	ret = ldb_search_exp_fmt(b_state->sam_ctx, mem_ctx, &res, sites_dn, LDB_SCOPE_SUBTREE, attrs, 
				 "objectClass=server");
	
	if (ret) {
		return WERR_GENERAL_FAILURE;
	}

	switch (r->out.level_out) {
	case 1:
		ctr1 = &r->out.ctr.ctr1;
		ctr1->count = res->count;
		ctr1->array = talloc_zero_array(mem_ctx, 
						struct drsuapi_DsGetDCInfo1, 
						res->count);
		for (i=0; i < res->count; i++) {
			struct ldb_dn *domain_dn;
			struct ldb_result *res_domain;
			struct ldb_result *res_account;
			struct ldb_dn *ntds_dn = ldb_dn_copy(b_state->sam_ctx, res->msgs[i]->dn);
			
			struct ldb_dn *ref_dn
				= ldb_msg_find_attr_as_dn(b_state->sam_ctx, 
							  mem_ctx, res->msgs[i], 
							  "serverReference");

			if (!ntds_dn || !ldb_dn_add_child_fmt(ntds_dn, "CN=NTDS Settings")) {
				return WERR_NOMEM;
			}

			ret = ldb_search_exp_fmt(b_state->sam_ctx, mem_ctx, &res_account, ref_dn, 
						 LDB_SCOPE_BASE, attrs_account_1, "objectClass=computer");
			if (ret) {
				return WERR_GENERAL_FAILURE;
			}
			if (res_account->count == 1) {
				ctr1->array[i].dns_name
					= ldb_msg_find_attr_as_string(res_account->msgs[0], "dNSHostName", NULL);
				ctr1->array[i].netbios_name
					= ldb_msg_find_attr_as_string(res_account->msgs[0], "cn", NULL);
				ctr1->array[i].computer_dn
					= ldb_dn_get_linearized(res_account->msgs[0]->dn);

				/* Determine if this is the PDC */
				domain_dn = samdb_search_for_parent_domain(b_state->sam_ctx, 
									   mem_ctx, res_account->msgs[0]->dn);
				
				if (domain_dn) {
					ret = ldb_search_exp_fmt(b_state->sam_ctx, mem_ctx, &res_domain, domain_dn, 
								 LDB_SCOPE_BASE, attrs_none, "fSMORoleOwner=%s",
								 ldb_dn_get_linearized(ntds_dn));
					if (ret) {
						return WERR_GENERAL_FAILURE;
					}
					if (res_domain->count == 1) {
						ctr1->array[i].is_pdc = True;
					}
				}
			}

			/* Look at server DN and extract site component */
			ctr1->array[i].site_name = result_site_name(res->msgs[i]->dn);
			ctr1->array[i].server_dn = ldb_dn_get_linearized(res->msgs[i]->dn);


			ctr1->array[i].is_enabled = True;

		}
		break;
	case 2:
		ctr2 = &r->out.ctr.ctr2;
		ctr2->count = res->count;
		ctr2->array = talloc_zero_array(mem_ctx, 
						 struct drsuapi_DsGetDCInfo2, 
						 res->count);
		for (i=0; i < res->count; i++) {
			struct ldb_dn *domain_dn;
			struct ldb_result *res_domain;
			struct ldb_result *res_account;
			struct ldb_dn *ntds_dn = ldb_dn_copy(b_state->sam_ctx, res->msgs[i]->dn);
			struct ldb_result *res_ntds;
			struct ldb_dn *site_dn = ldb_dn_copy(b_state->sam_ctx, res->msgs[i]->dn);
			struct ldb_result *res_site;
			struct ldb_dn *ref_dn
				= ldb_msg_find_attr_as_dn(b_state->sam_ctx, 
							  mem_ctx, res->msgs[i], 
							  "serverReference");

			if (!ntds_dn || !ldb_dn_add_child_fmt(ntds_dn, "CN=NTDS Settings")) {
				return WERR_NOMEM;
			}

			/* Format is cn=<NETBIOS name>,cn=Servers,cn=<site>,cn=sites.... */
			if (!site_dn || !ldb_dn_remove_child_components(site_dn, 2)) {
				return WERR_NOMEM;
			}

			ret = ldb_search_exp_fmt(b_state->sam_ctx, mem_ctx, &res_ntds, ntds_dn, 
						 LDB_SCOPE_BASE, attrs_ntds, "objectClass=nTDSDSA");
			if (ret) {
				return WERR_GENERAL_FAILURE;
			}
			if (res_ntds->count == 1) {
				ctr2->array[i].is_gc
					= (ldb_msg_find_attr_as_int(res_ntds->msgs[0], "options", 0) == 1);
				ctr2->array[i].ntds_guid 
					= samdb_result_guid(res_ntds->msgs[0], "objectGUID");
				ctr2->array[i].ntds_dn = ldb_dn_get_linearized(res_ntds->msgs[0]->dn);
			}

			ret = ldb_search_exp_fmt(b_state->sam_ctx, mem_ctx, &res_site, site_dn, 
						 LDB_SCOPE_BASE, attrs_site, "objectClass=site");
			if (ret) {
				return WERR_GENERAL_FAILURE;
			}
			if (res_site->count == 1) {
				ctr2->array[i].site_guid 
					= samdb_result_guid(res_site->msgs[0], "objectGUID");
				ctr2->array[i].site_dn = ldb_dn_get_linearized(res_site->msgs[0]->dn);
			}

			ret = ldb_search_exp_fmt(b_state->sam_ctx, mem_ctx, &res_account, ref_dn, 
						 LDB_SCOPE_BASE, attrs_account_2, "objectClass=computer");
			if (ret) {
				return WERR_GENERAL_FAILURE;
			}
			if (res_account->count == 1) {
				ctr2->array[i].dns_name
					= ldb_msg_find_attr_as_string(res_account->msgs[0], "dNSHostName", NULL);
				ctr2->array[i].netbios_name
					= ldb_msg_find_attr_as_string(res_account->msgs[0], "cn", NULL);
				ctr2->array[i].computer_dn = ldb_dn_get_linearized(res_account->msgs[0]->dn);
				ctr2->array[i].computer_guid 
					= samdb_result_guid(res_account->msgs[0], "objectGUID");

				/* Determine if this is the PDC */
				domain_dn = samdb_search_for_parent_domain(b_state->sam_ctx, 
									   mem_ctx, res_account->msgs[0]->dn);
				
				if (domain_dn) {
					ret = ldb_search_exp_fmt(b_state->sam_ctx, mem_ctx, &res_domain, domain_dn, 
								 LDB_SCOPE_BASE, attrs_none, "fSMORoleOwner=%s",
								 ldb_dn_get_linearized(ntds_dn));
					if (ret) {
						return WERR_GENERAL_FAILURE;
					}
					if (res_domain->count == 1) {
						ctr2->array[i].is_pdc = True;
					}
				}
			}

			/* Look at server DN and extract site component */
			ctr2->array[i].site_name = result_site_name(res->msgs[i]->dn);
			ctr2->array[i].server_dn = ldb_dn_get_linearized(res->msgs[i]->dn);
			ctr2->array[i].server_guid 
				= samdb_result_guid(res->msgs[i], "objectGUID");

			ctr2->array[i].is_enabled = True;

		}
		break;
	}
	return WERR_OK;
}

/* 
  drsuapi_DsGetDomainControllerInfo 
*/
static WERROR drsuapi_DsGetDomainControllerInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
						struct drsuapi_DsGetDomainControllerInfo *r)
{
	struct dcesrv_handle *h;
	struct drsuapi_bind_state *b_state;	
	DCESRV_PULL_HANDLE_WERR(h, r->in.bind_handle, DRSUAPI_BIND_HANDLE);
	b_state = h->data;

	switch (r->in.level) {
	case 1:
		return drsuapi_DsGetDomainControllerInfo_1(b_state, mem_ctx, r);
	}

	return WERR_UNKNOWN_LEVEL;
}


/* 
  drsuapi_DsAddEntry
*/
static WERROR drsuapi_DsAddEntry(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct drsuapi_DsAddEntry *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_EXECUTE_KCC 
*/
static WERROR DRSUAPI_EXECUTE_KCC(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_EXECUTE_KCC *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  drsuapi_DsReplicaGetInfo 
*/
static WERROR drsuapi_DsReplicaGetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct drsuapi_DsReplicaGetInfo *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_ADD_SID_HISTORY 
*/
static WERROR DRSUAPI_ADD_SID_HISTORY(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_ADD_SID_HISTORY *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/* 
  drsuapi_DsGetMemberships2 
*/
static WERROR drsuapi_DsGetMemberships2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct drsuapi_DsGetMemberships2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/* 
  DRSUAPI_REPLICA_VERIFY_OBJECTS 
*/
static WERROR DRSUAPI_REPLICA_VERIFY_OBJECTS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_REPLICA_VERIFY_OBJECTS *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_GET_OBJECT_EXISTENCE 
*/
static WERROR DRSUAPI_GET_OBJECT_EXISTENCE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_GET_OBJECT_EXISTENCE *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DRSUAPI_QUERY_SITES_BY_COST 
*/
static WERROR DRSUAPI_QUERY_SITES_BY_COST(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DRSUAPI_QUERY_SITES_BY_COST *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_drsuapi_s.c"
