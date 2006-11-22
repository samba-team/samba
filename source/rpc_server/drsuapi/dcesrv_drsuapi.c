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


/* 
  drsuapi_DsGetDomainControllerInfo 
*/
static WERROR drsuapi_DsGetDomainControllerInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
						struct drsuapi_DsGetDomainControllerInfo *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
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
